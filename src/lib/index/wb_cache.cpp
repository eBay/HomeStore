#pragma once

#include "wb_cache.hpp"
#include "device/virtual_dev.hpp"
#include "common/homestore_assert.hpp"

namespace homestore {
IndexWBCache::IndexWBCache(const std::shared_ptr< VirtualDev >& vdev, const std::shared_ptr< Evictor >& evictor,
                           uint32_t node_size) :
        m_vdev{vdev},
        m_node_size{node_size},
        m_cache{evictor, 1000, node_size,
                [](const BtreeNodePtr& node) -> BlkId { return to_hs_btree_node(node)->m_idx_buf->m_blkid; },
                [](const CacheRecord& rec) -> bool {
                    const auto& hnode = (SingleEntryHashNode< BtreeNodePtr >&)rec;
                    return (hnode.m_value.m_refcount < 2);
                }} {
    for (size_t i{0}; i < MAX_CP_CNT; ++i) {
        m_dirty_list[i] = std::make_unique< sisl::ThreadVector< IndexBufferPtr > >();
        m_free_blkid_list[i] = std::make_unique< sisl::ThreadVector< BlkId > >();
        m_dirty_buf_cnt[i].set(0);
    }
}

BtreeNodePtr IndexWBCache::alloc_buf(auto&& node_initializer) {
    // Alloc a block of data from underlying vdev
    static thread_local std::vector< BlkId > t_blkids;
    t_blkids.clear();
    auto ret = m_vdev->alloc_blks(1, blk_alloc_hints{}, t_blkids);
    if (ret != BlkAllocStatus::SUCCESS) { return nullptr; }
    BlkId blkid = t_blkids[0];

    // Alloc buffer and initialize the node
    auto idx_buf = std::make_shared< IndexBuffer >(blkid, m_node_size(), m_vdev->get_align_size());
    auto node = node_initializer(idx_buf);

    // Add the node to the cache
    bool done = m_cache.insert(node);
    HS_RELEASE_ASSERT_EQ(done, true, "Unable to add alloc'd node to cache, low memory or duplicate inserts?");
    return node;
}

void IndexWBCache::realloc_buf(const IndexBufferPtr& buf) {
    // Commit the blk which was previously allocated
    m_vdev->commit_blk(buf->blkid);
}

void IndexWBCache::write_buf(const IndexBufferPtr& buf, CPContext* cp_ctx) {
    r_cast< BtreeCPContext* >(cp_ctx)->add_to_dirty_list(buf);
    ResourceMgrSI().inc_dirty_buf_size(m_node_size);
}

std::error_condition IndexWBCache::read_buf(bnodeid_t id, BtreeNodePtr& node, bool cache_only,
                                            auto&& node_initializer) {
retry:
    // Check if the blkid is already in cache, if not load and put it into the cache
    if (m_cache.get(id, node)) {
        return no_error;
    } else if (cache_only) {
        return std::make_error_condition(std::errc::operation_would_block);
    }

    // Read the buffer from virtual device
    auto const blkid = BlkId{id};
    auto idx_buf = std::make_shared< IndexBuffer >(blkid, m_node_size(), m_vdev->get_align_size());
    auto raw_buf = idx_buf->raw_buffer();
    std::error_condition const ret = m_vdev->sync_read(blkid, raw_buf, idx_buf.get());
    if (ret != no_error) { return ret; }

    // Create the btree node out of buffer
    node = node_initializer(idx_buf);

    // Push the node into cache
    bool done = m_cache.insert(node);
    if (!done) {
        // There is a race between 2 concurrent reads from vdev and other party won the race. Re-read from cache
        goto retry;
    }
    return no_error;
}

bool IndexWBCache::create_chain(const IndexBufferPtr& second, const IndexBufferPtr& third) {
    bool copied{false};
    if (second->m_next_buffer != nullptr) {
        HS_DBG_ASSERT_EQ((void*)second->m_next_buffer.get(), third,
                         "Overwriting second (child node) with different third (parent node)");
        HS_DBG_ASSERT_EQ((void*)second->m_next_buffer->m_next_buffer.get(), nullptr,
                         "Third node buffer should be the last in the list";)

        // Second buf has already a next buffer, which means same node is in-place modified with structure change,
        // we need to copy both this and next buffer.
        auto new_second = copy_buffer(second);
        auto new_third = copy_buffer(third);

        third->m_next_buffer = new_second;
        new_second->m_wait_for_leaders.increment(1);

        second = new_second;
        third = new_third;
        copied = true;
    }
    second->m_next_buffer = third;
    third->m_wait_for_leaders.increment(1);

    return copied;
}

void IndexWBCache::prepend_to_chain(const IndexBufferPtr& first, const IndexBufferPtr& second) {
    first->m_next_buffer = second;
    second->m_wait_for_leaders.increment(1);
}

void IndexWBCache::free_buf(const IndexBufferPtr& buf, BtreeCPContext* cp_ctx) {
    bool done = m_cache->remove(buf->m_blkid);
    HS_REL_ASSERT_EQ(done, true, "Race on cache removal of btree blkid?");

    ResourceMgrSI().inc_free_blk(m_node_size);
    cp_ctx->add_to_free_node_list(buf->m_blkid);
}

//////////////////// CP Related API section /////////////////////////////////
void IndexWBCache::cp_flush(CPContext* context) override {
    BtreeCPContext* cp_ctx = s_cast< BtreeCPContext >(context);
    if (!cp_ctx->any_dirty_buffers()) {
        CP_PERIODIC_LOG(DEBUG, cp_ctx->cp_id(), "Btree does not have any dirty buffers to flush");
        // TODO: Call checkpoint to indicate that flush phase is done
        return; // nothing to flush
    }

    cp_ctx->prepare_flush_iteration();
    for (auto& thr : m_flush_thread_ids) {
        iomanager.run_on(thr, [this, cp_ctx](const io_thread_addr_t addr) {
            static thread_local std::vector< IndexBufferPtr > t_buf_list;
            t_buf_list.clear();
            get_next_bufs(cp_ctx, ResourceMgrSI().get_dirty_buf_qd(), t_buf_list);

            for (auto& buf : t_buf_list) {
                do_flush_one_buf(cp_ctx, buf, true);
            }
            m_vdev->submit_batch();
        });
    }
}

std::unique_ptr< CPContext > IndexWBCache::create_cp_context(cp_id_t cp_id) override {
    size_t const cp_id_slot = cpid % MAX_CP_CNT;
    return std::make_unique< BtreeCPContext >(cpid, m_dirty_list[cp_id_slot].get(),
                                              m_free_blkid_list[cp_id_slot].get());
}

IndexBufferPtr IndexWBCache::copy_buffer(const IndexBufferPtr& cur_buf) {
    auto new_buf = std::make_shared< IndexBuffer >(cur_buf->m_blkid, m_node_size, m_vdev->get_align_size());
    std::memcpy(new_buf->raw_buffer(), cur_buf->raw_buffer(), m_node_size);
    return new_buf;
}

void IndexWBCache::do_flush_one_buf(BtreeCPContext* cp_ctx, const IndexBufferPtr& buf, bool part_of_batch) {
    buf->m_buf_state = btree_buf_state_t::FLUSHING;
    m_vdev->async_write(buf->m_blkid, buf->raw_buffer(), buf.get(), [this, cp_ctx](vdev_req_context* ctx) {
        IndexBuffer* buf = (IndexBuffer*)ctx;
        ResourceMgrSI().dec_dirty_buf_size(m_node_size);
        auto [next_buf, has_more] = on_buf_flush_done(cp_ctx, buf);
        if (next_buf) {
            do_flush_one_buf(cp_ctx, next_buf, false);
        } else if (!has_more) {
            // We are done flushing the buffers, lets free the btree blocks and then flush the bitmap
            do_free_btree_blks(cp_ctx);
        }
    });

    if (!part_of_batch) { m_vdev->submit_batch(); }
}

std::pair< IndexBufferPtr, bool > IndexWBCache::on_buf_flush_done(BtreeCPContext* cp_ctx, IndexBuffer* buf) {
    if (m_flush_thread_ids.size() > 1) {
        std::unique_lock lg(m_flush_mtx);
        return on_buf_flush_done_internal(cp_ctx, nullptr);
    } else {
        return on_buf_flush_done_internal(cp_ctx, nullptr);
    }
}

std::pair< IndexBufferPtr, bool > IndexWBCache::on_buf_flush_done_internal(BtreeCPContext* cp_ctx, IndexBuffer* buf) {
    static thread_local std::vector< IndexBufferPtr > t_buf_list;
    t_buf_list.clear();

    buf->m_buf_state = btree_buf_state_t::CLEAN;

    if (cp_ctx->m_dirty_buf_count.decrement_testz()) {
        return nullptr;
    } else {
        get_next_bufs_internal(1u, buf, t_buf_list);
        return t_buf_list.size() ? t_buf_list[0] : nullptr;
    }
}

void IndexWBCache::get_next_bufs(BtreeCPContext* cp_ctx, uint32_t max_count, std::vector< IndexBufferPtr >& bufs) {
    if (m_flush_thread_ids.size() > 1) {
        std::unique_lock lg(m_flush_mtx);
        get_next_bufs_internal(cp_ctx, max_count, nullptr, bufs);
    } else {
        get_next_bufs_internal(cp_ctx, max_count, nullptr, bufs);
    }
}

void IndexWBCache::get_next_bufs_internal(BtreeCPContext* cp_ctx, uint32_t max_count, IndexBuffer* prev_flushed_buf,
                                          std::vector< IndexBufferPtr >& bufs) {
    uint32_t count{0};

    // First attempt to execute any follower buffer flush
    if (prev_flushed_buf) {
        auto& next_buffer = prev_flushed_buf->m_next_buffer;
        if (next_buffer && next_buffer->m_wait_for_leaders.decrement_testz()) {
            bufs.emplace_back(next_buffer);
            ++count;
        }
    }

    // If we still have room to push the next buffer, take it from the main list
    while (count < max_count) {
        IndexBufferPtr* ppbuf = cp_ctx->dirty_buf_list->next(buf_it.dirty_buf_list_it);
        if (ppbuf == nullptr) { break; } // End of list
        IndexBufferPtr buf = *ppbuf;
        if (buf->m_wait_for_leaders.testz()) {
            bufs.emplace_back(std::move(buf));
            ++count;
        } else {
            // There is some leader buffer still flushing, once done its completion will flush this buffer
        }
    }
}

void IndexWBCache::do_free_btree_blks(BtreeCPContext* cp_ctx) {
    while ((auto pbid = cp_ctx->m_free_node_blkid_list->next(it)) != nullptr) {
        m_vdev->free_blk(*pbid);
    }

    m_vdev->cp_flush(cp_ctx); // As of now its a sync call, since metablk manager is sync write
    // m_on_done_cb(this);
}

} // namespace homestore