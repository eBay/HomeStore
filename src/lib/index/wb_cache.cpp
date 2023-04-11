/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 *********************************************************************************/
#include <sisl/fds/thread_vector.hpp>
#include <homestore/btree/detail/btree_node.hpp>
#include <homestore/index_service.hpp>
#include <homestore/homestore.hpp>
#include "common/homestore_assert.hpp"

#include "wb_cache.hpp"
#include "index_cp.hpp"
#include "device/virtual_dev.hpp"
#include "common/resource_mgr.hpp"

namespace homestore {
IndexWBCache& wb_cache() { return index_service().wb_cache(); }

IndexWBCache::IndexWBCache(const std::shared_ptr< VirtualDev >& vdev, const std::shared_ptr< sisl::Evictor >& evictor,
                           uint32_t node_size) :
        m_vdev{vdev},
        m_cache{
            evictor, 1000, node_size,
            [](const BtreeNodePtr& node) -> BlkId { return IndexBtreeNode::convert(node.get())->m_idx_buf->m_blkid; },
            [](const sisl::CacheRecord& rec) -> bool {
                const auto& hnode = (sisl::SingleEntryHashNode< BtreeNodePtr >&)rec;
                return (hnode.m_value->m_refcount.test_le(1));
            }},
        m_node_size{node_size} {

    start_flush_threads();
    for (size_t i{0}; i < MAX_CP_COUNT; ++i) {
        m_dirty_list[i] = std::make_unique< sisl::ThreadVector< IndexBufferPtr > >();
        m_free_blkid_list[i] = std::make_unique< sisl::ThreadVector< BlkId > >();
    }
}

void IndexWBCache::start_flush_threads() {
    // Start WBCache flush threads
    struct Context {
        std::condition_variable cv;
        std::mutex mtx;
        int32_t thread_cnt{0};
    };
    auto ctx = std::make_shared< Context >();
    auto nthreads = std::max(1, HS_DYNAMIC_CONFIG(generic.cache_flush_threads));

    for (int32_t i{0}; i < nthreads; ++i) {
        iomanager.create_reactor("index_cp_flush" + std::to_string(i), INTERRUPT_LOOP, 1u,
                                 [this, &ctx](bool is_started) {
                                     if (is_started) {
                                         {
                                             std::unique_lock< std::mutex > lk{ctx->mtx};
                                             m_cp_flush_fibers.push_back(iomanager.iofiber_self());
                                             ++(ctx->thread_cnt);
                                         }
                                         ctx->cv.notify_one();
                                     }
                                 });
    }

    {
        std::unique_lock< std::mutex > lk{ctx->mtx};
        ctx->cv.wait(lk, [&ctx, nthreads] { return (ctx->thread_cnt == nthreads); });
    }
}

BtreeNodePtr IndexWBCache::alloc_buf(node_initializer_t&& node_initializer) {
    // Alloc a block of data from underlying vdev
    static thread_local std::vector< BlkId > t_blkids;
    t_blkids.clear();
    auto ret = m_vdev->alloc_blk(1, blk_alloc_hints{}, t_blkids);
    if (ret != BlkAllocStatus::SUCCESS) { return nullptr; }
    BlkId blkid = t_blkids[0];

    // Alloc buffer and initialize the node
    auto idx_buf = std::make_shared< IndexBuffer >(blkid, m_node_size, m_vdev->align_size());
    auto node = node_initializer(idx_buf);

    // Add the node to the cache
    bool done = m_cache.insert(node);
    HS_REL_ASSERT_EQ(done, true, "Unable to add alloc'd node to cache, low memory or duplicate inserts?");
    return node;
}

void IndexWBCache::realloc_buf(const IndexBufferPtr& buf) {
    // Commit the blk which was previously allocated
    m_vdev->commit_blk(buf->m_blkid);
}

void IndexWBCache::write_buf(const IndexBufferPtr& buf, CPContext* cp_ctx) {
    r_cast< IndexCPContext* >(cp_ctx)->add_to_dirty_list(buf);
    resource_mgr().inc_dirty_buf_size(m_node_size);
}

void IndexWBCache::read_buf(bnodeid_t id, BtreeNodePtr& node, node_initializer_t&& node_initializer) {
    auto const blkid = BlkId{id};

retry:
    // Check if the blkid is already in cache, if not load and put it into the cache
    if (m_cache.get(blkid, node)) { return; }

    // Read the buffer from virtual device
    auto idx_buf = std::make_shared< IndexBuffer >(blkid, m_node_size, m_vdev->align_size());
    auto raw_buf = idx_buf->raw_buffer();

    m_vdev->sync_read(r_cast< char* >(raw_buf), m_node_size, blkid);

    // Create the btree node out of buffer
    node = node_initializer(idx_buf);

    // Push the node into cache
    bool done = m_cache.insert(node);
    if (!done) {
        // There is a race between 2 concurrent reads from vdev and other party won the race. Re-read from cache
        goto retry;
    }
}

bool IndexWBCache::create_chain(IndexBufferPtr& second, IndexBufferPtr& third) {
    bool copied{false};
    if (second->m_next_buffer != nullptr) {
        HS_DBG_ASSERT_EQ((void*)second->m_next_buffer.get(), (void*)third.get(),
                         "Overwriting second (child node) with different third (parent node)");
        HS_DBG_ASSERT_EQ((void*)second->m_next_buffer->m_next_buffer.get(), (void*)nullptr,
                         "Third node buffer should be the last in the list");

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

void IndexWBCache::free_buf(const IndexBufferPtr& buf, CPContext* cp_ctx) {
    BtreeNodePtr node;
    bool done = m_cache.remove(buf->m_blkid, node);
    HS_REL_ASSERT_EQ(done, true, "Race on cache removal of btree blkid?");

    resource_mgr().inc_free_blk(m_node_size);
    r_cast< IndexCPContext* >(cp_ctx)->add_to_free_node_list(buf->m_blkid);
}

//////////////////// CP Related API section /////////////////////////////////
void IndexWBCache::async_cp_flush(CPContext* context, cp_flush_done_cb_t cp_done_cb) {
    IndexCPContext* cp_ctx = s_cast< IndexCPContext* >(context);
    if (!cp_ctx->any_dirty_buffers()) {
        CP_PERIODIC_LOG(DEBUG, cp_ctx->id(), "Btree does not have any dirty buffers to flush");
        cp_done_cb(cp_ctx->cp());
        return; // nothing to flush
    }

    cp_ctx->m_flush_done_cb = std::move(cp_done_cb);
    cp_ctx->prepare_flush_iteration();

    for (auto& fiber : m_cp_flush_fibers) {
        iomanager.run_on_forget(fiber, [this, cp_ctx]() {
            static thread_local std::vector< IndexBufferPtr > t_buf_list;
            t_buf_list.clear();
            get_next_bufs(cp_ctx, resource_mgr().get_dirty_buf_qd(), t_buf_list);

            for (auto& buf : t_buf_list) {
                do_flush_one_buf(cp_ctx, buf, true);
            }
            m_vdev->submit_batch();
        });
    }
}

std::unique_ptr< CPContext > IndexWBCache::create_cp_context(cp_id_t cp_id) {
    size_t const cp_id_slot = cp_id % MAX_CP_COUNT;
    return std::make_unique< IndexCPContext >(cp_id, m_dirty_list[cp_id_slot].get(),
                                              m_free_blkid_list[cp_id_slot].get());
}

IndexBufferPtr IndexWBCache::copy_buffer(const IndexBufferPtr& cur_buf) const {
    auto new_buf = std::make_shared< IndexBuffer >(cur_buf->m_blkid, m_node_size, m_vdev->align_size());
    std::memcpy(new_buf->raw_buffer(), cur_buf->raw_buffer(), m_node_size);
    return new_buf;
}

void IndexWBCache::do_flush_one_buf(IndexCPContext* cp_ctx, const IndexBufferPtr& buf, bool part_of_batch) {
    buf->m_buf_state = index_buf_state_t::FLUSHING;
    m_vdev->async_write(r_cast< const char* >(buf->raw_buffer()), m_node_size, buf->m_blkid, part_of_batch)
        .thenValue([pbuf = buf.get(), cp_ctx](auto) {
            auto& pthis = s_cast< IndexWBCache& >(wb_cache()); // Avoiding more than 16 bytes capture
            pthis.process_write_completion(cp_ctx, pbuf);
        });

    if (!part_of_batch) { m_vdev->submit_batch(); }
}

void IndexWBCache::process_write_completion(IndexCPContext* cp_ctx, IndexBuffer* pbuf) {
    resource_mgr().dec_dirty_buf_size(m_node_size);
    auto [next_buf, has_more] = on_buf_flush_done(cp_ctx, pbuf);
    if (next_buf) {
        do_flush_one_buf(cp_ctx, next_buf, false);
    } else if (!has_more) {
        // We are done flushing the buffers, lets free the btree blocks and then flush the bitmap
        do_free_btree_blks(cp_ctx);
    }
}

std::pair< IndexBufferPtr, bool > IndexWBCache::on_buf_flush_done(IndexCPContext* cp_ctx, IndexBuffer* buf) {
    if (m_cp_flush_fibers.size() > 1) {
        std::unique_lock lg(m_flush_mtx);
        return on_buf_flush_done_internal(cp_ctx, buf);
    } else {
        return on_buf_flush_done_internal(cp_ctx, buf);
    }
}

std::pair< IndexBufferPtr, bool > IndexWBCache::on_buf_flush_done_internal(IndexCPContext* cp_ctx, IndexBuffer* buf) {
    static thread_local std::vector< IndexBufferPtr > t_buf_list;
    t_buf_list.clear();

    buf->m_buf_state = index_buf_state_t::CLEAN;

    if (cp_ctx->m_dirty_buf_count.decrement_testz()) {
        return std::make_pair(nullptr, false);
    } else {
        get_next_bufs_internal(cp_ctx, 1u, buf, t_buf_list);
        return std::make_pair((t_buf_list.size() ? t_buf_list[0] : nullptr), true);
    }
}

void IndexWBCache::get_next_bufs(IndexCPContext* cp_ctx, uint32_t max_count, std::vector< IndexBufferPtr >& bufs) {
    if (m_cp_flush_fibers.size() > 1) {
        std::unique_lock lg(m_flush_mtx);
        get_next_bufs_internal(cp_ctx, max_count, nullptr, bufs);
    } else {
        get_next_bufs_internal(cp_ctx, max_count, nullptr, bufs);
    }
}

void IndexWBCache::get_next_bufs_internal(IndexCPContext* cp_ctx, uint32_t max_count, IndexBuffer* prev_flushed_buf,
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
        IndexBufferPtr* ppbuf = cp_ctx->next_dirty();
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

void IndexWBCache::do_free_btree_blks(IndexCPContext* cp_ctx) {
    BlkId* pbid;
    while ((pbid = cp_ctx->next_blkid()) != nullptr) {
        m_vdev->free_blk(*pbid);
    }

    m_vdev->cp_flush(); // As of now its a sync call, since metablk manager is sync write
    cp_ctx->m_flush_done_cb(cp_ctx->cp());
}

IndexBtreeNode* IndexBtreeNode::convert(BtreeNode* bt_node) {
    return r_cast< IndexBtreeNode* >(bt_node->get_node_context());
}

} // namespace homestore
