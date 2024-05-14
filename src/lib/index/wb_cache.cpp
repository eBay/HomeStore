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
#include "device/chunk.h"
#include "common/homestore_assert.hpp"

#include "wb_cache.hpp"
#include "index_cp.hpp"
#include "device/virtual_dev.hpp"
#include "common/resource_mgr.hpp"

SISL_LOGGING_DECL(wbcache)

namespace homestore {

IndexWBCacheBase& wb_cache() { return index_service().wb_cache(); }

IndexWBCache::IndexWBCache(const std::shared_ptr< VirtualDev >& vdev, std::pair< meta_blk*, sisl::byte_view > sb,
                           const std::shared_ptr< sisl::Evictor >& evictor, uint32_t node_size) :
        m_vdev{vdev},
        m_cache{
            evictor, 100000, node_size,
            [](const BtreeNodePtr& node) -> BlkId { return IndexBtreeNode::convert(node.get())->m_idx_buf->m_blkid; },
            [](const sisl::CacheRecord& rec) -> bool {
                const auto& hnode = (sisl::SingleEntryHashNode< BtreeNodePtr >&)rec;
                return (hnode.m_value->m_refcount.test_le(1));
            }},
        m_node_size{node_size},
        m_meta_blk{sb.first} {
    start_flush_threads();

    // We need to register the consumer first before recovery, so that recovery can use the cp_ctx created to add/track
    // recovered new nodes.
    hs()->cp_mgr().register_consumer(cp_consumer_t::INDEX_SVC, std::move(std::make_unique< IndexCPCallbacks >(this)));
    recover_new_nodes(std::move(sb.second));
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
        iomanager.create_reactor("index_cp_flush" + std::to_string(i), iomgr::INTERRUPT_LOOP, 1u,
                                 [this, ctx](bool is_started) {
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
        ctx->cv.wait(lk, [ctx, nthreads] { return (ctx->thread_cnt == nthreads); });
    }
}

void IndexWBCache::recover_new_nodes(sisl::byte_view sb) {
    // If sb is empty, its possible a first time boot.
    if ((sb.bytes() == nullptr) || (sb.size() == 0)) { return; }

    auto cpg = hs()->cp_mgr().cp_guard();
    auto cp_ctx = r_cast< IndexCPContext* >(cpg.context(cp_consumer_t::INDEX_SVC));
    cp_id_t cur_cp_id = cpg->id();

    auto const* new_blks_sb = r_cast< IndexCPContext::new_blks_sb_t const* >(sb.bytes());
    if (new_blks_sb->cp_id != cur_cp_id) {
        // On clean shutdown, cp_id would be lesser than the current cp_id, in that case ignore this sb
        HS_DBG_ASSERT_LT(new_blks_sb->cp_id, cur_cp_id, "Persisted cp in wbcache_sb is more than current cp");
        return;
    }

    LOGINFOMOD(wbcache, "Prior to restart allocated {} new blks, validating if they need to be persisted",
               new_blks_sb->num_blks);

    std::unordered_map< BlkId, sisl::io_blob_safe > cached_inplace_nodes;
    for (auto i = 0u; i < new_blks_sb->num_blks; ++i) {
        auto const& [inplace_p, new_p] = new_blks_sb->blks[i];
        auto const inplace_blkid = BlkId{inplace_p.first, (blk_count_t)1, inplace_p.second};
        auto const new_blkid = BlkId{new_p.first, (blk_count_t)1, new_p.second};

        // Read the new btree node
        sisl::io_blob_safe node_buf(m_node_size, 512);
        m_vdev->sync_read(r_cast< char* >(node_buf.bytes()), m_node_size, new_blkid);

        // Invalid node indicates it was never written during cp_flush prior to unclean shutdown, ignore the blkid
        if (!IndexTableBase::is_valid_btree_node(node_buf)) { continue; }

        // Read the inplace node and find out if they have same cp_id as new_blks. If so, the inplace node is also
        // written and in that case the new_node should be retained. It means the first part of dependency chain was
        // already persisted prior to unclean shutdown. If its not written, we can discard the new_node.
        // Note: There can be multiple new_blks point to the same in-place node, so we keep them cached.
        auto it = cached_inplace_nodes.find(inplace_blkid);
        if (it == cached_inplace_nodes.end()) {
            sisl::io_blob_safe inplace_buf(m_node_size, 512);
            m_vdev->sync_read(r_cast< char* >(inplace_buf.bytes()), m_node_size, inplace_blkid);

            if (!IndexTableBase::is_valid_btree_node(inplace_buf)) {
                HS_LOG_ASSERT(false, "Inplace node is invalid btree node at blkid={}, should not happen",
                              inplace_blkid);
                continue;
            }
            bool happened;
            std::tie(it, happened) =
                cached_inplace_nodes.emplace(std::make_pair(inplace_blkid, std::move(inplace_buf)));
        }

        if (IndexTableBase::modified_cp_id(it->second) == cur_cp_id) {
            LOGDEBUGMOD(wbcache, "Inplace node={} has been written prior to unclean shutdown, retaining new_node={} ",
                        inplace_blkid.to_string(), new_blkid.to_string());
            // Put them in current cp, to support unclean shutdown during recovery
            cp_ctx->track_new_blk(inplace_blkid, new_blkid);
            m_vdev->commit_blk(new_blkid);
        } else {
            LOGDEBUGMOD(wbcache, "Inplace node={} was not written prior to unclean shutdowm, so discarding new_node={}",
                        inplace_blkid.to_string(), new_blkid.to_string());
        }
    }
}

BtreeNodePtr IndexWBCache::alloc_buf(node_initializer_t&& node_initializer) {
    auto cpg = hs()->cp_mgr().cp_guard();
    auto cp_ctx = r_cast< IndexCPContext* >(cpg.context(cp_consumer_t::INDEX_SVC));

    // Alloc a block of data from underlying vdev
    BlkId blkid;
    auto ret = m_vdev->alloc_contiguous_blks(1, blk_alloc_hints{}, blkid);
    if (ret != BlkAllocStatus::SUCCESS) { return nullptr; }

    // Alloc buffer and initialize the node
    auto idx_buf = std::make_shared< IndexBuffer >(blkid, m_node_size, m_vdev->align_size());
    idx_buf->m_created_cp_id = cpg->id();
    idx_buf->m_dirtied_cp_id = cpg->id();
    auto node = node_initializer(idx_buf);

    // Add the node to the cache
    bool done = m_cache.insert(node);
    HS_REL_ASSERT_EQ(done, true, "Unable to add alloc'd node to cache, low memory or duplicate inserts?");

    // The entire index is updated in the commit path, so we alloc the blk and commit them right away
    auto alloc_status = m_vdev->commit_blk(blkid);
    // if any error happens when committing the blk to index service, we should assert and crash
    if (alloc_status != BlkAllocStatus::SUCCESS) HS_REL_ASSERT(0, "Failed to commit blk: {}", blkid.to_string());
    return node;
}

void IndexWBCache::write_buf(const BtreeNodePtr& node, const IndexBufferPtr& buf, CPContext* cp_ctx) {
    // TODO upsert always returns false even if it succeeds.
    if (node != nullptr) { m_cache.upsert(node); }
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
    m_vdev->sync_read(r_cast< char* >(idx_buf->raw_buffer()), m_node_size, blkid);

    // Create the btree node out of buffer
    node = node_initializer(idx_buf);

    // Push the node into cache
    bool done = m_cache.insert(node);
    if (!done) {
        // There is a race between 2 concurrent reads from vdev and other party won the race. Re-read from cache
        goto retry;
    }
}

bool IndexWBCache::get_writable_buf(const BtreeNodePtr& node, CPContext* context) {
    IndexCPContext* icp_ctx = r_cast< IndexCPContext* >(context);
    auto& idx_buf = IndexBtreeNode::convert(node.get())->m_idx_buf;
    if (idx_buf->m_dirtied_cp_id == icp_ctx->id()) {
        return true; // For same cp, we don't need a copy, we can rewrite on the same buffer
    } else if (idx_buf->m_dirtied_cp_id > icp_ctx->id()) {
        return false; // We are asked to provide the buffer of an older CP, which is not possible
    }

    // If buffer is in clean state, which means it is already flushed, we can reuse the same buffer, if not
    // we must copy the buffer and return the new buffer.
    if (!idx_buf->is_clean()) {
        HS_DBG_ASSERT_EQ(idx_buf->m_dirtied_cp_id, icp_ctx->id() - 1,
                         "Buffer is dirty, but its dirtied_cp_id is neither current nor previous cp id");

        // If its not clean, we do deep copy.
        auto new_buf = std::make_shared< IndexBuffer >(idx_buf->m_blkid, m_node_size, m_vdev->align_size());
        std::memcpy(new_buf->raw_buffer(), idx_buf->raw_buffer(), m_node_size);

        node->update_phys_buf(new_buf->raw_buffer());
        LOGTRACEMOD(wbcache, "cp={} cur_buf={} for node={} is dirtied by cp={} copying new_buf={}", icp_ctx->id(),
                    static_cast< void* >(idx_buf.get()), node->node_id(), idx_buf->m_dirtied_cp_id,
                    static_cast< void* >(new_buf.get()));
        idx_buf = std::move(new_buf);
    }
    idx_buf->m_dirtied_cp_id = icp_ctx->id();
    return true;
}

void IndexWBCache::link_buf(IndexBufferPtr& up_buf, IndexBufferPtr& down_buf, CPContext* cp_ctx) {
    HS_DBG_ASSERT_NE((void*)up_buf->m_up_buffer.lock().get(), (void*)down_buf.get(), "Cyclic dependency detected");
    IndexBufferPtr real_up_buf = up_buf;
    IndexCPContext* icp_ctx = r_cast< IndexCPContext* >(cp_ctx);

    if (down_buf->m_up_buffer.lock() == up_buf) {
        // Already linked, nothing to do
        HS_DBG_ASSERT(!up_buf->m_wait_for_down_buffers.testz(),
                      "Up buffer waiting count is zero, whereas down buf is already linked to up buf");
        HS_DBG_ASSERT_EQ(up_buf->m_dirtied_cp_id, down_buf->m_dirtied_cp_id,
                         "Up buffer is not modified by current cp, but down buffer is linked to it");
#ifndef NDEBUG
        bool found{false};
        for (auto const& dbuf : up_buf->m_down_buffers) {
            if (dbuf.lock() == down_buf) {
                found = true;
                break;
            }
        }
        HS_DBG_ASSERT(found, "Down buffer is linked to Up buf, but up_buf doesn't have down_buf in its list");
#endif
        return;
    }

    // If down_buf is created as part of this cp_id, its a new buffer and we need to track the new blks, so that upon
    // recovery we can pre-commit these new blkids.
    if (down_buf->m_created_cp_id == icp_ctx->id()) {
        // If the up buffer is also a new buffer created as part of cp, we need to link it with real up buffer, which
        // was created part of earlier cps.
        if (up_buf->m_created_cp_id == cp_ctx->id()) {
            real_up_buf = up_buf->m_up_buffer.lock();
            HS_DBG_ASSERT(real_up_buf, "Up buffer is new buffer, but it doesn't have parent buffer, its not expected");
            icp_ctx->track_new_blk(real_up_buf->m_blkid, down_buf->m_blkid);
        }
    }

    // Now we link the child to the real parent
    real_up_buf->m_wait_for_down_buffers.increment(1);
    down_buf->m_up_buffer = real_up_buf;
#ifndef NDEBUG
    real_up_buf->m_down_buffers.emplace_back(down_buf);
#endif
}

void IndexWBCache::free_buf(const IndexBufferPtr& buf, CPContext* cp_ctx) {
    BtreeNodePtr node;
    bool done = m_cache.remove(buf->m_blkid, node);
    HS_REL_ASSERT_EQ(done, true, "Race on cache removal of btree blkid?");

    resource_mgr().inc_free_blk(m_node_size);
    m_vdev->free_blk(buf->m_blkid, s_cast< VDevCPContext* >(cp_ctx));
}

//////////////////// CP Related API section /////////////////////////////////

folly::Future< bool > IndexWBCache::async_cp_flush(IndexCPContext* cp_ctx) {
    LOGTRACEMOD(wbcache, "cp_ctx {}", cp_ctx->to_string());
    if (!cp_ctx->any_dirty_buffers()) {
        CP_PERIODIC_LOG(DEBUG, cp_ctx->id(), "Btree does not have any dirty buffers to flush");
        return folly::makeFuture< bool >(true); // nothing to flush
    }

    // First thing is to flush the new_blks created as part of the CP.
    auto const& new_blk_sb_buf = cp_ctx->new_blk_buf();
    if (m_meta_blk) {
        meta_service().update_sub_sb(new_blk_sb_buf.cbytes(), new_blk_sb_buf.size(), m_meta_blk);
    } else {
        meta_service().add_sub_sb("wb_cache", new_blk_sb_buf.cbytes(), new_blk_sb_buf.size(), m_meta_blk);
    }

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
    return std::move(cp_ctx->get_future());
}

void IndexWBCache::do_flush_one_buf(IndexCPContext* cp_ctx, IndexBufferPtr buf, bool part_of_batch) {
    LOGTRACEMOD(wbcache, "cp {} buf {}", cp_ctx->id(), buf->to_string());
    buf->set_state(index_buf_state_t::FLUSHING);

#ifdef _PRERELEASE

    if (cp_ctx->is_abrupt()) {
        LOGTRACEMOD(wbcache, "The cp {} is abrupt! for {}", cp_ctx->id(), BtreeNode::to_string_buf(buf->raw_buffer()));
        LOGINFO("The cp {} is abrupt! for {}", cp_ctx->id(), BtreeNode::to_string_buf(buf->raw_buffer()));
        return;
    }
    if (auto it = crashing_buffers.find(buf); it != crashing_buffers.end()) {
        const auto& reasons = it->second;
        std::string formatted_reasons = fmt::format("[{}]", fmt::join(reasons, ", "));
        LOGTRACEMOD(wbcache, "Buffer {} is in crashing_buffers with reason(s): {} - Buffer info: {}", buf->to_string(),
                    formatted_reasons, BtreeNode::to_string_buf(buf->raw_buffer()));
        LOGINFO("Buffer {} is in crashing_buffers with reason(s): {} - Buffer info: {}", buf->to_string(),
                formatted_reasons, BtreeNode::to_string_buf(buf->raw_buffer()));
        LOGINFO(" CP context info: {}", cp_ctx->to_string());
        crashing_buffers.clear();
        cp_ctx->abrupt();
        return;
    }
#endif
    LOGTRACEMOD(wbcache, "flushing cp {} buf {} info: {}", cp_ctx->id(), buf->to_string(),
                BtreeNode::to_string_buf(buf->raw_buffer()));
    m_vdev->async_write(r_cast< const char* >(buf->raw_buffer()), m_node_size, buf->m_blkid, part_of_batch)
        .thenValue([buf, cp_ctx](auto) {
            auto& pthis = s_cast< IndexWBCache& >(wb_cache()); // Avoiding more than 16 bytes capture
            pthis.process_write_completion(cp_ctx, buf);
        });

    if (!part_of_batch) { m_vdev->submit_batch(); }
}

void IndexWBCache::process_write_completion(IndexCPContext* cp_ctx, IndexBufferPtr buf) {
    LOGTRACEMOD(wbcache, "cp {} buf {}", cp_ctx->id(), buf->to_string());
    resource_mgr().dec_dirty_buf_size(m_node_size);
    auto [next_buf, has_more] = on_buf_flush_done(cp_ctx, buf);
    if (next_buf) {
        do_flush_one_buf(cp_ctx, next_buf, false);
    } else if (!has_more) {
        // We are done flushing the buffers, We flush the vdev to persist the vdev bitmaps and free blks
        // Pick a CP Manager blocking IO fiber to execute the cp flush of vdev
        iomanager.run_on_forget(hs()->cp_mgr().pick_blocking_io_fiber(), [this, cp_ctx]() {
            LOGTRACEMOD(wbcache, "Initiating CP flush");
            m_vdev->cp_flush(cp_ctx); // This is a blocking io call
            cp_ctx->complete(true);
        });
    }
}

std::pair< IndexBufferPtr, bool > IndexWBCache::on_buf_flush_done(IndexCPContext* cp_ctx, IndexBufferPtr& buf) {
    if (m_cp_flush_fibers.size() > 1) {
        std::unique_lock lg(m_flush_mtx);
        return on_buf_flush_done_internal(cp_ctx, buf);
    } else {
        return on_buf_flush_done_internal(cp_ctx, buf);
    }
}

std::pair< IndexBufferPtr, bool > IndexWBCache::on_buf_flush_done_internal(IndexCPContext* cp_ctx,
                                                                           IndexBufferPtr& buf) {
    static thread_local std::vector< IndexBufferPtr > t_buf_list;
#ifndef NDEBUG
    buf->m_down_buffers.clear();
#endif
    buf->set_state(index_buf_state_t::CLEAN);
    t_buf_list.clear();

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

void IndexWBCache::get_next_bufs_internal(IndexCPContext* cp_ctx, uint32_t max_count, IndexBufferPtr prev_flushed_buf,
                                          std::vector< IndexBufferPtr >& bufs) {
    uint32_t count{0};

    // First attempt to execute any follower buffer flush
    if (prev_flushed_buf) {
        auto next_buffer = prev_flushed_buf->m_up_buffer.lock();
        if (next_buffer && next_buffer->m_wait_for_down_buffers.decrement_testz()) {
            HS_DBG_ASSERT(next_buffer->state() == index_buf_state_t::DIRTY,
                          "Trying to flush a parent buffer after child buffer is completed, but parent buffer is "
                          "not in dirty state, but in {} state",
                          (int)next_buffer->state());
            bufs.emplace_back(next_buffer);
            ++count;
        }
    }

    // If we still have room to push the next buffer, take it from the main list
    while (count < max_count) {
        std::optional< IndexBufferPtr > buf = cp_ctx->next_dirty();
        if (!buf) { break; } // End of list

        if ((*buf)->m_wait_for_down_buffers.testz()) {
            bufs.emplace_back(std::move(*buf));
            ++count;
        } else {
            // There is some leader buffer still flushing, once done its completion will flush this buffer
        }
    }
}

IndexBtreeNode* IndexBtreeNode::convert(BtreeNode* bt_node) {
    return r_cast< IndexBtreeNode* >(bt_node->get_node_context());
}
} // namespace homestore
