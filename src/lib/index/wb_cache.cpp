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

IndexWBCache::IndexWBCache(const std::shared_ptr< VirtualDev >& vdev, const std::shared_ptr< sisl::Evictor >& evictor,
                           uint32_t node_size) :
        m_vdev{vdev},
        m_cache{
            evictor, 100000, node_size,
            [](const BtreeNodePtr& node) -> BlkId { return IndexBtreeNode::convert(node.get())->m_idx_buf->m_blkid; },
            [](const sisl::CacheRecord& rec) -> bool {
                const auto& hnode = (sisl::SingleEntryHashNode< BtreeNodePtr >&)rec;
                return (hnode.m_value->m_refcount.test_le(1));
            }},
        m_node_size{node_size} {
    start_flush_threads();
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

BtreeNodePtr IndexWBCache::alloc_buf(node_initializer_t&& node_initializer) {
    // Alloc a block of data from underlying vdev
    BlkId blkid;
    auto ret = m_vdev->alloc_contiguous_blks(1, blk_alloc_hints{}, blkid);
    if (ret != BlkAllocStatus::SUCCESS) { return nullptr; }

    // Alloc buffer and initialize the node
    auto idx_buf = std::make_shared< IndexBuffer >(blkid, m_node_size, m_vdev->align_size());
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

void IndexWBCache::realloc_buf(const IndexBufferPtr& buf) {
    // Commit the blk which was previously allocated
    auto alloc_status = m_vdev->commit_blk(buf->m_blkid);
    if (alloc_status != BlkAllocStatus::SUCCESS) HS_REL_ASSERT(0, "Failed to commit blk: {}", buf->m_blkid.to_string());
}

void IndexWBCache::write_buf(const BtreeNodePtr& node, const IndexBufferPtr& buf, CPContext* cp_ctx) {
    // TODO upsert always returns false even if it succeeds.
    m_cache.upsert(node);
    r_cast< IndexCPContext* >(cp_ctx)->add_to_dirty_list(buf);
    resource_mgr().inc_dirty_buf_size(m_node_size);
}

IndexBufferPtr IndexWBCache::copy_buffer(const IndexBufferPtr& cur_buf, const CPContext* cp_ctx) const {
    IndexBufferPtr new_buf = nullptr;
    bool copied = false;

    // When we copy the buffer we check if the node buffer is clean or not. If its clean
    // we could reuse it otherwise create a copy.
    if (cur_buf->is_clean()) {
        // Refer to the same node buffer.
        new_buf = std::make_shared< IndexBuffer >(cur_buf->m_node_buf, cur_buf->m_blkid);
    } else {
        // If its not clean, we do deep copy.
        new_buf = std::make_shared< IndexBuffer >(cur_buf->m_blkid, m_node_size, m_vdev->align_size());
        std::memcpy(new_buf->raw_buffer(), cur_buf->raw_buffer(), m_node_size);
        copied = true;
    }

    LOGTRACEMOD(wbcache, "cp {} new_buf {} cur_buf {} cur_buf_blkid {} copied {}", cp_ctx->id(),
                static_cast< void* >(new_buf.get()), static_cast< void* >(cur_buf.get()), cur_buf->m_blkid.to_integer(),
                copied);
    return new_buf;
}

std::pair<bnodeid_t, uint64_t> IndexWBCache::get_root(bnodeid_t super_node_id) {
    LOGINFO("read bufeer id {}", super_node_id);
    auto const blkid = BlkId{super_node_id};
    auto idx_buf = std::make_shared< IndexBuffer >(blkid, m_node_size, m_vdev->align_size());
    auto raw_buf = idx_buf->raw_buffer();

    m_vdev->sync_read(r_cast< char* >(raw_buf), m_node_size, blkid);
    LOGINFO("\n\n\n raw buf  {}", BtreeNode::to_string_buf(idx_buf->raw_buffer()));
    auto root_info = BtreeNode::identify_edge_info(idx_buf->raw_buffer());

    return {root_info.m_bnodeid, root_info.m_link_version};

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
#ifdef _PRERELEASE
void IndexWBCache::add_to_crashing_buffers(IndexBufferPtr buf, std::string reason) {
    std::unique_lock lg(flip_mtx);
    this->crashing_buffers[buf].push_back(reason);
}
#endif
std::pair< bool, bool > IndexWBCache::create_chain(IndexBufferPtr& second, IndexBufferPtr& third, CPContext* cp_ctx) {
    bool second_copied{false}, third_copied{false};
    auto chain = second;
    auto old_third = third;
    if (!second->is_clean()) {
        auto new_second = copy_buffer(second, cp_ctx);
        chain = second;
        second = new_second;
        second_copied = true;
    }

    if (!third->is_clean()) {
        auto new_third = copy_buffer(third, cp_ctx);
        chain = third;
        third = new_third;
        third_copied = true;
    }

    // Append parent(third) to the left child(second).
    second->m_next_buffer = third;
    third->m_wait_for_leaders.increment(1);
    if (second_copied || third_copied) {
        // We want buffers to be append to the end of the chain which are related.
        // If we split a node multiple times in same or different CP's, each dirty buffer will be
        // added to the end of that chain. Whichever dependent buffer is dirty, we add this
        // parent-left combination to the end of that chain.
        while (chain->m_next_buffer.lock() != nullptr) {
            chain = chain->m_next_buffer.lock();
        }

        chain->m_next_buffer = second;
        second->m_wait_for_leaders.increment(1);
    }

    return {second_copied, third_copied};
}

void IndexWBCache::prepend_to_chain(const IndexBufferPtr& first, const IndexBufferPtr& second) {
    assert(first->m_next_buffer.lock() != second);
    assert(first->m_next_buffer.lock() == nullptr);
    first->m_next_buffer = second;
    second->m_wait_for_leaders.increment(1);
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

#ifndef NDEBUG
    // Check no cycles or invalid wait_for_leader count in the dirty buffer
    // dependency graph.
    // cp_ctx->check_wait_for_leaders();
    // cp_ctx->check_cycle();
#endif

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
    if (auto it = crashing_buffers.find(buf);it != crashing_buffers.end()) {
        const auto& reasons = it->second;
                std::string formatted_reasons = fmt::format("[{}]", fmt::join(reasons, ", "));
        LOGTRACEMOD(wbcache, "Buffer {} is in crashing_buffers with reason(s): {} - Buffer info: {}",
                    buf->to_string(), formatted_reasons, BtreeNode::to_string_buf(buf->raw_buffer()));
        LOGINFO("Buffer {} is in crashing_buffers with reason(s): {} - Buffer info: {}",
                    buf->to_string(), formatted_reasons, BtreeNode::to_string_buf(buf->raw_buffer()));
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
        auto next_buffer = prev_flushed_buf->m_next_buffer.lock();
        if (next_buffer && next_buffer->state() == index_buf_state_t::DIRTY &&
            next_buffer->m_wait_for_leaders.decrement_testz()) {
            bufs.emplace_back(next_buffer);
            ++count;
        }
    }

    // If we still have room to push the next buffer, take it from the main list
    while (count < max_count) {
        std::optional< IndexBufferPtr > buf = cp_ctx->next_dirty();
        if (!buf) { break; } // End of list

        if ((*buf)->m_wait_for_leaders.testz()) {
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
