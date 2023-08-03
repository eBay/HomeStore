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

SISL_LOGGING_DECL(wbcache)

namespace homestore {

IndexWBCache& wb_cache() { return index_service().wb_cache(); }

IndexWBCache::IndexWBCache(const std::shared_ptr< VirtualDev >& vdev, const std::shared_ptr< sisl::Evictor >& evictor,
                           uint32_t node_size) :
        m_vdev{vdev},
        m_cache{
            evictor, 1000000, node_size,
            [](const BtreeNodePtr& node) -> BlkId { return IndexBtreeNode::convert(node.get())->m_idx_buf->m_blkid; },
            [](const sisl::CacheRecord& rec) -> bool {
                const auto& hnode = (sisl::SingleEntryHashNode< BtreeNodePtr >&)rec;
                return (hnode.m_value->m_refcount.test_le(1));
            }},
        m_node_size{node_size} {
    start_flush_threads();
    for (size_t i{0}; i < MAX_CP_COUNT; ++i) {
        m_dirty_list[i] = std::make_unique< sisl::ThreadVector< IndexBufferGroupPtr > >();
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
    LOGTRACEMOD(wbcache, "idx_buf {} blkid {}", static_cast< void* >(idx_buf.get()), blkid.to_integer());

    // Add the node to the cache
    bool done = m_cache.insert(node);
    HS_REL_ASSERT_EQ(done, true, "Unable to add alloc'd node to cache, low memory or duplicate inserts?");
    return node;
}

void IndexWBCache::realloc_buf(const IndexBufferPtr& buf) {
    // Commit the blk which was previously allocated
    m_vdev->commit_blk(buf->m_blkid);
}

IndexBufferPtr IndexWBCache::copy_buffer(const IndexBufferPtr& cur_buf) const {
    auto new_buf = std::make_shared< IndexBuffer >(cur_buf->m_blkid, m_node_size, m_vdev->align_size());
    std::memcpy(new_buf->raw_buffer(), cur_buf->raw_buffer(), m_node_size);
    LOGTRACEMOD(wbcache, "new_buf {} cur_buf {} cur_buf_blkid {}", static_cast< void* >(new_buf.get()),
                static_cast< void* >(cur_buf.get()), cur_buf->m_blkid.to_integer());
    return new_buf;
}

void IndexWBCache::write_buf_group(const IndexBufferGroupPtr& buf_group, CPContext* cp_ctx) {
    LOGTRACEMOD(wbcache, "buf_group {}", buf_group->to_string());
    r_cast< IndexCPContext* >(cp_ctx)->add_to_dirty_list(buf_group);
    resource_mgr().inc_dirty_buf_size(buf_group->count() * m_node_size);
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

std::tuple< bool, bool > IndexWBCache::create_chain(IndexBufferPtr& second, IndexBufferPtr& third, CPContext* cp_ctx) {
    bool second_copied{false}, third_copied{false};
    IndexBufferGroupPtr chain_end = second->m_buf_group;

    if (!second->is_clean()) {
        auto new_second = copy_buffer(second);
        LOGTRACEMOD(wbcache, "copied blkid {} second {} new_second {}", second->m_blkid.to_integer(),
                    static_cast< void* >(second.get()), static_cast< void* >(new_second.get()));
        second = new_second;
        second_copied = true;
    }
    if (!third->is_clean()) {
        auto new_third = copy_buffer(third);
        LOGTRACEMOD(wbcache, "copied blkid {} third {} new_third {}", third->m_blkid.to_integer(),
                    static_cast< void* >(third.get()), static_cast< void* >(new_third.get()));
        third = new_third;
        third_copied = true;
    }

    // TODO put left child and parent in same indexbuffergroup.
    auto second_buf_group = std::make_shared< IndexBufferGroup >(second, nullptr);
    second->m_buf_group = second_buf_group;

    auto third_buf_group = std::make_shared< IndexBufferGroup >(third, nullptr);
    third->m_buf_group = third_buf_group;

    prepend_to_chain(second_buf_group, third_buf_group);

    if (chain_end) {
        while (chain_end->m_next_group != nullptr) {
            chain_end = chain_end->m_next_group;
        }

        chain_end->m_next_group = second_buf_group;
        second_buf_group->m_wait_for_leaders.increment(1);
    }

    return {second_copied, third_copied};
}

void IndexWBCache::prepend_to_chain(const IndexBufferGroupPtr& first, const IndexBufferGroupPtr& second) {
    // first is the right child. create a new group with only the right child and
    // depend on the parent-left child group.
    assert(first->m_next_group == nullptr);
    first->m_next_group = second;
    second->m_wait_for_leaders.increment(1);
    LOGTRACEMOD(wbcache, "first {} second {}", first->to_string(), second->to_string());
}

void IndexWBCache::free_buf(const IndexBufferPtr& buf, CPContext* cp_ctx) {
    BtreeNodePtr node;
    bool done = m_cache.remove(buf->m_blkid, node);
    HS_REL_ASSERT_EQ(done, true, "Race on cache removal of btree blkid?");

    resource_mgr().inc_free_blk(m_node_size);
    r_cast< IndexCPContext* >(cp_ctx)->add_to_free_node_list(buf->m_blkid);
}

//////////////////// CP Related API section /////////////////////////////////
folly::Future< bool > IndexWBCache::async_cp_flush(CPContext* context) {
    IndexCPContext* cp_ctx = s_cast< IndexCPContext* >(context);
    LOGTRACEMOD(wbcache, "cp_ctx {}", cp_ctx->to_string());
    if (!cp_ctx->any_dirty_buffers()) {
        CP_PERIODIC_LOG(DEBUG, cp_ctx->id(), "Btree does not have any dirty buffers to flush");
        return folly::makeFuture< bool >(true); // nothing to flush
    }

    cp_ctx->prepare_flush_iteration();

    for (auto& fiber : m_cp_flush_fibers) {
        iomanager.run_on_forget(fiber, [this, cp_ctx]() {
            static thread_local std::vector< IndexBufferGroupPtr > t_buf_group_list;
            t_buf_group_list.clear();
            get_next_buf_groups(cp_ctx, resource_mgr().get_dirty_buf_qd(), t_buf_group_list);

            for (auto& buf_group : t_buf_group_list) {
                do_flush_one_buf_group(cp_ctx, buf_group, true);
            }
            m_vdev->submit_batch();
        });
    }
    return std::move(cp_ctx->get_future());
}

std::unique_ptr< CPContext > IndexWBCache::create_cp_context(cp_id_t cp_id) {
    size_t const cp_id_slot = cp_id % MAX_CP_COUNT;
    return std::make_unique< IndexCPContext >(cp_id, m_dirty_list[cp_id_slot].get(),
                                              m_free_blkid_list[cp_id_slot].get());
}

void IndexWBCache::do_flush_one_buf_group(IndexCPContext* cp_ctx, const IndexBufferGroupPtr& buf_group,
                                          bool part_of_batch) {
    LOGTRACEMOD(wbcache, "buf_group {}", buf_group->to_string());
    auto buf = buf_group->first();
    buf->m_buf_state = index_buf_state_t::FLUSHING;
    m_vdev->async_write(r_cast< const char* >(buf->raw_buffer()), m_node_size, buf->m_blkid, part_of_batch)
        .thenValue([this, buf_group, part_of_batch, cp_ctx](auto) {
            if (!buf_group->second()) { return folly::makeFuture< bool >(true); }

            auto buf = buf_group->second();
            buf->m_buf_state = index_buf_state_t::FLUSHING;
            LOGTRACEMOD(wbcache, "write second {}", buf_group->to_string());
            return m_vdev->async_write(r_cast< const char* >(buf->raw_buffer()), m_node_size, buf->m_blkid,
                                       part_of_batch);
        })
        .thenValue([this, buf_group, cp_ctx](auto) {
            LOGTRACEMOD(wbcache, "done {}", buf_group->to_string());
            auto& pthis = s_cast< IndexWBCache& >(wb_cache()); // Avoiding more than 16 bytes capture
            pthis.process_write_completion(cp_ctx, buf_group);
        });

    if (!part_of_batch) { m_vdev->submit_batch(); }
}

void IndexWBCache::process_write_completion(IndexCPContext* cp_ctx, IndexBufferGroupPtr buf_group) {
    LOGTRACEMOD(wbcache, "buf_group {}", buf_group->to_string());
    resource_mgr().dec_dirty_buf_size(buf_group->count() * m_node_size);
    auto [next_buf_group, has_more] = on_buf_group_flush_done(cp_ctx, buf_group);
    if (next_buf_group) {
        do_flush_one_buf_group(cp_ctx, next_buf_group, false);
    } else if (!has_more) {
        // We are done flushing the buffers, lets free the btree blocks and then flush the bitmap
        free_btree_blks_and_flush(cp_ctx);
    }
}

std::pair< IndexBufferGroupPtr, bool > IndexWBCache::on_buf_group_flush_done(IndexCPContext* cp_ctx,
                                                                             IndexBufferGroupPtr pbuf_group) {
    if (m_cp_flush_fibers.size() > 1) {
        std::unique_lock lg(m_flush_mtx);
        return on_buf_group_flush_done_internal(cp_ctx, pbuf_group);
    } else {
        return on_buf_group_flush_done_internal(cp_ctx, pbuf_group);
    }
}

std::pair< IndexBufferGroupPtr, bool > IndexWBCache::on_buf_group_flush_done_internal(IndexCPContext* cp_ctx,
                                                                                      IndexBufferGroupPtr buf_group) {
    static thread_local std::vector< IndexBufferGroupPtr > t_buf_group_list;
    buf_group->first()->m_buf_state = index_buf_state_t::CLEAN;
    if (buf_group->second()) { buf_group->second()->m_buf_state = index_buf_state_t::CLEAN; }
    t_buf_group_list.clear();

    if (cp_ctx->m_dirty_buf_count.decrement_testz()) {
        return std::make_pair(nullptr, false);
    } else {
        get_next_buf_groups_internal(cp_ctx, 1u, buf_group, t_buf_group_list);
        return std::make_pair((t_buf_group_list.size() ? t_buf_group_list[0] : nullptr), true);
    }
}

void IndexWBCache::get_next_buf_groups(IndexCPContext* cp_ctx, uint32_t max_count,
                                       std::vector< IndexBufferGroupPtr >& buf_groups) {
    if (m_cp_flush_fibers.size() > 1) {
        std::unique_lock lg(m_flush_mtx);
        get_next_buf_groups_internal(cp_ctx, max_count, nullptr, buf_groups);
    } else {
        get_next_buf_groups_internal(cp_ctx, max_count, nullptr, buf_groups);
    }
}

void IndexWBCache::get_next_buf_groups_internal(IndexCPContext* cp_ctx, uint32_t max_count,
                                                IndexBufferGroupPtr prev_flushed_buf_group,
                                                std::vector< IndexBufferGroupPtr >& buf_groups) {
    uint32_t count{0};

    // First attempt to execute any follower buffer flush
    if (prev_flushed_buf_group) {
        auto& next_group = prev_flushed_buf_group->m_next_group;
        if (next_group) {
            if (next_group->m_wait_for_leaders.decrement_testz()) {
                LOGTRACEMOD(wbcache, "added prev_flushed_buf_group {} next_buf {}",
                            static_cast< void* >(prev_flushed_buf_group.get()), static_cast< void* >(next_group.get()));

                buf_groups.emplace_back(next_group);
                ++count;
            }
        }
    }

    // If we still have room to push the next buffer, take it from the main list
    while (count < max_count) {
        IndexBufferGroupPtr* ppbuf = cp_ctx->next_dirty();
        if (ppbuf == nullptr) { break; } // End of list
        IndexBufferGroupPtr group = *ppbuf;
        if (group->m_wait_for_leaders.testz()) {
            buf_groups.emplace_back(std::move(group));
            ++count;
        } else {
            // There is some leader buffer still flushing, once done its completion will flush this buffer
        }
    }
}

void IndexWBCache::free_btree_blks_and_flush(IndexCPContext* cp_ctx) {
    BlkId* pbid;
    while ((pbid = cp_ctx->next_blkid()) != nullptr) {
        m_vdev->free_blk(*pbid);
    }

    // Pick a CP Manager blocking IO fiber to execute the cp flush of vdev
    iomanager.run_on_forget(hs()->cp_mgr().pick_blocking_io_fiber(), [this, cp_ctx]() {
        LOGTRACEMOD(wbcache, "Initiating CP flush");
        m_vdev->cp_flush(); // This is a blocking io call
        cp_ctx->complete(true);
    });
}

IndexBtreeNode* IndexBtreeNode::convert(BtreeNode* bt_node) {
    return r_cast< IndexBtreeNode* >(bt_node->get_node_context());
}
} // namespace homestore
