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
#include "common/homestore_utils.hpp"

#include "wb_cache.hpp"
#include "index_cp.hpp"
#include "device/virtual_dev.hpp"
#include "common/resource_mgr.hpp"

SISL_LOGGING_DECL(wbcache)

namespace homestore {

void usage_log(const IndexBufferPtr& buf, const std::string& msg) {
    /*LOGINFO("{}: Buf={} state={} create/dirty_cp={}/{} down_wait#={} use_count={}", msg,
            voidptr_cast(const_cast< IndexBuffer* >(buf.get())), int_cast(buf->state()), buf->m_created_cp_id,
            buf->m_dirtied_cp_id, buf->m_wait_for_down_buffers.get(), buf.use_count());*/
}

IndexWBCacheBase& wb_cache() { return index_service().wb_cache(); }

IndexWBCache::IndexWBCache(const std::shared_ptr< VirtualDev >& vdev, std::pair< meta_blk*, sisl::byte_view > sb,
                           const std::shared_ptr< sisl::Evictor >& evictor, uint32_t node_size) :
        m_vdev{vdev},
        m_cache{evictor, 100000, node_size,
                [](const BtreeNodePtr& node) -> BlkId {
                    return static_cast< IndexBtreeNode* >(node.get())->m_idx_buf->m_blkid;
                },
                [](const sisl::CacheRecord& rec) -> bool {
                    const auto& hnode = (sisl::SingleEntryHashNode< BtreeNodePtr >&)rec;
                    return (hnode.m_value->m_refcount.test_le(1));
                }},
        m_node_size{node_size},
        m_meta_blk{sb.first} {
    start_flush_threads();

    // We need to register the consumer first before recovery, so that recovery can use the cp_ctx created to add/track
    // recovered new nodes.
    cp_mgr().register_consumer(cp_consumer_t::INDEX_SVC, std::move(std::make_unique< IndexCPCallbacks >(this)));
    recover(std::move(sb.second));
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
    auto cpg = cp_mgr().cp_guard();
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

    usage_log(idx_buf, "After init");

    // The entire index is updated in the commit path, so we alloc the blk and commit them right away
    auto alloc_status = m_vdev->commit_blk(blkid);
    // if any error happens when committing the blk to index service, we should assert and crash
    if (alloc_status != BlkAllocStatus::SUCCESS) HS_REL_ASSERT(0, "Failed to commit blk: {}", blkid.to_string());
    return node;
}

void IndexWBCache::write_buf(const BtreeNodePtr& node, const IndexBufferPtr& buf, CPContext* cp_ctx) {
    // TODO upsert always returns false even if it succeeds.
    if (node != nullptr) {
        m_cache.upsert(node);
        usage_log(buf, "After inserting to cache");
    }
    r_cast< IndexCPContext* >(cp_ctx)->add_to_dirty_list(buf);
    usage_log(buf, "After adding to dirty list");
    resource_mgr().inc_dirty_buf_size(m_node_size);
}

void IndexWBCache::read_buf(bnodeid_t id, BtreeNodePtr& node, node_initializer_t&& node_initializer) {
    auto const blkid = BlkId{id};

retry:
    // Check if the blkid is already in cache, if not load and put it into the cache
    if (m_cache.get(blkid, node)) {
        usage_log(static_cast< IndexBtreeNode* >(node.get())->m_idx_buf, "After read cache hit");
        return;
    }

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
    usage_log(idx_buf, "After read cache miss and insert to cache");
}

bool IndexWBCache::get_writable_buf(const BtreeNodePtr& node, CPContext* context) {
    IndexCPContext* icp_ctx = r_cast< IndexCPContext* >(context);
    auto& idx_buf = static_cast< IndexBtreeNode* >(node.get())->m_idx_buf;
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
        new_buf->m_created_cp_id = idx_buf->m_created_cp_id;
        std::memcpy(new_buf->raw_buffer(), idx_buf->raw_buffer(), m_node_size);

        usage_log(idx_buf, "Forced copy - Current Dirty buf");
        usage_log(new_buf, "Forced copy - New clean buf");

        node->update_phys_buf(new_buf->raw_buffer());
        LOGTRACEMOD(wbcache, "cp={} cur_buf={} for node={} is dirtied by cp={} copying new_buf={}", icp_ctx->id(),
                    static_cast< void* >(idx_buf.get()), node->node_id(), idx_buf->m_dirtied_cp_id,
                    static_cast< void* >(new_buf.get()));
        idx_buf = std::move(new_buf);
    }
    idx_buf->m_dirtied_cp_id = icp_ctx->id();
    return true;
}

bool IndexWBCache::refresh_meta_buf(shared< MetaIndexBuffer >& meta_buf, CPContext* cp_ctx) {
    if (meta_buf->m_dirtied_cp_id > cp_ctx->id()) {
        return false; // meta_buf modified by a newer CP, we shouldn't overwrite that
    } else if (meta_buf->m_dirtied_cp_id == cp_ctx->id()) {
        // Modified by the same cp, no need to create new index buffer, but we only copy the superblk to the buffer
        meta_buf->copy_sb_to_buf();
    } else {
        // We always create a new meta index buffer on every meta buf update, which copies the superblk
        auto new_buf = std::make_shared< MetaIndexBuffer >(meta_buf);
        new_buf->m_dirtied_cp_id = cp_ctx->id();
        write_buf(nullptr, new_buf, cp_ctx);
        meta_buf = new_buf; // Replace the meta_buf with new buf
    }
    return true;
}

#ifdef _PRERELEASE
static void set_crash_flips(IndexBufferPtr const& parent_buf, IndexBufferPtr const& child_buf,
                            IndexBufferPtrList const& new_node_bufs, IndexBufferPtrList const& freed_node_bufs) {
    // TODO: Need an API from flip to quickly check if flip is enabled, so this method doesn't check flip_enabled a
    // bunch of times.
    if ((new_node_bufs.size() == 1) && freed_node_bufs.empty()) {
        // Its a split node situation
        if (iomgr_flip::instance()->test_flip("crash_flush_on_split_at_meta")) {
            if (parent_buf->is_meta_buf()) { parent_buf->set_crash_flag(); }
        } else if (iomgr_flip::instance()->test_flip("crash_flush_on_split_at_root")) {
            if (parent_buf->is_meta_buf()) { child_buf->set_crash_flag(); }
        } else if (iomgr_flip::instance()->test_flip("crash_flush_on_split_at_parent")) {
            parent_buf->set_crash_flag();
        } else if (iomgr_flip::instance()->test_flip("crash_flush_on_split_at_left_child")) {
            child_buf->set_crash_flag();
        } else if (iomgr_flip::instance()->test_flip("crash_flush_on_split_at_right_child")) {
            new_node_bufs[0]->set_crash_flag();
        }
    } else if (!freed_node_bufs.empty() && (new_node_bufs.size() != freed_node_bufs.size())) {
        // Its a merge nodes sitation
        if (iomgr_flip::instance()->test_flip("crash_flush_on_merge_at_meta")) {
            if (parent_buf->is_meta_buf()) { parent_buf->set_crash_flag(); }
        } else if (iomgr_flip::instance()->test_flip("crash_flush_on_merge_at_root")) {
            if (parent_buf->is_meta_buf()) { child_buf->set_crash_flag(); }
        } else if (iomgr_flip::instance()->test_flip("crash_flush_on_merge_at_parent")) {
            parent_buf->set_crash_flag();
        } else if (iomgr_flip::instance()->test_flip("crash_flush_on_merge_at_left_child")) {
            child_buf->set_crash_flag();
        } else if (iomgr_flip::instance()->test_flip("crash_flush_on_merge_at_right_child")) {
            if (!new_node_bufs.empty()) { new_node_bufs[0]->set_crash_flag(); }
        }
    } else if (!freed_node_bufs.empty() && (new_node_bufs.size() == freed_node_bufs.size())) {
        // Its a rebalance node situation
        if (iomgr_flip::instance()->test_flip("crash_flush_on_rebalance_at_meta")) {
            if (parent_buf->is_meta_buf()) { parent_buf->set_crash_flag(); }
        } else if (iomgr_flip::instance()->test_flip("crash_flush_on_rebalance_at_root")) {
            if (parent_buf->is_meta_buf()) { child_buf->set_crash_flag(); }
        } else if (iomgr_flip::instance()->test_flip("crash_flush_on_rebalance_at_parent")) {
            parent_buf->set_crash_flag();
        } else if (iomgr_flip::instance()->test_flip("crash_flush_on_rebalance_at_left_child")) {
            child_buf->set_crash_flag();
        } else if (iomgr_flip::instance()->test_flip("crash_flush_on_rebalance_at_right_child")) {
            if (!new_node_bufs.empty()) { new_node_bufs[0]->set_crash_flag(); }
        }
    }
}
#endif

void IndexWBCache::transact_bufs(uint32_t index_ordinal, IndexBufferPtr const& parent_buf,
                                 IndexBufferPtr const& child_buf, IndexBufferPtrList const& new_node_bufs,
                                 IndexBufferPtrList const& freed_node_bufs, CPContext* cp_ctx) {
    IndexCPContext* icp_ctx = r_cast< IndexCPContext* >(cp_ctx);
    if (parent_buf) { link_buf(parent_buf, child_buf, false /* is_sibling_link */, cp_ctx); }

#ifdef _PRERELEASE
    set_crash_flips(parent_buf, child_buf, new_node_bufs, freed_node_bufs);
#endif

    for (auto const& buf : new_node_bufs) {
        link_buf(child_buf, buf, true /* is_sibling_link */, cp_ctx);
    }

    for (auto const& buf : freed_node_bufs) {
        if (!buf->m_wait_for_down_buffers.testz()) {
            // This buffer has some down bufs depending on it. It can happen for an upper level interior node, where
            // lower level node (say leaf) has split causing it to write entries in this node, but this node is now
            // merging with other node, causing it to free. In these rare instances, we link this node to the new
            // node resulting in waiting for all the down bufs to be flushed before up buf can flush (this buf is
            // not written anyways)
            link_buf(child_buf, buf, true /* is_sibling_link */, cp_ctx);
        }
    }

    icp_ctx->add_to_txn_journal(index_ordinal, child_buf->m_up_buffer,
                                new_node_bufs.size() ? new_node_bufs[0]->m_up_buffer : nullptr, new_node_bufs,
                                freed_node_bufs);
}

void IndexWBCache::link_buf(IndexBufferPtr const& up_buf, IndexBufferPtr const& down_buf, bool is_sibling_link,
                            CPContext* cp_ctx) {
    HS_DBG_ASSERT_NE((void*)up_buf->m_up_buffer.get(), (void*)down_buf.get(), "Cyclic dependency detected");
    IndexBufferPtr real_up_buf = up_buf;
    IndexCPContext* icp_ctx = r_cast< IndexCPContext* >(cp_ctx);

    // Condition 1: If the down buffer and up buffer are both created by the current cp_id, unconditionally we need
    // to link it with up_buffer's up_buffer. In other words, there should never a link between down and up buffers
    // created in current generation (cp). In real terms, it means all new buffers can be flushed independently to
    // each other and dependency is needed only for the buffers created in previous cps.
    if ((down_buf->m_created_cp_id == icp_ctx->id()) && (up_buf->m_created_cp_id == icp_ctx->id())) {
        real_up_buf = up_buf->m_up_buffer;
        HS_DBG_ASSERT(real_up_buf,
                      "Up buffer is newly created in this cp, but it doesn't have its own up_buffer, its not expected");
    }

    // Condition 2: If down_buf already has an up_buf, we can override it newly passed up_buf it only in case of
    // sibling link. Say there is a parent node P1 and child C0, C1 (all 3 created in previous cps). Consider the
    // scenarios
    //
    // Scenario 1: Following thing happens:
    // 1. Child C1 first splits and thus chain will have P1 <-- C1 <-- C2.
    // 2. Child C2 splits further creating C3 and writes to P1, the link_buf(P1, C2, is_sibling=false) will be
    // called first. In this instance, we don't want to break the above chain, because C2 should rely on C1 for its
    // repair. The link_buf calls will be
    //   a) link_buf(P1, C2, is_sibling=false),  => P1 <-- C1 <-- C2 (because C2 has up_buffer C1 and not a sibling
    //   so no override)
    //   b) link_buf(C2, C3, is_sibling=true),   => P1 <--- C1 <-- { C2, C3 } (because of Condition 1,
    //      where C2, C3 are created in this CP, so link C3 with C2's real_up_buf = C2)
    //
    // Scenario 2: Following thing happens:
    // 1. Child C1 first splits and thus chain will have P1 <-- C1 <-- C2.
    // 2. Child C1 merges with C0, which means we create a new node C1' and free C1. The link_buf calls will be
    //    a) link_buf(P1, C0, is_sibling=false),  => P1 <-- C0, C1 <--- C2
    //    b) link_buf(C0, C1', is_sibling=true),  =>
    //                        P1
    //                     C0,   C1
    //                  C1'
    //    c) link_buf(C0, C1, is_sibling=true),   =>
    //                        P1
    //                     C0,
    //                  C1'   C1
    // This link is acheived by unconditionally changing the link in case of is_sibling=true to passed up_buf, but
    // conditionally do it in case of parent link where it already has a link don't override it.
    if (down_buf->m_up_buffer != nullptr) {
        HS_DBG_ASSERT_LT(down_buf->m_up_buffer->m_created_cp_id, icp_ctx->id(),
                         "down_buf=[{}] up_buffer=[{}] should never have been created on same cp",
                         down_buf->to_string(), down_buf->m_up_buffer->to_string());

        if (!is_sibling_link || (down_buf->m_up_buffer == real_up_buf)) {
            // Already linked with same buf or its not a sibling link to override, nothing to do other than asserts
            real_up_buf = down_buf->m_up_buffer;
            HS_DBG_ASSERT(!real_up_buf->m_wait_for_down_buffers.testz(),
                          "Up buffer waiting count is zero, whereas down buf is already linked to up buf");
            HS_DBG_ASSERT((real_up_buf->m_dirtied_cp_id == down_buf->m_dirtied_cp_id) || (real_up_buf->is_meta_buf()),
                          "Up buffer is not modified by current cp, but down buffer is linked to it");
#ifndef NDEBUG
            bool found{false};
            for (auto const& dbuf : real_up_buf->m_down_buffers) {
                if (dbuf.lock() == down_buf) {
                    found = true;
                    break;
                }
            }
            HS_DBG_ASSERT(found, "Down buffer is linked to Up buf, but up_buf doesn't have down_buf in its list");
#endif
            return;
        }
    }

    // Now we link the down_buffer to the real up_buffer
    real_up_buf->m_wait_for_down_buffers.increment(1);
    down_buf->m_up_buffer = real_up_buf;
#ifndef NDEBUG
    real_up_buf->m_down_buffers.emplace_back(down_buf);
#endif

    usage_log(real_up_buf, "After link buf - Up buf");
    usage_log(down_buf, "After link buf - Down buf");
}

void IndexWBCache::free_buf(const IndexBufferPtr& buf, CPContext* cp_ctx) {
    BtreeNodePtr node;
    bool done = m_cache.remove(buf->m_blkid, node);
    HS_REL_ASSERT_EQ(done, true, "Race on cache removal of btree blkid?");
    usage_log(buf, "After free buf - remove from cache");

    resource_mgr().inc_free_blk(m_node_size);
    m_vdev->free_blk(buf->m_blkid, s_cast< VDevCPContext* >(cp_ctx));
}

//////////////////// Recovery Related section /////////////////////////////////
void IndexWBCache::recover(sisl::byte_view sb) {
    // If sb is empty, its possible a first time boot.
    if ((sb.bytes() == nullptr) || (sb.size() == 0)) { return; }

    // Recover the CP Context with the buf_map of all the buffers that were dirtied in the last cp with its
    // relationship (up/down buf links) as it was by the cp that was flushing the buffers prior to unclean shutdown.
    auto cpg = cp_mgr().cp_guard();
    auto icp_ctx = r_cast< IndexCPContext* >(cpg.context(cp_consumer_t::INDEX_SVC));
    std::map< BlkId, IndexBufferPtr > bufs = icp_ctx->recover(std::move(sb));

    // With all the buffers recovered, we first make the decision of which blk to keep and which blk to free. This
    // is needed so that subsequent repair can do blk allocation and shouldn't incorrectly allocate the blks which
    // are going to be committed later.
    std::vector< IndexBufferPtr > new_bufs;
    for (auto const& [_, buf] : bufs) {
        if (buf->m_node_freed) {
            // If the node was freed according txn records, we need to check if up_buf node was also written
            if (was_node_committed(buf->m_up_buffer)) {
                // Up buffer was written, so this buffer can be freed and thus can free the blk.
                m_vdev->free_blk(buf->m_blkid, s_cast< VDevCPContext* >(icp_ctx));
            }
            buf->m_up_buffer->m_wait_for_down_buffers.decrement();
        } else if (buf->m_created_cp_id == icp_ctx->id()) {
            if (was_node_committed(buf) && was_node_committed(buf->m_up_buffer)) {
                // The buffer was newly created on this cp, and its up_buffer is also written, we need to commit
                // this blk again, so that it will not be reallocated for other node during repair.
                m_vdev->commit_blk(buf->m_blkid);
                new_bufs.push_back(buf);
            }
        }
    }

    // Second iteration we start from the lowest levels (which are all new_bufs) and check if up_buffers need to be
    // repaired. All L1 buffers are not needed to repair, because they are sibling nodes and so we pass false in
    // do_repair flag.
    for (auto const& buf : new_bufs) {
        process_up_buf(buf->m_up_buffer, false /* do_repair */);
    }
}

void IndexWBCache::process_up_buf(IndexBufferPtr const& buf, bool do_repair) {
    if (do_repair) {
        // If the buffer needs to be repaired, reset the dirtied_cp_id so once all down buffers are done, it does
        // repair
        buf->m_dirtied_cp_id = -1;
    }

    if (!buf->m_wait_for_down_buffers.decrement_testz()) { return; }

    // One of the down buffer indicated that it has to repair our node, so we issue a repair
    if (buf->m_dirtied_cp_id == -1) { index_service().repair_index_node(buf->m_index_ordinal, buf); }

    // If there is an up buffer on next level, we need to process them and ask them to repair in case they were not
    // written as part of this CP.
    if (buf->m_up_buffer) {
        if (buf->m_up_buffer->is_meta_buf()) {
            // If the up_buf is meta buffer, then we found the new root, repair the current node accordingly
            index_service().repair_index_root(buf->m_index_ordinal, buf);
        } else {
            process_up_buf(buf->m_up_buffer, !was_node_committed(buf->m_up_buffer));
        }
    }
}

bool IndexWBCache::was_node_committed(IndexBufferPtr const& buf) {
    if (buf == nullptr) { return false; }

    // If the node is freed, then it can be considered committed as long as its up buffer was committed
    if (buf->m_node_freed) {
        HS_DBG_ASSERT(buf->m_up_buffer, "Buf was marked deleted, but doesn't have an up_buffer");
        return was_node_committed(buf->m_up_buffer);
    }

    // All down_buf has indicated that they have seen this up buffer, now its time to repair them.
    if (buf->m_bytes == nullptr) {
        // Read the btree node and get its modified cp_id
        buf->m_bytes = hs_utils::iobuf_alloc(m_node_size, sisl::buftag::btree_node, m_vdev->align_size());
        m_vdev->sync_read(r_cast< char* >(buf->m_bytes), m_node_size, buf->blkid());
        if (!BtreeNode::is_valid_node(sisl::blob{buf->m_bytes, m_node_size})) { return false; }

        buf->m_dirtied_cp_id = BtreeNode::get_modified_cp_id(buf->m_bytes);
    }
    auto cpg = cp_mgr().cp_guard();
    return (buf->m_dirtied_cp_id == cpg->id());
}

//////////////////// CP Related API section /////////////////////////////////
folly::Future< bool > IndexWBCache::async_cp_flush(IndexCPContext* cp_ctx) {
    LOGTRACEMOD(wbcache, "cp_ctx {}", cp_ctx->to_string());
    if (!cp_ctx->any_dirty_buffers()) {
        CP_PERIODIC_LOG(DEBUG, cp_ctx->id(), "Btree does not have any dirty buffers to flush");
        return folly::makeFuture< bool >(true); // nothing to flush
    }

    // First thing is to flush the new_blks created as part of the CP.
    auto const& journal_buf = cp_ctx->journal_buf();
    if (m_meta_blk) {
        meta_service().update_sub_sb(journal_buf.cbytes(), journal_buf.size(), m_meta_blk);
    } else {
        meta_service().add_sub_sb("wb_cache", journal_buf.cbytes(), journal_buf.size(), m_meta_blk);
    }

    cp_ctx->prepare_flush_iteration();

    for (auto& fiber : m_cp_flush_fibers) {
        iomanager.run_on_forget(fiber, [this, cp_ctx]() {
            IndexBufferPtrList buf_list;
            get_next_bufs(cp_ctx, resource_mgr().get_dirty_buf_qd(), buf_list);

            for (auto& buf : buf_list) {
                do_flush_one_buf(cp_ctx, buf, true);
            }
            m_vdev->submit_batch();
        });
    }
    return std::move(cp_ctx->get_future());
}

void IndexWBCache::do_flush_one_buf(IndexCPContext* cp_ctx, IndexBufferPtr const& buf, bool part_of_batch) {
    LOGTRACEMOD(wbcache, "cp {} buf {}", cp_ctx->id(), buf->to_string());
    buf->set_state(index_buf_state_t::FLUSHING);

#ifdef _PRERELEASE
    if (auto it = crashing_buffers.find(buf); it != crashing_buffers.end()) {
        const auto& reasons = it->second;
        LOGTRACEMOD(wbcache, "Buffer {} is in crashing_buffers with reason(s): [{}] - Buffer info: {}",
                    buf->to_string(), fmt::join(reasons, ", "), BtreeNode::to_string_buf(buf->raw_buffer()));
        crashing_buffers.clear();
        return;
    }
#endif
    if (buf->is_meta_buf()) {
        LOGTRACEMOD(wbcache, "flushing cp {} meta buf {} possibly because of root split", cp_ctx->id(),
                    buf->to_string());
        auto const& sb = r_cast< MetaIndexBuffer* >(buf.get())->m_sb;
        meta_service().update_sub_sb(buf->m_bytes, sb.size(), sb.meta_blk());
        process_write_completion(cp_ctx, buf);
    } else if (buf->m_node_freed) {
        LOGTRACEMOD(wbcache, "Not flushing buf {} as it was freed, its here for merely dependency", cp_ctx->id(),
                    buf->to_string());
        process_write_completion(cp_ctx, buf);
    } else {
        LOGTRACEMOD(wbcache, "flushing cp {} buf {} info: {}", cp_ctx->id(), buf->to_string(),
                    BtreeNode::to_string_buf(buf->raw_buffer()));
        usage_log(buf, "After issuing flush");
        m_vdev->async_write(r_cast< const char* >(buf->raw_buffer()), m_node_size, buf->m_blkid, part_of_batch)
            .thenValue([buf, cp_ctx](auto) {
                auto& pthis = s_cast< IndexWBCache& >(wb_cache()); // Avoiding more than 16 bytes capture
                pthis.process_write_completion(cp_ctx, buf);
            });

        if (!part_of_batch) { m_vdev->submit_batch(); }
    }
}

void IndexWBCache::process_write_completion(IndexCPContext* cp_ctx, IndexBufferPtr const& buf) {
    LOGTRACEMOD(wbcache, "cp {} buf {}", cp_ctx->id(), buf->to_string());
    resource_mgr().dec_dirty_buf_size(m_node_size);
    auto [next_buf, has_more] = on_buf_flush_done(cp_ctx, buf);
    if (next_buf) {
        do_flush_one_buf(cp_ctx, next_buf, false);
    } else if (!has_more) {
        // We are done flushing the buffers, We flush the vdev to persist the vdev bitmaps and free blks
        // Pick a CP Manager blocking IO fiber to execute the cp flush of vdev
        iomanager.run_on_forget(cp_mgr().pick_blocking_io_fiber(), [this, cp_ctx]() {
            LOGTRACEMOD(wbcache, "Initiating CP flush");
            m_vdev->cp_flush(cp_ctx); // This is a blocking io call
            cp_ctx->complete(true);
        });
    }
}

std::pair< IndexBufferPtr, bool > IndexWBCache::on_buf_flush_done(IndexCPContext* cp_ctx, IndexBufferPtr const& buf) {
    if (m_cp_flush_fibers.size() > 1) {
        std::unique_lock lg(m_flush_mtx);
        return on_buf_flush_done_internal(cp_ctx, buf);
    } else {
        return on_buf_flush_done_internal(cp_ctx, buf);
    }
}

std::pair< IndexBufferPtr, bool > IndexWBCache::on_buf_flush_done_internal(IndexCPContext* cp_ctx,
                                                                           IndexBufferPtr const& buf) {
    IndexBufferPtrList buf_list;
#ifndef NDEBUG
    buf->m_down_buffers.clear();
#endif
    buf->set_state(index_buf_state_t::CLEAN);

    usage_log(buf, "After finishing flush");
    if (cp_ctx->m_dirty_buf_count.decrement_testz()) {
        return std::make_pair(nullptr, false);
    } else {
        get_next_bufs_internal(cp_ctx, 1u, buf, buf_list);
        return std::make_pair((buf_list.size() ? buf_list[0] : nullptr), true);
    }
}

void IndexWBCache::get_next_bufs(IndexCPContext* cp_ctx, uint32_t max_count, IndexBufferPtrList& bufs) {
    if (m_cp_flush_fibers.size() > 1) {
        std::unique_lock lg(m_flush_mtx);
        get_next_bufs_internal(cp_ctx, max_count, nullptr, bufs);
    } else {
        get_next_bufs_internal(cp_ctx, max_count, nullptr, bufs);
    }
}

void IndexWBCache::get_next_bufs_internal(IndexCPContext* cp_ctx, uint32_t max_count,
                                          IndexBufferPtr const& prev_flushed_buf, IndexBufferPtrList& bufs) {
    uint32_t count{0};

    // First attempt to execute any follower buffer flush
    if (prev_flushed_buf) {
        auto next_buffer = prev_flushed_buf->m_up_buffer;
        if (next_buffer && next_buffer->m_wait_for_down_buffers.decrement_testz()) {
            HS_DBG_ASSERT(next_buffer->state() == index_buf_state_t::DIRTY,
                          "Trying to flush a up_buffer after down buffer is completed, but up_buffer is "
                          "not in dirty state, but in {} state",
                          (int)next_buffer->state());
            bufs.emplace_back(next_buffer);
            ++count;
        }
#ifndef NDEBUG
        // Retain prev up buffer for debugging purposes
        // prev_flushed_buf->m_prev_up_buffer = std::move(next_buffer);
#endif
        prev_flushed_buf->m_up_buffer.reset();
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

/*
IndexBtreeNode* IndexBtreeNode::convert(BtreeNode* bt_node) {
    return r_cast< IndexBtreeNode* >(bt_node->get_node_context());
}*/
} // namespace homestore
