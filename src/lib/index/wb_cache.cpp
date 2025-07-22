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

#ifdef _PRERELEASE
#include "common/crash_simulator.hpp"
#endif

SISL_LOGGING_DECL(wbcache)

namespace homestore {

IndexWBCacheBase& wb_cache() {
    try {
        return index_service().wb_cache();
    } catch (const std::runtime_error& e) {
        throw std::runtime_error(fmt::format("Failed to access wb_cache: {}", e.what()));
    }
}

IndexWBCache::IndexWBCache(const std::shared_ptr< VirtualDev >& vdev, std::pair< meta_blk*, sisl::byte_view > sb,
                           const std::shared_ptr< sisl::Evictor >& evictor, uint32_t node_size) :
        m_vdev{vdev},
        m_cache{evictor, HS_DYNAMIC_CONFIG(generic.cache_hashmap_nbuckets), node_size,
                [](const BtreeNodePtr& node) -> BlkId {
                    return static_cast< IndexBtreeNode* >(node.get())->m_idx_buf->m_blkid;
                },
                [](const sisl::CacheRecord& rec) -> bool {
                    const auto& hnode = (sisl::SingleEntryHashNode< BtreeNodePtr >&)rec;
                    return static_cast< IndexBtreeNode* >(hnode.m_value.get())->m_idx_buf->is_clean();
                }},
        m_node_size{node_size},
        m_meta_blk{sb.first} {
    start_flush_threads();

    // We need to register the consumer first before recovery, so that recovery can use the cp_ctx created to add/track
    // recovered new nodes.
    cp_mgr().register_consumer(cp_consumer_t::INDEX_SVC, std::move(std::make_unique< IndexCPCallbacks >(this)));
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

BtreeNodePtr IndexWBCache::alloc_buf(uint32_t ordinal, node_initializer_t&& node_initializer) {
    auto cpg = cp_mgr().cp_guard();
    auto cp_ctx = r_cast< IndexCPContext* >(cpg.context(cp_consumer_t::INDEX_SVC));

    // Alloc a block of data from underlying vdev
    MultiBlkId blkid;
    // Ordinal used as a hint in the case of custom chunk selector exists
    blk_alloc_hints hints;
    hints.application_hint = ordinal;
    auto ret = m_vdev->alloc_contiguous_blks(1, hints, blkid);
    if (ret != BlkAllocStatus::SUCCESS) { return nullptr; }

    // Alloc buffer and initialize the node
    auto idx_buf = std::make_shared< IndexBuffer >(blkid, m_node_size, m_vdev->align_size());
    idx_buf->m_created_cp_id = cpg->id();
    idx_buf->m_dirtied_cp_id = cpg->id();
    auto node = node_initializer(idx_buf);
    idx_buf->m_node_level = node->level();

    if (!m_in_recovery) {
        // Add the node to the cache. Skip if we are in recovery mode.
        bool done = m_cache.insert(node);
        HS_REL_ASSERT_EQ(done, true, "Unable to add alloc'd node to cache, low memory or duplicate inserts?");
    }

    // The entire index is updated in the commit path, so we alloc the blk and commit them right away
    auto alloc_status = m_vdev->commit_blk(blkid);
    // if any error happens when committing the blk to index service, we should assert and crash
    if (alloc_status != BlkAllocStatus::SUCCESS) HS_REL_ASSERT(0, "Failed to commit blk: {}", blkid.to_string());
    return node;
}

void IndexWBCache::write_buf(const BtreeNodePtr& node, const IndexBufferPtr& buf, CPContext* cp_ctx) {
    // TODO upsert always returns false even if it succeeds.
    if (m_in_recovery) {
        if (buf->is_meta_buf()) {
            auto const& sb = r_cast< MetaIndexBuffer* >(buf.get())->m_sb;
            meta_service().update_sub_sb(buf->m_bytes, sb.size(), sb.meta_blk());
        } else {
            LOGTRACEMOD(wbcache, "write buf [{}] in recovery mode", buf->to_string());
            m_vdev->sync_write(r_cast< const char* >(buf->raw_buffer()), m_node_size, buf->m_blkid);
        }
    } else {
        if (node != nullptr) { m_cache.upsert(node); }
        LOGTRACEMOD(wbcache, "add to dirty list cp {} {}", cp_ctx->id(), buf->to_string());
        r_cast< IndexCPContext* >(cp_ctx)->add_to_dirty_list(buf);
        resource_mgr().inc_dirty_buf_size(m_node_size);
    }
}

void IndexWBCache::read_buf(bnodeid_t id, BtreeNodePtr& node, node_initializer_t&& node_initializer) {
    auto const blkid = BlkId{id};

retry:
    // Check if the blkid is already in cache, if notL load and put it into the cache
    if (!m_in_recovery && m_cache.get(blkid, node)) { return; }

    // Read the buffer from virtual device
    auto idx_buf = std::make_shared< IndexBuffer >(blkid, m_node_size, m_vdev->align_size());
    m_vdev->sync_read(r_cast< char* >(idx_buf->raw_buffer()), m_node_size, blkid);

    // Create the btree node out of buffer
    node = node_initializer(idx_buf);

    // Push the node into cache
    if (!m_in_recovery) {
        bool done = m_cache.insert(node);
        if (!done) {
            // There is a race between 2 concurrent reads from vdev and other party won the race. Re-read from cache
            goto retry;
        }
    }
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
        new_buf->m_node_level = idx_buf->m_node_level;
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

bool IndexWBCache::refresh_meta_buf(shared< MetaIndexBuffer >& meta_buf, CPContext* cp_ctx) {
    if (meta_buf->m_dirtied_cp_id > cp_ctx->id()) {
        return false; // meta_buf modified by a newer CP, we shouldn't overwrite that
    } else if (meta_buf->m_dirtied_cp_id == cp_ctx->id()) {
        // Modified by the same cp, no need to create new index buffer, but we only copy the superblk to the buffer
        LOGTRACEMOD(wbcache, "meta buf {} is already dirtied in cp {} now is in recovery {}", meta_buf->to_string(),
                    cp_ctx->id(), m_in_recovery);
        meta_buf->copy_sb_to_buf();
        // TODO: corner case , meta buffer is dirtied by the same cp but not added to dirty list due to previously
        // recovery mode
    } else {
        // We always create a new meta index buffer on every meta buf update, which copies the superblk
        auto new_buf = std::make_shared< MetaIndexBuffer >(meta_buf);
        new_buf->m_dirtied_cp_id = cp_ctx->id();
        write_buf(nullptr, new_buf, cp_ctx);
        meta_buf = new_buf; // Replace the meta_buf with new buf
        LOGTRACEMOD(wbcache, "meta buf {} is created in cp {} in recovery = {}", meta_buf->to_string(), cp_ctx->id(),
                    m_in_recovery);
    }
    return true;
}

#ifdef _PRERELEASE
static void set_crash_flips(IndexBufferPtr const& parent_buf, IndexBufferPtr const& child_buf,
                            IndexBufferPtrList const& new_node_bufs, IndexBufferPtrList const& freed_node_bufs) {
    // TODO: Need an API from flip to quickly check if flip is enabled, so this method doesn't check flip_enabled a
    // bunch of times.
    // TODO: Need an API to check if a flip is triggered easilly to avoid the use of several atomics.
    if (parent_buf && parent_buf->is_meta_buf()) {
        // Split or merge happening on root
        if (iomgr_flip::instance()->test_flip("crash_flush_on_meta")) {
            parent_buf->set_crash_flag();
            hs()->crash_simulator().set_will_crash(true);
        } else if (iomgr_flip::instance()->test_flip("crash_flush_on_root")) {
            child_buf->set_crash_flag();
            hs()->crash_simulator().set_will_crash(true);
        }
    } else if ((new_node_bufs.size() == 1) && freed_node_bufs.empty()) {
        // Its a split node situation
        if (iomgr_flip::instance()->test_flip("crash_flush_on_split_at_parent")) {
            parent_buf->set_crash_flag();
            hs()->crash_simulator().set_will_crash(true);
        } else if (iomgr_flip::instance()->test_flip("crash_flush_on_split_at_left_child")) {
            child_buf->set_crash_flag();
            hs()->crash_simulator().set_will_crash(true);
        } else if (iomgr_flip::instance()->test_flip("crash_flush_on_split_at_right_child")) {
            new_node_bufs[0]->set_crash_flag();
            hs()->crash_simulator().set_will_crash(true);
        }
    } else if (!freed_node_bufs.empty() && (new_node_bufs.size() != freed_node_bufs.size())) {
        // Its a merge nodes sitation
        if (iomgr_flip::instance()->test_flip("crash_flush_on_merge_at_parent")) {
            parent_buf->set_crash_flag();
            hs()->crash_simulator().set_will_crash(true);
        } else if (iomgr_flip::instance()->test_flip("crash_flush_on_merge_at_left_child")) {
            child_buf->set_crash_flag();
            hs()->crash_simulator().set_will_crash(true);
        } else if (iomgr_flip::instance()->test_flip("crash_flush_on_merge_at_right_child")) {
            if (!new_node_bufs.empty()) {
                new_node_bufs[0]->set_crash_flag();
                hs()->crash_simulator().set_will_crash(true);
            }
        }
    } else if (!freed_node_bufs.empty() && (new_node_bufs.size() == freed_node_bufs.size())) {
        // Its a rebalance node situation
        if (iomgr_flip::instance()->test_flip("crash_flush_on_rebalance_at_parent")) {
            parent_buf->set_crash_flag();
            hs()->crash_simulator().set_will_crash(true);
        } else if (iomgr_flip::instance()->test_flip("crash_flush_on_rebalance_at_left_child")) {
            child_buf->set_crash_flag();
            hs()->crash_simulator().set_will_crash(true);
        } else if (iomgr_flip::instance()->test_flip("crash_flush_on_rebalance_at_right_child")) {
            if (!new_node_bufs.empty()) {
                new_node_bufs[0]->set_crash_flag();
                hs()->crash_simulator().set_will_crash(true);
            }
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

    if (new_node_bufs.empty() && freed_node_bufs.empty()) {
        // This is an update for meta, root transaction.
        if (child_buf->m_created_cp_id < icp_ctx->id()) {
            icp_ctx->add_to_txn_journal(index_ordinal, parent_buf, child_buf, {}, {});
        } else {
            icp_ctx->add_to_txn_journal(index_ordinal, parent_buf, nullptr, {child_buf}, {});
        }
    } else {
        icp_ctx->add_to_txn_journal(index_ordinal, child_buf->m_up_buffer /* real up buffer */, child_buf,
                                    new_node_bufs, freed_node_bufs);
    }
#ifdef _PRERELEASE
    // log new nodes and freed nodes and parent and child
    static uint32_t txn_id = 0;
    static int last_cp_id = -2;
    std::string txn = "";
    if (last_cp_id != icp_ctx->id()) {
        last_cp_id = icp_ctx->id();
        txn_id = 0;
    }

    if (new_node_bufs.empty() && freed_node_bufs.empty()) {
        fmt::format_to(std::back_inserter(txn), "{} - parent=[{}] child=[{}] new=[{}] freed=[{}]", txn_id,
                       (parent_buf && parent_buf->blkid().to_integer() != 0)
                           ? std::to_string(parent_buf->blkid().to_integer())
                           : "empty",
                       child_buf->blkid().to_integer(), "empty", "empty");
    } else {
        std::string new_nodes;
        for (auto const& buf : new_node_bufs) {
            new_nodes += std::to_string(buf->blkid().to_integer()) + ", ";
        }
        std::string freed_nodes;
        for (auto const& buf : freed_node_bufs) {
            freed_nodes += std::to_string(buf->blkid().to_integer()) + ", ";
        }
        std::string parent_str = (parent_buf && parent_buf->blkid().to_integer() != 0)
            ? std::to_string(parent_buf->blkid().to_integer())
            : "empty";
        std::string child_str = (child_buf && child_buf->blkid().to_integer() != 0)
            ? std::to_string(child_buf->blkid().to_integer())
            : "empty";

        fmt::format_to(std::back_inserter(txn), ": {} - parent={} child={} new=[{}] freed=[{}]", txn_id, parent_str,
                       child_str, new_nodes, freed_nodes);
    }
    LOGTRACEMOD(wbcache, "tranasction till now: cp: {} {}", icp_ctx->id(), txn);
    txn_id++;
#endif
#if 0
    static int id = 0;
    auto filename = fmt::format("txn_buf_{}_{}.dot", icp_ctx->id(), id++);
    LOGTRACEMOD(wbcache,"Writing txn to file: {}", filename);
    icp_ctx->to_string_dot(filename);
#endif
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
    if (up_buf->m_created_cp_id == icp_ctx->id()) {
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
            HS_DBG_ASSERT(real_up_buf->is_in_down_buffers(down_buf),
                          "Down buffer is linked to Up buf, but up_buf doesn't have down_buf in its list");
#endif
            return;
        }
    }

    // Now we link the down_buffer to the real up_buffer
    if (down_buf->m_up_buffer) {
        // release existing up_buffer's wait count
        down_buf->m_up_buffer->remove_down_buffer(down_buf);
    }
    down_buf->m_up_buffer = real_up_buf;
    real_up_buf->add_down_buffer(down_buf);
}

void IndexWBCache::free_buf(const IndexBufferPtr& buf, CPContext* cp_ctx) {
    BtreeNodePtr node;
    if (!m_in_recovery) {
        bool done = m_cache.remove(buf->m_blkid, node);
        HS_REL_ASSERT_EQ(done, true, "Race on cache removal of btree blkid?");
    }
    buf->m_node_freed = true;
    resource_mgr().inc_free_blk(m_node_size);
    m_vdev->free_blk(buf->m_blkid, s_cast< VDevCPContext* >(cp_ctx));
}

//////////////////// Recovery Related section /////////////////////////////////
void IndexWBCache::load_buf(IndexBufferPtr const& buf) {
    if (buf->m_bytes == nullptr) {
        buf->m_bytes = hs_utils::iobuf_alloc(m_node_size, sisl::buftag::btree_node, m_vdev->align_size());
        m_vdev->sync_read(r_cast< char* >(buf->m_bytes), m_node_size, buf->blkid());
        buf->m_dirtied_cp_id = BtreeNode::get_modified_cp_id(buf->m_bytes);
    }
}

IndexWBCache::DagMap IndexWBCache::generate_dag_buffers(std::map< BlkId, IndexBufferPtr >& bufmap) {
    std::vector< IndexBufferPtr > bufs;
    std::ranges::transform(bufmap, std::back_inserter(bufs), [](const auto& pair) { return pair.second; });

    auto buildReverseMapping = [](const std::vector< IndexBufferPtr >& buffers) {
        std::unordered_map< IndexBufferPtr, std::vector< IndexBufferPtr > > parentToChildren;
        for (const auto& buffer : buffers) {
            if (buffer->m_up_buffer) { parentToChildren[buffer->m_up_buffer].push_back(buffer); }
        }
        return parentToChildren;
    };

    std::function< DagPtr(IndexBufferPtr, std::unordered_map< IndexBufferPtr, std::vector< IndexBufferPtr > >&) >
        buildDag;
    buildDag =
        [&buildDag](IndexBufferPtr buffer,
                    std::unordered_map< IndexBufferPtr, std::vector< IndexBufferPtr > >& parentToChildren) -> DagPtr {
        auto dagNode = std::make_shared< DagNode >();
        dagNode->buffer = buffer;
        if (parentToChildren.count(buffer)) {
            for (const auto& child : parentToChildren[buffer]) {
                dagNode->children.push_back(buildDag(child, parentToChildren));
            }
        }
        return dagNode;
    };

    auto generateDagMap = [&](const std::vector< IndexBufferPtr >& buffers) {
        DagMap dagMap;
        auto parentToChildren = buildReverseMapping(buffers);
        for (const auto& buffer : buffers) {
            if (!buffer->m_up_buffer) { // This is a root buffer
                auto dagRoot = buildDag(buffer, parentToChildren);
                dagMap[buffer] = dagRoot;
            }
        }
        return dagMap;
    };

    return generateDagMap(bufs);
}

std::string IndexWBCache::to_string_dag_bufs(DagMap& dags, cp_id_t cp_id) {
    std::string str{fmt::format("#_of_dags={}\n", dags.size())};
    int cnt = 1;
    for (const auto& [_, dag] : dags) {
        std::vector< std::tuple< std::shared_ptr< DagNode >, int, int > > stack;
        stack.emplace_back(dag, 0, cnt++);
        while (!stack.empty()) {
            auto [node, level, index] = stack.back();
            stack.pop_back();
            auto snew = node->buffer->m_created_cp_id == cp_id ? "NEW" : "";
            auto sfree = node->buffer->m_node_freed ? "FREED" : "";
            load_buf(node->buffer);
            fmt::format_to(std::back_inserter(str), "{}{}-{} {} {}\n", std::string(level * 4, ' '), index,
                           node->buffer->to_string(), snew, sfree);
            int c = node->children.size();
            for (const auto& d : node->children) {
                stack.emplace_back(d, level + 1, c--);
            }
        }
    }
    return str;
}

void IndexWBCache::prune_up_buffers(IndexBufferPtr const& buf, std::vector< IndexBufferPtr >& pruned_bufs_to_repair) {
    auto up_buf = buf->m_up_buffer;
    auto grand_up_buf = up_buf->m_up_buffer;
    if (!up_buf || !up_buf->m_wait_for_down_buffers.testz()) { return; }

    // if up buffer has up buffer, then we need to decrement its wait_for_down_buffers
    LOGINFOMOD(wbcache, "\n\npruning up_buffer due to zero dependency of child\n up buffer {}\n buffer {}",
               up_buf->to_string(), buf->to_string());
    update_up_buffer_counters(up_buf);

    pruned_bufs_to_repair.push_back(up_buf);
    if (grand_up_buf && !grand_up_buf->is_meta_buf() && grand_up_buf->m_wait_for_down_buffers.testz()) {
        LOGTRACEMOD(
            wbcache,
            "\nadding grand_buffer to repair list due to zero dependency of child\n grand buffer {}\n buffer {}",
            grand_up_buf->to_string(), buf->to_string());
        pruned_bufs_to_repair.push_back(grand_up_buf);
    }
}

void IndexWBCache::recover(sisl::byte_view sb) {
    // If sb is empty, its possible a first time boot.
    if ((sb.bytes() == nullptr) || (sb.size() == 0)) {
        m_vdev->recovery_completed();
        return;
    }

    m_in_recovery = true; // For entirity of this call, we should mark it as being recovered.

    // Recover the CP Context with the buf_map of all the buffers that were dirtied in the last cp with its
    // relationship (up/down buf links) as it was by the cp that was flushing the buffers prior to unclean shutdown.
    auto cpg = cp_mgr().cp_guard();
    auto icp_ctx = r_cast< IndexCPContext* >(cpg.context(cp_consumer_t::INDEX_SVC));
    std::map< BlkId, IndexBufferPtr > bufs = icp_ctx->recover(std::move(sb));

    LOGINFOMOD(wbcache, "Detected unclean shutdown, prior cp={} had to flush {} nodes, recovering... ", icp_ctx->id(),
               bufs.size());

#ifdef _PRERELEASE
    auto detailed_log = [this](std::map< BlkId, IndexBufferPtr > const& bufs,
                               std::vector< IndexBufferPtr > const& pending_bufs) {
        std::string log = fmt::format("\trecovered bufs (#of bufs = {})\n", bufs.size());
        for (auto const& [_, buf] : bufs) {
            load_buf(buf);
            fmt::format_to(std::back_inserter(log), "{}\n", buf->to_string());
        }

        // list of new_bufs
        if (!pending_bufs.empty()) {
            fmt::format_to(std::back_inserter(log), "\n\tpending_bufs (#of bufs = {})\n", pending_bufs.size());
            for (auto const& buf : pending_bufs) {
                fmt::format_to(std::back_inserter(log), "{}\n", buf->to_string());
            }
        }
        return log;
    };

    auto dags = generate_dag_buffers(bufs);
    LOGTRACEMOD(wbcache, "before processing recovery DAGS:\n {}\n\n\n\n", to_string_dag_bufs(dags, icp_ctx->id()));
#endif

    // At this point, we have the DAG structure (up/down dependency graph), exactly the same as prior to crash, with one
    // addition of all freed buffers also put in the DAG structure.
    //
    // We do repair/recovery as 2 passes. A quick glance would look like we don't need 2 passes of the walking through
    // all the buffers, but it is essential.
    //
    // In the first pass, we look for any new bufs and any freed bufs and commit/free their corresponding node blkids.
    // This has to be done before doing any repair, because repair can allocate blkids and we don't want to allocate
    // the same blkid which could clash with the blkid next in the buf list.
    //
    // On the second pass, we only take part of the parents/siblings and then repair them, if needed.
    std::vector< IndexBufferPtr > pending_bufs;
    std::vector< IndexBufferPtr > deleted_bufs;
    std::multiset< IndexBufferPtr, bool (*)(const IndexBufferPtr&, const IndexBufferPtr&) >
        potential_parent_recovered_bufs(
            [](const IndexBufferPtr& a, const IndexBufferPtr& b) { return a->m_node_level < b->m_node_level; });

    std::vector< IndexBufferPtr > pruned_bufs_to_repair;
    LOGTRACEMOD(wbcache, "\n\n\nRecovery processing begins\n\n\n");
    for (auto const& [_, buf] : bufs) {
        load_buf(buf);

        if (buf->m_node_freed) {
            LOGTRACEMOD(wbcache, "recovering free buf {}", buf->to_string());
            if (was_node_committed(buf)) {
                // Mark this buffer as deleted, so that we can avoid using it anymore when repairing its parent's link
                r_cast< persistent_hdr_t* >(buf->m_bytes)->node_deleted = true;
                write_buf(nullptr, buf, icp_ctx); // no need to write it here !!
                deleted_bufs.push_back(buf);
                pending_bufs.push_back(buf->m_up_buffer);
                LOGINFOMOD(wbcache, "Freeing deleted buf {} and adding up buffer to pending {}", buf->to_string(),
                           buf->m_up_buffer->to_string());
            } else {
                // (Up) buffer is not committed, node need to be kept and (potentially) repaired later
                if (buf->m_created_cp_id != icp_ctx->id()) {
                    LOGTRACEMOD(wbcache,
                                "NOT FREE committing buffer {} node deleted is false reason: node commited?= {} "
                                "up committed? {}",
                                buf->to_string(), was_node_committed(buf), was_node_committed(buf->m_up_buffer));
                    buf->m_node_freed = false;
                    r_cast< persistent_hdr_t* >(buf->m_bytes)->node_deleted = false;
                    m_vdev->commit_blk(buf->m_blkid);
                    // it can happen when children moved to one of right parent sibling and then the previous node is
                    // deleted but not commited during crash (upbuffer is not committed). but its children already
                    // committed. and freed (or changed)
                    if (buf->m_node_level) { potential_parent_recovered_bufs.insert(buf); }
                } else {
                    LOGINFO("deleting and creating new buf {}", buf->to_string());
                    deleted_bufs.push_back(buf);
                }
                //  1- upbuffer was dirtied by the same cp, so it is not commited, so we don't need to repair it.
                //  remove it from down_waiting list (probably recursively going up) 2- upbuffer was created and
                //  freed at the same cp, so it is not commited, so we don't need to repair it.
                if (buf->m_up_buffer) {
                    LOGTRACEMOD(wbcache, "remove_down_buffer {} from up buffer {}", buf->to_string(),
                                buf->m_up_buffer->to_string());
                    buf->m_up_buffer->remove_down_buffer(buf);
                    prune_up_buffers(buf, pruned_bufs_to_repair);
                    buf->m_up_buffer = nullptr;
                }
            }
        } else if (buf->m_created_cp_id == icp_ctx->id()) {
            LOGTRACEMOD(wbcache, "recovering new buf {}", buf->to_string());
            // New node
            if (was_node_committed(buf) && was_node_committed(buf->m_up_buffer)) {
                // Both current and up buffer is commited, we can safely commit the current block
                LOGTRACEMOD(wbcache, "New buffer {} and the up buffer {} are committed", buf->to_string(),
                            buf->m_up_buffer->to_string());
                m_vdev->commit_blk(buf->m_blkid);
                pending_bufs.push_back(buf->m_up_buffer);
            } else {
                // Up buffer is not committed, we need to repair it first
                LOGTRACEMOD(wbcache, "The up buffer {} is not committed for the new buffer {}",
                            buf->m_up_buffer->to_string(), buf->to_string());
                buf->m_up_buffer->remove_down_buffer(buf);
                prune_up_buffers(buf, pruned_bufs_to_repair);
                //                buf->m_up_buffer = nullptr;
            }
        }
    }
    LOGTRACEMOD(wbcache, "\n\n\nRecovery processing Ends\n\n\n");
#ifdef _PRERELEASE
    LOGINFOMOD(wbcache, "Index Recovery detected {} nodes out of {} as new/freed nodes to be recovered in prev cp={}",
               pending_bufs.size(), bufs.size(), icp_ctx->id());
    // add deleted bufs to logs here as well
    auto modified_dags = generate_dag_buffers(bufs);
    LOGTRACEMOD(wbcache, "All unclean bufs list\n{}", detailed_log({}, pending_bufs));
    LOGTRACEMOD(wbcache, "All pruned bufs for recovery\n{}", detailed_log({}, pruned_bufs_to_repair));
    LOGTRACEMOD(wbcache, "After recovery: {}", to_string_dag_bufs(modified_dags, icp_ctx->id()));

#endif
    uint32_t cnt = 0;
    LOGTRACEMOD(wbcache, "Potential parent recovered bufs (#of bufs = {})", potential_parent_recovered_bufs.size());
    for (auto const& buf : potential_parent_recovered_bufs) {
        LOGTRACEMOD(wbcache, " {} - check stale recovered buf {}", cnt++, buf->to_string());
    }
    // This step is needed since there is a case where all(or some) children of an interior node is freed (after moving
    // to a previous sibling parent) and after crash, this node has stale links to its children
    cnt = 0;
    std::vector< IndexBufferPtr > buffers_to_repair;
    for (auto const& buf : potential_parent_recovered_bufs) {
        LOGTRACEMOD(wbcache, " {} - potential parent recovered buf {}", cnt, buf->to_string());
        parent_recover(buf);
        if (buf->m_bytes == nullptr || r_cast< persistent_hdr_t* >(buf->m_bytes)->node_deleted) {
            // This buffer was marked as deleted during repair, so we also need to free it
            deleted_bufs.push_back(buf);
        } else {
            // This buffer was not marked as deleted during repair, so we need to repair it
            buffers_to_repair.push_back(buf);
        }
    }
    // let all unfreed buffers to be repaired first. This is important to let detect and remove all stale links first
    // and then repair them before actual repair (due to dependency of finding true siblings)
    for (auto const& buf : buffers_to_repair) {
        LOGTRACEMOD(wbcache, "recover and repairing unfreed non-stale link interior node buf {}", buf->to_string());
        index_service().repair_index_node(buf->m_index_ordinal, buf);
    }
    // actual recover is done here in recovery path
    for (auto const& buf : pending_bufs) {
        LOGTRACEMOD(wbcache, "recover and repairing  up_buffer buf {}", buf->to_string());
        recover_buf(buf);
    }

    // When we prune a buffer due to zero down dependency, there is a case where the key range of the parent needs to be
    // adjusted. This can happen when a child is merged and its right sibling is flushed before the parent is flushed.
    // And during recovery, we prune the node and keep the deleted child and keep the parent as is.
    // We need to call repair_links directly on them as the recovery_buf() path will not trigger it.
    for (auto const& buf : pruned_bufs_to_repair) {
        LOGTRACEMOD(wbcache, "pruned buf {} is repaired", buf->to_string());
        index_service().repair_index_node(buf->m_index_ordinal, buf);
    }

    for (auto const& buf : deleted_bufs) {
        LOGTRACEMOD(wbcache, "freeing buf after repairing (last step) {}", buf->to_string());
        m_vdev->free_blk(buf->m_blkid, s_cast< VDevCPContext* >(icp_ctx));
    }

    if (pending_bufs.empty()) {
        LOGTRACEMOD(wbcache, "No buffers to repair, recovery completed");
    } else {
        std::map< uint32_t, IndexBufferPtrList > changed_bufs;
        for (auto const& [_, buf] : bufs) {
            LOGTRACEMOD(wbcache, "{}", buf->to_string());
            if (!buf->m_node_freed) { changed_bufs[buf->m_index_ordinal].push_back(buf); }
        }
        for (auto const& [index_ordinal, bufs] : changed_bufs) {
            LOGTRACEMOD(wbcache, "Sanity checking buffers for index ordinal {}: # of bufs {}", index_ordinal,
                        bufs.size());
            auto ret = index_service().sanity_check(index_ordinal, bufs);
            if (ret) {
                LOGTRACEMOD(wbcache, "Sanity check for index ordinal {} passed", index_ordinal);
            } else {
                LOGERRORMOD(wbcache, "Sanity check for index ordinal {} failed", index_ordinal);
#ifdef _PRELEASE
                HS_DBG_ASSERT(true, "sanity failed: {}", ret);
#else
                // TODO: make this index table offline and let others work
                HS_REL_ASSERT(0, "sanity failed: {}", ret);
#endif
            }
        }
    }
    m_in_recovery = false;
    m_vdev->recovery_completed();
}

void IndexWBCache::parent_recover(IndexBufferPtr const& buf) {
    index_service().parent_recover(buf->m_index_ordinal, buf);
}
// if buf->m_wait_for_down_buffers.testz() is true (which means that it has  no dependency on any other buffer) then we
// can decrement the wait_for_down_buffers of its up buffer. If the up buffer has up buffer, then we need to decrement
// its wait_for_down_buffers. If the up buffer of up buffer has wait_for_down_buffers as 0, then we need to decrement
// its wait_for_down_buffers. This process continues until we reach the root buffer. If the root buffer has
// wait_for_down_buffers as 0, then we need to decrement its wait_for_down_buffers.
void IndexWBCache::update_up_buffer_counters(IndexBufferPtr const& buf) {
    if (buf == nullptr || !buf->m_wait_for_down_buffers.testz() || buf->m_up_buffer == nullptr) {
        LOGINFOMOD(wbcache, "Finish decrementing wait_for_down_buffers\n");
        return;
    }
    auto grand_buf = buf->m_up_buffer;
    LOGINFOMOD(wbcache,
               "Decrementing wait_for_down_buffers due to zero dependency of child for grand_buffer {} up_buffer {}, "
               "Keep going up",
               grand_buf->to_string(), buf->to_string());
    grand_buf->remove_down_buffer(buf);
    buf->m_up_buffer = nullptr;
    update_up_buffer_counters(grand_buf);
}

void IndexWBCache::recover_buf(IndexBufferPtr const& buf) {
    if (!buf->m_wait_for_down_buffers.decrement_testz()) {
        // TODO: remove the buf_>m_up_buffer from down_buffers list of buf->m_up_buffer
        return;
    }

    // All down buffers are completed and given a nod saying that they are committed. If this buffer is not committed,
    // then we need to repair this node/buffer. After that we will keep going to the next up level to repair them if
    // needed
    if (!was_node_committed(buf)) {
        LOGDEBUGMOD(wbcache, "Index Recovery detected uncommitted up node [{}], repairing it", buf->to_string());
        index_service().repair_index_node(buf->m_index_ordinal, buf);
    } else {
        LOGTRACEMOD(wbcache, "Index Recovery detected up node [{}] as committed no need to repair that",
                    buf->to_string());
        if (buf->m_up_buffer && buf->m_up_buffer->is_meta_buf()) {
            // Our up buffer is a meta buffer, which means old root is dirtied and may need no repair but possible of
            // new root on upper level so needs to be retore the edge
            LOGTRACEMOD(wbcache, "check root change for without repairing {}", buf->to_string());
            index_service().update_root(buf->m_index_ordinal, buf);
        }
    }

    if (buf->m_up_buffer) { recover_buf(buf->m_up_buffer); }
}

bool IndexWBCache::was_node_committed(IndexBufferPtr const& buf) {
    if (buf == nullptr) { return false; }

    // If the node is freed, then it can be considered committed as long as its up buffer was committed
    if (buf->m_node_freed) {
        HS_DBG_ASSERT(buf->m_up_buffer, "Buf {} was marked deleted, but doesn't have an up_buffer", buf->to_string());
        return was_node_committed(buf->m_up_buffer);
    }

    // All down_buf has indicated that they have seen this up buffer, now its time to repair them.
    load_buf(buf);
    if (!BtreeNode::is_valid_node(sisl::blob{buf->m_bytes, m_node_size})) { return false; }
    return (buf->m_dirtied_cp_id == cp_mgr().cp_guard()->id());
}

//////////////////// CP Related API section /////////////////////////////////
folly::Future< bool > IndexWBCache::async_cp_flush(IndexCPContext* cp_ctx) {
    LOGTRACEMOD(wbcache, "Starting Index CP Flush with cp \ndag={}", cp_ctx->to_string_with_dags());
    // #ifdef _PRERELEASE
    //     static int id = 0;
    //     auto filename = "cp_" + std::to_string(id++) + "_" + std::to_string(rand() % 100) + ".dot";
    //     LOGTRACEMOD(wbcache, "Transact cp storing in file {}\n\n\n", filename);
    //     cp_ctx->to_string_dot(filename);
    // #endif
    if (!cp_ctx->any_dirty_buffers()) {
        if (cp_ctx->id() == 0) {
            // For the first CP, we need to flush the journal buffer to the meta blk
            LOGINFO("First time boot cp, we shall flush the vdev to ensure all cp information is created");
            m_vdev->cp_flush(cp_ctx);
        } else {
            CP_PERIODIC_LOG(DEBUG, cp_ctx->id(), "Btree does not have any dirty buffers to flush");
        }
        return folly::makeFuture< bool >(true); // nothing to flush
    }

#ifdef _PRERELEASE
    if (hs()->crash_simulator().is_crashed()) {
        LOGINFO("crash simulation is ongoing, so skip the cp flush");
        return folly::makeFuture< bool >(true);
    }
#endif

    // First thing is to flush the journal created as part of the CP.
    auto const& journal_buf = cp_ctx->journal_buf();
    auto txn = r_cast< IndexCPContext::txn_journal const* >(journal_buf.cbytes());
    if (journal_buf.size() != 0) {
        if (m_meta_blk) {
            LOGTRACEMOD(wbcache, " journal {} ", txn->to_string());
            meta_service().update_sub_sb(journal_buf.cbytes(), journal_buf.size(), m_meta_blk);
        } else {
            LOGTRACEMOD(wbcache, " First time journal {} ", txn->to_string());
            meta_service().add_sub_sb("wb_cache", journal_buf.cbytes(), journal_buf.size(), m_meta_blk);
        }
    }

    cp_ctx->prepare_flush_iteration();
    m_updated_ordinals.clear();
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
    static std::once_flag flag;
#ifdef _PRERELEASE
    if (hs()->crash_simulator().is_crashed()) {
        std::call_once(flag, []() { LOGINFO("Crash simulation is ongoing; aid simulation by not flushing."); });
        return;
    }
    if (buf->m_crash_flag_on) {
        std::string filename = "crash_buf_" + std::to_string(cp_ctx->id()) + ".dot";
        LOGINFO("Simulating crash while writing buffer {},  stored in file {}", buf->to_string(), filename);
        //        cp_ctx->to_string_dot(filename);
        hs()->crash_simulator().crash();
        cp_ctx->complete(true);
        return;
    }
#endif

    buf->set_state(index_buf_state_t::FLUSHING);

    if (buf->is_meta_buf()) {
        LOGTRACEMOD(wbcache, "Flushing cp {} meta buf {} possibly because of root split", cp_ctx->id(),
                    buf->to_string());
        auto const sb_buf = r_cast< MetaIndexBuffer* >(buf.get());
        if (sb_buf->m_valid) {
            auto const& sb = sb_buf->m_sb;
            if (!sb.is_empty()) { meta_service().update_sub_sb(buf->m_bytes, sb.size(), sb.meta_blk()); }
        }
        process_write_completion(cp_ctx, buf);
    } else if (buf->m_node_freed) {
        LOGTRACEMOD(wbcache, "cp {} Not flushing buf {} as it was freed, its here for merely dependency", cp_ctx->id(),
                    buf->to_string());
        process_write_completion(cp_ctx, buf);
    } else {
        m_vdev->async_write(r_cast< const char* >(buf->raw_buffer()), m_node_size, buf->m_blkid, part_of_batch)
            .thenValue([buf, cp_ctx](auto) {
                try {
                    auto& pthis = s_cast< IndexWBCache& >(wb_cache());
                    pthis.process_write_completion(cp_ctx, buf);
                } catch (const std::runtime_error& e) {
                    std::call_once(flag,
                                   []() { LOGERROR("Crash simulation is ongoing; aid simulation by not flushing."); });
                }
            });
        if (!part_of_batch) { m_vdev->submit_batch(); }
    }
}

void IndexWBCache::process_write_completion(IndexCPContext* cp_ctx, IndexBufferPtr const& buf) {
#ifdef _PRERELEASE
    static std::once_flag flag;
    if (hs()->crash_simulator().is_crashed()) {
        std::call_once(
            flag, []() { LOGINFOMOD(wbcache, "Crash simulation is ongoing, ignore all process_write_completion"); });
        return;
    }
#endif

    LOGTRACEMOD(wbcache, "cp {} buf {}", cp_ctx->id(), buf->to_string());
    resource_mgr().dec_dirty_buf_size(m_node_size);
    m_updated_ordinals.insert(buf->m_index_ordinal);
    auto [next_buf, has_more] = on_buf_flush_done(cp_ctx, buf);
    if (next_buf) {
        do_flush_one_buf(cp_ctx, next_buf, false);
    } else if (!has_more) {
        for (const auto& ordinal : m_updated_ordinals) {
            LOGTRACEMOD(wbcache, "Updating sb for ordinal {}", ordinal);
            index_service().write_sb(ordinal);
        }

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
    {
        std::lock_guard lg(buf->m_down_buffers_mtx);
        buf->m_down_buffers.clear();
    }
#endif
    buf->set_state(index_buf_state_t::CLEAN);

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

        if ((*buf)->state() == index_buf_state_t::DIRTY && (*buf)->m_wait_for_down_buffers.testz()) {
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
