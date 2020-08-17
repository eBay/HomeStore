/*
 * ssd_btree.hpp
 *
 *  Created on: 14-Jun-2016
 *      Author: Hari Kadayam
 *
 *  Copyright © 2016 Kadayam, Hari. All rights reserved.
 */
#pragma once

#include <iostream>
#include <assert.h>
#include <pthread.h>
#include <vector>
#include <atomic>

#include "engine/homeds/btree/writeBack_cache.hpp"
#include "engine/homeds/memory/composite_allocator.hpp"
#include "engine/homeds/memory/chunk_allocator.hpp"
#include "engine/homeds/memory/sys_allocator.hpp"
#include "engine/cache/cache.h"
#include "engine/blkstore/blkstore.hpp"
#include "btree_store.hpp"
#include "btree_node.h"
#include "physical_node.hpp"
#include "homelogstore/log_store.hpp"
#include "engine/common/homestore_config.hpp"

namespace homeds {
namespace btree {

#define SSDBtreeStore BtreeStore< btree_store_type::SSD_BTREE, K, V, InteriorNodeType, LeafNodeType >
#define ssd_btree_t Btree< btree_store_type::SSD_BTREE, K, V, InteriorNodeType, LeafNodeType >

template < typename K, typename V, btree_node_type InteriorNodeType, btree_node_type LeafNodeType >
class SSDBtreeStore {
public:
    using HeaderType = wb_cache_buffer_t;

    static std::unique_ptr< SSDBtreeStore > init_btree(ssd_btree_t* btree, BtreeConfig& cfg) {
        static std::once_flag flag1;
        std::call_once(flag1, [&cfg]() { m_blkstore = (btree_blkstore_t*)cfg.blkstore; });
        return std::make_unique< SSDBtreeStore >(btree, cfg);
    }

    BtreeStore(ssd_btree_t* btree, BtreeConfig& cfg) :
            m_btree(btree),
            m_cfg(cfg),
            m_wb_cache(cfg.blkstore, cfg.align_size, bind_this(SSDBtreeStore::cp_done_store, 1), cfg.trigger_cp_cb) {
        m_node_size = cfg.get_node_size();
        m_cfg.set_node_area_size(m_node_size - sizeof(LeafPhysicalNode));
        m_first_cp = btree_cp_ptr(new (btree_cp));
    }

    static void create_done(SSDBtreeStore* store, bnodeid_t m_root_node) { store->create_done_store(m_root_node); }

    /* It is called when its consumer has successfully persisted its superblock. */
    void create_done_store(bnodeid_t m_root_node) {
        auto bid = BlkId(m_root_node);
        m_blkstore->reserve_blk(bid);
    }

    void cp_done_store(const btree_cp_ptr& bcp) { bcp->cb(bcp); }

    /* It attaches the new CP and prepare for cur cp flush */
    static btree_cp_ptr attach_prepare_cp(SSDBtreeStore* store, const btree_cp_ptr& cur_bcp, bool is_last_cp,
                                          bool blkalloc_checkpoint) {
        return (store->attach_prepare_cp_store(cur_bcp, is_last_cp, blkalloc_checkpoint));
    }

    btree_cp_ptr attach_prepare_cp_store(const btree_cp_ptr& cur_bcp, bool is_last_cp, bool blkalloc_checkpoint) {
        /* start with ref cnt = 1. We dec it when trigger is called */
        if (cur_bcp) {
            cur_bcp->end_seqid = m_journal->get_contiguous_issued_seq_num(cur_bcp->start_seqid);
            assert(cur_bcp->end_seqid >= cur_bcp->start_seqid);
        }
        if (cur_bcp == m_first_cp) { m_first_cp = nullptr; }
        if (!cur_bcp) {
            /* it can not be last cp if this volume hasn't participated yet in a cp */
            assert(!is_last_cp);
            assert(m_first_cp);
            return m_first_cp;
        }

        btree_cp_ptr new_cp(nullptr);
        if (!is_last_cp) {
            new_cp = btree_cp_ptr(new (btree_cp));
            new_cp->start_seqid = cur_bcp->end_seqid;
            new_cp->cp_id = cur_bcp->cp_id + 1;
        }
        m_wb_cache.prepare_cp(new_cp, cur_bcp, blkalloc_checkpoint);
        return new_cp;
    }

    /* It is called only during first time create or after recovery */
    static void update_sb(SSDBtreeStore* store, btree_super_block& sb, btree_cp_sb* cp_sb, bool is_recovery) {
        store->update_store_sb(sb, cp_sb, is_recovery);
    }

    void update_store_sb(btree_super_block& sb, btree_cp_sb* cp_sb, bool is_recovery) {
        m_is_recovering = is_recovery;

        // Need to set this before opening log store, since log_found depends on cp_id
        m_first_cp->start_seqid = cp_sb->active_seqid;
        m_first_cp->cp_id = cp_sb->cp_id + 1;

        if (is_recovery) {
            // add recovery code
            HomeLogStoreMgr::instance().open_log_store(
                sb.journal_id, ([this](std::shared_ptr< HomeLogStore > logstore) {
                    m_journal = logstore;
                    m_journal->register_log_found_cb(bind_this(SSDBtreeStore::log_found, 3));
                    m_journal->register_log_replay_done_cb(bind_this(SSDBtreeStore::replay_done, 1));
                }));
            // reserve this blk unconditionally as root node never changes
            BlkId bid(sb.root_node);
            m_blkstore->reserve_blk(bid);
            HS_SUBMOD_LOG(INFO, base, , "btree", m_cfg.get_name(), "{}", cp_sb->to_string());
        } else {
            m_journal = HomeLogStoreMgr::instance().create_new_log_store();
            sb.journal_id = get_journal_id_store();
        }

        m_wb_cache.prepare_cp(m_first_cp, nullptr, false);
    }

    logstore_id_t get_journal_id_store() { return (m_journal->get_store_id()); }

    void log_found(logstore_seq_num_t seqnum, log_buffer log_buf, void* mem) {
        auto& cp_sb = m_btree->get_last_cp_cb();
        btree_journal_entry* jentry = (btree_journal_entry*)log_buf.bytes();
        bool is_replayed = false;

        auto cp_id = jentry->cp_id;
        HS_SUBMOD_LOG(TRACE, base, , "btree", m_cfg.get_name(), "seqnum {} entry cp cnt {}", seqnum, cp_id);
        if (jentry->cp_id > cp_sb.cp_id) {
            // Entry is not replayed yet
            if (jentry->op == journal_op::BTREE_CREATE) {
                m_btree->create_btree_replay(jentry, m_first_cp);
            } else if (jentry->op == journal_op::BTREE_SPLIT) {
                m_btree->split_node_replay(jentry, m_first_cp);
            }
            ++m_replayed_count;
            is_replayed = true;
        }

        if (jentry->cp_id > cp_sb.blkalloc_cp_id) {
            /* get all the free blks and allocated blks and set it in a bitmap. These entries are not persisted yet in a
             * bitmap.
             */
            /* getting all the free blks */

            jentry->foreach_node(bt_journal_node_op::removal,
                                 ([this, is_replayed](bt_node_gen_pair node_info, sisl::blob key_blob) {
                                     get_wb_cache()->free_blk(node_info.node_id, m_first_cp->free_blkid_list);
                                     if (is_replayed) { m_first_cp->btree_size.fetch_sub(1); }
                                 }));

            /* getting all the allocated blks */
            jentry->foreach_node(bt_journal_node_op::creation,
                                 ([this, is_replayed](bt_node_gen_pair node_info, sisl::blob key_blob) {
                                     assert(node_info.node_id != empty_bnodeid);
                                     BlkId bid(node_info.node_id);
                                     m_blkstore->reserve_blk(bid);
                                     if (is_replayed) { m_first_cp->btree_size.fetch_add(1); }
                                 }));
        }
    }

    void replay_done(std::shared_ptr< HomeLogStore > store) {
        HS_SUBMOD_LOG(INFO, base, , "btree", m_cfg.get_name(), "Replay of btree completed and replayed {} entries",
                      m_replayed_count);
        m_is_recovering = false;
        auto& cp_sb = m_btree->get_last_cp_cb();
        if (cp_sb.cp_id == -1 && m_replayed_count == 0) {
            m_btree->create_btree_replay(nullptr, m_first_cp);
            m_first_cp->btree_size.fetch_add(1);
        }
    }

    static void cp_start(SSDBtreeStore* store, const btree_cp_ptr& bcp, cp_comp_callback cb) {
        store->cp_start_store(bcp, cb);
    }

    void cp_start_store(const btree_cp_ptr& bcp, cp_comp_callback cb) {
        bcp->cb = cb;
        try_cp_start(bcp);
    }

    void try_cp_start(const btree_cp_ptr& bcp) {
        auto ref_cnt = bcp->ref_cnt.fetch_sub(1);
        if (ref_cnt == 1) { m_wb_cache.cp_start(bcp); }
    }

    static void flush_free_blks(SSDBtreeStore* store, const btree_cp_ptr& bcp,
                                std::shared_ptr< homestore::blkalloc_cp >& ba_cp) {
        store->flush_free_blks(bcp, ba_cp);
    }

    void flush_free_blks(const btree_cp_ptr& bcp, std::shared_ptr< homestore::blkalloc_cp >& ba_cp) {
        m_wb_cache.flush_free_blks(bcp, ba_cp);
    }

    static void truncate(SSDBtreeStore* store, const btree_cp_ptr& bcp) { store->truncate_store(bcp); }

    void truncate_store(const btree_cp_ptr& bcp) { m_journal->truncate(bcp->end_seqid); }

    static void cp_done(trigger_cp_callback cb) { wb_cache_t::cp_done(cb); }

    static void destroy_done(SSDBtreeStore* store) { store->destroy_done_store(); }

    void destroy_done_store() { home_log_store_mgr.remove_log_store(m_journal->get_store_id()); }

    static bool is_aligned_buf_needed(SSDBtreeStore* store, size_t size) {
        return HomeLogStore::is_aligned_buf_needed(size);
    }

    // bool is_aligned_buf_needed(size_t size) { return m_journal->is_aligned_buf_needed(size); }

    static uint8_t* get_physical(const SSDBtreeNode* bn) {
        wb_cache_buffer_t* bbuf = (wb_cache_buffer_t*)(bn);
        sisl::blob b = bbuf->at_offset(0);
        return b.bytes;
    }

    static uint32_t get_node_area_size(SSDBtreeStore* store) {
        return store->get_node_size() - sizeof(LeafPhysicalNode);
    }

    static boost::intrusive_ptr< SSDBtreeNode >
    alloc_node(SSDBtreeStore* store, bool is_leaf,
               bool& is_new_allocation, // indicates if allocated node is same as copy_from
               const boost::intrusive_ptr< SSDBtreeNode >& copy_from = nullptr) {
        is_new_allocation = true;
        homestore::blk_alloc_hints hints;
        homestore::BlkId blkid;
        auto safe_buf = m_blkstore->alloc_blk_cached(1 * store->get_node_size(), hints, &blkid);
        if (safe_buf == nullptr) {
            LOGERROR("btree alloc failed. No space avail");
            return nullptr;
        }
        return _init_node(store, safe_buf, is_leaf, blkid, copy_from);
    }

    static boost::intrusive_ptr< SSDBtreeNode >
    reserve_node(SSDBtreeStore* store, bool is_leaf, const BlkId& blkid,
                 const boost::intrusive_ptr< SSDBtreeNode >& copy_from = nullptr) {
        auto safe_buf = m_blkstore->init_blk_cached(blkid);
        if (safe_buf == nullptr) {
            LOGERROR("btree alloc failed. No space avail");
            return nullptr;
        }
        return _init_node(store, safe_buf, is_leaf, blkid, copy_from);
    }

    static boost::intrusive_ptr< SSDBtreeNode >
    _init_node(SSDBtreeStore* store, auto& safe_buf, bool is_leaf, const BlkId& blkid,
               const boost::intrusive_ptr< SSDBtreeNode >& copy_from = nullptr) {
        // Access the physical node buffer and initialize it
        sisl::blob b = safe_buf->at_offset(0);
        assert(b.size == store->get_node_size());
        if (is_leaf) {
            bnodeid_t bid = blkid.to_integer();
            auto n = new (b.bytes) VariantNode< LeafNodeType, K, V >(&bid, true, store->m_cfg);
        } else {
            bnodeid_t bid = blkid.to_integer();
            auto n = new (b.bytes) VariantNode< InteriorNodeType, K, V >(&bid, true, store->m_cfg);
        }
        boost::intrusive_ptr< SSDBtreeNode > new_node = boost::static_pointer_cast< SSDBtreeNode >(safe_buf);

        if (copy_from != nullptr) {
            copy_node(store, copy_from, new_node);
        } else {
            new_node->init();
        }
        return new_node;
    }

    uint32_t get_node_size() { return m_node_size; }
    wb_cache_t* get_wb_cache() { return &m_wb_cache; }

    static btree_status_t read_node(SSDBtreeStore* store, bnodeid_t id, boost::intrusive_ptr< SSDBtreeNode >& bnode) {
        auto ret = btree_status_t::success;
        // Read the data from the block store
        try {
#ifdef _PRERELEASE
            if (homestore_flip->test_flip("btree_read_fail", id)) { folly::throwSystemError("flip error"); }
#endif
            homestore::BlkId blkid(id);
            auto req = writeback_req_t::make_request();
            req->is_read = true;
            req->isSyncCall = true;
            auto cache_only = iomanager.am_i_tight_loop_reactor();

#ifndef NDEBUG
            /* testing slow path */
            if (iomanager.am_i_tight_loop_reactor() && homestore_flip->test_flip("btree_read_fast_path_not_possible")) {
                bnode = nullptr;
                LOGINFO("Trigger slow path intentionally.");
                return btree_status_t::fast_path_not_possible;
            }
#endif

            auto safe_buf = m_blkstore->read(blkid, 0, store->get_node_size(), req, cache_only);

            if (safe_buf == nullptr) {
                // only expect to see null buf when we are in spdk reactor;
                HS_ASSERT_CMP(DEBUG, iomanager.am_i_tight_loop_reactor(), ==, true);
                bnode = nullptr;
                return btree_status_t::fast_path_not_possible;
            }

            bnode = boost::static_pointer_cast< SSDBtreeNode >(safe_buf);
        } catch (std::exception& e) {
            LOGERROR("{}", e.what());
            ret = btree_status_t::read_failed;
            bnode = nullptr;
        }

        return ret;
    }

    static void copy_node(SSDBtreeStore* store, boost::intrusive_ptr< SSDBtreeNode > copy_from,
                          boost::intrusive_ptr< SSDBtreeNode > copy_to) {
        bnodeid_t original_to_id = copy_to->get_node_id();
        boost::intrusive_ptr< wb_cache_buffer_t > to_buff = boost::dynamic_pointer_cast< wb_cache_buffer_t >(copy_to);
        boost::intrusive_ptr< wb_cache_buffer_t > frm_buff =
            boost::dynamic_pointer_cast< wb_cache_buffer_t >(copy_from);
        to_buff->set_memvec(frm_buff->get_memvec_intrusive(), frm_buff->get_data_offset(), frm_buff->get_cache_size());
        copy_to->set_node_id(original_to_id); // restore original copy_to id
        copy_to->init();
    }

    static void swap_node(SSDBtreeStore* store, boost::intrusive_ptr< SSDBtreeNode > node1,
                          boost::intrusive_ptr< SSDBtreeNode > node2) {
        bnodeid_t id1 = node1->get_node_id();
        bnodeid_t id2 = node2->get_node_id();
        auto gen1 = node1->get_gen();
        auto gen2 = node2->get_gen();
        auto mvec1 = node1->get_memvec_intrusive();
        auto mvec2 = node2->get_memvec_intrusive();

        assert(node1->get_data_offset() == node2->get_data_offset());
        assert(node1->get_cache_size() == node2->get_cache_size());
        /* move the underneath memory */
        node1->set_memvec(mvec2, node1->get_data_offset(), node1->get_cache_size());
        node2->set_memvec(mvec1, node2->get_data_offset(), node2->get_cache_size());
        /* restore the node ids and gen */
        node1->set_node_id(id1);
        node1->set_gen(gen1);
        node1->inc_gen(); // we are incrementing the gen since contents are changed.
        node1->init();

        /* restore the node ids and gen */
        node2->set_node_id(id2);
        node2->set_gen(gen2);
        node2->inc_gen(); // we are incrementing the gen since contents are changed.
        node2->init();
    }

    static btree_status_t write_node_sync(SSDBtreeStore* store, boost::intrusive_ptr< SSDBtreeNode > bn) {
        try {
            auto req = writeback_req_t::make_request();
            req->is_read = false;
            req->isSyncCall = true;
            BlkId bid(bn->get_node_id().m_id);
            auto physical_node = (LeafPhysicalNode*)(bn->at_offset(0).bytes);
            physical_node->set_checksum(get_node_area_size(store));
            m_blkstore->write(bid, bn->get_memvec_intrusive(), 0, req, false);
        } catch (std::exception& e) {
            LOGERROR("{}", e.what());
            return btree_status_t::write_failed;
        }
        return btree_status_t::success;
    }

    static btree_status_t write_node(SSDBtreeStore* store, const boost::intrusive_ptr< SSDBtreeNode >& bn,
                                     const boost::intrusive_ptr< SSDBtreeNode >& dependent_bn,
                                     const btree_cp_ptr& bcp) {
        homestore::BlkId blkid(bn->get_node_id());

        auto physical_node = (LeafPhysicalNode*)(bn->at_offset(0).bytes);
        physical_node->set_checksum(get_node_area_size(store));
        store->get_wb_cache()->write(bn, dependent_bn, bcp);

        return btree_status_t::success;
    }

    static btree_status_t refresh_node(SSDBtreeStore* store, const boost::intrusive_ptr< SSDBtreeNode >& bn,
                                       bool is_write_modifiable, const btree_cp_ptr& bcp) {
        /* add the latest request pending on this node */
        auto ret = store->get_wb_cache()->refresh_buf(bn, is_write_modifiable, bcp);
        if (ret != btree_status_t::success) { return ret; }
        auto physical_node = (LeafPhysicalNode*)((boost::static_pointer_cast< SSDBtreeNode >(bn))->at_offset(0).bytes);
        verify_result vr;
        auto is_match = physical_node->verify_node(get_node_area_size(store), vr);
        if (!is_match) {
            LOGERROR("mismatch node: {} is it from cache", vr.to_string());
            assert(0);
            abort();
        }
        return btree_status_t::success;
    }

    static void free_node(SSDBtreeStore* store, const boost::intrusive_ptr< SSDBtreeNode >& bn,
                          const blkid_list_ptr& free_blkid_list, bool in_mem = false) {
        if (in_mem) { return; }
        store->get_wb_cache()->free_blk(bn->get_node_id(), free_blkid_list);
    }

    static void ref_node(SSDBtreeNode* bn) {
        homestore::CacheBuffer< homestore::BlkId >::ref((homestore::CacheBuffer< homestore::BlkId >&)*bn);
    }

    static void deref_node(SSDBtreeNode* bn) {
        homestore::CacheBuffer< homestore::BlkId >::deref((homestore::CacheBuffer< homestore::BlkId >&)*bn);
    }

    /************************** Journal entry section **********************/
    static sisl::io_blob make_journal_entry(journal_op op, bool is_root, const btree_cp_ptr& bcp,
                                            bt_node_gen_pair pair = {empty_bnodeid, 0}) {
        auto b = sisl::io_blob(journal_entry_initial_size(),
                               HomeLogStore::is_aligned_buf_needed(journal_entry_initial_size())
                                   ? HS_STATIC_CONFIG(disk_attr.align_size)
                                   : 0);
        new (b.bytes) btree_journal_entry(op, is_root, pair, bcp->cp_id);
        return b;
    }

    static inline constexpr btree_journal_entry* blob_to_entry(const sisl::io_blob& b) {
        return (btree_journal_entry*)b.bytes;
    }

    static void append_node_to_journal(sisl::io_blob& j_iob, bt_journal_node_op node_op,
                                       const boost::intrusive_ptr< SSDBtreeNode >& node, const btree_cp_ptr& bcp) {
        sisl::blob key_blob;
        K key;
        append_node_to_journal(j_iob, node_op, node, bcp, key_blob);
    }

    static void append_node_to_journal(sisl::io_blob& j_iob, bt_journal_node_op node_op,
                                       const boost::intrusive_ptr< SSDBtreeNode >& node, const btree_cp_ptr& bcp,
                                       const sisl::blob& key_blob) {
        uint16_t append_size = sizeof(bt_journal_node_info) + key_blob.size;
        auto e = realloc_if_needed(j_iob, append_size);
        e->append_node(node_op, node->get_node_id(), node->get_gen(), key_blob);

        if (node_op == bt_journal_node_op::creation) {
            bcp->btree_size.fetch_add(1);
        } else if (node_op == bt_journal_node_op::removal) {
            bcp->btree_size.fetch_sub(1);
        }
    }

    static void write_journal_entry(SSDBtreeStore* store, const btree_cp_ptr& bcp, sisl::io_blob& j_iob) {
        store->write_journal_entry_store(bcp, j_iob);
    }

private:
    void write_journal_entry_store(const btree_cp_ptr& bcp, sisl::io_blob& j_iob) {
        ++bcp->ref_cnt;

        // Update the size to actual size for unaligned buffer. For aligned we have to write entire buffer (since it
        // will avoid a copy and write directly)
        if (!j_iob.aligned) j_iob.size = blob_to_entry(j_iob)->actual_size;

        m_journal->append_async(
            j_iob, nullptr, ([this, bcp](logstore_seq_num_t seq_num, sisl::io_blob& iob, bool status, void* cookie) {
                btree_journal_entry* jentry = blob_to_entry(iob);
                if (jentry->op != journal_op::BTREE_CREATE) {
                    /*
                     * blk id is allocated for newly created nodes in disk bitmap only after it is
                     * writing to journal. check blk_alloctor base class for further explanations.
                     */
                    jentry->foreach_node(bt_journal_node_op::creation, [&](bt_node_gen_pair n, sisl::blob k) {
                        auto bid = BlkId(n.node_id);
                        // LOGINFO("Allocating blk inside btree journal entry {}", bid.to_string());
                        m_blkstore->reserve_blk(bid);
                    });
                    // For root node, disk bitmap is later persisted with btree root node.
                }
                jentry->~btree_journal_entry();
                iob.buf_free();

                try_cp_start(bcp);
            }));
    }

    static constexpr size_t journal_entry_alloc_increment = 256;
    static constexpr size_t journal_entry_initial_size() {
        return std::max(journal_entry_alloc_increment, sizeof(btree_journal_entry));
    }

    static btree_journal_entry* realloc_if_needed(sisl::io_blob& b, uint16_t append_size) {
        auto entry = blob_to_entry(b);
        assert(b.size > entry->actual_size);
        uint16_t avail_size = b.size - entry->actual_size;
        if (avail_size < append_size) {
            auto new_size = sisl::round_up(entry->actual_size + append_size, journal_entry_alloc_increment);
            b.buf_realloc(new_size,
                          HomeLogStore::is_aligned_buf_needed(new_size) ? HS_STATIC_CONFIG(disk_attr.align_size) : 0);
        }
        return blob_to_entry(b); // Get the revised entry from blob before returning
    }

private:
    ssd_btree_t* m_btree;
    std::shared_ptr< HomeLogStore > m_journal;
    BtreeConfig m_cfg;
    uint32_t m_node_size;
    wb_cache_t m_wb_cache;
    btree_cp_ptr m_first_cp;
    bool m_is_recovering = false;
    uint64_t m_replayed_count = 0;

private:
    static homestore::BlkStore< homestore::VdevFixedBlkAllocatorPolicy, wb_cache_buffer_t >* m_blkstore;
};

template < typename K, typename V, btree_node_type InteriorNodeType, btree_node_type LeafNodeType >
homestore::BlkStore< homestore::VdevFixedBlkAllocatorPolicy, wb_cache_buffer_t >* SSDBtreeStore::m_blkstore;

} // namespace btree
} // namespace homeds
