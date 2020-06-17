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

namespace homeds {
namespace btree {

#define SSDBtreeStore BtreeStore< btree_store_type::SSD_BTREE, K, V, InteriorNodeType, LeafNodeType >
#define ssd_btree_t Btree< btree_store_type::SSD_BTREE, K, V, InteriorNodeType, LeafNodeType >

template < typename K, typename V, btree_node_type InteriorNodeType, btree_node_type LeafNodeType >
class SSDBtreeStore {
public:
    using HeaderType = wb_cache_buffer_t;
    struct superblock {
        logstore_id_t journal_id;
    } __attribute((packed));

    static std::unique_ptr< SSDBtreeStore > init_btree(ssd_btree_t* btree, BtreeConfig& cfg) {
        static std::once_flag flag1;
        std::call_once(flag1, [&cfg]() { m_blkstore = (btree_blkstore_t*)cfg.blkstore; });
        return std::make_unique< SSDBtreeStore >(btree, cfg);
    }

    BtreeStore(ssd_btree_t* btree, BtreeConfig& cfg) :
            m_btree(btree),
            m_cfg(cfg),
            m_wb_cache(cfg.blkstore, cfg.align_size,
                       std::bind(&SSDBtreeStore::cp_done_store, this, std::placeholders::_1), cfg.trigger_cp_cb) {
        m_node_size = cfg.get_node_size();
        m_cfg.set_node_area_size(m_node_size - sizeof(LeafPhysicalNode));
        m_first_cp = btree_cp_id_ptr(new (btree_cp_id));
    }

    static void create_done(SSDBtreeStore* store, bnodeid_t m_root_node) { store->create_done_store(m_root_node); }

    /* It is called when its consumer has successfully persisted its superblock. */
    void create_done_store(bnodeid_t m_root_node) {
        auto bid = BlkId(m_root_node);
        m_blkstore->alloc_blk(bid);
    }

    void cp_done_store(btree_cp_id_ptr cp_id) { cp_id->cb(cp_id); }

    /* It attaches the new CP and prepare for cur cp flush */
    static btree_cp_id_ptr attach_prepare_cp(SSDBtreeStore* store, btree_cp_id_ptr cur_cp_id, bool is_last_cp) {
        return (store->attach_prepare_cp_store(cur_cp_id, is_last_cp));
    }

    btree_cp_id_ptr attach_prepare_cp_store(btree_cp_id_ptr cur_cp_id, bool is_last_cp) {
        /* start with ref cnt = 1. We dec it when trigger is called */
        if (cur_cp_id) {
            cur_cp_id->end_psn = m_journal->get_contiguous_issued_seq_num(cur_cp_id->start_psn);
            assert(cur_cp_id->end_psn >= cur_cp_id->start_psn);
        }
        if (cur_cp_id == m_first_cp) { m_first_cp = nullptr; }
        if (!cur_cp_id) {
            /* it can not be last cp if this volume hasn't participated yet in a cp */
            assert(!is_last_cp);
            assert(m_first_cp);
            return m_first_cp;
        }

        btree_cp_id_ptr new_cp(nullptr);
        if (!is_last_cp) {
            new_cp = btree_cp_id_ptr(new (btree_cp_id));
            new_cp->start_psn = cur_cp_id->end_psn;
            new_cp->cp_cnt = cur_cp_id->cp_cnt + 1;
        }
        m_wb_cache.prepare_cp(new_cp, cur_cp_id);
        return new_cp;
    }

    /* It is called only during first time create or after recovery */
    static void update_sb(SSDBtreeStore* store, SSDBtreeStore::superblock& sb, btree_cp_superblock* cp_sb,
                          bool is_recovery) {
        store->update_store_sb(sb, cp_sb, is_recovery);
    }

    void update_store_sb(SSDBtreeStore::superblock& sb, btree_cp_superblock* cp_sb, bool is_recovery) {
        if (is_recovery) {
            // add recovery code
            HomeLogStoreMgr::instance().open_log_store(
                sb.journal_id, ([this](std::shared_ptr< HomeLogStore > logstore) {
                    m_journal = logstore;
                    m_journal->register_log_found_cb(bind_this(SSDBtreeStore::log_found, 3));
                }));
        } else {
            m_journal = HomeLogStoreMgr::instance().create_new_log_store();
            sb.journal_id = get_journal_id_store();
        }

        m_first_cp->start_psn = cp_sb->active_psn;
        m_first_cp->cp_cnt = cp_sb->cp_cnt + 1;
        m_wb_cache.prepare_cp(m_first_cp, nullptr);
    }

    logstore_id_t get_journal_id_store() { return (m_journal->get_store_id()); }

    void log_found(logstore_seq_num_t seqnum, log_buffer log_buf, void* mem) {
#if 0
        auto& cp_sb = m_btree->get_last_cp_cb();
        if (seqnum >= cp_sb.active_psn) {
            // Entry is not replayed yet
            btree_journal_entry* jentry = (btree_journal_entry*)log_buf.bytes;
            if (jentry->op == journal_op::BTREE_SPLIT) { m_btree->split_node_replay(jentry, m_first_cp); }
        }

        if ()
#endif
    }

    static void cp_start(SSDBtreeStore* store, btree_cp_id_ptr cp_id, cp_comp_callback cb) {
        store->cp_start_store(cp_id, cb);
    }

    void cp_start_store(btree_cp_id_ptr cp_id, cp_comp_callback cb) {
        cp_id->cb = cb;
        try_cp_start(cp_id);
    }

    void try_cp_start(btree_cp_id_ptr cp_id) {
        auto ref_cnt = cp_id->ref_cnt.fetch_sub(1);
        if (ref_cnt == 1) { m_wb_cache.cp_start(cp_id); }
    }

    static void flush_free_blks(SSDBtreeStore* store, btree_cp_id_ptr btree_id,
                                std::shared_ptr< homestore::blkalloc_cp_id >& blkalloc_id) {
        store->flush_free_blks(btree_id, blkalloc_id);
    }

    void flush_free_blks(btree_cp_id_ptr btree_id, std::shared_ptr< homestore::blkalloc_cp_id >& blkalloc_id) {
        m_wb_cache.flush_free_blks(btree_id, blkalloc_id);
    }

    static void truncate(SSDBtreeStore* store, btree_cp_id_ptr cp_id) { store->truncate_store(cp_id); }

    void truncate_store(btree_cp_id_ptr cp_id) { m_journal->truncate(cp_id->end_psn); }

    static void cp_done(trigger_cp_callback cb) { wb_cache_t::cp_done(cb); }

    static void destroy_done(SSDBtreeStore* store) { store->destroy_done_store(); }

    void destroy_done_store() { home_log_store_mgr.remove_log_store(m_journal->get_store_id()); }

    static void write_journal_entry(SSDBtreeStore* store, btree_cp_id_ptr cp_id, btree_journal_entry* entry) {
        store->write_journal_entry_store(cp_id, entry);
    }

    void write_journal_entry_store(btree_cp_id_ptr cp_id, btree_journal_entry* entry) {
        ++cp_id->ref_cnt;
        sisl::blob b((uint8_t*)entry, entry->actual_size);
        m_journal->append_async(b, (void*)entry, ([this, cp_id](logstore_seq_num_t seq_num, bool status, void* cookie) {
                                    btree_journal_entry* jentry = (btree_journal_entry*)cookie;
                                    LOGINFO("btree_journal_entry: {}", jentry->to_string());
                                    if (jentry->op != journal_op::BTREE_CREATE) {
                                        /*
                                         * blk id is allocated for newly created nodes in disk bitmap only after it is
                                         * writing to journal. check blk_alloctor base class for further explanations.
                                         */
                                        jentry->foreach_node(bt_journal_node_op::creation,
                                                             [&](bt_node_gen_pair n, sisl::blob k) {
                                                                 auto bid = BlkId(n.node_id);
                                                                 m_blkstore->alloc_blk(bid);
                                                             });
                                        // For root node, disk bitmap is later persisted with btree root node.
                                    }

                                    jentry->~btree_journal_entry();
                                    free(jentry);
                                    try_cp_start(cp_id);
                                }));
    }

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
               boost::intrusive_ptr< SSDBtreeNode > copy_from = nullptr) {

        is_new_allocation = true;
        homestore::blk_alloc_hints hints;
        homestore::BlkId blkid;
        auto safe_buf = m_blkstore->alloc_blk_cached(1 * store->get_node_size(), hints, &blkid);
        if (safe_buf == nullptr) {
            LOGERROR("btree alloc failed. No space avail");
            return nullptr;
        }

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

        if (copy_from != nullptr) { copy_node(store, copy_from, new_node); }
        new_node->init();
        return new_node;
    }

    uint32_t get_node_size() { return m_node_size; }
    wb_cache_t* get_wb_cache() { return &m_wb_cache; }

    static boost::intrusive_ptr< SSDBtreeNode > read_node(SSDBtreeStore* store, bnodeid_t id) {
        // Read the data from the block store
        try {
#ifdef _PRERELEASE
            if (homestore_flip->test_flip("btree_read_fail", id)) { folly::throwSystemError("flip error"); }
#endif
            homestore::BlkId blkid(id);
            auto req = writeback_req_t::make_request();
            req->is_read = true;
            req->isSyncCall = true;
            auto safe_buf = m_blkstore->read(blkid, 0, store->get_node_size(), req);

            return boost::static_pointer_cast< SSDBtreeNode >(safe_buf);
        } catch (std::exception& e) {
            LOGERROR("{}", e.what());
            return nullptr;
        }
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
        auto mvec1 = node1->get_memvec_intrusive();
        auto mvec2 = node2->get_memvec_intrusive();

        assert(node1->get_data_offset() == node2->get_data_offset());
        assert(node1->get_cache_size() == node2->get_cache_size());
        /* move the underneath memory */
        node1->set_memvec(mvec2, node1->get_data_offset(), node1->get_cache_size());
        node2->set_memvec(mvec1, node2->get_data_offset(), node2->get_cache_size());
        /* restore the node ids */
        node1->set_node_id(id1);
        node1->init();
        node2->set_node_id(id2);
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
                                     const boost::intrusive_ptr< SSDBtreeNode >& dependent_bn, btree_cp_id_ptr cp_id) {
        homestore::BlkId blkid(bn->get_node_id());

        auto physical_node = (LeafPhysicalNode*)(bn->at_offset(0).bytes);
        physical_node->set_checksum(get_node_area_size(store));
        store->get_wb_cache()->write(bn, dependent_bn, cp_id);

        return btree_status_t::success;
    }

    static btree_status_t refresh_node(SSDBtreeStore* store, const boost::intrusive_ptr< SSDBtreeNode >& bn,
                                       bool is_write_modifiable, btree_cp_id_ptr cp_id) {

        /* add the latest request pending on this node */
        auto ret = store->get_wb_cache()->refresh_buf(bn, is_write_modifiable, cp_id);
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

    static void free_node(SSDBtreeStore* store, boost::intrusive_ptr< SSDBtreeNode > bn, bool mem_only,
                          btree_cp_id_ptr cp_id) {
        if (mem_only) {
            /* it will be automatically freed */
            return;
        }
        store->get_wb_cache()->free_blk(bn, cp_id);
    }

    static void ref_node(SSDBtreeNode* bn) {
        homestore::CacheBuffer< homestore::BlkId >::ref((homestore::CacheBuffer< homestore::BlkId >&)*bn);
    }

    static void deref_node(SSDBtreeNode* bn) {
        homestore::CacheBuffer< homestore::BlkId >::deref((homestore::CacheBuffer< homestore::BlkId >&)*bn);
    }

private:
    ssd_btree_t* m_btree;
    std::shared_ptr< HomeLogStore > m_journal;
    BtreeConfig m_cfg;
    uint32_t m_node_size;
    wb_cache_t m_wb_cache;
    btree_cp_id_ptr m_first_cp;

private:
    static homestore::BlkStore< homestore::VdevFixedBlkAllocatorPolicy, wb_cache_buffer_t >* m_blkstore;
};

template < typename K, typename V, btree_node_type InteriorNodeType, btree_node_type LeafNodeType >
homestore::BlkStore< homestore::VdevFixedBlkAllocatorPolicy, wb_cache_buffer_t >* SSDBtreeStore::m_blkstore;

} // namespace btree
} // namespace homeds
