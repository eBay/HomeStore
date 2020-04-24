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

#include "homeds/memory/composite_allocator.hpp"
#include "homeds/memory/chunk_allocator.hpp"
#include "homeds/memory/sys_allocator.hpp"
#include "cache/cache.h"
#include "blkstore/blkstore.hpp"
#include "writeBack_cache.hpp"
#include "btree_store.hpp"
#include "btree_node.h"
#include "physical_node.hpp"
#include "homelogstore/log_store.hpp"

namespace homeds {
namespace btree {

#define SSDBtreeStore BtreeStore< btree_store_type::SSD_BTREE, K, V, InteriorNodeType, LeafNodeType >

template < typename K, typename V, btree_node_type InteriorNodeType, btree_node_type LeafNodeType >
class SSDBtreeStore {

public:
    using HeaderType = wb_cache_buffer_t;
    struct superblock {
        logstore_id_t journal_id;
    } __attribute((packed));

    static std::unique_ptr< SSDBtreeStore > init_btree(BtreeConfig& cfg) {
        static std::once_flag flag1;
        std::call_once(flag1, [&cfg]() { m_blkstore = (btree_blkstore_t*)cfg.blkstore; });
        return std::unique_ptr< SSDBtreeStore >(new SSDBtreeStore(cfg));
    }

    BtreeStore(BtreeConfig& cfg) :
            m_cfg(cfg),
            m_wb_cache(cfg.blkstore, cfg.align_size,
                       std::bind(&SSDBtreeStore::cp_done_store, this, std::placeholders::_1), cfg.trigger_cp_cb) {
        m_node_size = cfg.get_node_size();
        m_cfg.set_node_area_size(m_node_size - sizeof(LeafPhysicalNode));
        m_journal = HomeLogStoreMgr::instance().create_new_log_store();
    }

    void cp_done_store(btree_cp_id_ptr cp_id) {
        m_wb_cache.flush_free_blk(cp_id);
        cp_id->cb(cp_id);
    }

    /* It attaches the new CP and prepare for cur cp flush */
    static btree_cp_id_ptr attach_prepare_cp(SSDBtreeStore* store, btree_cp_id_ptr cur_cp_id, bool is_last_cp) {
        return (store->attach_prepare_cp_store(cur_cp_id, is_last_cp));
    }

    btree_cp_id_ptr attach_prepare_cp_store(btree_cp_id_ptr cur_cp_id, bool is_last_cp) {
        /* start with ref cnt = 1. We dec it when trigger is called */
        if (cur_cp_id) {
            cur_cp_id->end_seq_id = m_journal->get_contiguous_issued_seq_num(cur_cp_id->start_seq_id);
            assert(cur_cp_id->end_seq_id >= cur_cp_id->start_seq_id);
        }
        btree_cp_id_ptr new_cp(nullptr);
        if (!is_last_cp) {
            new_cp = btree_cp_id_ptr(new (btree_cp_id));
            if (cur_cp_id) {
                new_cp->start_seq_id = cur_cp_id->end_seq_id;
                new_cp->cp_cnt = cur_cp_id->cp_cnt + 1;
            } else {
                new_cp->start_seq_id = m_journal->get_contiguous_issued_seq_num(-1);
                new_cp->cp_cnt = 1;
            }
        }
        m_wb_cache.prepare_cp(new_cp, cur_cp_id);
        return new_cp;
    }

    static void update_store_sb(SSDBtreeStore* store, SSDBtreeStore::superblock& sb) {
        sb.journal_id = store->get_journal_id_store();
    }

    logstore_id_t get_journal_id_store() { return (m_journal->get_store_id()); }

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

    static void truncate(SSDBtreeStore* store, btree_cp_id_ptr cp_id) { store->truncate_store(cp_id); }

    void truncate_store(btree_cp_id_ptr cp_id) { m_journal->truncate(cp_id->end_seq_id); }

    static void cp_done(trigger_cp_callback cb) { wb_cache_t::cp_done(cb); }

    static void destroy_done(SSDBtreeStore* store) { store->destroy_done_store(); }

    void destroy_done_store() { home_log_store_mgr.remove_log_store(m_journal->get_store_id()); }

    static void write_journal_entry(SSDBtreeStore* store, btree_cp_id_ptr cp_id, uint8_t* mem, size_t size) {
        store->write_journal_entry_store(cp_id, mem, size);
    }

    void write_journal_entry_store(btree_cp_id_ptr cp_id, uint8_t* mem, size_t size) {
        ++cp_id->ref_cnt;
        sisl::blob b(mem, size);
        m_journal->append_async(b, mem, ([this, cp_id](logstore_seq_num_t seq_num, bool status, void* cookie) {
                                    free(cookie);
                                    try_cp_start(cp_id);
                                }));
    }

    static uint8_t* get_physical(const SSDBtreeNode* bn) {
        wb_cache_buffer_t* bbuf = (wb_cache_buffer_t*)(bn);
        homeds::blob b = bbuf->at_offset(0);
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
        homeds::blob b = safe_buf->at_offset(0);
        assert(b.size == store->get_node_size());
        if (is_leaf) {
            bnodeid_t bid(blkid.to_integer(), 0);
            auto n = new (b.bytes) VariantNode< LeafNodeType, K, V >(&bid, true, store->m_cfg);
        } else {
            bnodeid_t bid(blkid.to_integer(), 0);
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
            if (homestore_flip->test_flip("btree_read_fail", (uint64_t)(id.m_id))) {
                folly::throwSystemError("flip error");
            }
#endif
            homestore::BlkId blkid(id.m_id);
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
        original_to_id.m_pc_gen_flag = copy_from->get_node_id().m_pc_gen_flag; // copy pc gen flag
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

    static btree_status_t write_node(SSDBtreeStore* store, boost::intrusive_ptr< SSDBtreeNode > bn,
                                     boost::intrusive_ptr< SSDBtreeNode > dependent_bn, btree_cp_id_ptr cp_id) {
        homestore::BlkId blkid(bn->get_node_id().m_id);

        auto physical_node = (LeafPhysicalNode*)(bn->at_offset(0).bytes);
        physical_node->set_checksum(get_node_area_size(store));
        store->get_wb_cache()->write(bn, dependent_bn, cp_id);

        return btree_status_t::success;
    }

    static btree_status_t refresh_node(SSDBtreeStore* store, boost::intrusive_ptr< SSDBtreeNode > bn,
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
    std::shared_ptr< HomeLogStore > m_journal;
    BtreeConfig m_cfg;
    uint32_t m_node_size;
    wb_cache_t m_wb_cache;

private:
    static homestore::BlkStore< homestore::VdevFixedBlkAllocatorPolicy, wb_cache_buffer_t >* m_blkstore;
};

template < typename K, typename V, btree_node_type InteriorNodeType, btree_node_type LeafNodeType >
homestore::BlkStore< homestore::VdevFixedBlkAllocatorPolicy, wb_cache_buffer_t >* SSDBtreeStore::m_blkstore;

} // namespace btree
} // namespace homeds
