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
#include "btree_store.hpp"
#include "btree_node.h"
#include "physical_node.hpp"

extern int btree_buf_alloc;
extern int btree_buf_free;
extern int btree_buf_make_obj;
namespace homeds { namespace btree {

#define SSDBtreeNode  BtreeNode<SSD_BTREE, K, V, InteriorNodeType, LeafNodeType, NodeSize, homestore::writeback_req>
#define SSDBtreeStore BtreeStore<SSD_BTREE, K, V, InteriorNodeType, LeafNodeType, NodeSize, homestore::writeback_req>
#define btree_buffer_t BtreeBuffer<K, V, InteriorNodeType, LeafNodeType, NodeSize>

/* The class BtreeBuffer represents the buffer type that is used to interact with the BlkStore. It will have
 * all the SSD Btree Node declarative type. Hence in-memory representation of this buffer is as follows
 *
 *   ****************Cache Buffer************************
 *   *    ****************Cache Record***************   *
 *   *    *   ************Hash Node**************   *   *
 *   *    *   * Singly Linked list of hash node *   *   *
 *   *    *   ***********************************   *   *
 *   *    *******************************************   *
 *   * BlkId                                            *
 *   * Memvector of actual buffer                       *
 *   * Usage Reference counter                          *
 *   ****************************************************
 *   ************** Transient Header ********************
 *   * Upgraders count                                  *
 *   * Reader Write Lock                                *
 *   ****************************************************
 */
template<
        typename K,
        typename V,
        btree_node_type InteriorNodeType,
        btree_node_type LeafNodeType,
        size_t NodeSize
>
class BtreeBuffer : public homestore::WriteBackCacheBuffer< homestore::BlkId > {
public:
#ifndef NDEBUG
#endif
    static BtreeBuffer *make_object() {
        btree_buf_make_obj++;
        return homeds::ObjectAllocator< SSDBtreeNode >::make_object();
    }
    BtreeBuffer() {
        btree_buf_alloc++;
#ifndef NDEBUG
        is_btree = true;
        recovered = false;
#endif
        if (btree_buf_alloc > btree_buf_make_obj) {
            assert(0);
        }
    }
    virtual ~BtreeBuffer() {
        btree_buf_free++;
    }
};


struct btree_device_info {
    homestore::DeviceManager *dev_mgr;
    homestore::Cache< homestore::BlkId > *cache;
    homestore::vdev_info_block *vb;
    void *blkstore;
    uint64_t size;
    bool new_device;
    bool is_async;
};

template<
        typename K,
        typename V,
        btree_node_type InteriorNodeType,
        btree_node_type LeafNodeType,
        size_t NodeSize
        >
class SSDBtreeStore {
    typedef std::function< void (boost::intrusive_ptr<homestore::writeback_req> cookie,
           std::error_condition status) > comp_callback;

    struct ssd_btree_req : homestore::blkstore_req<btree_buffer_t> {
           boost::intrusive_ptr<homestore::writeback_req> cookie;
           BtreeStore<SSD_BTREE, K, V, InteriorNodeType, LeafNodeType, NodeSize, homestore::writeback_req> *btree_instance;
           ssd_btree_req() {};
           ~ssd_btree_req() {};
    };
public:
    using HeaderType = BtreeBuffer<K, V, InteriorNodeType, LeafNodeType, NodeSize>;

    static std::unique_ptr<SSDBtreeStore> init_btree(BtreeConfig &cfg, void *btree_specific_context,
            comp_callback comp_cb, bool is_in_recovery = false) {
        return std::unique_ptr<SSDBtreeStore>(new SSDBtreeStore(cfg,btree_specific_context, comp_cb, is_in_recovery));
    }

    BtreeStore(BtreeConfig &cfg, void *btree_specific_context, comp_callback comp_cbt, bool is_in_recovery) {
        m_comp_cb = comp_cbt;
        assert(comp_cbt);
        assert(m_comp_cb);
        m_is_in_recovery = is_in_recovery;
        m_cfg = cfg;
        m_cfg.set_node_area_size(NodeSize - sizeof(SSDBtreeNode) - sizeof(LeafPhysicalNode));

        auto bt_dev_info = (btree_device_info *)btree_specific_context;
 
        // Create or load the Blkstore out of this info
        if (bt_dev_info->new_device) {
            m_cache = new homestore::Cache< homestore::BlkId >(100 * 1024 * 1024, 4096);
            m_blkstore = new homestore::BlkStore<homestore::VdevFixedBlkAllocatorPolicy, 
                btree_buffer_t>(bt_dev_info->dev_mgr, m_cache, 0, 
                    homestore::BlkStoreCacheType::RD_MODIFY_WRITEBACK_CACHE, 0,
                    (std::bind(&SSDBtreeStore::process_req_completions,
                           this, std::placeholders::_1)), nullptr, bt_dev_info->size, 
                           HomeStoreConfig::atomic_phys_page_size);
        } else {
            m_blkstore = (homestore::BlkStore<homestore::VdevFixedBlkAllocatorPolicy, btree_buffer_t> *)
                                    bt_dev_info->blkstore;
            m_blkstore->attach_compl(std::bind(&SSDBtreeStore::process_completions, std::placeholders::_1));
        }
    }

    static void recovery_cmpltd(SSDBtreeStore *store) {
        store->m_is_in_recovery = false;  
    }

    static void process_completions(boost::intrusive_ptr<homestore::blkstore_req<btree_buffer_t>> bs_req) {
        boost::intrusive_ptr<ssd_btree_req> req = boost::static_pointer_cast<ssd_btree_req> (bs_req);
        req->btree_instance->process_req_completions(bs_req);
    }

    void process_req_completions(boost::intrusive_ptr<homestore::blkstore_req<btree_buffer_t>> bs_req) {
  
        boost::intrusive_ptr<ssd_btree_req> req = boost::static_pointer_cast<ssd_btree_req> (bs_req);
        assert(!req->isSyncCall);
        if (req->cookie) {
            m_comp_cb(req->cookie, req->err);
        }
    }

    static uint8_t *get_physical(const SSDBtreeNode *bn) {
        btree_buffer_t *bbuf = (btree_buffer_t *)(bn);
        homeds::blob b = bbuf->at_offset(0);
        assert(b.size == NodeSize);
        return b.bytes;
    }

    static uint32_t get_node_area_size(SSDBtreeStore *store) {
        return NodeSize - sizeof(SSDBtreeNode) - sizeof(LeafPhysicalNode);
    }

    static boost::intrusive_ptr<SSDBtreeNode> alloc_node(SSDBtreeStore *store, bool is_leaf,
                                           bool &is_new_allocation,// indicates if allocated node is same as copy_from
                                           boost::intrusive_ptr<SSDBtreeNode> copy_from = nullptr) {

        is_new_allocation=true;
        homestore::blk_alloc_hints hints;
        homestore::BlkId blkid;
        auto safe_buf = store->m_blkstore->alloc_blk_cached(1 * HomeStoreConfig::atomic_phys_page_size, hints, &blkid);


#ifndef NDEBUG
        assert(safe_buf->is_btree);
#endif
        // Access the physical node buffer and initialize it
        homeds::blob b = safe_buf->at_offset(0);
        assert(b.size == NodeSize);
        if (is_leaf) {
            bnodeid_t bid(blkid.to_integer(),0);
            auto n = new (b.bytes) VariantNode<LeafNodeType, K, V, NodeSize>( &bid, true, store->m_cfg);
        } else {
            bnodeid_t bid(blkid.to_integer(),0);
            auto n = new (b.bytes) VariantNode<InteriorNodeType, K, V, NodeSize>( &bid, true, store->m_cfg);
        }
        boost::intrusive_ptr<SSDBtreeNode> new_node = boost::static_pointer_cast<SSDBtreeNode>(safe_buf);

        if (copy_from != nullptr) { copy_node(store, copy_from, new_node); }
        return new_node;
    }

    static boost::intrusive_ptr<SSDBtreeNode> read_node(SSDBtreeStore *store, bnodeid_t id) {
        // Read the data from the block store
        homestore::BlkId blkid(id.m_id);
        boost::intrusive_ptr< ssd_btree_req >req(new ssd_btree_req());
        req->is_read = true;
        req->isSyncCall = true;
        auto safe_buf = store->m_blkstore->read(blkid, 0, NodeSize,
                        boost::static_pointer_cast<homestore::blkstore_req<btree_buffer_t>>(req));

#ifndef NDEBUG
        assert(safe_buf->is_btree);
#endif
        if (store->m_is_in_recovery) {
#ifndef NDEBUG
            safe_buf->recovered = true;
#endif
            store->m_blkstore->alloc_blk(blkid);
        }
        return boost::static_pointer_cast<SSDBtreeNode>(safe_buf);
    }

    static void copy_node(SSDBtreeStore *store, boost::intrusive_ptr<SSDBtreeNode> copy_from,
                        boost::intrusive_ptr<SSDBtreeNode> copy_to) {
        bnodeid_t original_to_id = copy_to->get_node_id();
        original_to_id.m_pc_gen_flag = copy_from->get_node_id().m_pc_gen_flag; //copy pc gen flag
        boost::intrusive_ptr< btree_buffer_t > to_buff = boost::dynamic_pointer_cast< btree_buffer_t >(copy_to);
        boost::intrusive_ptr< btree_buffer_t > frm_buff = boost::dynamic_pointer_cast< btree_buffer_t >(copy_from);
        to_buff->set_memvec(frm_buff->get_memvec_intrusive(), frm_buff->get_data_offset(), frm_buff->get_cache_size());
        copy_to->set_node_id(original_to_id);//restore original copy_to id
    }

    static void swap_node(SSDBtreeStore *impl, boost::intrusive_ptr<SSDBtreeNode> node1, 
                            boost::intrusive_ptr<SSDBtreeNode> node2) {
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
        node2->set_node_id(id2);
    }

    static void write_node(SSDBtreeStore *impl, boost::intrusive_ptr<SSDBtreeNode> bn, 
                        std::deque<boost::intrusive_ptr<homestore::writeback_req>> &dependent_req_q, 
                        boost::intrusive_ptr <homestore::writeback_req> cookie, 
                        bool is_sync) {
        homestore::BlkId blkid(bn->get_node_id().m_id);
        boost::intrusive_ptr< ssd_btree_req >req(new ssd_btree_req());
        req->is_read = false;
        req->cookie = cookie;
        if (is_sync) {
            req->isSyncCall = true;
        } else {
            req->isSyncCall = false;
        }
#ifndef NDEBUG
        assert(bn->is_btree);
#endif
        req->btree_instance = impl;
        impl->m_blkstore->write(blkid, 
                    boost::dynamic_pointer_cast<btree_buffer_t>(bn), 
                    boost::static_pointer_cast<homestore::blkstore_req<btree_buffer_t>>(req), 
                    dependent_req_q);
        /* empty the queue and add this request to the dependent req q. Now any further
         * writes of this btree update should depend on this request. 
         */
        while (!dependent_req_q.empty()) {
            dependent_req_q.pop_back();
        }
        dependent_req_q.push_back(boost::static_pointer_cast<homestore::writeback_req>(req));
    }

    static void read_node_lock(SSDBtreeStore *store,
            boost::intrusive_ptr<SSDBtreeNode> bn,
            bool is_write_modifiable, 
            std::deque<boost::intrusive_ptr<homestore::writeback_req>> *dependent_req_q) {
  
        /* add the latest request pending on this node */
        if (dependent_req_q) {
            auto req = store->m_blkstore->read_locked(boost::static_pointer_cast<btree_buffer_t>(bn), is_write_modifiable);
            if (req) { dependent_req_q->push_back(req); }
        }
    }

    static void free_node(SSDBtreeStore *store, boost::intrusive_ptr<SSDBtreeNode> bn,
                    std::deque<boost::intrusive_ptr<homestore::writeback_req>> &dependent_req_q) {
        homestore::BlkId blkid(bn->get_node_id().m_id);
        store->m_blkstore->free_blk(blkid, boost::none, boost::none, dependent_req_q);
    }

    static void ref_node(SSDBtreeNode *bn) {
        homestore::CacheBuffer< homestore::BlkId >::ref((homestore::CacheBuffer<homestore::BlkId> &)*bn);
    }


    static void deref_node(SSDBtreeNode *bn) {
        homestore::CacheBuffer< homestore::BlkId >::deref_testz((homestore::CacheBuffer<homestore::BlkId> &)*bn);
    }

private:
    homestore::BlkStore<homestore::VdevFixedBlkAllocatorPolicy, btree_buffer_t> *m_blkstore;

    comp_callback m_comp_cb;
    /* TODO: cache has lot of bugs because of locking which become more prominent with btree
     * which has lot of reads/writes. For now, it is better to have separate cache
     * for btree and move it to global cache later after fixing all the bugs.
     */
    homestore::Cache <homestore::BlkId>* m_cache;

    BtreeConfig m_cfg;
    bool m_is_in_recovery;
};
} }


