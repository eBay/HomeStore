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

namespace homeds {
namespace btree {

#define SSDBtreeNode BtreeNode< btree_store_type::SSD_BTREE, K, V, InteriorNodeType, LeafNodeType, homestore::writeback_req >
#define SSDBtreeStore BtreeStore< btree_store_type::SSD_BTREE, K, V, InteriorNodeType, LeafNodeType, homestore::writeback_req >
#define btree_buffer_t BtreeBuffer< K, V, InteriorNodeType, LeafNodeType >
#define ssdbtree_multinode_req_ptr boost::intrusive_ptr < btree_multinode_req < homestore::writeback_req > > 

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
template < typename K, typename V, btree_node_type InteriorNodeType, btree_node_type LeafNodeType >
class BtreeBuffer : public homestore::WriteBackCacheBuffer< homestore::BlkId > {
    /* error is set if any write fails. Read from the same buffer keep on failing
     * until it is not evicted from the cache.
     */
    sisl::atomic_counter< uint32_t > is_err;
public:
#ifndef NDEBUG
#endif
    static BtreeBuffer* make_object() { return homeds::ObjectAllocator< SSDBtreeNode >::make_object(); }
    BtreeBuffer(): is_err(0) {
#ifndef NDEBUG
        is_btree = true;
        recovered = false;
#endif
    }
    virtual ~BtreeBuffer() = default;
    virtual void free_yourself() override { ObjectAllocator< SSDBtreeNode >::deallocate((SSDBtreeNode*)this); }
    // virtual size_t get_your_size() const override { return sizeof(SSDBtreeNode); }
    void set_error() {
        is_err.increment();
    }

    bool is_err_set() {
        return is_err.get() != 0 ? true : false;
    }

    virtual void init() override {
        /* Note : it is called under cache lock to prevent multiple threads to call init. And init function
         * internally also try to take the cache lock to access cache to update in memory structure. So 
         * we have to be careful in taking any lock inside this function.
         */
        ((SSDBtreeNode *)this)->init();
    }
};

struct btree_device_info {
    homestore::DeviceManager*             dev_mgr;
    homestore::Cache< homestore::BlkId >* cache;
    homestore::vdev_info_block*           vb;
    void*                                 blkstore;
    uint64_t                              size;
    bool                                  new_device;
    bool                                  is_async;
};

template < typename K, typename V, btree_node_type InteriorNodeType, btree_node_type LeafNodeType >
class SSDBtreeStore {
    typedef std::function< void(btree_status_t status, ssdbtree_multinode_req_ptr multinode_req) > 
                            comp_callback;

    struct ssd_btree_req : homestore::blkstore_req< btree_buffer_t > {
        ssdbtree_multinode_req_ptr      multinode_req;
        SSDBtreeStore* instance;
        boost::intrusive_ptr< btree_buffer_t > ssd_buf;

        ssd_btree_req(){};
        ~ssd_btree_req(){};

        // virtual size_t get_your_size() const override { return sizeof(ssd_btree_req); }
        static boost::intrusive_ptr< ssd_btree_req > make_object() {
            return boost::intrusive_ptr< ssd_btree_req >(homeds::ObjectAllocator< ssd_btree_req >::make_object());
        }
        virtual void free_yourself() override { homeds::ObjectAllocator< ssd_btree_req >::deallocate(this); }
    };

public:
    using HeaderType = BtreeBuffer< K, V, InteriorNodeType, LeafNodeType >;

    static std::unique_ptr< SSDBtreeStore > init_btree(BtreeConfig& cfg, void* btree_specific_context,
                                                       comp_callback comp_cb, bool is_in_recovery = false) {
        return std::unique_ptr< SSDBtreeStore >(
            new SSDBtreeStore(cfg, btree_specific_context, comp_cb, is_in_recovery));
    }

    BtreeStore(BtreeConfig& cfg, void* btree_specific_context, comp_callback comp_cbt, bool is_in_recovery) : m_cfg(cfg) {
        m_comp_cb = comp_cbt;
        DEBUG_ASSERT((m_comp_cb != nullptr), "Expected m_comp_cb to valid");
        assert(comp_cbt);
        assert(m_comp_cb);
        m_is_in_recovery = is_in_recovery;
        m_node_size = cfg.get_node_size();
        m_cfg.set_node_area_size(m_node_size - sizeof(LeafPhysicalNode));

        auto bt_dev_info = (btree_device_info*)btree_specific_context;

        // Create or load the Blkstore out of this info
        if (bt_dev_info->new_device) {
            m_cache = new homestore::Cache< homestore::BlkId >(100 * 1024 * 1024, 4096);

            assert(bt_dev_info->dev_mgr != nullptr);

            m_blkstore = new homestore::BlkStore< homestore::VdevFixedBlkAllocatorPolicy, btree_buffer_t >(
                bt_dev_info->dev_mgr, m_cache, 0, homestore::BlkStoreCacheType::RD_MODIFY_WRITEBACK_CACHE, 0,
                nullptr, bt_dev_info->size, m_node_size, "Btree",
                (std::bind(&SSDBtreeStore::process_completions, std::placeholders::_1)));
        } else {
            m_blkstore =
                (homestore::BlkStore< homestore::VdevFixedBlkAllocatorPolicy, btree_buffer_t >*)bt_dev_info->blkstore;
            m_blkstore->attach_compl(std::bind(&SSDBtreeStore::process_completions, std::placeholders::_1));
        }
    }

    static void recovery_cmpltd(SSDBtreeStore* store) { store->m_is_in_recovery = false; }

    static void process_completions(boost::intrusive_ptr< homestore::blkstore_req< btree_buffer_t > > bs_req) {
        assert(!bs_req->isSyncCall);
        boost::intrusive_ptr< ssd_btree_req > req = boost::static_pointer_cast< ssd_btree_req >(bs_req);
        req->instance->process_req_completions(req, (req->err ? btree_status_t::write_failed : btree_status_t::success));

    }

    void process_req_completions(boost::intrusive_ptr< ssd_btree_req > req, btree_status_t status) {
        if (status != btree_status_t::success) {
            req->ssd_buf->set_error();
        }
        m_comp_cb(status, req->multinode_req);
    }

    static uint8_t* get_physical(const SSDBtreeNode* bn) {
        btree_buffer_t* bbuf = (btree_buffer_t*)(bn);
        homeds::blob    b = bbuf->at_offset(0);
        return b.bytes;
    }

    static uint32_t get_node_area_size(SSDBtreeStore* store) { return store->get_node_size() - sizeof(LeafPhysicalNode); }

    static boost::intrusive_ptr< SSDBtreeNode >
    alloc_node(SSDBtreeStore* store, bool is_leaf,
               bool& is_new_allocation, // indicates if allocated node is same as copy_from
               boost::intrusive_ptr< SSDBtreeNode > copy_from = nullptr) {

        is_new_allocation = true;
        homestore::blk_alloc_hints hints;
        homestore::BlkId           blkid;
        auto safe_buf = store->m_blkstore->alloc_blk_cached(1 * store->get_node_size(), hints, &blkid);
        if (safe_buf == nullptr) {
            LOGERROR("btree alloc failed. No space avail");
            return nullptr;
        }

#ifndef NDEBUG
        assert(safe_buf->is_btree);
#endif
        // Access the physical node buffer and initialize it
        homeds::blob b = safe_buf->at_offset(0);
        assert(b.size == store->get_node_size());
        if (is_leaf) {
            bnodeid_t bid(blkid.to_integer(), 0);
            auto      n = new (b.bytes) VariantNode< LeafNodeType, K, V >(&bid, true, store->m_cfg);
        } else {
            bnodeid_t bid(blkid.to_integer(), 0);
            auto      n = new (b.bytes) VariantNode< InteriorNodeType, K, V >(&bid, true, store->m_cfg);
        }
        boost::intrusive_ptr< SSDBtreeNode > new_node = boost::static_pointer_cast< SSDBtreeNode >(safe_buf);

        if (copy_from != nullptr) {
            copy_node(store, copy_from, new_node);
        }
        new_node->init();
        return new_node;
    }

    uint32_t get_node_size() { return m_node_size; };
    static boost::intrusive_ptr< SSDBtreeNode > read_node(SSDBtreeStore* store, bnodeid_t id) {
        // Read the data from the block store
        try {
#ifdef _PRERELEASE
            if (homestore_flip->test_flip("btree_read_fail", (uint64_t)(id.m_id))) {
                folly::throwSystemError("flip error");
            }
#endif
            homestore::BlkId blkid(id.m_id);
            auto             req = ssd_btree_req::make_object();
            req->is_read = true;
            if (store->m_is_in_recovery) {
                store->m_blkstore->alloc_blk(blkid);
            }
            req->isSyncCall = true;
            auto safe_buf = store->m_blkstore->read(
                    blkid, 0, store->get_node_size(), boost::static_pointer_cast< homestore::blkstore_req< btree_buffer_t > >(req));

#ifndef NDEBUG
            if (store->m_is_in_recovery) {
                safe_buf->recovered = true;
            }
            assert(safe_buf->is_btree);
#endif
            return boost::static_pointer_cast< SSDBtreeNode >(safe_buf);
        } catch (std::exception &e) {
            LOGERROR("{}", e.what());
            return nullptr;
        }
    }

    static void copy_node(SSDBtreeStore* store, boost::intrusive_ptr< SSDBtreeNode > copy_from,
                          boost::intrusive_ptr< SSDBtreeNode > copy_to) {
        bnodeid_t original_to_id = copy_to->get_node_id();
        original_to_id.m_pc_gen_flag = copy_from->get_node_id().m_pc_gen_flag; // copy pc gen flag
        boost::intrusive_ptr< btree_buffer_t > to_buff = boost::dynamic_pointer_cast< btree_buffer_t >(copy_to);
        boost::intrusive_ptr< btree_buffer_t > frm_buff = boost::dynamic_pointer_cast< btree_buffer_t >(copy_from);
        to_buff->set_memvec(frm_buff->get_memvec_intrusive(), frm_buff->get_data_offset(), frm_buff->get_cache_size());
        copy_to->set_node_id(original_to_id); // restore original copy_to id
        copy_to->init();
    }

    static void swap_node(SSDBtreeStore* impl, boost::intrusive_ptr< SSDBtreeNode > node1,
                          boost::intrusive_ptr< SSDBtreeNode > node2) {
        bnodeid_t id1 = node1->get_node_id();
        bnodeid_t id2 = node2->get_node_id();
        auto      mvec1 = node1->get_memvec_intrusive();
        auto      mvec2 = node2->get_memvec_intrusive();

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

    static btree_status_t write_node(SSDBtreeStore* impl, boost::intrusive_ptr< SSDBtreeNode > bn,
                           ssdbtree_multinode_req_ptr multinode_req) {
        auto req = ssd_btree_req::make_object();
        homestore::BlkId blkid(bn->get_node_id().m_id);
        req->is_read = false;
        req->multinode_req = multinode_req;
        req->isSyncCall = multinode_req ? multinode_req->is_sync : true;
#ifndef NDEBUG
        assert(bn->is_btree);
#endif

#ifndef NO_CHECKSUM
        auto physical_node = (LeafPhysicalNode*)(bn->at_offset(0).bytes);
        physical_node->set_checksum(get_node_area_size(impl));
#endif

        req->instance = impl;
        req->ssd_buf = boost::dynamic_pointer_cast< btree_buffer_t >(bn);
        if (multinode_req) {
            multinode_req->writes_pending.increment(1);
        }
        try {
            if (multinode_req) {
                impl->m_blkstore->write(blkid, req->ssd_buf,
                        boost::static_pointer_cast< homestore::blkstore_req< btree_buffer_t > >(req),
                        multinode_req->dependent_req_q);
#ifndef NDEBUG
                {
                    if (!req->isSyncCall) {
                        multinode_req->child_req_q.push_back((uint64_t)req.get());
                    }
                }
#endif
            } else {
                std::deque< boost::intrusive_ptr< homestore::writeback_req > >dependent_req_q(0);
                impl->m_blkstore->write(blkid, req->ssd_buf,
                        boost::static_pointer_cast< homestore::blkstore_req< btree_buffer_t > >(req),
                        dependent_req_q);
                return btree_status_t::success;
            }
           
            /* empty the queue and add this request to the dependent req q. Now any further
             * writes of this btree update should depend on this request.
             */
            while (!multinode_req->dependent_req_q.empty()) {
                multinode_req->dependent_req_q.pop_back();
            }
            multinode_req->dependent_req_q.push_back(boost::static_pointer_cast< homestore::writeback_req >(req));
        } catch (const std::exception& e) {
            LOGERROR("{}", e.what());

            /* Call process req completions for both sync and async. It will be ignored for sync
             * in the callee.
             */
            impl->process_req_completions(req, btree_status_t::write_failed);
            return btree_status_t::write_failed;
        }
        return btree_status_t::success;
    }

    static btree_status_t refresh_node(SSDBtreeStore* store, boost::intrusive_ptr< SSDBtreeNode > bn, 
                        ssdbtree_multinode_req_ptr multinode_req, bool is_write_modifiable) {

        if (boost::static_pointer_cast< btree_buffer_t >(bn)->is_err_set()) {
            LOGERROR("failing refresh");
            return btree_status_t::stale_buf;
        }

        /* add the latest request pending on this node */
        try {
            auto req =
                store->m_blkstore->refresh_buf(boost::static_pointer_cast< btree_buffer_t >(bn), is_write_modifiable);
            if (req && multinode_req) {
                multinode_req->dependent_req_q.push_back(req);
            }
#ifdef _PRERELEASE
            if (homestore_flip->test_flip("btree_refresh_fail", bn->get_node_id().m_id)) {
                folly::throwSystemError("flip error");
            }
#endif
#ifndef NO_CHECKSUM
            auto physical_node = (LeafPhysicalNode*)((boost::static_pointer_cast< SSDBtreeNode >(bn))->at_offset(0).bytes);
            verify_result vr;
            auto is_match = physical_node->verify_node(get_node_area_size(store),vr);
            if (!is_match) {
                LOGERROR("mismatch node: {} is it from cache", vr.to_string());
                assert(0);
                abort();
            }
#endif
        } catch (std::exception &e) {
            LOGERROR("{}", e.what());
            return  btree_status_t::refresh_failed;
        }
        return btree_status_t::success;
    }

    static void free_node(SSDBtreeStore* store, boost::intrusive_ptr< SSDBtreeNode > bn,
                            ssdbtree_multinode_req_ptr multinode_req, bool mem_only = false) {
        homestore::BlkId blkid(bn->get_node_id().m_id);
        if (multinode_req) {
            store->m_blkstore->free_blk(blkid, boost::none, boost::none, multinode_req->dependent_req_q, mem_only);
        } else {
            std::deque< boost::intrusive_ptr< homestore::writeback_req > >dependent_req_q(0);
            store->m_blkstore->free_blk(blkid, boost::none, boost::none, dependent_req_q, mem_only);
        }       
    }

    static void ref_node(SSDBtreeNode* bn) {
        homestore::CacheBuffer< homestore::BlkId >::ref((homestore::CacheBuffer< homestore::BlkId >&)*bn);
    }

    static void deref_node(SSDBtreeNode* bn) {
        homestore::CacheBuffer< homestore::BlkId >::deref((homestore::CacheBuffer< homestore::BlkId >&)*bn);
    }

private:
    homestore::BlkStore< homestore::VdevFixedBlkAllocatorPolicy, btree_buffer_t >* m_blkstore;

    comp_callback m_comp_cb;
    /* TODO: cache has lot of bugs because of locking which become more prominent with btree
     * which has lot of reads/writes. For now, it is better to have separate cache
     * for btree and move it to global cache later after fixing all the bugs.
     */
    homestore::Cache< homestore::BlkId >* m_cache;

    BtreeConfig m_cfg;
    bool        m_is_in_recovery;
    uint32_t    m_node_size;
};
} // namespace btree
} // namespace homeds
