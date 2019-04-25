/*
 *  Created on: 14-May-2016
 *      Author: Hari Kadayam
 *
 *  Copyright © 2016 Kadayam, Hari. All rights reserved.
 */
#pragma once

#include <iostream>
#include <cassert>
#include <pthread.h>
#include <vector>
#include <atomic>
#include <array>
#include "homeds/thread/lock.hpp"
#include "btree_internal.h"
#include "btree_node.cpp"
#include "physical_node.hpp"
#include <sds_logging/logging.h>
#include <boost/intrusive_ptr.hpp>
#include <error/error.h>
#include <csignal>
#include "homeds/utility/useful_defs.hpp"
#include <spdlog/fmt/bundled/ostream.h>
#include "homeds/array/reserve_vector.hpp"

using namespace std;
using namespace homeds::thread;

#ifndef NDEBUG
#define MAX_BTREE_DEPTH 100
#endif

SDS_LOGGING_DECL(btree_structures, btree_nodes, btree_generics)

/* TODO: Temporary till we move this to sds_logging for general consumption */
#ifndef NDEBUG
#define DLOGCRITICAL(...) LOGCRITICAL(__VA_ARGS__)
#define DLOGERROR(...)    LOGERROR(__VA_ARGS__)
#define DLOGWARN(...)     LOGWARN(__VA_ARGS__)
#define DLOGINFO(...)     LOGINFO(__VA_ARGS__)
#define DLOGDEBUG(...)    LOGDEBUG(__VA_ARGS__)
#define DLOGTRACE(...)    LOGTRACE(__VA_ARGS__)

#define DLOGCRITICALMOD(...) LOGCRITICALMOD(__VA_ARGS__)
#define DLOGERRORMOD(...)    LOGERRORMOD(__VA_ARGS__)
#define DLOGWARNMOD(...)     LOGWARNMOD(__VA_ARGS__)
#define DLOGINFOMOD(...)     LOGINFOMOD(__VA_ARGS__)
#define DLOGDEBUGMOD(...)    LOGDEBUGMOD(__VA_ARGS__)
#define DLOGTRACEMOD(...)    LOGTRACEMOD(__VA_ARGS__)
#else
#define DLOGCRITICAL(...) 
#define DLOGERROR(...)    
#define DLOGWARN(...)     
#define DLOGINFO(...)     
#define DLOGDEBUG(...)    
#define DLOGTRACE(...)    

#define DLOGCRITICALMOD(...) 
#define DLOGERRORMOD(...)    
#define DLOGWARNMOD(...)     
#define DLOGINFOMOD(...)     
#define DLOGDEBUGMOD(...)    
#define DLOGTRACEMOD(...)    
#endif
namespace homeds {
namespace btree {

#if 0
#define container_of(ptr, type, member) ({ (type*)((char*)ptr - offsetof(type, member)); })
#endif

#define btree_t Btree< BtreeStoreType, K, V, InteriorNodeType, LeafNodeType, NodeSize, btree_req_type >

struct btree_super_block {
    bnodeid root_node;
} __attribute((packed));

template < btree_store_type BtreeStoreType, typename K, typename V, btree_node_type InteriorNodeType,
        btree_node_type LeafNodeType, size_t NodeSize = 8192, typename btree_req_type = struct empty_writeback_req >
struct _btree_locked_node_info {
    btree_node_t* node;
    Clock::time_point start_time;
};

#define btree_locked_node_info  \
    _btree_locked_node_info< BtreeStoreType, K, V, InteriorNodeType, LeafNodeType, NodeSize, btree_req_type>


template < btree_store_type BtreeStoreType, typename K, typename V, btree_node_type InteriorNodeType,
           btree_node_type LeafNodeType, size_t NodeSize = 8192, typename btree_req_type = struct empty_writeback_req >
class Btree {
    typedef std::function< void(boost::intrusive_ptr< btree_req_type > cookie, bool status) > comp_callback;
    typedef std::function< void (V& mv) >      free_blk_callback;
    typedef std::function< void () >           destroy_btree_comp_callback;

private:
    bnodeid_t              m_root_node;
    homeds::thread::RWLock m_btree_lock;

    uint32_t          m_max_nodes;
    BtreeConfig       m_btree_cfg;
    btree_super_block m_sb;

    BtreeMetrics                     m_metrics;
    std::unique_ptr< btree_store_t > m_btree_store;
    comp_callback m_comp_cb;

    static thread_local homeds::reserve_vector< btree_locked_node_info, 5 >  wr_locked_nodes;
    static thread_local homeds::reserve_vector< btree_locked_node_info, 5 >  rd_locked_nodes;

    ////////////////// Implementation /////////////////////////
public:
    btree_super_block get_btree_sb() {
        return m_sb;
    }
    
    void process_completions(btree_status_t status, btree_multinode_req_ptr multinode_req) {
        
        if (!multinode_req) {
            return;
        }
        if (multinode_req->status == btree_status_t::success) {
            multinode_req->status = status;
        }
        if (multinode_req->writes_pending.decrement_testz()) {
            if (m_comp_cb && multinode_req->cookie) {
                assert(!multinode_req->is_sync);
                m_comp_cb(multinode_req->cookie, 
                        (multinode_req->status == btree_status_t::success) ? true : false);
            }

            /* initialize this req to empty the dependent req_q */
            multinode_req->cmpltd();
        }
    }

    static btree_t *create_btree(BtreeConfig &cfg, void *btree_specific_context, comp_callback comp_cb) {
        Btree *bt = new Btree(cfg);
        bt->m_comp_cb = comp_cb;
        auto impl_ptr = btree_store_t::init_btree(cfg, btree_specific_context, 
                std::bind(&Btree::process_completions, bt, std::placeholders::_1, std::placeholders::_2));
        bt->m_btree_store = std::move(impl_ptr);
        btree_status_t ret = bt->init();
        if (ret != btree_status_t::success)  {
            LOGERROR("btree create failed. error {} name {}", ret, cfg.get_name());
            return nullptr;
        }
        
        LOGINFO("btree created {}", cfg.get_name());
        return bt;
    }

    static btree_t* create_btree(BtreeConfig& cfg, void* btree_specific_context) {
        auto impl_ptr = btree_store_t::init_btree(cfg, btree_specific_context, nullptr);
        Btree *bt = new Btree(cfg);
        bt->m_btree_store = std::move(impl_ptr);
        btree_status_t ret = bt->init();
        if (ret != btree_status_t::success)  {
            LOGERROR("btree create failed. error {} name {}", ret, cfg.get_name());
            return nullptr;
        }
        LOGINFO("btree created {}", cfg.get_name());
        return bt;
    }

    static btree_t *create_btree(btree_super_block &btree_sb, BtreeConfig& cfg,
                                    void *btree_specific_context, comp_callback comp_cb) {
        Btree *bt = new Btree(cfg);
        bt->m_comp_cb = comp_cb;
        auto impl_ptr = btree_store_t::init_btree(cfg, btree_specific_context,
                std::bind(&Btree::process_completions, bt, std::placeholders::_1, std::placeholders::_2), true);
        bt->m_btree_store = std::move(impl_ptr);
        bt->init_recovery(btree_sb);
        LOGINFO("btree recovered and created {}", cfg.get_name());
        return bt;
    }

    void do_common_init() {
        BtreeNodeAllocator< NodeSize >::create();

        // TODO: Check if node_area_size need to include persistent header
        uint32_t node_area_size = btree_store_t::get_node_area_size(m_btree_store.get());
        m_btree_cfg.set_node_area_size(node_area_size);

        // calculate number of nodes
        uint32_t max_leaf_nodes =
            (m_btree_cfg.get_max_objs() * (m_btree_cfg.get_max_key_size() + m_btree_cfg.get_max_value_size())) /
                node_area_size + 1;
        max_leaf_nodes += (100 * max_leaf_nodes) / 60; // Assume 60% btree full

        m_max_nodes = max_leaf_nodes + ((double) max_leaf_nodes * 0.05) + 1; // Assume 5% for interior nodes
    }
    
    btree_status_t init() {
        do_common_init();
        return(create_root_node());
    }
    
    void init_recovery(btree_super_block btree_sb){
        m_sb = btree_sb;
        do_common_init();
        m_root_node = m_sb.root_node;
    }

    Btree(BtreeConfig &cfg) :
            m_btree_cfg(cfg),
            m_metrics(BtreeStoreType, cfg.get_name().c_str()) {}
    
    ~Btree() {
        destroy();
    }
        
    btree_status_t destroy(free_blk_callback free_blk_cb = nullptr, destroy_btree_comp_callback destroy_btree_comp_cb = nullptr) {
        m_btree_lock.write_lock();
        BtreeNodePtr  root;
        homeds::thread::locktype acq_lock = LOCKTYPE_WRITE;
        
        btree_multinode_req_ptr multinode_req = btree_multinode_req<btree_req_type>::make_request();
        auto ret = read_and_lock_root(m_root_node, root, acq_lock, acq_lock, multinode_req);
        if (ret != btree_status_t::success) {
            m_btree_lock.unlock();
            return ret;
        }
        ret = free(root, free_blk_cb, multinode_req);
        unlock_node(root, acq_lock);
        m_btree_lock.unlock();
        // if this is a delete vol call, send the comp callback to caller;
        if (ret == btree_status_t::success && destroy_btree_comp_cb) {
            /* XXX: do we need to pass the status to callback */
            destroy_btree_comp_cb();
        }
        DLOGDEBUG("btree nodes destroyed {}", m_btree_cfg.get_name());
        return ret;
    }

    void recovery_cmpltd() { 
        btree_store_t::recovery_cmpltd(m_btree_store.get()); 
        DLOGDEBUG("recovery completed {}", m_btree_cfg.get_name());
    }

    // 
    // 1. free nodes in post order traversal of tree to free non-leaf node
    // 2. If free_blk_cb is not null, callback to caller for leaf node's blk_id;
    // Assumption is that there are no pending IOs when it is called.
    // 
    btree_status_t free(BtreeNodePtr node, free_blk_callback free_blk_cb, btree_multinode_req_ptr multinode_req) {
        // TODO - this calls free node on mem_tree and ssd_tree.
        // In ssd_tree we free actual block id, which is not correct behavior
        // we shouldnt really free any blocks on free node, just reclaim any memory
        // occupied by ssd_tree structure in memory. Ideally we should have sepearte
        // api like deleteNode which should be called instead of freeNode
        homeds::thread::locktype                             acq_lock = homeds::thread::LOCKTYPE_WRITE;
        uint32_t                                             i = 0;
        btree_status_t ret = btree_status_t::success;
 
        if (!node->is_leaf()) {
            BtreeNodeInfo child_info;
            while (i <= node->get_total_entries()) {
                if (i == node->get_total_entries()) {
                    if(!(node->get_edge_id().is_valid()))break;
                    child_info.set_bnode_id(node->get_edge_id());
                } else {
                    node->get(i, &child_info, false /* copy */);
                }

                BtreeNodePtr child;
                ret = read_and_lock_child(child_info.bnode_id(), child, node, i, acq_lock, acq_lock, multinode_req);
                if (ret != btree_status_t::success) {
                    return ret;
                }
                ret = free(child, free_blk_cb, multinode_req);
                unlock_node(child, acq_lock);
                i++;
            }
        } else if (free_blk_cb) {
            // get value from leaf node and return to caller via callback;
            for (uint32_t i = 0; i < node->get_total_entries(); i++) {
                V val;
                node->get(i, &val, false);
                // Caller will free the blk in blkstore in sync mode, which is fine since it is in-memory operation;
                free_blk_cb(val);
            }
        }
      
        if (ret != btree_status_t::success) {
            return ret;
        }
        if (free_blk_cb) { 
            free_node(node, multinode_req);
        } else  {
            free_node(node, multinode_req, true);
        }
        return ret;
    }

    btree_status_t range_put(const BtreeKey &k, const BtreeValue &v, btree_put_type put_type,
                   boost::intrusive_ptr<btree_req_type> dependent_req, boost::intrusive_ptr<btree_req_type> cookie,
                   BtreeUpdateRequest<K, V> &bur) {
        V temp_v;
        //initialize cb param
        K sub_st(*(K*)bur.get_input_range().get_start_key()), sub_en(*(K*)bur.get_input_range().get_end_key());//cpy
        K in_st(*(K*)bur.get_input_range().get_start_key()), in_en(*(K*)bur.get_input_range().get_end_key());//cpy
        bur.get_cb_param()->get_input_range().set(in_st, bur.get_input_range().is_start_inclusive(),
                                                in_en, bur.get_input_range().is_end_inclusive());
        bur.get_cb_param()->get_sub_range().set(sub_st, bur.get_input_range().is_start_inclusive(),
                                                sub_en, bur.get_input_range().is_end_inclusive());
        return(put(k, v, put_type, dependent_req, cookie, &temp_v, &bur));
    }
    
    btree_status_t put(const BtreeKey &k, const BtreeValue &v, btree_put_type put_type) {
        V temp_v;
        return(put(k, v, put_type, nullptr, nullptr, &temp_v));
    }
    
    btree_status_t put(const BtreeKey &k, const BtreeValue &v, btree_put_type put_type, 
            boost::intrusive_ptr<btree_req_type> dependent_req,
            boost::intrusive_ptr<btree_req_type> cookie, BtreeValue *existing_val = nullptr, 
            BtreeUpdateRequest<K,V> *bur = nullptr) {

        homeds::thread::locktype acq_lock = homeds::thread::LOCKTYPE_READ;
        int ind = -1;
        bool is_leaf = false;

        m_btree_lock.read_lock();
        
        btree_multinode_req_ptr multinode_req;
        multinode_req = btree_multinode_req<btree_req_type>::make_request(cookie, dependent_req, true, false);
        multinode_req->writes_pending.increment(1);
        btree_status_t ret = btree_status_t::success;
retry:
        assert(rd_locked_nodes.size() == 0 && wr_locked_nodes.size() == 0);
       
        BtreeNodePtr root;
        ret = read_and_lock_root(m_root_node, root, acq_lock, acq_lock, multinode_req);
        if (ret != btree_status_t::success) {
            goto out;
        }
        is_leaf = root->is_leaf();

        if (root->is_split_needed(m_btree_cfg, k, v, &ind, put_type, bur)) {

            // Time to do the split of root.
            unlock_node(root, acq_lock);
            m_btree_lock.unlock();
            ret = check_split_root(k, v, multinode_req, put_type, bur);
            assert(rd_locked_nodes.size() == 0 && wr_locked_nodes.size() == 0);
            // We must have gotten a new root, need to start from scratch.
            m_btree_lock.read_lock();
            
            if (ret != btree_status_t::success) {
                LOGERROR("root split failed btree name {}", m_btree_cfg.get_name());
                goto out;
            }
            
            goto retry;
        
        } else if ((is_leaf) && (acq_lock != homeds::thread::LOCKTYPE_WRITE)) {
           
            // Root is a leaf, need to take write lock, instead of read, retry
            unlock_node(root, acq_lock);
            acq_lock = homeds::thread::LOCKTYPE_WRITE;
            goto retry;
        
        } else {
            ret = do_put(root, acq_lock, k, v, ind, put_type, *existing_val, multinode_req, bur);
            if (ret == btree_status_t::retry) {
                // Need to start from top down again, since there is a race between 2 inserts or deletes.
                acq_lock = homeds::thread::LOCKTYPE_READ;
                DLOGTRACEMOD(btree_generics, "retrying put operation");
                assert(rd_locked_nodes.size() == 0 && wr_locked_nodes.size() == 0);
                goto retry;
            }
        }

out:
        m_btree_lock.unlock();
#ifndef NDEBUG
        check_lock_debug();
#endif
        if (ret != btree_status_t::success) {
            LOGTRACE("btree put failed {}", ret);
        }
        process_completions(ret, multinode_req);
        
        return ret;
    }

    btree_status_t get(const BtreeKey& key, BtreeValue* outval) { return get(key, nullptr, outval); }

    btree_status_t get(const BtreeKey& key, BtreeKey* outkey, BtreeValue* outval) {
        return get_any(BtreeSearchRange(key), outkey, outval);
    }

    btree_status_t get_any(const BtreeSearchRange& range, BtreeKey* outkey, BtreeValue* outval) {
        btree_status_t ret = btree_status_t::success;;
        bool is_found;

        m_btree_lock.read_lock();
        BtreeNodePtr root;
        btree_multinode_req_ptr multinode_req = btree_multinode_req<btree_req_type>::make_request(false, false);
       
        ret = read_and_lock_root(m_root_node, root, LOCKTYPE_READ, LOCKTYPE_READ, multinode_req);
        if (ret != btree_status_t::success) {
            goto out;
        }

        ret = do_get(root, range, outkey, outval, multinode_req);
out:
        m_btree_lock.unlock();

        // TODO: Assert if key returned from do_get is same as key requested, incase of perfect match

#ifndef NDEBUG
        check_lock_debug();
#endif
        return ret;
    }

    btree_status_t query(BtreeQueryRequest< K, V >& query_req, std::vector< std::pair< K, V > >& out_values) {
        //initialize cb param
        K in_st(*(K*)query_req.get_input_range().get_start_key());
        K in_en(*(K*)query_req.get_input_range().get_end_key());//cpy
        if (query_req.get_cb_param()) {
            query_req.get_cb_param()->get_input_range().set(in_st, query_req.get_input_range().is_start_inclusive(),
                                                  in_en, query_req.get_input_range().is_end_inclusive());
        }
        
        btree_status_t ret = btree_status_t::success;
        if (query_req.get_batch_size() == 0) {
            return ret;
        }
        
        btree_multinode_req_ptr multinode_req = btree_multinode_req<btree_req_type>::make_request(false, false);

        query_req.init_batch_range();

        m_btree_lock.read_lock();
        BtreeNodePtr root = nullptr;
        ret = read_and_lock_root(m_root_node, root, LOCKTYPE_READ, LOCKTYPE_READ, multinode_req);
        if (ret != btree_status_t::success) {
            goto out;
        }

        switch (query_req.query_type()) {
        case BtreeQueryType::SWEEP_NON_INTRUSIVE_PAGINATION_QUERY:
            ret = do_sweep_query(root, query_req, out_values, multinode_req);
            break;

        case BtreeQueryType::TREE_TRAVERSAL_QUERY: 
            ret = do_traversal_query(root, query_req, out_values, nullptr, multinode_req);
            break;

        default:
            unlock_node(root, homeds::thread::locktype::LOCKTYPE_READ);
            LOGERROR("Query type {} is not supported yet", query_req.query_type());
            break;
        }

out:
        m_btree_lock.unlock();
#ifndef NDEBUG
        check_lock_debug();
#endif
        return ret;
    }

#ifdef SERIALIZABLE_QUERY_IMPLEMENTATION
    btree_status_t sweep_query(BtreeQueryRequest& query_req, std::vector< std::pair< K, V > >& out_values) {
        COUNTER_INCREMENT(m_metrics, btree_read_ops_count, 1);
        query_req.init_batch_range();

        m_btree_lock.read_lock();
        
        BtreeNodePtr root;
        btree_status_t ret = btree_status_t::success;

        ret = read_and_lock_root(m_root_node, root, LOCKTYPE_READ, LOCKTYPE_READ, nullptr);
        if (ret != btree_status_t::success) {
            goto out;
        }

        ret = do_sweep_query(root, query_req, out_values);
out:
        m_btree_lock.unlock();

#ifndef NDEBUG
        check_lock_debug();
#endif
        return ret;
    }

    btree_status_t serializable_query(BtreeSerializableQueryRequest& query_req, 
                                      std::vector< std::pair< K, V > >& out_values) {
        query_req.init_batch_range();

        COUNTER_INCREMENT(m_metrics, btree_read_ops_count, 1);
        m_btree_lock.read_lock();
        BtreeNodePtr node;
        btree_status_t ret;

        if (query_req.is_empty_cursor()) {
            // Initialize a new lock tracker and put inside the cursor.
            query_req.cursor().m_locked_nodes = std::make_unique< BtreeLockTrackerImpl >(this);

            BtreeNodePtr root;
            ret = read_and_lock_root(m_root_node, root, LOCKTYPE_READ, LOCKTYPE_READ, nullptr);
            if (ret != btree_status_t::success) {
                goto out;
            }
            get_tracker(query_req)->push(root); // Start tracking the locked nodes.
        } else {
            node = get_tracker(query_req)->top();
        }

        ret = do_serialzable_query(node, query_req, out_values);
out:
        m_btree_lock.unlock();

        // TODO: Assert if key returned from do_get is same as key requested, incase of perfect match

#ifndef NDEBUG
        check_lock_debug();
#endif

        return ret;
    }

    BtreeLockTrackerImpl* get_tracker(BtreeSerializableQueryRequest& query_req) {
        return (BtreeLockTrackerImpl*)query_req->get_cursor.m_locked_nodes.get();
    }
#endif

    /* It doesn't support async */
    btree_status_t remove_any(const BtreeSearchRange& range, BtreeKey* outkey, BtreeValue* outval) {
        return (remove_any(range, outkey, outval, nullptr, nullptr));
    }

    btree_status_t remove_any(const BtreeSearchRange& range, BtreeKey* outkey, BtreeValue* outval,
                    boost::intrusive_ptr< btree_req_type > dependent_req,
                    boost::intrusive_ptr< btree_req_type > cookie) {
        homeds::thread::locktype acq_lock = homeds::thread::locktype::LOCKTYPE_READ;
        bool                     is_found = false;
        bool is_leaf = false;

#ifdef REFCOUNT_DEBUG
        assert(OmDBGlobals::getGlobalRefCount() == 0);
#endif

        m_btree_lock.read_lock();
        
        btree_multinode_req_ptr multinode_req = btree_multinode_req<btree_req_type>::make_request(cookie, 
                                                                    dependent_req, true, false);
        multinode_req->writes_pending.increment(1);
    retry:

        btree_status_t status = btree_status_t::success;

        BtreeNodePtr root;
        status = read_and_lock_root(m_root_node, root, acq_lock, acq_lock, multinode_req);
        if (status != btree_status_t::success) {
            goto out;
        }
        is_leaf = root->is_leaf();

        if (root->get_total_entries() == 0) {
            if (is_leaf) {
                // There are no entries in btree.
                unlock_node(root, acq_lock);
                status = btree_status_t::not_found;
                DLOGDEBUG("btree not found for name {}", m_btree_cfg.get_name());
                goto out;
            }
            assert(root->get_edge_id().is_valid());
            unlock_node(root, acq_lock);
            m_btree_lock.unlock();

            status = check_collapse_root(multinode_req);
            if (status != btree_status_t::success) {
                LOGERROR("check collapse read failed btree name {}", m_btree_cfg.get_name());
                goto out;
            }

            // We must have gotten a new root, need to
            // start from scratch.
            m_btree_lock.read_lock();
            goto retry;
        } else if ((is_leaf) && (acq_lock != homeds::thread::LOCKTYPE_WRITE)) {
            // Root is a leaf, need to take write lock, instead
            // of read, retry
            unlock_node(root, acq_lock);
            acq_lock = homeds::thread::LOCKTYPE_WRITE;
            goto retry;
        } else {
            status = do_remove(root, acq_lock, range, outkey, outval, multinode_req);
            if (status == btree_status_t::retry) {
                // Need to start from top down again, since
                // there is a race between 2 inserts or deletes.
                acq_lock = homeds::thread::LOCKTYPE_READ;
                goto retry;
            }
        }

out:
        m_btree_lock.unlock();
#ifndef NDEBUG
        check_lock_debug();
#endif

#ifdef REFCOUNT_DEBUG
        assert(OmDBGlobals::getGlobalRefCount() == 0);
#endif
        process_completions(status, multinode_req);
        return status;
    }

    btree_status_t remove(const BtreeKey& key, BtreeValue* outval) { return (remove(key, outval, nullptr, nullptr)); }

    btree_status_t remove(const BtreeKey& key, BtreeValue* outval, boost::intrusive_ptr< btree_req_type > dependent_req,
                boost::intrusive_ptr< btree_req_type > cookie) {
        return remove_any(BtreeSearchRange(key), nullptr, outval, dependent_req, cookie);
    }

    void print_tree() {
        m_btree_lock.read_lock();
        std::stringstream ss;
        to_string(m_root_node, ss);
        LOGINFO("Pre order traversal of tree : <{}>", ss.str());
        m_btree_lock.unlock();
    }

    nlohmann::json get_metrics_in_json(bool updated = true) { return m_metrics.get_result_in_json(updated); }

private:
    void to_string(bnodeid_t bnodeid, std::stringstream &ss) {
        BtreeNodePtr node;

        homeds::thread::locktype acq_lock = homeds::thread::locktype::LOCKTYPE_READ;

        if (read_and_lock_node(bnodeid, node, acq_lock, acq_lock, nullptr) != btree_status_t::success) {
            return;
        }
        ss << "[" << node->to_string() << "]";

        if (!node->is_leaf()) {
            uint32_t i = 0;
            while (i < node->get_total_entries()) {
                BtreeNodeInfo p;
                node->get(i, &p, false);
                to_string(p.bnode_id(),ss);
                i++;
            }
            if(node->get_edge_id().is_valid())
                to_string(node->get_edge_id(),ss);
        }
        unlock_node(node, acq_lock);
    }

    btree_status_t do_get(BtreeNodePtr my_node, const BtreeSearchRange& range, BtreeKey* outkey, 
                          BtreeValue* outval, btree_multinode_req_ptr multinode_req) {
        btree_status_t ret = btree_status_t::success;
        bool is_child_lock = false;
        homeds::thread::locktype child_locktype;

        if (my_node->is_leaf()) {
            auto result = my_node->find(range, outkey, outval);
            if (result.found) {
                ret = btree_status_t::success;
            } else {
                ret = btree_status_t::not_found; 
            }
            unlock_node(my_node, homeds::thread::locktype::LOCKTYPE_READ);
            return ret;
        }

        BtreeNodeInfo child_info;
        auto          result = my_node->find(range, nullptr, &child_info);
        assert(IS_VALID_INTERIOR_CHILD_INDX(result, my_node));
        
        BtreeNodePtr  child_node;
        child_locktype = homeds::thread::LOCKTYPE_READ;
        ret = read_and_lock_child(child_info.bnode_id(), child_node, my_node, result.end_of_search_index, 
                            child_locktype, child_locktype, multinode_req);
        if (ret != btree_status_t::success) {
            goto out;
        }
        
        unlock_node(my_node, homeds::thread::locktype::LOCKTYPE_READ);

        return (do_get(child_node, range, outkey, outval, multinode_req));
out:
        unlock_node(my_node, homeds::thread::locktype::LOCKTYPE_READ);
        return ret;
    }

    btree_status_t do_sweep_query(BtreeNodePtr my_node, BtreeQueryRequest< K, V >& query_req,
                        std::vector< std::pair< K, V > >& out_values, btree_multinode_req_ptr multinode_req) {
        btree_status_t ret = btree_status_t::success;
        if (my_node->is_leaf()) {
            assert(query_req.get_batch_size() > 0);

            auto         count = 0U;
            BtreeNodePtr next_node = nullptr;

            do {
                if (next_node) {
                    unlock_node(my_node, homeds::thread::locktype::LOCKTYPE_READ);
                    my_node = next_node;
                    if (my_node->get_total_entries() > 0) {
                        K ekey;
                        next_node->get_nth_key(0,&ekey,false);
                        if (query_req.get_input_range().get_end_key()->compare(&ekey) < 0) {//early lookup end
                            query_req.cursor().m_last_key = nullptr;
                            break;
                        }
                    }
                }

                LOGTRACEMOD(btree_nodes, "Query leaf node:\n {}", my_node->to_string());

                int                              start_ind = 0, end_ind = 0;
                std::vector< std::pair< K, V > > match_kv;
                auto cur_count = my_node->get_all(query_req.this_batch_range(), query_req.get_batch_size() - count,
                                                  start_ind, end_ind, &match_kv);

                if (query_req.callback()) {
                    // TODO - support accurate sub ranges in future instead of setting input range
                    query_req.get_cb_param()->set_sub_range(query_req.get_input_range());
                    std::vector< std::pair< K, V > > result_kv;
                    query_req.callback()(match_kv, result_kv, query_req.get_cb_param());
                    auto ele_to_add = result_kv.size();
                    if (count + ele_to_add > query_req.get_batch_size())
                        ele_to_add = query_req.get_batch_size() - count;
                    if (ele_to_add > 0)
                        out_values.insert(out_values.end(), result_kv.begin(), result_kv.begin() + ele_to_add);
                    count += ele_to_add;
                    assert(count <= query_req.get_batch_size());
                } else {
                    out_values.insert(std::end(out_values), std::begin(match_kv), std::end(match_kv));
                    count += cur_count;
                }

                if ((count < query_req.get_batch_size()) && my_node->get_next_bnode().is_valid()) {
                    ret = read_and_lock_sibling(my_node->get_next_bnode(), next_node, LOCKTYPE_READ, 
                                                      LOCKTYPE_READ, multinode_req);
                    if (ret != btree_status_t::success) {
                        LOGERROR("read failed btree name {}", m_btree_cfg.get_name());
                        ret = btree_status_t::read_failed;
                        break;
                    }
                } else {
                    // If we are here because our count is full, then setup the last key as cursor, otherwise, it would
                    // mean count is 0, but this is the rightmost leaf node in the tree. So no more cursors.
                    query_req.cursor().m_last_key = (count) ? std::make_unique< K >(out_values.back().first) : nullptr;
                    break;
                }
            } while (true);

            unlock_node(my_node, homeds::thread::locktype::LOCKTYPE_READ);
            if (ret != btree_status_t::success) {
                return ret;
            }
            if (query_req.cursor().m_last_key != nullptr) {
                return btree_status_t::has_more;
            } else {
                return btree_status_t::success;
            }
        }

        BtreeNodeInfo start_child_info;
        auto result = my_node->find(query_req.get_start_of_range(), nullptr, &start_child_info);
        assert(IS_VALID_INTERIOR_CHILD_INDX(result, my_node));

        BtreeNodePtr child_node;
        ret = read_and_lock_child(start_child_info.bnode_id(), child_node, my_node, result.end_of_search_index, 
                        LOCKTYPE_READ, LOCKTYPE_READ, multinode_req);
        unlock_node(my_node, homeds::thread::locktype::LOCKTYPE_READ);
        if (ret != btree_status_t::success) {
            return ret;
        }
        return (do_sweep_query(child_node, query_req, out_values, multinode_req));
    }

    btree_status_t do_traversal_query(BtreeNodePtr my_node, BtreeQueryRequest< K, V >& query_req,
                            std::vector< std::pair< K, V > >& out_values, BtreeSearchRange* sub_range, 
                            btree_multinode_req_ptr multinode_req) {
        btree_status_t ret = btree_status_t::success;

        if (my_node->is_leaf()) {
            assert(query_req.get_batch_size() > 0);

            int                              start_ind = 0, end_ind = 0;
            std::vector< std::pair< K, V > > match_kv;
            my_node->get_all(query_req.this_batch_range(), query_req.get_batch_size() - (uint32_t)out_values.size(),
                             start_ind, end_ind, &match_kv);

            if (query_req.callback()) {
                //TODO - support accurate sub ranges in future instead of setting input range
                query_req.get_cb_param()->set_sub_range(query_req.get_input_range());
                std::vector<std::pair<K, V>> result_kv;
                query_req.callback()(match_kv, result_kv, query_req.get_cb_param());
                auto ele_to_add = result_kv.size();
                if (ele_to_add > 0) {
                    out_values.insert(out_values.end(), result_kv.begin(), result_kv.begin()+ele_to_add);
                }
            }
            out_values.insert(std::end(out_values), std::begin(match_kv), std::end(match_kv));

            unlock_node(my_node, homeds::thread::locktype::LOCKTYPE_READ);
            if (out_values.size() >= query_req.get_batch_size()) {
                assert(out_values.size() == query_req.get_batch_size());
                query_req.cursor().m_last_key = std::make_unique< K >(out_values.back().first);
                return btree_status_t::has_more;
            }

            return ret;
        }

        auto start_ret = my_node->find(query_req.get_start_of_range(), nullptr, nullptr);
        assert(IS_VALID_INTERIOR_CHILD_INDX(start_ret, my_node));
        auto end_ret = my_node->find(query_req.get_end_of_range(), nullptr, nullptr);
        assert(IS_VALID_INTERIOR_CHILD_INDX(end_ret, my_node));
        bool unlocked_already = false;
        int ind = -1;
        
        if(start_ret.end_of_search_index==(int)my_node->get_total_entries() && !(my_node->get_edge_id().is_valid())) {
            goto done;//no results found
        } else if(end_ret.end_of_search_index==(int)my_node->get_total_entries() && !(my_node->get_edge_id().is_valid())) {
            end_ret.end_of_search_index--;//end is not valid
        }
        assert(start_ret.end_of_search_index <=  end_ret.end_of_search_index);
        ind = start_ret.end_of_search_index;
        
        while (ind <= end_ret.end_of_search_index) {
            BtreeNodeInfo child_info;
            my_node->get(ind, &child_info, false);
            BtreeNodePtr child_node = nullptr; 
            homeds::thread::locktype child_cur_lock = homeds::thread::LOCKTYPE_READ;
            ret = read_and_lock_child(child_info.bnode_id(), child_node, my_node, ind, 
                                            child_cur_lock, child_cur_lock, multinode_req);
            if (ret != btree_status_t::success) {
                break;
            }

            if (ind == end_ret.end_of_search_index) {
                // If we have reached the last index, unlock before traversing down, because we no longer need
                // this lock. Holding this lock will impact performance unncessarily.
                unlock_node(my_node, homeds::thread::locktype::LOCKTYPE_READ);
                unlocked_already = true;
            }
            // TODO - pass sub range if child is leaf
            ret = do_traversal_query(child_node, query_req, out_values, nullptr, multinode_req);
            if (ret == btree_status_t::has_more) {
                break;
            }
            ind++;
        }
done:
        if (!unlocked_already) {
            unlock_node(my_node, homeds::thread::locktype::LOCKTYPE_READ);
        }

        return ret;
    }

#ifdef SERIALIZABLE_QUERY_IMPLEMENTATION
    btree_status_t do_serialzable_query(BtreeNodePtr my_node, BtreeSerializableQueryRequest& query_req,
                              std::vector< std::pair< K, V > >& out_values) {

        btree_status_t ret = btree_status_t::success;
        if (my_node->is_leaf) {
            auto count = 0;
            auto start_result = my_node->find(query_req.get_start_of_range(), nullptr, nullptr);
            auto start_ind = start_result.end_of_search_index;

            auto end_result = my_node->find(query_req.get_end_of_range(), nullptr, nullptr);
            auto end_ind = end_result.end_of_search_index;
            if (!end_result.found) {
                end_ind--;
            } // not found entries will point to 1 ind after last in range.

            ind = start_ind;
            while ((ind <= end_ind) && (count < query_req.get_batch_size())) {
                K key;
                V value;
                my_node->get_nth_element(ind, &key, &value, false);

                if (!query_req.m_match_item_cb || query_req.m_match_item_cb(key, value)) {
                    out_values.emplace_back(std::make_pair< K, V >(key, value));
                    count++;
                }
                ind++;
            }

            bool has_more = ((ind >= start_ind) && (ind < end_ind));
            if (!has_more) {
                unlock_node(my_node, homeds::thread::locktype::LOCKTYPE_READ);
                get_tracker(query_req)->pop();
                return success;
            }

            return has_more;
        }

        BtreeNodeId start_child_ptr, end_child_ptr;
        auto        start_ret = my_node->find(query_req.get_start_of_range(), nullptr, &start_child_ptr);
        assert(IS_VALID_INTERIOR_CHILD_INDX(start_ret, my_node));
        auto        end_ret = my_node->find(query_req.get_end_of_range(), nullptr, &end_child_ptr);
        assert(IS_VALID_INTERIOR_CHILD_INDX(end_ret, my_node));

        BtreeNodePtr child_node;
        if (start_ret.end_of_search_index == end_ret.end_of_search_index) {
            assert(start_child_ptr == end_child_ptr);
            ret = read_and_lock_node(start_child_ptr.get_node_id(), child_node, 
                                        LOCKTYPE_READ, LOCKTYPE_READ, nullptr);
            if (ret != btree_status_t::success) {
                unlock_node(my_node, homeds::thread::locktype::LOCKTYPE_READ);
                return ret;
            }
            unlock_node(my_node, homeds::thread::locktype::LOCKTYPE_READ);

            // Pop the last node and push this child node
            get_tracker(query_req)->pop();
            get_tracker(query_req)->push(child_node);
            return do_serialzable_query(child_node, query_req, search_range, out_values);
        } else {
            // This is where the deviation of tree happens. Do not pop the node out of lock tracker
            bool has_more = false;

            for (auto i = start_ret.end_of_search_index; i <= end_ret.end_of_search_index; i++) {
                BtreeNodeId child_ptr;
                my_node->get_nth_value(i, &child_ptr, false);
                ret = read_and_lock_node(child_ptr.get_node_id(), child_node, 
                                             LOCKTYPE_READ, LOCKTYPE_READ, nullptr);
                if (ret != btree_status_t::success) {
                    unlock_node(my_node, homeds::thread::locktype::LOCKTYPE_READ);
                    return ret;
                }

                get_tracker(query_req)->push(child_node);

                ret = do_serialzable_query(child_node, query_req, out_values);
                if (ret == BTREE_AGAIN) {
                    assert(out_values.size() == query_req.get_batch_size());
                    break;
                }
            }

            if (ret == BTREE_SUCCESS) {
                unlock_node(my_node, homeds::thread::locktype::LOCKTYPE_READ);
                assert(get_tracker(query_req)->top() == my_node);
                get_tracker(query_req)->pop();
            }
            return ret;
        }
    }
#endif

    /* This function upgrades the node lock and take required steps if things have
     * changed during the upgrade.
     *
     * Inputs:
     * myNode - Node to upgrade
     * childNode - In case childNode needs to be unlocked. Could be nullptr
     * curLock - Input/Output: current lock type
     *
     * Returns - If successfully able to upgrade, return true, else false.
     *
     * About Locks: This function expects the myNode to be locked and if childNode is not nullptr, expects
     * it to be locked too. If it is able to successfully upgrade it continue to retain its
     * old lock. If failed to upgrade, will release all locks.
     */
     btree_status_t upgrade_node(BtreeNodePtr my_node, BtreeNodePtr child_node, homeds::thread::locktype& cur_lock,
                      homeds::thread::locktype &child_cur_lock, btree_multinode_req_ptr multinode_req) {
        uint64_t prev_gen;
        btree_status_t ret = btree_status_t::success;
        homeds::thread::locktype child_lock_type = child_cur_lock;

        if (cur_lock == homeds::thread::LOCKTYPE_WRITE) {
            goto done;
        }

        prev_gen = my_node->get_gen();
        if (child_node) {
            unlock_node(child_node, child_cur_lock);
            child_cur_lock = locktype::LOCKTYPE_NONE;
        }


        ret = lock_node_upgrade(my_node, multinode_req);
        if (ret != btree_status_t::success) {
            cur_lock = locktype::LOCKTYPE_NONE;
            return ret;
        }
        
        // The node was not changed by anyone else during upgrade.
        cur_lock = homeds::thread::LOCKTYPE_WRITE;

        // If the node has been made invalid (probably by mergeNodes) ask caller to start over again, but before that
        // cleanup or free this node if there is no one waiting.
        if (!my_node->is_valid_node()) {
            unlock_node(my_node, homeds::thread::LOCKTYPE_WRITE);
            cur_lock = locktype::LOCKTYPE_NONE;
            ret = btree_status_t::retry;
            goto done;
        }

        // If node has been updated, while we have upgraded, ask caller to start all over again.
        if (prev_gen != my_node->get_gen()) {
            unlock_node(my_node, cur_lock);
            cur_lock = locktype::LOCKTYPE_NONE;
            ret = btree_status_t::retry;
            goto done;
        }

        if (child_node) {
            ret = lock_and_refresh_node(child_node, child_lock_type, multinode_req);
            if (ret != btree_status_t::success) {
                unlock_node(my_node, cur_lock);
                cur_lock = locktype::LOCKTYPE_NONE;
                child_cur_lock = locktype::LOCKTYPE_NONE;
                goto done;
            }
            child_cur_lock = child_lock_type;
        }

       assert(my_node->m_common_header.is_lock);
    done:
        return ret;
    }

    btree_status_t update_leaf_node(BtreeNodePtr my_node, const BtreeKey &k, const BtreeValue &v, 
                                    btree_put_type put_type, BtreeValue &existing_val, btree_multinode_req_ptr multinode_req,
                                    BtreeUpdateRequest<K, V> *bur) {

        btree_status_t ret = btree_status_t::success;
        if (bur != nullptr) {
            assert(bur->callback() != nullptr); // TODO - range req without callback implementation
            std::vector< std::pair< K, V > > match;
            int                              start_ind = 0, end_ind = 0;
            my_node->get_all(bur->get_input_range(), UINT32_MAX, start_ind, end_ind, &match);

            vector< pair< K, V > > replace_kv;
            bur->callback()(match, replace_kv, bur->get_cb_param());
            if (match.size() > 0 && start_ind <= end_ind) {
                my_node->remove(start_ind, end_ind);
            }
            for (auto &pair : replace_kv) { // insert is based on compare() of BtreeKey
                my_node->insert(pair.first, pair.second);
            }
        } else {
            if (!my_node->put(k, v, put_type, existing_val)) {
                ret = btree_status_t::put_failed;
            }
        }

#ifndef NDEBUG
        //sorted check
        for(auto i=1u;i<my_node->get_total_entries();i++){
            K curKey, prevKey;
            my_node->get_nth_key(i-1,&prevKey,false);
            my_node->get_nth_key(i,&curKey,false);
            assert(prevKey.compare(&curKey)<=0);
        }
#endif
        write_node_async(my_node, multinode_req);
        COUNTER_INCREMENT(m_metrics, btree_obj_count, 1);
        return ret;
    }

    btree_status_t get_start_and_end_ind(BtreeNodePtr my_node, BtreeUpdateRequest<K, V> *bur, const BtreeKey &k, 
                                         int &start_ind, int &end_ind) {

        btree_status_t ret = btree_status_t::success;
        if (bur != nullptr) { 
            /* just get start/end index from get_all. We don't release the parent lock until this
             * key range is not inserted from start_ind to end_ind.
             */
            my_node->get_all(bur->get_input_range(), UINT32_MAX, start_ind, end_ind);
        } else {
            auto result = my_node->find(k, nullptr, nullptr);
            end_ind = start_ind = result.end_of_search_index;
            assert(IS_VALID_INTERIOR_CHILD_INDX(result, my_node));
        }

        if (start_ind > end_ind) {
            assert(0);//dont expect this to happen
            // Either the node was updated or mynode is freed. Just proceed again from top.
            ret = btree_status_t::retry;
        }
        return ret;
    }

    /* It split the child if a split is required. It releases lock on parent and child_node in case of failure */
    btree_status_t check_and_split_node(BtreeNodePtr my_node, BtreeUpdateRequest<K, V> *bur, const BtreeKey &k,
                                        const BtreeValue &v, int ind_hint, btree_put_type put_type, 
                                        btree_multinode_req_ptr multinode_req, BtreeNodePtr  child_node,
                                        homeds::thread::locktype &curlock, homeds::thread::locktype &child_curlock,
                                        int child_ind, bool &split_occured) {

        split_occured = false;
        K split_key;
        btree_status_t ret = btree_status_t::success;
        auto child_lock_type = child_curlock;
        auto none_lock_type = LOCKTYPE_NONE;
        
        if (!child_node->is_split_needed(m_btree_cfg, k, v, &ind_hint, put_type, bur)) {
            return ret;
        }
       
        /* Split needed */
        if (bur) {

            /* In case of range update we might split multiple childs of a parent in a single
             * iteration which result into less space in the parent node.
             */
            if (my_node->is_split_needed(m_btree_cfg, k, v, &ind_hint, put_type, bur)) {
                //restart from root
                ret = btree_status_t::retry;
                goto out;
            }
            /* refresh node is needed wherever we are writing to a node multiple times
             * in a single lock iteration.
             */
            btree_store_t::refresh_node(m_btree_store.get(), my_node, multinode_req, true);
        }

        // Time to split the child, but we need to convert parent to write lock
        ret = upgrade_node(my_node, child_node, curlock, child_curlock, multinode_req);
        if (ret != btree_status_t::success) {
            LOGDEBUGMOD(btree_structures, "Upgrade of lock for node {} failed, retrying from root",
                    my_node->get_node_id_int());
            assert(curlock == homeds::thread::LOCKTYPE_NONE);
            goto out;
        }
        assert(child_curlock == child_lock_type);
        assert(curlock == homeds::thread::LOCKTYPE_WRITE);

        // We need to upgrade the child to WriteLock
        ret = upgrade_node(child_node, nullptr, child_curlock, none_lock_type, multinode_req);
        if (ret != btree_status_t::success) {
            LOGDEBUGMOD(btree_structures, "Upgrade of lock for node {} failed, retrying from root",
                    child_node->get_node_id_int());
            assert(child_curlock == homeds::thread::LOCKTYPE_NONE);
            goto out;
        }
        assert(none_lock_type == homeds::thread::LOCKTYPE_NONE);
        assert(child_curlock == homeds::thread::LOCKTYPE_WRITE);

        // Real time to split the node and get point at which it was split
        ret = split_node(my_node, child_node, child_ind, &split_key, multinode_req);
        if (ret != btree_status_t::success) {
            goto out;
        }
        
        // After split, parentNode would have split, retry search and walk down.
        unlock_node(child_node, homeds::thread::LOCKTYPE_WRITE);
        child_curlock = LOCKTYPE_NONE;
        COUNTER_INCREMENT(m_metrics, btree_split_count, 1);
        split_occured = true;
out:
        if (ret != btree_status_t::success) {
            if (curlock != LOCKTYPE_NONE) {
                unlock_node(my_node, curlock);
                curlock = LOCKTYPE_NONE;
            }

            if (child_curlock != LOCKTYPE_NONE) {
                unlock_node(child_node, child_curlock);
                child_curlock = LOCKTYPE_NONE;
            }
        }
        return ret;
    }

    void get_subrange(BtreeNodePtr my_node, BtreeUpdateRequest<K, V> *bur, int curr_ind) {
        if (!bur) {
            return;
        }

        //find start of subrange
        bool start_inc;
        K start_key;
        BtreeKey *start_key_ptr = &start_key;
        
        if (curr_ind > 0) {
            /* start of subrange will be more then the key in curr_ind - 1 */
            my_node->get_nth_key(curr_ind - 1, start_key_ptr, false);
            start_inc = false;
        } else {
            /* start key is the start key of the input range */
            start_key_ptr = const_cast<BtreeKey *>(bur->get_input_range().get_start_key());
            start_inc = bur->get_input_range().is_start_inclusive();
        }
        
        const_cast<BtreeKey *>(bur->get_cb_param()->get_sub_range().get_start_key())->copy_blob(
                start_key_ptr->get_blob());//copy
        bur->get_cb_param()->get_sub_range().set_start_incl(start_inc);

        
        //find end of subrange
        bool end_inc = true;
        K end_key;
        BtreeKey *end_key_ptr = &end_key;
        
        if (curr_ind < (int) my_node->get_total_entries()) {
            my_node->get_nth_key(curr_ind, end_key_ptr, false);
            end_inc = true;
        } else {
            /* it is the edge node. end key is the end of input range */
            assert(my_node->get_edge_id().is_valid());
            end_key_ptr = const_cast<BtreeKey *>(bur->get_input_range().get_end_key());
            end_inc = bur->get_input_range().is_end_inclusive();
        }
        
        const_cast<BtreeKey *>(bur->get_cb_param()->get_sub_range().get_end_key())->copy_blob(
                end_key_ptr->get_blob());//copy
        bur->get_cb_param()->get_sub_range().set_end_incl(end_inc);
    }

    /* This function does the heavy lifiting of co-ordinating inserts. It is a recursive function which walks
     * down the tree.
     *
     * NOTE: It expects the node it operates to be locked (either read or write) and also the node should not be full.
     *
     * Input:
     * myNode      = Node it operates on
     * curLock     = Type of lock held for this node
     * k           = Key to insert
     * v           = Value to insert
     * ind_hint    = If we already know which slot to insert to, if not -1
     * put_type    = Type of the put (refer to structure btree_put_type)
     * is_end_path = set to true only for last path from root to tree, for range put
     * op          = tracks multi node io.
     */
    btree_status_t do_put(BtreeNodePtr my_node, homeds::thread::locktype curlock,
                const BtreeKey &k, const BtreeValue &v, int ind_hint, btree_put_type put_type,
                BtreeValue &existing_val,
                btree_multinode_req_ptr multinode_req,
                BtreeUpdateRequest<K, V> *bur = nullptr) {

        btree_status_t ret = btree_status_t::success;
        bool unlocked_already = false;
        int  curr_ind = -1;
        
        if (my_node->is_leaf()) {
            /* update the leaf node */
            assert(curlock == LOCKTYPE_WRITE);
            ret = update_leaf_node(my_node, k, v, put_type, existing_val, multinode_req, bur);
            unlock_node(my_node, curlock);
            return ret;
        }
        
        bool is_any_child_splitted = false;
        
retry:
        int start_ind = 0, end_ind = -1;

        /* Get the start and end ind in a parent node for the range updates. For 
         * non range updates, start ind and end ind are same.
         */
        ret = get_start_and_end_ind(my_node, bur, k, start_ind, end_ind);
        if (ret != btree_status_t::success) {
            goto out;
        }

        assert(curlock == LOCKTYPE_READ || curlock == LOCKTYPE_WRITE);
        curr_ind = start_ind;
        while (curr_ind <= end_ind) { // iterate all matched childrens
            homeds::thread::locktype child_cur_lock = homeds::thread::LOCKTYPE_NONE;

            // Get the childPtr for given key.
            BtreeNodeInfo child_info;
            BtreeNodePtr  child_node;
            
            ret = get_child_and_lock_node(my_node, curr_ind, child_info, child_node, LOCKTYPE_READ, 
                               LOCKTYPE_WRITE, multinode_req);
            if (ret != btree_status_t::success) {
               if (ret == btree_status_t::not_found) {
                    // Either the node was updated or mynode is freed. Just proceed again from top.
                    /* XXX: Is this case really possible as we always take the parent lock and never
                     * release it.
                     */
                    ret = btree_status_t::retry;
               }
               goto out; 
            }

            // Directly get write lock for leaf, since its an insert.
            child_cur_lock = (child_node->is_leaf()) ? LOCKTYPE_WRITE : LOCKTYPE_READ;
            
            /* check if child node is needed to split */
            bool split_occured = false;
            ret = check_and_split_node(my_node, bur, k, v, ind_hint, put_type, multinode_req, child_node, 
                                       curlock, child_cur_lock, curr_ind, split_occured);
            if (ret != btree_status_t::success) {
                goto out;
            }
            if (split_occured) {
                ind_hint = -1; // Since split is needed, hint is no longer valid
                goto retry;
            }

            /* Get subrange if it is a range update */
            if (bur) {
                get_subrange(my_node, bur, curr_ind);
                DLOGDEBUGMOD(btree_structures, "Subrange:s:{},e:{},c:{},nid:{},eidvalid?:{},sk:{},ek:{}", start_ind, end_ind, curr_ind,
                        my_node->get_node_id().to_string(), my_node->get_edge_id().is_valid(),
                        bur->get_cb_param()->get_sub_range().get_start_key()->to_string(),
                        bur->get_cb_param()->get_sub_range().get_end_key()->to_string());
            }

#ifndef NDEBUG
            K ckey,pkey;
            if (curr_ind != (int)my_node->get_total_entries()) { //not edge
                my_node->get_nth_key(curr_ind, &pkey, true);
                if (child_node->get_total_entries() != 0){
                    child_node->get_last_key(&ckey);
                    assert(ckey.compare(&pkey) <= 0);
                }
                assert(k.compare(&pkey) <= 0);
            }
            if (curr_ind > 0){//not first child
                my_node->get_nth_key(curr_ind - 1, &pkey, true);
                if (child_node->get_total_entries() != 0){
                    child_node->get_first_key(&ckey);
                    assert(pkey.compare(&ckey) <= 0);
                }
                assert(k.compare(&pkey) >= 0);
            }
#endif
            if (curr_ind == end_ind) {
                // If we have reached the last index, unlock before traversing down, because we no longer need
                // this lock. Holding this lock will impact performance unncessarily.
                unlock_node(my_node, curlock);
                curlock = LOCKTYPE_NONE;
            }

#ifndef NDEBUG
            if (child_cur_lock == homeds::thread::LOCKTYPE_WRITE) {
                assert(child_node->m_common_header.is_lock);
            }
#endif
            ret = do_put(child_node, child_cur_lock, k, v, ind_hint, put_type,
                                  existing_val, multinode_req, bur);

            if (ret != btree_status_t::success) {
                goto out;
            }
            if (bur) {//savepoint of range
                // update original input range
                // cb gets cb->input range for manipulation
                const_cast<BtreeKey *>(bur->get_input_range().get_start_key())->copy_blob(
                        const_cast<BtreeKey *>(bur->get_cb_param()->get_sub_range().get_end_key())->get_blob());//copy
                bur->get_input_range().set_start_incl(false);
            }
            curr_ind++;
        }
out:
        if (curlock != LOCKTYPE_NONE) {
            unlock_node(my_node, curlock);
        }
        return ret;
        // Warning: Do not access childNode or myNode beyond this point, since it would
        // have been unlocked by the recursive function and it could also been deleted.
    }

    btree_status_t do_remove(BtreeNodePtr my_node, homeds::thread::locktype curlock, const BtreeSearchRange& range,
                             BtreeKey* outkey, BtreeValue* outval,
                             btree_multinode_req_ptr multinode_req) {
        btree_status_t ret = btree_status_t::success;
        if (my_node->is_leaf()) {
            assert(curlock == LOCKTYPE_WRITE);

#ifndef NDEBUG
            for(auto i=1u;i<my_node->get_total_entries();i++){
                K curKey, prevKey;
                my_node->get_nth_key(i-1,&prevKey,false);
                my_node->get_nth_key(i,&curKey,false);
                assert(prevKey.compare(&curKey)<=0);
            }
#endif
            bool is_found = my_node->remove_one(range, outkey, outval);
#ifndef NDEBUG
            for(auto i=1u;i<my_node->get_total_entries();i++){
                K curKey, prevKey;
                my_node->get_nth_key(i-1,&prevKey,false);
                my_node->get_nth_key(i,&curKey,false);
                assert(prevKey.compare(&curKey)<=0);
            }
#endif
            if (is_found) {
                write_node_async(my_node, multinode_req);
                COUNTER_DECREMENT(m_metrics, btree_obj_count, 1);
            } 

            unlock_node(my_node, curlock);
            return is_found ? btree_status_t::success : btree_status_t::not_found;
        }

    retry:
        locktype child_cur_lock = LOCKTYPE_NONE;

       
        /* range delete is not supported yet */
        // Get the childPtr for given key.
        auto result = my_node->find(range, nullptr, nullptr);
        assert(IS_VALID_INTERIOR_CHILD_INDX(result, my_node));
        uint32_t ind = result.end_of_search_index;

        BtreeNodeInfo child_info;
        BtreeNodePtr child_node;
        ret = get_child_and_lock_node(my_node, ind, child_info, child_node, 
                        LOCKTYPE_READ, LOCKTYPE_WRITE, multinode_req);

        if (ret != btree_status_t::success) {
            unlock_node(my_node, curlock);
            return ret;
        }

        if (child_node->is_leaf()) {
            child_cur_lock = LOCKTYPE_WRITE;
        } else {
            child_cur_lock = LOCKTYPE_READ;
        }

        // Check if child node is minimal.
        if (child_node->is_merge_needed(m_btree_cfg)) {
            // If we are unable to upgrade the node, ask the caller to retry.
            ret = upgrade_node(my_node, child_node, curlock, child_cur_lock, multinode_req);
            if (ret != btree_status_t::success) {
                assert(curlock == homeds::thread::LOCKTYPE_NONE);
                return ret;
            }
            assert(curlock == homeds::thread::LOCKTYPE_WRITE);

#define MAX_ADJANCENT_INDEX 3

            // We do have the write lock and hence can remove entries. Get a list of entries around the minimal child
            // node. Use the list of child entries and merge/share the keys among them.
            vector< int > indices_list;
            my_node->get_adjacent_indicies(ind, indices_list, MAX_ADJANCENT_INDEX);

            // There has to be at least 2 nodes to merge or share. If not let the node be and proceed further down.
            if (indices_list.size() > 1) {
                // It is safe to unlock child without upgrade, because child node would not be deleted, since its
                // parent (myNode) is being write locked by this thread. In fact upgrading would be a problem, since
                // this child might be a middle child in the list of indices, which means we might have to lock one in
                // left against the direction of intended locking (which could cause deadlock).
                unlock_node(child_node, child_cur_lock);
                auto result = merge_nodes(my_node, indices_list, multinode_req);
                if (result.status != btree_status_t::success) {
                    // write or read failed
                    unlock_node(my_node, curlock);
                    return result.status;
                }
                if (result.merged) {
                    // Retry only if we merge them.
                    // release_node(child_node);
                    COUNTER_INCREMENT(m_metrics, btree_merge_count, 1);
                    goto retry;
                } else {
                    ret = lock_and_refresh_node(child_node, child_cur_lock, multinode_req);
                    if (ret != btree_status_t::success) {
                        unlock_node(my_node, curlock);
                        return ret;
                    }
                }
            }
        }

#ifndef NDEBUG
        K ckey,pkey;
        if(ind!=my_node->get_total_entries()) { //not edge
            child_node->get_last_key(&ckey);
            my_node->get_nth_key(ind, &pkey, true);
            assert(ckey.compare(&pkey) <= 0);
        }
        if(ind>0){//not first child
            child_node->get_first_key(&ckey);
            my_node->get_nth_key(ind-1, &pkey, true);
            assert(pkey.compare(&ckey) < 0);
        }
#endif

        unlock_node(my_node, curlock);
        return (do_remove(child_node, child_cur_lock, range, outkey, outval, multinode_req));

        // Warning: Do not access childNode or myNode beyond this point, since it would
        // have been unlocked by the recursive function and it could also been deleted.
    }

    btree_status_t check_split_root(const BtreeKey& k, const BtreeValue& v,
                          btree_multinode_req_ptr multinode_req, btree_put_type& putType,
                          BtreeUpdateRequest< K, V >* bur = nullptr) {
        int          ind;
        K            split_key;
        BtreeNodePtr child_node = nullptr;
        btree_status_t ret = btree_status_t::success;

        m_btree_lock.write_lock();
        BtreeNodePtr root;
        
        ret = read_and_lock_root(m_root_node, root, locktype::LOCKTYPE_WRITE, 
                                locktype::LOCKTYPE_WRITE, multinode_req);
        if (ret != btree_status_t::success) {
            goto done;
        }

        if (!root->is_split_needed(m_btree_cfg, k, v, &ind, putType, bur)) {
            unlock_node(root, homeds::thread::LOCKTYPE_WRITE);
            goto done;
        }

        // Create a new child node and split them
        child_node = alloc_interior_node();

        /* it swap the data while keeping the nodeid same */
        btree_store_t::swap_node(m_btree_store.get(), root, child_node);
        write_node_async(child_node, multinode_req);

        LOGDEBUGMOD(btree_structures, "Root node: {} is full, swapping contents to child_node {} and split that",
                root->get_node_id_int(), child_node->get_node_id_int());

        /* Reading a node again to get the latest buffer from writeback cache. We are going
         * to write this node again in split node. We can not have two consecutive writes on the
         * same buffer without reading in between because we have to update the dependent
         * req_q and underneath buffer from the writeback cache layer. Since it is a new node
         * we can safely say that write lock is taking without actually taking it because no
         * body can acccess this child node.
         */
        ret = btree_store_t::refresh_node(m_btree_store.get(), child_node, multinode_req, true);
        if (ret != btree_status_t::success) {
            unlock_node(root, homeds::thread::LOCKTYPE_WRITE);
            goto done;
        }

        assert(root->get_total_entries() == 0);
        ret = split_node(root, child_node, root->get_total_entries(), &split_key, multinode_req);
        /* unlock child node */
        assert(m_root_node == root->get_node_id());
        ret = btree_store_t::refresh_node(m_btree_store.get(), root, multinode_req, true);
        unlock_node(root, homeds::thread::LOCKTYPE_WRITE);
        
        if (ret == btree_status_t::success) {
            COUNTER_INCREMENT(m_metrics, btree_depth, 1);
        }
    done:
        m_btree_lock.unlock();
        return ret;
    }

    btree_status_t check_collapse_root(btree_multinode_req_ptr multinode_req) {
        BtreeNodePtr child_node = nullptr;
        btree_status_t ret = btree_status_t::success;

        m_btree_lock.write_lock();
        BtreeNodePtr root; 
        
        ret = read_and_lock_root(m_root_node, root, locktype::LOCKTYPE_WRITE, 
                                                locktype::LOCKTYPE_WRITE, multinode_req);
        if (ret != btree_status_t::success) {
            goto done;
        }

        if (root->get_total_entries() != 0 || root->is_leaf()/*some other thread collapsed root already*/) {
            unlock_node(root, locktype::LOCKTYPE_WRITE);
            goto done;
        }

        assert(root->get_edge_id().is_valid());
        child_node = read_node(root->get_edge_id(), multinode_req);
        if (child_node == nullptr) {
            unlock_node(root, locktype::LOCKTYPE_WRITE);
            ret = btree_status_t::read_failed;
            goto done;
        }

        btree_store_t::swap_node(m_btree_store.get(), root, child_node);
        write_node_async(root, multinode_req);
        // Elevate the edge child as root.
        unlock_node(root, locktype::LOCKTYPE_WRITE);
        assert(m_root_node == root->get_node_id());
        free_node(child_node, multinode_req);

        if (ret == btree_status_t::success) {
            COUNTER_DECREMENT(m_metrics, btree_depth, 1);
        }
    done:
        m_btree_lock.unlock();
        return ret;
    }

    /* Requires read/write lock on parent_node and requires write lock on child_node1 before calling this func.
     * This function doesn't accept multinode request unlike other APIs and also call btree store APIs directly.
     * Operations in this function is independent of the actual operation so it shouldn't depend on original
     * multinode request which is created in the caller.
     */
    btree_status_t fix_pc_gen_mistmatch(BtreeNodePtr parent_node, BtreeNodePtr child_node1, uint32_t parent_ind) {

        LOGTRACEMOD(btree_generics, "Before fix, parent: {}, child: {}", parent_node->get_node_id_int(),
                child_node1->get_node_id_int());

        vector< BtreeNodePtr > nodes_to_free;
        K                      parent_key;
        BtreeNodePtr           parent_sibbling = nullptr;
        bnodeid_t              sibbling_id;
        btree_status_t ret = btree_status_t::success;

        if (parent_ind != parent_node->get_total_entries()) {
            parent_node->get_nth_key(parent_ind, &parent_key, false);
            auto result = child_node1->find(parent_key, nullptr);
            if (result.found) {
                // either do nothing or do trim
                if (result.end_of_search_index != (int)child_node1->get_total_entries()) {
                    child_node1->invalidate_edge(); // incase was valid edge
                    child_node1->remove(result.end_of_search_index + 1, child_node1->get_total_entries() - 1);
                }
                // else its an edge entry, do nothing
            } else {
                bool         borrowKeys = true;
                BtreeNodePtr old_sibbling = nullptr;
                do {
                    // merge case, borrow entries
                    if ((old_sibbling == nullptr) && (child_node1->get_next_bnode().is_valid())) {
                        old_sibbling = read_node(child_node1->get_next_bnode(), nullptr);
                        if (old_sibbling == nullptr) {
                            // read failed
                            ret = btree_status_t::read_failed;
                            return ret;
                        }
                    } else if ((old_sibbling->get_total_entries() == 0) &&
                               (old_sibbling->get_next_bnode().is_valid())) {
                        old_sibbling = read_node(old_sibbling->get_next_bnode(), nullptr);
                        if (old_sibbling == nullptr) {
                            // read failed
                            ret = btree_status_t::read_failed;
                            return ret;
                        }
                    } else {
                        assert(0); // something went wrong
                    }
                    auto res = old_sibbling->find(parent_key, nullptr);
                    int  no_of_keys = old_sibbling->get_total_entries();
                    if (res.found) {
                        no_of_keys = res.end_of_search_index + 1;
                        borrowKeys = false;
                    }
                    uint32_t nentries =
                        child_node1->move_in_from_right_by_entries(m_btree_cfg, old_sibbling, no_of_keys);
                    assert(nentries > 0);
                    nodes_to_free.push_back(old_sibbling);
                } while (borrowKeys);
            }

            // update correct sibbling of child node1
            if (parent_ind == parent_node->get_total_entries() - 1) {
                if (parent_node->get_edge_id().is_valid()) {
                    sibbling_id = parent_node->get_edge_id();
                } else if (parent_node->get_next_bnode().is_valid()) {
                    // edge entry, so get first parents sibbling and get its first child
                    parent_sibbling = read_node(parent_node->get_next_bnode(), nullptr);
                    if (parent_sibbling == nullptr) {
                        return btree_status_t::read_failed;
                    }
                    parent_sibbling->lock(locktype::LOCKTYPE_READ);

                    BtreeNodeInfo sibbling_info;
                    parent_sibbling->get(0, &sibbling_info, false);
                    sibbling_id = sibbling_info.bnode_id();
                } else {
                    sibbling_id = bnodeid_t::empty_bnodeid();
                }
            } else {
                BtreeNodeInfo sibbling_info;
                parent_node->get(parent_ind + 1, &sibbling_info, false);
                sibbling_id = sibbling_info.bnode_id();
            }
            child_node1->set_next_bnode(sibbling_id);
        } else {
            // parent ind is edge , so no key in parent to match against this is not valid in case of split crash
            // for merge, we have borrow everything on right
            BtreeNodePtr curr = nullptr;
            bnodeid_t    next = child_node1->get_next_bnode();
            while ((next.is_valid())) {
                curr = read_node(next, nullptr);
                if (curr == nullptr) {
                    return btree_status_t::read_failed;
                }
                child_node1->move_in_from_right_by_entries(m_btree_cfg, curr, curr->get_total_entries());
                nodes_to_free.push_back(curr);
                next = curr->get_next_bnode();
            }
            child_node1->set_next_bnode(bnodeid_t::empty_bnodeid());
        }

        // correct child version
        child_node1->flip_pc_gen_flag();

        /* we should synchronously try to recover this node. If we write asynchronously then
         * we need to do refresh.
         */
        ret = write_node_sync(child_node1);

        if (parent_sibbling != nullptr) {
            unlock_node(parent_sibbling, locktype::LOCKTYPE_READ);
        }

        if (ret != btree_status_t::success) {
            return ret;
        }
        
        for (int i = 0; i < (int)nodes_to_free.size(); i++) {
            free_node(nodes_to_free[i], nullptr);
        }

        COUNTER_INCREMENT(m_metrics, btree_num_pc_gen_mismatch, 1);

#ifndef NDEBUG
        if (parent_ind != parent_node->get_total_entries()) {
            K child_node1_last_key;
            child_node1->get_last_key(&child_node1_last_key);
            assert(child_node1_last_key.compare(&parent_key) == 0);
        }
#endif
        return ret;
    }

    btree_status_t split_node(BtreeNodePtr parent_node, BtreeNodePtr child_node, uint32_t parent_ind, 
                BtreeKey* out_split_key, btree_multinode_req_ptr multinode_req) {
        BtreeNodeInfo ninfo;
        BtreeNodePtr child_node1 = child_node;
        BtreeNodePtr child_node2 = child_node1->is_leaf() ? alloc_leaf_node() : alloc_interior_node();
        btree_status_t ret = btree_status_t::success;

        child_node2->set_next_bnode(child_node1->get_next_bnode());
        child_node1->set_next_bnode(child_node2->get_node_id());
        uint32_t child1_filled_size = m_btree_cfg.get_node_area_size() - child_node1->get_available_size(m_btree_cfg);
        uint32_t res =child_node1->move_out_to_right_by_size(m_btree_cfg, child_node2,
                        m_btree_cfg.get_split_size(child1_filled_size));
        assert(res>0);//means cannot split entries
        assert(child_node1->get_total_entries()>0);
        child_node1->flip_pc_gen_flag();

        // Update the existing parent node entry to point to second child ptr.
        ninfo.set_bnode_id(child_node2->get_node_id());
        parent_node->update(parent_ind, ninfo);

        // Insert the last entry in first child to parent node
        child_node1->get_last_key(out_split_key);
        ninfo.set_bnode_id(child_node1->get_node_id());
        parent_node->insert(*out_split_key, ninfo);

#ifndef NDEBUG
        K split_key;
        child_node2->get_first_key(&split_key);
        assert(split_key.compare(out_split_key) > 0);
#endif
        LOGDEBUGMOD(btree_structures, "Split child_node={} with new_child_node={}, parent_node={}, split_key={}",
                child_node1->get_node_id_int(), child_node2->get_node_id_int(), parent_node->get_node_id_int(),
                out_split_key->to_string());

       
       // NOTE: Do not access parentInd after insert, since insert would have
        // we write right child node, than parent and than left child
        write_node_async(child_node2, multinode_req);
        write_node_async(parent_node, multinode_req);
        write_node_async(child_node1, multinode_req);
        
        // NOTE: Do not access parentInd after insert, since insert would have
        // shifted parentNode to the right.
        return ret;
    }

    struct merge_info {
        BtreeNodePtr node;
        BtreeNodePtr node_orig;
        uint16_t  parent_index=0xFFFF;
        bool freed=false;
        bool is_new_allocation=false;
        bool is_last_key=false;
    };

    auto merge_nodes(BtreeNodePtr parent_node, std::vector< int >& indices_list,  btree_multinode_req_ptr multinode_req) {
        struct {
            bool     merged;  // Have we merged at all
            uint32_t nmerged; // If we merged, how many are the final result of nodes 
            btree_status_t status;       
        } ret{false, 0, btree_status_t::success};

        std::vector< merge_info > minfo;
        BtreeNodeInfo             child_info;
        uint32_t                  ndeleted_nodes = 0;

        // Loop into all index and initialize list
        minfo.reserve(indices_list.size());
        
        for (auto i = 0u; i < indices_list.size(); i++) {
            
            if (indices_list[i] == (int)parent_node->get_total_entries()) {
                assert(parent_node->get_edge_id().is_valid());//ensure its valid edge
            }
                
            parent_node->get(indices_list[i], &child_info, false /* copy */);
            merge_info m;

            ret.status = read_and_lock_node(child_info.bnode_id(), m.node_orig, locktype::LOCKTYPE_WRITE, 
                                    locktype::LOCKTYPE_WRITE, multinode_req);
            if (ret.status != btree_status_t::success) {
                return ret;
            }
            assert(m.node_orig->is_valid_node());
            m.node = m.node_orig;

            if (i != 0) { // create replica childs except first child
                m.node = btree_store_t::alloc_node(m_btree_store.get(), m.node_orig->is_leaf(), m.is_new_allocation,
                                                   m.node_orig);
                minfo[i - 1].node->set_next_bnode(m.node->get_node_id()); // link them
            }
            m.node->flip_pc_gen_flag();
            m.freed = false;
            m.parent_index = indices_list[i];
            minfo.push_back(m);
        }

        assert(indices_list.size() > 1);
        
        assert(indices_list.size() == minfo.size());
        K last_pkey;//last key of parent node
        if (minfo[indices_list.size() - 1].parent_index != parent_node->get_total_entries()) {
            /* If it is not edge we always preserve the last key in a given merge group of nodes.*/
            parent_node->get_nth_key(minfo[indices_list.size() - 1].parent_index, &last_pkey, true);
        }

        // Rebalance entries for each of the node and mark any node to be removed, if empty.
        auto i = 0U;
        auto j = 1U;
        auto balanced_size = m_btree_cfg.get_ideal_fill_size();
        int last_indx = minfo[0].parent_index;//last seen index in parent whos child was not freed
        while ((i < indices_list.size() - 1) && (j < indices_list.size())) {
            minfo[j].parent_index -= ndeleted_nodes; // Adjust the parent index for deleted nodes

            if (minfo[i].node->get_occupied_size(m_btree_cfg) < balanced_size) {
                // We have room to pull some from next node
                uint32_t pull_size = balanced_size - minfo[i].node->get_occupied_size(m_btree_cfg);
                if (minfo[i].node->move_in_from_right_by_size(m_btree_cfg, minfo[j].node, pull_size)) {
                    // move in internally updates edge if needed
                    ret.merged = true;
                }
                
                if (minfo[j].node->get_total_entries() == 0) {
                    // We have removed all the entries from the next node, remove the entry in parent and move on to
                    // the next node. 

                    minfo[j].freed = true;
                    parent_node->remove(minfo[j].parent_index); // remove interally updates parents edge if needed
                    minfo[i].node->set_next_bnode(minfo[j].node->get_next_bnode());
                    ndeleted_nodes++;
                    ret.merged = true;//case when no entries moved but node is still empty
                }
            }

            if (!minfo[j].freed) {
                last_indx = minfo[j].parent_index;
                /* update the sibling index */
                i = j;
            }
            j++;
        }

        assert(!minfo[0].freed); // If we merge it, we expect the left most one has at least 1 entry.
        for (auto n = 0u; n < minfo.size(); n++) {
            if (!minfo[n].freed) {
                // lets get the last key and put in the entry into parent node
                BtreeNodeInfo ninfo(minfo[n].node->get_node_id());

                if (minfo[n].parent_index == parent_node->get_total_entries()) { //edge entrys
                    parent_node->update(minfo[n].parent_index, ninfo);
                } else if (minfo[n].node->get_total_entries() != 0) {
                    K last_ckey;//last key in child
                    minfo[n].node->get_last_key(&last_ckey);
                    parent_node->update(minfo[n].parent_index, last_ckey, ninfo);
                } else {
                    parent_node->update(minfo[n].parent_index, ninfo);
                }

                if (n == 0) {
                    continue;
                } // skip first child commit.

                write_node_async(minfo[n].node, multinode_req);
            }
        }

        if (last_indx != (int)parent_node->get_total_entries()) {
            /* preserve the last key if it is not the edge */
            V temp_value;
            parent_node->get(last_indx, &temp_value, true);//save value
            parent_node->update(last_indx, last_pkey, temp_value);//update key keeping same value
        }
#ifndef NDEBUG
        validate_sanity_next_child(parent_node, (uint32_t)last_indx);
#endif
        // Its time to write the parent node and loop again to write all nodes and free freed nodes
        write_node_async(parent_node, multinode_req);

        ret.nmerged = minfo.size() - ndeleted_nodes;

        write_node_async(minfo[0].node, multinode_req);
#ifndef NDEBUG
        validate_sanity(minfo,parent_node,indices_list);
#endif

        // Loop again in reverse order to unlock the nodes. freeable nodes need to be unlocked and freed
        for (int n = minfo.size() - 1; n >= 0; n--) {
            if (minfo[n].freed) {
                // free copied node if it became empty
                free_node(minfo[n].node, multinode_req);
            }
            // free original node except first
            if (n != 0 && minfo[n].is_new_allocation) {
                free_node(minfo[n].node_orig, multinode_req);
            }
            unlock_node(minfo[n].node_orig, locktype::LOCKTYPE_WRITE);
        }

        return ret;
    }


#ifndef NDEBUG
    void validate_sanity_next_child(BtreeNodePtr parent_node, uint32_t ind) {
        BtreeNodeInfo             child_info;
        K child_key;
        K parent_key;

        if (parent_node->get_edge_id().is_valid()) {
            if (ind == parent_node->get_total_entries()) {
                return;
            }
        } else {
            if (ind == parent_node->get_total_entries() - 1) {
                return;
            }
        }
        parent_node->get(ind+1, &child_info, false /* copy */);
        auto child_node = read_node(child_info.bnode_id(), nullptr);
        lock_and_refresh_node(child_node, locktype::LOCKTYPE_READ, nullptr);
        if (child_node->get_total_entries() == 0) {
            unlock_node(child_node, locktype::LOCKTYPE_READ);
            return;
        }
        child_node->get_first_key(&child_key);
        parent_node->get_nth_key(ind, &parent_key, false);
        assert(child_key.compare(&parent_key) > 0);
        unlock_node(child_node, locktype::LOCKTYPE_READ);
    }

    void validate_sanity(std::vector< merge_info >& minfo, BtreeNodePtr parent_node, std::vector< int >& indices_list) {
        int          index_sub = indices_list[0];
        BtreeNodePtr prev = nullptr;
        int last_indx = -1;

        for (int i = 0; i < (int)indices_list.size(); i++) {
            if (minfo[i].freed != true) {
                last_indx = i;
            }
        }

        for (int i = 0; i < (int)indices_list.size(); i++) {
            if (minfo[i].freed != true) {
                BtreeNodeInfo child_info;
                assert(index_sub == minfo[i].parent_index);
                parent_node->get(minfo[i].parent_index, &child_info, false);
                assert(child_info.bnode_id() == minfo[i].node->get_node_id());
                index_sub++;
                if (prev != nullptr && prev->get_next_bnode().m_id != minfo[i].node->get_node_id().m_id) {
                    cout << "oops";
                }
                
                if (minfo[i].node->get_total_entries() == 0) {
                    continue;
                }
                K last_key;
                minfo[i].node->get_last_key(&last_key);
                K first_key;
                minfo[i].node->get_first_key(&first_key);

                if (minfo[i].parent_index != 0) {
                    K parent_key;
                    parent_node->get_nth_key(minfo[i].parent_index - 1, &parent_key, false);
                    assert(first_key.compare(&parent_key) >= 0);
                }

                if (minfo[i].parent_index != parent_node->get_total_entries()) {
                    K parent_key;
                    parent_node->get_nth_key(minfo[i].parent_index, &parent_key, false);
                    if (i == last_indx) {
                        /* we always preserve the last key */
                        assert(last_key.compare(&parent_key) <= 0);
                    } else {
                        assert(last_key.compare(&parent_key) == 0);
                    }
                }
                prev = minfo[i].node;
            }
        }
    }

#endif

    BtreeNodePtr alloc_leaf_node() {
        bool         is_new_allocation;
        BtreeNodePtr n = btree_store_t::alloc_node(m_btree_store.get(), true /* is_leaf */, is_new_allocation);
        n->set_leaf(true);
        COUNTER_INCREMENT(m_metrics, btree_leaf_node_count, 1);
        return n;
    }

    BtreeNodePtr alloc_interior_node() {
        bool         is_new_allocation;
        BtreeNodePtr n = btree_store_t::alloc_node(m_btree_store.get(), false /* isLeaf */, is_new_allocation);
        n->set_leaf(false);
        COUNTER_INCREMENT(m_metrics, btree_int_node_count, 1);
        return n;
    }

    /* Note:- This function assumes that access of this node is thread safe. */
    void free_node(BtreeNodePtr& node, btree_multinode_req_ptr multinode_req, bool mem_only = false) {
        LOGDEBUGMOD(btree_generics, "Free node-{}", node->get_node_id_int());

        COUNTER_DECREMENT_IF_ELSE(m_metrics, node->is_leaf(), btree_leaf_node_count, btree_int_node_count, 1);
        assert(node->is_valid_node());
        node->set_valid_node(false);
        btree_store_t::free_node(m_btree_store.get(), node, multinode_req, mem_only);
    }

    /* Recovery process is different for root node, child node and sibling node depending on how the node
     * is accessed. This is the reason to create below three apis separately. 
     */
    btree_status_t read_and_lock_root(bnodeid_t id, BtreeNodePtr &node_ptr, thread::locktype int_lock_type, 
                                        thread::locktype leaf_lock_type, btree_multinode_req_ptr multinode_req) {
        /* there is no recovery for root node as it is always written to a fixed bnodeid */
        return(read_and_lock_node(id, node_ptr, int_lock_type, int_lock_type, multinode_req));
    }

    /* It read the node, take the lock and recover it if required */
    btree_status_t read_and_lock_child(bnodeid_t child_id, BtreeNodePtr &child_node, BtreeNodePtr parent_node,
        uint32_t parent_ind,
        thread::locktype int_lock_type,
        thread::locktype leaf_lock_type, btree_multinode_req_ptr multinode_req) {

        child_node = read_node(child_id, multinode_req);
        if (child_node == nullptr) {
            LOGERROR("read failed btree name {}", m_btree_cfg.get_name());
            return btree_status_t::read_failed;
        }

        if (child_id.m_pc_gen_flag != child_node->get_node_id().m_pc_gen_flag) {
            auto ret = lock_and_refresh_node(child_node, LOCKTYPE_WRITE, multinode_req);
            if (ret != btree_status_t::success) {
                LOGERROR("refresh failed btree name {}", m_btree_cfg.get_name());
                return ret;
            }
            if (child_id.m_pc_gen_flag != child_node->get_node_id().m_pc_gen_flag) { //check again
                ret = fix_pc_gen_mistmatch(parent_node, child_node, parent_ind);
                if (ret != btree_status_t::success) {
                    LOGERROR("node recovery failed btree name {}", m_btree_cfg.get_name());
                    child_node->unlock(LOCKTYPE_WRITE);
                    return ret;
                }
            }
            child_node->unlock(LOCKTYPE_WRITE);
        }
        
        auto acq_lock = (child_node->is_leaf()) ? leaf_lock_type : int_lock_type;
        btree_status_t ret = lock_and_refresh_node(child_node, acq_lock, multinode_req);
        assert(child_node->is_valid_node());
        return ret;
    }

    /* It read the node, take the lock and recover it if required */
    btree_status_t read_and_lock_sibling(bnodeid_t id, BtreeNodePtr &node_ptr, thread::locktype int_lock_type,
                                            thread::locktype leaf_lock_type, 
                                            btree_multinode_req_ptr multinode_req) {
        
        /* TODO: Currently we do not have any recovery while sibling is read. It is not a problem today
         * as we always scan the whole btree traversally during boot. However, we should support
         * it later.
         */
        return(read_and_lock_node(id, node_ptr, int_lock_type, int_lock_type, multinode_req));
    }

    /* It read the node and take a lock of the node. It doesn't recover the node.
     * @int_lock_type  :- lock type if a node is interior node.
     * @leaf_lock_type :- lock type if a node is leaf node.
     */
    btree_status_t read_and_lock_node(bnodeid_t id, BtreeNodePtr &node_ptr, thread::locktype int_lock_type, 
                                        thread::locktype leaf_lock_type, 
                                        btree_multinode_req_ptr multinode_req) {
        
        node_ptr = read_node(id, multinode_req);
        if (node_ptr == nullptr) {
            LOGERROR("read failed btree name {}", m_btree_cfg.get_name());
            return btree_status_t::read_failed;
        }
        
        auto acq_lock = (node_ptr->is_leaf()) ? leaf_lock_type : int_lock_type;
        auto ret = lock_and_refresh_node(node_ptr, acq_lock, multinode_req);
        if (ret != btree_status_t::success) {
            LOGERROR("refresh failed btree name {}", m_btree_cfg.get_name());
            return ret;
        }

        return btree_status_t::success;
    }

    btree_status_t get_child_and_lock_node(BtreeNodePtr node, uint32_t index, BtreeNodeInfo &child_info, 
                                    BtreeNodePtr &child_node, thread::locktype int_lock_type, 
                                    thread::locktype leaf_lock_type, 
                                    btree_multinode_req_ptr multinode_req) {

        if (index == node->get_total_entries()) {
            child_info.set_bnode_id(node->get_edge_id());
            // If bsearch points to last index, it means the search has not found entry unless it is an edge value.
            if (!child_info.has_valid_bnode_id()) {
                assert(0);
                return btree_status_t::not_found;
            }
        } else {
            assert(index < node->get_total_entries());
            node->get(index, &child_info, false /* copy */);
        }

        return(read_and_lock_child(child_info.bnode_id(), child_node, node, index, int_lock_type, 
                                    leaf_lock_type, multinode_req));
    }

    /* It doesn't return anything as io will be completed (success or failure) asynchronously */
    void  write_node_async(BtreeNodePtr& node, btree_multinode_req_ptr multinode_req) {
        /* ignore the return status */
        assert(multinode_req);
        assert(node->m_common_header.is_lock);
        write_node(node, multinode_req);
    }

    btree_status_t write_node_sync(BtreeNodePtr& node) {
        return(write_node(node, nullptr));
    }

    btree_status_t write_node(BtreeNodePtr& node, btree_multinode_req_ptr multinode_req) {
              
        LOGDEBUGMOD(btree_generics, "Write node-{}", node->get_node_id_int());

        COUNTER_INCREMENT_IF_ELSE(m_metrics, node->is_leaf(), btree_leaf_node_writes, btree_int_node_writes, 1);
        HISTOGRAM_OBSERVE_IF_ELSE(m_metrics, node->is_leaf(), btree_leaf_node_occupancy, btree_int_node_occupancy,
                                  ((NodeSize - node->get_available_size(m_btree_cfg)) * 100)/NodeSize);
        return(btree_store_t::write_node(m_btree_store.get(), node, multinode_req));
    }

    BtreeNodePtr read_node(bnodeid_t id, btree_multinode_req_ptr multinode_req) {
        return(btree_store_t::read_node(m_btree_store.get(), id));
    }

    btree_status_t lock_and_refresh_node(BtreeNodePtr node, homeds::thread::locktype type,
                   btree_multinode_req_ptr multinode_req) {
        bool is_write_modifiable;
        node->lock(type);
        if (type == homeds::thread::LOCKTYPE_WRITE) {
            is_write_modifiable = true;
#ifndef NDEBUG
            node->m_common_header.is_lock = 1;
#endif
        } else {
            is_write_modifiable = false;
        }

        auto ret = btree_store_t::refresh_node(m_btree_store.get(), node, multinode_req, is_write_modifiable);
        if (ret != btree_status_t::success) {
            node->unlock(type);
            return ret;
        }
        start_of_lock(node, type);
        return btree_status_t::success;
    }

    btree_status_t lock_node_upgrade(const BtreeNodePtr& node, btree_multinode_req_ptr multinode_req) {
        // Explicitly dec and incr, for upgrade, since it does not call top level functions to lock/unlock node
        auto time_spent = end_of_lock(node, LOCKTYPE_READ);

        node->lock_upgrade();
#ifndef NDEBUG
        node->m_common_header.is_lock = 1;
#endif
        node->lock_acknowledge();
        auto ret = btree_store_t::refresh_node(m_btree_store.get(), node, multinode_req, true);
        if (ret != btree_status_t::success) {
            node->unlock(LOCKTYPE_WRITE);
            return ret;
        }

        observe_lock_time(node, LOCKTYPE_READ, time_spent);
        start_of_lock(node, LOCKTYPE_WRITE);
        return btree_status_t::success;
    }

    void unlock_node(const BtreeNodePtr& node, homeds::thread::locktype type) {
#ifndef NDEBUG
        if (type == homeds::thread::LOCKTYPE_WRITE) {
            node->m_common_header.is_lock = 0;
        }
#endif
        node->unlock(type);
        auto time_spent = end_of_lock(node, type);
        observe_lock_time(node, type, time_spent);
#if 0
        if (release) { release_node(node); }
#endif
    }

    void observe_lock_time(const BtreeNodePtr& node, homeds::thread::locktype type, uint64_t time_spent) {
        if (time_spent == 0) { return; }

        if (type == LOCKTYPE_READ) {
            HISTOGRAM_OBSERVE_IF_ELSE(m_metrics, node->is_leaf(),
                    btree_inclusive_time_in_leaf_node, btree_inclusive_time_in_int_node, time_spent);
        } else {
            HISTOGRAM_OBSERVE_IF_ELSE(m_metrics, node->is_leaf(),
                                      btree_exclusive_time_in_leaf_node, btree_exclusive_time_in_int_node, time_spent);
        }
    }

    static std::string node_info_list(std::vector< btree_locked_node_info > *pnode_infos) {
        std::stringstream ss;
        for (auto &info : *pnode_infos) {
            ss << (void *)info.node << ", ";
        }
        ss << "\n";
        return ss.str();
    }

    static void start_of_lock(const BtreeNodePtr& node, locktype ltype) {
        btree_locked_node_info info;

        info.start_time = Clock::now();
        info.node = node.get();
        if (ltype == LOCKTYPE_WRITE) {
            wr_locked_nodes.push_back(info);
            DLOGTRACEMOD(btree_generics, "ADDING node {} to write locked nodes list, its size = {}", (void *)info.node,
                    wr_locked_nodes.size());
        } else if (ltype == LOCKTYPE_READ) {
            rd_locked_nodes.push_back(info);
            DLOGTRACEMOD(btree_generics,"ADDING node {} to read locked nodes list, its size = {}", (void *)info.node,
                    rd_locked_nodes.size());
        } else {
            assert(0);
        }
    }

    static bool remove_locked_node(const BtreeNodePtr& node, locktype ltype, btree_locked_node_info* out_info) {
        auto pnode_infos = (ltype == LOCKTYPE_WRITE) ? &wr_locked_nodes : &rd_locked_nodes;

        if (!pnode_infos->empty()) {
            auto info = pnode_infos->back();
            if (info.node == node.get()) {
                *out_info = info;
                pnode_infos->pop_back();
                DLOGTRACEMOD(btree_generics, "REMOVING node {} from {} locked nodes list, its size = {}",
                        (void *)info.node, (ltype == LOCKTYPE_WRITE) ? "write" : "read", pnode_infos->size());
                return true;
            } else if (pnode_infos->size() > 1) {
                info = pnode_infos->at(pnode_infos->size() - 2);
                if (info.node == node.get()) {
                    *out_info = info;
                    pnode_infos->at(pnode_infos->size() - 2) = pnode_infos->back();
                    pnode_infos->pop_back();
                    DLOGTRACEMOD(btree_generics, "REMOVING node {} from {} locked nodes list, its size = {}",
                            (void *)info.node,(ltype == LOCKTYPE_WRITE) ? "write" : "read", pnode_infos->size());
                    return true;
                }
            }
        }

#ifndef NDEBUG
        if (pnode_infos->empty()) {
            LOGERROR("locked_node_list: node = {} not found, locked node list empty", (void*)node.get());
        } else if (pnode_infos->size() == 1) {
            LOGERROR("locked_node_list: node = {} not found, total list count = 1, Expecting node = {}", (void*)node.get(),
                     (void*)pnode_infos->back().node);
        } else {
            LOGERROR("locked_node_list: node = {} not found, total list count = {}, Expecting nodes = {} or {}",
                    (void*)node.get(), pnode_infos->size(), (void*)pnode_infos->back().node,
                    (void*)pnode_infos->at(pnode_infos->size()-2).node);
        }
#endif
        return false;
    }

    static uint64_t end_of_lock(const BtreeNodePtr& node, locktype ltype) {
        btree_locked_node_info info;
        if (!remove_locked_node(node, ltype, &info)) {
            LOGDEBUG("Expected node = {} is not there in locked_node_list", (void *)node.get());
            assert(0);
            return 0;
        }
        assert(node.get() == info.node);
        return get_elapsed_time_ns(info.start_time);
    }

#ifndef NDEBUG
    static void check_lock_debug() {
        if (wr_locked_nodes.size()) {
            LOGERROR("There are {} write locks held on the exit of API", wr_locked_nodes.size());
            assert(0);
        }

        if (rd_locked_nodes.size()) {
            LOGERROR("There are {} read locks held on the exit of API", rd_locked_nodes.size());
            assert(0);
        }
    }
#endif

protected:
    btree_status_t create_root_node() {
        // Assign one node as root node and initially root is leaf
        BtreeNodePtr root = alloc_leaf_node();
        m_root_node = root->get_node_id();
        btree_status_t ret = btree_status_t::success;

        ret = write_node_sync(root);
        if (ret != btree_status_t::success) {
            return ret;
        }
        m_sb.root_node = m_root_node;
        return btree_status_t::success;
    }

    BtreeConfig* get_config() { return &m_btree_cfg; }
};

template < btree_store_type BtreeStoreType, typename K, typename V, btree_node_type InteriorNodeType,
           btree_node_type LeafNodeType, size_t NodeSize, typename btree_req_type >
thread_local homeds::reserve_vector< btree_locked_node_info, 5 > btree_t::wr_locked_nodes;

template < btree_store_type BtreeStoreType, typename K, typename V, btree_node_type InteriorNodeType,
           btree_node_type LeafNodeType, size_t NodeSize, typename btree_req_type >
thread_local homeds::reserve_vector< btree_locked_node_info, 5 > btree_t::rd_locked_nodes;


#ifdef SERIALIZABLE_QUERY_IMPLEMENTATION
template < btree_store_type BtreeStoreType, typename K, typename V, btree_node_type InteriorNodeType,
           btree_node_type LeafNodeType, size_t NodeSize = 8192, typename btree_req_type = struct empty_writeback_req >
class BtreeLockTrackerImpl : public BtreeLockTracker {
public:
    BtreeLockTrackerImpl(btree_t* bt) : m_bt(bt) {}

    virtual ~BtreeLockTrackerImpl() {
        while (m_nodes.size()) {
            auto& p = m_nodes.top();
            m_bt->unlock_node(p.first, p.second);
            m_nodes.pop();
        }
    }

    void push(BtreeNodePtr node, homeds::thread::locktype locktype) {
        m_nodes.emplace(std::make_pair<>(node, locktype));
    }

    std::pair< BtreeNodePtr, homeds::thread::locktype > pop() {
        assert(m_nodes.size());
        std::pair< BtreeNodePtr, homeds::thread::locktype > p;
        if (m_nodes.size()) {
            p = m_nodes.top();
            m_nodes.pop();
        } else {
            p = std::make_pair<>(nullptr, homeds::thread::locktype::LOCKTYPE_NONE);
        }

        return p;
    }

    BtreeNodePtr top() { return (m_nodes.size == 0) ? nullptr : m_nodes.top().first; }

private:
    btree_t                                                           m_bt;
    std::stack< std::pair< BtreeNodePtr, homeds::thread::locktype > > m_nodes;
};
#endif

} // namespace btree
} // namespace homeds
