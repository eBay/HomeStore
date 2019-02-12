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
class Btree {
    typedef std::function< void(boost::intrusive_ptr< btree_req_type > cookie, std::error_condition status) >
        comp_callback;

private:
    bnodeid_t              m_root_node;
    homeds::thread::RWLock m_btree_lock;

    uint32_t          m_max_nodes;
    BtreeConfig       m_btree_cfg;
    btree_super_block m_sb;

    BtreeMetrics                     m_metrics;
    std::unique_ptr< btree_store_t > m_btree_store;
    comp_callback m_comp_cb;

#ifndef NDEBUG
    static thread_local int                                          wr_locked_count;
    static thread_local std::array< btree_node_t*, MAX_BTREE_DEPTH > wr_locked_nodes;

    static thread_local int                                          rd_locked_count;
    static thread_local std::array< btree_node_t*, MAX_BTREE_DEPTH > rd_locked_nodes;
#endif

    ////////////////// Implementation /////////////////////////
public:
    btree_super_block get_btree_sb() {
        return m_sb;
    }
    
    void process_completions(boost::intrusive_ptr<btree_req_type> cookie,
                             error_condition status,
                             boost::intrusive_ptr<btree_multinode_req> multinode_req) {
        if(cookie) {
            if (multinode_req == nullptr)
                m_comp_cb(cookie, status);
            else {
                int cnt = multinode_req->writes_pending.fetch_sub(1, std::memory_order_acq_rel);
                if (cnt == 1) 
                    m_comp_cb(cookie, status);
            }
        }
    }

    static btree_t *create_btree(BtreeConfig &cfg, void *btree_specific_context, comp_callback comp_cb) {
        Btree *bt = new Btree(cfg);
        bt->m_comp_cb = comp_cb;
        auto impl_ptr = btree_store_t::init_btree(cfg, btree_specific_context, 
                std::bind(&Btree::process_completions, bt, std::placeholders::_1, std::placeholders::_2,
                        std::placeholders::_3));
        bt->m_btree_store = std::move(impl_ptr);
        bt->init();
        return bt;
    }

    static btree_t* create_btree(BtreeConfig& cfg, void* btree_specific_context) {
        auto impl_ptr = btree_store_t::init_btree(cfg, btree_specific_context, nullptr);
        Btree *bt = new Btree(cfg);
        bt->m_btree_store = std::move(impl_ptr);
        bt->init();
        return bt;
    }

    static btree_t *create_btree(btree_super_block &btree_sb, BtreeConfig& cfg,
                                    void *btree_specific_context, comp_callback comp_cb) {
        Btree *bt = new Btree(cfg);
        bt->m_comp_cb = comp_cb;
        auto impl_ptr = btree_store_t::init_btree(cfg, btree_specific_context,
                std::bind(&Btree::process_completions, bt, std::placeholders::_1, std::placeholders::_2,
                          std::placeholders::_3), true);
        bt->m_btree_store = std::move(impl_ptr);
        bt->init_recovery(btree_sb);
        return bt;
    }

    void do_common_init(){
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
    
    void init(){
        do_common_init();
        create_root_node();
    }
    
    void init_recovery(btree_super_block btree_sb){
        m_sb = btree_sb;
        do_common_init();
        m_root_node = m_sb.root_node;
    }

    Btree(BtreeConfig &cfg) :
            m_btree_cfg(cfg),
            m_metrics(cfg.get_name().c_str()) {}
    
    ~Btree() {
        m_btree_lock.write_lock();
        BtreeNodePtr             root = btree_store_t::read_node(m_btree_store.get(), m_root_node);
        homeds::thread::locktype acq_lock = homeds::thread::LOCKTYPE_WRITE;
        std::deque< boost::intrusive_ptr< btree_req_type > > dependent_req_q;
        lock_node(root, acq_lock, &dependent_req_q);
        free(root);
        unlock_node(root, acq_lock);
        m_btree_lock.unlock();
    }

    void recovery_cmpltd() { btree_store_t::recovery_cmpltd(m_btree_store.get()); }

    // free nodes in post order traversal of tree
    void free(BtreeNodePtr node) {
        // TODO - this calls free node on mem_tree and ssd_tree.
        // In ssd_tree we free actual block id, which is not correct behavior
        // we shouldnt really free any blocks on free node, just reclaim any memory
        // occupied by ssd_tree structure in memory. Ideally we should have sepearte
        // api like deleteNode which should be called instead of freeNode
        homeds::thread::locktype                             acq_lock = homeds::thread::LOCKTYPE_WRITE;
        std::deque< boost::intrusive_ptr< btree_req_type > > dependent_req_q;
        uint32_t                                             i = 0;
        if (!node->is_leaf()) {
            BtreeNodeInfo child_info;
            while (i <= node->get_total_entries()) {
                if (i == node->get_total_entries()) {
                    child_info.set_bnode_id(node->get_edge_id());
                } else {
                    node->get(i, &child_info, false /* copy */);
                }

                BtreeNodePtr child = btree_store_t::read_node(m_btree_store.get(), child_info.bnode_id());

                lock_node(child, acq_lock, &dependent_req_q);
                try {
                    free(child);
                } catch (const homestore::homestore_exception& e) {
                    /* it can happen if read from the disk fails */
                    unlock_node(child, acq_lock);
                    throw e;
                } catch (const std::exception& e) {
                    unlock_node(child, acq_lock);
                    assert(0);
                    throw e;
                }
                unlock_node(child, acq_lock);
                i++;
            }
        }
        free_node(node, dependent_req_q);
    }

    void range_put(const BtreeKey &k, const BtreeValue &v, PutType put_type,
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
        put(k, v, put_type, dependent_req, cookie, &temp_v, &bur);
    }
    
    void put(const BtreeKey &k, const BtreeValue &v, PutType put_type) {
        V temp_v;
        put(k, v, put_type, nullptr, nullptr, &temp_v);
    }
    void put(const BtreeKey &k, const BtreeValue &v, PutType put_type, boost::intrusive_ptr<btree_req_type> dependent_req,
            boost::intrusive_ptr<btree_req_type> cookie, BtreeValue *existing_val = nullptr, 
            BtreeUpdateRequest<K,V> *bur = nullptr) {
        homeds::thread::locktype acq_lock = homeds::thread::LOCKTYPE_READ;
        int                      ind = -1;

#ifndef NDEBUG
        init_lock_debug();
#endif
        m_btree_lock.read_lock();
        int retry_cnt = 0;

retry:
        assert(rd_locked_count == 0 && wr_locked_count == 0);
        BtreeNodePtr root = btree_store_t::read_node(m_btree_store.get(), m_root_node);
        std::deque< boost::intrusive_ptr< btree_req_type > > dependent_req_q;
        if (dependent_req.get()) {
            dependent_req_q.push_back(dependent_req);
        }
        lock_node(root, acq_lock, &dependent_req_q);
        bool is_leaf = root->is_leaf();

        retry_cnt++;
        if (root->is_split_needed(m_btree_cfg, k, v, &ind, put_type, bur)) {
            // Time to do the split of root.
            unlock_node(root, acq_lock);
            m_btree_lock.unlock();
            check_split_root(k, v, dependent_req_q, put_type, bur);

            assert(rd_locked_count == 0 && wr_locked_count == 0);
            // We must have gotten a new root, need to start from scratch.
            m_btree_lock.read_lock();
            goto retry;
        } else if ((is_leaf) && (acq_lock != homeds::thread::LOCKTYPE_WRITE)) {
            // Root is a leaf, need to take write lock, instead of read, retry
            unlock_node(root, acq_lock);
            acq_lock = homeds::thread::LOCKTYPE_WRITE;
            goto retry;
        } else {
            boost::intrusive_ptr<btree_multinode_req> multinode_req;
            if(bur){
                assert(bur->callback() && bur->get_cb_param());//TODO- support BUR without callback
                multinode_req = new btree_multinode_req();
                multinode_req->writes_pending.fetch_add(1, std::memory_order_acq_rel);
            }

            bool success = do_put(root, acq_lock, k, v, ind, put_type, 
                        dependent_req_q, cookie, *existing_val,multinode_req, bur);
            if (success == false) {
                // Need to start from top down again, since there is a race between 2 inserts or deletes.
                acq_lock = homeds::thread::LOCKTYPE_READ;
                assert(rd_locked_count == 0 && wr_locked_count == 0);
                goto retry;
            }
            if(bur)
                process_completions(cookie,homestore::no_error,multinode_req);
        }

        m_btree_lock.unlock();

#ifndef NDEBUG
        check_lock_debug();
#endif
    }

    bool get(const BtreeKey& key, BtreeValue* outval) { return get(key, nullptr, outval); }

    bool get(const BtreeKey& key, BtreeKey* outkey, BtreeValue* outval) {
        return get_any(BtreeSearchRange(key), outkey, outval);
    }

    bool get_any(const BtreeSearchRange& range, BtreeKey* outkey, BtreeValue* outval) {
        bool is_found;
#ifndef NDEBUG
        init_lock_debug();
#endif

        m_btree_lock.read_lock();
        BtreeNodePtr root = btree_store_t::read_node(m_btree_store.get(), m_root_node);
        lock_node(root, homeds::thread::locktype::LOCKTYPE_READ, nullptr);

        is_found = do_get(root, range, outkey, outval);
        m_btree_lock.unlock();

        // TODO: Assert if key returned from do_get is same as key requested, incase of perfect match

#ifndef NDEBUG
        check_lock_debug();
#endif
        return is_found;
    }

    bool query(BtreeQueryRequest< K, V >& query_req, std::vector< std::pair< K, V > >& out_values) {
        //initialize cb param
        K in_st(*(K*)query_req.get_input_range().get_start_key());
        K in_en(*(K*)query_req.get_input_range().get_end_key());//cpy
        if(query_req.get_cb_param())
            query_req.get_cb_param()->get_input_range().set(in_st, query_req.get_input_range().is_start_inclusive(),
                                                  in_en, query_req.get_input_range().is_end_inclusive());
        
        bool has_more = false;
        if (query_req.get_batch_size() == 0) {
            return false;
        }

        query_req.init_batch_range();

        m_btree_lock.read_lock();
        BtreeNodePtr root = btree_store_t::read_node(m_btree_store.get(), m_root_node);
        lock_node(root, homeds::thread::locktype::LOCKTYPE_READ, nullptr);

        switch (query_req.query_type()) {
        case BtreeQueryType::SWEEP_NON_INTRUSIVE_PAGINATION_QUERY:
            has_more = do_sweep_query(root, query_req, out_values);
            break;

        case BtreeQueryType::TREE_TRAVERSAL_QUERY: has_more = do_traversal_query(root, query_req, out_values); break;

        default:
            unlock_node(root, homeds::thread::locktype::LOCKTYPE_READ);
            LOGERROR("Query type {} is not supported yet", query_req.query_type());
            break;
        }

        m_btree_lock.unlock();
        return has_more;
    }

#ifdef SERIALIZABLE_QUERY_IMPLEMENTATION
    bool sweep_query(BtreeQueryRequest& query_req, std::vector< std::pair< K, V > >& out_values) {
#ifndef NDEBUG
        init_lock_debug();
#endif
        query_req.init_batch_range();

        m_btree_lock.read_lock();
        BtreeNodePtr root = btree_store_t::read_node(m_btree_store.get(), m_root_node);
        lock_node(root, homeds::thread::locktype::LOCKTYPE_READ, nullptr);
        bool has_more = do_sweep_query(root, query_req, out_values);
        m_btree_lock.unlock();

#ifndef NDEBUG
        check_lock_debug();
#endif
        return has_more;
    }

    bool serializable_query(BtreeSerializableQueryRequest& query_req, std::vector< std::pair< K, V > >& out_values) {
#ifndef NDEBUG
        init_lock_debug();
#endif
        query_req.init_batch_range();

        m_btree_lock.read_lock();
        BtreeNodePtr node;

        if (query_req.is_empty_cursor()) {
            // Initialize a new lock tracker and put inside the cursor.
            query_req.cursor().m_locked_nodes = std::make_unique< BtreeLockTrackerImpl >(this);

            // Start and track from root.
            BtreeNodePtr root = btree_store_t::read_node(m_btree_store.get(), m_root_node);
            lock_node(root, homeds::thread::locktype::LOCKTYPE_READ, nullptr);
            get_tracker(query_req)->push(root); // Start tracking the locked nodes.
        } else {
            node = get_tracker(query_req)->top();
        }

        bool has_more = do_serialzable_query(node, query_req, out_values);
        m_btree_lock.unlock();

        // TODO: Assert if key returned from do_get is same as key requested, incase of perfect match

#ifndef NDEBUG
        check_lock_debug();
#endif

        return has_more;
    }

    BtreeLockTrackerImpl* get_tracker(BtreeSerializableQueryRequest& query_req) {
        return (BtreeLockTrackerImpl*)query_req->get_cursor.m_locked_nodes.get();
    }
#endif

    /* Given a regex key, tries to get all data that falls within the regex. Returns all the values
     * and also number of values that fall within the ranges */
    //    uint32_t get_multi(const BtreeSearchRange &range, std::vector<std::pair<BtreeKey *, BtreeValue *>> outval) {
    //    }

    bool remove_any(const BtreeSearchRange& range, BtreeKey* outkey, BtreeValue* outval) {
        return (remove_any(range, outkey, outval, nullptr, nullptr));
    }
    bool remove_any(const BtreeSearchRange& range, BtreeKey* outkey, BtreeValue* outval,
                    boost::intrusive_ptr< btree_req_type > dependent_req,
                    boost::intrusive_ptr< btree_req_type > cookie) {
        homeds::thread::locktype acq_lock = homeds::thread::locktype::LOCKTYPE_READ;
        bool                     is_found = false;

#ifndef NDEBUG
        init_lock_debug();
#endif

#ifdef REFCOUNT_DEBUG
        assert(OmDBGlobals::getGlobalRefCount() == 0);
#endif

        std::deque< boost::intrusive_ptr< btree_req_type > > dependent_req_q;
        if (dependent_req.get()) {
            dependent_req_q.push_back(dependent_req);
        }
        m_btree_lock.read_lock();

    retry:
        BtreeNodePtr root = btree_store_t::read_node(m_btree_store.get(), m_root_node);
        lock_node(root, acq_lock, &dependent_req_q);
        bool is_leaf = root->is_leaf();

        if (root->get_total_entries() == 0) {
            if (is_leaf) {
                // There are no entries in btree.
                unlock_node(root, acq_lock);
                m_btree_lock.unlock();
                return false;
            }
            assert(root->get_edge_id().is_valid());
            unlock_node(root, acq_lock);
            m_btree_lock.unlock();

            check_collapse_root(dependent_req_q);

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
            btree_status_t status = do_remove(root, acq_lock, range, outkey, outval, dependent_req_q, cookie);
            if (status == BTREE_RETRY) {
                // Need to start from top down again, since
                // there is a race between 2 inserts or deletes.
                acq_lock = homeds::thread::LOCKTYPE_READ;
                goto retry;
            } else if (status == BTREE_ITEM_FOUND) {
                is_found = true;
            } else {
                is_found = false;
            }
        }

        m_btree_lock.unlock();
#ifndef NDEBUG
        check_lock_debug();
#endif

#ifdef REFCOUNT_DEBUG
        assert(OmDBGlobals::getGlobalRefCount() == 0);
#endif
        return is_found;
    }

    bool remove(const BtreeKey& key, BtreeValue* outval) { return (remove(key, outval, nullptr, nullptr)); }

    bool remove(const BtreeKey& key, BtreeValue* outval, boost::intrusive_ptr< btree_req_type > dependent_req,
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

    nlohmann::json get_metrics_in_json(bool updated = true) { return m_metrics->get_result_in_json(updated); }

private:
    void to_string(bnodeid_t bnodeid, std::stringstream &ss) {
        BtreeNodePtr             node = btree_store_t::read_node(m_btree_store.get(), bnodeid);
        homeds::thread::locktype acq_lock = homeds::thread::locktype::LOCKTYPE_READ;
        lock_node(node, acq_lock, nullptr);

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

    bool do_get(BtreeNodePtr my_node, const BtreeSearchRange& range, BtreeKey* outkey, BtreeValue* outval) {
        if (my_node->is_leaf()) {
            auto result = my_node->find(range, outkey, outval);
            unlock_node(my_node, homeds::thread::locktype::LOCKTYPE_READ);
            return (result.found);
        }

        BtreeNodeInfo child_info;
        auto          result = my_node->find(range, nullptr, &child_info);
        BtreeNodePtr  child_node = btree_store_t::read_node(m_btree_store.get(), child_info.bnode_id());

        if (child_info.bnode_id().m_pc_gen_flag != child_node->get_node_id().m_pc_gen_flag) {
            lock_node(child_node, homeds::thread::LOCKTYPE_WRITE, NULL);
            /* check again in case somebody has already recovered this node */
            if (child_info.bnode_id().m_pc_gen_flag != child_node->get_node_id().m_pc_gen_flag) {
                fix_pc_gen_mistmatch(my_node, child_node, result.end_of_search_index, NULL);
            }
            unlock_node(child_node, homeds::thread::LOCKTYPE_WRITE);
        }
        lock_node(child_node, homeds::thread::LOCKTYPE_READ, NULL);
        unlock_node(my_node, homeds::thread::locktype::LOCKTYPE_READ);
        return (do_get(child_node, range, outkey, outval));
    }

    bool do_sweep_query(BtreeNodePtr my_node, BtreeQueryRequest< K, V >& query_req,
                        std::vector< std::pair< K, V > >& out_values) {
        if (my_node->is_leaf()) {
            assert(query_req.get_batch_size() > 0);

            auto         count = 0U;
            BtreeNodePtr next_node = nullptr;

            do {
                if (next_node) {
                    lock_node(next_node, homeds::thread::locktype::LOCKTYPE_READ, nullptr);
                    unlock_node(my_node, homeds::thread::locktype::LOCKTYPE_READ);
                    my_node = next_node;
                    if(my_node->get_total_entries()>0){
                        K ekey;
                        next_node->get_nth_key(0,&ekey,false);
                        if(query_req.get_input_range().get_end_key()->compare(&ekey) < 0) {//early lookup end
                            query_req.cursor().m_last_key = nullptr;
                            break;
                        }
                    }
                }

                LOGTRACE("Query leaf node:\n {}", my_node->to_string());

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
                    next_node = btree_store_t::read_node(m_btree_store.get(), my_node->get_next_bnode());
                } else {
                    // If we are here because our count is full, then setup the last key as cursor, otherwise, it would
                    // mean count is 0, but this is the rightmost leaf node in the tree. So no more cursors.
                    query_req.cursor().m_last_key = (count) ? std::make_unique< K >(out_values.back().first) : nullptr;
                    break;
                }
            } while (true);
            unlock_node(my_node, homeds::thread::locktype::LOCKTYPE_READ);
            return (query_req.cursor().m_last_key != nullptr);
        }

        BtreeNodeInfo start_child_info;
        my_node->find(query_req.get_start_of_range(), nullptr, &start_child_info);

        BtreeNodePtr child_node = btree_store_t::read_node(m_btree_store.get(), start_child_info.bnode_id());
        lock_node(child_node, homeds::thread::LOCKTYPE_READ, nullptr);
        unlock_node(my_node, homeds::thread::locktype::LOCKTYPE_READ);
        return (do_sweep_query(child_node, query_req, out_values));
    }

    bool do_traversal_query(BtreeNodePtr my_node, BtreeQueryRequest< K, V >& query_req,
                            std::vector< std::pair< K, V > >& out_values, BtreeSearchRange* sub_range = nullptr) {
        bool pagination_done = false;

        if (my_node->is_leaf()) {
            assert(query_req.get_batch_size() > 0);

            int                              start_ind = 0, end_ind = 0;
            std::vector< std::pair< K, V > > match_kv;
            my_node->get_all(query_req.this_batch_range(), query_req.get_batch_size() - (uint32_t)out_values.size(),
                             start_ind, end_ind, &match_kv);

            if(query_req.callback()){
                //TODO - support accurate sub ranges in future instead of setting input range
                query_req.get_cb_param()->set_sub_range(query_req.get_input_range());
                std::vector<std::pair<K, V>> result_kv;
                query_req.callback()(match_kv, result_kv, query_req.get_cb_param());
                auto ele_to_add =result_kv.size();
                if(ele_to_add>0)
                    out_values.insert(out_values.end(), result_kv.begin(), result_kv.begin()+ele_to_add);
            }
            out_values.insert(std::end(out_values), std::begin(match_kv), std::end(match_kv));

            unlock_node(my_node, homeds::thread::locktype::LOCKTYPE_READ);
            if (out_values.size() >= query_req.get_batch_size()) {
                assert(out_values.size() == query_req.get_batch_size());
                query_req.cursor().m_last_key = std::make_unique< K >(out_values.back().first);
                return true;
            }

            return false;
        }

        auto start_ret = my_node->find(query_req.get_start_of_range(), nullptr, nullptr);
        auto end_ret = my_node->find(query_req.get_end_of_range(), nullptr, nullptr);

        bool unlocked_already = false;
        auto ind = start_ret.end_of_search_index;
        while (ind <= end_ret.end_of_search_index) {
            BtreeNodeInfo child_info;
            my_node->get(ind, &child_info, false);
            auto child_node = btree_store_t::read_node(m_btree_store.get(), child_info.bnode_id());

            homeds::thread::locktype child_cur_lock = homeds::thread::LOCKTYPE_READ;
            lock_node(child_node, child_cur_lock, nullptr);

            if (child_info.bnode_id().m_pc_gen_flag != child_node->get_node_id().m_pc_gen_flag) {
                std::deque<boost::intrusive_ptr<btree_req_type>> dependent_req_q;
                if (upgrade_node(child_node, nullptr, child_cur_lock, LOCKTYPE_NONE, dependent_req_q) == false) {
                    unlock_node(my_node, homeds::thread::LOCKTYPE_READ);
                    unlock_node(child_node, child_cur_lock);
                    return (false); //retry from root
                }
                if (child_info.bnode_id().m_pc_gen_flag != child_node->get_node_id().m_pc_gen_flag) //check again
                    fix_pc_gen_mistmatch(my_node, child_node, ind, &dependent_req_q);
                unlock_node(child_node, homeds::thread::LOCKTYPE_WRITE);
                continue;
            }

            if (ind == end_ret.end_of_search_index) {
                // If we have reached the last index, unlock before traversing down, because we no longer need
                // this lock. Holding this lock will impact performance unncessarily.
                unlock_node(my_node, homeds::thread::locktype::LOCKTYPE_READ);
                unlocked_already = true;
            }
            // TODO - pass sub range if child is leaf
            pagination_done = do_traversal_query(child_node, query_req, out_values);
            if (pagination_done) {
                break;
            }
            ind++;
        }

        if (!unlocked_already) {
            unlock_node(my_node, homeds::thread::locktype::LOCKTYPE_READ);
        }
        return (pagination_done);
    }

#ifdef SERIALIZABLE_QUERY_IMPLEMENTATION
    bool do_serialzable_query(BtreeNodePtr my_node, BtreeSerializableQueryRequest& query_req,
                              std::vector< std::pair< K, V > >& out_values) {
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
            }

            return has_more;
        }

        BtreeNodeId start_child_ptr, end_child_ptr;
        auto        start_ret = my_node->find(query_req.get_start_of_range(), nullptr, &start_child_ptr);
        auto        end_ret = my_node->find(query_req.get_end_of_range(), nullptr, &end_child_ptr);

        BtreeNodePtr child_node;
        if (start_ret.end_of_search_index == end_ret.end_of_search_index) {
            assert(start_child_ptr == end_child_ptr);
            child_node = btree_store_t::read_node(m_btree_store.get(), start_child_ptr.get_node_id());
            lock_node(child_node, homeds::thread::LOCKTYPE_READ, nullptr);
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
                child_node = btree_store_t::read_node(m_btree_store.get(), child_ptr.get_node_id());

                lock_node(child_node, homeds::thread::LOCKTYPE_READ, nullptr);
                get_tracker(query_req)->push(child_node);

                if (do_serialzable_query(child_node, query_req, out_values)) {
                    has_more = true;
                    assert(out_values.size() == query_req.get_batch_size());
                    break;
                }
            }

            if (!has_more) {
                unlock_node(my_node, homeds::thread::locktype::LOCKTYPE_READ);
                assert(get_tracker(query_req)->top() == my_node);
                get_tracker(query_req)->pop();
            }
            return has_more;
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
    bool upgrade_node(BtreeNodePtr my_node, BtreeNodePtr child_node, homeds::thread::locktype& cur_lock,
                      homeds::thread::locktype                              child_cur_lock,
                      std::deque< boost::intrusive_ptr< btree_req_type > >& dependent_req_q) {
        uint64_t prev_gen;
        bool     ret = true;

        if (cur_lock == homeds::thread::LOCKTYPE_WRITE) {
            ret = true;
            goto done;
        }

        prev_gen = my_node->get_gen();
        if (child_node) {
            unlock_node(child_node, child_cur_lock);
        }

#ifndef NDEBUG
        // Explicitly dec and incr, for upgrade, since it does not call top level functions to lock/unlock node
        dec_check_lock_debug(my_node, LOCKTYPE_READ);
#endif

        lock_node_upgrade(my_node, &dependent_req_q);

#ifndef NDEBUG
        inc_lock_debug(my_node, LOCKTYPE_WRITE);
#endif

        // If the node has been made invalid (probably by mergeNodes) ask caller to start over again, but before that
        // cleanup or free this node if there is no one waiting.
        if (!my_node->is_valid_node()) {
            if (my_node->any_upgrade_waiters()) {
                // Still some one else is waiting, we are not the last.
                unlock_node(my_node, homeds::thread::LOCKTYPE_WRITE);
            } else {
                // No else is waiting for this node and this is an invalid node, free it up.
                assert(my_node->get_total_entries() == 0);
                unlock_node(my_node, homeds::thread::LOCKTYPE_WRITE);

                // Its ok to free after unlock, because the chain has been already cut when the node is invalidated.
                // So no one would have entered here after the chain is cut.
                free_node(my_node, dependent_req_q);
            }
            ret = false;
            goto done;
        }

        // If node has been updated, while we have upgraded, ask caller to start all over again.
        if (prev_gen != my_node->get_gen()) {
            unlock_node(my_node, homeds::thread::LOCKTYPE_WRITE);
            ret = false;
            goto done;
        }

        // The node was not changed by anyone else during upgrade.
        cur_lock = homeds::thread::LOCKTYPE_WRITE;
        if (child_node) {
            lock_node(child_node, child_cur_lock, &dependent_req_q);
        }

    done:
        if (ret == false) {
            // if (child_node) release_node(child_node);
        }
        return ret; // We have successfully upgraded the node.
    }

#if 0
    /* This method tries to get the child node from an interior parent node, based on the key. It also provides the
     * index within the parent node, which is pointing to the child node. In case if the child node is an edge node,
     * instead of creating a new child node */
    BtreeNodePtr get_child_node(BtreeNodePtr int_node, homeds::thread::locktype curlock, const BtreeKey &key,
                                 int *out_ind) {
        BtreeNodeId childptr;

        if (*out_ind == -1) {
            auto result = int_node->find(BtreeSearchRange(key), nullptr, nullptr);
            *out_ind = result.end_of_search_index;
        }

        // During Insert, it is possible to get the last entry where in it needs to insert
        // the data. In those cases, we will try to accommodate with the previous entry
        // and update its key to this entry.
        if (*out_ind == int_node->get_total_entries()) {
            childptr.set_node_id(int_node->get_edge_id());

            if (!childptr.is_valid_ptr()) {
                if (upgrade_node(int_node, nullptr /* childNode */, curlock, homeds::thread::LOCKTYPE_NONE) == false) {
                    return nullptr;
                }

                if (*out_ind == 0) {
                    // If index is 0 and this is the last entry, it is a nullptr node.
                    // We should never get to nullptr node after upgradeNode is successful.
                    assert(0);
                    return nullptr;
                }

                // Update the previous entry to cover this key as well.
                (*out_ind)--;
                int_node->get(*out_ind, &childptr, false /* copy */);
                int_node->update(*out_ind, key, childptr);
            }
        } else {
            int_node->get(*out_ind, &childptr, false /* copy */);
        }

        return read_node(childptr.get_node_id());
    }
#endif

    BtreeNodePtr get_child_node(BtreeNodePtr node, uint32_t index, BtreeNodeInfo* child_info) {

        if (index == node->get_total_entries()) {
            child_info->set_bnode_id(node->get_edge_id());
            // If bsearch points to last index, it means the search has not found entry unless it is an edge value.
            if (!child_info->has_valid_bnode_id()) {
                return nullptr;
            }
        } else {
            node->get(index, child_info, false /* copy */);
        }

        return btree_store_t::read_node(m_btree_store.get(), child_info->bnode_id());
    }

    BtreeNodePtr get_child_node(BtreeNodePtr int_node, const BtreeSearchRange& range, uint32_t* outind, bool* is_found,
                                BtreeNodeInfo* child_info, bool load_child = false) {
        auto result = int_node->find(range, nullptr, nullptr);
        *is_found = result.found;
        *outind = result.end_of_search_index;

        if (*outind == int_node->get_total_entries()) {
            // assert(!(*isFound));
            child_info->set_bnode_id(int_node->get_edge_id());

            // If bsearch points to last index, it means the search has not found entry unless it is an edge value.
            if (child_info->has_valid_bnode_id()) {
                *is_found = true;
            }
        } else {
            int_node->get(*outind, child_info, false /* copy */);
            *is_found = true;
        }
        if (load_child)
            return btree_store_t::read_node(m_btree_store.get(), child_info->bnode_id());
        else
            return nullptr;
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
     * put_type    = Type of the put (refer to structure PutType)
     * is_end_path = set to true only for last path from root to tree, for range put
     * op          = tracks multi node io.
     */
    bool do_put(BtreeNodePtr my_node, homeds::thread::locktype curlock,
                const BtreeKey &k, const BtreeValue &v, int ind_hint,
                PutType put_type, std::deque<boost::intrusive_ptr<btree_req_type>> &dependent_req_q,
                boost::intrusive_ptr<btree_req_type> cookie,
                BtreeValue &existing_val,
                boost::intrusive_ptr<btree_multinode_req> multinode_req,
                BtreeUpdateRequest<K, V> *bur = nullptr) {

        if (my_node->is_leaf()) {
            assert(curlock == LOCKTYPE_WRITE);
            if (bur != nullptr) {
                assert(bur->callback() != nullptr); // TODO - range req without callback implementation
                std::vector< std::pair< K, V > > match;
                int                              start_ind = 0, end_ind = 0;
                my_node->get_all(bur->get_input_range(), UINT32_MAX, start_ind, end_ind, &match);

                vector< pair< K, V > > replace_kv;
                bur->callback()(match, replace_kv, bur->get_cb_param());
                if (match.size() > 0 && start_ind <= end_ind)
                    my_node->remove(start_ind, end_ind);
                for (auto &pair : replace_kv) // insert is based on compare() of BtreeKey
                    my_node->insert(pair.first, pair.second);
                multinode_req->writes_pending.fetch_add(1, std::memory_order_acq_rel);
            } else
                my_node->put(k, v, put_type, existing_val);

#ifndef NDEBUG
            //sorted check
            for(auto i=1u;i<my_node->get_total_entries();i++){
                K curKey, prevKey;
                my_node->get_nth_key(i-1,&prevKey,false);
                my_node->get_nth_key(i,&curKey,false);
                assert(prevKey.compare(&curKey)<=0);
            }
#endif
            btree_store_t::write_node(m_btree_store.get(), my_node, dependent_req_q, cookie, false, multinode_req);
            unlock_node(my_node, curlock);
            COUNTER_INCREMENT(m_metrics, btree_obj_count, 1);
            return true;
        }

        int start_ind = 0, end_ind = -1;
        if (bur != nullptr) // just get start/end index from get_all
            my_node->get_all(bur->get_input_range(), UINT32_MAX, start_ind, end_ind);
        else {
            bool          is_found = false;
            BtreeNodeInfo child_info;
            uint32_t      index = 0;
            get_child_node(my_node, BtreeSearchRange(k), &index, &is_found, &child_info);
            if (is_found) {
                start_ind = index;
                end_ind = index;
            }
        }
        if (start_ind > end_ind) {
            // Either the node was updated or mynode is freed. Just proceed again from top.
            unlock_node(my_node, curlock);
            return false;
        }

        bool unlocked_already = false;
        int  curr_ind = start_ind;
        bool is_any_child_splitted = false;
        while (curr_ind <= end_ind) { // iterate all matched childrens

        //retry:
            homeds::thread::locktype child_cur_lock = homeds::thread::LOCKTYPE_NONE;

            // Get the childPtr for given key.
            BtreeNodeInfo child_info;
            BtreeNodePtr  child_node = get_child_node(my_node, curr_ind, &child_info);
            if (child_node == nullptr) {
                // Either the node was updated or mynode is freed. Just proceed again from top.
                unlock_node(my_node, curlock);
                return false;
            }

            // Directly get write lock for leaf, since its an insert.
            child_cur_lock = (child_node->is_leaf()) ? LOCKTYPE_WRITE : LOCKTYPE_READ;
            lock_node(child_node, child_cur_lock, &dependent_req_q);

            if (child_info.bnode_id().m_pc_gen_flag != child_node->get_node_id().m_pc_gen_flag) {
                if (upgrade_node(child_node, nullptr, child_cur_lock, LOCKTYPE_NONE, dependent_req_q) == false) {
                    unlock_node(my_node, curlock);
                    unlock_node(child_node, child_cur_lock);
                    return (false); // retry from root
                }
                if (child_info.bnode_id().m_pc_gen_flag != child_node->get_node_id().m_pc_gen_flag) {//check again
                fix_pc_gen_mistmatch(my_node, child_node, curr_ind, &dependent_req_q);
                }
                unlock_node(child_node, homeds::thread::LOCKTYPE_WRITE);
                continue;
            }

            if (bur != nullptr) { // calculate subrange
                //find end of subrange
                bool end_inc = true;
                K end_key;
                BtreeKey *end_key_ptr = &end_key;
                if (curr_ind == (int) my_node->get_total_entries() && my_node->get_edge_id().is_valid()) {//edge
                    end_key_ptr = const_cast<BtreeKey *>(bur->get_input_range().get_end_key());
                    end_inc = bur->get_input_range().is_end_inclusive();
                } else
                    my_node->get_nth_key(curr_ind, end_key_ptr, false);

                const_cast<BtreeKey *>(bur->get_cb_param()->get_sub_range().get_end_key())->copy_blob(
                        end_key_ptr->get_blob());//copy
                bur->get_cb_param()->get_sub_range().set_end_incl(end_inc);

                //find start of subrange
                if (curr_ind > 0) {
                    K start_key;
                    my_node->get_nth_key(curr_ind - 1, &start_key, true);
                    const_cast<BtreeKey *>(bur->get_cb_param()->get_sub_range().get_start_key())->copy_blob(
                            start_key.get_blob());//copy
                    bur->get_cb_param()->get_sub_range().set_start_incl(false);
                }//else no need to update, we carry fwd with start value from parent

                DLOGDEBUGMOD(btree_structures,
                         "Subrange:s:{},e:{},c:{},nid:{},eidvalid?:{},sk:{},ek:{}", start_ind, end_ind, curr_ind,
                          my_node->get_node_id().to_string(), my_node->get_edge_id().is_valid(),
                          bur->get_cb_param()->get_sub_range().get_start_key()->to_string(),
                          bur->get_cb_param()->get_sub_range().get_end_key()->to_string());
            }

            if (child_node->is_split_needed(m_btree_cfg, k, v, &ind_hint, put_type, bur)) {
                if(bur && is_any_child_splitted) { // spliting another child
                    if(my_node->is_split_needed(m_btree_cfg, k, v, &ind_hint, put_type, bur)){
#if 0
                        if(curr_ind!=0){
                            K resume_range_st_key;
                            my_node->get_nth_key(curr_ind-1,&resume_range_st_key, true);//get prev key
                            const_cast<BtreeKey *>(bur->get_input_range().get_start_key())->copy_blob(
                                    resume_range_st_key.get_blob());
                            bur->get_input_range().set_start_incl(false);
                        }// in case curr_ind==0, and my node wants to split, we contine with inherited start
#endif
                        //restart from root
                        unlock_node(child_node, child_cur_lock);
                        unlock_node(my_node, curlock);
                        return (false);
                    }
                    btree_store_t::refresh_node(m_btree_store.get(), my_node, true, &dependent_req_q);
                }
                // Time to split the child, but we need to convert ours to write lock
                if (upgrade_node(my_node, child_node, curlock, child_cur_lock, dependent_req_q) == false) {
                    LOGDEBUGMOD(btree_structures, "Upgrade of lock for node {} failed, retrying from root",
                            my_node->get_node_id_int());
                    return (false);
                }

                // We need to upgrade the child to WriteLock
                if (upgrade_node(child_node, nullptr, child_cur_lock, LOCKTYPE_NONE, dependent_req_q) == false) {
                    // Since we have parent node write locked, child node should never have any issues upgrading.
                    LOGDFATAL_IF(true, "Upgrade of lock for childnode {} failed, which is not expected, will retry "
                                       "from root", child_node->get_node_id_int());
                    unlock_node(my_node, homeds::thread::LOCKTYPE_WRITE);
                    return (false);
                }

                // Real time to split the node and get point at which it was split
                K split_key;
                split_node(my_node, child_node, curr_ind, &split_key, dependent_req_q);
                ind_hint = -1; // Since split is needed, hint is no longer valid

                if (split_key.compare(&k) < 0){//skip processing of left node after split
                    assert(curr_ind==start_ind);//only possible for start of range
                    curr_ind++;
                }
                if(bur) { end_ind++; }     // range update - we update endind regardless on split
                else { end_ind=curr_ind; } // regular update - end moves with curr

                // After split, parentNode would have split, retry search and walk down.
                unlock_node(child_node, homeds::thread::LOCKTYPE_WRITE);
                COUNTER_INCREMENT(m_metrics, btree_split_count, 1);

                is_any_child_splitted=true;
                continue;
            }

            if (curr_ind == end_ind) {
                // If we have reached the last index, unlock before traversing down, because we no longer need
                // this lock. Holding this lock will impact performance unncessarily.
                unlock_node(my_node, curlock);
                unlocked_already = true;
            }

            bool success = do_put(child_node, child_cur_lock, k, v, ind_hint, put_type,
                                  dependent_req_q, cookie, existing_val, multinode_req, bur);

            if (success == false) {
                if (!unlocked_already)
                    unlock_node(my_node, curlock);
                return false;
            }
            if(bur){//savepoint of range
                // update original input range
                // cb gets cb->input range for manipulation
                const_cast<BtreeKey *>(bur->get_input_range().get_start_key())->copy_blob(
                        const_cast<BtreeKey *>(bur->get_cb_param()->get_sub_range().get_end_key())->get_blob());//copy
                bur->get_input_range().set_start_incl(false);
            }
            curr_ind++;
        }
        if (!unlocked_already) {
            unlock_node(my_node, curlock);
        }
        return true;
        // Warning: Do not access childNode or myNode beyond this point, since it would
        // have been unlocked by the recursive function and it could also been deleted.
    }

    btree_status_t do_remove(BtreeNodePtr my_node, homeds::thread::locktype curlock, const BtreeSearchRange& range,
                             BtreeKey* outkey, BtreeValue* outval,
                             std::deque< boost::intrusive_ptr< btree_req_type > >& dependent_req_q,
                             boost::intrusive_ptr< btree_req_type >                cookie) {
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
                btree_store_t::write_node(m_btree_store.get(), my_node, dependent_req_q, cookie, false);
                COUNTER_DECREMENT(m_metrics, btree_obj_count, 1);
            } else {
#ifndef NDEBUG
                // my_node->to_string();
#endif
            }

            unlock_node(my_node, curlock);
            return is_found ? BTREE_ITEM_FOUND : BTREE_NOT_FOUND;
        }

    retry:
        locktype child_cur_lock = LOCKTYPE_NONE;

        // Get the childPtr for given key.
        uint32_t ind;

        bool          is_found = true;
        BtreeNodeInfo child_info;
        BtreeNodePtr  child_node = get_child_node(my_node, range, &ind, &is_found, &child_info, true);
        if (!is_found || (child_node == nullptr)) {
            unlock_node(my_node, curlock);
            return BTREE_NOT_FOUND;
        }

        // Directly get write lock for leaf, since its a delete.
        child_cur_lock = (child_node->is_leaf()) ? LOCKTYPE_WRITE : LOCKTYPE_READ;
        lock_node(child_node, child_cur_lock, &dependent_req_q);

        // If my child info does not match actual child node's info internally, fix them
        if (child_info.bnode_id().m_pc_gen_flag != child_node->get_node_id().m_pc_gen_flag) {
            if (upgrade_node(child_node, nullptr, child_cur_lock, LOCKTYPE_NONE, dependent_req_q) == false) {
                unlock_node(child_node, child_cur_lock);
                unlock_node(my_node, curlock);
                return BTREE_RETRY;
            }
            fix_pc_gen_mistmatch(my_node, child_node, ind, &dependent_req_q);
            unlock_node(child_node, homeds::thread::LOCKTYPE_WRITE);
            goto retry;
        }

        // Check if child node is minimal.
        if (child_node->is_merge_needed(m_btree_cfg)) {
            // If we are unable to upgrade the node, ask the caller to retry.
            if (upgrade_node(my_node, child_node, curlock, child_cur_lock, dependent_req_q) == false) {
                return BTREE_RETRY;
            }

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
                auto result = merge_nodes(my_node, indices_list, dependent_req_q);
                if (result.merged) {
                    // Retry only if we merge them.
                    // release_node(child_node);
                    COUNTER_INCREMENT(m_metrics, btree_merge_count, 1);
                    goto retry;
                } else {
                    lock_node(child_node, child_cur_lock, &dependent_req_q);
                }
            }
        }

        unlock_node(my_node, curlock);
        return (do_remove(child_node, child_cur_lock, range, outkey, outval, dependent_req_q, cookie));

        // Warning: Do not access childNode or myNode beyond this point, since it would
        // have been unlocked by the recursive function and it could also been deleted.
    }

    void check_split_root(const BtreeKey& k, const BtreeValue& v,
                          std::deque< boost::intrusive_ptr< btree_req_type > >& dependent_req_q, PutType& putType,
                          BtreeUpdateRequest< K, V >* bur = nullptr) {
        int          ind;
        K            split_key;
        BtreeNodePtr child_node = nullptr;

        m_btree_lock.write_lock();
        BtreeNodePtr root = btree_store_t::read_node(m_btree_store.get(), m_root_node);
        lock_node(root, locktype::LOCKTYPE_WRITE, &dependent_req_q);

        if (!root->is_split_needed(m_btree_cfg, k, v, &ind, putType, bur)) {
            unlock_node(root, homeds::thread::LOCKTYPE_WRITE);
            goto done;
        }

        // Create a new child node and split them
        child_node = alloc_interior_node();

        /* it swap the data while keeping the nodeid same */
        btree_store_t::swap_node(m_btree_store.get(), root, child_node);
        btree_store_t::write_node(m_btree_store.get(), child_node, dependent_req_q, NULL, false);

        LOGDEBUGMOD(btree_structures, "Root node: {} is full, swapping contents to child_node {} and split that",
                root->get_node_id_int(), child_node->get_node_id_int());

        /* Reading a node again to get the latest buffer from writeback cache. We are going
         * to write this node again in split node. We can not have two consecutive writes on the
         * same buffer without reading in between because we have to update the dependent
         * req_q and underneath buffer from the writeback cache layer. Since it is a new node
         * we can safely say that write lock is taking without actually taking it because no
         * body can acccess this child node.
         */
        btree_store_t::refresh_node(m_btree_store.get(), child_node, true, &dependent_req_q);

        assert(root->get_total_entries() == 0);
        split_node(root, child_node, root->get_total_entries(), &split_key, dependent_req_q);
        /* unlock child node */
        assert(m_root_node == root->get_node_id());
        unlock_node(root, homeds::thread::LOCKTYPE_WRITE);

    done:
        m_btree_lock.unlock();
    }

    void check_collapse_root(std::deque< boost::intrusive_ptr< btree_req_type > >& dependent_req_q) {
        BtreeNodePtr child_node = nullptr;

        m_btree_lock.write_lock();
        BtreeNodePtr root = btree_store_t::read_node(m_btree_store.get(), m_root_node);
        lock_node(root, locktype::LOCKTYPE_WRITE, &dependent_req_q);

        if (root->get_total_entries() != 0) {
            unlock_node(root, locktype::LOCKTYPE_WRITE);
            goto done;
        }

        assert(root->get_edge_id().is_valid());
        child_node = btree_store_t::read_node(m_btree_store.get(), root->get_edge_id());
        assert(child_node != nullptr);

        btree_store_t::swap_node(m_btree_store.get(), root, child_node);
        btree_store_t::write_node(m_btree_store.get(), root, dependent_req_q, NULL, false);
        // Elevate the edge child as root.
        unlock_node(root, locktype::LOCKTYPE_WRITE);
        assert(m_root_node == root->get_node_id());
        free_node(child_node, dependent_req_q);

        // release_node(child_node);
    done:
        m_btree_lock.unlock();
    }

    // requires read/write lock on parent_node and requires write lock on child_node1 before calling this func
    void fix_pc_gen_mistmatch(BtreeNodePtr parent_node, BtreeNodePtr child_node1, uint32_t parent_ind,
                              std::deque< boost::intrusive_ptr< btree_req_type > >* dependent_req_q) {

        DLOGTRACEMOD(btree_generics, "Before fix, parent: {}, child: {}", parent_node->get_node_id_int(),
                child_node1->get_node_id_int());

        vector< BtreeNodePtr > nodes_to_free;
        K                      parent_key;
        BtreeNodePtr           parent_sibbling = nullptr;
        bnodeid_t              sibbling_id;
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
                        old_sibbling = btree_store_t::read_node(m_btree_store.get(), child_node1->get_next_bnode());
                    } else if ((old_sibbling->get_total_entries() == 0) &&
                               (old_sibbling->get_next_bnode().is_valid())) {
                        old_sibbling = btree_store_t::read_node(m_btree_store.get(), old_sibbling->get_next_bnode());
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
                    parent_sibbling = btree_store_t::read_node(m_btree_store.get(), parent_node->get_next_bnode());
                    lock_node(parent_sibbling, locktype::LOCKTYPE_READ, dependent_req_q);
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
                curr = btree_store_t::read_node(m_btree_store.get(), next);
                child_node1->move_in_from_right_by_entries(m_btree_cfg, curr, curr->get_total_entries());
                nodes_to_free.push_back(curr);
                next = curr->get_next_bnode();
            }
            child_node1->set_next_bnode(bnodeid_t::empty_bnodeid());
        }

        // correct child version
        child_node1->flip_pc_gen_flag();

        /* we should synchronously try to recover this node. While recovery, if panic happen before
         * it is commited then we would have lost this node. Sync write should not depend on any dependent
         * requests.
         */
        std::deque<boost::intrusive_ptr<btree_req_type>> temp_dependent_req_q(0);
        btree_store_t::write_node(m_btree_store.get(), child_node1, temp_dependent_req_q, NULL, true);
        if (parent_sibbling != nullptr) {
            unlock_node(parent_sibbling, locktype::LOCKTYPE_READ);
        }

        for (int i = 0; i < (int)nodes_to_free.size(); i++) {
            free_node(nodes_to_free[i], *dependent_req_q);
        }

#ifndef NDEBUG
        if (parent_ind != parent_node->get_total_entries()) {
            K child_node1_last_key;
            child_node1->get_last_key(&child_node1_last_key);
            assert(child_node1_last_key.compare(&parent_key) == 0);
        }
#endif
    }

    void split_node(BtreeNodePtr parent_node, BtreeNodePtr child_node, uint32_t parent_ind, BtreeKey* out_split_key,
                    std::deque< boost::intrusive_ptr< btree_req_type > >& dependent_req_q) {
        BtreeNodeInfo ninfo;
        BtreeNodePtr child_node1 = child_node;
        BtreeNodePtr child_node2 = child_node1->is_leaf() ? alloc_leaf_node() : alloc_interior_node();

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

        if(parent_node->get_total_entries()!=0 && parent_ind!=parent_node->get_total_entries()) {
            //update child2 last key as parent key when parent has some entries(non-root) or split point is not edge
            K child2_last_key;
            child_node2->get_last_key(&child2_last_key);
            parent_node->set_nth_key(parent_ind, &child2_last_key);
        }

        // Insert the last entry in first child to parent node
        child_node1->get_last_key(out_split_key);
        ninfo.set_bnode_id(child_node1->get_node_id());
        parent_node->insert(*out_split_key, ninfo);

        LOGDEBUGMOD(btree_structures, "Split child_node={} with new_child_node={}, parent_node={}, split_key={}",
                child_node1->get_node_id_int(), child_node2->get_node_id_int(), parent_node->get_node_id_int(),
                out_split_key->to_string());

        // we write right child node, than parent and than left child
        btree_store_t::write_node(m_btree_store.get(), child_node2, dependent_req_q, NULL, false);
        btree_store_t::write_node(m_btree_store.get(), parent_node, dependent_req_q, NULL, false);
        btree_store_t::write_node(m_btree_store.get(), child_node1, dependent_req_q, nullptr, false);
        // NOTE: Do not access parentInd after insert, since insert would have
        // shifted parentNode to the right.
    }

    struct merge_info {
        BtreeNodePtr node;
        BtreeNodePtr node_orig;
        uint16_t  parent_index=0xFFFF;
        bool freed=false;
        bool is_new_allocation=false;
    };

    auto merge_nodes(BtreeNodePtr parent_node, std::vector< int >& indices_list,
                     std::deque< boost::intrusive_ptr< btree_req_type > >& dependent_req_q) {
        struct {
            bool     merged;  // Have we merged at all
            uint32_t nmerged; // If we merged, how many are the final result of nodes
        } ret{false, 0};

        std::vector< merge_info > minfo;
        BtreeNodeInfo             child_info;
        uint32_t                  ndeleted_nodes = 0;

        // Loop into all index and initialize list
        minfo.reserve(indices_list.size());
        for (auto i = 0u; i < indices_list.size(); i++) {
            parent_node->get(indices_list[i], &child_info, false /* copy */);
            merge_info m;

            m.node_orig = btree_store_t::read_node(m_btree_store.get(), child_info.bnode_id());
            assert(m.node_orig->is_valid_node());
            lock_node(m.node_orig, locktype::LOCKTYPE_WRITE, &dependent_req_q);
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

        // Rebalance entries for each of the node and mark any node to be removed, if empty.
        auto i = 0U;
        auto j = 1U;
        auto balanced_size = m_btree_cfg.get_ideal_fill_size();
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
                    j++;
                    continue;
                }
            }

            i = j++;
        }

        assert(!minfo[0].freed); // If we merge it, we expect the left most one has at least 1 entry.

        for (auto n = 0u; n < minfo.size(); n++) {
            if (!minfo[n].freed) {
                // lets get the last key and put in the entry into parent node
                BtreeNodeInfo ninfo(minfo[n].node->get_node_id());

                if (minfo[n].parent_index == parent_node->get_total_entries()) { //edge entrys
                    parent_node->update(minfo[n].parent_index, ninfo);
                } else {
                    K last_key;
                    minfo[n].node->get_last_key(&last_key);
                    parent_node->update(minfo[n].parent_index, last_key, ninfo);
                }

                if (n == 0) {
                    continue;
                } // skip first child commit
                btree_store_t::write_node(m_btree_store.get(), minfo[n].node, dependent_req_q, NULL, false);
            }
        }

        // Its time to write the parent node and loop again to write all nodes and free freed nodes
        btree_store_t::write_node(m_btree_store.get(), parent_node, dependent_req_q, NULL, false);

        ret.nmerged = minfo.size() - ndeleted_nodes;

        btree_store_t::write_node(m_btree_store.get(), minfo[0].node, dependent_req_q, NULL, false);
#ifndef NDEBUG
        validate_sanity(minfo,parent_node,indices_list);
#endif

        // Loop again in reverse order to unlock the nodes. freeable nodes need to be unlocked and freed
        for (int n = minfo.size() - 1; n >= 0; n--) {
            if (minfo[n].freed) {
                // free copied node if it became empty
                free_node(minfo[n].node, dependent_req_q);
            }
            // free original node except first
            if (n != 0 && minfo[n].is_new_allocation) {
                node_free_safely(minfo[n].node_orig, dependent_req_q);
            } else {
                unlock_node(minfo[n].node_orig, locktype::LOCKTYPE_WRITE);
            }
        }

        return ret;
    }

#ifndef NDEBUG
    void validate_sanity(std::vector< merge_info >& minfo, BtreeNodePtr parent_node, std::vector< int >& indices_list) {
        int          index_sub = indices_list[0];
        BtreeNodePtr prev = nullptr;
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

                if (minfo[i].node->get_total_entries() != 0) {
                    K last_key;
                    minfo[i].node->get_last_key(&last_key);

                    if (minfo[i].parent_index != parent_node->get_total_entries()) {
                        K parent_key;
                        parent_node->get_nth_key(minfo[i].parent_index, &parent_key, false);
                        assert(last_key.compare(&parent_key) == 0);
                    }
                }
                prev = minfo[i].node;
            }
        }
    }

#endif

    void node_free_safely(BtreeNodePtr node, std::deque< boost::intrusive_ptr< btree_req_type > >& dependent_req_q) {
        if (node->any_upgrade_waiters()) {
            LOGTRACE("Marking invalid:{}", node->get_node_id().to_string());
            node->set_valid_node(false);
            unlock_node(node, locktype::LOCKTYPE_WRITE);
        } else {
            unlock_node(node, locktype::LOCKTYPE_WRITE);
            free_node(node, dependent_req_q);
        }
    }

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

    void free_node(BtreeNodePtr& node, std::deque< boost::intrusive_ptr< btree_req_type > >& dependent_req_q) {
        LOGDEBUGMOD(btree_generics, "Free node-{}", node->get_node_id_int());

        COUNTER_DECREMENT_IF_ELSE(m_metrics, node->is_leaf(), btree_leaf_node_count, btree_int_node_count, 1);
        btree_store_t::free_node(m_btree_store.get(), node, dependent_req_q);
    }

    void lock_node(BtreeNodePtr node, homeds::thread::locktype type,
                   std::deque< boost::intrusive_ptr< btree_req_type > >* dependent_req_q) {
        node->lock(type);
        btree_store_t::refresh_node(m_btree_store.get(), node,
                                            ((type == locktype::LOCKTYPE_WRITE) ? true:false), dependent_req_q);
#ifndef NDEBUG
        inc_lock_debug(node, type);
#endif
    }

    void lock_node_upgrade(BtreeNodePtr node, std::deque< boost::intrusive_ptr< btree_req_type > >* dependent_req_q) {
        node->lock_upgrade();
        btree_store_t::refresh_node(m_btree_store.get(), node, true, dependent_req_q);
        node->lock_acknowledge();
    }

    void unlock_node(BtreeNodePtr node, homeds::thread::locktype type) {
        node->unlock(type);
#ifndef NDEBUG
        dec_check_lock_debug(node, type);
#endif
#if 0
        if (release) {
            release_node(node);
        }
#endif
    }

#ifndef NDEBUG
    static void init_lock_debug() {
        rd_locked_count = 0;
        wr_locked_count = 0;
    }

    static void check_lock_debug() {
        if (wr_locked_count != 0) {
            LOGERROR("There are {} write locks held on the exit of API", wr_locked_count);
            assert(0);
        }

        if (rd_locked_count != 0) {
            LOGERROR("There are {} read locks held on the exit of API", rd_locked_count);
            assert(0);
        }
    }

    static void inc_lock_debug(BtreeNodePtr node, locktype ltype) {
        if (ltype == LOCKTYPE_WRITE) {
            wr_locked_nodes[wr_locked_count++] = node.get();
        } else if (ltype == LOCKTYPE_READ) {
            rd_locked_nodes[rd_locked_count++] = node.get();
        }
        //        std::cout << "lock_node: node = " << (void *)node << " Locked count = " << locked_count << std::endl;
    }

    static void dec_check_lock_debug(BtreeNodePtr node, locktype ltype) {
        std::array< btree_node_t*, MAX_BTREE_DEPTH >* pnodes;
        int*                                          pcount;
        if (ltype == LOCKTYPE_WRITE) {
            pnodes = &wr_locked_nodes;
            pcount = &wr_locked_count;
        } else {
            pnodes = &rd_locked_nodes;
            pcount = &rd_locked_count;
        }

        // std::cout << "unlock_node: node = " << (void *)node << " Locked count = " << locked_count << std::endl;
        if (node == pnodes->at(*pcount - 1)) {
            (*pcount)--;
        } else if ((*pcount > 1) && (node == pnodes->at((*pcount) - 2))) {
            pnodes->at(*(pcount)-2) = pnodes->at((*pcount) - 1);
            (*pcount)--;
        } else {
            if (*pcount > 1) {
                LOGERROR("unlock_node: node = {} Locked count = {} Expecting nodes = {} or {}", (void*)node.get(),
                         (*pcount), (void*)pnodes->at(*(pcount)-1), (void*)pnodes->at(*(pcount)-2));
            } else {
                LOGERROR("unlock_node: node = {} Locked count = {} Expecting node = {}", (void*)node.get(), (*pcount),
                         (void*)pnodes->at(*(pcount)-1));
            }
            assert(0);
        }
    }
#endif

protected:
    void create_root_node() {
        std::deque< boost::intrusive_ptr< btree_req_type > > dependent_req_q;
        // Assign one node as root node and initially root is leaf
        BtreeNodePtr root = alloc_leaf_node();
        m_root_node = root->get_node_id();

        btree_store_t::write_node(m_btree_store.get(), root, dependent_req_q, NULL, true);
        m_sb.root_node = m_root_node;
    }

    BtreeConfig* get_config() { return &m_btree_cfg; }

#if 0
    void release_node(BtreeNodePtr node)
    {
        node->derefNode();
    }
#endif
};

#ifndef NDEBUG
template < btree_store_type BtreeStoreType, typename K, typename V, btree_node_type InteriorNodeType,
           btree_node_type LeafNodeType, size_t NodeSize, typename btree_req_type >
thread_local int btree_t::wr_locked_count = 0;

template < btree_store_type BtreeStoreType, typename K, typename V, btree_node_type InteriorNodeType,
           btree_node_type LeafNodeType, size_t NodeSize, typename btree_req_type >
thread_local std::array< btree_node_t*, MAX_BTREE_DEPTH > btree_t::wr_locked_nodes = {{}};

template < btree_store_type BtreeStoreType, typename K, typename V, btree_node_type InteriorNodeType,
           btree_node_type LeafNodeType, size_t NodeSize, typename btree_req_type >
thread_local int btree_t::rd_locked_count = 0;

template < btree_store_type BtreeStoreType, typename K, typename V, btree_node_type InteriorNodeType,
           btree_node_type LeafNodeType, size_t NodeSize, typename btree_req_type >
thread_local std::array< btree_node_t*, MAX_BTREE_DEPTH > btree_t::rd_locked_nodes = {{}};

#endif

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
