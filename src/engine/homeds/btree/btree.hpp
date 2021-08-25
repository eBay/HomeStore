/*
 *  Created on: 14-May-2016
 *      Author: Hari Kadayam
 *
 *  Copyright © 2016 Kadayam, Hari. All rights reserved.
 */
#pragma once

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <functional>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <boost/intrusive_ptr.hpp>
#include <fds/buffer.hpp>
#include <flip/flip.hpp>
#include <fmt/ostream.h>
#include <sds_logging/logging.h>

#include "engine/common/error.h"
#include "engine/common/homestore_config.hpp"
#include "engine/common/homestore_flip.hpp"
#include "engine/common/homestore_header.hpp"
#include "engine/homeds/array/reserve_vector.hpp"
#include "engine/homeds/thread/lock.hpp"

#include "btree_internal.h"
#include "btree_node.cpp"
#include "physical_node.hpp"

// need to remove these.  polluting scope in headers is a bad idea
using namespace std;
using namespace homeds::thread;
using namespace flip;

#ifndef NDEBUG
#define MAX_BTREE_DEPTH 100
#endif

SDS_LOGGING_DECL(btree_structures, btree_nodes, btree_generics)
namespace homestore {
extern bool vol_test_run;
}
namespace homeds {
namespace btree {

#if 0
#define container_of(ptr, type, member) ({ (type*)((char*)ptr - offsetof(type, member)); })
#endif

#define btree_t Btree< BtreeStoreType, K, V, InteriorNodeType, LeafNodeType >

template < btree_store_type BtreeStoreType, typename K, typename V, btree_node_type InteriorNodeType,
           btree_node_type LeafNodeType >
struct _btree_locked_node_info {
    btree_node_t* node;
    Clock::time_point start_time;
    const char* fname;
    int line;
    void dump() { LOGINFO("node locked by file: {}, line: {}", fname, line); }
};

#define btree_locked_node_info _btree_locked_node_info< BtreeStoreType, K, V, InteriorNodeType, LeafNodeType >

#define lock_and_refresh_node(a, b, c) _lock_and_refresh_node(a, b, c, __FILE__, __LINE__)
#define lock_node_upgrade(a, b) _lock_node_upgrade(a, b, __FILE__, __LINE__)
#define start_of_lock(a, b) _start_of_lock(a, b, __FILE__, __LINE__)

template < btree_store_type BtreeStoreType, typename K, typename V, btree_node_type InteriorNodeType,
           btree_node_type LeafNodeType >
class Btree {
    typedef std::function< void(V& mv) > free_blk_callback;
    typedef std::function< void() > destroy_btree_comp_callback;
    typedef std::function< void(const K& k, const V& v, const K& split_key,
                                std::vector< std::pair< K, V > >& replace_kv) >
        split_key_callback;

private:
    bnodeid_t m_root_node;
    homeds::thread::RWLock m_btree_lock;

    uint32_t m_max_nodes;
    BtreeConfig m_btree_cfg;
    btree_super_block m_sb;

    BtreeMetrics m_metrics;
    std::unique_ptr< btree_store_t > m_btree_store;
    bool m_destroy = false;
    std::atomic< uint64_t > m_total_nodes = 0;
    uint32_t m_node_size = 4096;
    btree_cp_sb m_last_cp_sb;
    split_key_callback m_split_key_cb;
#ifndef NDEBUG
    std::atomic< uint64_t > m_req_id = 0;
#endif

    static thread_local homeds::reserve_vector< btree_locked_node_info, 5 > wr_locked_nodes;
    static thread_local homeds::reserve_vector< btree_locked_node_info, 5 > rd_locked_nodes;

    ////////////////// Implementation /////////////////////////
public:
    btree_super_block get_btree_sb() { return m_sb; }
    const btree_cp_sb& get_last_cp_cb() const { return m_last_cp_sb; }

    /**
     * @brief : return the btree cfg
     *
     * @return : the btree cfg;
     */
    BtreeConfig get_btree_cfg() const { return m_btree_cfg; }

#ifdef _PRERELEASE
    static void set_io_flip() {
        /* IO flips */
        FlipClient* fc = homestore::HomeStoreFlip::client_instance();
        FlipFrequency freq;
        FlipCondition cond1;
        FlipCondition cond2;
        freq.set_count(2000000000);
        freq.set_percent(2);

        FlipCondition null_cond;
        fc->create_condition("", flip::Operator::DONT_CARE, (int)1, &null_cond);

        fc->create_condition("nuber of entries in a node", flip::Operator::EQUAL, 0, &cond1);
        fc->create_condition("nuber of entries in a node", flip::Operator::EQUAL, 1, &cond2);
        fc->inject_noreturn_flip("btree_upgrade_node_fail", {cond1, cond2}, freq);

        fc->create_condition("nuber of entries in a node", flip::Operator::EQUAL, 4, &cond1);
        fc->create_condition("nuber of entries in a node", flip::Operator::EQUAL, 2, &cond2);

        fc->inject_retval_flip("btree_delay_and_split", {cond1, cond2}, freq, 20);
        fc->inject_retval_flip("btree_delay_and_split_leaf", {cond1, cond2}, freq, 20);
        fc->inject_noreturn_flip("btree_parent_node_full", {null_cond}, freq);
        fc->inject_noreturn_flip("btree_leaf_node_split", {null_cond}, freq);
        fc->inject_retval_flip("btree_upgrade_delay", {null_cond}, freq, 20);
        fc->inject_retval_flip("writeBack_completion_req_delay_us", {null_cond}, freq, 20);
        fc->inject_noreturn_flip("btree_read_fast_path_not_possible", {null_cond}, freq);
    }

    static void set_error_flip() {
        /* error flips */
        FlipClient* fc = homestore::HomeStoreFlip::client_instance();
        FlipFrequency freq;
        freq.set_count(20);
        freq.set_percent(10);

        FlipCondition null_cond;
        fc->create_condition("", flip::Operator::DONT_CARE, (int)1, &null_cond);

        fc->inject_noreturn_flip("btree_read_fail", {null_cond}, freq);
        fc->inject_noreturn_flip("fixed_blkalloc_no_blks", {null_cond}, freq);
    }
#endif

    static btree_t* create_btree(BtreeConfig& cfg) {
        Btree* bt = new Btree(cfg);
        auto impl_ptr = btree_store_t::init_btree(bt, cfg);
        bt->m_btree_store = std::move(impl_ptr);
        btree_status_t ret = bt->init();
        if (ret != btree_status_t::success) {
            LOGERROR("btree create failed. error {} name {}", ret, cfg.get_name());
            delete (bt);
            return nullptr;
        }

        HS_SUBMOD_LOG(INFO, base, , "btree", cfg.get_name(), "New {} created: Node size {}", BtreeStoreType,
                      cfg.get_node_size());
        return bt;
    }

    static btree_t* create_btree(const btree_super_block& btree_sb, BtreeConfig& cfg, btree_cp_sb* cp_sb,
                                 const split_key_callback& split_key_cb) {
        Btree* bt = new Btree(cfg);
        auto impl_ptr = btree_store_t::init_btree(bt, cfg);
        bt->m_btree_store = std::move(impl_ptr);
        bt->init_recovery(btree_sb, cp_sb, split_key_cb);
        LOGINFO("btree recovered and created {}, node size {}", cfg.get_name(), cfg.get_node_size());
        return bt;
    }

    void do_common_init(bool is_recovery = false) {
        // TODO: Check if node_area_size need to include persistent header
        uint32_t node_area_size = btree_store_t::get_node_area_size(m_btree_store.get());
        m_btree_cfg.set_node_area_size(node_area_size);

        // calculate number of nodes
        uint32_t max_leaf_nodes =
            (m_btree_cfg.get_max_objs() * (m_btree_cfg.get_max_key_size() + m_btree_cfg.get_max_value_size())) /
                node_area_size +
            1;
        max_leaf_nodes += (100 * max_leaf_nodes) / 60; // Assume 60% btree full

        m_max_nodes = max_leaf_nodes + ((double)max_leaf_nodes * 0.05) + 1; // Assume 5% for interior nodes
        m_total_nodes = m_last_cp_sb.btree_size;
        btree_store_t::update_sb(m_btree_store.get(), m_sb, &m_last_cp_sb, is_recovery);
    }

    void replay_done(const btree_cp_ptr& bcp) {
        m_total_nodes = m_last_cp_sb.btree_size + bcp->btree_size.load();
        THIS_BT_LOG(INFO, base, , "total btree nodes {}", m_total_nodes);
    }

    btree_status_t init() {
        do_common_init();
        return (create_root_node());
    }

    void init_recovery(const btree_super_block& btree_sb, btree_cp_sb* cp_sb, const split_key_callback& split_key_cb) {
        m_sb = btree_sb;
        m_split_key_cb = split_key_cb;
        if (cp_sb) { memcpy(&m_last_cp_sb, cp_sb, sizeof(m_last_cp_sb)); }
        do_common_init(true);
        m_root_node = m_sb.root_node;
    }

    Btree(BtreeConfig& cfg) :
            m_btree_cfg(cfg), m_metrics(BtreeStoreType, cfg.get_name().c_str()), m_node_size(cfg.get_node_size()) {}

    ~Btree() {
        if (BtreeStoreType == btree_store_type::SSD_BTREE) {
            LOGINFO("Skipping destroy in-memory btree nodes for ssd_btree.");
            return;
        }

        uint64_t free_node_cnt;
        auto ret = destroy(nullptr, free_node_cnt, true);

        HS_DEBUG_ASSERT_EQ(ret, btree_status_t::success, "btree destroy failed");
        LOGWARN("Destroy in-memory btree nodes failed.");
    }

    /* It is called when its btree consumer has successfully stored the btree superblock */
    void create_done() { btree_store_t::create_done(m_btree_store.get(), m_root_node); }

    btree_status_t destroy(blkid_list_ptr free_blkid_list, uint64_t& free_node_cnt, bool in_mem = false) {
        btree_status_t ret{btree_status_t::success};
        m_btree_lock.write_lock();
        if (!m_destroy) { // if previous destroy is successful, do not destroy again;
            BtreeNodePtr root;
            homeds::thread::locktype acq_lock = LOCKTYPE_WRITE;

            ret = read_and_lock_root(m_root_node, root, acq_lock, acq_lock, nullptr);
            if (ret != btree_status_t::success) {
                m_btree_lock.unlock();
                return ret;
            }

            free_node_cnt = 0;
            ret = free(root, free_blkid_list, in_mem, free_node_cnt);

            unlock_node(root, acq_lock);

            if (ret == btree_status_t::success) {
                THIS_BT_LOG(DEBUG, base, , "btree(root: {})  nodes destroyed successfully", m_root_node);
                m_destroy = true;
            } else {
                THIS_BT_LOG(ERROR, base, , "btree(root: {}) nodes destroyed failed, ret: {}", m_root_node, ret);
            }
        }
        m_btree_lock.unlock();
        return ret;
    }

    //
    // 1. free nodes in post order traversal of tree to free non-leaf node
    //
    btree_status_t free(BtreeNodePtr node, blkid_list_ptr free_blkid_list, bool in_mem, uint64_t& free_node_cnt) {
        // TODO - this calls free node on mem_tree and ssd_tree.
        // In ssd_tree we free actual block id, which is not correct behavior
        // we shouldnt really free any blocks on free node, just reclaim any memory
        // occupied by ssd_tree structure in memory. Ideally we should have sepearte
        // api like deleteNode which should be called instead of freeNode
        homeds::thread::locktype acq_lock = homeds::thread::LOCKTYPE_WRITE;
        uint32_t i = 0;
        btree_status_t ret = btree_status_t::success;

        if (!node->is_leaf()) {
            BtreeNodeInfo child_info;
            while (i <= node->get_total_entries()) {
                if (i == node->get_total_entries()) {
                    if (!node->has_valid_edge()) { break; }
                    child_info.set_bnode_id(node->get_edge_id());
                } else {
                    node->get(i, &child_info, false /* copy */);
                }

                BtreeNodePtr child;
                ret = read_and_lock_child(child_info.bnode_id(), child, node, i, acq_lock, acq_lock, nullptr);
                if (ret != btree_status_t::success) { return ret; }
                ret = free(child, free_blkid_list, in_mem, free_node_cnt);
                unlock_node(child, acq_lock);
                i++;
            }
        }

        if (ret != btree_status_t::success) { return ret; }
        free_node(node, free_blkid_list, in_mem);
        ++free_node_cnt;
        return ret;
    }

    /* It attaches the new CP and prepare for cur cp flush */
    btree_cp_ptr attach_prepare_cp(const btree_cp_ptr& cur_bcp, bool is_last_cp, bool blkalloc_checkpoint) {
        return (btree_store_t::attach_prepare_cp(m_btree_store.get(), cur_bcp, is_last_cp, blkalloc_checkpoint));
    }

    void cp_start(const btree_cp_ptr& bcp, cp_comp_callback cb) {
        btree_store_t::cp_start(m_btree_store.get(), bcp, cb);
    }

    std::string get_cp_flush_status(const btree_cp_ptr& bcp) {
        return (btree_store_t::get_cp_flush_status(m_btree_store.get(), bcp));
    }

    void truncate(const btree_cp_ptr& bcp) { btree_store_t::truncate(m_btree_store.get(), bcp); }

    void destroy_done() { btree_store_t::destroy_done(m_btree_store.get()); }

    /* It is called before superblock is persisted for each CP */
    void update_btree_cp_sb(const btree_cp_ptr& bcp, btree_cp_sb& btree_sb, bool is_blkalloc_cp) {
        btree_sb.active_seqid = bcp->end_seqid;
        btree_sb.blkalloc_cp_id = is_blkalloc_cp ? bcp->cp_id : m_last_cp_sb.blkalloc_cp_id;
        btree_sb.btree_size = bcp->btree_size.load() + m_last_cp_sb.btree_size;
        btree_sb.cp_id = bcp->cp_id;
        HS_ASSERT_CMP(DEBUG, (int64_t)m_last_cp_sb.cp_id, ==, (int64_t)bcp->cp_id - 1);
        memcpy(&m_last_cp_sb, &btree_sb, sizeof(m_last_cp_sb));
    }

    void flush_free_blks(const btree_cp_ptr& bcp, std::shared_ptr< homestore::blkalloc_cp >& ba_cp) {
        btree_store_t::flush_free_blks(m_btree_store.get(), bcp, ba_cp);
    }

    uint64_t get_used_size() const { return m_node_size * m_total_nodes.load(); }

    btree_status_t range_put(btree_put_type put_type, BtreeUpdateRequest< K, V >& bur, const btree_cp_ptr& bcp) {
        K k; // these key/values are not used. It takes key/value from update request
        V v;
        BtreeQueryCursor cur;
        bool reset_cur = false;
        if (!bur.get_input_range().is_cursor_valid()) {
            bur.get_input_range().set_cursor(&cur);
            reset_cur = true;
        }
        auto ret = put(k, v, put_type, &v, bcp, &bur);
        if (reset_cur) { bur.get_input_range().reset_cursor(); }
        return ret;
    }

    btree_status_t put(const BtreeKey& k, const BtreeValue& v, btree_put_type put_type) {
        V temp_v;
        return (put(k, v, put_type, &temp_v));
    }

    btree_status_t put(const BtreeKey& k, const BtreeValue& v, btree_put_type put_type, BtreeValue* existing_val,
                       const btree_cp_ptr& bcp = nullptr, BtreeUpdateRequest< K, V >* bur = nullptr) {
        COUNTER_INCREMENT(m_metrics, btree_write_ops_count, 1);
        homeds::thread::locktype acq_lock = homeds::thread::LOCKTYPE_READ;
        int ind = -1;
        bool is_leaf = false;

        // THIS_BT_LOG(INFO, base, , "Put called for key = {}, value = {}", k.to_string(), v.to_string());

        m_btree_lock.read_lock();

        btree_status_t ret = btree_status_t::success;
    retry:

        BT_LOG_ASSERT_CMP(rd_locked_nodes.size(), ==, 0, );
        BT_LOG_ASSERT_CMP(wr_locked_nodes.size(), ==, 0, );

        BtreeNodePtr root;
        ret = read_and_lock_root(m_root_node, root, acq_lock, acq_lock, bcp);
        if (ret != btree_status_t::success) { goto out; }
        is_leaf = root->is_leaf();

        if (root->is_split_needed(m_btree_cfg, k, v, &ind, put_type, bur)) {
            // Time to do the split of root.
            unlock_node(root, acq_lock);
            m_btree_lock.unlock();
            ret = check_split_root(k, v, put_type, bur, bcp);
            BT_LOG_ASSERT_CMP(rd_locked_nodes.size(), ==, 0, );
            BT_LOG_ASSERT_CMP(wr_locked_nodes.size(), ==, 0, );

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
            K subrange_start_key, subrange_end_key;
            bool start_incl = false, end_incl = false;
            if (bur) {
                bur->get_input_range().copy_start_end_blob(subrange_start_key, start_incl, subrange_end_key, end_incl);
            }
            BtreeSearchRange subrange(subrange_start_key, start_incl, subrange_end_key, end_incl);
            ret = do_put(root, acq_lock, k, v, ind, put_type, *existing_val, bur, bcp, subrange);
            if (ret == btree_status_t::retry) {
                // Need to start from top down again, since there is a race between 2 inserts or deletes.
                acq_lock = homeds::thread::LOCKTYPE_READ;
                THIS_BT_LOG(TRACE, btree_generics, , "retrying put operation");
                BT_LOG_ASSERT_CMP(rd_locked_nodes.size(), ==, 0, );
                BT_LOG_ASSERT_CMP(wr_locked_nodes.size(), ==, 0, );
                goto retry;
            }
        }

    out:
        m_btree_lock.unlock();
#ifndef NDEBUG
        check_lock_debug();
#endif
        if (ret != btree_status_t::success && ret != btree_status_t::fast_path_not_possible &&
            ret != btree_status_t::cp_mismatch) {
            THIS_BT_LOG(ERROR, base, , "btree put failed {}", ret);
            COUNTER_INCREMENT(m_metrics, write_err_cnt, 1);
        }

        return ret;
    }

    btree_status_t get(const BtreeKey& key, BtreeValue* outval) { return get(key, nullptr, outval); }

    btree_status_t get(const BtreeKey& key, BtreeKey* outkey, BtreeValue* outval) {
        return get_any(BtreeSearchRange(key), outkey, outval);
    }

    btree_status_t get_any(const BtreeSearchRange& range, BtreeKey* outkey, BtreeValue* outval) {
        btree_status_t ret = btree_status_t::success;
        bool is_found;

        m_btree_lock.read_lock();
        BtreeNodePtr root;

        ret = read_and_lock_root(m_root_node, root, LOCKTYPE_READ, LOCKTYPE_READ, nullptr);
        if (ret != btree_status_t::success) { goto out; }

        ret = do_get(root, range, outkey, outval);
    out:
        m_btree_lock.unlock();

        // TODO: Assert if key returned from do_get is same as key requested, incase of perfect match

#ifndef NDEBUG
        check_lock_debug();
#endif
        return ret;
    }

    btree_status_t query(BtreeQueryRequest< K, V >& query_req, std::vector< std::pair< K, V > >& out_values) {
        COUNTER_INCREMENT(m_metrics, btree_query_ops_count, 1);

        btree_status_t ret = btree_status_t::success;
        if (query_req.get_batch_size() == 0) { return ret; }

        /* set cursor if it is invalid. User is not interested in the cursor but we need it for internal logic */
        BtreeQueryCursor cur;
        bool reset_cur = false;
        if (!query_req.get_input_range().is_cursor_valid()) {
            query_req.get_input_range().set_cursor(&cur);
            reset_cur = true;
        }

        m_btree_lock.read_lock();
        BtreeNodePtr root = nullptr;
        ret = read_and_lock_root(m_root_node, root, LOCKTYPE_READ, LOCKTYPE_READ, nullptr);
        if (ret != btree_status_t::success) { goto out; }

        switch (query_req.query_type()) {
        case BtreeQueryType::SWEEP_NON_INTRUSIVE_PAGINATION_QUERY:
            ret = do_sweep_query(root, query_req, out_values);
            break;

        case BtreeQueryType::TREE_TRAVERSAL_QUERY:
            ret = do_traversal_query(root, query_req, out_values);
            break;

        default:
            unlock_node(root, homeds::thread::locktype::LOCKTYPE_READ);
            LOGERROR("Query type {} is not supported yet", query_req.query_type());
            break;
        }

        if ((query_req.query_type() == BtreeQueryType::SWEEP_NON_INTRUSIVE_PAGINATION_QUERY ||
             query_req.query_type() == BtreeQueryType::TREE_TRAVERSAL_QUERY) &&
            out_values.size() > 0) {

            /* if return is not success then set the cursor to last read. No need to set cursor if user is not
             * interested in it.
             */
            if (!reset_cur) {
                query_req.get_input_range().set_cursor_key(&out_values.back().first, ([](BtreeKey* key) {
                    K end_key;
                    end_key.copy_end_key_blob(key->get_blob());
                    return std::move(std::make_unique< K >(end_key));
                }));
            }

            /* check if we finished just at the last key */
            if (out_values.back().first.compare(query_req.get_input_range().get_end_key()) == 0) {
                ret = btree_status_t::success;
            }
        }

    out:
        m_btree_lock.unlock();
#ifndef NDEBUG
        check_lock_debug();
#endif
        if (ret != btree_status_t::success && ret != btree_status_t::has_more &&
            ret != btree_status_t::fast_path_not_possible) {
            THIS_BT_LOG(ERROR, base, , "btree get failed {}", ret);
            COUNTER_INCREMENT(m_metrics, query_err_cnt, 1);
        }
        if (reset_cur) { query_req.get_input_range().reset_cursor(); }
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
        if (ret != btree_status_t::success) { goto out; }

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

        m_btree_lock.read_lock();
        BtreeNodePtr node;
        btree_status_t ret;

        if (query_req.is_empty_cursor()) {
            // Initialize a new lock tracker and put inside the cursor.
            query_req.cursor().m_locked_nodes = std::make_unique< BtreeLockTrackerImpl >(this);

            BtreeNodePtr root;
            ret = read_and_lock_root(m_root_node, root, LOCKTYPE_READ, LOCKTYPE_READ, nullptr);
            if (ret != btree_status_t::success) { goto out; }
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
    btree_status_t remove_any(BtreeSearchRange& range, BtreeKey* outkey, BtreeValue* outval) {
        return (remove_any(range, outkey, outval, nullptr));
    }

    btree_status_t remove_any(BtreeSearchRange& range, BtreeKey* outkey, BtreeValue* outval, const btree_cp_ptr& bcp) {
        homeds::thread::locktype acq_lock = homeds::thread::locktype::LOCKTYPE_READ;
        bool is_found = false;
        bool is_leaf = false;
        /* set cursor if it is invalid. User is not interested in the cursor but we need it for internal logic */
        BtreeQueryCursor cur;
        bool reset_cur = false;
        if (!range.is_cursor_valid()) {
            range.set_cursor(&cur);
            reset_cur = true;
        }

        m_btree_lock.read_lock();

    retry:

        btree_status_t status = btree_status_t::success;

        BtreeNodePtr root;
        status = read_and_lock_root(m_root_node, root, acq_lock, acq_lock, bcp);
        if (status != btree_status_t::success) { goto out; }
        is_leaf = root->is_leaf();

        if (root->get_total_entries() == 0) {
            if (is_leaf) {
                // There are no entries in btree.
                unlock_node(root, acq_lock);
                status = btree_status_t::not_found;
                THIS_BT_LOG(DEBUG, base, root, "entry not found in btree");
                goto out;
            }
            BT_LOG_ASSERT(root->has_valid_edge(), root, "Invalid edge id");
            unlock_node(root, acq_lock);
            m_btree_lock.unlock();

            status = check_collapse_root(bcp);
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
            status = do_remove(root, acq_lock, range, outkey, outval, bcp);
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
        if (reset_cur) { range.reset_cursor(); }
        return status;
    }

    btree_status_t remove(const BtreeKey& key, BtreeValue* outval) { return (remove(key, outval, nullptr)); }

    btree_status_t remove(const BtreeKey& key, BtreeValue* outval, const btree_cp_ptr& bcp) {
        auto range = BtreeSearchRange(key);
        return remove_any(range, nullptr, outval, bcp);
    }

    /**
     * @brief : verify btree is consistent and no corruption;
     *
     * @param update_debug_bm : true or false;
     *
     * @return : true if btree is not corrupted.
     *           false if btree is corrupted;
     */
    bool verify_tree(bool update_debug_bm) {
        m_btree_lock.read_lock();
        bool ret = verify_node(m_root_node, nullptr, -1, update_debug_bm);
        m_btree_lock.unlock();

        return ret;
    }

    /**
     * @brief : get the status of this btree;
     *
     * @param log_level : verbosity level;
     *
     * @return : status in json form;
     */
    nlohmann::json get_status(const int log_level) {
        nlohmann::json j;
        return j;
    }

    void diff(Btree* other, uint32_t param, vector< pair< K, V > >* diff_kv) {
        std::vector< pair< K, V > > my_kvs, other_kvs;

        get_all_kvs(&my_kvs);
        other->get_all_kvs(&other_kvs);
        auto it1 = my_kvs.begin();
        auto it2 = other_kvs.begin();

        K k1, k2;
        V v1, v2;

        if (it1 != my_kvs.end()) {
            k1 = it1->first;
            v1 = it1->second;
        }
        if (it2 != other_kvs.end()) {
            k2 = it2->first;
            v2 = it2->second;
        }

        while ((it1 != my_kvs.end()) && (it2 != other_kvs.end())) {
            if (k1.preceeds(&k2)) {
                /* k1 preceeds k2 - push k1 and continue */
                diff_kv->emplace_back(make_pair(k1, v1));
                it1++;
                if (it1 == my_kvs.end()) { break; }
                k1 = it1->first;
                v1 = it1->second;
            } else if (k1.succeeds(&k2)) {
                /* k2 preceeds k1 - push k2 and continue */
                diff_kv->emplace_back(make_pair(k2, v2));
                it2++;
                if (it2 == other_kvs.end()) { break; }
                k2 = it2->first;
                v2 = it2->second;
            } else {
                /* k1 and k2 overlaps */
                std::vector< pair< K, V > > overlap_kvs;
                diff_read_next_t to_read = READ_BOTH;

                v1.get_overlap_diff_kvs(&k1, &v1, &k2, &v2, param, to_read, overlap_kvs);
                for (auto ovr_it = overlap_kvs.begin(); ovr_it != overlap_kvs.end(); ovr_it++) {
                    diff_kv->emplace_back(make_pair(ovr_it->first, ovr_it->second));
                }

                switch (to_read) {
                case READ_FIRST:
                    it1++;
                    if (it1 == my_kvs.end()) {
                        // Add k2,v2
                        diff_kv->emplace_back(make_pair(k2, v2));
                        it2++;
                        break;
                    }
                    k1 = it1->first;
                    v1 = it1->second;
                    break;

                case READ_SECOND:
                    it2++;
                    if (it2 == other_kvs.end()) {
                        diff_kv->emplace_back(make_pair(k1, v1));
                        it1++;
                        break;
                    }
                    k2 = it2->first;
                    v2 = it2->second;
                    break;

                case READ_BOTH:
                    /* No tail part */
                    it1++;
                    if (it1 == my_kvs.end()) { break; }
                    k1 = it1->first;
                    v1 = it1->second;
                    it2++;
                    if (it2 == my_kvs.end()) { break; }
                    k2 = it2->first;
                    v2 = it2->second;
                    break;

                default:
                    LOGERROR("ERROR: Getting Overlapping Diff KVS for {}:{}, {}:{}, to_read {}", k1, v1, k2, v2,
                             to_read);
                    /* skip both */
                    it1++;
                    if (it1 == my_kvs.end()) { break; }
                    k1 = it1->first;
                    v1 = it1->second;
                    it2++;
                    if (it2 == my_kvs.end()) { break; }
                    k2 = it2->first;
                    v2 = it2->second;
                    break;
                }
            }
        }

        while (it1 != my_kvs.end()) {
            diff_kv->emplace_back(make_pair(it1->first, it1->second));
            it1++;
        }

        while (it2 != other_kvs.end()) {
            diff_kv->emplace_back(make_pair(it2->first, it2->second));
            it2++;
        }
    }

    void merge(Btree* other, match_item_cb_t< K, V > merge_cb) {
        std::vector< pair< K, V > > other_kvs;

        other->get_all_kvs(&other_kvs);
        for (auto it = other_kvs.begin(); it != other_kvs.end(); it++) {
            K k = it->first;
            V v = it->second;
            BRangeCBParam local_param(k, v);
            K start(k.start(), 1), end(k.end(), 1);

            auto search_range = BtreeSearchRange(start, true, end, true);
            BtreeUpdateRequest< K, V > ureq(search_range, merge_cb, nullptr, (BRangeCBParam*)&local_param);
            range_put(k, v, btree_put_type::APPEND_IF_EXISTS_ELSE_INSERT, nullptr, nullptr, ureq);
        }
    }

    void get_all_kvs(std::vector< pair< K, V > >* kvs) {
        std::vector< BtreeNodePtr > leaves;

        get_leaf_nodes(&leaves);
        for (auto l : leaves) {
            l->get_all_kvs(kvs);
        }
    }

    uint64_t get_btree_node_cnt() {
        uint64_t cnt = 0;
        m_btree_lock.read_lock();
        /* increment it for root */
        cnt++;
        get_child_node_cnt(m_root_node, cnt);
        m_btree_lock.unlock();
        return cnt;
    }

    void get_child_node_cnt(bnodeid_t bnodeid, uint64_t& cnt) {
        BtreeNodePtr node;

        homeds::thread::locktype acq_lock = homeds::thread::locktype::LOCKTYPE_READ;

        if (read_and_lock_node(bnodeid, node, acq_lock, acq_lock, nullptr) != btree_status_t::success) { return; }

        if (!node->is_leaf()) {
            uint32_t i = 0;
            while (i < node->get_total_entries()) {
                BtreeNodeInfo p;
                node->get(i, &p, false);
                get_child_node_cnt(p.bnode_id(), cnt);
                i++;
                cnt++;
            }
            if (node->has_valid_edge()) {
                get_child_node_cnt(node->get_edge_id(), cnt);
                cnt++;
            }
        }
        unlock_node(node, acq_lock);
    }

    void print_tree() {
        std::string buf;
        m_btree_lock.read_lock();
        to_string(m_root_node, buf);
        m_btree_lock.unlock();

        THIS_BT_LOG(INFO, base, , "Pre order traversal of tree:\n<{}>", buf);
    }

    void print_node(const bnodeid_t& bnodeid) {
        std::string buf;
        BtreeNodePtr node;

        m_btree_lock.read_lock();
        homeds::thread::locktype acq_lock = homeds::thread::locktype::LOCKTYPE_READ;
        if (read_and_lock_node(bnodeid, node, acq_lock, acq_lock, nullptr) != btree_status_t::success) { goto done; }
        buf = node->to_string(true /* print_friendly */);
        unlock_node(node, acq_lock);

    done:
        m_btree_lock.unlock();

        THIS_BT_LOG(INFO, base, , "Node: <{}>", buf);
    }

    nlohmann::json get_metrics_in_json(bool updated = true) { return m_metrics.get_result_in_json(updated); }

private:
    /**
     * @brief : verify the btree node is corrupted or not;
     *
     * Note: this function should never assert, but only return success or failure since it is in verification mode;
     *
     * @param bnodeid : node id
     * @param parent_node : parent node ptr
     * @param indx : index within thie node;
     * @param update_debug_bm : true or false;
     *
     * @return : true if this node including all its children are not corrupted;
     *           false if not;
     */
    bool verify_node(bnodeid_t bnodeid, BtreeNodePtr parent_node, uint32_t indx, bool update_debug_bm) {
        homeds::thread::locktype acq_lock = homeds::thread::locktype::LOCKTYPE_READ;
        BtreeNodePtr my_node;
        if (read_and_lock_node(bnodeid, my_node, acq_lock, acq_lock, nullptr) != btree_status_t::success) {
            LOGINFO("read node failed");
            return false;
        }
        if (update_debug_bm &&
            (btree_store_t::update_debug_bm(m_btree_store.get(), my_node) != btree_status_t::success)) {
            LOGERROR("bitmap update failed for node {}", my_node->to_string());
            return false;
        }

        K prev_key;
        bool success = true;
        for (uint32_t i = 0; i < my_node->get_total_entries(); ++i) {
            K key;
            my_node->get_nth_key(i, &key, false);
            if (!my_node->is_leaf()) {
                BtreeNodeInfo child;
                my_node->get(i, &child, false);
                success = verify_node(child.bnode_id(), my_node, i, update_debug_bm);
                if (!success) { goto exit_on_error; }

                if (i > 0) {
                    BT_LOG_ASSERT_CMP(prev_key.compare(&key), <, 0, my_node);
                    if (prev_key.compare(&key) >= 0) {
                        success = false;
                        goto exit_on_error;
                    }
                }
            }
            if (my_node->is_leaf() && i > 0) {
                BT_LOG_ASSERT_CMP(prev_key.compare_start(&key), <, 0, my_node);
                if (prev_key.compare_start(&key) >= 0) {
                    success = false;
                    goto exit_on_error;
                }
            }
            prev_key = key;
        }

        if (my_node->is_leaf() && my_node->get_total_entries() == 0) {
            /* this node has zero entries */
            goto exit_on_error;
        }
        if (parent_node && parent_node->get_total_entries() != indx) {
            K parent_key;
            parent_node->get_nth_key(indx, &parent_key, false);

            K last_key;
            my_node->get_nth_key(my_node->get_total_entries() - 1, &last_key, false);
            if (!my_node->is_leaf()) {
                BT_LOG_ASSERT_CMP(last_key.compare(&parent_key), ==, 0, parent_node,
                                  "last key {} parent_key {} child {}", last_key.to_string(), parent_key.to_string(),
                                  my_node->to_string());
                if (last_key.compare(&parent_key) != 0) {
                    success = false;
                    goto exit_on_error;
                }
            } else {
                BT_LOG_ASSERT_CMP(last_key.compare(&parent_key), <=, 0, parent_node,
                                  "last key {} parent_key {} child {}", last_key.to_string(), parent_key.to_string(),
                                  my_node->to_string());
                if (last_key.compare(&parent_key) > 0) {
                    success = false;
                    goto exit_on_error;
                }
                BT_LOG_ASSERT_CMP(parent_key.compare_start(&last_key), >=, 0, parent_node,
                                  "last key {} parent_key {} child {}", last_key.to_string(), parent_key.to_string(),
                                  my_node->to_string());
                if (parent_key.compare_start(&last_key) < 0) {
                    success = false;
                    goto exit_on_error;
                }
            }
        }

        if (parent_node && indx != 0) {
            K parent_key;
            parent_node->get_nth_key(indx - 1, &parent_key, false);

            K first_key;
            my_node->get_nth_key(0, &first_key, false);
            BT_LOG_ASSERT_CMP(first_key.compare(&parent_key), >, 0, parent_node, "my node {}", my_node->to_string());
            if (first_key.compare(&parent_key) <= 0) {
                success = false;
                goto exit_on_error;
            }

            BT_LOG_ASSERT_CMP(parent_key.compare_start(&first_key), <, 0, parent_node, "my node {}",
                              my_node->to_string());
            if (parent_key.compare_start(&first_key) > 0) {
                success = false;
                goto exit_on_error;
            }
        }

        if (my_node->has_valid_edge()) {
            success = verify_node(my_node->get_edge_id(), my_node, my_node->get_total_entries(), update_debug_bm);
            if (!success) { goto exit_on_error; }
        }

    exit_on_error:
        unlock_node(my_node, acq_lock);
        return success;
    }

    void to_string(bnodeid_t bnodeid, std::string& buf) {
        BtreeNodePtr node;

        homeds::thread::locktype acq_lock = homeds::thread::locktype::LOCKTYPE_READ;

        if (read_and_lock_node(bnodeid, node, acq_lock, acq_lock, nullptr) != btree_status_t::success) { return; }
        fmt::format_to(std::back_inserter(buf), "{}\n", node->to_string(true /* print_friendly */));

        if (!node->is_leaf()) {
            uint32_t i = 0;
            while (i < node->get_total_entries()) {
                BtreeNodeInfo p;
                node->get(i, &p, false);
                to_string(p.bnode_id(), buf);
                i++;
            }
            if (node->has_valid_edge()) { to_string(node->get_edge_id(), buf); }
        }
        unlock_node(node, acq_lock);
    }

    /*
     * Get all leaf nodes from the read-only tree (CP tree, Snap Tree etc)
     * NOTE: Doesn't take any lock
     */
    void get_leaf_nodes(std::vector< BtreeNodePtr >* leaves) {
        /* TODO: Add a flag to indicate RO tree
         * TODO: Check the flag here
         */
        get_leaf_nodes(m_root_node, leaves);
    }

    // TODO: Remove the locks once we have RO flags
    void get_leaf_nodes(bnodeid_t bnodeid, std::vector< BtreeNodePtr >* leaves) {
        BtreeNodePtr node;

        if (read_and_lock_node(bnodeid, node, LOCKTYPE_READ, LOCKTYPE_READ, nullptr) != btree_status_t::success) {
            return;
        }

        if (node->is_leaf()) {
            BtreeNodePtr next_node = nullptr;
            leaves->push_back(node);
            while (node->get_next_bnode() != empty_bnodeid) {
                auto ret =
                    read_and_lock_sibling(node->get_next_bnode(), next_node, LOCKTYPE_READ, LOCKTYPE_READ, nullptr);
                unlock_node(node, LOCKTYPE_READ);
                HS_ASSERT_CMP(DEBUG, ret, ==, btree_status_t::success);
                if (ret != btree_status_t::success) {
                    LOGERROR("Cannot read sibling node for {}", node);
                    return;
                }
                HS_ASSERT_CMP(DEBUG, next_node->is_leaf(), ==, true);
                leaves->push_back(next_node);
                node = next_node;
            }
            unlock_node(node, LOCKTYPE_READ);
            return;
        }

        HS_ASSERT_CMP(DEBUG, node->get_total_entries(), >, 0);
        if (node->get_total_entries() > 0) {
            BtreeNodeInfo p;
            node->get(0, &p, false);
            // XXX If we cannot get rid of locks, lock child and release parent here
            get_leaf_nodes(p.bnode_id(), leaves);
        }
        unlock_node(node, LOCKTYPE_READ);
    }

    btree_status_t do_get(const BtreeNodePtr& my_node, const BtreeSearchRange& range, BtreeKey* outkey,
                          BtreeValue* outval) {
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
        auto result = my_node->find(range, nullptr, &child_info);
        ASSERT_IS_VALID_INTERIOR_CHILD_INDX(result, my_node);

        BtreeNodePtr child_node;
        child_locktype = homeds::thread::LOCKTYPE_READ;
        ret = read_and_lock_child(child_info.bnode_id(), child_node, my_node, result.end_of_search_index,
                                  child_locktype, child_locktype, nullptr);
        if (ret != btree_status_t::success) { goto out; }

        unlock_node(my_node, homeds::thread::locktype::LOCKTYPE_READ);

        return (do_get(child_node, range, outkey, outval));
    out:
        unlock_node(my_node, homeds::thread::locktype::LOCKTYPE_READ);
        return ret;
    }

    btree_status_t do_sweep_query(BtreeNodePtr& my_node, BtreeQueryRequest< K, V >& query_req,
                                  std::vector< std::pair< K, V > >& out_values) {
        btree_status_t ret = btree_status_t::success;
        if (my_node->is_leaf()) {
            BT_DEBUG_ASSERT_CMP(query_req.get_batch_size(), >, 0, my_node);

            auto count = 0U;
            BtreeNodePtr next_node = nullptr;

            do {
                if (next_node) {
                    unlock_node(my_node, homeds::thread::locktype::LOCKTYPE_READ);
                    my_node = next_node;
                }

                THIS_BT_LOG(TRACE, btree_nodes, my_node, "Query leaf node:\n {}", my_node->to_string());

                int start_ind = 0, end_ind = 0;
                static thread_local std::vector< std::pair< K, V > > s_match_kv;

                s_match_kv.clear();
                auto cur_count = my_node->get_all(query_req.get_input_range(), query_req.get_batch_size() - count,
                                                  start_ind, end_ind, &s_match_kv);
                if (cur_count == 0) {
                    K key;
                    my_node->get_last_key(&key);
                    if (key.compare(query_req.get_input_range().get_end_key()) >= 0) {
                        // we've covered all lba range, we are done now;
                        break;
                    }
                }

                // fall through to visit siblings if we haven't covered lba range yet;

                if (cur_count) {
                    if (query_req.callback()) {
                        K subrange_start_key, subrange_end_key;
                        bool start_incl = false, end_incl = false;
                        query_req.get_input_range().copy_start_end_blob(subrange_start_key, start_incl,
                                                                        subrange_end_key, end_incl);

                        BtreeSearchRange subrange(subrange_start_key, start_incl, subrange_end_key, end_incl);
                        static thread_local std::vector< std::pair< K, V > > s_result_kv;

                        s_result_kv.clear();
                        query_req.get_cb_param()->node_version = my_node->get_version();
                        ret = query_req.callback()(s_match_kv, s_result_kv, query_req.get_cb_param(), subrange);

                        auto ele_to_add = s_result_kv.size();
                        if (count + ele_to_add > query_req.get_batch_size()) {
                            ele_to_add = query_req.get_batch_size() - count;
                        }
                        if (ele_to_add > 0) {
                            out_values.insert(out_values.end(), s_result_kv.begin(), s_result_kv.begin() + ele_to_add);
                        }
                        count += ele_to_add;
                        BT_DEBUG_ASSERT_CMP(count, <=, query_req.get_batch_size(), my_node);
                    } else {
                        out_values.insert(std::end(out_values), std::begin(s_match_kv), std::end(s_match_kv));
                        count += cur_count;
                    }
                }

                // if cur_count is 0, keep querying sibling nodes;

                if (ret == btree_status_t::success && (count < query_req.get_batch_size())) {
                    if (my_node->get_next_bnode() == empty_bnodeid) { break; }
                    ret = read_and_lock_sibling(my_node->get_next_bnode(), next_node, LOCKTYPE_READ, LOCKTYPE_READ,
                                                nullptr);
                    if (ret == btree_status_t::fast_path_not_possible) { break; }

                    if (ret != btree_status_t::success) {
                        LOGERROR("read failed btree name {}", m_btree_cfg.get_name());
                        break;
                    }
                } else {
                    if (count >= query_req.get_batch_size()) { ret = btree_status_t::has_more; }
                    break;
                }
            } while (true);

            unlock_node(my_node, homeds::thread::locktype::LOCKTYPE_READ);
            return ret;
        }

        BtreeNodeInfo start_child_info;
        auto result = my_node->find(query_req.get_input_range().get_start_of_range(), nullptr, &start_child_info);
        ASSERT_IS_VALID_INTERIOR_CHILD_INDX(result, my_node);

        BtreeNodePtr child_node;
        ret = read_and_lock_child(start_child_info.bnode_id(), child_node, my_node, result.end_of_search_index,
                                  LOCKTYPE_READ, LOCKTYPE_READ, nullptr);
        unlock_node(my_node, homeds::thread::locktype::LOCKTYPE_READ);
        if (ret != btree_status_t::success) { return ret; }
        return (do_sweep_query(child_node, query_req, out_values));
    }

    btree_status_t do_traversal_query(const BtreeNodePtr& my_node, BtreeQueryRequest< K, V >& query_req,
                                      std::vector< std::pair< K, V > >& out_values) {
        btree_status_t ret = btree_status_t::success;

        if (my_node->is_leaf()) {
            BT_LOG_ASSERT_CMP(query_req.get_batch_size(), >, 0, my_node);

            int start_ind = 0, end_ind = 0;
            static thread_local std::vector< std::pair< K, V > > s_match_kv;
            s_match_kv.clear();

            auto cur_count =
                my_node->get_all(query_req.get_input_range(), query_req.get_batch_size() - (uint32_t)out_values.size(),
                                 start_ind, end_ind, &s_match_kv);

            if (cur_count && query_req.callback()) {
                K subrange_start_key, subrange_end_key;
                static thread_local std::vector< std::pair< K, V > > s_result_kv;
                s_result_kv.clear();

                bool start_incl = false, end_incl = false;
                query_req.get_input_range().copy_start_end_blob(subrange_start_key, start_incl, subrange_end_key,
                                                                end_incl);

                BtreeSearchRange subrange(subrange_start_key, start_incl, subrange_end_key, end_incl);
                query_req.get_cb_param()->node_version = my_node->get_version();
                ret = query_req.callback()(s_match_kv, s_result_kv, query_req.get_cb_param(), subrange);

                auto ele_to_add = s_result_kv.size();
                if (ele_to_add > 0) {
                    out_values.insert(out_values.end(), s_result_kv.begin(), s_result_kv.begin() + ele_to_add);
                }
            }
            out_values.insert(std::end(out_values), std::begin(s_match_kv), std::end(s_match_kv));

            unlock_node(my_node, homeds::thread::locktype::LOCKTYPE_READ);
            if (ret != btree_status_t::success || out_values.size() >= query_req.get_batch_size()) {
                if (out_values.size() >= query_req.get_batch_size()) { ret = btree_status_t::has_more; }
            }

            return ret;
        }

        auto start_ret = my_node->find(query_req.get_input_range().get_start_of_range(), nullptr, nullptr);
        auto end_ret = my_node->find(query_req.get_input_range().get_end_of_range(), nullptr, nullptr);
        bool unlocked_already = false;
        int ind = -1;

        if (start_ret.end_of_search_index == (int)my_node->get_total_entries() && !(my_node->has_valid_edge())) {
            goto done; // no results found
        } else if (end_ret.end_of_search_index == (int)my_node->get_total_entries() && !(my_node->has_valid_edge())) {
            end_ret.end_of_search_index--; // end is not valid
        }

        BT_LOG_ASSERT_CMP(start_ret.end_of_search_index, <=, end_ret.end_of_search_index, my_node);
        ind = start_ret.end_of_search_index;

        while (ind <= end_ret.end_of_search_index) {
            BtreeNodeInfo child_info;
            my_node->get(ind, &child_info, false);
            BtreeNodePtr child_node = nullptr;
            homeds::thread::locktype child_cur_lock = homeds::thread::LOCKTYPE_READ;
            ret = read_and_lock_child(child_info.bnode_id(), child_node, my_node, ind, child_cur_lock, child_cur_lock,
                                      nullptr);
            if (ret != btree_status_t::success) { break; }

            if (ind == end_ret.end_of_search_index) {
                // If we have reached the last index, unlock before traversing down, because we no longer need
                // this lock. Holding this lock will impact performance unncessarily.
                unlock_node(my_node, homeds::thread::locktype::LOCKTYPE_READ);
                unlocked_already = true;
            }
            // TODO - pass sub range if child is leaf
            ret = do_traversal_query(child_node, query_req, out_values);
            if (ret == btree_status_t::has_more) { break; }
            ind++;
        }
    done:
        if (!unlocked_already) { unlock_node(my_node, homeds::thread::locktype::LOCKTYPE_READ); }

        return ret;
    }

#ifdef SERIALIZABLE_QUERY_IMPLEMENTATION
    btree_status_t do_serialzable_query(const BtreeNodePtr& my_node, BtreeSerializableQueryRequest& query_req,
                                        std::vector< std::pair< K, V > >& out_values) {

        btree_status_t ret = btree_status_t::success;
        if (my_node->is_leaf) {
            auto count = 0;
            auto start_result = my_node->find(query_req.get_start_of_range(), nullptr, nullptr);
            auto start_ind = start_result.end_of_search_index;

            auto end_result = my_node->find(query_req.get_end_of_range(), nullptr, nullptr);
            auto end_ind = end_result.end_of_search_index;
            if (!end_result.found) { end_ind--; } // not found entries will point to 1 ind after last in range.

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
        auto start_ret = my_node->find(query_req.get_start_of_range(), nullptr, &start_child_ptr);
        ASSERT_IS_VALID_INTERIOR_CHILD_INDX(start_ret, my_node);
        auto end_ret = my_node->find(query_req.get_end_of_range(), nullptr, &end_child_ptr);
        ASSERT_IS_VALID_INTERIOR_CHILD_INDX(end_ret, my_node);

        BtreeNodePtr child_node;
        if (start_ret.end_of_search_index == end_ret.end_of_search_index) {
            BT_LOG_ASSERT_CMP(start_child_ptr, ==, end_child_ptr, my_node);

            ret = read_and_lock_node(start_child_ptr.get_node_id(), child_node, LOCKTYPE_READ, LOCKTYPE_READ, nullptr);
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
                ret = read_and_lock_node(child_ptr.get_node_id(), child_node, LOCKTYPE_READ, LOCKTYPE_READ, nullptr);
                if (ret != btree_status_t::success) {
                    unlock_node(my_node, homeds::thread::locktype::LOCKTYPE_READ);
                    return ret;
                }

                get_tracker(query_req)->push(child_node);

                ret = do_serialzable_query(child_node, query_req, out_values);
                if (ret == BTREE_AGAIN) {
                    BT_LOG_ASSERT_CMP(out_values.size(), ==, query_req.get_batch_size(), );
                    break;
                }
            }

            if (ret == BTREE_SUCCESS) {
                unlock_node(my_node, homeds::thread::locktype::LOCKTYPE_READ);
                HS_ASSERT_CMP(DEBUG, get_tracker(query_req)->top(), ==, my_node);
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
    btree_status_t upgrade_node(const BtreeNodePtr& my_node, BtreeNodePtr child_node,
                                homeds::thread::locktype& cur_lock, homeds::thread::locktype& child_cur_lock,
                                const btree_cp_ptr& bcp) {
        uint64_t prev_gen;
        btree_status_t ret = btree_status_t::success;
        homeds::thread::locktype child_lock_type = child_cur_lock;

        if (cur_lock == homeds::thread::LOCKTYPE_WRITE) { goto done; }

        prev_gen = my_node->get_gen();
        if (child_node) {
            unlock_node(child_node, child_cur_lock);
            child_cur_lock = locktype::LOCKTYPE_NONE;
        }

#ifdef _PRERELEASE
        {
            auto time = homestore_flip->get_test_flip< uint64_t >("btree_upgrade_delay");
            if (time) { std::this_thread::sleep_for(std::chrono::microseconds{time.get()}); }
        }
#endif
        ret = lock_node_upgrade(my_node, bcp);
        if (ret != btree_status_t::success) {
            cur_lock = locktype::LOCKTYPE_NONE;
            return ret;
        }

        // The node was not changed by anyone else during upgrade.
        cur_lock = homeds::thread::LOCKTYPE_WRITE;

        // If the node has been made invalid (probably by mergeNodes) ask caller to start over again, but before
        // that cleanup or free this node if there is no one waiting.
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
            ret = lock_and_refresh_node(child_node, child_lock_type, bcp);
            if (ret != btree_status_t::success) {
                unlock_node(my_node, cur_lock);
                cur_lock = locktype::LOCKTYPE_NONE;
                child_cur_lock = locktype::LOCKTYPE_NONE;
                goto done;
            }
            child_cur_lock = child_lock_type;
        }

#ifdef _PRERELEASE
        {
            int is_leaf = 0;

            if (child_node && child_node->is_leaf()) { is_leaf = 1; }
            if (homestore_flip->test_flip("btree_upgrade_node_fail", is_leaf)) {
                unlock_node(my_node, cur_lock);
                cur_lock = locktype::LOCKTYPE_NONE;
                if (child_node) {
                    unlock_node(child_node, child_cur_lock);
                    child_cur_lock = locktype::LOCKTYPE_NONE;
                }
                ret = btree_status_t::retry;
                goto done;
            }
        }
#endif

        BT_DEBUG_ASSERT_CMP(my_node->m_common_header.is_lock, ==, 1, my_node);
    done:
        return ret;
    }

    btree_status_t update_leaf_node(const BtreeNodePtr& my_node, const BtreeKey& k, const BtreeValue& v,
                                    btree_put_type put_type, BtreeValue& existing_val, BtreeUpdateRequest< K, V >* bur,
                                    const btree_cp_ptr& bcp, BtreeSearchRange& subrange) {
        btree_status_t ret = btree_status_t::success;
        if (bur != nullptr) {
            // BT_DEBUG_ASSERT_CMP(bur->callback(), !=, nullptr, my_node); // TODO - range req without
            // callback implementation
            static thread_local std::vector< std::pair< K, V > > s_match;
            s_match.clear();
            int start_ind = 0, end_ind = 0;
            my_node->get_all(bur->get_input_range(), UINT32_MAX, start_ind, end_ind, &s_match);

            static thread_local std::vector< pair< K, V > > s_replace_kv;
            s_replace_kv.clear();
            bur->get_cb_param()->node_version = my_node->get_version();
            ret = bur->callback()(s_match, s_replace_kv, bur->get_cb_param(), subrange);
            if (ret != btree_status_t::success) { return ret; }

            HS_ASSERT_CMP(DEBUG, start_ind, <=, end_ind);
            if (s_match.size() > 0) { my_node->remove(start_ind, end_ind); }
            COUNTER_DECREMENT(m_metrics, btree_obj_count, s_match.size());

            for (const auto& pair : s_replace_kv) { // insert is based on compare() of BtreeKey
                auto status = my_node->insert(pair.first, pair.second);
                BT_RELEASE_ASSERT((status == btree_status_t::success), my_node, "unexpected insert failure");
                COUNTER_INCREMENT(m_metrics, btree_obj_count, 1);
            }

            /* update cursor in input range */
            auto end_key_ptr = const_cast< BtreeKey* >(subrange.get_end_key());
            bur->get_input_range().set_cursor_key(
                end_key_ptr, ([](BtreeKey* end_key) { return std::move(std::make_unique< K >(*((K*)end_key))); }));
            if (homestore::vol_test_run) {
                // sorted check
                for (auto i = 1u; i < my_node->get_total_entries(); i++) {
                    K curKey, prevKey;
                    my_node->get_nth_key(i - 1, &prevKey, false);
                    my_node->get_nth_key(i, &curKey, false);
                    if (prevKey.compare(&curKey) >= 0) {
                        LOGINFO("my_node {}", my_node->to_string());
                        for (const auto& [k, v] : s_match) {
                            LOGINFO("match key {} value {}", k.to_string(), v.to_string());
                        }
                        for (const auto& [k, v] : s_replace_kv) {
                            LOGINFO("replace key {} value {}", k.to_string(), v.to_string());
                        }
                    }
                    BT_RELEASE_ASSERT_CMP(prevKey.compare(&curKey), <, 0, my_node);
                }
            }
        } else {
            if (!my_node->put(k, v, put_type, existing_val)) { ret = btree_status_t::put_failed; }
            COUNTER_INCREMENT(m_metrics, btree_obj_count, 1);
        }

        write_node(my_node, bcp);
        return ret;
    }

    btree_status_t get_start_and_end_ind(const BtreeNodePtr& my_node, BtreeUpdateRequest< K, V >* bur,
                                         const BtreeKey& k, int& start_ind, int& end_ind) {

        btree_status_t ret = btree_status_t::success;
        if (bur != nullptr) {
            /* just get start/end index from get_all. We don't release the parent lock until this
             * key range is not inserted from start_ind to end_ind.
             */
            my_node->get_all(bur->get_input_range(), UINT32_MAX, start_ind, end_ind);
        } else {
            auto result = my_node->find(k, nullptr, nullptr, true, true);
            end_ind = start_ind = result.end_of_search_index;
            ASSERT_IS_VALID_INTERIOR_CHILD_INDX(result, my_node);
        }

        if (start_ind > end_ind) {
            BT_LOG_ASSERT(false, my_node, "start ind {} greater than end ind {}", start_ind, end_ind);
            ret = btree_status_t::retry;
        }
        return ret;
    }

    /* It split the child if a split is required. It releases lock on parent and child_node in case of failure */
    btree_status_t check_and_split_node(const BtreeNodePtr& my_node, BtreeUpdateRequest< K, V >* bur, const BtreeKey& k,
                                        const BtreeValue& v, int ind_hint, btree_put_type put_type,
                                        BtreeNodePtr child_node, homeds::thread::locktype& curlock,
                                        homeds::thread::locktype& child_curlock, int child_ind, bool& split_occured,
                                        const btree_cp_ptr& bcp) {

        split_occured = false;
        K split_key;
        btree_status_t ret = btree_status_t::success;
        auto child_lock_type = child_curlock;
        auto none_lock_type = LOCKTYPE_NONE;

#ifdef _PRERELEASE
        boost::optional< int > time;
        if (child_node->is_leaf()) {
            time = homestore_flip->get_test_flip< int >("btree_delay_and_split_leaf", child_node->get_total_entries());
        } else {
            time = homestore_flip->get_test_flip< int >("btree_delay_and_split", child_node->get_total_entries());
        }
        if (time && child_node->get_total_entries() > 2) {
            std::this_thread::sleep_for(std::chrono::microseconds{time.get()});
        } else
#endif
        {
            if (!child_node->is_split_needed(m_btree_cfg, k, v, &ind_hint, put_type, bur)) { return ret; }
        }

        /* Split needed */
        if (bur) {

            /* In case of range update we might split multiple childs of a parent in a single
             * iteration which result into less space in the parent node.
             */
#ifdef _PRERELEASE
            if (homestore_flip->test_flip("btree_parent_node_full")) {
                ret = btree_status_t::retry;
                goto out;
            }
#endif
            if (my_node->is_split_needed(m_btree_cfg, k, v, &ind_hint, put_type, bur)) {
                // restart from root
                ret = btree_status_t::retry;
                goto out;
            }
        }

        // Time to split the child, but we need to convert parent to write lock
        ret = upgrade_node(my_node, child_node, curlock, child_curlock, bcp);
        if (ret != btree_status_t::success) {
            THIS_BT_LOG(DEBUG, btree_structures, my_node, "Upgrade of node lock failed, retrying from root");
            BT_LOG_ASSERT_CMP(curlock, ==, homeds::thread::LOCKTYPE_NONE, my_node);
            goto out;
        }
        BT_LOG_ASSERT_CMP(child_curlock, ==, child_lock_type, my_node);
        BT_LOG_ASSERT_CMP(curlock, ==, homeds::thread::LOCKTYPE_WRITE, my_node);

        // We need to upgrade the child to WriteLock
        ret = upgrade_node(child_node, nullptr, child_curlock, none_lock_type, bcp);
        if (ret != btree_status_t::success) {
            THIS_BT_LOG(DEBUG, btree_structures, child_node, "Upgrade of child node lock failed, retrying from root");
            BT_LOG_ASSERT_CMP(child_curlock, ==, homeds::thread::LOCKTYPE_NONE, child_node);
            goto out;
        }
        BT_LOG_ASSERT_CMP(none_lock_type, ==, homeds::thread::LOCKTYPE_NONE, my_node);
        BT_LOG_ASSERT_CMP(child_curlock, ==, homeds::thread::LOCKTYPE_WRITE, child_node);

        // Real time to split the node and get point at which it was split
        ret = split_node(my_node, child_node, child_ind, &split_key, bcp);
        if (ret != btree_status_t::success) { goto out; }

        // After split, retry search and walk down.
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

    /* This function is called for the interior nodes whose childs are leaf nodes to calculate the sub range */
    void get_subrange(const BtreeNodePtr& my_node, BtreeUpdateRequest< K, V >* bur, int curr_ind, K& subrange_start_key,
                      K& subrange_end_key, bool& subrange_start_inc, bool& subrange_end_inc) {

#ifndef NDEBUG
        if (curr_ind > 0) {
            /* start of subrange will always be more then the key in curr_ind - 1 */
            K start_key;
            BtreeKey* start_key_ptr = &start_key;

            my_node->get_nth_key(curr_ind - 1, start_key_ptr, false);
            HS_ASSERT_CMP(DEBUG, start_key_ptr->compare(bur->get_input_range().get_start_key()), <=, 0);
        }
#endif

        // find end of subrange
        bool end_inc = true;
        K end_key;
        BtreeKey* end_key_ptr = &end_key;

        if (curr_ind < (int)my_node->get_total_entries()) {
            my_node->get_nth_key(curr_ind, end_key_ptr, false);
            if (end_key_ptr->compare(bur->get_input_range().get_end_key()) >= 0) {
                /* this is last index to process as end of range is smaller then key in this node */
                end_key_ptr = const_cast< BtreeKey* >(bur->get_input_range().get_end_key());
                end_inc = bur->get_input_range().is_end_inclusive();
            } else {
                end_inc = true;
            }
        } else {
            /* it is the edge node. end key is the end of input range */
            BT_LOG_ASSERT_CMP(my_node->has_valid_edge(), ==, true, my_node);
            end_key_ptr = const_cast< BtreeKey* >(bur->get_input_range().get_end_key());
            end_inc = bur->get_input_range().is_end_inclusive();
        }

        BtreeSearchRange& input_range = bur->get_input_range();
        auto start_key_ptr = input_range.get_start_key();
        subrange_start_key.copy_blob(start_key_ptr->get_blob());
        subrange_end_key.copy_blob(end_key_ptr->get_blob());
        subrange_start_inc = input_range.is_start_inclusive();
        subrange_end_inc = end_inc;

        auto ret = subrange_start_key.compare(&subrange_end_key);
        BT_RELEASE_ASSERT_CMP(ret, <=, 0, my_node);
        ret = subrange_start_key.compare(bur->get_input_range().get_end_key());
        BT_RELEASE_ASSERT_CMP(ret, <=, 0, my_node);
        /* We don't neeed to update the start at it is updated when entries are inserted in leaf nodes */
    }

    /* This function does the heavy lifiting of co-ordinating inserts. It is a recursive function which walks
     * down the tree.
     *
     * NOTE: It expects the node it operates to be locked (either read or write) and also the node should not be
     * full.
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
    btree_status_t do_put(const BtreeNodePtr& my_node, homeds::thread::locktype curlock, const BtreeKey& k,
                          const BtreeValue& v, int ind_hint, btree_put_type put_type, BtreeValue& existing_val,
                          BtreeUpdateRequest< K, V >* bur, const btree_cp_ptr& bcp, BtreeSearchRange& child_subrange) {

        btree_status_t ret = btree_status_t::success;
        bool unlocked_already = false;
        int curr_ind = -1;

        if (my_node->is_leaf()) {
            /* update the leaf node */
            BT_LOG_ASSERT_CMP(curlock, ==, LOCKTYPE_WRITE, my_node);
            ret = update_leaf_node(my_node, k, v, put_type, existing_val, bur, bcp, child_subrange);
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
        if (ret != btree_status_t::success) { goto out; }

        BT_DEBUG_ASSERT((curlock == LOCKTYPE_READ || curlock == LOCKTYPE_WRITE), my_node, "unexpected locktype {}",
                        curlock);
        curr_ind = start_ind;

        while (curr_ind <= end_ind) { // iterate all matched childrens

#ifdef _PRERELEASE
            if (curr_ind - start_ind > 1 && homestore_flip->test_flip("btree_leaf_node_split")) {
                ret = btree_status_t::retry;
                goto out;
            }
#endif

            homeds::thread::locktype child_cur_lock = homeds::thread::LOCKTYPE_NONE;

            // Get the childPtr for given key.
            BtreeNodeInfo child_info;
            BtreeNodePtr child_node;

            ret =
                get_child_and_lock_node(my_node, curr_ind, child_info, child_node, LOCKTYPE_READ, LOCKTYPE_WRITE, bcp);
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

            /* Get subrange if it is a range update */
            K start_key, end_key;
            bool start_incl = false, end_incl = false;
            if (bur && child_node->is_leaf()) {
                /* We get the subrange only for leaf because this is where we will be inserting keys. In interior
                 * nodes, keys are always propogated from the lower nodes.
                 */
                get_subrange(my_node, bur, curr_ind, start_key, end_key, start_incl, end_incl);
            }
            BtreeSearchRange subrange(start_key, start_incl, end_key, end_incl);

            /* check if child node is needed to split */
            bool split_occured = false;
            ret = check_and_split_node(my_node, bur, k, v, ind_hint, put_type, child_node, curlock, child_cur_lock,
                                       curr_ind, split_occured, bcp);
            if (ret != btree_status_t::success) { goto out; }
            if (split_occured) {
                ind_hint = -1; // Since split is needed, hint is no longer valid
                goto retry;
            }

            if (bur && child_node->is_leaf()) {
                THIS_BT_LOG(DEBUG, btree_structures, my_node, "Subrange:s:{},e:{},c:{},nid:{},edgeid:{},sk:{},ek:{}",
                            start_ind, end_ind, curr_ind, my_node->get_node_id(), my_node->get_edge_id(),
                            subrange.get_start_key()->to_string(), subrange.get_end_key()->to_string());
            }

#ifndef NDEBUG
            K ckey, pkey;
            if (curr_ind != (int)my_node->get_total_entries()) { // not edge
                my_node->get_nth_key(curr_ind, &pkey, true);
                if (child_node->get_total_entries() != 0) {
                    child_node->get_last_key(&ckey);
                    if (!child_node->is_leaf()) {
                        HS_ASSERT_CMP(DEBUG, ckey.compare(&pkey), ==, 0);
                    } else {
                        HS_ASSERT_CMP(DEBUG, ckey.compare(&pkey), <=, 0);
                    }
                }
                HS_ASSERT_CMP(DEBUG, (bur != nullptr || k.compare(&pkey) <= 0), ==, true);
            }
            if (curr_ind > 0) { // not first child
                my_node->get_nth_key(curr_ind - 1, &pkey, true);
                if (child_node->get_total_entries() != 0) {
                    child_node->get_first_key(&ckey);
                    HS_ASSERT_CMP(DEBUG, pkey.compare(&ckey), <=, 0);
                }
                HS_ASSERT_CMP(DEBUG, (bur != nullptr || k.compare(&pkey) >= 0), ==, true);
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
                HS_ASSERT_CMP(DEBUG, child_node->m_common_header.is_lock, ==, true);
            }
#endif

            ret = do_put(child_node, child_cur_lock, k, v, ind_hint, put_type, existing_val, bur, bcp, subrange);

            if (ret != btree_status_t::success) { goto out; }

            curr_ind++;
        }
    out:
        if (curlock != LOCKTYPE_NONE) { unlock_node(my_node, curlock); }
        return ret;
        // Warning: Do not access childNode or myNode beyond this point, since it would
        // have been unlocked by the recursive function and it could also been deleted.
    }

    btree_status_t do_remove(const BtreeNodePtr& my_node, homeds::thread::locktype curlock,
                             const BtreeSearchRange& range, BtreeKey* outkey, BtreeValue* outval,
                             const btree_cp_ptr& bcp) {
        btree_status_t ret = btree_status_t::success;
        if (my_node->is_leaf()) {
            BT_DEBUG_ASSERT_CMP(curlock, ==, LOCKTYPE_WRITE, my_node);

#ifndef NDEBUG
            for (auto i = 1u; i < my_node->get_total_entries(); i++) {
                K curKey, prevKey;
                my_node->get_nth_key(i - 1, &prevKey, false);
                my_node->get_nth_key(i, &curKey, false);
                HS_ASSERT_CMP(DEBUG, prevKey.compare(&curKey), <, 0);
            }
#endif
            bool is_found = my_node->remove_one(range, outkey, outval);
#ifndef NDEBUG
            for (auto i = 1u; i < my_node->get_total_entries(); i++) {
                K curKey, prevKey;
                my_node->get_nth_key(i - 1, &prevKey, false);
                my_node->get_nth_key(i, &curKey, false);
                HS_ASSERT_CMP(DEBUG, prevKey.compare(&curKey), <, 0);
            }
#endif
            if (is_found) {
                write_node(my_node, bcp);
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
        ASSERT_IS_VALID_INTERIOR_CHILD_INDX(result, my_node);
        uint32_t ind = result.end_of_search_index;

        BtreeNodeInfo child_info;
        BtreeNodePtr child_node;
        ret = get_child_and_lock_node(my_node, ind, child_info, child_node, LOCKTYPE_READ, LOCKTYPE_WRITE, bcp);

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
            ret = upgrade_node(my_node, child_node, curlock, child_cur_lock, bcp);
            if (ret != btree_status_t::success) {
                BT_DEBUG_ASSERT_CMP(curlock, ==, homeds::thread::LOCKTYPE_NONE, my_node)
                return ret;
            }
            BT_DEBUG_ASSERT_CMP(curlock, ==, homeds::thread::LOCKTYPE_WRITE, my_node);

            uint32_t node_end_indx =
                my_node->has_valid_edge() ? my_node->get_total_entries() : my_node->get_total_entries() - 1;
            uint32_t end_ind = (ind + HS_DYNAMIC_CONFIG(btree->max_nodes_to_rebalance)) < node_end_indx
                ? (ind + HS_DYNAMIC_CONFIG(btree->max_nodes_to_rebalance))
                : node_end_indx;
            if (end_ind > ind) {
                // It is safe to unlock child without upgrade, because child node would not be deleted, since its
                // parent (myNode) is being write locked by this thread. In fact upgrading would be a problem, since
                // this child might be a middle child in the list of indices, which means we might have to lock one
                // in left against the direction of intended locking (which could cause deadlock).
                unlock_node(child_node, child_cur_lock);
                auto result = merge_nodes(my_node, ind, end_ind, bcp);
                if (result != btree_status_t::success && result != btree_status_t::merge_not_required) {
                    // write or read failed
                    unlock_node(my_node, curlock);
                    return ret;
                }
                if (result == btree_status_t::success) { COUNTER_INCREMENT(m_metrics, btree_merge_count, 1); }
                goto retry;
            }
        }

#ifndef NDEBUG
        K ckey, pkey;
        if (ind != my_node->get_total_entries() && child_node->get_total_entries()) { // not edge
            child_node->get_last_key(&ckey);
            my_node->get_nth_key(ind, &pkey, true);
            BT_DEBUG_ASSERT_CMP(ckey.compare(&pkey), <=, 0, my_node);
        }

        if (ind > 0 && child_node->get_total_entries()) { // not first child
            child_node->get_first_key(&ckey);
            my_node->get_nth_key(ind - 1, &pkey, true);
            BT_DEBUG_ASSERT_CMP(pkey.compare(&ckey), <, 0, my_node);
        }
#endif

        unlock_node(my_node, curlock);
        return (do_remove(child_node, child_cur_lock, range, outkey, outval, bcp));

        // Warning: Do not access childNode or myNode beyond this point, since it would
        // have been unlocked by the recursive function and it could also been deleted.
    }

    btree_status_t check_split_root(const BtreeKey& k, const BtreeValue& v, btree_put_type& putType,
                                    BtreeUpdateRequest< K, V >* bur = nullptr, const btree_cp_ptr& bcp = nullptr) {
        int ind;
        K split_key;
        BtreeNodePtr child_node = nullptr;
        btree_status_t ret = btree_status_t::success;

        m_btree_lock.write_lock();
        BtreeNodePtr root;

        ret = read_and_lock_root(m_root_node, root, locktype::LOCKTYPE_WRITE, locktype::LOCKTYPE_WRITE, bcp);
        if (ret != btree_status_t::success) { goto done; }

        if (!root->is_split_needed(m_btree_cfg, k, v, &ind, putType, bur)) {
            unlock_node(root, homeds::thread::LOCKTYPE_WRITE);
            goto done;
        }

        // Create a new child node and split them
        child_node = alloc_interior_node();
        if (child_node == nullptr) {
            ret = btree_status_t::space_not_avail;
            unlock_node(root, homeds::thread::LOCKTYPE_WRITE);
            goto done;
        }

        /* it swap the data while keeping the nodeid same */
        btree_store_t::swap_node(m_btree_store.get(), root, child_node);
        write_node(child_node, bcp);

        THIS_BT_LOG(DEBUG, btree_structures, root,
                    "Root node is full, swapping contents with child_node {} and split that",
                    child_node->get_node_id());

        BT_DEBUG_ASSERT_CMP(root->get_total_entries(), ==, 0, root);
        ret = split_node(root, child_node, root->get_total_entries(), &split_key, bcp, true);
        BT_DEBUG_ASSERT_CMP(m_root_node, ==, root->get_node_id(), root);

        if (ret != btree_status_t::success) {
            btree_store_t::swap_node(m_btree_store.get(), child_node, root);
            write_node(child_node, bcp);
        }

        /* unlock child node */
        unlock_node(root, homeds::thread::LOCKTYPE_WRITE);

        if (ret == btree_status_t::success) { COUNTER_INCREMENT(m_metrics, btree_depth, 1); }
    done:
        m_btree_lock.unlock();
        return ret;
    }

    btree_status_t check_collapse_root(const btree_cp_ptr& bcp) {
        BtreeNodePtr child_node = nullptr;
        btree_status_t ret = btree_status_t::success;
        std::vector< BtreeNodePtr > old_nodes;
        std::vector< BtreeNodePtr > new_nodes;

        m_btree_lock.write_lock();
        BtreeNodePtr root;

        ret = read_and_lock_root(m_root_node, root, locktype::LOCKTYPE_WRITE, locktype::LOCKTYPE_WRITE, bcp);
        if (ret != btree_status_t::success) { goto done; }

        if (root->get_total_entries() != 0 || root->is_leaf() /*some other thread collapsed root already*/) {
            unlock_node(root, locktype::LOCKTYPE_WRITE);
            goto done;
        }

        BT_DEBUG_ASSERT_CMP(root->has_valid_edge(), ==, true, root);
        ret = read_node(root->get_edge_id(), child_node);
        if (child_node == nullptr) {
            unlock_node(root, locktype::LOCKTYPE_WRITE);
            goto done;
        }

        // Elevate the edge child as root.
        btree_store_t::swap_node(m_btree_store.get(), root, child_node);
        write_node(root, bcp);
        BT_DEBUG_ASSERT_CMP(m_root_node, ==, root->get_node_id(), root);

        old_nodes.push_back(child_node);

        if (BtreeStoreType == btree_store_type::SSD_BTREE) {
            auto j_iob = btree_store_t::make_journal_entry(journal_op::BTREE_MERGE, true /* is_root */, bcp);
            btree_store_t::append_node_to_journal(j_iob, bt_journal_node_op::inplace_write, root, bcp);
            btree_store_t::append_node_to_journal(j_iob, bt_journal_node_op::removal, child_node, bcp);
            btree_store_t::write_journal_entry(m_btree_store.get(), bcp, j_iob);
        }
        unlock_node(root, locktype::LOCKTYPE_WRITE);
        free_node(child_node, (bcp ? bcp->free_blkid_list : nullptr));

        if (ret == btree_status_t::success) { COUNTER_DECREMENT(m_metrics, btree_depth, 1); }
    done:
        m_btree_lock.unlock();
        return ret;
    }

    btree_status_t split_node(const BtreeNodePtr& parent_node, BtreeNodePtr child_node, uint32_t parent_ind,
                              BtreeKey* out_split_key, const btree_cp_ptr& bcp, bool root_split = false) {
        BtreeNodeInfo ninfo;
        BtreeNodePtr child_node1 = child_node;
        BtreeNodePtr child_node2 = child_node1->is_leaf() ? alloc_leaf_node() : alloc_interior_node();

        if (child_node2 == nullptr) { return (btree_status_t::space_not_avail); }

        btree_status_t ret = btree_status_t::success;

        child_node2->set_next_bnode(child_node1->get_next_bnode());
        child_node1->set_next_bnode(child_node2->get_node_id());
        uint32_t child1_filled_size = m_btree_cfg.get_node_area_size() - child_node1->get_available_size(m_btree_cfg);

        auto split_size = m_btree_cfg.get_split_size(child1_filled_size);
        uint32_t res = child_node1->move_out_to_right_by_size(m_btree_cfg, child_node2, split_size);

        BT_RELEASE_ASSERT_CMP(res, >, 0, child_node1,
                              "Unable to split entries in the child node"); // means cannot split entries
        BT_DEBUG_ASSERT_CMP(child_node1->get_total_entries(), >, 0, child_node1);

        // Update the existing parent node entry to point to second child ptr.
        bool edge_split = (parent_ind == parent_node->get_total_entries());
        ninfo.set_bnode_id(child_node2->get_node_id());
        parent_node->update(parent_ind, ninfo);

        // Insert the last entry in first child to parent node
        child_node1->get_last_key(out_split_key);
        ninfo.set_bnode_id(child_node1->get_node_id());

        /* If key is extent then we always insert the end key in the parent node */
        K out_split_end_key;
        out_split_end_key.copy_end_key_blob(out_split_key->get_blob());
        parent_node->insert(out_split_end_key, ninfo);

#ifndef NDEBUG
        K split_key;
        child_node2->get_first_key(&split_key);
        BT_DEBUG_ASSERT_CMP(split_key.compare(out_split_key), >, 0, child_node2);
#endif
        THIS_BT_LOG(DEBUG, btree_structures, parent_node, "Split child_node={} with new_child_node={}, split_key={}",
                    child_node1->get_node_id(), child_node2->get_node_id(), out_split_key->to_string());

        if (BtreeStoreType == btree_store_type::SSD_BTREE) {
            auto j_iob = btree_store_t::make_journal_entry(journal_op::BTREE_SPLIT, root_split, bcp,
                                                           {parent_node->get_node_id(), parent_node->get_gen()});
            btree_store_t::append_node_to_journal(
                j_iob, (root_split ? bt_journal_node_op::creation : bt_journal_node_op::inplace_write), child_node1,
                bcp, out_split_end_key.get_blob());

            // For root split or split around the edge, we don't write the key, which will cause replay to insert
            // edge
            if (edge_split) {
                btree_store_t::append_node_to_journal(j_iob, bt_journal_node_op::creation, child_node2, bcp);
            } else {
                K child2_pkey;
                parent_node->get_nth_key(parent_ind, &child2_pkey, true);
                btree_store_t::append_node_to_journal(j_iob, bt_journal_node_op::creation, child_node2, bcp,
                                                      child2_pkey.get_blob());
            }
            btree_store_t::write_journal_entry(m_btree_store.get(), bcp, j_iob);
        }

        // we write right child node, than left and than parent child
        write_node(child_node2, nullptr, bcp);
        write_node(child_node1, child_node2, bcp);
        write_node(parent_node, child_node1, bcp);

        // NOTE: Do not access parentInd after insert, since insert would have
        // shifted parentNode to the right.
        return ret;
    }

public:
    btree_status_t create_btree_replay(btree_journal_entry* jentry, const btree_cp_ptr& bcp) {
        if (jentry) {
            BT_DEBUG_ASSERT_CMP(jentry->is_root, ==, true, ,
                                "Expected create_btree_replay entry to be root journal entry");
            BT_DEBUG_ASSERT_CMP(jentry->parent_node.get_id(), ==, m_root_node, , "Root node journal entry mismatch");
        }

        // Create a root node by reserving the leaf node
        BtreeNodePtr root = reserve_leaf_node(BlkId(m_root_node));
        auto ret = write_node(root, nullptr, bcp);
        BT_DEBUG_ASSERT_CMP(ret, ==, btree_status_t::success, , "expecting success in writing root node");
        return btree_status_t::success;
    }

    btree_status_t split_node_replay(btree_journal_entry* jentry, const btree_cp_ptr& bcp) {
        bnodeid_t id = jentry->is_root ? m_root_node : jentry->parent_node.node_id;
        BtreeNodePtr parent_node;

        // read parent node
        read_node_or_fail(id, parent_node);

        // Parent already went ahead of the journal entry, return done
        if (parent_node->get_gen() >= jentry->parent_node.node_gen) {
            THIS_BT_LOG(INFO, base, ,
                        "Journal replay: parent_node gen {} ahead of jentry gen {} is root {} , skipping ",
                        parent_node->get_gen(), jentry->parent_node.get_gen(), jentry->is_root);
            return btree_status_t::replay_not_needed;
        }

        // Read the first inplace write node which is the leftmost child and also form child split key from journal
        auto j_child_nodes = jentry->get_nodes();

        BtreeNodePtr child_node1;
        if (jentry->is_root) {
            // If root is not written yet, parent_node will be pointing child_node1, so create a new parent_node to
            // be treated as root here on.
            child_node1 = reserve_interior_node(BlkId(j_child_nodes[0]->node_id()));
            btree_store_t::swap_node(m_btree_store.get(), parent_node, child_node1);

            THIS_BT_LOG(INFO, btree_generics, ,
                        "Journal replay: root split, so creating child_node id={} and swapping the node with "
                        "parent_node id={} names {}",
                        child_node1->get_node_id(), parent_node->get_node_id(), m_btree_cfg.get_name());

        } else {
            read_node_or_fail(j_child_nodes[0]->node_id(), child_node1);
        }

        THIS_BT_LOG(INFO, btree_generics, ,
                    "Journal replay: child_node1 => jentry: [id={} gen={}], ondisk: [id={} gen={}] names {}",
                    j_child_nodes[0]->node_id(), j_child_nodes[0]->node_gen(), child_node1->get_node_id(),
                    child_node1->get_gen(), m_btree_cfg.get_name());
        if (jentry->is_root) {
            BT_RELEASE_ASSERT_CMP(j_child_nodes[0]->type, ==, bt_journal_node_op::creation, ,
                                  "Expected first node in journal entry to be new creation for root split");
        } else {
            BT_RELEASE_ASSERT_CMP(j_child_nodes[0]->type, ==, bt_journal_node_op::inplace_write, ,
                                  "Expected first node in journal entry to be in-place write");
        }
        BT_RELEASE_ASSERT_CMP(j_child_nodes[1]->type, ==, bt_journal_node_op::creation, ,
                              "Expected second node in journal entry to be new node creation");

        // recover child node
        bool child_split = recover_child_nodes_in_split(child_node1, j_child_nodes, bcp);

        // recover parent node
        recover_parent_node_in_split(parent_node, child_split ? child_node1 : nullptr, j_child_nodes, bcp);
        return btree_status_t::success;
    }

private:
    bool recover_child_nodes_in_split(const BtreeNodePtr& child_node1,
                                      const std::vector< bt_journal_node_info* >& j_child_nodes,
                                      const btree_cp_ptr& bcp) {

        BtreeNodePtr child_node2;
        // Check if child1 is ahead of the generation
        if (child_node1->get_gen() >= j_child_nodes[0]->node_gen()) {
            // leftmost_node is written, so right node must have been written as well.
            read_node_or_fail(child_node1->get_next_bnode(), child_node2);

            // sanity check for right node
            BT_RELEASE_ASSERT_CMP(child_node2->get_gen(), >=, j_child_nodes[1]->node_gen(), child_node2,
                                  "gen cnt should be more than the journal entry");
            // no need to recover child nodes
            return false;
        }

        K split_key;
        split_key.set_blob({j_child_nodes[0]->key_area(), j_child_nodes[0]->key_size});
        child_node2 = child_node1->is_leaf() ? reserve_leaf_node(BlkId(j_child_nodes[1]->node_id()))
                                             : reserve_interior_node(BlkId(j_child_nodes[1]->node_id()));

        // We need to do split based on entries since the left children is also not written yet.
        // Find the split key within the child_node1. It is not always found, so we split upto that.
        auto ret = child_node1->find(split_key, nullptr, false);

        // sanity check for left mode node before recovery
        {
            if (!ret.found) {
                if (!child_node1->is_leaf()) {
                    BT_RELEASE_ASSERT(0, , "interior nodes should always have this key if it is written yet");
                }
            }
        }

        THIS_BT_LOG(INFO, btree_generics, , "Journal replay: split key {}, split indx {} child_node1 {}",
                    split_key.to_string(), ret.end_of_search_index, child_node1->to_string());
        /* if it is not found than end_of_search_index points to first ind which is greater than split key */
        auto split_ind = ret.end_of_search_index;
        if (ret.found) { ++split_ind; } // we don't want to move split key */
        if (child_node1->is_leaf() && split_ind < (int)child_node1->get_total_entries()) {
            K key;
            child_node1->get_nth_key(split_ind, &key, false);

            if (split_key.compare_start(&key) >= 0) { /* we need to split the key range */
                THIS_BT_LOG(INFO, btree_generics, , "splitting a leaf node key {}", key.to_string());
                V v;
                child_node1->get_nth_value(split_ind, &v, false);
                vector< pair< K, V > > replace_kv;
                child_node1->remove(split_ind, split_ind);
                m_split_key_cb(key, v, split_key, replace_kv);
                for (auto& pair : replace_kv) {
                    auto status = child_node1->insert(pair.first, pair.second);
                    BT_RELEASE_ASSERT((status == btree_status_t::success), child_node1, "unexpected insert failure");
                }
                auto ret = child_node1->find(split_key, nullptr, false);
                BT_RELEASE_ASSERT((ret.found && (ret.end_of_search_index == split_ind)), child_node1,
                                  "found new indx {}, old split indx{}", ret.end_of_search_index, split_ind);
                ++split_ind;
            }
        }
        child_node1->move_out_to_right_by_entries(m_btree_cfg, child_node2,
                                                  child_node1->get_total_entries() - split_ind);

        child_node2->set_next_bnode(child_node1->get_next_bnode());
        child_node2->set_gen(j_child_nodes[1]->node_gen());

        child_node1->set_next_bnode(child_node2->get_node_id());
        child_node1->set_gen(j_child_nodes[0]->node_gen());

        THIS_BT_LOG(INFO, btree_generics, , "Journal replay: child_node2 {}", child_node2->to_string());
        write_node(child_node2, nullptr, bcp);
        write_node(child_node1, child_node2, bcp);
        return true;
    }

    void recover_parent_node_in_split(const BtreeNodePtr& parent_node, const BtreeNodePtr& child_node1,
                                      std::vector< bt_journal_node_info* >& j_child_nodes, const btree_cp_ptr& bcp) {

        // find child_1 key
        K child1_key; // we need to insert child1_key
        BT_RELEASE_ASSERT_CMP(j_child_nodes[0]->key_size, !=, 0, , "key size of left mode node is zero");
        child1_key.set_blob({j_child_nodes[0]->key_area(), j_child_nodes[0]->key_size});
        auto child1_node_id = j_child_nodes[0]->node_id();

        // find split indx
        auto ret = parent_node->find(child1_key, nullptr, false);
        BT_RELEASE_ASSERT_CMP(ret.found, ==, false, , "child_1 key should not be in this parent");
        auto split_indx = ret.end_of_search_index;

        // find child2_key
        K child2_key; // we only need to update child2_key to new node
        if (j_child_nodes[1]->key_size != 0) {
            child2_key.set_blob({j_child_nodes[1]->key_area(), j_child_nodes[1]->key_size});
            ret = parent_node->find(child2_key, nullptr, false);
            BT_RELEASE_ASSERT_CMP(split_indx, ==, ret.end_of_search_index, , "it should be same as split index");
        } else {
            // parent should be valid edge it is not a root split
        }
        auto child2_node_id = j_child_nodes[1]->node_id();

        // update child2_key value
        BtreeNodeInfo ninfo;
        ninfo.set_bnode_id(child2_node_id);
        parent_node->update(split_indx, ninfo);

        // insert child 1
        ninfo.set_bnode_id(child1_node_id);
        K out_split_end_key;
        out_split_end_key.copy_end_key_blob(child1_key.get_blob());
        parent_node->insert(out_split_end_key, ninfo);

        // Write the parent node
        write_node(parent_node, child_node1, bcp);

        /* do sanity check after recovery split */
        {
            validate_sanity_child(parent_node, split_indx);
            validate_sanity_next_child(parent_node, split_indx);
        }
    }

    btree_status_t merge_nodes(const BtreeNodePtr& parent_node, uint32_t start_indx, uint32_t end_indx,
                               const btree_cp_ptr& bcp) {
        btree_status_t ret = btree_status_t::merge_failed;
        std::vector< BtreeNodePtr > child_nodes;
        std::vector< BtreeNodePtr > old_nodes;
        std::vector< BtreeNodePtr > replace_nodes;
        std::vector< BtreeNodePtr > new_nodes;
        std::vector< BtreeNodePtr > deleted_nodes;
        BtreeNodePtr left_most_node;
        K last_pkey; // last key of parent node
        bool last_pkey_valid = false;
        uint32_t balanced_size;
        BtreeNodePtr merge_node;
        K last_ckey; // last key in child
        uint32_t parent_insert_indx = start_indx;
#ifndef NDEBUG
        uint32_t total_child_entries = 0;
        uint32_t new_entries = 0;
        K last_debug_ckey;
        K new_last_debug_ckey;
        BtreeNodePtr last_node;
#endif
        /* Try to take a lock on all nodes participating in merge*/
        for (auto indx = start_indx; indx <= end_indx; ++indx) {
            if (indx == parent_node->get_total_entries()) {
                BT_LOG_ASSERT(parent_node->has_valid_edge(), parent_node,
                              "Assertion failure, expected valid edge for parent_node: {}");
            }

            BtreeNodeInfo child_info;
            parent_node->get(indx, &child_info, false /* copy */);

            BtreeNodePtr child;
            ret = read_and_lock_node(child_info.bnode_id(), child, locktype::LOCKTYPE_WRITE, locktype::LOCKTYPE_WRITE,
                                     bcp);
            if (ret != btree_status_t::success) { goto out; }
            BT_LOG_ASSERT_CMP(child->is_valid_node(), ==, true, child);

            /* check if left most node has space */
            if (indx == start_indx) {
                balanced_size = m_btree_cfg.get_ideal_fill_size();
                left_most_node = child;
                if (left_most_node->get_occupied_size(m_btree_cfg) > balanced_size) {
                    /* first node doesn't have any free space. we can exit now */
                    ret = btree_status_t::merge_not_required;
                    goto out;
                }
            } else {
                bool is_allocated = true;
                /* pre allocate the new nodes. We will free the nodes which are not in use later */
                auto new_node = btree_store_t::alloc_node(m_btree_store.get(), child->is_leaf(), is_allocated, child);
                if (is_allocated) {
                    /* we are going to allocate new blkid of all the nodes except the first node.
                     * Note :- These blkids will leak if we fail or crash before writing entry into
                     * journal.
                     */
                    old_nodes.push_back(child);
                    COUNTER_INCREMENT_IF_ELSE(m_metrics, child->is_leaf(), btree_leaf_node_count, btree_int_node_count,
                                              1);
                }
                /* Blk IDs can leak if it crash before writing it to a journal */
                if (new_node == nullptr) {
                    ret = btree_status_t::space_not_avail;
                    goto out;
                }
                new_nodes.push_back(new_node);
            }
#ifndef NDEBUG
            total_child_entries += child->get_total_entries();
            child->get_last_key(&last_debug_ckey);
#endif
            child_nodes.push_back(child);
        }

        if (end_indx != parent_node->get_total_entries()) {
            /* If it is not edge we always preserve the last key in a given merge group of nodes.*/
            parent_node->get_nth_key(end_indx, &last_pkey, true);
            last_pkey_valid = true;
        }

        merge_node = left_most_node;
        /* We can not fail from this point. Nodes will be modified in memory. */
        for (uint32_t i = 0; i < new_nodes.size(); ++i) {
            auto occupied_size = merge_node->get_occupied_size(m_btree_cfg);
            if (occupied_size < balanced_size) {
                uint32_t pull_size = balanced_size - occupied_size;
                merge_node->move_in_from_right_by_size(m_btree_cfg, new_nodes[i], pull_size);
                if (new_nodes[i]->get_total_entries() == 0) {
                    /* this node is freed */
                    deleted_nodes.push_back(new_nodes[i]);
                    continue;
                }
            }

            /* update the last key of merge node in parent node */
            K last_ckey; // last key in child
            merge_node->get_last_key(&last_ckey);
            BtreeNodeInfo ninfo(merge_node->get_node_id());
            parent_node->update(parent_insert_indx, last_ckey, ninfo);
            ++parent_insert_indx;

            merge_node->set_next_bnode(new_nodes[i]->get_node_id()); // link them
            merge_node = new_nodes[i];
            if (merge_node != left_most_node) {
                /* left most node is not replaced */
                replace_nodes.push_back(merge_node);
            }
        }

        /* update the latest merge node */
        merge_node->get_last_key(&last_ckey);
        if (last_pkey_valid) {
            BT_DEBUG_ASSERT_CMP(last_ckey.compare(&last_pkey), <=, 0, parent_node);
            last_ckey = last_pkey;
        }

        /* update the last key */
        {
            BtreeNodeInfo ninfo(merge_node->get_node_id());
            parent_node->update(parent_insert_indx, last_ckey, ninfo);
            ++parent_insert_indx;
        }

        /* remove the keys which are no longer used */
        if ((parent_insert_indx) <= end_indx) { parent_node->remove(parent_insert_indx, end_indx); }

        /* write the journal entry */
        if (BtreeStoreType == btree_store_type::SSD_BTREE) {
            auto j_iob = btree_store_t::make_journal_entry(journal_op::BTREE_MERGE, false /* is_root */, bcp,
                                                           {parent_node->get_node_id(), parent_node->get_gen()});
            K child_pkey;
            if (start_indx < parent_node->get_total_entries()) {
                parent_node->get_nth_key(start_indx, &child_pkey, true);
                BT_RELEASE_ASSERT_CMP(start_indx, ==, (parent_insert_indx - 1), parent_node, "it should be last index");
            }
            btree_store_t::append_node_to_journal(j_iob, bt_journal_node_op::inplace_write, left_most_node, bcp,
                                                  child_pkey.get_blob());
            for (auto& node : old_nodes) {
                btree_store_t::append_node_to_journal(j_iob, bt_journal_node_op::removal, node, bcp);
            }
            uint32_t insert_indx = 0;
            for (auto& node : replace_nodes) {
                K child_pkey;
                if ((start_indx + insert_indx) < parent_node->get_total_entries()) {
                    parent_node->get_nth_key(start_indx + insert_indx, &child_pkey, true);
                    BT_RELEASE_ASSERT_CMP((start_indx + insert_indx), ==, (parent_insert_indx - 1), parent_node,
                                          "it should be last index");
                }
                btree_store_t::append_node_to_journal(j_iob, bt_journal_node_op::creation, node, bcp,
                                                      child_pkey.get_blob());
                ++insert_indx;
            }
            BT_RELEASE_ASSERT_CMP((start_indx + insert_indx), ==, parent_insert_indx, parent_node, "it should be same");
            btree_store_t::write_journal_entry(m_btree_store.get(), bcp, j_iob);
        }

        if (replace_nodes.size() > 0) {
            /* write the right most node */
            write_node(replace_nodes[replace_nodes.size() - 1], nullptr, bcp);
            if (replace_nodes.size() > 1) {
                /* write the middle nodes */
                for (int i = replace_nodes.size() - 2; i >= 0; --i) {
                    write_node(replace_nodes[i], replace_nodes[i + 1], bcp);
                }
            }
            /* write the left most node */
            write_node(left_most_node, replace_nodes[0], bcp);
        } else {
            /* write the left most node */
            write_node(left_most_node, nullptr, bcp);
        }

        /* write the parent node */
        write_node(parent_node, left_most_node, bcp);

#ifndef NDEBUG
        for (const auto& n : replace_nodes) {
            new_entries += n->get_total_entries();
        }

        new_entries += left_most_node->get_total_entries();
        HS_ASSERT_CMP(DEBUG, total_child_entries, ==, new_entries);

        if (replace_nodes.size()) {
            replace_nodes[replace_nodes.size() - 1]->get_last_key(&new_last_debug_ckey);
            last_node = replace_nodes[replace_nodes.size() - 1];
        } else {
            left_most_node->get_last_key(&new_last_debug_ckey);
            last_node = left_most_node;
        }
        if (last_debug_ckey.compare(&new_last_debug_ckey) != 0) {
            LOGINFO("{}", last_node->to_string());
            if (deleted_nodes.size() > 0) { LOGINFO("{}", (deleted_nodes[deleted_nodes.size() - 1]->to_string())); }
            HS_ASSERT(DEBUG, false, "compared failed");
        }
#endif
        /* free nodes. It actually gets freed after cp is completed */
        for (const auto& n : old_nodes) {
            free_node(n, (bcp ? bcp->free_blkid_list : nullptr));
        }
        for (const auto& n : deleted_nodes) {
            free_node(n);
        }
        ret = btree_status_t::success;
    out:
#ifndef NDEBUG
        uint32_t freed_entries = deleted_nodes.size();
        uint32_t scan_entries = end_indx - start_indx - freed_entries + 1;
        for (uint32_t i = 0; i < scan_entries; ++i) {
            if (i < (scan_entries - 1)) { validate_sanity_next_child(parent_node, (uint32_t)start_indx + i); }
            validate_sanity_child(parent_node, (uint32_t)start_indx + i);
        }
#endif
        // Loop again in reverse order to unlock the nodes. freeable nodes need to be unlocked and freed
        for (uint32_t i = child_nodes.size() - 1; i != 0; i--) {
            unlock_node(child_nodes[i], locktype::LOCKTYPE_WRITE);
        }
        unlock_node(child_nodes[0], locktype::LOCKTYPE_WRITE);
        if (ret != btree_status_t::success) {
            /* free the allocated nodes */
            for (const auto& n : new_nodes) {
                free_node(n);
            }
        }
        return ret;
    }

#if 0
                btree_status_t merge_node_replay(btree_journal_entry* jentry, const btree_cp_ptr& bcp) {
                    BtreeNodePtr parent_node = (jentry->is_root) ? read_node(m_root_node) : read_node(jentry->parent_node.node_id);

                    // Parent already went ahead of the journal entry, return done
                    if (parent_node->get_gen() >= jentry->parent_node.node_gen) { return btree_status_t::replay_not_needed; }
                }
#endif

    void validate_sanity_child(const BtreeNodePtr& parent_node, uint32_t ind) {
        BtreeNodeInfo child_info;
        K child_first_key;
        K child_last_key;
        K parent_key;

        parent_node->get(ind, &child_info, false /* copy */);
        BtreeNodePtr child_node = nullptr;
        auto ret = read_node(child_info.bnode_id(), child_node);
        HS_ASSERT_CMP(RELEASE, ret, ==, btree_status_t::success, "read failed, reason: {}", ret);
        if (child_node->get_total_entries() == 0) {
            auto parent_entries = parent_node->get_total_entries();
            if (!child_node->is_leaf()) { // leaf node or edge node can have 0 entries
                HS_ASSERT_CMP(RELEASE, ((parent_node->has_valid_edge() && ind == parent_entries)), ==, true);
            }
            return;
        }
        child_node->get_first_key(&child_first_key);
        child_node->get_last_key(&child_last_key);
        HS_ASSERT_CMP(RELEASE, child_first_key.compare(&child_last_key), <=, 0);
        if (ind == parent_node->get_total_entries()) {
            HS_ASSERT_CMP(RELEASE, parent_node->has_valid_edge(), ==, true);
            if (ind > 0) {
                parent_node->get_nth_key(ind - 1, &parent_key, false);
                HS_ASSERT_CMP(RELEASE, child_first_key.compare(&parent_key), >, 0);
                HS_ASSERT_CMP(RELEASE, parent_key.compare_start(&child_first_key), <, 0);
            }
        } else {
            parent_node->get_nth_key(ind, &parent_key, false);
            HS_ASSERT_CMP(RELEASE, child_first_key.compare(&parent_key), <=, 0);
            HS_ASSERT_CMP(RELEASE, child_last_key.compare(&parent_key), <=, 0);
            HS_ASSERT_CMP(RELEASE, parent_key.compare_start(&child_first_key), >=, 0);
            HS_ASSERT_CMP(RELEASE, parent_key.compare_start(&child_first_key), >=, 0);
            if (ind != 0) {
                parent_node->get_nth_key(ind - 1, &parent_key, false);
                HS_ASSERT_CMP(RELEASE, child_first_key.compare(&parent_key), >, 0);
                HS_ASSERT_CMP(RELEASE, parent_key.compare_start(&child_first_key), <, 0);
            }
        }
    }

    void validate_sanity_next_child(const BtreeNodePtr& parent_node, uint32_t ind) {
        BtreeNodeInfo child_info;
        K child_key;
        K parent_key;

        if (parent_node->has_valid_edge()) {
            if (ind == parent_node->get_total_entries()) { return; }
        } else {
            if (ind == parent_node->get_total_entries() - 1) { return; }
        }
        parent_node->get(ind + 1, &child_info, false /* copy */);
        BtreeNodePtr child_node = nullptr;
        auto ret = read_node(child_info.bnode_id(), child_node);
        HS_ASSERT(RELEASE, ret == btree_status_t::success, "read failed, reason: {}", ret);
        if (child_node->get_total_entries() == 0) {
            auto parent_entries = parent_node->get_total_entries();
            if (!child_node->is_leaf()) { // leaf node can have 0 entries
                HS_ASSERT_CMP(RELEASE,
                              ((parent_node->has_valid_edge() && ind == parent_entries) || (ind = parent_entries - 1)),
                              ==, true);
            }
            return;
        }
        /* in case of merge next child will never have zero entries otherwise it would have been merged */
        HS_ASSERT_CMP(RELEASE, child_node->get_total_entries(), !=, 0);
        child_node->get_first_key(&child_key);
        parent_node->get_nth_key(ind, &parent_key, false);
        HS_ASSERT_CMP(RELEASE, child_key.compare(&parent_key), >, 0);
        HS_ASSERT_CMP(RELEASE, parent_key.compare_start(&child_key), <, 0);
    }

    BtreeNodePtr alloc_leaf_node() {
        bool is_new_allocation;
        BtreeNodePtr n = btree_store_t::alloc_node(m_btree_store.get(), true /* is_leaf */, is_new_allocation);
        if (n == nullptr) { return nullptr; }
        n->set_leaf(true);
        COUNTER_INCREMENT(m_metrics, btree_leaf_node_count, 1);
        m_total_nodes++;
        return n;
    }

    BtreeNodePtr alloc_interior_node() {
        bool is_new_allocation;
        BtreeNodePtr n = btree_store_t::alloc_node(m_btree_store.get(), false /* isLeaf */, is_new_allocation);
        if (n == nullptr) { return nullptr; }
        n->set_leaf(false);
        COUNTER_INCREMENT(m_metrics, btree_int_node_count, 1);
        m_total_nodes++;
        return n;
    }

    BtreeNodePtr reserve_leaf_node(const BlkId& blkid) {
        BtreeNodePtr n = btree_store_t::reserve_node(m_btree_store.get(), true /* is_leaf */, blkid);
        if (n == nullptr) { return nullptr; }
        n->set_leaf(true);
        COUNTER_INCREMENT(m_metrics, btree_leaf_node_count, 1);
        return n;
    }

    BtreeNodePtr reserve_interior_node(const BlkId& blkid) {
        BtreeNodePtr n = btree_store_t::reserve_node(m_btree_store.get(), false /* is_leaf */, blkid);
        if (n == nullptr) { return nullptr; }
        n->set_leaf(false);
        COUNTER_INCREMENT(m_metrics, btree_int_node_count, 1);
        return n;
    }

    /* Note:- This function assumes that access of this node is thread safe. */
    void free_node(const BtreeNodePtr& node, const blkid_list_ptr& free_blkid_list = nullptr, bool in_mem = false) {
        THIS_BT_LOG(DEBUG, btree_generics, node, "Freeing node");

        COUNTER_DECREMENT_IF_ELSE(m_metrics, node->is_leaf(), btree_leaf_node_count, btree_int_node_count, 1);
        if (node->is_valid_node() == false) {
            // a node could be marked as invalid during previous destroy and hit crash before destroy completes;
            // and upon boot volume continues to destroy this btree;
            THIS_BT_LOG(INFO, btree_generics, node,
                        "Freeing a node already freed because of crash during destroy btree.");
        }
        node->set_valid_node(false);
        m_total_nodes--;
        btree_store_t::free_node(m_btree_store.get(), node, free_blkid_list, in_mem);
    }

    /* Recovery process is different for root node, child node and sibling node depending on how the node
     * is accessed. This is the reason to create below three apis separately.
     */
    btree_status_t read_and_lock_root(bnodeid_t id, BtreeNodePtr& node_ptr, thread::locktype int_lock_type,
                                      thread::locktype leaf_lock_type, const btree_cp_ptr& bcp) {
        /* there is no recovery for root node as it is always written to a fixed bnodeid */
        return (read_and_lock_node(id, node_ptr, int_lock_type, int_lock_type, bcp));
    }

    /* It read the node, take the lock and recover it if required */
    btree_status_t read_and_lock_child(bnodeid_t child_id, BtreeNodePtr& child_node, const BtreeNodePtr& parent_node,
                                       uint32_t parent_ind, thread::locktype int_lock_type,
                                       thread::locktype leaf_lock_type, const btree_cp_ptr& bcp) {

        auto ret = read_node(child_id, child_node);
        if (child_node == nullptr) {
            if (ret != btree_status_t::fast_path_not_possible) {
                LOGERROR("read failed btree name {}, reason: {}", m_btree_cfg.get_name(), ret);
            }
            return ret;
        }

        auto is_leaf = child_node->is_leaf();
        auto acq_lock = is_leaf ? leaf_lock_type : int_lock_type;
        ret = lock_and_refresh_node(child_node, acq_lock, bcp);

        BT_DEBUG_ASSERT_CMP(is_leaf, ==, child_node->is_leaf(), child_node);

        return ret;
    }

    /* It read the node, take the lock and recover it if required */
    btree_status_t read_and_lock_sibling(bnodeid_t id, BtreeNodePtr& node_ptr, thread::locktype int_lock_type,
                                         thread::locktype leaf_lock_type, const btree_cp_ptr& bcp) {

        /* TODO: Currently we do not have any recovery while sibling is read. It is not a problem today
         * as we always scan the whole btree traversally during boot. However, we should support
         * it later.
         */
        return (read_and_lock_node(id, node_ptr, int_lock_type, int_lock_type, bcp));
    }

    /* It read the node and take a lock of the node. It doesn't recover the node.
     * @int_lock_type  :- lock type if a node is interior node.
     * @leaf_lock_type :- lock type if a node is leaf node.
     */
    btree_status_t read_and_lock_node(bnodeid_t id, BtreeNodePtr& node_ptr, thread::locktype int_lock_type,
                                      thread::locktype leaf_lock_type, const btree_cp_ptr& bcp) {
        auto ret = read_node(id, node_ptr);
        if (node_ptr == nullptr) {
            if (ret != btree_status_t::fast_path_not_possible) {
                LOGERROR("read failed btree name {}, reason: {}", m_btree_cfg.get_name(), ret);
            }
            return ret;
        }

        auto acq_lock = (node_ptr->is_leaf()) ? leaf_lock_type : int_lock_type;
        ret = lock_and_refresh_node(node_ptr, acq_lock, bcp);
        if (ret != btree_status_t::success) {
            LOGERROR("refresh failed btree name {}", m_btree_cfg.get_name());
            return ret;
        }

        return btree_status_t::success;
    }

    btree_status_t get_child_and_lock_node(const BtreeNodePtr& node, uint32_t index, BtreeNodeInfo& child_info,
                                           BtreeNodePtr& child_node, thread::locktype int_lock_type,
                                           thread::locktype leaf_lock_type, const btree_cp_ptr& bcp) {

        if (index == node->get_total_entries()) {
            const auto& edge_id{node->get_edge_id()};
            child_info.set_bnode_id(edge_id);
            // If bsearch points to last index, it means the search has not found entry unless it is an edge value.
            if (!child_info.has_valid_bnode_id()) {
                BT_LOG_ASSERT(false, node, "Child index {} does not have valid bnode_id", index);
                return btree_status_t::not_found;
            }
        } else {
            BT_LOG_ASSERT_CMP(index, <, node->get_total_entries(), node);
            node->get(index, &child_info, false /* copy */);
        }

        return (
            read_and_lock_child(child_info.bnode_id(), child_node, node, index, int_lock_type, leaf_lock_type, bcp));
    }

    btree_status_t write_node_sync(const BtreeNodePtr& node) {
        return (btree_store_t::write_node_sync(m_btree_store.get(), node));
    }

    btree_status_t write_node(const BtreeNodePtr& node, const btree_cp_ptr& bcp) {
        return (write_node(node, nullptr, bcp));
    }

    btree_status_t write_node(const BtreeNodePtr& node, const BtreeNodePtr& dependent_node, const btree_cp_ptr& bcp) {
        THIS_BT_LOG(DEBUG, btree_generics, node, "Writing node");

        COUNTER_INCREMENT_IF_ELSE(m_metrics, node->is_leaf(), btree_leaf_node_writes, btree_int_node_writes, 1);
        HISTOGRAM_OBSERVE_IF_ELSE(m_metrics, node->is_leaf(), btree_leaf_node_occupancy, btree_int_node_occupancy,
                                  ((m_node_size - node->get_available_size(m_btree_cfg)) * 100) / m_node_size);
        return (btree_store_t::write_node(m_btree_store.get(), node, dependent_node, bcp));
    }

    /* Caller of this api doesn't expect read to fail in any circumstance */
    void read_node_or_fail(bnodeid_t id, BtreeNodePtr& node) {
        auto ret = btree_store_t::read_node(m_btree_store.get(), id, node);
        BT_RELEASE_ASSERT_CMP(ret, ==, btree_status_t::success, );
    }

    btree_status_t read_node(bnodeid_t id, BtreeNodePtr& node) {
        return (btree_store_t::read_node(m_btree_store.get(), id, node));
    }

    btree_status_t _lock_and_refresh_node(const BtreeNodePtr& node, homeds::thread::locktype type,
                                          const btree_cp_ptr& bcp, const char* fname, int line) {
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

        auto ret = btree_store_t::refresh_node(m_btree_store.get(), node, is_write_modifiable, bcp);
        if (ret != btree_status_t::success) {
            node->unlock(type);
            return ret;
        }

        _start_of_lock(node, type, fname, line);
        return btree_status_t::success;
    }

    btree_status_t _lock_node_upgrade(const BtreeNodePtr& node, const btree_cp_ptr& bcp, const char* fname, int line) {
        // Explicitly dec and incr, for upgrade, since it does not call top level functions to lock/unlock node
        auto time_spent = end_of_lock(node, LOCKTYPE_READ);

        node->lock_upgrade();
#ifndef NDEBUG
        node->m_common_header.is_lock = 1;
#endif
        node->lock_acknowledge();
        auto ret = btree_store_t::refresh_node(m_btree_store.get(), node, true, bcp);
        if (ret != btree_status_t::success) {
            node->unlock(LOCKTYPE_WRITE);
            return ret;
        }

        observe_lock_time(node, LOCKTYPE_READ, time_spent);
        _start_of_lock(node, LOCKTYPE_WRITE, fname, line);
        return btree_status_t::success;
    }

    void unlock_node(const BtreeNodePtr& node, homeds::thread::locktype type) {
#ifndef NDEBUG
        if (type == homeds::thread::LOCKTYPE_WRITE) { node->m_common_header.is_lock = 0; }
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
            HISTOGRAM_OBSERVE_IF_ELSE(m_metrics, node->is_leaf(), btree_inclusive_time_in_leaf_node,
                                      btree_inclusive_time_in_int_node, time_spent);
        } else {
            HISTOGRAM_OBSERVE_IF_ELSE(m_metrics, node->is_leaf(), btree_exclusive_time_in_leaf_node,
                                      btree_exclusive_time_in_int_node, time_spent);
        }
    }

    static std::string node_info_list(std::vector< btree_locked_node_info >* pnode_infos) {
        std::stringstream ss;
        for (auto& info : *pnode_infos) {
            ss << (void*)info.node << ", ";
        }
        ss << "\n";
        return ss.str();
    }

    static void _start_of_lock(const BtreeNodePtr& node, locktype ltype, const char* fname, int line) {
        btree_locked_node_info info;

#ifndef NDEBUG
        info.fname = fname;
        info.line = line;
#endif

        info.start_time = Clock::now();
        info.node = node.get();
        if (ltype == LOCKTYPE_WRITE) {
            wr_locked_nodes.push_back(info);
            DLOGTRACEMOD(btree_generics, "ADDING node {} to write locked nodes list, its size = {}", (void*)info.node,
                         wr_locked_nodes.size());
        } else if (ltype == LOCKTYPE_READ) {
            rd_locked_nodes.push_back(info);
            DLOGTRACEMOD(btree_generics, "ADDING node {} to read locked nodes list, its size = {}", (void*)info.node,
                         rd_locked_nodes.size());
        } else {
            DEBUG_ASSERT(false, "Invalid locktype {}", ltype);
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
                             (void*)info.node, (ltype == LOCKTYPE_WRITE) ? "write" : "read", pnode_infos->size());
                return true;
            } else if (pnode_infos->size() > 1) {
                info = pnode_infos->at(pnode_infos->size() - 2);
                if (info.node == node.get()) {
                    *out_info = info;
                    pnode_infos->at(pnode_infos->size() - 2) = pnode_infos->back();
                    pnode_infos->pop_back();
                    DLOGTRACEMOD(btree_generics, "REMOVING node {} from {} locked nodes list, its size = {}",
                                 (void*)info.node, (ltype == LOCKTYPE_WRITE) ? "write" : "read", pnode_infos->size());
                    return true;
                }
            }
        }

#ifndef NDEBUG
        if (pnode_infos->empty()) {
            LOGERROR("locked_node_list: node = {} not found, locked node list empty", (void*)node.get());
        } else if (pnode_infos->size() == 1) {
            LOGERROR("locked_node_list: node = {} not found, total list count = 1, Expecting node = {}",
                     (void*)node.get(), (void*)pnode_infos->back().node);
        } else {
            LOGERROR("locked_node_list: node = {} not found, total list count = {}, Expecting nodes = {} or {}",
                     (void*)node.get(), pnode_infos->size(), (void*)pnode_infos->back().node,
                     (void*)pnode_infos->at(pnode_infos->size() - 2).node);
        }
#endif
        return false;
    }

    static uint64_t end_of_lock(const BtreeNodePtr& node, locktype ltype) {
        btree_locked_node_info info;
        if (!remove_locked_node(node, ltype, &info)) {
            DEBUG_ASSERT(false, "Expected node = {} is not there in locked_node_list", (void*)node.get());
            return 0;
        }
        // DEBUG_ASSERT_EQ(node.get(), info.node);
        return get_elapsed_time_ns(info.start_time);
    }

#ifndef NDEBUG
    static void check_lock_debug() {
        // both wr_locked_nodes and rd_locked_nodes are thread_local;
        // nothing will be dumpped if there is no assert failure;
        for (auto& x : wr_locked_nodes) {
            x.dump();
        }
        for (auto& x : rd_locked_nodes) {
            x.dump();
        }
        DEBUG_ASSERT_EQ(wr_locked_nodes.size(), 0);
        DEBUG_ASSERT_EQ(rd_locked_nodes.size(), 0);
    }
#endif

protected:
    btree_status_t create_root_node() {
        // Assign one node as root node and initially root is leaf
        BtreeNodePtr root = alloc_leaf_node();
        if (root == nullptr) { return (btree_status_t::space_not_avail); }
        m_root_node = root->get_node_id();

        auto bcp = attach_prepare_cp(nullptr, false, false);
        if (BtreeStoreType == btree_store_type::SSD_BTREE) {
            auto j_iob = btree_store_t::make_journal_entry(journal_op::BTREE_CREATE, true /* is_root */, bcp,
                                                           {m_root_node, root->get_gen()});
            btree_store_t::append_node_to_journal(j_iob, bt_journal_node_op::creation, root, bcp);
            btree_store_t::write_journal_entry(m_btree_store.get(), bcp, j_iob);
        }

        auto ret = write_node(root, nullptr, bcp);
        BT_DEBUG_ASSERT_CMP(ret, ==, btree_status_t::success, , "expecting success in writing root node");
        m_sb.root_node = m_root_node;
        /* write an entry to the journal also */
        return btree_status_t::success;
    }

    BtreeConfig* get_config() { return &m_btree_cfg; }
}; // namespace btree

// static inline const char* _type_desc(const BtreeNodePtr& n) { return n->is_leaf() ? "L" : "I"; }

template < btree_store_type BtreeStoreType, typename K, typename V, btree_node_type InteriorNodeType,
           btree_node_type LeafNodeType >
thread_local homeds::reserve_vector< btree_locked_node_info, 5 > btree_t::wr_locked_nodes;

template < btree_store_type BtreeStoreType, typename K, typename V, btree_node_type InteriorNodeType,
           btree_node_type LeafNodeType >
thread_local homeds::reserve_vector< btree_locked_node_info, 5 > btree_t::rd_locked_nodes;

#ifdef SERIALIZABLE_QUERY_IMPLEMENTATION
template < btree_store_type BtreeStoreType, typename K, typename V, btree_node_type InteriorNodeType,
           btree_node_type LeafNodeType >
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

    void push(const BtreeNodePtr& node, homeds::thread::locktype locktype) {
        m_nodes.emplace(std::make_pair<>(node, locktype));
    }

    std::pair< BtreeNodePtr, homeds::thread::locktype > pop() {
        HS_ASSERT_CMP(DEBUG, m_nodes.size(), !=, 0);
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
    btree_t m_bt;
    std::stack< std::pair< BtreeNodePtr, homeds::thread::locktype > > m_nodes;
};
#endif

} // namespace btree
} // namespace homeds
