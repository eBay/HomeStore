/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 * Author/Developer(s): Harihara Kadayam, Rishabh Mittal
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
#pragma once

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <boost/intrusive_ptr.hpp>
//#include <flip/flip.hpp>
#include <sisl/logging/logging.h>
#include <sisl/fds/buffer.hpp>

#include "btree/btree.hpp"
#include "btree/detail/btree_common.ipp"
#include "btree/detail/btree_node_mgr.ipp"
#include "btree/detail/btree_mutate_impl.ipp"
#include "btree/detail/btree_query_impl.ipp"
#include "btree/detail/btree_get_impl.ipp"
#include "btree/detail/btree_remove_impl.ipp"
#include "btree/detail/btree_node.hpp"

SISL_LOGGING_DECL(btree)
namespace homestore {
#if 0
#define container_of(ptr, type, member) ({ (type*)((char*)ptr - offsetof(type, member)); })
#endif

template < typename K, typename V >
Btree< K, V >::Btree(const BtreeConfig& cfg, on_kv_read_t&& read_cb, on_kv_update_t&& update_cb,
                     on_kv_remove_t&& remove_cb) :
        m_metrics{cfg.name().c_str()},
        m_node_size{cfg.node_size()},
        m_on_read_cb{std::move(read_cb)},
        m_on_update_cb{std::move(update_cb)},
        m_on_remove_cb{std::move(remove_cb)},
        m_bt_cfg{cfg} {
    m_bt_cfg.set_node_data_size(cfg.node_size() - sizeof(persistent_hdr_t));
}

template < typename K, typename V >
Btree< K, V >::~Btree() = default;

template < typename K, typename V >
btree_status_t Btree< K, V >::init(void* op_context) {
    return create_root_node(op_context);
}

template < typename K, typename V >
std::pair< btree_status_t, uint64_t > Btree< K, V >::destroy_btree(void* context) {
    btree_status_t ret{btree_status_t::success};
    uint64_t n_freed_nodes{0};

    bool expected = false;
    if (!m_destroyed.compare_exchange_strong(expected, true)) {
        BT_LOG(DEBUG, "Btree is already being destroyed, ignorining this request");
        return std::make_pair(btree_status_t::not_found, 0);
    }
    ret = do_destroy(n_freed_nodes, context);
    if (ret == btree_status_t::success) {
        BT_LOG(DEBUG, "btree(root: {}) {} nodes destroyed successfully", m_root_node_info.bnode_id(), n_freed_nodes);
    } else {
        m_destroyed = false;
        BT_LOG(ERROR, "btree(root: {}) nodes destroyed failed, ret: {}", m_root_node_info.bnode_id(), ret);
    }

    return std::make_pair(ret, n_freed_nodes);
}

template < typename K, typename V >
template < typename ReqT >
btree_status_t Btree< K, V >::put(ReqT& put_req) {
    static_assert(std::is_same_v< ReqT, BtreeSinglePutRequest > || std::is_same_v< ReqT, BtreeRangePutRequest< K > >,
                  "put api is called with non put request type");
    COUNTER_INCREMENT(m_metrics, btree_write_ops_count, 1);
    auto acq_lock = locktype_t::READ;
    bool is_leaf = false;

    m_btree_lock.lock_shared();
    btree_status_t ret = btree_status_t::success;

retry:
#ifndef NDEBUG
    check_lock_debug();
#endif
    BT_LOG_ASSERT_EQ(bt_thread_vars()->rd_locked_nodes.size(), 0);
    BT_LOG_ASSERT_EQ(bt_thread_vars()->wr_locked_nodes.size(), 0);

    BtreeNodePtr< K > root;
    ret = read_and_lock_node(m_root_node_info.bnode_id(), root, acq_lock, acq_lock, put_req.m_op_context);
    if (ret != btree_status_t::success) { goto out; }
    is_leaf = root->is_leaf();

    if (is_split_needed(root, m_bt_cfg, put_req)) {
        // Time to do the split of root.
        unlock_node(root, acq_lock);
        m_btree_lock.unlock_shared();
        ret = check_split_root(put_req);
        BT_LOG_ASSERT_EQ(bt_thread_vars()->rd_locked_nodes.size(), 0);
        BT_LOG_ASSERT_EQ(bt_thread_vars()->wr_locked_nodes.size(), 0);

        // We must have gotten a new root, need to start from scratch.
        m_btree_lock.lock_shared();
        if (ret != btree_status_t::success) {
            LOGERROR("root split failed btree name {}", m_bt_cfg.name());
            goto out;
        }

        goto retry;
    } else if ((is_leaf) && (acq_lock != locktype_t::WRITE)) {
        // Root is a leaf, need to take write lock, instead of read, retry
        unlock_node(root, acq_lock);
        acq_lock = locktype_t::WRITE;
        goto retry;
    } else {
        ret = do_put(root, acq_lock, put_req);
        if ((ret == btree_status_t::retry) || (ret == btree_status_t::has_more)) {
            // Need to start from top down again, since there was a split or we have more to insert in case of range put
            acq_lock = locktype_t::READ;
            BT_LOG(TRACE, "retrying put operation");
            BT_LOG_ASSERT_EQ(bt_thread_vars()->rd_locked_nodes.size(), 0);
            BT_LOG_ASSERT_EQ(bt_thread_vars()->wr_locked_nodes.size(), 0);
            goto retry;
        }
    }

out:
    m_btree_lock.unlock_shared();
#ifndef NDEBUG
    check_lock_debug();
#endif
    if (ret != btree_status_t::success && ret != btree_status_t::fast_path_not_possible &&
        ret != btree_status_t::cp_mismatch) {
        BT_LOG(ERROR, "btree put failed {}", ret);
        COUNTER_INCREMENT(m_metrics, write_err_cnt, 1);
    }

    return ret;
}

template < typename K, typename V >
template < typename ReqT >
btree_status_t Btree< K, V >::get(ReqT& greq) const {
    static_assert(std::is_same_v< BtreeSingleGetRequest, ReqT > || std::is_same_v< BtreeGetAnyRequest< K >, ReqT >,
                  "get api is called with non get request type");

    btree_status_t ret = btree_status_t::success;

    m_btree_lock.lock_shared();
    BtreeNodePtr< K > root;

    ret = read_and_lock_node(m_root_node_info.bnode_id(), root, locktype_t::READ, locktype_t::READ, greq.m_op_context);
    if (ret != btree_status_t::success) { goto out; }

    ret = do_get(root, greq);
out:
    m_btree_lock.unlock_shared();

#ifndef NDEBUG
    check_lock_debug();
#endif
    return ret;
}

template < typename K, typename V >
template < typename ReqT >
btree_status_t Btree< K, V >::remove(ReqT& req) {
    static_assert(std::is_same_v< ReqT, BtreeSingleRemoveRequest > ||
                      std::is_same_v< ReqT, BtreeRangeRemoveRequest< K > > ||
                      std::is_same_v< ReqT, BtreeRemoveAnyRequest< K > >,
                  "remove api is called with non remove request type");

    locktype_t acq_lock = locktype_t::READ;
    m_btree_lock.lock_shared();

retry:
    btree_status_t ret = btree_status_t::success;
    BtreeNodePtr< K > root;
    ret = read_and_lock_node(m_root_node_info.bnode_id(), root, acq_lock, acq_lock, req.m_op_context);
    if (ret != btree_status_t::success) { goto out; }

    if (root->total_entries() == 0) {
        if (root->is_leaf()) {
            // There are no entries in btree.
            unlock_node(root, acq_lock);
            m_btree_lock.unlock_shared();
            ret = btree_status_t::not_found;
            goto out;
        }

        BT_NODE_LOG_ASSERT_EQ(root->has_valid_edge(), true, root, "Orphaned root with no entries and edge");
        unlock_node(root, acq_lock);
        m_btree_lock.unlock_shared();

        ret = check_collapse_root(req);
        if (ret != btree_status_t::success) {
            LOGERROR("check collapse read failed btree name {}", m_bt_cfg.name());
            goto out;
        }

        // We must have gotten a new root, need to start from scratch.
        m_btree_lock.lock_shared();
        goto retry;
    } else if (root->is_leaf() && (acq_lock != locktype_t::WRITE)) {
        // Root is a leaf, need to take write lock, instead of read, retry
        unlock_node(root, acq_lock);
        acq_lock = locktype_t::WRITE;
        goto retry;
    } else {
        ret = do_remove(root, acq_lock, req);
        if (ret == btree_status_t::retry) {
            // Need to start from top down again, since there was a merge nodes in-between
            acq_lock = locktype_t::READ;
            goto retry;
        }
    }
    m_btree_lock.unlock_shared();

out:
#ifndef NDEBUG
    check_lock_debug();
#endif
    return ret;
}

template < typename K, typename V >
btree_status_t Btree< K, V >::query(BtreeQueryRequest< K >& qreq, std::vector< std::pair< K, V > >& out_values) const {
    COUNTER_INCREMENT(m_metrics, btree_query_ops_count, 1);

    btree_status_t ret = btree_status_t::success;
    if (qreq.batch_size() == 0) { return ret; }

    m_btree_lock.lock_shared();
    BtreeNodePtr< K > root = nullptr;
    ret = read_and_lock_node(m_root_node_info.bnode_id(), root, locktype_t::READ, locktype_t::READ, qreq.m_op_context);
    if (ret != btree_status_t::success) { goto out; }

    switch (qreq.query_type()) {
    case BtreeQueryType::SWEEP_NON_INTRUSIVE_PAGINATION_QUERY:
        ret = do_sweep_query(root, qreq, out_values);
        break;

    case BtreeQueryType::TREE_TRAVERSAL_QUERY:
        ret = do_traversal_query(root, qreq, out_values);
        break;

    default:
        unlock_node(root, locktype_t::READ);
        LOGERROR("Query type {} is not supported yet", qreq.query_type());
        break;
    }

    if ((qreq.query_type() == BtreeQueryType::SWEEP_NON_INTRUSIVE_PAGINATION_QUERY ||
         qreq.query_type() == BtreeQueryType::TREE_TRAVERSAL_QUERY) &&
        out_values.size() > 0) {

        /* if return is not success then set the cursor to last read. No need to set cursor if user is not
         * interested in it.
         */
        qreq.set_cursor_key(out_values.back().first);

        /* check if we finished just at the last key */
        if (out_values.back().first.compare(qreq.input_range().end_key()) == 0) { ret = btree_status_t::success; }
    }

out:
    m_btree_lock.unlock_shared();
#ifndef NDEBUG
    check_lock_debug();
#endif
    if (ret != btree_status_t::success && ret != btree_status_t::has_more &&
        ret != btree_status_t::fast_path_not_possible) {
        BT_LOG(ERROR, "btree query failed {}", ret);
        COUNTER_INCREMENT(m_metrics, query_err_cnt, 1);
    }
    return ret;
}

#if 0
/**
 * @brief : verify btree is consistent and no corruption;
 *
 * @param update_debug_bm : true or false;
 *
 * @return : true if btree is not corrupted.
 *           false if btree is corrupted;
 */
template < typename K, typename V >
bool Btree< K, V >::verify_tree(bool update_debug_bm) const {
    m_btree_lock.lock_shared();
    bool ret = verify_node(m_root_node_info.bnode_id(), nullptr, -1, update_debug_bm);
    m_btree_lock.unlock_shared();

    return ret;
}
#endif

/**
 * @brief : get the status of this btree;
 *
 * @param log_level : verbosity level;
 *
 * @return : status in json form;
 */
template < typename K, typename V >
nlohmann::json Btree< K, V >::get_status(int log_level) const {
    nlohmann::json j;
    return j;
}

template < typename K, typename V >
void Btree< K, V >::print_tree() const {
    std::string buf;
    m_btree_lock.lock_shared();
    to_string(m_root_node_info.bnode_id(), buf);
    m_btree_lock.unlock_shared();

    BT_LOG(INFO, "Pre order traversal of tree:\n<{}>", buf);
}

template < typename K, typename V >
nlohmann::json Btree< K, V >::get_metrics_in_json(bool updated) {
    return m_metrics.get_result_in_json(updated);
}

// TODO: Commenting out flip till we figure out how to move flip dependency inside sisl package.
#if 0
#ifdef _PRERELEASE
template < typename K, typename V >
static void Btree< K, V >::set_io_flip() {
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

template < typename K, typename V >
static void Btree< K, V >::set_error_flip() {
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
#endif

template < typename K >
void intrusive_ptr_add_ref(BtreeNode< K >* node) {
    node->m_refcount.increment(1);
}

template < typename K >
void intrusive_ptr_release(BtreeNode< K >* node) {
    if (node->m_refcount.decrement_testz(1)) { delete node; }
}

#ifdef INCASE_WE_NEED_COMMON
template < typename K, typename V >
bool Btree< K, V >::create_store_common(btree_store_t store_type,
                                        std::function< std::shared_ptr< BtreeCommon< K, V > >() >&& create_cb) {
    std::unique_lock lg(s_store_reg_mtx);
    if (s_btree_stores[int_cast(store_type)] != nullptr) { return false; }
    s_btree_stores[int_cast(store_type)] = create_cb();
    return true;
}

// Get doesn't need to take any lock, since the create/register is once and started once. Please don't add the lock
// here as this is called in critical path and completely unneccessary.
template < typename K, typename V >
BtreeCommon< K, V >* Btree< K, V >::get_store_common(uint8_t store_type) {
    return s_btree_stores[store_type].get();
}

friend void intrusive_ptr_add_ref(BtreeNode< K >* node) { node->m_refcount.increment(1); }
friend void intrusive_ptr_release(BtreeNode< K >* node) { Btree< K, V >::get_store_common()->deref_node(node); }

// static inline const char* _type_desc(const BtreeNodePtr< K >& n) { return n->is_leaf() ? "L" : "I"; }

template < typename K, typename V >
std::array< std::shared_ptr< BtreeCommon< K, V > >, sizeof(btree_stores_t) > Btree< K, V >::s_btree_stores;

template < typename K, typename V >
std::mutex Btree< K, V >::s_store_reg_mtx;
#endif

} // namespace homestore
