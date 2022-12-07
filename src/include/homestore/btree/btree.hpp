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

#include <atomic>
#include <array>

#include <boost/intrusive_ptr.hpp>
#include <folly/small_vector.h>

#include "btree_req.hpp"
#include "btree_kv.hpp"
#include <homestore/btree/detail/btree_internal.hpp>
#include <homestore/btree/detail/btree_node.hpp>

namespace homestore {

typedef std::function< bool(const BtreeKey&, const BtreeValue&, const BtreeRequest&) > on_kv_read_t;
typedef std::function< bool(const BtreeKey&, const BtreeValue&, const BtreeRequest&) > on_kv_remove_t;
typedef std::function< bool(const BtreeKey&, const BtreeKey&, const BtreeValue&, const BtreeRequest&) > on_kv_update_t;

#ifdef INCASE_WE_NEED_COMMON
template < typename K, typename V >
class BtreeCommon {
public:
    void deref_node(BtreeNode< K >* node) = 0;
};
#endif

template < typename K >
using BtreeNodePtr = boost::intrusive_ptr< BtreeNode< K > >;

template < typename K, typename V >
struct BtreeThreadVariables {
    std::vector< btree_locked_node_info< K, V > > wr_locked_nodes;
    std::vector< btree_locked_node_info< K, V > > rd_locked_nodes;
    BtreeNodePtr< K > force_split_node{nullptr};
};

template < typename K >
void intrusive_ptr_add_ref(BtreeNode< K >* node);

template < typename K >
void intrusive_ptr_release(BtreeNode< K >* node);

template < typename K, typename V >
class Btree {
private:
    mutable folly::SharedMutexWritePriority m_btree_lock;
    BtreeLinkInfo m_root_node_info;

    BtreeMetrics m_metrics;
    std::atomic< bool > m_destroyed{false};
    std::atomic< uint64_t > m_total_nodes{0};
    uint32_t m_node_size{4096};
#ifndef NDEBUG
    std::atomic< uint64_t > m_req_id{0};
#endif

    // Optional callback on various read or kv operations
    on_kv_read_t m_on_read_cb{nullptr};
    on_kv_update_t m_on_update_cb{nullptr};
    on_kv_remove_t m_on_remove_cb{nullptr};

    // This workaround of BtreeThreadVariables is needed instead of directly declaring statics
    // to overcome the gcc bug, pointer here: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=66944
    static BtreeThreadVariables< K, V >* bt_thread_vars() {
        static thread_local BtreeThreadVariables< K, V >* s_ptr{nullptr};
        if (s_ptr == nullptr) {
            static thread_local BtreeThreadVariables< K, V > inst;
            s_ptr = &inst;
        }
        return s_ptr;
    }

protected:
    BtreeConfig m_bt_cfg;

public:
    /////////////////////////////////////// All External APIs /////////////////////////////
    Btree(const BtreeConfig& cfg, on_kv_read_t&& read_cb = nullptr, on_kv_update_t&& update_cb = nullptr,
          on_kv_remove_t&& remove_cb = nullptr);
    virtual ~Btree();
    virtual btree_status_t init(void* op_context);

    template < typename ReqT >
    btree_status_t put(ReqT& put_req);

    template < typename ReqT >
    btree_status_t get(ReqT& get_req) const;

    template < typename ReqT >
    btree_status_t remove(ReqT& rreq);

    btree_status_t query(BtreeQueryRequest< K >& query_req, std::vector< std::pair< K, V > >& out_values) const;

    // bool verify_tree(bool update_debug_bm) const;
    virtual std::pair< btree_status_t, uint64_t > destroy_btree(void* context);
    nlohmann::json get_status(int log_level) const;
    void print_tree() const;
    nlohmann::json get_metrics_in_json(bool updated = true);

    // static void set_io_flip();
    // static void set_error_flip();

    // static std::array< std::shared_ptr< BtreeCommon< K, V > >, sizeof(btree_stores_t) > s_btree_stores;
    // static std::mutex s_store_reg_mtx;

protected:
    /////////////////////////// Methods the underlying store is expected to handle ///////////////////////////
    virtual BtreeNodePtr< K > alloc_node(bool is_leaf) = 0;
    virtual BtreeNode< K >* init_node(uint8_t* node_buf, bnodeid_t id, bool init_buf, bool is_leaf);
    virtual btree_status_t read_node_impl(bnodeid_t id, BtreeNodePtr< K >& node) const = 0;
    virtual btree_status_t write_node_impl(const BtreeNodePtr< K >& node, void* context) = 0;
    virtual btree_status_t refresh_node(const BtreeNodePtr< K >& node, bool for_read_modify_write,
                                        void* context) const = 0;
    virtual void free_node_impl(const BtreeNodePtr< K >& node, void* context) = 0;
    virtual btree_status_t prepare_node_txn(const BtreeNodePtr< K >& parent_node, const BtreeNodePtr< K >& child_node,
                                            void* context) = 0;
    virtual btree_status_t transact_write_nodes(const folly::small_vector< BtreeNodePtr< K >, 3 >& new_nodes,
                                                const BtreeNodePtr< K >& child_node,
                                                const BtreeNodePtr< K >& parent_node, void* context) = 0;

    /*virtual void create_tree_precommit(const BtreeNodePtr< K >& root_node, void* op_context) = 0;
     virtual void split_node_precommit(const BtreeNodePtr< K >& parent_node, const BtreeNodePtr< K >& child_node1,
                                       const BtreeNodePtr< K >& child_node2, bool root_split, bool edge_split,
                                       void* op_context) = 0;
     virtual void merge_node_precommit(bool is_root_merge, const BtreeNodePtr< K >& parent_node,
                                       uint32_t parent_merge_start_idx, const BtreeNodePtr< K >& child_node1,
                                       const std::vector< BtreeNodePtr< K > >* old_child_nodes,
                                       const std::vector< BtreeNodePtr< K > >* replace_child_nodes,
                                       void* op_context) = 0; */
    virtual std::string btree_store_type() const = 0;

    /////////////////////////// Methods the application use case is expected to handle ///////////////////////////

protected:
    btree_status_t create_root_node(void* op_context);

    /////////////////////////////// Internal Node Management Methods ////////////////////////////////////
    btree_status_t read_and_lock_node(bnodeid_t id, BtreeNodePtr< K >& node_ptr, locktype_t int_lock_type,
                                      locktype_t leaf_lock_type, void* context) const;
    void read_node_or_fail(bnodeid_t id, BtreeNodePtr< K >& node) const;
    btree_status_t write_node(const BtreeNodePtr< K >& node, void* context);
    void free_node(const BtreeNodePtr< K >& node, locktype_t cur_lock, void* context);
    BtreeNodePtr< K > alloc_leaf_node();
    BtreeNodePtr< K > alloc_interior_node();

    btree_status_t get_child_and_lock_node(const BtreeNodePtr< K >& node, uint32_t index, BtreeLinkInfo& child_info,
                                           BtreeNodePtr< K >& child_node, locktype_t int_lock_type,
                                           locktype_t leaf_lock_type, void* context) const;
    btree_status_t upgrade_node_locks(const BtreeNodePtr< K >& parent_node, const BtreeNodePtr< K >& child_node,
                                      locktype_t parent_cur_lock, locktype_t child_cur_lock, void* context);
    btree_status_t upgrade_node(const BtreeNodePtr< K >& node, locktype_t prev_lock, void* context, uint64_t prev_gen);
    btree_status_t _lock_node(const BtreeNodePtr< K >& node, locktype_t type, void* context, const char* fname,
                              int line) const;
    void unlock_node(const BtreeNodePtr< K >& node, locktype_t type) const;

    std::pair< btree_status_t, uint64_t > do_destroy();
    void observe_lock_time(const BtreeNodePtr< K >& node, locktype_t type, uint64_t time_spent) const;

    static void _start_of_lock(const BtreeNodePtr< K >& node, locktype_t ltype, const char* fname, int line);
    static bool remove_locked_node(const BtreeNodePtr< K >& node, locktype_t ltype,
                                   btree_locked_node_info< K, V >* out_info);
    static uint64_t end_of_lock(const BtreeNodePtr< K >& node, locktype_t ltype);
    bool can_extents_auto_merge() const { return true; } // TODO: Make this rcu and dynamically settable

#ifndef NDEBUG
    static void check_lock_debug();
#endif

    /////////////////////////////////// Helper Methods ///////////////////////////////////////
    btree_status_t post_order_traversal(locktype_t acq_lock, const auto& cb);
    btree_status_t post_order_traversal(const BtreeNodePtr< K >& node, locktype_t acq_lock, const auto& cb);
    void get_all_kvs(std::vector< pair< K, V > >& kvs) const;
    btree_status_t do_destroy(uint64_t& n_freed_nodes, void* context);
    uint64_t get_btree_node_cnt() const;
    uint64_t get_child_node_cnt(bnodeid_t bnodeid) const;
    void to_string(bnodeid_t bnodeid, std::string& buf) const;
    void validate_sanity_child(const BtreeNodePtr< K >& parent_node, uint32_t ind) const;
    void validate_sanity_next_child(const BtreeNodePtr< K >& parent_node, uint32_t ind) const;
    void print_node(const bnodeid_t& bnodeid) const;
    bool call_on_read_kv_cb(const BtreeNodePtr< K >& node, uint32_t idx, const BtreeRequest& req) const;
    bool call_on_remove_kv_cb(const BtreeNodePtr< K >& node, uint32_t idx, const BtreeRequest& req) const;
    bool call_on_update_kv_cb(const BtreeNodePtr< K >& node, uint32_t idx, const BtreeKey& new_key,
                              const BtreeRequest& req) const;

    //////////////////////////////// Impl Methods //////////////////////////////////////////

    ///////// Mutate Impl Methods
    template < typename ReqT >
    btree_status_t do_put(const BtreeNodePtr< K >& my_node, locktype_t curlock, ReqT& req);

    template < typename ReqT >
    btree_status_t mutate_write_leaf_node(const BtreeNodePtr< K >& my_node, ReqT& req);

    template < typename ReqT >
    btree_status_t check_split_root(ReqT& req);

    template < typename ReqT >
    bool is_split_needed(const BtreeNodePtr< K >& node, const BtreeConfig& cfg, ReqT& req) const;

    btree_status_t split_node(const BtreeNodePtr< K >& parent_node, const BtreeNodePtr< K >& child_node,
                              uint32_t parent_ind, BtreeKey* out_split_key, void* context);
    btree_status_t mutate_extents_in_leaf(const BtreeNodePtr< K >& my_node, BtreeRangePutRequest< K >& rpreq);
    btree_status_t repair_split(const BtreeNodePtr< K >& parent_node, const BtreeNodePtr< K >& child_node1,
                                uint32_t parent_split_idx, void* context);

    ///////// Remove Impl Methods
    template < typename ReqT >
    btree_status_t check_collapse_root(ReqT& rreq);

    template < typename ReqT >
    btree_status_t do_remove(const BtreeNodePtr< K >& my_node, locktype_t curlock, ReqT& rreq);

    btree_status_t merge_nodes(const BtreeNodePtr< K >& parent_node, const BtreeNodePtr< K >& leftmost_node,
                               uint32_t start_indx, uint32_t end_indx, void* context);
    bool remove_extents_in_leaf(const BtreeNodePtr< K >& node, BtreeRangeRemoveRequest< K >& rrreq);
    btree_status_t repair_merge(const BtreeNodePtr< K >& parent_node, const BtreeNodePtr< K >& left_child,
                                uint32_t parent_merge_idx, void* context);

    ///////// Query Impl Methods
    btree_status_t do_sweep_query(BtreeNodePtr< K >& my_node, BtreeQueryRequest< K >& qreq,
                                  std::vector< std::pair< K, V > >& out_values) const;
    btree_status_t do_traversal_query(const BtreeNodePtr< K >& my_node, BtreeQueryRequest< K >& qreq,
                                      std::vector< std::pair< K, V > >& out_values) const;
#ifdef SERIALIZABLE_QUERY_IMPLEMENTATION
    btree_status_t do_serialzable_query(const BtreeNodePtr< K >& my_node, BtreeSerializableQueryRequest& qreq,
                                        std::vector< std::pair< K, V > >& out_values);
    btree_status_t sweep_query(BtreeQueryRequest< K >& qreq, std::vector< std::pair< K, V > >& out_values);
    btree_status_t serializable_query(BtreeSerializableQueryRequest& qreq,
                                      std::vector< std::pair< K, V > >& out_values);
#endif

    ///////// Get Impl Methods
    template < typename ReqT >
    btree_status_t do_get(const BtreeNodePtr< K >& my_node, ReqT& greq) const;
};
} // namespace homestore
