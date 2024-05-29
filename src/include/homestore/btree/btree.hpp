/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
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
#include <iomgr/fiber_lib.hpp>

#include "btree_req.hpp"
#include "btree_kv.hpp"
#include <homestore/btree/detail/btree_internal.hpp>
#include <homestore/btree/detail/btree_node.hpp>

SISL_LOGGING_DECL(btree)

namespace homestore {

using BtreeNodePtr = boost::intrusive_ptr< BtreeNode >;
using BtreeNodeList = folly::small_vector< BtreeNodePtr, 3 >;

struct BtreeThreadVariables {
    std::vector< btree_locked_node_info > wr_locked_nodes;
    std::vector< btree_locked_node_info > rd_locked_nodes;
    BtreeNodePtr force_split_node{nullptr};
};

struct BTREE_FLIPS {
    static constexpr uint32_t INDEX_PARENT_NON_ROOT = 1 << 0;
    static constexpr uint32_t INDEX_PARENT_ROOT = 1 << 1;
    static constexpr uint32_t INDEX_LEFT_SIBLING = 1 << 2;
    static constexpr uint32_t INDEX_RIGHT_SIBLING = 1 << 3;

    uint32_t flips;
    BTREE_FLIPS() : flips{0} {}
    std::string list() const {
        std::string str;
        if (flips & INDEX_PARENT_NON_ROOT) { str += "index_parent_non_root,"; }
        if (flips & INDEX_PARENT_ROOT) { str += "index_parent_root,"; }
        if (flips & INDEX_LEFT_SIBLING) { str += "index_left_sibling,"; }
        if (flips & INDEX_RIGHT_SIBLING) { str += "index_right_sibling,"; }
        return str;
    }
    void set_flip(uint32_t flip) { flips |= flip; }
    void set_flip(std::string flip) {
        if (flip == "index_parent_non_root") { set_flip(INDEX_PARENT_NON_ROOT); }
        if (flip == "index_parent_root") { set_flip(INDEX_PARENT_ROOT); }
        if (flip == "index_left_sibling") { set_flip(INDEX_LEFT_SIBLING); }
        if (flip == "index_right_sibling") { set_flip(INDEX_RIGHT_SIBLING); }
    }
};

template < typename K, typename V >
class Btree {
protected:
    mutable iomgr::FiberManagerLib::shared_mutex m_btree_lock;
    BtreeLinkInfo m_root_node_info;

    BtreeMetrics m_metrics;
    std::atomic< bool > m_destroyed{false};
    std::atomic< uint64_t > m_total_nodes{0};
    uint32_t m_node_size{4096};
#ifndef NDEBUG
    std::atomic< uint64_t > m_req_id{0};
#endif
#ifdef _PRERELEASE
    BTREE_FLIPS m_flips;
#endif
    // This workaround of BtreeThreadVariables is needed instead of directly declaring statics
    // to overcome the gcc bug, pointer here: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=66944
    static BtreeThreadVariables* bt_thread_vars() {
        auto this_id(boost::this_fiber::get_id());
        static thread_local std::map< boost::fibers::fiber::id, std::unique_ptr< BtreeThreadVariables > > fiber_map;
        if (fiber_map.count(this_id)) { return fiber_map[this_id].get(); }
        fiber_map[this_id] = std::make_unique< BtreeThreadVariables >();
        return fiber_map[this_id].get();
    }

protected:
    BtreeConfig m_bt_cfg;

public:
    /////////////////////////////////////// All External APIs /////////////////////////////
    Btree(const BtreeConfig& cfg);
    virtual ~Btree();

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

    void print_tree(const std::string& file = "") const;
    void print_tree_keys() const;
    uint64_t count_keys(bnodeid_t bnodeid) const;

    nlohmann::json get_metrics_in_json(bool updated = true);
    bnodeid_t root_node_id() const;

    uint64_t root_link_version() const;
    void set_root_node_info(const BtreeLinkInfo& info);

    // static void set_io_flip();
    // static void set_error_flip();
#ifdef _PRERELEASE
    void set_flip_point(std::string flip) { m_flips.set_flip(flip); }
    void set_flips(std::vector< std::string > flips) {
        for (const auto& flip : flips) {
            set_flip_point(flip);
        }
    }
    std::string flip_list() const { return m_flips.list(); }
#endif

protected:
    /////////////////////////// Methods the underlying store is expected to handle ///////////////////////////
    virtual BtreeNodePtr alloc_node(bool is_leaf) = 0;
    virtual BtreeNode* init_node(uint8_t* node_buf, bnodeid_t id, bool init_buf, bool is_leaf) const;
    virtual btree_status_t read_node_impl(bnodeid_t id, BtreeNodePtr& node) const = 0;
    virtual btree_status_t write_node_impl(const BtreeNodePtr& node, void* context) = 0;
    virtual btree_status_t refresh_node(const BtreeNodePtr& node, bool for_read_modify_write, void* context) const = 0;
    virtual void free_node_impl(const BtreeNodePtr& node, void* context) = 0;
    virtual btree_status_t transact_nodes(const BtreeNodeList& new_nodes, const BtreeNodeList& freed_nodes,
                                          const BtreeNodePtr& left_child_node, const BtreeNodePtr& parent_node,
                                          void* context) = 0;
    virtual btree_status_t on_root_changed(BtreeNodePtr const& root, void* context) = 0;
    virtual std::string btree_store_type() const = 0;

    /////////////////////////// Methods the application use case is expected to handle ///////////////////////////

protected:
    btree_status_t create_root_node(void* op_context);

    /////////////////////////////// Internal Node Management Methods ////////////////////////////////////
    btree_status_t read_and_lock_node(bnodeid_t id, BtreeNodePtr& node_ptr, locktype_t int_lock_type,
                                      locktype_t leaf_lock_type, void* context) const;
    void read_node_or_fail(bnodeid_t id, BtreeNodePtr& node) const;
    btree_status_t write_node(const BtreeNodePtr& node, void* context);
    void free_node(const BtreeNodePtr& node, locktype_t cur_lock, void* context);
    BtreeNodePtr alloc_leaf_node();
    BtreeNodePtr alloc_interior_node();

    btree_status_t get_child_and_lock_node(const BtreeNodePtr& node, uint32_t index, BtreeLinkInfo& child_info,
                                           BtreeNodePtr& child_node, locktype_t int_lock_type,
                                           locktype_t leaf_lock_type, void* context) const;
    btree_status_t upgrade_node_locks(const BtreeNodePtr& parent_node, const BtreeNodePtr& child_node,
                                      locktype_t& parent_cur_lock, locktype_t& child_cur_lock, void* context);
    btree_status_t upgrade_node_lock(const BtreeNodePtr& node, locktype_t& cur_lock, void* context);
    btree_status_t _lock_node(const BtreeNodePtr& node, locktype_t type, void* context, const char* fname,
                              int line) const;
    void unlock_node(const BtreeNodePtr& node, locktype_t type) const;

    std::pair< btree_status_t, uint64_t > do_destroy();
    void observe_lock_time(const BtreeNodePtr& node, locktype_t type, uint64_t time_spent) const;

    static void _start_of_lock(const BtreeNodePtr& node, locktype_t ltype, const char* fname, int line);
    static bool remove_locked_node(const BtreeNodePtr& node, locktype_t ltype, btree_locked_node_info* out_info);
    static uint64_t end_of_lock(const BtreeNodePtr& node, locktype_t ltype);
    bool can_extents_auto_merge() const { return true; } // TODO: Make this rcu and dynamically settable

#ifndef NDEBUG
    static void check_lock_debug();
#endif

    /////////////////////////////////// Helper Methods ///////////////////////////////////////
    btree_status_t post_order_traversal(locktype_t acq_lock, const auto& cb);
    btree_status_t post_order_traversal(const BtreeNodePtr& node, locktype_t acq_lock, const auto& cb);
    void get_all_kvs(std::vector< std::pair< K, V > >& kvs) const;
    btree_status_t do_destroy(uint64_t& n_freed_nodes, void* context);
    uint64_t get_btree_node_cnt() const;
    uint64_t get_child_node_cnt(bnodeid_t bnodeid) const;
    void to_string(bnodeid_t bnodeid, std::string& buf) const;
    void to_string_keys(bnodeid_t bnodeid, std::string& buf) const;
    void validate_sanity_child(const BtreeNodePtr& parent_node, uint32_t ind) const;
    void validate_sanity_next_child(const BtreeNodePtr& parent_node, uint32_t ind) const;
    void print_node(const bnodeid_t& bnodeid) const;

    void append_route_trace(BtreeRequest& req, const BtreeNodePtr& node, btree_event_t event, uint32_t start_idx = 0,
                            uint32_t end_idx = 0) const;

    //////////////////////////////// Impl Methods //////////////////////////////////////////

    ///////// Mutate Impl Methods
    template < typename ReqT >
    btree_status_t do_put(const BtreeNodePtr& my_node, locktype_t curlock, ReqT& req);

    template < typename ReqT >
    btree_status_t mutate_write_leaf_node(const BtreeNodePtr& my_node, ReqT& req);

    template < typename ReqT >
    btree_status_t check_split_root(ReqT& req);

    template < typename ReqT >
    bool is_split_needed(const BtreeNodePtr& node, ReqT& req) const;

    btree_status_t split_node(const BtreeNodePtr& parent_node, const BtreeNodePtr& child_node, uint32_t parent_ind,
                              K* out_split_key, void* context);
    btree_status_t mutate_extents_in_leaf(const BtreeNodePtr& my_node, BtreeRangePutRequest< K >& rpreq);

    ///////// Remove Impl Methods
    template < typename ReqT >
    btree_status_t check_collapse_root(ReqT& rreq);

    template < typename ReqT >
    btree_status_t do_remove(const BtreeNodePtr& my_node, locktype_t curlock, ReqT& rreq);

    btree_status_t merge_nodes(const BtreeNodePtr& parent_node, const BtreeNodePtr& leftmost_node, uint32_t start_indx,
                               uint32_t end_indx, void* context);
    bool remove_extents_in_leaf(const BtreeNodePtr& node, BtreeRangeRemoveRequest< K >& rrreq);

    ///////// Query Impl Methods
    btree_status_t do_sweep_query(BtreeNodePtr& my_node, BtreeQueryRequest< K >& qreq,
                                  std::vector< std::pair< K, V > >& out_values) const;
    btree_status_t do_traversal_query(const BtreeNodePtr& my_node, BtreeQueryRequest< K >& qreq,
                                      std::vector< std::pair< K, V > >& out_values) const;
#ifdef SERIALIZABLE_QUERY_IMPLEMENTATION
    btree_status_t do_serialzable_query(const BtreeNodePtr& my_node, BtreeSerializableQueryRequest& qreq,
                                        std::vector< std::pair< K, V > >& out_values);
    btree_status_t sweep_query(BtreeQueryRequest< K >& qreq, std::vector< std::pair< K, V > >& out_values);
    btree_status_t serializable_query(BtreeSerializableQueryRequest& qreq,
                                      std::vector< std::pair< K, V > >& out_values);
#endif

    ///////// Get Impl Methods
    template < typename ReqT >
    btree_status_t do_get(const BtreeNodePtr& my_node, ReqT& greq) const;
};
} // namespace homestore
