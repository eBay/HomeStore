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

#include <boost/preprocessor/control/if.hpp>
#include <boost/preprocessor/facilities/empty.hpp>
#include <boost/preprocessor/facilities/identity.hpp>
#include <boost/vmd/is_empty.hpp>
#include <sisl/fds/utils.hpp>
#include <sisl/metrics/metrics.hpp>

namespace homestore {

#define _BT_LOG_METHOD_IMPL(req, btcfg, node)                                                                          \
    ([&](fmt::memory_buffer& buf, const char* msgcb, auto&&... args) -> bool {                                         \
        fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}:{}] "},                                              \
                        fmt::make_format_args(file_name(__FILE__), __LINE__));                                         \
        BOOST_PP_IF(BOOST_VMD_IS_EMPTY(req), BOOST_PP_EMPTY,                                                           \
                    BOOST_PP_IDENTITY(fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[req={}] "},               \
                                                      fmt::make_format_args(req->to_string()))))                       \
        ();                                                                                                            \
        BOOST_PP_IF(BOOST_VMD_IS_EMPTY(btcfg), BOOST_PP_EMPTY,                                                         \
                    BOOST_PP_IDENTITY(fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[btree={}] "},             \
                                                      fmt::make_format_args(btcfg.name()))))                           \
        ();                                                                                                            \
        BOOST_PP_IF(BOOST_VMD_IS_EMPTY(node), BOOST_PP_EMPTY,                                                          \
                    BOOST_PP_IDENTITY(fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[node={}] "},              \
                                                      fmt::make_format_args(node->to_string()))))                      \
        ();                                                                                                            \
        fmt::vformat_to(fmt::appender{buf}, fmt::string_view{msgcb},                                                   \
                        fmt::make_format_args(std::forward< decltype(args) >(args)...));                               \
        return true;                                                                                                   \
    })

#define BT_LOG(level, msg, ...)                                                                                        \
    { LOG##level##MOD_FMT(btree, (_BT_LOG_METHOD_IMPL(, this->m_bt_cfg, )), msg, ##__VA_ARGS__); }

#define BT_NODE_LOG(level, node, msg, ...)                                                                             \
    { LOG##level##MOD_FMT(btree, (_BT_LOG_METHOD_IMPL(, this->m_bt_cfg, node)), msg, ##__VA_ARGS__); }

#if 0
#define THIS_BT_LOG(level, req, msg, ...)                                                                              \
    {                                                                                                                  \
        LOG##level##MOD_FMT(                                                                                           \
            btree, ([&](fmt::memory_buffer& buf, const char* msgcb, auto&&... args) -> bool {                          \
                fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}:{}] "},                                      \
                                fmt::make_format_args(file_name(__FILE__), __LINE__));                                 \
                BOOST_PP_IF(BOOST_VMD_IS_EMPTY(req), BOOST_PP_EMPTY,                                                   \
                            BOOST_PP_IDENTITY(fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[req={}] "},       \
                                                              fmt::make_format_args(req->to_string()))))               \
                ();                                                                                                    \
                fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[btree={}] "},                                   \
                                fmt::make_format_args(m_cfg.name()));                                                  \
                fmt::vformat_to(fmt::appender{buf}, fmt::string_view{msgcb},                                           \
                                fmt::make_format_args(std::forward< decltype(args) >(args)...));                       \
                return true;                                                                                           \
            }),                                                                                                        \
            msg, ##__VA_ARGS__);                                                                                       \
    }

#define THIS_NODE_LOG(level, btcfg, msg, ...)                                                                          \
    {                                                                                                                  \
        LOG##level##MOD_FMT(                                                                                           \
            btree, ([&](fmt::memory_buffer& buf, const char* msgcb, auto&&... args) -> bool {                          \
                fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}:{}] "},                                      \
                                fmt::make_format_args(file_name(__FILE__), __LINE__));                                 \
                fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[btree={}] "},                                   \
                                fmt::make_format_args(btcfg.name()));                                                  \
                BOOST_PP_IF(BOOST_VMD_IS_EMPTY(req), BOOST_PP_EMPTY,                                                   \
                            BOOST_PP_IDENTITY(fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[node={}] "},      \
                                                              fmt::make_format_args(to_string()))))                    \
                ();                                                                                                    \
                fmt::vformat_to(fmt::appender{buf}, fmt::string_view{msgcb},                                           \
                                fmt::make_format_args(std::forward< decltype(args) >(args)...));                       \
                return true;                                                                                           \
            }),                                                                                                        \
            msg, ##__VA_ARGS__);                                                                                       \
    }

#define BT_ASSERT(assert_type, cond, req, ...)                                                                         \
    {                                                                                                                  \
        assert_type##_ASSERT_FMT(                                                                                      \
            cond,                                                                                                      \
            [&](fmt::memory_buffer& buf, const char* msgcb, auto&&... args) -> bool {                                  \
                BOOST_PP_IF(BOOST_VMD_IS_EMPTY(req), BOOST_PP_EMPTY,                                                   \
                            BOOST_PP_IDENTITY(fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"\n[req={}] "},     \
                                                              fmt::make_format_args(req->to_string()))))               \
                ();                                                                                                    \
                fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[btree={}] "},                                   \
                                fmt::make_format_args(m_cfg.name()));                                                  \
                fmt::vformat_to(fmt::appender{buf}, fmt::string_view{msgcb},                                           \
                                fmt::make_format_args(std::forward< decltype(args) >(args)...));                       \
                return true;                                                                                           \
            },                                                                                                         \
            msg, ##__VA_ARGS__);                                                                                       \
    }

#define BT_ASSERT_CMP(assert_type, val1, cmp, val2, req, ...)                                                          \
    {                                                                                                                  \
        assert_type##_ASSERT_CMP(                                                                                      \
            val1, cmp, val2,                                                                                           \
            [&](fmt::memory_buffer& buf, const char* msgcb, auto&&... args) -> bool {                                  \
                BOOST_PP_IF(BOOST_VMD_IS_EMPTY(req), BOOST_PP_EMPTY,                                                   \
                            BOOST_PP_IDENTITY(fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"\n[req={}] "},     \
                                                              fmt::make_format_args(req->to_string()))))               \
                ();                                                                                                    \
                fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[btree={}] "},                                   \
                                fmt::make_format_args(m_cfg.name()));                                                  \
                fmt::vformat_to(fmt::appender{buf}, fmt::string_view{msgcb},                                           \
                                fmt::make_format_args(std::forward< decltype(args) >(args)...));                       \
                return true;                                                                                           \
            },                                                                                                         \
            msg, ##__VA_ARGS__);                                                                                       \
    }
#endif

#define BT_ASSERT(assert_type, cond, ...)                                                                              \
    { assert_type##_ASSERT_FMT(cond, _BT_LOG_METHOD_IMPL(, this->m_bt_cfg, ), ##__VA_ARGS__); }

#define BT_ASSERT_CMP(assert_type, val1, cmp, val2, ...)                                                               \
    { assert_type##_ASSERT_CMP(val1, cmp, val2, _BT_LOG_METHOD_IMPL(, this->m_bt_cfg, ), ##__VA_ARGS__); }

#define BT_DBG_ASSERT(cond, ...) BT_ASSERT(DEBUG, cond, ##__VA_ARGS__)
#define BT_DBG_ASSERT_EQ(val1, val2, ...) BT_ASSERT_CMP(DEBUG, val1, ==, val2, ##__VA_ARGS__)
#define BT_DBG_ASSERT_NE(val1, val2, ...) BT_ASSERT_CMP(DEBUG, val1, !=, val2, ##__VA_ARGS__)
#define BT_DBG_ASSERT_LT(val1, val2, ...) BT_ASSERT_CMP(DEBUG, val1, <, val2, ##__VA_ARGS__)
#define BT_DBG_ASSERT_LE(val1, val2, ...) BT_ASSERT_CMP(DEBUG, val1, <=, val2, ##__VA_ARGS__)
#define BT_DBG_ASSERT_GT(val1, val2, ...) BT_ASSERT_CMP(DEBUG, val1, >, val2, ##__VA_ARGS__)
#define BT_DBG_ASSERT_GE(val1, val2, ...) BT_ASSERT_CMP(DEBUG, val1, >=, val2, ##__VA_ARGS__)

#define BT_LOG_ASSERT(cond, ...) BT_ASSERT(LOGMSG, cond, ##__VA_ARGS__)
#define BT_LOG_ASSERT_EQ(val1, val2, ...) BT_ASSERT_CMP(LOGMSG, val1, ==, val2, ##__VA_ARGS__)
#define BT_LOG_ASSERT_NE(val1, val2, ...) BT_ASSERT_CMP(LOGMSG, val1, !=, val2, ##__VA_ARGS__)
#define BT_LOG_ASSERT_LT(val1, val2, ...) BT_ASSERT_CMP(LOGMSG, val1, <, val2, ##__VA_ARGS__)
#define BT_LOG_ASSERT_LE(val1, val2, ...) BT_ASSERT_CMP(LOGMSG, val1, <=, val2, ##__VA_ARGS__)
#define BT_LOG_ASSERT_GT(val1, val2, ...) BT_ASSERT_CMP(LOGMSG, val1, >, val2, ##__VA_ARGS__)
#define BT_LOG_ASSERT_GE(val1, val2, ...) BT_ASSERT_CMP(LOGMSG, val1, >=, val2, ##__VA_ARGS__)

#define BT_REL_ASSERT(cond, ...) BT_ASSERT(RELEASE, cond, ##__VA_ARGS__)
#define BT_REL_ASSERT_EQ(val1, val2, ...) BT_ASSERT_CMP(RELEASE, val1, ==, val2, ##__VA_ARGS__)
#define BT_REL_ASSERT_NE(val1, val2, ...) BT_ASSERT_CMP(RELEASE, val1, !=, val2, ##__VA_ARGS__)
#define BT_REL_ASSERT_LT(val1, val2, ...) BT_ASSERT_CMP(RELEASE, val1, <, val2, ##__VA_ARGS__)
#define BT_REL_ASSERT_LE(val1, val2, ...) BT_ASSERT_CMP(RELEASE, val1, <=, val2, ##__VA_ARGS__)
#define BT_REL_ASSERT_GT(val1, val2, ...) BT_ASSERT_CMP(RELEASE, val1, >, val2, ##__VA_ARGS__)
#define BT_REL_ASSERT_GE(val1, val2, ...) BT_ASSERT_CMP(RELEASE, val1, >=, val2, ##__VA_ARGS__)

#define BT_NODE_ASSERT(assert_type, cond, node, ...)                                                                   \
    { assert_type##_ASSERT_FMT(cond, _BT_LOG_METHOD_IMPL(, m_bt_cfg, node), ##__VA_ARGS__); }

#define BT_NODE_ASSERT_CMP(assert_type, val1, cmp, val2, node, ...)                                                    \
    { assert_type##_ASSERT_CMP(val1, cmp, val2, _BT_LOG_METHOD_IMPL(, m_bt_cfg, node), ##__VA_ARGS__); }

#define BT_NODE_DBG_ASSERT(cond, ...) BT_NODE_ASSERT(DEBUG, cond, ##__VA_ARGS__)
#define BT_NODE_DBG_ASSERT_EQ(val1, val2, ...) BT_NODE_ASSERT_CMP(DEBUG, val1, ==, val2, ##__VA_ARGS__)
#define BT_NODE_DBG_ASSERT_NE(val1, val2, ...) BT_NODE_ASSERT_CMP(DEBUG, val1, !=, val2, ##__VA_ARGS__)
#define BT_NODE_DBG_ASSERT_LT(val1, val2, ...) BT_NODE_ASSERT_CMP(DEBUG, val1, <, val2, ##__VA_ARGS__)
#define BT_NODE_DBG_ASSERT_LE(val1, val2, ...) BT_NODE_ASSERT_CMP(DEBUG, val1, <=, val2, ##__VA_ARGS__)
#define BT_NODE_DBG_ASSERT_GT(val1, val2, ...) BT_NODE_ASSERT_CMP(DEBUG, val1, >, val2, ##__VA_ARGS__)
#define BT_NODE_DBG_ASSERT_GE(val1, val2, ...) BT_NODE_ASSERT_CMP(DEBUG, val1, >=, val2, ##__VA_ARGS__)

#define BT_NODE_LOG_ASSERT(cond, ...) BT_NODE_ASSERT(LOGMSG, cond, ##__VA_ARGS__)
#define BT_NODE_LOG_ASSERT_EQ(val1, val2, ...) BT_NODE_ASSERT_CMP(LOGMSG, val1, ==, val2, ##__VA_ARGS__)
#define BT_NODE_LOG_ASSERT_NE(val1, val2, ...) BT_NODE_ASSERT_CMP(LOGMSG, val1, !=, val2, ##__VA_ARGS__)
#define BT_NODE_LOG_ASSERT_LT(val1, val2, ...) BT_NODE_ASSERT_CMP(LOGMSG, val1, <, val2, ##__VA_ARGS__)
#define BT_NODE_LOG_ASSERT_LE(val1, val2, ...) BT_NODE_ASSERT_CMP(LOGMSG, val1, <=, val2, ##__VA_ARGS__)
#define BT_NODE_LOG_ASSERT_GT(val1, val2, ...) BT_NODE_ASSERT_CMP(LOGMSG, val1, >, val2, ##__VA_ARGS__)
#define BT_NODE_LOG_ASSERT_GE(val1, val2, ...) BT_NODE_ASSERT_CMP(LOGMSG, val1, >=, val2, ##__VA_ARGS__)

#define BT_NODE_REL_ASSERT(cond, ...) BT_NODE_ASSERT(RELEASE, cond, ##__VA_ARGS__)
#define BT_NODE_REL_ASSERT_EQ(val1, val2, ...) BT_NODE_ASSERT_CMP(RELEASE, val1, ==, val2, ##__VA_ARGS__)
#define BT_NODE_REL_ASSERT_NE(val1, val2, ...) BT_NODE_ASSERT_CMP(RELEASE, val1, !=, val2, ##__VA_ARGS__)
#define BT_NODE_REL_ASSERT_LT(val1, val2, ...) BT_NODE_ASSERT_CMP(RELEASE, val1, <, val2, ##__VA_ARGS__)
#define BT_NODE_REL_ASSERT_LE(val1, val2, ...) BT_NODE_ASSERT_CMP(RELEASE, val1, <=, val2, ##__VA_ARGS__)
#define BT_NODE_REL_ASSERT_GT(val1, val2, ...) BT_NODE_ASSERT_CMP(RELEASE, val1, >, val2, ##__VA_ARGS__)
#define BT_NODE_REL_ASSERT_GE(val1, val2, ...) BT_NODE_ASSERT_CMP(RELEASE, val1, >=, val2, ##__VA_ARGS__)

#define ASSERT_IS_VALID_INTERIOR_CHILD_INDX(is_found, found_idx, node)                                                 \
    BT_NODE_DBG_ASSERT((!is_found || ((int)found_idx < (int)node->total_entries()) || node->has_valid_edge()), node,   \
                       "Is_valid_interior_child_check_failed: found_idx={}", found_idx)

using bnodeid_t = uint64_t;
static constexpr bnodeid_t empty_bnodeid = std::numeric_limits< bnodeid_t >::max();
static constexpr uint16_t bt_init_crc_16 = 0x8005;

VENUM(btree_node_type, uint32_t, FIXED = 0, VAR_VALUE = 1, VAR_KEY = 2, VAR_OBJECT = 3, PREFIX = 4, COMPACT = 5)

#ifdef USE_STORE_TYPE
VENUM(btree_store_type, uint8_t, MEM = 0, SSD = 1)
#endif

ENUM(btree_status_t, uint32_t, success, not_found, retry, has_more, node_read_failed, put_failed, space_not_avail,
     cp_mismatch, merge_not_required, merge_failed, crc_mismatch, not_supported, node_freed)

/*ENUM(btree_node_write_type, uint8_t,
     new_node,     // Node write whenever a new node is created.
     inplace_leaf, // Node write after an entry is updated/added in leaf without changing btree structure, most common
     inplace_interior, // Node write after a structure change, but this interior node is changed in-place only.
     after_shift       // Node write after a structure change, but this node has its keys shifted to other node.
);*/

class BtreeNode;
void intrusive_ptr_add_ref(BtreeNode* node);
void intrusive_ptr_release(BtreeNode* node);

template < typename K, typename V >
using to_string_cb_t = std::function< std::string(std::vector< std::pair< K, V > > const&) >;

ENUM(btree_event_t, uint8_t, READ, MUTATE, REMOVE, SPLIT, REPAIR, MERGE);

struct trace_route_entry {
    bnodeid_t node_id{empty_bnodeid};
    BtreeNode* node{nullptr};
    uint32_t start_idx{0};
    uint32_t end_idx{0};
    uint32_t num_entries{0};
    uint16_t level{0};
    bool is_leaf{false};
    btree_event_t event{btree_event_t::READ};

    std::string to_string() const {
        return fmt::format("[level={} {} event={} id={} ptr={} start_idx={} end_idx={} entries={}]", level,
                           (is_leaf ? "LEAF" : "INTERIOR"), enum_name(event), node_id, (void*)node, start_idx, end_idx,
                           num_entries);
    }
};

struct BtreeConfig {
    uint32_t m_node_size;
    uint32_t m_node_data_size;
    uint8_t m_ideal_fill_pct{90};
    uint8_t m_suggested_min_pct{30};
    uint8_t m_split_pct{50};
    uint32_t m_max_merge_nodes{3};
#ifdef _PRERELEASE
    // These are for testing purpose only
    uint64_t m_max_keys_in_node{0};
    uint64_t m_min_keys_in_node{0};
#endif
    bool m_rebalance_turned_on{false};
    bool m_merge_turned_on{true};

    btree_node_type m_leaf_node_type{btree_node_type::VAR_OBJECT};
    btree_node_type m_int_node_type{btree_node_type::VAR_KEY};
    std::string m_btree_name; // Unique name for the btree

private:
    uint32_t m_suggested_min_size; // Precomputed values
    uint32_t m_ideal_fill_size;

public:
    BtreeConfig(uint32_t node_size, const std::string& btree_name = "") :
            m_node_size{node_size}, m_btree_name{btree_name.empty() ? std::string("btree") : btree_name} {
        set_node_data_size(node_size - 512); // Just put estimate at this point of time.
    }

    virtual ~BtreeConfig() = default;
    uint32_t node_size() const { return m_node_size; };

    void set_node_data_size(uint32_t data_size) {
        m_node_data_size = data_size;
        m_ideal_fill_size = (uint32_t)(m_node_data_size * m_ideal_fill_pct) / 100; // Recompute the values
        m_suggested_min_size = (uint32_t)(m_node_data_size * m_suggested_min_pct) / 100;
    }

    uint32_t split_size(uint32_t filled_size) const { return uint32_cast(filled_size * m_split_pct) / 100; }
    uint32_t ideal_fill_size() const { return m_ideal_fill_size; }
    uint32_t suggested_min_size() const { return m_suggested_min_size; }
    uint32_t node_data_size() const { return m_node_data_size; }

    void set_ideal_fill_pct(uint8_t pct) {
        m_ideal_fill_pct = pct;
        m_ideal_fill_size = (uint32_t)(node_data_size() * m_ideal_fill_pct) / 100;
    }

    void set_suggested_min_size(uint8_t pct) {
        m_suggested_min_pct = pct;
        m_suggested_min_size = (uint32_t)(node_data_size() * m_suggested_min_pct) / 100;
    }

    const std::string& name() const { return m_btree_name; }
    btree_node_type leaf_node_type() const { return m_leaf_node_type; }
    btree_node_type interior_node_type() const { return m_int_node_type; }
};

class BtreeMetrics : public sisl::MetricsGroup {
public:
    explicit BtreeMetrics(const char* inst_name) : sisl::MetricsGroup("Btree", inst_name) {
        REGISTER_COUNTER(btree_obj_count, "Btree object count", _publish_as::publish_as_gauge);
        REGISTER_COUNTER(btree_leaf_node_count, "Btree Leaf node count", "btree_node_count", {"node_type", "leaf"},
                         _publish_as::publish_as_gauge);
        REGISTER_COUNTER(btree_int_node_count, "Btree Interior node count", "btree_node_count",
                         {"node_type", "interior"}, _publish_as::publish_as_gauge);
        REGISTER_COUNTER(btree_split_count, "Total number of btree node splits");
        REGISTER_COUNTER(btree_merge_count, "Total number of btree node merges");
        REGISTER_COUNTER(btree_depth, "Depth of btree", _publish_as::publish_as_gauge);

        REGISTER_COUNTER(btree_int_node_writes, "Total number of btree interior node writes", "btree_node_writes",
                         {"node_type", "interior"});
        REGISTER_COUNTER(btree_leaf_node_writes, "Total number of btree leaf node writes", "btree_node_writes",
                         {"node_type", "leaf"});
        REGISTER_COUNTER(btree_num_pc_gen_mismatch, "Number of gen mismatches to recover");

        REGISTER_HISTOGRAM(btree_int_node_occupancy, "Interior node occupancy", "btree_node_occupancy",
                           {"node_type", "interior"}, HistogramBucketsType(LinearUpto128Buckets));
        REGISTER_HISTOGRAM(btree_leaf_node_occupancy, "Leaf node occupancy", "btree_node_occupancy",
                           {"node_type", "leaf"}, HistogramBucketsType(LinearUpto128Buckets));
        REGISTER_COUNTER(btree_retry_count, "number of retries");
        REGISTER_COUNTER(write_err_cnt, "number of errors in write");
        REGISTER_COUNTER(query_err_cnt, "number of errors in query");
        REGISTER_COUNTER(read_node_count_in_write_ops, "number of nodes read in write_op");
        REGISTER_COUNTER(read_node_count_in_query_ops, "number of nodes read in query_op");
        REGISTER_COUNTER(btree_write_ops_count, "number of btree operations");
        REGISTER_COUNTER(btree_query_ops_count, "number of btree operations");
        REGISTER_COUNTER(btree_remove_ops_count, "number of btree operations");
        REGISTER_HISTOGRAM(btree_exclusive_time_in_int_node,
                           "Exclusive time spent (Write locked) on interior node (ns)", "btree_exclusive_time_in_node",
                           {"node_type", "interior"});
        REGISTER_HISTOGRAM(btree_exclusive_time_in_leaf_node, "Exclusive time spent (Write locked) on leaf node (ns)",
                           "btree_exclusive_time_in_node", {"node_type", "leaf"});
        REGISTER_HISTOGRAM(btree_inclusive_time_in_int_node, "Inclusive time spent (Read locked) on interior node (ns)",
                           "btree_inclusive_time_in_node", {"node_type", "interior"});
        REGISTER_HISTOGRAM(btree_inclusive_time_in_leaf_node, "Inclusive time spent (Read locked) on leaf node (ns)",
                           "btree_inclusive_time_in_node", {"node_type", "leaf"});

        register_me_to_farm();
    }

    ~BtreeMetrics() { deregister_me_from_farm(); }
};

} // namespace homestore
