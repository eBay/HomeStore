//
// Created by Kadayam, Hari on 16/01/18.
//
#pragma once

#include <atomic>
#include "omds/utility/stats.hpp"

namespace omds { namespace btree {
#define VALUES              \
    X(BTREE_STATS_OBJ_COUNT,            COUNTER,    STATS_INVALID_INDEX, "Btree Object Count")    \
    X(BTREE_STATS_LEAF_NODE_COUNT,      COUNTER,    STATS_INVALID_INDEX, "Btree Leaf node Count") \
    X(BTREE_STATS_INT_NODE_COUNT,       COUNTER,    STATS_INVALID_INDEX, "Btree Interior node Count") \
    X(BTREE_STATS_SPLIT_COUNT,          COUNTER,    STATS_INVALID_INDEX, "Btree Node split Count") \
    X(BTREE_STATS_MERGE_COUNT,          COUNTER,    STATS_INVALID_INDEX, "Btree Node merge Count")

#define X(ind, type, mean_of, desc) ind,
enum btree_stats_type : uint32_t {VALUES};
#undef X

#define X(ind, type, mean_of, desc) {ind, type, mean_of, desc},
static std::vector< omds::stats_key > btree_stats_keys = {VALUES};

class BtreeStats : public Stats {
public:
    BtreeStats() :
            //Stats({VALUES}) {}
            Stats(btree_stats_keys) {}

    uint64_t get_obj_count() const {
        return this->get(BTREE_STATS_OBJ_COUNT);
    }

    uint64_t get_leaf_nodes_count() const {
        return this->get(BTREE_STATS_LEAF_NODE_COUNT);
    }

    uint64_t get_interior_nodes_count() const {
        return this->get(BTREE_STATS_INT_NODE_COUNT);
    }
};
}}

