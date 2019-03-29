//
// Created by Kadayam, Hari on 2/22/19.
//
#ifndef HOMESTORE_WORKLOAD_GENERATOR_HPP
#define HOMESTORE_WORKLOAD_GENERATOR_HPP

#include "homeds/loadgen/loadgen_common.hpp"
#include "homeds/btree/btree.hpp"
#include <spdlog/fmt/bundled/ostream.h>

namespace homeds { namespace loadgen {

template< typename K >
struct compare_keys {
public:
    bool operator()(const K &key1, const K &key2) const {
        return key1.compare(&key2) == 0;
    }
};

template< typename K >
struct key_hash {
    size_t operator()(const K &key) const {
        auto b = key.get_blob();
        return util::Hash32((const char *)b.bytes, (size_t)b.size);
    }
};

class KeySpec {
public:
    virtual bool operator==(const KeySpec& rhs) const = 0;
    virtual bool operator!=(const KeySpec& rhs) const { return !(operator==(rhs));}
};
} } // namespace homeds::loadgen
#endif // HOMESTORE_WORKLOAD_GENERATOR_HPP
