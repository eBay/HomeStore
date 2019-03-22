//
// Created by Kadayam, Hari on 2/24/19.
//

#ifndef HOMESTORE_STORE_SPEC_HPP
#define HOMESTORE_STORE_SPEC_HPP

#include "homeds/btree/btree.hpp"
#include "homeds/btree/mem_btree.hpp"

using namespace homeds::btree;

namespace homeds {
namespace loadgen {
template < typename K, typename V >
class StoreSpec {
public:
    virtual bool insert(K& k, V& v) = 0;
    virtual bool upsert(K& k, V& v) = 0;
    virtual bool get(K& k, V* out_v) = 0;
    virtual bool remove(K& k, V* removed_v = nullptr) = 0;
    virtual bool remove_any(K& start_key, bool start_incl, K& end_key, bool end_incl, K *out_key, V* out_val) = 0;
    virtual std::vector< V > query(K& start_key, bool start_incl, K& end_key, bool end_incl) = 0;
    virtual std::vector< V > range_update(K& start_key, bool start_incl, K& end_key, bool end_incl) = 0;
};

template< typename K, typename V >
static constexpr btree_node_type find_leaf_node_type() {
    if (K::is_fixed_size() && V::is_fixed_size()) {
        return btree_node_type::SIMPLE;
    } else if (K::is_fixed_size() && !V::is_fixed_size()) {
        return btree_node_type::VAR_VALUE;
    } else if (!K::is_fixed_size() && V::is_fixed_size()) {
        return btree_node_type::VAR_KEY;
    } else {
        return btree_node_type::VAR_OBJECT;
    }
}

template< typename K >
static constexpr btree_node_type find_interior_node_type() {
    return (K::is_fixed_size() ? btree_node_type::SIMPLE : btree_node_type::VAR_KEY);
}

#define TOTAL_ENTRIES 1000000

#define LoadGenMemBtree  Btree<btree_store_type::MEM_BTREE, K, V, find_interior_node_type<K>(), find_leaf_node_type<K, V>(), NodeSize>

template< typename K, typename V, size_t NodeSize = 8192 >
class MemBtreeStoreSpec : public StoreSpec< K, V > {
public:
    MemBtreeStoreSpec() {
        BtreeConfig btree_cfg;
        btree_cfg.set_max_objs(TOTAL_ENTRIES);
        btree_cfg.set_max_key_size(K::get_max_size());
        btree_cfg.set_max_value_size(V::get_max_size());
        m_bt = std::unique_ptr< LoadGenMemBtree >(LoadGenMemBtree::create_btree(btree_cfg, nullptr));
    }

    virtual bool insert(K& k, V& v) override {
        m_bt->put(k, v, btree_put_type::INSERT_ONLY_IF_NOT_EXISTS);
        return true;
    }

    virtual bool upsert(K& k, V& v) override {
        m_bt->put(k, v, btree_put_type::REPLACE_IF_EXISTS_ELSE_INSERT);
        return true;
    }

    virtual bool get(K& k, V* out_v) override {
        return m_bt->get(k, out_v);
    }

    virtual bool remove(K& k, V* removed_v = nullptr) override {
        return m_bt->remove(k, removed_v);
    }

    virtual bool remove_any(K& start_key, bool start_incl, K& end_key, bool end_incl, K *out_key, V* out_val) {
        BtreeSearchRange range(start_key, start_incl, end_key, end_incl);
        return m_bt->remove_any(range, out_key, out_val);
    }

    virtual std::vector< V > query(K& start_key, bool start_incl, K& end_key, bool end_incl) {
        assert(0); // not supported yet
        return {};
    }
    virtual std::vector< V > range_update(K& start_key, bool start_incl, K& end_key, bool end_incl) {
        assert(0); // not supported yet
        return {};
    }

private:
    std::unique_ptr< LoadGenMemBtree > m_bt;
};
} // namespace loadgen
} // namespace homeds
#endif // HOMESTORE_STORE_SPEC_HPP
