//
// Created by Kadayam, Hari on 3/28/19.
//

#ifndef HOMESTORE_BTREE_STORE_SPEC_HPP
#define HOMESTORE_BTREE_STORE_SPEC_HPP

#include "homeds/loadgen/spec/store_spec.hpp"
#include "homeds/btree/btree.hpp"
#include "homeds/btree/mem_btree.hpp"

using namespace homeds::btree;

namespace homeds {
namespace loadgen {

template < typename K, typename V >
static constexpr btree_node_type find_leaf_node_type() {
    if (K::is_fixed_size() && V::is_fixed_size()) {
        return btree_node_type::SIMPLE;
    } else if (K::is_fixed_size() && !V::is_fixed_size()) {
        return btree_node_type::VAR_VALUE;
    } else if (!K::is_fixed_size() && V::is_fixed_size()) {
        return btree_node_type::VAR_KEY;
    } else {
        // return btree_node_type::VAR_OBJECT;
        return btree_node_type::VAR_VALUE;
    }
}

template < typename K >
static constexpr btree_node_type find_interior_node_type() {
    // return (K::is_fixed_size() ? btree_node_type::SIMPLE : btree_node_type::VAR_KEY);
    return (K::is_fixed_size() ? btree_node_type::SIMPLE : btree_node_type::VAR_VALUE);
}

#define TOTAL_ENTRIES 1000000

#define LoadGenMemBtree                                                                                                \
    Btree< btree_store_type::MEM_BTREE, K, V, find_interior_node_type< K >(), find_leaf_node_type< K, V >() >

template < typename K, typename V, size_t NodeSize = 8192 >
class MemBtreeStoreSpec : public StoreSpec< K, V > {
public:
    MemBtreeStoreSpec() {}

    virtual void init_store(homeds::loadgen::Param& parameters) override {
        BtreeConfig btree_cfg(4096);
        btree_cfg.set_max_objs(TOTAL_ENTRIES);
        btree_cfg.set_max_key_size(K::get_max_size());
        btree_cfg.set_max_value_size(V::get_max_size());
        m_bt = std::unique_ptr< LoadGenMemBtree >(LoadGenMemBtree::create_btree(btree_cfg, nullptr));
    }

    virtual bool insert(K& k, std::shared_ptr<V> v) override {
        auto status = m_bt->put(k, *(v.get()), btree_put_type::INSERT_ONLY_IF_NOT_EXISTS);
        return status == btree_status_t::success;
    }

    virtual bool upsert(K& k, std::shared_ptr<V> v) override {
        auto status = m_bt->put(k, *(v.get()), btree_put_type::REPLACE_IF_EXISTS_ELSE_INSERT);
        return status == btree_status_t::success;
    }

    virtual bool update(K& k, std::shared_ptr<V> v) override {
        auto status = m_bt->put(k, *(v.get()), btree_put_type::REPLACE_ONLY_IF_EXISTS);
        return status == btree_status_t::success;
    }

    virtual bool get(K& k, V* out_v) override {
        auto status = m_bt->get(k, out_v);
        return status == btree_status_t::success;
    }

    virtual bool remove(K& k, V* removed_v = nullptr) override {
        auto status = m_bt->remove(k, removed_v);
        return status == btree_status_t::success;
    }

    virtual bool remove_any(K& start_key, bool start_incl, K& end_key, bool end_incl, K* out_key, V* out_val) override {
        BtreeSearchRange range(start_key, start_incl, end_key, end_incl);
        auto             status = m_bt->remove_any(range, out_key, out_val);
        return status == btree_status_t::success;
    }

    virtual uint32_t query(K& start_key, bool start_incl, K& end_key, bool end_incl,
                           std::vector< std::pair< K, V > >& result) override {
#define MAX_BATCH_SIZE 20000000 // set it to big value so that everything is queried in one operation
        auto                      search_range = BtreeSearchRange(start_key, start_incl, end_key, end_incl);
        BtreeQueryRequest< K, V > qreq(search_range, BtreeQueryType::SWEEP_NON_INTRUSIVE_PAGINATION_QUERY, MAX_BATCH_SIZE);

        auto result_count = 0U;

        std::vector< std::pair< K, V > > values;

        bool has_more = false;
        do {
            auto status = m_bt->query(qreq, values);

            has_more = (status == btree_status_t::has_more);
            auto is_success = (status == btree_status_t::has_more) || (status == btree_status_t::success);

            result.insert(result.end(), values.begin(), values.end());

            values.clear();
        } while (has_more);

        result_count += result.size();
        return result_count;
    }

    virtual bool range_update(K& start_key, bool start_incl, K& end_key, bool end_incl, 
                              std::vector< std::shared_ptr<V> > &result) {
        assert(0); // not supported yet
        return {};
    }

private:
    std::unique_ptr< LoadGenMemBtree > m_bt;
};
} // namespace loadgen
} // namespace homeds

#endif // HOMESTORE_BTREE_STORE_SPEC_HPP
