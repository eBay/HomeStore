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

#ifndef HOMESTORE_SSD_BTREE_STORE_SPEC_HPP
#define HOMESTORE_SSD_BTREE_STORE_SPEC_HPP

#include <cassert>
#include <cstdint>
#include <memory>
#include <vector>

#include "homeds/loadgen/spec/store_spec.hpp"
#include "homeds/btree/btree.hpp"
#include "homeds/btree/btree_internal.h"
#include "homeds/btree/ssd_btree.hpp"
#include "homeblks/home_blks.hpp"

using namespace homeds::btree;

namespace homeds {
namespace loadgen {

struct ssd_loadgen_req;
typedef boost::intrusive_ptr< ssd_loadgen_req > ssd_loadgen_req_ptr;

struct ssd_loadgen_req : public blkstore_req< BlkBuffer > {
public:
    static boost::intrusive_ptr< ssd_loadgen_req > make_request() {
        return boost::intrusive_ptr< ssd_loadgen_req >(sisl::ObjectAllocator< ssd_loadgen_req >::make_object());
    }

    virtual void free_yourself() override { sisl::ObjectAllocator< ssd_loadgen_req >::deallocate(this); }

    virtual ~ssd_loadgen_req() = default;

    // virtual size_t get_your_size() const override { return sizeof(ssd_loadgen_req); }

    static ssd_loadgen_req_ptr cast(const boost::intrusive_ptr< blkstore_req< BlkBuffer > >& bs_req) {
        return boost::static_pointer_cast< ssd_loadgen_req >(bs_req);
    }

protected:
    friend class sisl::ObjectAllocator< ssd_loadgen_req >;
};

template < typename K, typename V, const size_t NodeSize = 8192 >
class SSDBtreeStoreSpec : public StoreSpec< K, V > {
private:
    static constexpr uint64_t TOTAL_ENTRIES{1000000};

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

    static constexpr btree_node_type find_interior_node_type() {
        // return (K::is_fixed_size() ? btree_node_type::SIMPLE : btree_node_type::VAR_KEY);
        return (K::is_fixed_size() ? btree_node_type::SIMPLE : btree_node_type::VAR_VALUE);
    }

    typedef Btree< btree_store_type::SSD_BTREE, K, V, find_interior_node_type(), find_leaf_node_type() >
        LoadGenSSDBtree;

public:
    SSDBtreeStoreSpec() = default;
    SSDBtreeStoreSpec(const SSDBtreeStoreSpec&) = delete;
    SSDBtreeStoreSpec& operator=(const SSDBtreeStoreSpec&) = delete;
    SSDBtreeStoreSpec(SSDBtreeStoreSpec&&) noexcept = delete;
    SSDBtreeStoreSpec& operator=(SSDBtreeStoreSpec&&) noexcept = delete;
    virtual ~SSDBtreeStoreSpec() override = default;

    virtual void init_store(const homeds::loadgen::Param& parameters) override {
        homeds::btree::BtreeConfig btree_cfg(4096);
        btree_cfg.set_max_objs(TOTAL_ENTRIES);
        btree_cfg.set_max_key_size(K::get_max_size());
        btree_cfg.set_max_value_size(V::get_max_size());
        btree_cfg.blkstore = HomeBlks::instance()->get_index_blkstore();

        m_bt = std::unique_ptr< LoadGenSSDBtree >(LoadGenSSDBtree::create_btree(btree_cfg));
    }

    virtual bool insert(K& k, std::shared_ptr< V > v) override { return update(k, v); }

    virtual bool upsert(K& k, std::shared_ptr< V > v) override { return update(k, v); }

    virtual bool update(K& k, std::shared_ptr< V > v) override {
        V existing_val;
        // m_bt->put(k, v, btree_put_type::REPLACE_ONLY_IF_EXISTS, to_wb_req(req), to_wb_req(req), &existing_val);
        m_bt->put(k, *(v.get()), btree_put_type::REPLACE_IF_EXISTS_ELSE_INSERT);
        return true;
    }

    virtual bool get(const K& k, V* const out_v) const override {
        const auto status{m_bt->get(k, out_v)};
        return (status == btree_status_t::success);
    }

    virtual bool remove(const K& k, V* const removed_v = nullptr) override {
        const auto status{m_bt->remove(k, removed_v)};
        return (status == btree_status_t::success);
    }

    virtual bool remove_any(const K& start_key, const bool start_incl, const K& end_key, const bool end_incl,
                            K* out_key, V* const out_val) override {
        BtreeSearchRange range{start_key, start_incl, end_key, end_incl};
        const auto status{m_bt->remove_any(range, out_key, out_val)};
        return (status == btree_status_t::success);
    }

    virtual uint32_t query(const K& start_key, const bool start_incl, const K& end_key, const bool end_incl,
                           std::vector< std::pair< K, V > >& result) const override {
        constexpr uint32_t MAX_BATCH_SIZE{
            20000000}; // set it to big value so that everything is queried in one operation
        BtreeSearchRange search_range{start_key, start_incl, end_key, end_incl};
        BtreeQueryRequest< K, V > qreq{search_range, BtreeQueryType::SWEEP_NON_INTRUSIVE_PAGINATION_QUERY,
                                       MAX_BATCH_SIZE};

        uint32_t result_count{0};

        std::vector< std::pair< K, V > > values;

        bool has_more{false};
        do {
            const auto status{m_bt->query(qreq, values)};

            has_more = (status == btree_status_t::has_more);
            const auto is_success{(status == btree_status_t::has_more) || (status == btree_status_t::success)};

            result.insert(std::end(result), std::move_iterator(std::begin(values)),
                          std::move_iterator(std::end(values)));

            values.clear();
        } while (has_more);

        result_count += result.size();
        return result_count;
    }

    virtual bool range_update(K& start_key, const bool start_incl, K& end_key, const bool end_incl,
                              std::vector< std::shared_ptr< V > >& result) override {
        assert(false); // not supported yet
        return false;
    }

private:
    std::unique_ptr< LoadGenSSDBtree > m_bt;
};
} // namespace loadgen
} // namespace homeds

#endif // HOMESTORE_BTREE_STORE_SPEC_HPP
