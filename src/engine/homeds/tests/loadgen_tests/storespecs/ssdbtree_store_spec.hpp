
#ifndef HOMESTORE_SSD_BTREE_STORE_SPEC_HPP
#define HOMESTORE_SSD_BTREE_STORE_SPEC_HPP

#include "homeds/loadgen/spec/store_spec.hpp"
#include "homeds/btree/btree.hpp"
#include "homeds/btree/btree_internal.h"
#include "homeds/btree/ssd_btree.hpp"
#include "homeblks/home_blks.hpp"

using namespace homeds::btree;

namespace homeds {
namespace loadgen {

#define TOTAL_ENTRIES 1000000

//#define LoadGenSSDBtree  Btree<btree_store_type::SSD_BTREE, K, V, btree_node_type::VAR_VALUE,
// btree_node_type::VAR_VALUE, NodeSize, writeback_req>

#define LoadGenSSDBtree                                                                                                \
    Btree< btree_store_type::SSD_BTREE, K, V, find_interior_node_type< K >(), find_leaf_node_type< K, V >(),           \
           writeback_req >

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

template < typename K, typename V, size_t NodeSize = 8192 >
class SSDBtreeStoreSpec : public StoreSpec< K, V > {

public:
    SSDBtreeStoreSpec() {}

    virtual void init_store(homeds::loadgen::Param& parameters) override {
        homeds::btree::BtreeConfig btree_cfg(4096);
        btree_cfg.set_max_objs(TOTAL_ENTRIES);
        btree_cfg.set_max_key_size(K::get_max_size());
        btree_cfg.set_max_value_size(V::get_max_size());

        homeds::btree::btree_device_info bt_dev_info;
        bt_dev_info.blkstore = HomeBlks::instance()->get_index_blkstore();
        bt_dev_info.new_device = false;
        m_bt = std::unique_ptr< LoadGenSSDBtree >(LoadGenSSDBtree::create_btree(
            btree_cfg, &bt_dev_info,
            std::bind(&SSDBtreeStoreSpec::process_completions, this, std::placeholders::_1, std::placeholders::_2)));
    }

    void process_completions(boost::intrusive_ptr< writeback_req > cookie, bool status) {
        boost::intrusive_ptr< ssd_loadgen_req > req = boost::static_pointer_cast< ssd_loadgen_req >(cookie);
        if (req->status == no_error) { req->status = status ? no_error : btree_write_failed; }
    }

    virtual bool insert(K& k, std::shared_ptr< V > v) override { return update(k, v); }

    virtual bool upsert(K& k, std::shared_ptr< V > v) override { return update(k, v); }

    virtual bool update(K& k, std::shared_ptr< V > v) override {
        boost::intrusive_ptr< ssd_loadgen_req > req = ssd_loadgen_req::make_request();
        V existing_val;
        req->state = writeback_req_state::WB_REQ_COMPL;
        // m_bt->put(k, v, btree_put_type::REPLACE_ONLY_IF_EXISTS, to_wb_req(req), to_wb_req(req), &existing_val);
        m_bt->put(k, *(v.get()), btree_put_type::REPLACE_IF_EXISTS_ELSE_INSERT, to_wb_req(req), to_wb_req(req),
                  &existing_val);
        return true;
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
        auto status = m_bt->remove_any(range, out_key, out_val);
        return status == btree_status_t::success;
    }

    virtual uint32_t query(K& start_key, bool start_incl, K& end_key, bool end_incl,
                           std::vector< std::pair< K, V > >& result) override {
#define MAX_BATCH_SIZE 20000000 // set it to big value so that everything is queried in one operation
        auto search_range = BtreeSearchRange(start_key, start_incl, end_key, end_incl);
        BtreeQueryRequest< K, V > qreq(search_range, BtreeQueryType::SWEEP_NON_INTRUSIVE_PAGINATION_QUERY,
                                       MAX_BATCH_SIZE);

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
                              std::vector< std::shared_ptr< V > >& result) {
        assert(0); // not supported yet
        return {};
    }

private:
    std::unique_ptr< LoadGenSSDBtree > m_bt;
};
} // namespace loadgen
} // namespace homeds

#endif // HOMESTORE_BTREE_STORE_SPEC_HPP
