//
// Modified by Amit Desai
//

#ifndef HOMESTORE_MAP_STORE_SPEC_HPP
#define HOMESTORE_MAP_STORE_SPEC_HPP

#include "homeds/loadgen/spec/store_spec.hpp"

using namespace homeds::btree;
using namespace homestore;

namespace homeds {
namespace loadgen {
#define INVALID_SEQ_ID UINT64_MAX

template < typename K, typename V, size_t NodeSize = 8192 >
class MapStoreSpec : public StoreSpec< K, V > {
    typedef std::function< void(generator_op_error, const key_info< K, V >*, void*, const std::string&) >
        store_error_cb_t;

public:
    MapStoreSpec() {}

    void process_metadata_completions(const volume_req_ptr& req) {
        LOGTRACE("MapInfo persisted:", req->lba, req->nlbas);
    }

    void process_free_blk_callback(Free_Blk_Entry fbe) {
        // remove this assert if someone is actually calling this funciton
        assert(0);
    }

    virtual bool insert(K& k, std::shared_ptr< V > v) override { return update(k, v); }

    virtual bool upsert(K& k, std::shared_ptr< V > v) override { return update(k, v); }

    virtual void init_store(homeds::loadgen::Param& parameters) override {
        vol_params params;
        params.page_size = NodeSize;
        params.size = 10 * Gi;
        params.uuid = boost::uuids::random_generator()();
        std::string name = "vol1";
        memcpy(params.vol_name, name.c_str(), (name.length() + 1));

        boost::uuids::string_generator gen;
        uuid = gen("01970496-0262-11e9-8eb2-f2801f1b9fd1");

        m_map = std::make_unique< mapping >(
            params.size, params.page_size, name,
            std::bind(&MapStoreSpec::process_metadata_completions, this, std::placeholders::_1),
            std::bind(&MapStoreSpec::process_free_blk_callback, this, std::placeholders::_1));
    }

    /* Map put always appends if exists, no feature to force udpate/insert and return error */
    virtual bool update(K& k, std::shared_ptr< V > v) override {
        boost::intrusive_ptr< volume_req > req(new volume_req());
        ValueEntry ve;
        v->get_array().get(0, ve, false);
        req->seqId = ve.get_seqId();
        req->lastCommited_seqId = req->seqId; // keeping only latest version always
        req->lba = k.start();
        req->nlbas = k.get_n_lba();
        req->push_blkid(ve.get_blkId());
        m_map->put(req, k, *(v.get()));
        return true;
    }

    virtual bool get(K& k, V* out_v) override {
        std::vector< std::pair< K, V > > kvs;
        query(k, true, k, true, kvs);
        assert(kvs.size() <= 1);
        if (kvs.size() == 0) return false;
        out_v->copy_blob(kvs[0].second.get_blob());
        return true;
    }

    virtual bool remove(K& k, V* removed_v = nullptr) override {
        assert(0);
        return true; // map does not have remove impl
    }

    virtual bool remove_any(K& start_key, bool start_incl, K& end_key, bool end_incl, K* out_key, V* out_val) override {
        assert(0);
        return true; // map does not have remove impl
    }

    virtual uint32_t query(K& start_key, bool start_incl, K& end_key, bool end_incl,
                           std::vector< std::pair< K, V > >& result) override {
        auto search_range = BtreeSearchRange(start_key, start_incl, end_key, end_incl);
        BtreeQueryRequest< K, V > qreq(search_range, BtreeQueryType::SWEEP_NON_INTRUSIVE_PAGINATION_QUERY,
                                       end_key.start() - start_key.start() + 1);

        auto result_count = 0U;
        boost::intrusive_ptr< volume_req > volreq(new volume_req());
        volreq->lba = start_key.start();
        if (!start_incl) { volreq->lba++; }
        volreq->nlbas = end_key.end() - volreq->lba + 1;
        if (!end_incl) { volreq->nlbas--; }
        volreq->seqId = INVALID_SEQ_ID;
        volreq->lastCommited_seqId = INVALID_SEQ_ID; // read only latest value

        std::vector< std::pair< MappingKey, MappingValue > > kvs;
        m_map->get(volreq, kvs, false);
        uint64_t j = 0;

        std::array< uint16_t, CS_ARRAY_STACK_SIZE > carr;
        for (auto i = 0ul; i < CS_ARRAY_STACK_SIZE; i++) {
            carr[i] = 1;
        }

        for (uint64_t lba = volreq->lba; lba < volreq->lba + volreq->nlbas;) {
            if (kvs[j].first.start() != lba) {
                lba++;
                continue;
            }
            ValueEntry ve;
            (kvs[j].second.get_array()).get(0, ve, false);
            int cnt = 0;
            while (lba <= kvs[j].first.end()) {
                auto storeblk = ve.get_blkId().get_id() + ve.get_blk_offset() + cnt;
                ValueEntry ve(INVALID_SEQ_ID, BlkId(storeblk, 1, 0), 0, 1, &carr[0]);
                result.push_back(std::make_pair(K(lba, 1), V(ve)));
                lba++;
                cnt++;
            }
            j++;
        }

        result_count += result.size();
        return result_count;
    }

    virtual bool range_update(K& start_key, bool start_incl, K& end_key, bool end_incl,
                              std::vector< std::shared_ptr< V > >& result) {
        assert(start_incl);
        assert(end_incl);
        boost::intrusive_ptr< volume_req > req(new volume_req());
        V& start_value = *(result[0].get());
        V& end_value = *(result.back());

        req->seqId = INVALID_SEQ_ID;
        req->lastCommited_seqId = INVALID_SEQ_ID; // keeping only latest version always

        BlkId bid = start_value.get_blkId();
        bid.set_nblks(end_value.end() - start_value.start() + 1);
        req->push_blkid(bid);

        req->lba = start_key.start();
        req->nlbas = end_key.end() - req->lba + 1;

        MappingKey key(req->lba, req->nlbas);

        std::array< uint16_t, CS_ARRAY_STACK_SIZE > carr;
        for (auto i = 0ul; i < CS_ARRAY_STACK_SIZE; i++)
            carr[i] = 1;

        // NOTE assuming data block size is same as lba-volume block size
        ValueEntry ve(INVALID_SEQ_ID, BlkId(bid.get_id(), bid.get_nblks(), 0), 0, bid.get_nblks(), &carr[0]);
        MappingValue value(ve);
        LOGDEBUG("Mapping range put:{} {} ", key.to_string(), value.to_string());

        assert(req->nlbas == bid.get_nblks());
        m_map->put(req, key, value);

        return true;
    }

private:
    std::unique_ptr< mapping > m_map;
    boost::uuids::uuid uuid;
};

} // namespace loadgen
} // namespace homeds

#endif // HOMESTORE_MAP_STORE_SPEC_HPP
