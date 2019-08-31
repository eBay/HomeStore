//
// Modified by Amit Desai
//

#ifndef HOMESTORE_MAP_STORE_SPEC_HPP
#define HOMESTORE_MAP_STORE_SPEC_HPP

#include "homeds/loadgen/spec/store_spec.hpp"

using namespace homeds::btree;

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

    virtual bool insert(K& k, V& v) override { return update(k, v); }

    virtual bool upsert(K& k, V& v) override { return update(k, v); }

    virtual void init_store() override {
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

    /*Map put always appends if exists, no feature to force udpate/insert and return error*/
    virtual bool update(K& k, V& v) override {
        boost::intrusive_ptr< volume_req > req = volume_req::make_request();
        ValueEntry                         ve;
        v.get_array().get(0, ve, false);
        req->seqId = ve.get_seqId();
        req->lastCommited_seqId = req->seqId; // keeping only latest version always
        req->lba = k.start();
        req->nlbas = k.get_n_lba();
        req->blkId = ve.get_blkId();
#ifndef NDEBUG
        req->vol_uuid = uuid;
#endif
        req->state = writeback_req_state::WB_REQ_COMPL;
        m_map->put(req, k, v);
        return true;
    }

    virtual bool get(K& k, V* out_v) override {
        std::vector< std::pair< K, V > > kvs;
        query(k, true, k, true, 1, kvs);
        assert(kvs.size() <= 1);
        if (kvs.size() == 0)
            return false;
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

    virtual uint32_t query(K& start_key, bool start_incl, K& end_key, bool end_incl, uint32_t batch_size,
                           std::vector< std::pair< K, V > >& result) override {
        auto                      search_range = BtreeSearchRange(start_key, start_incl, end_key, end_incl);
        BtreeQueryRequest< K, V > qreq(search_range, BtreeQueryType::SWEEP_NON_INTRUSIVE_PAGINATION_QUERY, batch_size);

        auto                               result_count = 0U;
        boost::intrusive_ptr< volume_req > volreq = volume_req::make_request();
        volreq->lba = start_key.start();
        if (!start_incl) {
            volreq->lba++;
        }
        volreq->nlbas = end_key.end() - volreq->lba + 1;
        if (!end_incl) {
            volreq->nlbas--;
        }
        volreq->seqId = INVALID_SEQ_ID;
        volreq->lastCommited_seqId = INVALID_SEQ_ID; // read only latest value

#ifndef NDEBUG
        volreq->vol_uuid = uuid;
#endif
        std::vector< std::pair< MappingKey, MappingValue > > kvs;
        m_map->get(volreq, kvs, false);
        for (std::pair< MappingKey, MappingValue >& pair : kvs) {
            result.push_back(std::make_pair(K(pair.first), V(pair.second)));
        }

        result_count += result.size();
        return result_count;
    }

    virtual void verify(std::vector< key_info_ptr< K, V > > loadgenkv, std::vector< std::pair< K, V > > storekv,
                        store_error_cb_t error_cb, bool exclusive_access) override {

        /**
         * Keys are first put in loadgen and than in store.
         * Howver Keys found in store and missing in loadgen is still ok
         * This is because loadgen/store op are not atomic.
         *
         * T1 got contigious keys to query
         * T2 created intermittent key
         * T1 called stored and than called verify (key would be missing in loadgen)
         *
         * Case where key is found in loadgen and not in store is not possible, this is because
         * we would take exclusive access on that key, so no other verify op will end up in this case
         *
         * Similarly key is first removed from loadgen dataset and than removed from store
         * To remove it has to get exclusive access. So while verify is going on, it will not get access.
         * So same scenairio could happen, key missing in loadgen but present in store
         *
         * We do not want to make loadgen/store ops atomic,this will serialize all calls to store
         */

        auto l_itr = loadgenkv.begin();
        auto s_itr = storekv.begin();
        while (l_itr != loadgenkv.end() && s_itr != storekv.end()) {
            /* Gather some store value details */
            V          storeValue = s_itr->second;
            ValueEntry ve;
            storeValue.get_array().get(0, ve, false);
            auto storeblk = ve.get_blkId().get_id() + ve.get_blk_offset();
            auto storeblkend = storeblk + ve.get_nlba() - 1;
            assert(s_itr->first.get_n_lba() == ve.get_nlba());
            auto sid = ve.get_seqId();
            auto chunk = ve.get_blkId().get_chunk_num();
            // create 1 blk values
            std::array< uint16_t, CS_ARRAY_STACK_SIZE > carr;
            for (auto i = 0ul; i < CS_ARRAY_STACK_SIZE; i++)
                carr[i] = 1;
            auto storelba = s_itr->first.start();

            while (storeblk <= storeblkend) {
                auto loadgenki = *l_itr;
                auto loadgenlba = loadgenki.m_ki->m_key.start();
                if (loadgenlba > storelba) {
                    // loadgen missing the entry , which is ok, skip store lba
                } else if (loadgenlba < storelba) {
                    // missing entry in store
                    error_cb(generator_op_error::data_validation_failed, loadgenki.m_ki, nullptr, "");
                } else {
                    // compare values
                    ValueEntry tve(sid, BlkId(storeblk, 1, chunk), 0, 1, carr);
                    V          tmv(tve);
                    if (!loadgenki->validate_hash_code(tmv.get_hash_code(), exclusive_access)) {

                        // hashcode did not match, try to match direct last value
                        if (exclusive_access && 0 == tmv.compare(*loadgenki.m_ki->get_value().get())) {
                            // good
                        } else {
                            error_cb(generator_op_error::data_validation_failed, loadgenki.m_ki, nullptr, "");
                        }
                    }
                    l_itr++;
                }
                storelba++;
                storeblk++;
            }
            s_itr++;
        }
        if (l_itr == loadgenkv.end() && s_itr != storekv.end()) {
            error_cb(generator_op_error::data_missing, nullptr, nullptr, fmt::format("More data found than expected"));
        } else if (l_itr != loadgenkv.end() && s_itr == storekv.end()) {
            error_cb(generator_op_error::data_missing, (*l_itr).m_ki, nullptr,
                     fmt::format("Less data found than expected"));
        }
    }
    virtual bool range_update(K& start_key, bool start_incl, K& end_key, bool end_incl, V& start_value, V& end_value) {
        assert(start_incl);
        assert(end_incl);
        boost::intrusive_ptr< volume_req > req = volume_req::make_request();

        req->seqId = INVALID_SEQ_ID;
        req->lastCommited_seqId = INVALID_SEQ_ID; // keeping only latest version always

        req->blkId = start_value.get_blkId();
        req->blkId.set_nblks(end_value.end() - start_value.start() + 1);

        req->lba = start_key.start();
        req->nlbas = end_key.end() - req->lba + 1;

        MappingKey key(req->lba, req->nlbas);

        std::array< uint16_t, CS_ARRAY_STACK_SIZE > carr;
        for (auto i = 0ul; i < CS_ARRAY_STACK_SIZE; i++)
            carr[i] = 1;

        // NOTE assuming data block size is same as lba-volume block size
        ValueEntry ve(INVALID_SEQ_ID, BlkId(req->blkId.get_id(), req->blkId.get_nblks(), 0), 0, req->blkId.get_nblks(),
                      carr);
        MappingValue value(ve);
#ifndef NDEBUG
        req->vol_uuid = uuid;
#endif
        req->state = writeback_req_state::WB_REQ_COMPL;
        LOGDEBUG("Mapping range put:{} {} ", key.to_string(), value.to_string());

        assert(req->nlbas == req->blkId.get_nblks());
        m_map->put(req, key, value);

        return true;
    }

private:
    std::unique_ptr< mapping > m_map;
    boost::uuids::uuid         uuid;
};

} // namespace loadgen
} // namespace homeds

#endif // HOMESTORE_MAP_STORE_SPEC_HPP
