//
// Modified by Amit Desai
//

#ifndef HOMESTORE_MAP_STORE_SPEC_HPP
#define HOMESTORE_MAP_STORE_SPEC_HPP

#include "homeds/loadgen/spec/store_spec.hpp"
#include "homeblks/volume/volume.hpp"

using namespace homeds::btree;
using namespace homestore;

namespace homeds {
namespace loadgen {
#define INVALID_SEQ_ID -1

template < typename K, typename V, size_t NodeSize = 8192 >
class MapStoreSpec : public StoreSpec< K, V > {
    typedef std::function< void(generator_op_error, const key_info< K, V >*, void*, const std::string&) >
        store_error_cb_t;

public:
    MapStoreSpec() {}

    void process_metadata_completions(volume_req* req) { LOGTRACE("MapInfo persisted:", req->lba(), req->nlbas()); }

    void process_free_blk_callback(Free_Blk_Entry fbe) {
        // remove this assert if someone is actually calling this funciton
        assert(0);
    }

    virtual bool insert(K& k, std::shared_ptr< V > v) override { return update(k, v); }

    virtual bool upsert(K& k, std::shared_ptr< V > v) override { return update(k, v); }

    virtual void init_store(homeds::loadgen::Param& parameters) override {
        /* Create a volume */
        vol_params params;
        params.page_size = NodeSize;
        params.size = 10 * Gi;
        params.uuid = boost::uuids::random_generator()();
        std::string name = "vol1";
        memcpy(params.vol_name, name.c_str(), (name.length() + 1));

        boost::uuids::string_generator gen;
        uuid = gen("01970496-0262-11e9-8eb2-f2801f1b9fd1");

        m_vol = VolInterface::get_instance()->create_volume(params);
        m_map = m_vol->get_active_indx();
        m_indx_mgr = m_vol->get_indx_mgr_instance();
    }

    /* Map put always appends if exists, no feature to force udpate/insert and return error */
    virtual bool update(K& k, std::shared_ptr< V > v) override {
        auto iface_req = vol_interface_req_ptr(new vol_interface_req(nullptr, k.start(), k.get_n_lba()));
        iface_req->vol_instance = m_vol;
        iface_req->op_type = Op_type::WRITE;
        auto req = volume_req::make(iface_req);
        ValueEntry ve;
        v->get_array().get(0, ve, false);
        ve.set_seqid(req->seqid);
        req->lastCommited_seqid = req->seqid; // keeping only latest version always
        req->push_blkid(ve.get_blkId());
        send_io(k, *(v.get()), req);
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
        auto lba = start_incl ? start_key.start() : start_key.start() + 1;
        auto nblks = end_key.end() - lba + 1;
        if (!end_incl) { --nblks; }

        mapping_op_cntx cntx;
        cntx.op = READ_VAL_WITH_seqid;
        cntx.vreq = nullptr;
        MappingKey key(lba, nblks);
        std::vector< std::pair< MappingKey, MappingValue > > kvs;
        BtreeQueryCursor cur;
        auto ret = m_map->get(cntx, key, cur, kvs);
        assert(ret == btree_status_t::success);
        uint64_t j = 0;

        std::array< uint16_t, CS_ARRAY_STACK_SIZE > carr;
        for (auto i = 0ul; i < CS_ARRAY_STACK_SIZE; i++) {
            carr[i] = 1;
        }

        for (uint64_t next_lba = lba; next_lba < lba + nblks;) {
            if (kvs[j].first.start() != next_lba) {
                next_lba++;
                continue;
            }
            ValueEntry ve;
            (kvs[j].second.get_array()).get(0, ve, false);
            int cnt = 0;
            while (next_lba <= kvs[j].first.end()) {
                auto storeblk = ve.get_blkId().get_blk_num() + ve.get_blk_offset() + cnt;
                ValueEntry ve(INVALID_SEQ_ID, BlkId(storeblk, 1, 0), 0, 1, &carr[0], 1);
                result.push_back(std::make_pair(K(next_lba, 1), V(ve)));
                next_lba++;
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

        auto lba = start_key.start();
        auto nblks = end_key.end() - lba + 1;
        auto iface_req = vol_interface_req_ptr(new vol_interface_req(nullptr, lba, nblks));
        iface_req->vol_instance = m_vol;
        iface_req->op_type = Op_type::WRITE;
        auto req = volume_req::make(iface_req);

        req->lastCommited_seqid = req->seqid; // keeping only latest version always
        V& start_value = *(result[0].get());
        V& end_value = *(result.back());

        req->lastCommited_seqid = INVALID_SEQ_ID; // keeping only latest version always

        BlkId bid = start_value.get_blkId();
        bid.set_nblks(end_value.end() - start_value.start() + 1);
        req->push_blkid(bid);

        MappingKey key(req->lba(), req->nlbas());

        std::array< uint16_t, CS_ARRAY_STACK_SIZE > carr;
        for (auto i = 0ul; i < CS_ARRAY_STACK_SIZE; i++)
            carr[i] = 1;

        // NOTE assuming data block size is same as lba-volume block size
        ValueEntry ve(req->seqid, BlkId(bid.get_blk_num(), bid.get_nblks(), 0), 0, bid.get_nblks(), &carr[0], 1);
        MappingValue value(ve);
        LOGDEBUG("Mapping range put:{} {} ", key.to_string(), value.to_string());

        send_io(key, value, req);
        assert(req->nlbas() == bid.get_nblks());
        return true;
    }

    auto send_io(MappingKey& key, MappingValue& value, volume_req_ptr& req) {
        mapping_op_cntx cntx;
        cntx.op = UPDATE_VAL_AND_FREE_BLKS;
        cntx.vreq = req.get();
        BtreeQueryCursor cur;
        auto hs_cp = m_indx_mgr->cp_io_enter();
        auto cp_id = m_indx_mgr->get_btree_cp(hs_cp);
        auto ret = m_map->put(cntx, key, value, cp_id, cur);
        m_indx_mgr->cp_io_exit(hs_cp);
        HS_ASSERT_CMP(RELEASE, ret, ==, btree_status_t::success);
        return ret;
    }

private:
    std::shared_ptr< Volume > m_vol;
    mapping* m_map;
    boost::uuids::uuid uuid;
    std::shared_ptr< SnapMgr > m_indx_mgr;
};

} // namespace loadgen
} // namespace homeds

#endif // HOMESTORE_MAP_STORE_SPEC_HPP
