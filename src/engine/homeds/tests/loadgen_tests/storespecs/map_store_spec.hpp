//
// Modified by Amit Desai
//

#ifndef HOMESTORE_MAP_STORE_SPEC_HPP
#define HOMESTORE_MAP_STORE_SPEC_HPP

#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <boost/uuid/uuid.hpp>

#include "homeds/loadgen/spec/store_spec.hpp"
#include "homeblks/volume/volume.hpp"

namespace homeds {
namespace loadgen {

template < typename K, typename V, const size_t NodeSize = 8192 >
class MapStoreSpec : public StoreSpec< K, V > {
private:
    typedef std::function< void(generator_op_error, const key_info< K, V >*, void*, const std::string&) >
        store_error_cb_t;

    static auto gen_array() {
        std::array< uint16_t, CS_ARRAY_STACK_SIZE > carr;
        carr.fill(1);
        return carr;
    }

public:
    MapStoreSpec() = default;
    MapStoreSpec(const MapStoreSpec&) = delete;
    MapStoreSpec& operator=(const MapStoreSpec&) = delete;
    MapStoreSpec(MapStoreSpec&&) noexcept = delete;
    MapStoreSpec& operator=(MapStoreSpec&&) noexcept = delete;
    virtual ~MapStoreSpec() override = default;

    void process_metadata_completions(volume_req* const req) {
        LOGTRACE("MapInfo persisted:", req->lba(), req->nlbas());
    }

    void process_free_blk_callback(const Free_Blk_Entry& fbe) {
        // remove this assert if someone is actually calling this funciton
        assert(false);
    }

    virtual bool insert(K& k, std::shared_ptr< V > v) override { return update(k, v); }

    virtual bool upsert(K& k, std::shared_ptr< V > v) override { return update(k, v); }

    virtual void init_store(const homeds::loadgen::Param& parameters) override {
        /* Create a volume */
        vol_params params;
        params.page_size = NodeSize;
        params.size = 10 * Gi;
        params.uuid = boost::uuids::random_generator()();
        const std::string name{"vol1"};
        std::memcpy(static_cast< void* >(params.vol_name), static_cast< const void* >(name.c_str()),
                    (name.length() + 1));

        boost::uuids::string_generator gen;
        uuid = gen("01970496-0262-11e9-8eb2-f2801f1b9fd1");

        m_vol = VolInterface::get_instance()->create_volume(params);
        m_map = m_vol->get_active_indx();
        m_indx_mgr = m_vol->get_indx_mgr_instance();
    }

    /* Map put always appends if exists, no feature to force udpate/insert and return error */
    virtual bool update(K& k, std::shared_ptr< V > v) override {
        std::vector< std::shared_ptr< V > > result;
        result.push_back(v);
        range_update(k, true, k, true, result);
        return true;
    }

    virtual bool get(const K& k, V* const out_v) const override {
        std::vector< std::pair< K, V > > kvs;
        query(k, true, k, true, kvs);
        assert(kvs.size() <= 1);
        if (kvs.size() == 0) return false;
        out_v->copy_blob(kvs[0].second.get_blob());
        return true;
    }

    virtual bool remove(const K& k, V* const removed_v = nullptr) override {
        assert(false);
        return false; // map does not have remove impl
    }

    virtual bool remove_any(const K& start_key, const bool start_incl, const K& end_key, const bool end_incl,
                            K* const out_key, V* const out_val) override {
        assert(false);
        return false; // map does not have remove impl
    }

    virtual uint32_t query(const K& start_key, const bool start_incl, const K& end_key, const bool end_incl,
                           std::vector< std::pair< K, V > >& result) const override {
        auto search_range{BtreeSearchRange{start_key, start_incl, end_key, end_incl}};
        BtreeQueryRequest< K, V > qreq{search_range, BtreeQueryType::SWEEP_NON_INTRUSIVE_PAGINATION_QUERY,
                                       static_cast< uint32_t >(end_key.start() - start_key.start() + 1)};

        uint32_t result_count{0};
        const auto lba{start_incl ? start_key.start() : start_key.start() + 1};
        auto nblks{static_cast< uint32_t >(end_key.end() - lba + 1)};
        if (!end_incl) { --nblks; }

        mapping_op_cntx cntx;
        cntx.op = READ_VAL_WITH_seqid;
        cntx.vreq = nullptr;
        MappingKey key{lba, nblks};
        std::vector< std::pair< MappingKey, MappingValue > > kvs;
        BtreeQueryCursor cur;
        const auto ret{m_map->get(cntx, key, cur, kvs)};
        assert(ret == btree_status_t::success);
        uint64_t j{0};

        static const auto carr{gen_array()};
        for (auto next_lba{lba}; next_lba < lba + nblks;) {
            if (kvs[j].first.start() != next_lba) {
                ++next_lba;
                continue;
            }
            const ValueEntry* const ve{(kvs[j].second).get_nth_entry(0)};
            size_t cnt{0};
            while (next_lba <= kvs[j].first.end()) {
                const auto storeblk{
                    static_cast< blk_num_t >(ve->get_base_blkid().get_blk_num() + ve->get_lba_offset() + cnt)};

                result.push_back(std::make_pair(
                    K{next_lba, 1}, V{MappingValue{INVALID_SEQ_ID, BlkId{storeblk, 1u, 0u}, 0u, 1u, carr.data()}}));
                ++next_lba;
                ++cnt;
            }
            ++j;
        }

        result_count += result.size();
        return result_count;
    }

    virtual bool range_update(K& start_key, const bool start_incl, K& end_key, const bool end_incl,
                              std::vector< std::shared_ptr< V > >& result) override {
        assert(start_incl);
        assert(end_incl);

        const auto lba{start_key.start()};
        const auto nblks{static_cast< uint32_t >(end_key.end() - lba + 1)};
        auto iface_req{vol_interface_req_ptr(new vol_interface_req{nullptr, lba, nblks})};
        iface_req->vol_instance = m_vol;
        iface_req->op_type = Op_type::WRITE;
        auto req{volume_req::make(iface_req)};

        const V& start_value{*(result[0].get())};
        const V& end_value{*(result.back())};
        // update seq id since load test relies on seq id to be set before sending IO, because it use seqid as key to
        // get hash value;
        req->set_seq_id();
        req->lastCommited_seqid = req->seqid; // keeping only latest version always

        BlkId bid{start_value.get_blkId()};
        bid.set_nblks(end_value.end() - start_value.start() + 1);
        req->push_blkid(bid);

        MappingKey key{req->lba(), req->nlbas()};

        static const auto carr{gen_array()};

        // NOTE assuming data block size is same as lba-volume block size
        MappingValue value{req->seqid, BlkId{bid.get_blk_num(), bid.get_nblks(), 0}, 0, bid.get_nblks(), carr.data()};
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
        auto hs_cp{m_indx_mgr->cp_io_enter()};
        const auto cp_id{m_indx_mgr->get_btree_cp(hs_cp)};
        const auto ret{m_map->put(cntx, key, value, cp_id, cur)};
        m_indx_mgr->cp_io_exit(hs_cp);
        HS_REL_ASSERT_EQ(ret, btree_status_t::success);
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
