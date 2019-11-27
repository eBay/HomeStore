//
//  Created by Yaming Kuang
//
#pragma once

#include "homeds/loadgen/spec/store_spec.hpp"
#include "homeds/tests/loadgen_tests/keyspecs/vdev_key_spec.hpp"
#include "homeds/tests/loadgen_tests/valuespecs/vdev_value_spec.hpp"

namespace homeds {
namespace loadgen {

// 
// For vdev plugin, 
// VDevKey is not used
// VDevValue is the data buffer written to vdev
//
class VDevStoreSpec : public StoreSpec< VDevKey, VDevValue > {
public:
    virtual void init_store(homeds::loadgen::Param& parameters) override { 
        m_store = HomeBlks::instance()->get_logdev_blkstore();
    }

    // read
    virtual bool get(VDevKey& k, VDevValue* out_v) override { 
        auto off = k.get_key_val();
        auto count = m_off_to_size_map[off];
        uint8_t buf[count];
        auto bytes_read = m_store->pread((void*)buf, (size_t)count, (off_t)off);

        if (bytes_read == -1) {
            HS_ASSERT(DEBUG, false, "bytes_read returned -1, errno: {}", errno);
        }

        HS_ASSERT_CMP(DEBUG, (size_t)bytes_read, ==, count);

        auto crc = util::Hash64((const char*)buf, (size_t)bytes_read);
        HS_ASSERT_CMP(DEBUG, crc, ==, m_off_to_crc_map[off], "CRC Mismatch: read out crc: {}, saved write: {}", crc, m_off_to_crc_map[off]);

        m_read_cnt++;
        return true;
    }
    
    // write is just append;
    virtual bool insert(VDevKey& k, std::shared_ptr<VDevValue> v) override {
        auto off = k.get_key_val();
        auto buf = v->get_buf();
        auto count = v->get_size();
        auto bytes_written = m_store->pwrite(buf, count, off);
        if (bytes_written == -1) {
            HS_ASSERT(DEBUG, false, "bytes_written returned -1, errno: {}", errno);
        }

        HS_ASSERT_CMP(DEBUG, (size_t)bytes_written, ==, count);

        m_write_cnt++;
        m_off_to_size_map[off] = count;
        m_off_to_crc_map[off] = v->get_hash_code();
        return true;
    }

    virtual bool upsert(VDevKey& k, std::shared_ptr<VDevValue> v) override {
        assert(0);
        return true;
    }

    // 
    // over-write
    // 
    // vdev doesn't support overwrite
    //
    virtual bool update(VDevKey& k, std::shared_ptr<VDevValue> v) override {
        return true;
    }

    virtual bool remove(VDevKey& k, VDevValue* removed_v = nullptr) override {
        assert(0);
        return true;
    }
     
    virtual bool remove_any(VDevKey& start_key, bool start_incl, VDevKey& end_key, bool end_incl, VDevKey *out_key, VDevValue* out_val) override {
        assert(0);
        return true;
    }

    virtual uint32_t query(VDevKey& start_key, bool start_incl, VDevKey& end_key, bool end_incl, std::vector<std::pair<VDevKey, VDevValue>> &result) {
        assert(0);
        return 1;
    }

    virtual bool range_update(VDevKey& start_key, bool start_incl, VDevKey& end_key, bool end_incl, 
                              std::vector< std::shared_ptr<VDevValue> > &result) {
        assert(0);
        return true;
    }

private:
    uint64_t                                                                m_write_cnt;   
    uint64_t                                                                m_read_cnt;   
    homestore::BlkStore< homestore::VdevVarSizeBlkAllocatorPolicy >*        m_store;
    std::map<uint64_t, uint64_t>                                            m_off_to_size_map;    // offset to buf size map;
    std::map<uint64_t, uint64_t>                                            m_off_to_crc_map;     // offset to buf crc map;
};

}
}
