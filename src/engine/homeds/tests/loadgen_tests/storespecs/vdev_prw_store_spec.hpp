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
// vdev plugin for pread/pwrite;
//
// VDevKey generates offset reserved;
// VDevValue is the data buffer written to vdev;
//
// pread/rwrite APIs are not thread-safe;
//
class VDevPRWStoreSpec : public StoreSpec< VDevKey, VDevValue > {
    struct write_info {
        uint64_t size;
        uint64_t crc;
    };

public:
    virtual void init_store(homeds::loadgen::Param& parameters) override {
        m_store = HomeBlks::instance()->get_logdev_blkstore();
    }

    virtual bool get(VDevKey& k, VDevValue* out_v) override { return pread(k, out_v); }

    void verify_read(ssize_t bytes_read, uint8_t* buf, uint64_t off, uint64_t count) {
        if (bytes_read == -1) { HS_ASSERT(DEBUG, false, "bytes_read returned -1, errno: {}", errno); }

        HS_ASSERT_CMP(DEBUG, (size_t)bytes_read, ==, count);

        auto crc = util::Hash64((const char*)buf, (size_t)bytes_read);
        HS_ASSERT_CMP(DEBUG, crc, ==, m_off_to_info_map[off].crc, "CRC Mismatch: read out crc: {}, saved write: {}",
                      crc, m_off_to_info_map[off].crc);
    }

    // read
    bool pread(VDevKey& k, VDevValue* out_v) {
        std::lock_guard< std::mutex > l(m_mtx);
        auto off = k.get_offset();
        auto count = m_off_to_info_map[off].size;

        assert(count == k.get_alloc_size());

        uint8_t* buf = iomanager.iobuf_alloc(512, count);

        auto bytes_read = m_store->pread((void*)buf, (size_t)count, (off_t)off);
        verify_read(bytes_read, buf, off, count);

        iomanager.iobuf_free(buf);
        m_read_cnt++;
        print_counter();
        return true;
    }

    // write is just append;
    virtual bool insert(VDevKey& k, std::shared_ptr< VDevValue > v) override { return pwrite(k, v); }

    bool pwrite(VDevKey& k, std::shared_ptr< VDevValue > v) {
        std::lock_guard< std::mutex > l(m_mtx);
        auto off = k.get_offset();
        auto count = k.get_alloc_size();
        v->update_value(count);
        auto buf = v->get_buf();

        if (m_write_sz + count > m_store->get_size()) {
            LOGWARN("Expected out of space: write size {} : {} will exceed blkstore maximum size: {}", m_write_sz,
                    count, m_store->get_size());
            return true;
        }

        auto bytes_written = m_store->pwrite(buf, count, off);

        HS_ASSERT_CMP(DEBUG, bytes_written, !=, -1, "bytes_written returned -1, errno: {}", errno);
        HS_ASSERT_CMP(DEBUG, (size_t)bytes_written, ==, count);

        m_write_cnt++;
        m_off_to_info_map[off].size = count;
        m_off_to_info_map[off].crc = v->get_hash_code();

        print_counter();
        m_write_sz += count;
        return true;
    }

    virtual bool upsert(VDevKey& k, std::shared_ptr< VDevValue > v) override {
        assert(0);
        return true;
    }

    //
    // over-write
    //
    // vdev APIs doesn't have usecase for overwrite
    //
    virtual bool update(VDevKey& k, std::shared_ptr< VDevValue > v) override { return true; }

    virtual bool remove(VDevKey& k, VDevValue* removed_v = nullptr) override {
        assert(0);
        return true;
    }

    virtual bool remove_any(VDevKey& start_key, bool start_incl, VDevKey& end_key, bool end_incl, VDevKey* out_key,
                            VDevValue* out_val) override {
        assert(0);
        return true;
    }

    virtual uint32_t query(VDevKey& start_key, bool start_incl, VDevKey& end_key, bool end_incl,
                           std::vector< std::pair< VDevKey, VDevValue > >& result) {
        assert(0);
        return 1;
    }

    virtual bool range_update(VDevKey& start_key, bool start_incl, VDevKey& end_key, bool end_incl,
                              std::vector< std::shared_ptr< VDevValue > >& result) {
        assert(0);
        return true;
    }

private:
    void print_counter() {
        static uint64_t pt = 30;
        static Clock::time_point pt_start = Clock::now();

        auto elapsed_time = get_elapsed_time(pt_start);
        if (elapsed_time > pt) {
            LOGINFO("write ios cmpled: {}", m_write_cnt);
            LOGINFO("read ios cmpled: {}", m_read_cnt);
            pt_start = Clock::now();
        }
    }

    uint64_t get_elapsed_time(Clock::time_point start) {
        std::chrono::seconds sec = std::chrono::duration_cast< std::chrono::seconds >(Clock::now() - start);
        return sec.count();
    }

private:
    uint64_t m_write_cnt = 0;
    uint64_t m_read_cnt = 0;
    uint64_t m_write_sz = 0;
    homestore::BlkStore< homestore::VdevVarSizeBlkAllocatorPolicy >* m_store;
    std::map< uint64_t, write_info > m_off_to_info_map; // off to write info
    std::vector< uint64_t > m_off_arr;                  // unique off write
    std::mutex m_mtx;
};

} // namespace loadgen
} // namespace homeds
