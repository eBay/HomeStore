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
// For vdev plugin for read/write;
// SimpleNumberKey is not used
// VDevValue is the data buffer written to vdev
//
// read/write APIs are not thread-safe;
//
// TODO: add truncate API
//

class VDevRWStoreSpec : public StoreSpec< SimpleNumberKey, VDevValue > {
struct write_info {
    uint64_t    size;
    uint64_t    crc;
};

public:
    virtual void init_store(homeds::loadgen::Param& parameters) override { 
        m_store = HomeBlks::instance()->get_logdev_blkstore();
    }

    virtual bool get(SimpleNumberKey& k, VDevValue* out_v) override { 
        return read(k, out_v);
    }
    
    // 
    // 1. randomly pick up a offset that was priviously written by API `write` or `pwrite`
    // 2. lseek to this offset and do read
    // 3. Compare crc
    //
    bool read(SimpleNumberKey& k, VDevValue* out_v) { 
        std::lock_guard<std::mutex> l(m_mtx);
        auto index = rand() % m_off_arr.size();
        auto off = m_off_arr[index];

        auto count = m_off_to_info_map[off].size;

        uint8_t* buf = nullptr;
        auto ret = posix_memalign((void**)&buf, 4096, count);
        assert(!ret);

        auto seeked_pos = m_store->lseek(off);
        auto bytes_read = m_store->read((void*)buf, (size_t)count);

        // verify seek is working fine;
        HS_ASSERT_CMP(DEBUG, (uint64_t)seeked_pos, ==, (uint64_t)off);

        // verify new seeked pos is good after read;
        HS_ASSERT_CMP(DEBUG, (uint64_t)seeked_pos + bytes_read, ==, (uint64_t)m_store->seeked_pos());

        verify_read(bytes_read, buf, off, count);

        free(buf);
        m_read_cnt++;
        print_counter();
        return true;
    }

    void verify_read(ssize_t bytes_read, uint8_t* buf, uint64_t off, uint64_t count) {
        if (bytes_read == -1) {
            HS_ASSERT(DEBUG, false, "bytes_read returned -1, errno: {}", errno);
        }

        HS_ASSERT_CMP(DEBUG, (size_t)bytes_read, ==, count);

        auto crc = util::Hash64((const char*)buf, (size_t)bytes_read);
        HS_ASSERT_CMP(DEBUG, crc, ==, m_off_to_info_map[off].crc, 
                "CRC Mismatch: read out crc: {}, saved write: {}", 
                crc, m_off_to_info_map[off].crc);
    }

    // write is just append;
    virtual bool insert(SimpleNumberKey& k, std::shared_ptr<VDevValue> v) override {
        return write(k, v);
    }

    // 
    // write advances the cursor
    //
    bool write(SimpleNumberKey& k, std::shared_ptr<VDevValue> v) {
        std::lock_guard<std::mutex> l(m_mtx);
        auto buf = v->get_buf();
        auto count = v->get_size();
        
        // get curent offset
        auto off = m_store->lseek(0, SEEK_CUR);
        auto cursor = m_store->seeked_pos();

        HS_ASSERT_CMP(DEBUG, cursor, ==, off);

        if (m_write_sz + count > m_store->get_size()) {
            LOGWARN("Expected out of space: write size {} : {} will exceed blkstore maximum size: {}", m_write_sz, count, m_store->get_size());
            return true;
        }

        auto bytes_written = m_store->write(buf, count);
        
        auto cursor_after_write = m_store->seeked_pos();
        
        if (bytes_written == -1) {
            HS_ASSERT(DEBUG, false, "bytes_written returned -1, errno: {}", errno);
        }

        HS_ASSERT_CMP(DEBUG, (size_t)bytes_written, ==, count);

        HS_ASSERT_CMP(DEBUG, cursor_after_write, ==, off+ bytes_written, 
                "cursor: {} is not correct after write. write_cnt: {}, cursor before write: {}.", 
                cursor_after_write, bytes_written, off);

        m_write_cnt++;
        m_off_to_info_map[off].size = count;
        m_off_to_info_map[off].crc = v->get_hash_code();
        m_off_arr.push_back(off);
        
        print_counter();
        m_write_sz += count;
        return true;

    }

    virtual bool upsert(SimpleNumberKey& k, std::shared_ptr<VDevValue> v) override {
        assert(0);
        return true;
    }

    // 
    // over-write
    // 
    // vdev APIs doesn't have usecase for overwrite
    //
    virtual bool update(SimpleNumberKey& k, std::shared_ptr<VDevValue> v) override {
        return true;
    }

    virtual bool remove(SimpleNumberKey& k, VDevValue* removed_v = nullptr) override {
        assert(0);
        return true;
    }
     
    virtual bool remove_any(SimpleNumberKey& start_key, bool start_incl, SimpleNumberKey& end_key, bool end_incl, SimpleNumberKey *out_key, VDevValue* out_val) override {
        assert(0);
        return true;
    }

    virtual uint32_t query(SimpleNumberKey& start_key, bool start_incl, SimpleNumberKey& end_key, bool end_incl, std::vector<std::pair<SimpleNumberKey, VDevValue>> &result) {
        assert(0);
        return 1;
    }

    virtual bool range_update(SimpleNumberKey& start_key, bool start_incl, SimpleNumberKey& end_key, bool end_incl, 
                              std::vector< std::shared_ptr<VDevValue> > &result) {
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
    uint64_t                                                                m_write_cnt = 0;   
    uint64_t                                                                m_read_cnt = 0;   
    uint64_t                                                                m_write_sz = 0;   
    homestore::BlkStore< homestore::VdevVarSizeBlkAllocatorPolicy >*        m_store;
    std::map<uint64_t, write_info>                                          m_off_to_info_map;   // off to write info
    std::vector<uint64_t>                                                   m_off_arr;           // unique off write
    std::mutex                                                              m_mtx;
};

}
}
