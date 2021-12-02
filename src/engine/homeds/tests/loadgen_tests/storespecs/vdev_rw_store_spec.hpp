//
//  Created by Yaming Kuang
//
#pragma once

#include <cassert>
#include <chrono>
#include <cstdint>
#include <map>
#include <mutex>
#include <random>
#include <vector>

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
        uint64_t size;
        uint64_t crc;
    };

public:
    VDevRWStoreSpec() = default;
    VDevRWStoreSpec(const VDevRWStoreSpec&) = delete;
    VDevRWStoreSpec& operator=(const VDevRWStoreSpec&) = delete;
    VDevRWStoreSpec(VDevRWStoreSpec&&) noexcept = delete;
    VDevRWStoreSpec& operator=(VDevRWStoreSpec&&) noexcept = delete;
    virtual ~VDevRWStoreSpec() override = default;

    virtual void init_store(const homeds::loadgen::Param& parameters) override {
        m_store = HomeBlks::instance()->get_data_logdev_blkstore();
    }

    virtual bool get(const SimpleNumberKey& k, VDevValue* const out_v) const override { return read(k, out_v); }

    //
    // 1. randomly pick up a offset that was priviously written by API `write` or `pwrite`
    // 2. lseek to this offset and do read
    // 3. Compare crc
    //
    bool read(const SimpleNumberKey& k, VDevValue* const out_v) const {
        static thread_local std::random_device rd{};
        static thread_local std::default_random_engine re{rd()};

        std::lock_guard< std::mutex > l{m_mtx};
        std::uniform_int_distribution< size_t > index_rand{0, m_off_arr.size() - 1};
        const auto index{index_rand(re)};
        const auto off{m_off_arr[index]};

        const auto itr{m_off_to_info_map.find(off)};
        assert(itr != std::cend(m_off_to_info_map));
        const auto count{itr->second.size};
        uint8_t* const buf{iomanager.iobuf_alloc(512, count)};

        const auto seeked_pos{m_store->lseek(off)};
        const auto bytes_read{m_store->read(static_cast< void* >(buf), static_cast< size_t >(count))};

        // verify seek is working fine;
        HS_ASSERT_CMP(DEBUG, static_cast< int64_t >(seeked_pos), ==, static_cast< int64_t >(off));

        // verify new seeked pos is good after read;
        HS_ASSERT_CMP(DEBUG, static_cast< int64_t >(seeked_pos + bytes_read), ==,
                      static_cast< int64_t >(m_store->seeked_pos()));

        verify_read(bytes_read, buf, off, count);

        iomanager.iobuf_free(buf);
        ++m_read_cnt;
        print_counter();
        return true;
    }

    void verify_read(const ssize_t bytes_read, const uint8_t* const buf, const uint64_t off,
                     const uint64_t count) const {
        if (bytes_read == -1) { HS_ASSERT(DEBUG, false, "bytes_read returned -1, errno: {}", errno); }

        HS_ASSERT_CMP(DEBUG, static_cast< uint64_t >(bytes_read), ==, count);

        const auto crc{util::Hash64(reinterpret_cast< const char* >(buf), static_cast< size_t >(bytes_read))};
        const auto itr{m_off_to_info_map.find(off)};
        if (itr != std::cend(m_off_to_info_map)) {
            HS_ASSERT_CMP(DEBUG, crc, ==, itr->second.crc, "CRC Mismatch: read out crc: {}, saved write: {}", crc,
                          itr->second.crc);
        } else {
            HS_DEBUG_ASSERT(false, "CRC Mismatch: off: {} does not exist in map", off);
        }
    }

    // write is just append;
    virtual bool insert(SimpleNumberKey& k, std::shared_ptr< VDevValue > v) override { return write(k, v); }

    //
    // write advances the cursor
    //
    bool write(SimpleNumberKey& k, std::shared_ptr< VDevValue > v) {
        std::lock_guard< std::mutex > l{m_mtx};
        const auto buf{v->get_buf()};
        const auto count{v->get_size()};

        // get curent offset
        const auto off{m_store->lseek(0, SEEK_CUR)};
        const auto cursor{m_store->seeked_pos()};

        HS_ASSERT_CMP(DEBUG, cursor, ==, off);

        if (m_write_sz + count > m_store->get_size()) {
            LOGWARN("Expected out of space: write size {} : {} will exceed blkstore maximum size: {}", m_write_sz,
                    count, m_store->get_size());
            return true;
        }

        const auto bytes_written{m_store->write(static_cast< void* >(buf), static_cast< size_t >(count))};

        const auto cursor_after_write{m_store->seeked_pos()};

        if (bytes_written == -1) { HS_ASSERT(DEBUG, false, "bytes_written returned -1, errno: {}", errno); }

        HS_ASSERT_CMP(DEBUG, static_cast< std::decay_t< decltype(count) > >(bytes_written), ==, count);

        HS_ASSERT_CMP(DEBUG, static_cast< int64_t >(cursor_after_write), ==,
                      static_cast< int64_t >(off + bytes_written),
                      "cursor: {} is not correct after write. write_cnt: {}, cursor before write: {}.",
                      cursor_after_write, bytes_written, off);

        ++m_write_cnt;
        m_off_to_info_map[off].size = count;
        m_off_to_info_map[off].crc = v->get_hash_code();
        m_off_arr.push_back(off);

        print_counter();
        m_write_sz += count;
        return true;
    }

    virtual bool upsert(SimpleNumberKey& k, std::shared_ptr< VDevValue > v) override {
        assert(false);
        return false;
    }

    //
    // over-write
    //
    // vdev APIs doesn't have usecase for overwrite
    //
    virtual bool update(SimpleNumberKey& k, std::shared_ptr< VDevValue > v) override { return true; }

    virtual bool remove(const SimpleNumberKey& k, VDevValue* const removed_v = nullptr) override {
        assert(false);
        return false;
    }

    virtual bool remove_any(const SimpleNumberKey& start_key, const bool start_incl, const SimpleNumberKey& end_key,
                            const bool end_incl, SimpleNumberKey* const out_key, VDevValue* const out_val) override {
        assert(false);
        return false;
    }

    virtual uint32_t query(const SimpleNumberKey& start_key, const bool start_incl, const SimpleNumberKey& end_key,
                           const bool end_incl,
                           std::vector< std::pair< SimpleNumberKey, VDevValue > >& result) const override {
        assert(false);
        return 0;
    }

    virtual bool range_update(SimpleNumberKey& start_key, const bool start_incl, SimpleNumberKey& end_key,
                              const bool end_incl, std::vector< std::shared_ptr< VDevValue > >& result) override {
        assert(false);
        return false;
    }

private:
    void print_counter() const {
        static constexpr uint64_t pt{30};
        static Clock::time_point pt_start{Clock::now()};

        const auto elapsed_time{get_elapsed_time(pt_start)};
        if (elapsed_time > pt) {
            LOGINFO("write ios cmpled: {}", m_write_cnt);
            LOGINFO("read ios cmpled: {}", m_read_cnt);
            pt_start = Clock::now();
        }
    }

    uint64_t get_elapsed_time(Clock::time_point start) const {
        const std::chrono::seconds sec{std::chrono::duration_cast< std::chrono::seconds >(Clock::now() - start)};
        return sec.count();
    }

private:
    uint64_t m_write_cnt{0};
    mutable uint64_t m_read_cnt{0};
    uint64_t m_write_sz{0};
    JournalVirtualDev* m_store;
    std::map< uint64_t, write_info > m_off_to_info_map; // off to write info
    std::vector< uint64_t > m_off_arr;                  // unique off write
    mutable std::mutex m_mtx;
};

} // namespace loadgen
} // namespace homeds
