//
//  Created by Yaming Kuang
//
#pragma once

#include <cassert>
#include <chrono>
#include <cstdint>
#include <map>
#include <mutex>
#include <vector>

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
    VDevPRWStoreSpec() = default;
    VDevPRWStoreSpec(const VDevPRWStoreSpec&) = delete;
    VDevPRWStoreSpec& operator=(const VDevPRWStoreSpec&) = delete;
    VDevPRWStoreSpec(VDevPRWStoreSpec&&) noexcept = delete;
    VDevPRWStoreSpec& operator=(VDevPRWStoreSpec&&) noexcept = delete;
    virtual ~VDevPRWStoreSpec() override = default;

    virtual void init_store(const homeds::loadgen::Param& parameters) override {
        m_store = HomeBlks::instance()->get_data_logdev_blkstore();
    }

    virtual bool get(const VDevKey& k, VDevValue* const out_v) const override { return pread(k, out_v); }

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

    // read
    bool pread(const VDevKey& k, VDevValue* const out_v) const {
        std::lock_guard< std::mutex > l{m_mtx};
        const auto off{k.get_offset()};
        const auto itr{m_off_to_info_map.find(off)};
        assert(itr != std::cend(m_off_to_info_map));
        const auto count{itr->second.size};

        assert(count == k.get_alloc_size());

        uint8_t* const buf{iomanager.iobuf_alloc(512, count)};

        const auto bytes_read{
            m_store->pread(static_cast< void* >(buf), static_cast< size_t >(count), static_cast< off_t >(off))};
        verify_read(bytes_read, buf, off, count);

        iomanager.iobuf_free(buf);
        ++m_read_cnt;
        print_counter();
        return true;
    }

    // write is just append;
    virtual bool insert(VDevKey& k, std::shared_ptr< VDevValue > v) override { return pwrite(k, v); }

    bool pwrite(VDevKey& k, std::shared_ptr< VDevValue > v) {
        std::lock_guard< std::mutex > l(m_mtx);
        const auto off{k.get_offset()};
        const auto count{k.get_alloc_size()};
        v->update_value(count);
        const auto buf{v->get_buf()};

        if (m_write_sz + count > m_store->get_size()) {
            LOGWARN("Expected out of space: write size {} : {} will exceed blkstore maximum size: {}", m_write_sz,
                    count, m_store->get_size());
            return true;
        }

        const auto bytes_written{
            m_store->pwrite(static_cast< void* >(buf), static_cast< size_t >(count), static_cast< off_t >(off))};

        HS_ASSERT_CMP(DEBUG, bytes_written, !=, -1, "bytes_written returned -1, errno: {}", errno);
        HS_ASSERT_CMP(DEBUG, static_cast< std::decay_t< decltype(count) > >(bytes_written), ==, count);

        ++m_write_cnt;
        m_off_to_info_map[off].size = count;
        m_off_to_info_map[off].crc = v->get_hash_code();

        print_counter();
        m_write_sz += count;
        return true;
    }

    virtual bool upsert(VDevKey& k, std::shared_ptr< VDevValue > v) override {
        assert(false);
        return false;
    }

    //
    // over-write
    //
    // vdev APIs doesn't have usecase for overwrite
    //
    virtual bool update(VDevKey& k, std::shared_ptr< VDevValue > v) override { return true; }

    virtual bool remove(const VDevKey& k, VDevValue* const removed_v = nullptr) override {
        assert(false);
        return false;
    }

    virtual bool remove_any(const VDevKey& start_key, const bool start_incl, const VDevKey& end_key,
                            const bool end_incl, VDevKey* const out_key, VDevValue* const out_val) override {
        assert(false);
        return false;
    }

    virtual uint32_t query(const VDevKey& start_key, const bool start_incl, const VDevKey& end_key, const bool end_incl,
                           std::vector< std::pair< VDevKey, VDevValue > >& result) const override {
        assert(false);
        return 0;
    }

    virtual bool range_update(VDevKey& start_key, const bool start_incl, VDevKey& end_key, const bool end_incl,
                              std::vector< std::shared_ptr< VDevValue > >& result) override {
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

    uint64_t get_elapsed_time(const Clock::time_point& start) const {
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
