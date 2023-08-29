/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 *********************************************************************************/
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <random>

#include <gtest/gtest.h>
#include <iomgr/io_environment.hpp>
#include <sisl/logging/logging.h>
#include <sisl/options/options.h>
#include <farmhash.h>

#include <homestore/homestore.hpp>
#include <homestore/logstore_service.hpp>
#include "device/virtual_dev.hpp"
#include "device/journal_vdev.hpp"
#include "common/homestore_utils.hpp"
#include "common/homestore_assert.hpp"
#include "test_common/homestore_test_common.hpp"

using namespace homestore;

RCU_REGISTER_INIT
SISL_LOGGING_INIT(HOMESTORE_LOG_MODS)

SISL_OPTIONS_ENABLE(logging, test_vdev, iomgr, test_common_setup)
std::vector< std::string > test_common::HSTestHelper::s_dev_names;
blk_allocator_type_t test_common::HSTestHelper::s_ds_alloc_type;
chunk_selector_type_t test_common::HSTestHelper::s_ds_chunk_sel_type;
struct Param {
    uint64_t num_io;
    uint64_t run_time;
    uint32_t per_read;
    uint32_t per_write;
    uint32_t per_remove;
    bool fixed_wrt_sz_enabled;
    uint32_t fixed_wrt_sz;
    uint32_t min_wrt_sz;
    uint32_t max_wrt_sz;
    uint32_t truncate_watermark_percentage;
};
SISL_LOGGING_DECL(test_vdev)
static Param gp;

// trigger truncate when used space ratio reaches more than 80%
constexpr uint32_t dma_alignment = 512;

class VDevIOTest : public ::testing::Test {
    struct write_info {
        uint64_t size;
        uint64_t crc;
    };

public:
    virtual void SetUp() override {
        auto const ndevices = SISL_OPTIONS["num_devs"].as< uint32_t >();
        auto const dev_size = SISL_OPTIONS["dev_size_mb"].as< uint64_t >() * 1024 * 1024;
        test_common::HSTestHelper::start_homestore("test_vdev", 15.0, 75.0, 5.0, 0, 0, nullptr);
        m_vdev = hs()->logstore_service().get_vdev(homestore::LogStoreService::DATA_LOG_FAMILY_IDX);
    }

    virtual void TearDown() override { test_common::HSTestHelper::shutdown_homestore(); }

    uint64_t get_elapsed_time(Clock::time_point start) {
        std::chrono::seconds sec = std::chrono::duration_cast< std::chrono::seconds >(Clock::now() - start);
        return sec.count();
    }

    uint64_t io_cnt() { return m_read_cnt + m_wrt_cnt; }

    bool keep_running() {
        if (get_elapsed_time(m_start_time) >= gp.run_time && io_cnt() >= gp.num_io) { return false; }
        return true;
    }

    uint32_t write_ratio() {
        if (m_wrt_cnt == 0) return 0;
        if (m_read_cnt == 0) return 100;
        return (100 * m_wrt_cnt) / (m_read_cnt + m_wrt_cnt);
    }

    bool do_write() {
        if (write_ratio() < gp.per_write) { return true; }

        return false;
    }

    void execute() {
        m_start_time = Clock::now();
        // m_store = HomeBlks::instance()->get_data_logdev_blkstore();
        m_total_size = m_vdev->size();

        while (keep_running()) {
            if (do_write()) {
                random_write();
            } else {
                random_read();
            }

            if (time_to_truncate()) { truncate(get_rand_truncate_offset()); }

            print_counters(30); // print every 30 seconds;
        }
    }

    // get random truncate offset between [m_start_off + used_space*20%, m_start_off + used_space*80%], rounded up to
    // 512 bytes;
    off_t get_rand_truncate_offset() {
        auto used_space = m_vdev->used_size();

        static thread_local std::random_device rd{};
        static thread_local std::default_random_engine generator{rd()};
        std::uniform_int_distribution< long long unsigned > dist{m_start_off + used_space / 5,
                                                                 m_start_off + (used_space * 4) / 5};

        auto rand_off = dist(generator);
        auto off = sisl::round_up(rand_off, dma_alignment);

        // if it is larger than total size, ring back to valid offset;
        return off >= m_total_size ? (off - m_total_size) : off;
    }

    void truncate(off_t off_to_truncate) {
        LOGINFO("truncating to offset: 0x{}, start: 0x{}, tail: 0x{}", to_hex(off_to_truncate),
                to_hex(m_vdev->data_start_offset()), to_hex(m_vdev->tail_offset()));

        validate_truncate_offset(off_to_truncate);

        auto tail_before = m_vdev->tail_offset();
        m_vdev->truncate(off_to_truncate);
        auto tail_after = m_vdev->tail_offset();

        HS_DBG_ASSERT_EQ(tail_before, tail_after);
        HS_DBG_ASSERT_EQ(off_to_truncate, m_vdev->data_start_offset());

        if (off_to_truncate > m_start_off) {
            // remove the offsets before truncate offset, since they are not valid for read anymore;
            for (auto it = m_off_to_info_map.begin(); it != m_off_to_info_map.end();) {
                if (it->first < off_to_truncate && it->first >= m_start_off) {
                    LOGDEBUG("remove offset: 0x{}", to_hex(it->first));
                    it = m_off_to_info_map.erase(it);
                } else {
                    it++;
                }
            }
        } else { // truncate offset is before m_start_off;
            LOGINFO("truncating before start offset, looping back to beginning devices at offset: 0x{}",
                    to_hex(off_to_truncate));
            m_truncate_loop_back_cnt++;
            // remove the offsets before truncate offset and after m_start_off;
            for (auto it = m_off_to_info_map.begin(); it != m_off_to_info_map.end();) {
                if ((it->first >= m_start_off) || (it->first < off_to_truncate)) {
                    LOGDEBUG("remove offset: 0x{}", to_hex(it->first));
                    it = m_off_to_info_map.erase(it);
                } else {
                    it++;
                }
            }
        }

        m_start_off = off_to_truncate;
        m_truncate_cnt++;

        space_usage_asserts();
    }

    void print_counters(uint64_t print_every_n_secs) {
        static Clock::time_point pt_start = Clock::now();

        auto elapsed_time = get_elapsed_time(pt_start);
        if (elapsed_time > print_every_n_secs) {
            LOGINFO("write: {}, read: {}, truncate: {}, truncate_loop_back: {}", m_wrt_cnt, m_read_cnt, m_truncate_cnt,
                    m_truncate_loop_back_cnt);
            pt_start = Clock::now();
        }
    }

    void space_usage_asserts() {
        auto used_space = m_vdev->used_size();
        auto start_off = m_vdev->data_start_offset();

        HS_DBG_ASSERT_GT(m_total_size, 0);
        HS_DBG_ASSERT_LT(used_space, m_total_size);
        HS_DBG_ASSERT_EQ(start_off, m_start_off);
    }

    bool time_to_truncate() {
        auto used_space = m_vdev->used_size();

        if (gp.truncate_watermark_percentage <= (100 * used_space / m_total_size)) { return true; }
        return false;
    }

    void validate_truncate_offset(off_t off) {
        HS_DBG_ASSERT_LE((uint64_t)off, m_total_size);

        validate_read_offset(off);
    }

    void validate_write_offset(off_t off, uint64_t sz) {
        auto tail_offset = m_vdev->tail_offset();
        auto start_offset = m_vdev->data_start_offset();

        HS_DBG_ASSERT_LE(off + sz, m_vdev->size());

        if ((off + sz) == m_vdev->size()) {
            HS_DBG_ASSERT_EQ((uint64_t)0, (uint64_t)tail_offset);
        } else {
            HS_DBG_ASSERT_EQ((uint64_t)(off + sz), (uint64_t)tail_offset);
        }
    }

    void validate_read_offset(off_t off) {
        auto tail_offset = m_vdev->tail_offset();
        auto start_offset = m_vdev->data_start_offset();

        HS_DBG_ASSERT_EQ(m_start_off, start_offset);
        if (start_offset < tail_offset) {
            HS_DBG_ASSERT_GE(off, start_offset, "Wrong offset: {}, start_off: {}", off, start_offset);
            HS_DBG_ASSERT_LT(off, tail_offset, "Wrong offset: {}, tail_offset: {}", off, tail_offset);
        } else {
            HS_DBG_ASSERT(off < tail_offset || off >= start_offset, "Wrong offset: {}, start: {}, tail: {}", off,
                          start_offset, tail_offset);
        }
    }

    void random_read() {
        auto it = m_off_to_info_map.begin();
        std::advance(it, rand() % m_off_to_info_map.size());
        auto off_to_read = it->first;

        LOGDEBUG("reading on offset: 0x{}, size: {}, start: 0x{}, tail: 0x{}", to_hex(off_to_read), it->second.size,
                 to_hex(m_start_off), to_hex(m_vdev->tail_offset()));

        // validate_read_offset(off_to_read);

        auto buf = iomanager.iobuf_alloc(512, it->second.size);
        m_vdev->sync_pread(buf, (size_t)it->second.size, (off_t)off_to_read);

        auto crc = util::Hash64((const char*)buf, (size_t)it->second.size);
        HS_DBG_ASSERT_EQ(crc, it->second.crc, "CRC Mismatch: read out crc: {}, saved write: {}", crc, it->second.crc);
        iomanager.iobuf_free(buf);
        m_read_cnt++;
    }

    void random_write() {
        auto sz_to_wrt = rand_size();
        auto off_to_wrt = m_vdev->alloc_next_append_blk(sz_to_wrt);

        auto it = m_off_to_info_map.find(off_to_wrt);
        if (it != m_off_to_info_map.end()) {
            LOGERROR("write offset already exists, off: 0x{}, size: {}, crc: 0x{}", to_hex(it->first), it->second.size,
                     to_hex(it->second.crc));
            HS_DBG_ASSERT(it == m_off_to_info_map.end(),
                          "assert failure writing to some offset: {} that's already in the map!", off_to_wrt);
        }

        validate_write_offset(off_to_wrt, sz_to_wrt);

        LOGDEBUG("writing to offset: 0x{}, size: {}, start: 0x{}, tail: 0x{}", to_hex(off_to_wrt), sz_to_wrt,
                 to_hex(m_start_off), to_hex(m_vdev->tail_offset()));

        auto buf = iomanager.iobuf_alloc(512, sz_to_wrt);
        gen_rand_buf(buf, sz_to_wrt);

        m_vdev->sync_pwrite(buf, sz_to_wrt, off_to_wrt);
        HS_DBG_ASSERT_LT((size_t)off_to_wrt, (size_t)m_total_size);

        m_wrt_cnt++;
        m_off_to_info_map[off_to_wrt].size = sz_to_wrt;
        m_off_to_info_map[off_to_wrt].crc = util::Hash64((const char*)buf, (size_t)sz_to_wrt);

        iomanager.iobuf_free(buf);
    }

    void gen_rand_buf(uint8_t* s, uint32_t len) {
        static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        for (size_t i = 0u; i < len - 1; ++i) {
            s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
        }
        s[len - 1] = 0;
    }

    // size between 512 ~ 8192, 512 aligned;
    uint32_t rand_size() {
        if (gp.fixed_wrt_sz_enabled) { return gp.fixed_wrt_sz; }

        static thread_local std::random_device rd{};
        static thread_local std::default_random_engine generator{rd()};
        std::uniform_int_distribution< long unsigned > dist{gp.min_wrt_sz, gp.max_wrt_sz};
        return sisl::round_up(dist(generator), dma_alignment);
    }

private:
    off_t m_start_off = 0;
    uint64_t m_wrt_cnt = 0;
    uint64_t m_read_cnt = 0;
    uint64_t m_truncate_cnt = 0;
    uint64_t m_truncate_loop_back_cnt = 0;
    uint64_t m_total_size = 0;
    std::map< off_t, write_info > m_off_to_info_map;
    Clock::time_point m_start_time;
    std::shared_ptr< JournalVirtualDev > m_vdev;
};

TEST_F(VDevIOTest, VDevIOTest) { this->execute(); }

SISL_OPTION_GROUP(test_vdev,
                  (truncate_watermark_percentage, "", "truncate_watermark_percentage",
                   "percentage of space usage to trigger truncate", ::cxxopts::value< uint32_t >()->default_value("80"),
                   "number"),
                  (fixed_write_size_enabled, "", "fixed_write_size_enabled", "fixed write size enabled 0 or 1",
                   ::cxxopts::value< uint32_t >()->default_value("0"), "flag"),
                  (fixed_write_size, "", "fixed_write_size", "fixed write size",
                   ::cxxopts::value< uint32_t >()->default_value("512"), "number"),
                  (min_write_size, "", "min_write_size", "minimum write size",
                   ::cxxopts::value< uint32_t >()->default_value("512"), "number"),
                  (max_write_size, "", "max_write_size", "maximum write size",
                   ::cxxopts::value< uint32_t >()->default_value("8192"), "number"),
                  (run_time, "", "run_time", "running time in seconds",
                   ::cxxopts::value< uint64_t >()->default_value("30"), "number"),
                  (num_io, "", "num_io", "number of io", ::cxxopts::value< uint64_t >()->default_value("3000"),
                   "number"),
                  (per_read, "", "per_read", "read percentage of io that are reads",
                   ::cxxopts::value< uint32_t >()->default_value("20"), "number"),
                  (per_write, "", "per_write", "write percentage of io that are writes",
                   ::cxxopts::value< uint32_t >()->default_value("80"), "number"));

int main(int argc, char* argv[]) {
    SISL_OPTIONS_LOAD(argc, argv, logging, test_vdev, iomgr, test_common_setup);
    ::testing::InitGoogleTest(&argc, argv);
    sisl::logging::SetLogger("test_vdev");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    gp.num_io = SISL_OPTIONS["num_io"].as< uint64_t >();
    gp.run_time = SISL_OPTIONS["run_time"].as< uint64_t >();
    gp.per_read = SISL_OPTIONS["per_read"].as< uint32_t >();
    gp.per_write = SISL_OPTIONS["per_write"].as< uint32_t >();
    gp.fixed_wrt_sz_enabled = SISL_OPTIONS["fixed_write_size_enabled"].as< uint32_t >();
    gp.fixed_wrt_sz = SISL_OPTIONS["fixed_write_size"].as< uint32_t >();
    gp.min_wrt_sz = SISL_OPTIONS["min_write_size"].as< uint32_t >();
    gp.max_wrt_sz = SISL_OPTIONS["max_write_size"].as< uint32_t >();
    gp.truncate_watermark_percentage = SISL_OPTIONS["truncate_watermark_percentage"].as< uint32_t >();

    if (gp.per_read == 0 || gp.per_write == 0 || (gp.per_read + gp.per_write != 100)) {
        gp.per_read = 20;
        gp.per_write = 80;
    }

    if (gp.truncate_watermark_percentage <= 5 || gp.truncate_watermark_percentage >= 95) {
        LOGERROR("truncate_watermark_percentage need to be between [5, 95], change to defaut value: 80");
        gp.truncate_watermark_percentage = 80;
    }

    LOGINFO("Testing with run_time: {}, num_io: {},  read/write percentage: {}/{}, truncate_watermark_percentage: {}",
            gp.run_time, gp.num_io, gp.per_read, gp.per_write, gp.truncate_watermark_percentage);

    if (gp.fixed_wrt_sz_enabled) {
        LOGINFO("Testing with fixed write size: {}", gp.fixed_wrt_sz);
    } else {
        LOGINFO("Testing with min write size: {}, max write size: {}", gp.min_wrt_sz, gp.max_wrt_sz);
    }

    return RUN_ALL_TESTS();
}
