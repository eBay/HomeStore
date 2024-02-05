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
#include <vector>

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

SISL_OPTIONS_ENABLE(logging, test_journal_vdev, iomgr, test_common_setup)
std::vector< std::string > test_common::HSTestHelper::s_dev_names;

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
SISL_LOGGING_DECL(test_journal_vdev)
static Param gp;

// trigger truncate when used space ratio reaches more than 80%
constexpr uint32_t dma_alignment = 512;

class VDevJournalIOTest : public ::testing::Test {
public:
    const std::map< uint32_t, test_common::HSTestHelper::test_params > svc_params = {};

    virtual void SetUp() override {
        auto const ndevices = SISL_OPTIONS["num_devs"].as< uint32_t >();
        auto const dev_size = SISL_OPTIONS["dev_size_mb"].as< uint64_t >() * 1024 * 1024;
        test_common::HSTestHelper::start_homestore("test_journal_vdev",
                                                   {
                                                       {HS_SERVICE::META, {.size_pct = 15.0}},
                                                       {HS_SERVICE::LOG,
                                                        {.size_pct = 50.0,
                                                         .chunk_size = 32 * 1024 * 1024,
                                                         .vdev_size_type = vdev_size_type_t::VDEV_SIZE_DYNAMIC}},
                                                   },
                                                   nullptr /* starting_cb */, false /* restart */);
    }

    virtual void TearDown() override { test_common::HSTestHelper::shutdown_homestore(); }

    void restart_homestore() {
        test_common::HSTestHelper::start_homestore("test_journal_vdev",
                                                   {
                                                       {HS_SERVICE::META, {.size_pct = 15.0}},
                                                       {HS_SERVICE::LOG,
                                                        {.size_pct = 50.0,
                                                         .chunk_size = 32 * 1024 * 1024,
                                                         .vdev_size_type = vdev_size_type_t::VDEV_SIZE_DYNAMIC}},
                                                   },
                                                   nullptr /* starting_cb */, true /* restart */);
    }
};

class JournalDescriptorTest {
    struct write_info {
        uint64_t size;
        uint64_t crc;
    };

public:
    JournalDescriptorTest(logdev_id_t id) : m_logdev_id(id) { reinit(); }

    std::shared_ptr< JournalVirtualDev::Descriptor > vdev_jd() { return m_vdev_jd; }

    void reinit() {
        auto vdev = hs()->logstore_service().get_vdev();
        m_vdev_jd = vdev->open(m_logdev_id);
    }

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

    void longrunning() {
        m_start_time = Clock::now();
        // m_store = HomeBlks::instance()->get_data_logdev_blkstore();

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
        auto used_space = m_vdev_jd->used_size();

        static thread_local std::random_device rd{};
        static thread_local std::default_random_engine generator{rd()};
        std::uniform_int_distribution< long long unsigned > dist{m_start_off + used_space / 5,
                                                                 m_start_off + (used_space * 4) / 5};

        auto rand_off = dist(generator);
        off_t off = sisl::round_up(rand_off, dma_alignment);

        // if it is larger than total size, ring back to valid offset;
        assert(off <= m_vdev_jd->end_offset());
        return off >= m_vdev_jd->end_offset() ? (off - m_vdev_jd->end_offset()) : off;
    }

    void truncate(off_t off_to_truncate) {
        LOGDEBUG("truncating to offset: 0x{}, start: 0x{}, tail: 0x{}", to_hex(off_to_truncate),
                 to_hex(m_vdev_jd->data_start_offset()), to_hex(m_vdev_jd->tail_offset()));

        validate_truncate_offset(off_to_truncate);

        auto tail_before = m_vdev_jd->tail_offset();
        m_vdev_jd->truncate(off_to_truncate);
        auto tail_after = m_vdev_jd->tail_offset();

        HS_DBG_ASSERT_EQ(tail_before, tail_after);
        HS_DBG_ASSERT_EQ(off_to_truncate, m_vdev_jd->data_start_offset());

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
            LOGDEBUG("truncating before start offset, looping back to beginning devices at offset: 0x{}",
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
            LOGDEBUG("write: {}, read: {}, truncate: {}, truncate_loop_back: {}", m_wrt_cnt, m_read_cnt, m_truncate_cnt,
                     m_truncate_loop_back_cnt);
            pt_start = Clock::now();
        }
    }

    void space_usage_asserts() {
        auto used_space = m_vdev_jd->used_size();
        auto start_off = m_vdev_jd->data_start_offset();

        HS_DBG_ASSERT_GT(m_vdev_jd->size(), 0);
        HS_DBG_ASSERT_LT(used_space, m_vdev_jd->size());
        HS_DBG_ASSERT_EQ(start_off, m_start_off);
    }

    bool time_to_truncate() {
        auto used_space = m_vdev_jd->used_size();

        if (gp.truncate_watermark_percentage <= (100 * used_space / m_vdev_jd->size())) { return true; }
        return false;
    }

    void validate_truncate_offset(off_t off) {
        HS_DBG_ASSERT_LE(off, m_vdev_jd->end_offset());

        validate_read_offset(off);
    }

    void validate_write_offset(off_t off, uint64_t sz) {
        auto tail_offset = m_vdev_jd->tail_offset();
        auto start_offset = m_vdev_jd->data_start_offset();

        HS_DBG_ASSERT_LE(off + static_cast< off_t >(sz), m_vdev_jd->end_offset());

        if ((off + sz) == m_vdev_jd->size()) {
            // TODO confirm if this needed if no loop back.
            // HS_DBG_ASSERT_EQ((uint64_t)0, (uint64_t)tail_offset);
        } else {
            HS_DBG_ASSERT_EQ((uint64_t)(off + sz), (uint64_t)tail_offset);
        }
    }

    void validate_read_offset(off_t off) {
        auto tail_offset = m_vdev_jd->tail_offset();
        auto start_offset = m_vdev_jd->data_start_offset();

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
        read_and_validate(off_to_read);
    }

    void read_all() {
        // Validate all the offsets.
        for (const auto& iter : m_off_to_info_map) {
            read_and_validate(iter.first);
        }
    }

    void read_and_validate(off_t off_to_read) {
        auto& write_info = m_off_to_info_map[off_to_read];
        LOGDEBUG("reading on offset: 0x{}, size: {}, start: 0x{}, tail: 0x{}", to_hex(off_to_read), write_info.size,
                 to_hex(m_start_off), to_hex(m_vdev_jd->tail_offset()));

        validate_read_offset(off_to_read);

        auto buf = iomanager.iobuf_alloc(512, write_info.size);
        auto ec = m_vdev_jd->sync_pread(buf, (size_t)write_info.size, (off_t)off_to_read);
        HS_REL_ASSERT(!ec, "Error in reading");
        auto count = *(uint64_t*)buf;

        auto crc = util::Hash64((const char*)buf, (size_t)write_info.size);
        HS_DBG_ASSERT_EQ(crc, write_info.crc,
                         "CRC Mismatch: offset: 0x{} size: {} count: {} read out crc: {}, saved write: {}",
                         to_hex(off_to_read), write_info.size, count, crc, write_info.crc);
        iomanager.iobuf_free(buf);
        m_read_cnt++;
    }

    void random_write() {
        auto sz_to_wrt = rand_size();
        auto off_to_wrt = m_vdev_jd->alloc_next_append_blk(sz_to_wrt);

        auto it = m_off_to_info_map.find(off_to_wrt);
        if (it != m_off_to_info_map.end()) {
            LOGERROR("write offset already exists, off: 0x{}, size: {}, crc: 0x{}", to_hex(it->first), it->second.size,
                     to_hex(it->second.crc));
            HS_DBG_ASSERT(it == m_off_to_info_map.end(),
                          "assert failure writing to some offset: {} that's already in the map!", off_to_wrt);
        }

        validate_write_offset(off_to_wrt, sz_to_wrt);

        m_wrt_cnt++;
        auto buf = iomanager.iobuf_alloc(512, sz_to_wrt);
        gen_rand_buf(buf, sz_to_wrt);
        *(uint64_t*)buf = m_wrt_cnt;

        m_vdev_jd->sync_pwrite(buf, sz_to_wrt, off_to_wrt);
        HS_DBG_ASSERT_LT((size_t)off_to_wrt, (size_t)m_vdev_jd->end_offset());

        m_off_to_info_map[off_to_wrt].size = sz_to_wrt;
        m_off_to_info_map[off_to_wrt].crc = util::Hash64((const char*)buf, (size_t)sz_to_wrt);

        LOGDEBUG("writing to bytes offset: 0x{}, size: {}, write_count: {} start: 0x{}, tail: 0x{} crc: 0x{}",
                 to_hex(off_to_wrt), sz_to_wrt, m_wrt_cnt, to_hex(m_start_off), to_hex(m_vdev_jd->tail_offset()),
                 m_off_to_info_map[off_to_wrt].crc);

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
    logdev_id_t m_logdev_id = 0;
    off_t m_start_off = 0;
    uint64_t m_wrt_cnt = 0;
    uint64_t m_read_cnt = 0;
    uint64_t m_truncate_cnt = 0;
    uint64_t m_truncate_loop_back_cnt = 0;
    std::map< off_t, write_info > m_off_to_info_map;
    Clock::time_point m_start_time;
    std::shared_ptr< JournalVirtualDev::Descriptor > m_vdev_jd;
    friend class VDevJournalIOTest;
};

// TODO add more tests covering unclean shutdown and more corner cases.

TEST_F(VDevJournalIOTest, LongRunning) {
    // Create multiple journal descriptors and run long running test
    // of random read, write and truncate parallely.
    auto num_vdev_jd = SISL_OPTIONS["num_vdev_jd"].as< uint32_t >();
    std::vector< std::thread > threads;
    for (uint32_t i = 0; i < num_vdev_jd; i++) {
        logdev_id_t id = i + 2; // 0 and 1 are used for data and control logdev family.
        threads.emplace_back(std::thread([id] { JournalDescriptorTest(id).longrunning(); }));
    }
    for (auto& t : threads)
        t.join();
}

TEST_F(VDevJournalIOTest, Recovery) {
    // Create multiple journal descriptors and add log entries, truncate
    // do restart, add more entries and verify the log entries.
    gp.fixed_wrt_sz_enabled = true;
    gp.fixed_wrt_sz = 1024;
    int num_entries = 1024;

    auto num_vdev_jd = SISL_OPTIONS["num_vdev_jd"].as< uint32_t >();
    std::vector< JournalDescriptorTest > tests;
    for (uint32_t i = 0; i < num_vdev_jd; i++) {
        logdev_id_t id = i + 2; // 0 and 1 are used for data and control logdev family.
        tests.emplace_back(JournalDescriptorTest(id));
    }

    LOGINFO("Add log entries");
    // Write 512k logs which should create more chunks dynamically.
    for (uint32_t i = 0; i < tests.size(); i++) {
        for (int j = 0; j < num_entries; j++) {
            tests[i].random_write();
        }
    }

    // Validate all logs.
    LOGINFO("Validate log entries");
    for (uint32_t i = 0; i < tests.size(); i++) {
        tests[i].read_all();
    }

    // Truncate and validate logs.
    for (uint32_t i = 0; i < tests.size(); i++) {
        tests[i].truncate(tests[i].get_rand_truncate_offset());
        tests[i].read_all();
    }

    LOGINFO("Restart homestore");

    // Record the offsets of the journal descriptors.
    std::vector< uint64_t > last_tail_offset, last_start_offset;
    for (uint32_t i = 0; i < tests.size(); i++) {
        auto vdev_jd = tests[i].vdev_jd();
        last_tail_offset.push_back(vdev_jd->tail_offset());
        last_start_offset.push_back(vdev_jd->data_start_offset());
    }

    // Restart homestore.
    restart_homestore();

    // Set the offsets after restart.
    for (uint32_t i = 0; i < tests.size(); i++) {
        tests[i].reinit();
        auto vdev_jd = tests[i].vdev_jd();
        vdev_jd->update_data_start_offset(last_start_offset[i]);
        vdev_jd->update_tail_offset(last_tail_offset[i]);
    }

    // Validate all logs.
    for (uint32_t i = 0; i < tests.size(); i++) {
        tests[i].read_all();
    }

    LOGINFO("Add log entries");
    // Write 512k logs which should create more chunks dynamically.
    for (uint32_t i = 0; i < tests.size(); i++) {
        for (int j = 0; j < num_entries; j++) {
            tests[i].random_write();
        }
    }

    // Validate all logs.
    for (uint32_t i = 0; i < tests.size(); i++) {
        tests[i].read_all();
    }

    // Truncate and validate all logs.
    LOGINFO("Validate log entries");
    for (uint32_t i = 0; i < tests.size(); i++) {
        tests[i].truncate(tests[i].get_rand_truncate_offset());
        tests[i].read_all();
    }
}

SISL_OPTION_GROUP(test_journal_vdev,
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
                  (per_read, "", "per_read", "read percentage of io that are reads",
                   ::cxxopts::value< uint32_t >()->default_value("20"), "number"),
                  (per_write, "", "per_write", "write percentage of io that are writes",
                   ::cxxopts::value< uint32_t >()->default_value("80"), "number"),
                  (num_vdev_jd, "", "num_vdev_jd", "number of descriptors for journal vdev",
                   ::cxxopts::value< uint32_t >()->default_value("4"), "number"));

int main(int argc, char* argv[]) {
    int parsed_argc = argc;
    ::testing::InitGoogleTest(&parsed_argc, argv);
    SISL_OPTIONS_LOAD(parsed_argc, argv, logging, test_journal_vdev, iomgr, test_common_setup);
    sisl::logging::SetLogger("test_journal_vdev");
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
