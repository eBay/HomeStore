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
#include "common/homestore_utils.hpp"
#include "common/homestore_assert.hpp"
#include "logstore/log_dev.hpp"
#include "test_common/homestore_test_common.hpp"

using namespace homestore;

RCU_REGISTER_INIT
SISL_LOGGING_INIT(HOMESTORE_LOG_MODS)
SISL_OPTIONS_ENABLE(logging, test_log_dev, iomgr, test_common_setup)
SISL_LOGGING_DECL(test_log_dev)

struct test_log_data {
    test_log_data() = default;
    test_log_data(const test_log_data&) = delete;
    test_log_data(test_log_data&&) noexcept = delete;
    test_log_data& operator=(const test_log_data&) = delete;
    test_log_data& operator=(test_log_data&&) noexcept = delete;
    ~test_log_data() = default;

    uint32_t size;

    uint8_t* get_data() { return uintptr_cast(this) + sizeof(test_log_data); };
    uint8_t const* get_data_const() const { return r_cast< uint8_t const* >(this) + sizeof(test_log_data); }
    const uint8_t* get_data() const { return r_cast< const uint8_t* >(this) + sizeof(test_log_data); }
    uint32_t total_size() const { return sizeof(test_log_data) + size; }
    std::string get_data_str() const {
        return std::string(r_cast< const char* >(get_data_const()), static_cast< size_t >(size));
    }
};

class LogDevTest : public ::testing::Test {
public:
    test_common::HSTestHelper m_helper;
    static constexpr uint32_t max_data_size = 1024;
    uint64_t s_max_flush_multiple = 0;

    virtual void SetUp() override { start_homestore(); }

    void start_homestore(bool restart = false, hs_before_services_starting_cb_t starting_cb = nullptr) {
        auto const ndevices = SISL_OPTIONS["num_devs"].as< uint32_t >();
        auto const dev_size = SISL_OPTIONS["dev_size_mb"].as< uint64_t >() * 1024 * 1024;
        HS_SETTINGS_FACTORY().modifiable_settings([](auto& s) {
            // Disable flush timer in UT.
            s.logstore.flush_timer_frequency_us = 0;
            s.resource_limits.resource_audit_timer_ms = 0;
        });
        HS_SETTINGS_FACTORY().save();

        if (restart) {
            m_helper.change_start_cb(starting_cb);
            m_helper.restart_homestore();
        } else {
            m_helper.start_homestore("test_log_dev",
                                     {
                                         {HS_SERVICE::META, {.size_pct = 15.0}},
                                         {HS_SERVICE::LOG,
                                          {.size_pct = 50.0,
                                           .chunk_size = 8 * 1024 * 1024,
                                           .min_chunk_size = 8 * 1024 * 1024,
                                           .vdev_size_type = vdev_size_type_t::VDEV_SIZE_DYNAMIC}},
                                     },
                                     starting_cb);
        }
    }

    virtual void TearDown() override { m_helper.shutdown_homestore(); }

    test_log_data* prepare_data(const logstore_seq_num_t lsn, bool& io_memory, uint32_t fixed_size = 0) {
        static thread_local std::random_device rd{};
        static thread_local std::default_random_engine re{rd()};
        uint32_t sz{0};
        uint8_t* raw_buf{nullptr};

        // Generate buffer of random size and fill with specific data
        std::uniform_int_distribution< uint8_t > gen_percentage{0, 99};
        std::uniform_int_distribution< uint32_t > gen_data_size{0, max_data_size - 1};
        if (fixed_size == 0) {
            sz = gen_data_size(re);
        } else {
            sz = fixed_size;
        }
        if (gen_percentage(re) < static_cast< uint8_t >(10)) {
            // 10% of data is dma'ble aligned boundary
            const auto alloc_sz = sisl::round_up(sz + sizeof(test_log_data), s_max_flush_multiple);
            raw_buf = iomanager.iobuf_alloc(dma_address_boundary, alloc_sz);
            sz = alloc_sz - sizeof(test_log_data);
            io_memory = true;
        } else {
            raw_buf = static_cast< uint8_t* >(std::malloc(sizeof(test_log_data) + sz));
            io_memory = false;
        }

        test_log_data* d = new (raw_buf) test_log_data();
        d->size = sz;

        assert(uintptr_cast(d) == raw_buf);

        const char c = static_cast< char >((lsn % 94) + 33);
        std::memset(voidptr_cast(d->get_data()), c, static_cast< size_t >(d->size));
        return d;
    }

    void validate_data(std::shared_ptr< HomeLogStore > log_store, const test_log_data* d,
                       const logstore_seq_num_t lsn) {
        const char c = static_cast< char >((lsn % 94) + 33);
        const std::string actual = d->get_data_str();
        const std::string expected(static_cast< size_t >(d->size),
                                   c); // needs to be () because of same reason as vector
        ASSERT_EQ(actual, expected) << "Data mismatch for LSN=" << log_store->get_store_id() << ":" << lsn
                                    << " size=" << d->size;
    }

    void insert_sync(std::shared_ptr< HomeLogStore > log_store, logstore_seq_num_t lsn, uint32_t fixed_size = 0) {
        bool io_memory{false};
        auto* d = prepare_data(lsn, io_memory, fixed_size);
        log_store->write_and_flush(lsn, {uintptr_cast(d), d->total_size(), false});
        LOGINFO("Written sync data for LSN -> {}:{}", log_store->get_store_id(), lsn);
        if (io_memory) {
            iomanager.iobuf_free(uintptr_cast(d));
        } else {
            std::free(voidptr_cast(d));
        }
    }

    void kickstart_inserts(std::shared_ptr< HomeLogStore > log_store, logstore_seq_num_t& cur_lsn, int64_t batch,
                           uint32_t fixed_size = 0) {
        auto last = cur_lsn + batch;
        for (; cur_lsn < last; cur_lsn++) {
            insert_sync(log_store, cur_lsn, fixed_size);
        }
    }

    void read_verify(std::shared_ptr< HomeLogStore > log_store, logstore_seq_num_t lsn) {
        auto b = log_store->read_sync(lsn);
        auto* d = r_cast< test_log_data const* >(b.bytes());
        ASSERT_EQ(d->total_size(), b.size()) << "Size Mismatch for lsn=" << log_store->get_store_id() << ":" << lsn;
        validate_data(log_store, d, lsn);
    }

    void read_all_verify(std::shared_ptr< HomeLogStore > log_store) {
        const auto trunc_upto = log_store->truncated_upto();
        const auto upto = log_store->get_contiguous_completed_seq_num(-1);

        for (std::remove_const_t< decltype(trunc_upto) > i{0}; i <= trunc_upto; ++i) {
            ASSERT_THROW(log_store->read_sync(i), std::out_of_range)
                << "Expected std::out_of_range exception for lsn=" << log_store->get_store_id() << ":" << i
                << " but not thrown";
        }

        for (auto lsn = trunc_upto + 1; lsn < upto; lsn++) {
            try {
                read_verify(log_store, lsn);
            } catch (const std::exception& ex) {
                auto trunc_upto = log_store->truncated_upto();
                LOGFATAL("Failed to read at upto {} lsn {} trunc_upto {}", upto, lsn, trunc_upto);
            }
        }
    }

    void rollback_validate(std::shared_ptr< HomeLogStore > log_store, logstore_seq_num_t& cur_lsn,
                           uint32_t num_lsns_to_rollback) {
        cur_lsn -= num_lsns_to_rollback;
        auto const upto_lsn = cur_lsn - 1;
        log_store->rollback(upto_lsn);
        read_all_verify(log_store);
    }

    void truncate_validate(std::shared_ptr< HomeLogStore > log_store) {
        auto upto = log_store->get_contiguous_completed_seq_num(-1);
        LOGINFO("truncate_validate upto {}", upto);
        log_store->truncate(upto);
        read_all_verify(log_store);
        logstore_service().device_truncate();
    }

    void rollback_records_validate(std::shared_ptr< HomeLogStore > log_store, uint32_t expected_count) {
        auto actual_count = log_store->get_logdev()->log_dev_meta().num_rollback_records(log_store->get_store_id());
        ASSERT_EQ(actual_count, expected_count);
    }
};

TEST_F(LogDevTest, WriteSyncThenRead) {
    const auto iterations = SISL_OPTIONS["iterations"].as< uint32_t >();

    for (uint32_t iteration{0}; iteration < iterations; ++iteration) {
        LOGINFO("Iteration {}", iteration);
        auto logdev_id = logstore_service().create_new_logdev();
        s_max_flush_multiple = logstore_service().get_logdev(logdev_id)->get_flush_size_multiple();
        auto log_store = logstore_service().create_new_log_store(logdev_id, false);
        const auto store_id = log_store->get_store_id();
        LOGINFO("Created new log store -> id {}", store_id);
        const unsigned count{10};
        for (unsigned i{0}; i < count; ++i) {
            // Insert new entry.
            insert_sync(log_store, i);
            // Verify the entry.
            read_verify(log_store, i);
        }

        logstore_service().remove_log_store(logdev_id, store_id);
        LOGINFO("Remove logstore -> i {}", store_id);
    }
}

TEST_F(LogDevTest, Rollback) {
    LOGINFO("Step 1: Create a single logstore to start rollback test");
    auto logdev_id = logstore_service().create_new_logdev();
    s_max_flush_multiple = logstore_service().get_logdev(logdev_id)->get_flush_size_multiple();
    auto log_store = logstore_service().create_new_log_store(logdev_id, false);
    auto store_id = log_store->get_store_id();

    auto restart = [&]() {
        std::promise< bool > p;
        auto starting_cb = [&]() {
            logstore_service().open_logdev(logdev_id);
            logstore_service().open_log_store(logdev_id, store_id, false /* append_mode */).thenValue([&](auto store) {
                log_store = store;
                p.set_value(true);
            });
        };
        start_homestore(true /* restart */, starting_cb);
        p.get_future().get();
    };

    LOGINFO("Step 2: Issue sequential inserts with q depth of 10");
    logstore_seq_num_t cur_lsn = 0;
    kickstart_inserts(log_store, cur_lsn, 500);

    LOGINFO("Step 3: Rollback last 50 entries and validate if pre-rollback entries are intact");
    rollback_validate(log_store, cur_lsn, 50); // Last entry = 450

    LOGINFO("Step 4: Append 25 entries after rollback is completed");
    kickstart_inserts(log_store, cur_lsn, 25); // Last entry = 475

    LOGINFO("Step 5: Rollback again for 75 entries even before previous rollback entry");
    rollback_validate(log_store, cur_lsn, 75); // Last entry = 400

    LOGINFO("Step 6: Append 25 entries after second rollback is completed");
    kickstart_inserts(log_store, cur_lsn, 25); // Last entry = 425

    LOGINFO("Step 7: Restart homestore and ensure all rollbacks are effectively validated");
    restart();

    LOGINFO("Step 8: Post recovery, append another 25 entries");
    kickstart_inserts(log_store, cur_lsn, 25); // Last entry = 450

    LOGINFO("Step 9: Rollback again for 75 entries even before previous rollback entry");
    rollback_validate(log_store, cur_lsn, 75); // Last entry = 375

    LOGINFO("Step 10: After 3rd rollback, append another 25 entries");
    kickstart_inserts(log_store, cur_lsn, 25); // Last entry = 400

    LOGINFO("Step 11: Truncate all entries");
    truncate_validate(log_store);

    LOGINFO("Step 12: Restart homestore and ensure all truncations after rollbacks are effectively validated");
    restart();

    LOGINFO("Step 13: Append 25 entries after truncation is completed");
    kickstart_inserts(log_store, cur_lsn, 25); // Last entry = 425

    LOGINFO("Step 14: Do another truncation to effectively truncate previous records");
    truncate_validate(log_store);

    LOGINFO("Step 15: Validate if there are no rollback records");
    rollback_records_validate(log_store, 0 /* expected_count */);
}

TEST_F(LogDevTest, CreateRemoveLogDev) {
    auto num_logdev = SISL_OPTIONS["num_logdevs"].as< uint32_t >();
    std::vector< std::shared_ptr< HomeLogStore > > log_stores;
    auto vdev = logstore_service().get_vdev();

    // Create log dev, logstore, write some io. Delete all of them and
    // verify the size of vdev and count of logdev.
    auto log_devs = logstore_service().get_all_logdevs();
    ASSERT_EQ(log_devs.size(), 0);
    ASSERT_EQ(logstore_service().used_size(), 0);
    ASSERT_EQ(vdev->num_descriptors(), 0);

    for (uint32_t i{0}; i < num_logdev; ++i) {
        auto id = logstore_service().create_new_logdev();
        s_max_flush_multiple = logstore_service().get_logdev(id)->get_flush_size_multiple();
        auto store = logstore_service().create_new_log_store(id, false);
        log_stores.push_back(store);
    }

    // Used size is still 0.
    ASSERT_EQ(logstore_service().used_size(), 0);
    ASSERT_EQ(vdev->num_descriptors(), num_logdev);

    log_devs = logstore_service().get_all_logdevs();
    ASSERT_EQ(log_devs.size(), num_logdev);

    for (auto& log_store : log_stores) {
        const unsigned count{10};
        for (unsigned i{0}; i < count; ++i) {
            // Insert new entry.
            insert_sync(log_store, i);
            // Verify the entry.
            read_verify(log_store, i);
        }
    }

    // Used size should be non zero.
    ASSERT_GT(logstore_service().used_size(), 0);

    for (auto& store : log_stores) {
        logstore_service().remove_log_store(store->get_logdev()->get_id(), store->get_store_id());
    }
    for (auto& store : log_stores) {
        logstore_service().destroy_log_dev(store->get_logdev()->get_id());
    }

    // Test we released all chunks
    log_devs = logstore_service().get_all_logdevs();
    ASSERT_EQ(log_devs.size(), 0);
    ASSERT_EQ(vdev->num_descriptors(), 0);
    ASSERT_EQ(logstore_service().used_size(), 0);
}

TEST_F(LogDevTest, DeleteUnopenedLogDev) {
    auto num_logdev = SISL_OPTIONS["num_logdevs"].as< uint32_t >();
    std::vector< std::shared_ptr< HomeLogStore > > log_stores;
    auto vdev = logstore_service().get_vdev();

    // Test deletion of unopened logdev.
    std::set< logdev_id_t > id_set, unopened_id_set;
    for (uint32_t i{0}; i < num_logdev; ++i) {
        auto id = logstore_service().create_new_logdev();
        id_set.insert(id);
        if (i >= num_logdev / 2) { unopened_id_set.insert(id); }
        s_max_flush_multiple = logstore_service().get_logdev(id)->get_flush_size_multiple();
        auto store = logstore_service().create_new_log_store(id, false);
        log_stores.push_back(store);
    }

    // Write to all logstores so that there is atleast one chunk in each logdev.
    for (auto& log_store : log_stores) {
        const unsigned count{10};
        for (unsigned i{0}; i < count; ++i) {
            // Insert new entry.
            insert_sync(log_store, i);
            // Verify the entry.
            read_verify(log_store, i);
        }
    }

    // Restart homestore with only half of the logdev's open. Rest will be deleted as they are unopened.
    auto restart = [&]() {
        auto starting_cb = [&]() {
            auto it = id_set.begin();
            for (uint32_t i{0}; i < id_set.size() / 2; i++, it++) {
                logstore_service().open_logdev(*it);
            }
        };
        start_homestore(true /* restart */, starting_cb);
    };
    LOGINFO("Restart homestore");
    restart();

    // Explicitly call delete for unopened ones.
    hs()->logstore_service().delete_unopened_logdevs();
    auto log_devs = logstore_service().get_all_logdevs();
    ASSERT_EQ(log_devs.size(), id_set.size() / 2);
    for (auto& logdev : log_devs) {
        ASSERT_EQ(unopened_id_set.count(logdev->get_id()), 0);
    }
}

SISL_OPTION_GROUP(test_log_dev,
                  (num_logdevs, "", "num_logdevs", "number of log devs",
                   ::cxxopts::value< uint32_t >()->default_value("4"), "number"),
                  (num_logstores, "", "num_logstores", "number of log stores",
                   ::cxxopts::value< uint32_t >()->default_value("16"), "number"),
                  (num_records, "", "num_records", "number of record to test",
                   ::cxxopts::value< uint32_t >()->default_value("10000"), "number"),
                  (iterations, "", "iterations", "Iterations", ::cxxopts::value< uint32_t >()->default_value("1"),
                   "the number of iterations to run each test"));

int main(int argc, char* argv[]) {
    int parsed_argc = argc;
    ::testing::InitGoogleTest(&parsed_argc, argv);
    SISL_OPTIONS_LOAD(parsed_argc, argv, logging, test_log_dev, iomgr, test_common_setup);
    sisl::logging::SetLogger("test_log_dev");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%t] %v");

    const int ret = RUN_ALL_TESTS();
    return ret;
}
