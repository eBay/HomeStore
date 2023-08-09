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

#include <iomgr/io_environment.hpp>
#include <sisl/logging/logging.h>
#include <sisl/options/options.h>
#include <gtest/gtest.h>

#include <homestore/homestore.hpp>
#include <homestore/meta_service.hpp>
#include <homestore/checkpoint/cp_mgr.hpp>
#include "checkpoint/cp.hpp"
#include "test_common/homestore_test_common.hpp"

using namespace homestore;

SISL_LOGGING_INIT(HOMESTORE_LOG_MODS)

SISL_OPTIONS_ENABLE(logging, test_cp_mgr, iomgr, test_common_setup)
SISL_LOGGING_DECL(test_cp_mgr)
std::vector< std::string > test_common::HSTestHelper::s_dev_names;

SISL_OPTION_GROUP(test_cp_mgr,
                  (num_records, "", "num_records", "number of record to test",
                   ::cxxopts::value< uint32_t >()->default_value("1000"), "number"),
                  (iterations, "", "iterations", "Iterations", ::cxxopts::value< uint32_t >()->default_value("1"),
                   "the number of iterations to run each test"));

class TestCPContext : public CPContext {
public:
    TestCPContext(cp_id_t id) : CPContext{id} {}
    virtual ~TestCPContext() = default;

    void add() {
        auto val = m_next_val.fetch_add(1);
        if (val < max_values) { m_cur_values[val] = std::make_pair(id(), val); }
    }

    void validate(uint64_t cp_id) {
        for (uint64_t i{0}; i < m_next_val.load(); ++i) {
            auto [session, val] = m_cur_values[i];
            ASSERT_EQ(session, cp_id) << "CP Context has data with mismatched cp_id";
            ASSERT_EQ(val, i);
        }
        LOGINFO("CP={}, CPContext has {} values to be flushed/validated", cp_id, m_next_val.load());
    }

private:
    static constexpr size_t max_values = 10000;

    std::array< std::pair< uint64_t, uint64_t >, max_values > m_cur_values;
    std::atomic< uint64_t > m_next_val{0};
    folly::Promise< bool > m_comp_promise;
};

class TestCPCallbacks : public CPCallbacks {
public:
    std::unique_ptr< CPContext > on_switchover_cp(CP*, CP* new_cp) override {
        return std::make_unique< TestCPContext >(new_cp->id());
    }

    folly::Future< bool > cp_flush(CP* cp) override {
        auto ctx = s_cast< TestCPContext* >(cp->context(cp_consumer_t::HS_CLIENT));
        ctx->validate(cp->id());
        return folly::makeFuture< bool >(true);
    }

    void cp_cleanup(CP* cp) override {}

    int cp_progress_percent() override { return 100; }
};

class TestCPMgr : public ::testing::Test {
public:
    void SetUp() override {
        test_common::HSTestHelper::start_homestore("test_cp", 85.0, 0, 0, 0, 0, nullptr, false /* restart */);
        hs()->cp_mgr().register_consumer(cp_consumer_t::HS_CLIENT, std::move(std::make_unique< TestCPCallbacks >()));
    }
    void TearDown() override { test_common::HSTestHelper::shutdown_homestore(); }

    void simulate_io() {
        iomanager.run_on_forget(iomgr::reactor_regex::least_busy_worker, [this]() {
            auto cur_cp = homestore::hs()->cp_mgr().cp_guard();
            r_cast< TestCPContext* >(cur_cp->context(cp_consumer_t::HS_CLIENT))->add();
        });
    }

    void rescheduled_io() {
        iomanager.run_on_forget(iomgr::reactor_regex::least_busy_worker, [this]() {
            auto cur_cp = homestore::hs()->cp_mgr().cp_guard();
            iomanager.run_on_forget(iomgr::reactor_regex::least_busy_worker, [moved_cp = std::move(cur_cp)]() mutable {
                r_cast< TestCPContext* >(moved_cp->context(cp_consumer_t::HS_CLIENT))->add();
            });
        });
    }

    void nested_io() {
        [[maybe_unused]] auto cur_cp = homestore::hs()->cp_mgr().cp_guard();
        rescheduled_io();
    }

    void trigger_cp(bool wait) {
        static std::mutex mtx;
        static std::condition_variable cv;
        static uint64_t this_flush_cp{0};
        static uint64_t last_flushed_cp{0};

        {
            std::unique_lock lg(mtx);
            ++this_flush_cp;
        }

        auto fut = homestore::hs()->cp_mgr().trigger_cp_flush(true /* force */);

        auto on_complete = [&](auto success) {
            ASSERT_EQ(success, true) << "CP Flush failed";
            {
                std::unique_lock lg(mtx);
                ASSERT_LT(last_flushed_cp, this_flush_cp) << "CP out_of_order completion";
                ++last_flushed_cp;
            }
        };

        if (wait) {
            on_complete(std::move(fut).get());
        } else {
            std::move(fut).thenValue(on_complete);
        }
    }
};

TEST_F(TestCPMgr, cp_start_and_flush) {
    auto nrecords = SISL_OPTIONS["num_records"].as< uint32_t >();
    LOGINFO("Step 1: Simulate IO on cp session for {} records", nrecords);
    for (uint32_t i{0}; i < nrecords; ++i) {
        this->simulate_io();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{1000});

    LOGINFO("Step 2: Trigger a new cp without waiting for it to complete");
    this->trigger_cp(false /* wait */);

    LOGINFO("Step 3: Simulate IO parallel to CP for {} records", nrecords);
    for (uint32_t i{0}; i < nrecords; ++i) {
        this->simulate_io();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{1000});

    LOGINFO("Step 4: Trigger a back-to-back cp");
    this->trigger_cp(false /* wait */);
    this->trigger_cp(true /* wait */);

    LOGINFO("Step 5: Simulate rescheduled IO for {} records", nrecords);
    for (uint32_t i{0}; i < nrecords; ++i) {
        this->nested_io();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{1000});

    LOGINFO("Step 6: Trigger a cp to validate");
    this->trigger_cp(true /* wait */);
}

int main(int argc, char* argv[]) {
    int parsed_argc = argc;
    ::testing::InitGoogleTest(&parsed_argc, argv);
    SISL_OPTIONS_LOAD(parsed_argc, argv, logging, test_cp_mgr, iomgr, test_common_setup);
    sisl::logging::SetLogger("test_home_local_journal");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%t] %v");

    return RUN_ALL_TESTS();
}
