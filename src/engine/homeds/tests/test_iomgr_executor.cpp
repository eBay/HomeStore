#include "../loadgen/iomgr_executor.hpp"
#include <gtest/gtest.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <unordered_map>
#include <sds_logging/logging.h>
#include <sds_options/options.h>

SDS_LOGGING_INIT(HOMESTORE_LOG_MODS, flip, IOMGR_LOG_MODS)
SDS_OPTIONS_ENABLE(logging)
RCU_REGISTER_INIT

using namespace homeds::loadgen;

static uint64_t max_queue_cap = 100;
static std::atomic< std::size_t > thread_idx{0};

class IOMgrExecTest : public ::testing::Test {
public:
#define NUM_IO_THREADS 8
#define NUM_PRI 10
#define TIMEOUT_SECS 10
#define WAIT_DELTA_MS 10

    std::size_t get_thread_id() noexcept {
        thread_local std::size_t id = thread_idx;
        thread_idx++;
        return id;
    }

    bool wait_for_result(const uint64_t& cnt, const uint64_t& expected, const uint64_t timeout_secs) {
        auto start = std::chrono::steady_clock::now();
        while (cnt != expected) {
            std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_DELTA_MS));
            auto end = std::chrono::steady_clock::now();
            auto wait_num_secs = std::chrono::duration_cast< std::chrono::seconds >(end - start).count();
            if ((uint64_t)wait_num_secs >= timeout_secs) { return false; }
        }

        return true;
    }
};

// Case-1: push items less than queue capacity;
TEST_F(IOMgrExecTest, TEST1) {
    thread_idx = 0;
    max_queue_cap = 2000;
    IOMgrExecutor* exec = new IOMgrExecutor(NUM_IO_THREADS, NUM_PRI, max_queue_cap);

    const uint64_t repeat_cnt = 200;
    std::atomic< uint64_t > count = 0;
    for (auto i = 0ul; i < repeat_cnt; i++) {
        exec->add([&count, this]() {
            uint64_t cnt = count.fetch_add(1, std::memory_order_relaxed);
            LOGINFO("Receiving callback {} from I/O thread id: {}", cnt, get_thread_id());
        });
    }

    this->wait_for_result(count, repeat_cnt, TIMEOUT_SECS);
    EXPECT_EQ(count, repeat_cnt);

    delete exec;
}

// Case-2: push items larger than queue capacity;
TEST_F(IOMgrExecTest, TEST2) {
    thread_idx = 0;
    max_queue_cap = 20;
    IOMgrExecutor* exec = new IOMgrExecutor(NUM_IO_THREADS, NUM_PRI, max_queue_cap);

    const uint64_t repeat_cnt = 200;
    std::atomic< uint64_t > count = 0;
    for (auto i = 0ul; i < repeat_cnt; i++) {
        exec->add([&count, this]() {
            uint64_t cnt = count.fetch_add(1, std::memory_order_relaxed);
            LOGINFO("Receiving callback {} from I/O thread id: {}", cnt, get_thread_id());
        });
    }

    this->wait_for_result(count, repeat_cnt, TIMEOUT_SECS);
    EXPECT_EQ(count, repeat_cnt);

    delete exec;
}

int main(int argc, char* argv[]) {
    SDS_OPTIONS_LOAD(argc, argv, logging)
    ::testing::InitGoogleTest(&argc, argv);
    sds_logging::SetLogger("test_iomgr_exec");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    return RUN_ALL_TESTS();
}
