#include "../loadgen/iomgr_executor.hpp"
#include <gtest/gtest.h>
#include <iostream>
#include <thread>
#include <unordered_map>
#include <sds_logging/logging.h>
#include <sds_options/options.h>

SDS_LOGGING_INIT(iomgr)

SDS_OPTIONS_ENABLE(logging)
using namespace homeds::loadgen;

void dummy_callback() {
    static std::atomic_uint count = 0;
    std::cout << __FUNCTION__ << " count: " << count++ << std::endl;
}

#define NUM_IO_THREADS 8
#define NUM_PRI        10
static uint64_t max_queue_cap = 100;

static std::atomic<std::size_t> thread_idx{0};
std::size_t get_thread_id() noexcept {
    thread_local std::size_t id = thread_idx;
    thread_idx++;
    return id;
}

// Case-1: push items less than queue capacity;
TEST(TEST_IOMGR_EXEC, TEST1) {
    thread_idx = 0;
    max_queue_cap = 2000;
    IOMgrExecutor* exec = new IOMgrExecutor(NUM_IO_THREADS, NUM_PRI, max_queue_cap);
    
    const uint64_t repeat_cnt = 100;
    uint64_t count = 0;
    for (auto i = 0ul; i < repeat_cnt; i++) {
        exec->add([&count](){ 
                LOGINFO("Receiving callback {} from I/O thread id: {}", count++, get_thread_id());
                });
    }

    while (!exec->is_empty()) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
    
    EXPECT_EQ(count, repeat_cnt);

    delete exec;
}

// Case-2: push items larger than queue capacity;
TEST(TEST_IOMGR_EXEC, TEST2) {
    thread_idx = 0;
    max_queue_cap = 20;
    IOMgrExecutor* exec = new IOMgrExecutor(NUM_IO_THREADS, NUM_PRI, max_queue_cap);
    
    uint64_t count = 0;
    const uint64_t repeat_cnt = 100;
    for (auto i = 0ul; i < repeat_cnt; i++) {
        exec->add([&count](){ 
                LOGINFO("Receiving callback {} from I/O thread id: {}", count++, get_thread_id());
                });
    }

    while (!exec->is_empty()) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    EXPECT_EQ(count, repeat_cnt);

    delete exec;
}


int main(int argc, char *argv[]) {
    SDS_OPTIONS_LOAD(argc, argv, logging)
    testing::InitGoogleTest(&argc, argv);
    sds_logging::SetLogger("test_iomgr_exec");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    return RUN_ALL_TESTS();
}
