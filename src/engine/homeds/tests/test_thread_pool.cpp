/*
 * Copyright 2019 eBay
 *
 * */

#include <chrono>
#include <cstdint>
#include <iostream>
#include <vector>

#include <flip/flip.hpp>
#include <sds_logging/logging.h>
#include <sds_options/options.h>
#include <utility/thread_buffer.hpp>

#include <gtest/gtest.h>

#include "homeds/thread/threadpool/thread_pool.h"

SDS_LOGGING_INIT(HOMESTORE_LOG_MODS)
THREAD_BUFFER_INIT;

using homestore::submit_job;
using homestore::ThreadPool;

SDS_OPTIONS_ENABLE(logging)

TEST(THREAD_POOL, TEST1) {
    const std::uint32_t num_seconds_expected_to_run = 3;
    auto start = std::chrono::steady_clock::now();
    std::vector< ThreadPool::TaskFuture< void > > v;
    for (std::uint32_t i = 0; i < num_seconds_expected_to_run * MAX_NUM_CONCURRENT_THREADS; i++) {
        v.push_back(submit_job([i]() {
            // do something
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }));
    }

    for (auto& x : v) {
        x.get();
    }
    auto end = std::chrono::steady_clock::now();
    auto num_seconds_actaully_run = std::chrono::duration_cast< std::chrono::seconds >(end - start).count();
    std::cout << "Elapsed time in seconds : " << num_seconds_actaully_run << " sec\n";

    EXPECT_EQ(num_seconds_actaully_run, num_seconds_expected_to_run);
}

int main(int argc, char* argv[]) {
    SDS_OPTIONS_LOAD(argc, argv, logging)
    testing::InitGoogleTest(&argc, argv);
    sds_logging::SetLogger("test_threadpool");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    return RUN_ALL_TESTS();
}
