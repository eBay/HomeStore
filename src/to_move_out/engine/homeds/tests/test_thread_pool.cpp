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
#include <cstdint>
#include <iostream>
#include <thread>
#include <vector>

#include <sisl/flip/flip.hpp>
#include <sisl/logging/logging.h>
#include <sisl/options/options.h>
#include <sisl/utility/thread_buffer.hpp>

#include <gtest/gtest.h>

#include "homeds/thread/threadpool/thread_pool.h"

SISL_LOGGING_INIT(HOMESTORE_LOG_MODS)

using homestore::submit_job;
using homestore::ThreadPool;

SISL_OPTIONS_ENABLE(logging)

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
    SISL_OPTIONS_LOAD(argc, argv, logging)
    ::testing::InitGoogleTest(&argc, argv);
    sisl::logging::SetLogger("test_threadpool");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    return RUN_ALL_TESTS();
}
