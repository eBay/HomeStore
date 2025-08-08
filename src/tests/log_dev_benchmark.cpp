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
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <vector>

#include <benchmark/benchmark.h>
#include <sisl/logging/logging.h>
#include <sisl/options/options.h>

#include "logstore/log_dev.hpp"

 
RCU_REGISTER_INIT

static constexpr size_t ITERATIONS{100000};
static constexpr size_t THREADS{64};

static std::vector< logdev_key > s_log_keys;
static uint64_t first_offset{~static_cast< uint64_t >(0)};

void test_append(benchmark::State& state) {
    uint64_t counter{0};
    for ([[maybe_unused]] auto current_state : state) { // Loops upto iteration count
        my_request* req{nullptr};
        benchmark::DoNotOptimize(req = new my_request());
        LogDev::instance()->append();
    }
    std::cout << "Counter = " << counter << "\n";
}

[[nodiscard]] static std::shared_ptr< iomgr::ioMgr > start_homestore(const uint32_t ndevices, const uint64_t dev_size,
                                                                     const uint32_t nthreads) {
    std::vector< dev_info > device_info;
    // these should be static so that they stay in scope in the lambda in case function ends before lambda completes
    static std::mutex start_mutex;
    static std::condition_variable cv;
    static bool inited;

    inited = false;
    LOGINFO("creating {} device files with each of size {} ", ndevices, dev_size);
    for (uint32_t i{0}; i < ndevices; ++i) {
        const std::filesystem::path fpath{"/tmp/" + std::to_string(i + 1)};
        std::ofstream ofs{fpath.string(), std::ios::binary | std::ios::out};
        std::filesystem::resize_file(fpath, dev_size);
        device_info.emplace_back(std::filesystem::canonical(fpath).string(), HSDevType::Data);
    }

    LOGINFO("Creating iomgr with {} threads", nthreads);
    auto iomgr_obj{std::make_shared< iomgr::ioMgr >(2, nthreads)};

    const uint64_t app_mem_size{((ndevices * dev_size) * 15) / 100};
    LOGINFO("Initialize and start HomeBlks with app_mem_size = {}", app_mem_size);

    boost::uuids::string_generator gen;
    init_params params;
    params.open_flags = homestore::io_flag::DIRECT_IO;
    params.min_virtual_page_size = 4096;
    params.app_mem_size = app_mem_size;
    params.devices = device_info;
    params.iomgr = iomgr_obj;
    params.init_done_cb = [&iomgr_obj, &tl_start_mutex = start_mutex, &tl_cv = cv,
                           &tl_inited = inited](std::error_condition err, const out_params& params) {
        iomgr_obj->start();
        LOGINFO("HomeBlks Init completed");
        {
            std::unique_lock< std::mutex > lk{tl_start_mutex};
            tl_inited = true;
        }
        tl_cv.notify_one();
    };
    params.vol_mounted_cb = [](const VolumePtr& vol_obj, vol_state state) {};
    params.vol_state_change_cb = [](const VolumePtr& vol, vol_state old_state, vol_state new_state) {};
    params.vol_found_cb = [](boost::uuids::uuid uuid) -> bool { return true; };
    VolInterface::init(params);

    {
        std::unique_lock< std::mutex > lk{start_mutex};
        cv.wait(lk, [] { return inited; });
    }
    return iomgr_obj;
}

static void on_append_completion(const logdev_key lkey, void* const ctx) {
    s_log_keys.push_back(lkey);
    LOGINFO("Append completed with log_idx = {} offset = {}", lkey.idx, lkey.dev_offset);
    if (first_offset == ~static_cast< uint64_t >(0)) { first_offset = lkey.dev_offset; }
}

static void on_log_found(const logdev_key lkey, const log_buffer buf) {
    s_log_keys.push_back(lkey);
    LOGINFO("Found a log with log_idx = {} offset = {}", lkey.idx, lkey.dev_offset);
}

static void setup() {
    auto iomgr_obj = start_homestore(SISL_OPTIONS["num_devs"].as< uint32_t >(),
                                     SISL_OPTIONS["dev_size_mb"].as< uint64_t >() * 1024 * 1024,
                                     SISL_OPTIONS["num_threads"].as< uint32_t >());

    LogDev::instance()->register_append_cb(on_append_completion);
    LogDev::instance()->register_logfound_cb(on_log_found);
}

SISL_OPTIONS_ENABLE(logging, log_dev_benchmark)
SISL_OPTION_GROUP(log_dev_benchmark,
                  (num_threads, "", "num_threads", "number of threads",
                   ::cxxopts::value< uint32_t >()->default_value("2"), "number"),
                  (num_devs, "", "num_devs", "number of devices to create",
                   ::cxxopts::value< uint32_t >()->default_value("2"), "number"),
                  (dev_size_mb, "", "dev_size_mb", "size of each device in MB",
                   ::cxxopts::value< uint64_t >()->default_value("5120"), "number"));

BENCHMARK(test_append)->Iterations(ITERATIONS)->Threads(THREADS);

SISL_OPTIONS_ENABLE(logging)
int main(int argc, char** argv) {
    SISL_OPTIONS_LOAD(argc, argv, logging, log_dev_benchmark)
    sisl::logging::SetLogger("log_dev_benchmark");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    setup();
    ::benchmark::Initialize(&argc, argv);
    ::benchmark::RunSpecifiedBenchmarks();
}
