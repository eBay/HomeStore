/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 * Author/Developer(s): Harihara Kadayam
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
#include <atomic>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#include <fcntl.h>
#include <linux/fs.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/timeb.h>

#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <sisl/fds/bitset.hpp>
#include <iomgr/iomgr.hpp>
#include <sisl/metrics/metrics.hpp>
#include <sisl/logging/logging.h>
#include <sisl/options/options.h>
#include <sisl/utility/thread_buffer.hpp>

#include <gtest/gtest.h>

#include "api/vol_interface.hpp"
#include "homeblks/test_setup/simple_hs_setup.hpp"

using namespace homestore;

SISL_LOGGING_INIT(HOMESTORE_LOG_MODS)

/************************* CLI options ***************************/

SISL_OPTION_GROUP(perf_test_volume,
                  (run_time, "", "run_time", "run time for io", ::cxxopts::value< uint32_t >()->default_value("30"),
                   "seconds"),
                  (num_threads, "", "num_threads", "num threads for io",
                   ::cxxopts::value< uint32_t >()->default_value("8"), "number"),
                  (queue_depth, "", "queue_depth", "io queue depth per thread",
                   ::cxxopts::value< uint32_t >()->default_value("1024"), "number"),
                  (read_percent, "", "read_percent", "read in percentage",
                   ::cxxopts::value< uint32_t >()->default_value("50"), "percentage"),
                  (device_list, "", "device_list", "List of device paths",
                   ::cxxopts::value< std::vector< std::string > >(), "path [...]"),
                  (io_size, "", "io_size", "size of io in KB", ::cxxopts::value< uint32_t >()->default_value("64"),
                   "size of io in KB"),
                  (app_mem_size, "", "app_mem_size", "size of app mem (including cache) in GB",
                   ::cxxopts::value< uint32_t >()->default_value("4"), "size of app mem (incl cache) in GB"),
                  (init, "", "init", "init", ::cxxopts::value< uint32_t >()->default_value("1"), "init"),
                  (preload_writes, "", "preload_writes", "preload_writes",
                   ::cxxopts::value< uint32_t >()->default_value("100000000"), "preload_writes"),
                  (ref_cnt, "", "ref_count", "display object life counters",
                   ::cxxopts::value< uint32_t >()->default_value("0"), "display object life counters"))
#define ENABLED_OPTIONS logging, home_blks, perf_test_volume
SISL_OPTIONS_ENABLE(ENABLED_OPTIONS)

/* it will go away once shutdown is implemented correctly */

extern "C" __attribute__((no_sanitize_address)) const char* __asan_default_options() { return "detect_leaks=0"; }

/************************** MAIN ********************************/

/* We can run this target either by using default options which run the normal io tests or by setting different options.
 * Format is
 *   1. ./perf_test_volume --gtest_filter=*random* --run_time=120 --num_threads=16 --queue_depth 8
 *                         --device_list=file1 --device_list=file2 --io_size=8
 */
int main(int argc, char* argv[]) {
    srand(time(0));
    //::testing::GTEST_FLAG(filter) = "*normal_random*";
    //::testing::InitGoogleTest(&argc, argv);
    SISL_OPTIONS_LOAD(argc, argv, ENABLED_OPTIONS)
    sisl::logging::SetLogger("perf_test_volume");
    spdlog::set_pattern("[%D %T.%f%z] [%^%l%$] [%t] %v");

#if 0
    disk_init = SISL_OPTIONS["init"].as< uint32_t >() ? true : false;

    if (dev_names.size() == 0) {
        LOGINFO("creating files");
        for (uint32_t i{0}; i < MAX_DEVICES; ++i) {
            const std::filesystem::path fpath{names[i]};
            if (disk_init) {
                std::ofstream ofs(fpath.string(), std::ios::binary | std::ios::out);
                std::filesystem::resize_file(fpath, 10 * Gi);
            }
            dev_names.emplace_back(std::filesystem::canonical(fpath).string(), HSDevType::Data);
        }
    }
#endif
    simple_store_cfg cfg;
    cfg.m_run_time_ms = SISL_OPTIONS["run_time"].as< uint32_t >() * 1000;
    cfg.m_nthreads = SISL_OPTIONS["num_threads"].as< uint32_t >();
    cfg.m_qdepth = SISL_OPTIONS["queue_depth"].as< uint32_t >();
    cfg.m_read_pct = SISL_OPTIONS["read_percent"].as< uint32_t >();
    if (SISL_OPTIONS.count("device_list")) {
        cfg.m_devs = SISL_OPTIONS["device_list"].as< std::vector< std::string > >();
    }
    cfg.m_app_mem_size = SISL_OPTIONS["app_mem_size"].as< uint32_t >() * 1024 * 1024 * 1024;

    SimpleTestStore test_store(cfg);
    test_store.start_homestore();
    test_store.kickstart_io();
    test_store.wait_for_io_done();
    LOGINFO("Metrics: {}", sisl::MetricsFarm::getInstance().get_result_in_json().dump(2));
    test_store.shutdown();
    /*for (uint32_t i = 0; i < dev_names.size(); ++i) {
        auto   fd = open(dev_names[0].c_str(), O_RDWR);
        size_t devsize = 0;
        if (!is_file) {
            if (ioctl(fd, BLKGETSIZE64, &devsize) < 0) {
                LOGINFO("couldn't get size");
                assert(false);
                abort();
            }
        } else {
            struct stat buf;
            if (fstat(fd, &buf) < 0) {
                assert(false);
                throw std::system_error(errno, std::system_category(), "error while getting size of the device");
            }
            devsize = buf.st_size;
        }
        max_disk_capacity += devsize;
    }*/

    // return RUN_ALL_TESTS();
}
