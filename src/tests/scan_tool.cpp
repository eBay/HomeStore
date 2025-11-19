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
#include <homestore/homestore.hpp>
#include <iomgr/io_environment.hpp>
#include <sisl/logging/logging.h>
#include <sisl/options/options.h>

using namespace homestore;
SISL_LOGGING_INIT(HOMESTORE_LOG_MODS)
SISL_OPTIONS_ENABLE(logging, test_scan_tool, iomgr)

SISL_OPTION_GROUP(test_scan_tool,
                  (device_list, "", "device_list", "device list", ::cxxopts::value< std::vector< std::string > >(),
                   "[dev_path:dev_type,..]"),
                  (scan_type, "", "scan_type", "scan_type", ::cxxopts::value< std::string >()->default_value("chunk"),
                   "chunk/chain"),
                  (debug_chunk_id, "", "debug_chunk_id", "chunk id for debug printing",
                   ::cxxopts::value< uint16_t >(), "chunk_id"),
                  (debug_blk_num, "", "debug_blk_num", "block number for debug printing",
                   ::cxxopts::value< uint64_t >(), "blk_num"));

class ScanTool : public ::testing::Test {
public:
    virtual void SetUp() override {
        LOGINFO("Starting iomgr with 2 threads, spdk=false");
        ioenvironment.with_iomgr(iomgr::iomgr_params{.num_threads = 2, .is_spdk = false});
        const uint64_t app_mem_size = 2147483648;
        const int max_data_size = 67108864;
        const int max_snapshot_batch_size_in_bytes = 128 * 1024 * 1024;
        LOGINFO("Initialize and start HS tool with app_mem_size = {}", homestore::in_bytes(app_mem_size));

        auto devices = SISL_OPTIONS["device_list"].as< std::vector< std::string > >();
        ASSERT_FALSE(devices.empty()) << "Device list is empty. Please provide a valid device list.";

        std::vector< homestore::dev_info > device_info;
        for (auto const& dev : devices) {
            auto delimiter_pos = dev.find(':');
            ASSERT_TRUE(delimiter_pos != std::string::npos && delimiter_pos != 0 && delimiter_pos != dev.size() - 1)
                << "Invalid device format: " << dev << ". Expected format is 'path:type'.";

            std::string dev_path = dev.substr(0, delimiter_pos);
            std::string dev_type_str = dev.substr(delimiter_pos + 1);
            ASSERT_TRUE(dev_type_str == "HDD" || dev_type_str == "SSD" || dev_type_str == "NVME")
                << "Unknown device type: " << dev_type_str << ". Expected types are 'HDD', 'SSD', or 'NVME'.";
            LOGINFO("Adding device {} of type {}", dev_path, dev_type_str);
            auto hs_type = (dev_type_str == "HDD") ? homestore::HSDevType::Data : homestore::HSDevType::Fast;
            device_info.emplace_back(dev_path, hs_type);
        }

        auto scan_type = SISL_OPTIONS["scan_type"].as< std::string >();

        // Parse optional debug parameters
        std::optional< uint16_t > debug_chunk_id = std::nullopt;
        std::optional< blk_num_t > debug_blk_num = std::nullopt;

        if (SISL_OPTIONS.count("debug_chunk_id")) {
            debug_chunk_id = SISL_OPTIONS["debug_chunk_id"].as< uint16_t >();
            LOGINFO("Debug chunk_id set to: {}", debug_chunk_id.value());
        }

        if (SISL_OPTIONS.count("debug_blk_num")) {
            debug_blk_num = SISL_OPTIONS["debug_blk_num"].as< uint64_t >();
            LOGINFO("Debug blk_num set to: {}", debug_blk_num.value());
        }

        bool success = HomeStore::instance()->start_tool(
            hs_input_params{.devices = device_info,
                            .app_mem_size = app_mem_size,
                            .max_data_size = max_data_size,
                            .max_snapshot_batch_size = max_snapshot_batch_size_in_bytes},
            scan_type, debug_chunk_id, debug_blk_num);
        LOGINFO("HS tool started with status: {}", success ? "success" : "failure");
    }

    virtual void TearDown() override {
        HomeStore::instance()->stop_tool();
        iomanager.stop();
    }
};

TEST_F(ScanTool, SimpleTool) { LOGINFO("HS scan tool test completed"); }

int main(int argc, char* argv[]) {
    SISL_OPTIONS_LOAD(argc, argv, logging, test_scan_tool, iomgr);
    ::testing::InitGoogleTest(&argc, argv);
    sisl::logging::SetLogger("test_scan_tool");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    return RUN_ALL_TESTS();
}
