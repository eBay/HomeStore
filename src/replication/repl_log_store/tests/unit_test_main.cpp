/*
 * unit_test_main.cpp
 *
 *  Created on: Jan 8, 2019
 */

#include <cstdint>
#include <string>

#include <engine/common/homestore_header.hpp>
#include <iomgr/reactor.hpp>
#include <sds_logging/logging.h>
#include <sds_options/options.h>
#include <utility/thread_buffer.hpp>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

SDS_OPTION_GROUP(server,
                 (num_threads, "", "num_threads", "number of threads",
                  cxxopts::value< uint32_t >()->default_value("2"), "number"),
                 (test_type, "", "test_type", "test_type: basic, compact, pack",
                  cxxopts::value< std::string >()->default_value("basic"), ""),
                 (stats_port, "", "stats_port", "Port to expose stats on",
                  cxxopts::value< int32_t >()->default_value("5000"), ""),
                 (cleanup, "", "cleanup", "whether to cleanup after test",
                  cxxopts::value< bool >()->default_value("true"), ""),
                 (spdk, "", "spdk", "spdk", ::cxxopts::value< bool >()->default_value("false"), "true or false"),
                 (hb_stats_port, "", "hb_stats_port", "HS Port to expose stats on",
                  cxxopts::value< int32_t >()->default_value("6000"), ""))

SDS_OPTIONS_ENABLE(logging, server)
SDS_LOGGING_INIT(nublox_logstore, nuraft, HOMESTORE_LOG_MODS)

THREAD_BUFFER_INIT
RCU_REGISTER_INIT

int main(int argc, char** argv) {
    // Since Google Mock depends on Google Test, InitGoogleMock() is
    // also responsible for initializing Google Test.  Therefore there's
    // no need for calling testing::InitGoogleTest() separately.
    //  Whenever a Google Mock flag is seen, it is removed from argv, and *argc is decremented.
    ::testing::InitGoogleMock(&argc, argv);
    SDS_OPTIONS_LOAD(argc, argv, logging, server);

    sds_logging::SetLogger("log_store_test");
    spdlog::set_pattern("[%D %T.%f%z] [%^%l%$] [%t] %v");
    sds_logging::install_crash_handler();

    sds_logging::SetModuleLogLevel("nublox_logstore", spdlog::level::level_enum::trace);

    const auto test_type{SDS_OPTIONS["test_type"].as< std::string >()};

    LOGINFO("log initialized.");
    ::testing::GTEST_FLAG(filter) = "LogStoreTest." + test_type + "*";
    const int ret{RUN_ALL_TESTS()};

    return ret;
}
