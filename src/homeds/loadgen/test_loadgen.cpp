#include "iomgr_executor.hpp"
#include <gtest/gtest.h>
#include <iostream>
#include <thread>
#include <sds_logging/logging.h>
#include <sds_options/options.h>

SDS_LOGGING_INIT(iomgr)

SDS_OPTIONS_ENABLE(logging)

int main(int argc, char *argv[]) {
    SDS_OPTIONS_LOAD(argc, argv, logging)
    testing::InitGoogleTest(&argc, argv);
    sds_logging::SetLogger("test_loadgen");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    return 1;
}
