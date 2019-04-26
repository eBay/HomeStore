#include "iomgr_executor.hpp"
#include <gtest/gtest.h>
#include <iostream>
#include <thread>
#include <sds_logging/logging.h>
#include <sds_options/options.h>

SDS_LOGGING_INIT(iomgr)

SDS_OPTIONS_ENABLE(logging)
using namespace homeds::loadgen;
void dummy_callback() {
    static std::atomic_uint count = 0;
    std::cout << __FUNCTION__ << " count: " << count++ << std::endl;
}

TEST(TEST_IOMGR_EXEC, TEST1) {
    IOMgrExecutor* exec = new IOMgrExecutor(8, 10, 2000);
    exec->start();
    for (auto i = 0; i < 100; i++) {
        std::cout << "add: " << i << std::endl;
        exec->add(dummy_callback);
    }
    exec->stop();
    delete exec;
}

int main(int argc, char *argv[]) {
    SDS_OPTIONS_LOAD(argc, argv, logging)
    testing::InitGoogleTest(&argc, argv);
    sds_logging::SetLogger("test_loadgen");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    return RUN_ALL_TESTS();
}
