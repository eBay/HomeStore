#include <gtest/gtest.h>
#include <iomgr/iomgr.hpp>
#include <sds_logging/logging.h>
#include <main/vol_interface.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <fstream>

#define MAX_DEVICES 2
using namespace homestore;
std::vector<dev_info> device_info;
std::string names[4] = {"file1", "file2", "file3", "file4"};
std::string uuid[4] = {"01970496-0262-11e9-8eb2-f2801f1b9fd1", "01970496-0262-11e9-8eb2-f2801f1b9fd1", 
                  "5fe17890-030e-11e9-8eb2-f2801f1b9fd1", "5fe17b92-030e-11e9-8eb2-f2801f1b9fd1"};
uint64_t max_capacity;
uint64_t run_time;
using log_level = spdlog::level::level_enum;
SDS_LOGGING_INIT(cache_vmod_evict, cache_vmod_write, iomgr, VMOD_BTREE_MERGE, VMOD_BTREE_SPLIT
)

class IOTest :  public ::testing::Test {
protected:
public:
    IOTest() {
    }
    void print() {
    }
};

TEST_F(IOTest, random_io_test) {
    this->print();
}


SDS_OPTION_GROUP(test_volume, 
(run_time, "", "run_time", "run time for io", ::cxxopts::value<uint32_t>()->default_value("60"), "seconds"))

SDS_OPTIONS_ENABLE(logging, test_volume)

int main(int argc, char *argv[]) {
    testing::InitGoogleTest(&argc, argv);
    SDS_OPTIONS_LOAD(argc, argv, logging, test_volume)
    sds_logging::SetLogger("test_volume");
    spdlog::set_pattern("[%D %T.%f%z] [%^%l%$] [%t] %v");

    /* create files */
    for (uint32_t i = 0; i < MAX_DEVICES; i++) {
        dev_info temp_info;
        boost::uuids::string_generator gen;
        temp_info.dev_names = names[i];
        temp_info.uuid = gen(uuid[i]);
        device_info.push_back(temp_info);
        std::ofstream ofs(names[i].c_str(), std::ios::binary | std::ios::out);
        ofs.seekp((10ul<<30) - 1);
        ofs.write("", 1);
        max_capacity += (10ul << 30);
    }

    if (SDS_OPTIONS.count("run_time")) {
        run_time = SDS_OPTIONS["run_time"].as<uint64_t>();
    }
    std::cout << run_time;
    return RUN_ALL_TESTS();
}
