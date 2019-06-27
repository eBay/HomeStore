#include <iomgr/iomgr.hpp>
#include <sds_logging/logging.h>
#include <sds_options/options.h>
#include <main/vol_interface.hpp>
#include <volume/home_blks.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <fstream>
#include <iostream>
#include <string>
#include <homeds/bitmap/bitset.hpp>
#include <atomic>
#include <string>
#include <utility/thread_buffer.hpp>
#include <chrono>
#include <fstream>
#include <thread>
extern "C" {
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timeb.h>
}

using namespace homestore;

nlohmann::json get_config() {
    std::ifstream in("hs_config.json");
    if (!in.is_open()) {
        return nullptr;
    }
    nlohmann::json file;
    file << in;
    in.close();
    return file;
}

void init_done_cb(  std::error_condition err,
                    struct out_params params) {}

bool vol_found_cb (boost::uuids::uuid uuid) {
    return true;
}

void vol_mounted_cb(    std::shared_ptr<Volume> vol,
                        vol_state state     ) {}

void vol_state_change_cb(   std::shared_ptr<Volume> vol,
                            vol_state old_state,
                            vol_state new_state ) {}

/* start homestore */
void start_homestore() {
    auto config = get_config();
    init_params params;
    params.flag = homestore::io_flag::DIRECT_IO;
    params.min_virtual_page_size = config["min_page_size"];
    params.cache_size = config["cache_size"];
    params.disk_attr->physical_page_size = config["phys_page_size"];
    params.disk_attr->disk_align_size = config["align_size"];
    params.disk_attr->atomic_page_size = config["atomic_phys_page_size"];
    params.disk_init = false;
    params.devices = config["devices"].get<std::vector<dev_info>>();
    params.is_file = true;
    params.system_uuid = boost::lexical_cast<uuid>(config["system_uuid"]);
    params.iomgr = nullptr;
    params.init_done_cb = init_done_cb;
    params.vol_mounted_cb = vol_mounted_cb;
    params.vol_state_change_cb = vol_state_change_cb;
    params.vol_found_cb = vol_found_cb;
    VolInterface::init(params);
}

/************************* CLI options ***************************/

SDS_OPTION_GROUP(test_volume, 
(run_time, "", "run_time", "run time for io", ::cxxopts::value<uint32_t>()->default_value("30"), "seconds"),
(num_threads, "", "num_threads", "num threads for io", ::cxxopts::value<uint32_t>()->default_value("8"), "number"),
(read_enable, "", "read_enable", "read enable 0 or 1", ::cxxopts::value<uint32_t>()->default_value("1"), "flag"),
(max_disk_capacity, "", "max_disk_capacity", "max disk capacity", ::cxxopts::value<uint64_t>()->default_value("7"), "GB"),


#define ENABLED_OPTIONS logging, home_blks, test_volume
SDS_OPTIONS_ENABLE(ENABLED_OPTIONS)

/************************** MAIN ********************************/

int main(int argc, char *argv[]) {
    srand(time(0));
    SDS_OPTIONS_LOAD(argc, argv, ENABLED_OPTIONS)
    sds_logging::SetLogger("test_volume");
    spdlog::set_pattern("[%D %T.%f] [%^%L%$] [%t] %v");

    run_time = SDS_OPTIONS["run_time"].as<uint32_t>();
    num_threads = SDS_OPTIONS["num_threads"].as<uint32_t>();
    read_enable = SDS_OPTIONS["read_enable"].as<uint32_t>();
    max_disk_capacity = ((SDS_OPTIONS["max_disk_capacity"].as<uint64_t>())  * (1ul<< 30));
    max_vols = SDS_OPTIONS["max_volume"].as<uint64_t>();
    max_num_writes= SDS_OPTIONS["max_num_writes"].as<uint64_t>();
    enable_crash_handler = SDS_OPTIONS["enable_crash_handler"].as<uint32_t>();
    if (enable_crash_handler) sds_logging::install_crash_handler();

    this->start_homestore();
    this->wait_cmpl();
    this->shutdown();

    return 0;
}

