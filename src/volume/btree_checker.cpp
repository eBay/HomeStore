#include <iomgr/iomgr.hpp>
#include <sds_logging/logging.h>
#include <sds_options/options.h>
#include <main/vol_interface.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/string_generator.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/lexical_cast.hpp>
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

THREAD_BUFFER_INIT;
using log_level = spdlog::level::level_enum;
SDS_LOGGING_INIT(HOMESTORE_LOG_MODS)

std::string vol_uuid;
boost::uuids::string_generator gen;

nlohmann::json get_config() {
    std::ifstream in("/tmp/hs_config.json");
    if (!in.is_open()) {
        return nullptr;
    }
    nlohmann::json file;
    in >> file;
    in.close();
    return file;
}

void init_done_cb(  std::error_condition err,
                    struct out_params params) {

    auto uuid = gen(std::string(vol_uuid));
    auto vol = VolInterface::get_instance()->lookup_volume(uuid);
    VolInterface::get_instance()->print_tree(vol);
}

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
    params.flag = homestore::io_flag::READ_ONLY;
    std::cout << "Configuration\nio_flag = READ_ONLY\n";
    std::cout << "min page size=" << config["min_page_size"] << std::endl;
    params.min_virtual_page_size = config["min_page_size"];
    std::cout << "cache size=" << config["cache_size"] << std::endl;
    params.cache_size = config["cache_size"];
    params.disk_attr = disk_attributes();
    std::cout << "phys page size=" << config["phys_page_size"] << std::endl;
    params.disk_attr->physical_page_size = config["phys_page_size"];
    std::cout << "align size=" << config["align_size"] << std::endl;
    params.disk_attr->disk_align_size = config["align_size"];
    std::cout << "atomic phys page size=" << config["atomic_phys_page_size"] << std::endl;
    params.disk_attr->atomic_page_size = config["atomic_phys_page_size"];
    params.disk_init = false;
    std::cout << "device(s): ";
    for (auto& device : config["devices"]) {
        std::cout << device << " | ";
        params.devices.emplace_back(dev_info{device});
    }
    params.is_file = config["is_file"];
    std::cout << "\nsystem uuid=" << config["system_uuid"] << std::endl;
    params.system_uuid = gen(std::string(config["system_uuid"]));
    params.iomgr = std::make_shared<iomgr::ioMgr>(2, 1);
    params.init_done_cb = init_done_cb;
    params.vol_mounted_cb = vol_mounted_cb;
    params.vol_state_change_cb = vol_state_change_cb;
    params.vol_found_cb = vol_found_cb;
    VolInterface::init(params);
}

/************************* CLI options ***************************/

SDS_OPTION_GROUP(check_btree,
(vol_uuid, "", "vol_uuid", "volume uuid", ::cxxopts::value<std::string>(), "string"))

#define ENABLED_OPTIONS logging, home_blks, check_btree
SDS_OPTIONS_ENABLE(ENABLED_OPTIONS)

/************************** MAIN ********************************/

int main(int argc, char *argv[]) {
    SDS_OPTIONS_LOAD(argc, argv, ENABLED_OPTIONS)
    vol_uuid = SDS_OPTIONS["vol_uuid"].as<std::string>();
    start_homestore();
    return 0;
}

