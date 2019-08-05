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

#define VOL_PREFIX          "/tmp/vol"
#define STAGING_VOL_PREFIX  "staging"

THREAD_BUFFER_INIT;
using log_level = spdlog::level::level_enum;
SDS_LOGGING_INIT(HOMESTORE_LOG_MODS)

std::string vol_uuid;
bool print_checksum  = true;
bool cleanup_devices = true;

boost::uuids::string_generator gen;
std::condition_variable m_cv;
std::mutex m_mutex;

init_params params;

void notify_cmpl() {
    m_cv.notify_all();
}

void wait_cmpl() {
    std::unique_lock<std::mutex> lk(m_mutex);
    m_cv.wait(lk);
}

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
    notify_cmpl();
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
    params.is_read_only = bool();
    if (params.is_read_only) {
        std::cout << "\nRead only flag set" << std::endl;
    }
    params.is_file = config["is_file"];
    std::cout << "\nsystem uuid=" << config["system_uuid"] << std::endl;
    params.system_uuid = gen(std::string(config["system_uuid"]));
    params.iomgr = std::make_shared<iomgr::ioMgr>(2, 1);
    params.init_done_cb = std::bind(init_done_cb,
            std::placeholders::_1, std::placeholders::_2);
    params.vol_mounted_cb = std::bind(vol_mounted_cb,
            std::placeholders::_1, std::placeholders::_2);
    params.vol_state_change_cb = std::bind(vol_state_change_cb,
            std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
    params.vol_found_cb = std::bind(vol_found_cb, std::placeholders::_1);
    VolInterface::init(params);
}

void shutdown_callback() {
    VolInterface::del_instance();
}

void shutdown() {
    std::unique_lock<std::mutex> lk(m_mutex);
    VolInterface::get_instance()->shutdown(std::bind(shutdown_callback));
}

void remove_files() {
    if (cleanup_devices) {
        for (auto device : params.devices) {
            remove(device.dev_names.c_str());
        }
    }
    int ret = 0;
    for (uint32_t i = 0; !ret; i++) {
        std::string name = VOL_PREFIX + std::to_string(i);
        remove(name.c_str());
        name = name + STAGING_VOL_PREFIX;
        ret += remove(name.c_str());
    }
}

/************************* CLI options ***************************/

SDS_OPTION_GROUP(check_btree,
(vol_uuid, "", "vol_uuid", "volume uuid", ::cxxopts::value<std::string>(), "string"),
(print_checksum, "", "print_checksum", "print checksum", ::cxxopts::value<uint32_t>()->default_value("0"), "flag"),
(cleanup_devices, "", "cleanup_devices", "cleanup devices", ::cxxopts::value<uint32_t>()->default_value("0"), "flag")
)

#define ENABLED_OPTIONS logging, home_blks, check_btree
SDS_OPTIONS_ENABLE(ENABLED_OPTIONS)

/************************** MAIN ********************************/

int main(int argc, char *argv[]) {
    SDS_OPTIONS_LOAD(argc, argv, ENABLED_OPTIONS)
    sds_logging::SetLogger("check_btree");
    spdlog::set_pattern("[%D %T.%f] [%^%L%$] [%t] %v");
    vol_uuid = SDS_OPTIONS["vol_uuid"].as<std::string>();
    print_checksum  = SDS_OPTIONS["print_checksum"].as<uint32_t>();
    cleanup_devices = SDS_OPTIONS["cleanup_devices"].as<uint32_t>();

    start_homestore();
    wait_cmpl();
    shutdown();
    remove_files();

    return 0;
}

