#include <sds_logging/logging.h>
#include <sds_options/options.h>
#include <main/vol_interface.hpp>
#include <utility/thread_buffer.hpp>
#include <iomgr/iomgr.hpp>
#include <iomgr/aio_drive_interface.hpp>
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

std::vector< std::shared_ptr< Volume > > vol_list;
#define VOL_PREFIX "/tmp/vol"
#define STAGING_VOL_PREFIX "staging"

THREAD_BUFFER_INIT;
using log_level = spdlog::level::level_enum;
SDS_LOGGING_INIT(HOMESTORE_LOG_MODS)

std::string vol_uuid;

uint64_t blkid = 0;
bool print_tree = false;
bool verify_tree = false;

boost::uuids::string_generator gen;
std::condition_variable m_cv;
std::mutex m_mutex;

init_params params;

void notify_cmpl() { m_cv.notify_all(); }

void wait_cmpl() {
    std::unique_lock< std::mutex > lk(m_mutex);
    m_cv.wait(lk);
}

nlohmann::json get_config() {
    std::ifstream in("hs_config.json");
    if (!in.is_open()) { return nullptr; }
    nlohmann::json file;
    in >> file;
    in.close();
    return file;
}

void init_done_cb(std::error_condition err, struct out_params params) {

    boost::uuids::uuid uuid;
    if (vol_uuid.length() != 0) { uuid = gen(std::string(vol_uuid)); }
    auto vol = VolInterface::get_instance()->lookup_volume(uuid);
    if (print_tree) {
        VolInterface::get_instance()->print_tree(vol);
    } else if (verify_tree) {
        if (vol) {
            VolInterface::get_instance()->verify_tree(vol);
        } else {
            LOGINFO("verifying all volumes");
            for (uint32_t i = 0; i < vol_list.size(); ++i) {
                LOGINFO("verifying volume {}", VolInterface::get_instance()->get_name(vol_list[i]));
                VolInterface::get_instance()->verify_tree(vol_list[i]);
            }
        }
    } else { // print node
        VolInterface::get_instance()->print_node(vol, blkid, true);
    }
    notify_cmpl();
}

bool vol_found_cb(boost::uuids::uuid uuid) { return true; }

void vol_mounted_cb(std::shared_ptr< Volume > vol, vol_state state) { vol_list.push_back(vol); }

void vol_state_change_cb(std::shared_ptr< Volume > vol, vol_state old_state, vol_state new_state) {}

/* start homestore */
void start_homestore() {
    auto config = get_config();
    params.flag = homestore::io_flag::READ_ONLY;

    iomanager.start(1 /* total interfaces */, 2);
    iomanager.add_drive_interface(
        std::dynamic_pointer_cast< iomgr::DriveInterface >(std::make_shared< iomgr::AioDriveInterface >()),
        true /* is_default */);

    std::cout << "Configuration\nio_flag = READ_ONLY\n";
    std::cout << "min page size=" << config["min_virtual_page_size"] << std::endl;
    params.min_virtual_page_size = config["min_virtual_page_size"];
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
    if (params.is_read_only) { std::cout << "\nRead only flag set" << std::endl; }
    params.is_file = config["is_file"];
    std::cout << "\nsystem uuid=" << config["system_uuid"] << std::endl;
    params.system_uuid = gen(std::string(config["system_uuid"]));
    params.init_done_cb = std::bind(init_done_cb, std::placeholders::_1, std::placeholders::_2);
    params.vol_mounted_cb = std::bind(vol_mounted_cb, std::placeholders::_1, std::placeholders::_2);
    params.vol_state_change_cb =
        std::bind(vol_state_change_cb, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
    params.vol_found_cb = std::bind(vol_found_cb, std::placeholders::_1);
    VolInterface::init(params);
}

void shutdown() {
    std::unique_lock< std::mutex > lk(m_mutex);
    vol_list.clear();
    VolInterface::get_instance()->shutdown();
}

/************************* CLI options ***************************/

SDS_OPTION_GROUP(
    check_btree,
    (vol_uuid, "", "vol_uuid", "volume uuid", ::cxxopts::value< std::string >()->default_value(""), "string"),
    (blkid, "", "blkid", "block id", ::cxxopts::value< uint64_t >()->default_value("0"), "number"),
    (print_tree, "", "print_tree", "print tree", ::cxxopts::value< uint32_t >()->default_value("0"), "flag"),
    (verify_tree, "", "verify_tree", "verify tree", ::cxxopts::value< uint32_t >()->default_value("0"), "flag"))

#define ENABLED_OPTIONS logging, home_blks, check_btree
SDS_OPTIONS_ENABLE(ENABLED_OPTIONS)

/************************** MAIN ********************************/

int main(int argc, char* argv[]) {
    SDS_OPTIONS_LOAD(argc, argv, ENABLED_OPTIONS)
    sds_logging::SetLogger("check_btree");
    spdlog::set_pattern("[%D %T.%f] [%^%L%$] [%t] %v");

    vol_uuid = SDS_OPTIONS["vol_uuid"].as< std::string >();
    blkid = SDS_OPTIONS["blkid"].as< uint64_t >();
    print_tree = SDS_OPTIONS["print_tree"].as< uint32_t >();
    verify_tree = SDS_OPTIONS["verify_tree"].as< uint32_t >();
    start_homestore();
    wait_cmpl();
    shutdown();

    return 0;
}
