#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include <iomgr/aio_drive_interface.hpp>
#include <iomgr/io_environment.hpp>
#include <sisl/logging/logging.h>
#include <sisl/options/options.h>

#include "homeblks/home_blks.hpp"

using namespace homestore;

std::vector< std::shared_ptr< Volume > > vol_list;

RCU_REGISTER_INIT
SISL_LOGGING_INIT(HOMESTORE_LOG_MODS)
SISL_LOGGING_DECL(hs_svc_tool)

SISL_OPTIONS_ENABLE(logging, hs_svc_tool)

struct Param {
    bool zero_boot_sb = 0;
    std::vector< std::string > dev_names;
};

static Param gp;

static void gen_device_info(std::vector< dev_info >& device_info, uint32_t ndevices, uint64_t dev_size) {
    if (gp.dev_names.size() != 0) {
        for (uint32_t i = 0; i < gp.dev_names.size(); i++) {
            device_info.push_back(dev_info{gp.dev_names[i]});
        }
    } else {
        for (uint32_t i{0}; i < ndevices; ++i) {
            const std::filesystem::path fpath{"/tmp/hs_svc_tool_" + std::to_string(i + 1)};
            std::ofstream ofs{fpath.string(), std::ios::binary | std::ios::out};
            std::filesystem::resize_file(fpath, dev_size);
            device_info.emplace_back(std::filesystem::canonical(fpath).string(), HSDevType::Data);
        }
    }
}

/* start homestore */
static void start_homestore(uint32_t ndevices, uint64_t dev_size, uint32_t nthreads) {
    std::vector< dev_info > device_info;
    // this should be static so that it stays in scope in the lambda in case function ends before lambda completes
    static std::mutex start_mutex;
    static std::condition_variable cv;
    static bool inited;

    inited = false;
    LOGINFO("creating {} device files with each of size {} ", ndevices, dev_size);

    gen_device_info(device_info, ndevices, dev_size);

    LOGINFO("Starting iomgr with {} threads", nthreads);
    ioenvironment.with_iomgr(nthreads);

    uint64_t app_mem_size = ((ndevices * dev_size) * 15) / 100;
    LOGINFO("Initialize and start HomeBlks with app_mem_size = {}", app_mem_size);

    boost::uuids::string_generator gen;
    init_params params;
    params.data_open_flags = homestore::io_flag::DIRECT_IO;
    params.min_virtual_page_size = 4096;
    params.app_mem_size = app_mem_size;
    params.data_devices = device_info;
    params.init_done_cb = [&tl_start_mutex = start_mutex, &tl_cv = cv, &tl_inited = inited](std::error_condition err,
                                                                                            const out_params& params) {
        LOGINFO("HomeBlks Init completed");
        {
            std::unique_lock< std::mutex > lk{tl_start_mutex};
            tl_inited = true;
        }
        tl_cv.notify_one();
    };
    params.vol_mounted_cb = [&](const VolumePtr& vol, vol_state state) { vol_list.push_back(vol); };
    params.vol_state_change_cb = [](const VolumePtr& vol, vol_state old_state, vol_state new_state) {};
    params.vol_found_cb = [](boost::uuids::uuid uuid) -> bool { return true; };
    VolInterface::init(params);

    {
        std::unique_lock< std::mutex > lk{start_mutex};
        cv.wait(lk, [] { return inited; });
    }
}

/************************* CLI options ***************************/

SISL_OPTION_GROUP(hs_svc_tool,
                  (num_threads, "", "num_threads", "number of threads",
                   ::cxxopts::value< uint32_t >()->default_value("2"), "number"),
                  (num_devs, "", "num_devs", "number of devices to create",
                   ::cxxopts::value< uint32_t >()->default_value("2"), "number"),
                  (device_list, "", "device_list", "List of device paths",
                   ::cxxopts::value< std::vector< std::string > >(), "path [...]"),
                  (dev_size_gb, "", "dev_size_gb", "size of each device in GB",
                   ::cxxopts::value< uint64_t >()->default_value("10"), "number"),
                  (zero_boot_sb, "", "zero_boot_sb", "mark homestore init state",
                   ::cxxopts::value< bool >()->default_value("false"), "true or false"),
                  (spdk, "", "spdk", "spdk", ::cxxopts::value< bool >()->default_value("false"), "true or false"));

/************************** MAIN ********************************/

int main(int argc, char* argv[]) {
    SISL_OPTIONS_LOAD(argc, argv, logging, hs_svc_tool)
    ::testing::InitGoogleTest(&argc, argv);
    sisl::logging::SetLogger("hs_svc_tool");
    spdlog::set_pattern("[%D %T.%f] [%^%L%$] [%t] %v");

    gp.zero_boot_sb = SISL_OPTIONS["zero_boot_sb"].as< bool >();

    if (SISL_OPTIONS.count("device_list")) {
        gp.dev_names = SISL_OPTIONS["device_list"].as< std::vector< std::string > >();
    }

#if 0
    start_homestore(SISL_OPTIONS["num_devs"].as< uint32_t >(),
                    SISL_OPTIONS["dev_size_gb"].as< uint64_t >() * 1024 * 1024 * 1024,
                    SISL_OPTIONS["num_threads"].as< uint32_t >());
    VolInterface::shutdown();
    iomanager.stop();
#endif

    bool is_spdk = SISL_OPTIONS["spdk"].as< bool >();
    uint32_t nthreads = SISL_OPTIONS["num_threads"].as< uint32_t >();
    if (is_spdk) { nthreads = 2; }
    ioenvironment.with_iomgr(nthreads, is_spdk);

    auto ndevices = SISL_OPTIONS["num_devs"].as< uint32_t >();
    std::vector< dev_info > device_info;

    auto dev_size = SISL_OPTIONS["dev_size_gb"].as< uint64_t >() * 1024 * 1024 * 1024;
    gen_device_info(device_info, ndevices, dev_size);

    HS_DBG_ASSERT_EQ(device_info.size() > 0, true);

    if (gp.zero_boot_sb) { VolInterface::get_instance()->zero_boot_sbs(device_info); }

    iomanager.stop();

    return 0;
}
