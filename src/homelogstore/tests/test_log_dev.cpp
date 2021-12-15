#include <array>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <sisl/logging/logging.h>
#include <sisl/options/options.h>

#include "../log_dev.hpp"

using namespace homestore;
RCU_REGISTER_INIT
SISL_LOGGING_INIT(HOMESTORE_LOG_MODS)

std::vector< logdev_key > s_logdev_keys;
static uint64_t first_offset{~static_cast< uint64_t >(0)};

static void on_append_completion(const logdev_key lkey, void* const ctx) {
    s_logdev_keys.push_back(lkey);
    LOGINFO("Append completed with log_idx = {} offset = {}", lkey.idx, lkey.dev_offset);
    if (first_offset == ~static_cast< uint64_t >(0)) { first_offset = lkey.dev_offset; }
}

static void on_log_found(const logdev_key lkey, const log_buffer buf) {
    s_logdev_keys.push_back(lkey);
    LOGINFO("Found a log with log_idx = {} offset = {}", lkey.idx, lkey.dev_offset);
}

[[nodiscard]] static std::shared_ptr< iomgr::ioMgr > start_homestore(const uint32_t ndevices, const uint64_t dev_size,
                                                                     const uint32_t nthreads) {
    std::vector< dev_info > device_info;
    // these should be static so that they stay in scope in the lambda in case function ends before lambda completes
    static std::mutex start_mutex;
    static std::condition_variable cv;
    static bool inited;

    inited = false;
    LOGINFO("creating {} device files with each of size {} ", ndevices, dev_size);
    for (uint32_t i{0}; i < ndevices; ++i) {
        const std::filesystem::path fpath{"/tmp/" + std::to_string(i + 1)};
        std::ofstream ofs{fpath.string(), std::ios::binary | std::ios::out};
        std::filesystem::resize_file(fpath, dev_size);
        device_info.emplace_back(std::filesystem::canonical(fpath).string(), HSDevType::Data);
    }

    LOGINFO("Creating iomgr with {} threads", nthreads);
    auto iomgr_obj{std::make_shared< iomgr::ioMgr >(2, nthreads)};

    const uint64_t cache_size{((ndevices * dev_size) * 10) / 100};
    LOGINFO("Initialize and start HomeBlks with cache_size = {}", cache_size);

    boost::uuids::string_generator gen;
    init_params params;
    params.open_flags = homestore::io_flag::DIRECT_IO;
    params.min_virtual_page_size = 4096;
    params.cache_size = cache_size;
    params.devices = device_info;
    params.iomgr = iomgr_obj;
    params.init_done_cb = [&iomgr_obj, &tl_start_mutex = start_mutex, &tl_cv = cv,
                           &tl_inited = inited](std::error_condition err, const out_params& params) {
        iomgr_obj->start();
        LOGINFO("HomeBlks Init completed");
        {
            std::unique_lock< std::mutex > lk{tl_start_mutex};
            tl_inited = true;
        }
        tl_cv.notify_one();
    };
    params.vol_mounted_cb = [](const VolumePtr& vol_obj, vol_state state) {};
    params.vol_state_change_cb = [](const VolumePtr& vol, vol_state old_state, vol_state new_state) {};
    params.vol_found_cb = [](boost::uuids::uuid uuid) -> bool { return true; };
    VolInterface::init(params);

    {
        std::unique_lock< std::mutex > lk{start_mutex};
        cv.wait(lk, [] { return inited; });
    }
    return iomgr_obj;
}

SISL_OPTIONS_ENABLE(logging, test_log_dev)
SISL_OPTION_GROUP(test_log_dev,
                  (num_threads, "", "num_threads", "number of threads",
                   ::cxxopts::value< uint32_t >()->default_value("2"), "number"),
                  (num_devs, "", "num_devs", "number of devices to create",
                   ::cxxopts::value< uint32_t >()->default_value("2"), "number"),
                  (dev_size_mb, "", "dev_size_mb", "size of each device in MB",
                   ::cxxopts::value< uint64_t >()->default_value("5120"), "number"));

int main(int argc, char* argv[]) {
    SISL_OPTIONS_LOAD(argc, argv, logging, test_log_dev);
    sisl::logging::SetLogger("test_log_dev");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    auto iomgr_obj{start_homestore(SISL_OPTIONS["num_devs"].as< uint32_t >(),
                                   SISL_OPTIONS["dev_size_mb"].as< uint64_t >() * 1024 * 1024,
                                   SISL_OPTIONS["num_threads"].as< uint32_t >())};

    std::array< std::string, 1024 > s;
    auto ld{LogDev::instance()};
    ld->register_append_cb(on_append_completion);
    ld->register_logfound_cb(on_log_found);

    for (
        size_t i{0}; (i < std::min< size_t >(195, s.size()); ++i) {
        s[i] = std::to_string(i);
        ld->append_async(0, 0, {reinterpret_cast< const uint8_t* >(s[i].c_str()), s[i].size() + 1}, nullptr);
    }

    size_t i{0};
    for (const auto& lk : s_logdev_keys) {
        const auto b{ld->read(lk)};
        const auto exp_val{std::to_string(i)};
        const auto actual_val{reinterpret_cast< const char* >(b.data()), static_cast< size_t >(b.size())};
        if (actual_val != exp_val) {
            LOGERROR("Error in reading value for log_idx {} actual_val={} expected_val={}", i, actual_val, exp_val);
        } else {
            LOGINFO("Read value {} for log_idx {}", actual_val, i);
        }
        ++i;
    }

    ld->load(first_offset);
}
