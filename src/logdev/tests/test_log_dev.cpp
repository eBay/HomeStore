#include "../log_dev.hpp"
#include <sds_logging/logging.h>
#include <sds_options/options.h>

using namespace homestore;
THREAD_BUFFER_INIT;
SDS_LOGGING_INIT(test_log_dev, btree_structures, btree_nodes, btree_generics, cache, device, httpserver_lmod, iomgr,
                 varsize_blk_alloc, VMOD_VOL_MAPPING, volume, logdev, flip)

std::vector< logdev_key > _logdev_keys;
static uint64_t first_offset = (uint64_t)-1UL;
static void on_append_completion(logdev_key lkey, void* ctx) {
    _logdev_keys.push_back(lkey);
    LOGINFO("Append completed with log_idx = {} offset = {}", lkey.idx, lkey.dev_offset);
    if (first_offset == -1UL) { first_offset = lkey.dev_offset; }
}

static void on_log_found(logdev_key lkey, log_buffer buf) {
    _logdev_keys.push_back(lkey);
    LOGINFO("Found a log with log_idx = {} offset = {}", lkey.idx, lkey.dev_offset);
}

static std::shared_ptr< iomgr::ioMgr > start_homestore(uint32_t ndevices, uint64_t dev_size, uint32_t nthreads) {
    std::vector< dev_info > device_info;
    std::mutex start_mutex;
    std::condition_variable cv;
    bool inited = false;

    LOGINFO("creating {} device files with each of size {} ", ndevices, dev_size);
    for (uint32_t i = 0; i < ndevices; i++) {
        std::string fpath = "/tmp/" + std::to_string(i + 1);
        std::ofstream ofs(fpath.c_str(), std::ios::binary | std::ios::out);
        ofs.seekp(dev_size - 1);
        ofs.write("", 1);
        ofs.close();
        device_info.push_back({fpath});
    }

    LOGINFO("Creating iomgr with {} threads", nthreads);
    auto iomgr_obj = std::make_shared< iomgr::ioMgr >(2, nthreads);

    uint64_t cache_size = ((ndevices * dev_size) * 10) / 100;
    LOGINFO("Initialize and start HomeBlks with cache_size = {}", cache_size);

    boost::uuids::string_generator gen;
    init_params params;
    params.flag = homestore::io_flag::DIRECT_IO;
    params.min_virtual_page_size = 4096;
    params.cache_size = cache_size;
    params.disk_init = true;
    params.devices = device_info;
    params.is_file = true;
    params.iomgr = iomgr_obj;
    params.init_done_cb = [&](std::error_condition err, const out_params& params) {
        iomgr_obj->start();
        LOGINFO("HomeBlks Init completed");
        {
            std::unique_lock< std::mutex > lk(start_mutex);
            inited = true;
        }
        cv.notify_all();
    };
    params.vol_mounted_cb = [](const VolumePtr& vol_obj, vol_state state) {};
    params.vol_state_change_cb = [](const VolumePtr& vol, vol_state old_state, vol_state new_state) {};
    params.vol_found_cb = [](boost::uuids::uuid uuid) -> bool { return true; };
    params.system_uuid = gen("01970496-0262-11e9-8eb2-f2801f1b9fd1");
    VolInterface::init(params);

    std::unique_lock< std::mutex > lk(start_mutex);
    cv.wait(lk, [&] { return inited; });
    return iomgr_obj;
}

SDS_OPTIONS_ENABLE(logging, test_log_dev)
SDS_OPTION_GROUP(test_log_dev,
                 (num_threads, "", "num_threads", "number of threads",
                  ::cxxopts::value< uint32_t >()->default_value("2"), "number"),
                 (num_devs, "", "num_devs", "number of devices to create",
                  ::cxxopts::value< uint32_t >()->default_value("2"), "number"),
                 (dev_size_mb, "", "dev_size_mb", "size of each device in MB",
                  ::cxxopts::value< uint64_t >()->default_value("5120"), "number"));

int main(int argc, char* argv[]) {
    SDS_OPTIONS_LOAD(argc, argv, logging, test_log_dev);
    sds_logging::SetLogger("test_log_dev");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    auto iomgr_obj = start_homestore(SDS_OPTIONS["num_devs"].as< uint32_t >(),
                                     SDS_OPTIONS["dev_size_mb"].as< uint64_t >() * 1024 * 1024,
                                     SDS_OPTIONS["num_threads"].as< uint32_t >());

    std::string s[1024];
    auto ld = LogDev::instance();
    ld->register_append_cb(on_append_completion);
    ld->register_logfound_cb(on_log_found);

    for (auto i = 0u; i < 195; i++) {
        s[i] = std::to_string(i);
        ld->append((uint8_t*)s[i].c_str(), s[i].size() + 1, nullptr);
    }

    auto i = 0;
    for (auto& lk : _logdev_keys) {
        auto b = ld->read(lk);
        auto exp_val = std::to_string(i);
        auto actual_val = std::string((const char*)b.data(), (size_t)b.size());
        if (actual_val != exp_val) {
            LOGERROR("Error in reading value for log_idx {} actual_val={} expected_val={}", i, actual_val, exp_val);
        } else {
            LOGINFO("Read value {} for log_idx {}", actual_val, i);
        }
        ++i;
    }

    ld->load(first_offset);
}