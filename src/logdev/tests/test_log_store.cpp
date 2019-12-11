#include "../log_store.hpp"
#include <sds_logging/logging.h>
#include <sds_options/options.h>
#include <iomgr/iomgr.hpp>
#include <iomgr/aio_drive_interface.hpp>

using namespace homestore;
THREAD_BUFFER_INIT;
SDS_LOGGING_INIT(test_log_store, btree_structures, btree_nodes, btree_generics, cache, device, httpserver_lmod, iomgr,
                 varsize_blk_alloc, VMOD_VOL_MAPPING, volume, logdev, flip)

static void start_homestore(uint32_t ndevices, uint64_t dev_size, uint32_t nthreads) {
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

    LOGINFO("Starting iomgr with {} threads", nthreads);
    iomanager.start(2 /* total interfaces */, nthreads);
    iomanager.add_drive_interface(
        std::dynamic_pointer_cast< iomgr::DriveInterface >(std::make_shared< iomgr::AioDriveInterface >()),
        true /* is_default */);

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
    params.init_done_cb = [&](std::error_condition err, const out_params& params) {
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
}

SDS_OPTIONS_ENABLE(logging, test_log_store)
SDS_OPTION_GROUP(test_log_store,
                 (num_threads, "", "num_threads", "number of threads",
                  ::cxxopts::value< uint32_t >()->default_value("2"), "number"),
                 (num_devs, "", "num_devs", "number of devices to create",
                  ::cxxopts::value< uint32_t >()->default_value("2"), "number"),
                 (dev_size_mb, "", "dev_size_mb", "size of each device in MB",
                  ::cxxopts::value< uint64_t >()->default_value("5120"), "number"));

int main(int argc, char* argv[]) {
    SDS_OPTIONS_LOAD(argc, argv, logging, test_log_store);
    sds_logging::SetLogger("test_log_store");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    start_homestore(SDS_OPTIONS["num_devs"].as< uint32_t >(), SDS_OPTIONS["dev_size_mb"].as< uint64_t >() * 1024 * 1024,
                    SDS_OPTIONS["num_threads"].as< uint32_t >());

    HomeLogStore::start(true);
    auto ls = HomeLogStore::create_new_log_store();

    std::atomic< int64_t > pending_count = 0;
    std::mutex _mtx;
    std::condition_variable _cv;
    std::vector< std::string > s;
    s.reserve(200);

    for (auto i = 0; i < 195; i++) {
        ++pending_count;
        s.push_back(std::to_string(i));
        ls->write_async(i, {(uint8_t*)s.back().c_str(), (uint32_t)s.back().size() + 1}, nullptr,
                        [&pending_count, &_cv](logstore_seq_num_t seq_num, bool success, void* ctx) {
                            LOGINFO("Completed write of seq_num {} ", seq_num);
                            if (--pending_count == 0) { _cv.notify_all(); }
                        });
    }

    {
        std::unique_lock< std::mutex > lk(_mtx);
        _cv.wait(lk, [&] { return (pending_count == 0); });
    }
}