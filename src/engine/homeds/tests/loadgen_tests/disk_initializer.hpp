#pragma once

#include <cstdint>
#include <functional>
#include <system_error>
#include <vector>
#include <fstream>
#include <filesystem>

#include <boost/uuid/string_generator.hpp>
#include <boost/uuid/uuid.hpp>

#include "api/vol_interface.hpp"
#include "homeds/loadgen/loadgen_common.hpp"

namespace homeds {
namespace loadgen {

static constexpr uint64_t DISK_MAX_SIZE{14 * Gi};

typedef std::function< void(std::error_condition err, const homestore::out_params& params) > init_done_callback;

template < typename Executor >
class DiskInitializer {
    std::vector< homestore::dev_info > device_info;
    // boost::uuids::uuid uuid;

public:
    ~DiskInitializer() {}
    void cleanup() {
        auto success = homestore::VolInterface::shutdown();
        assert(success);
        remove("file_load_gen");
    }
    void init(Executor& executor, init_done_callback init_done_cb, size_t atomic_phys_page_size = 2048) {
        start_homestore(init_done_cb, atomic_phys_page_size);
    }

    void start_homestore(init_done_callback init_done_cb, size_t atomic_phys_page_size) {
        /* start homestore */
        /* create files */

        homestore::dev_info temp_info;
        temp_info.dev_names = "file_load_gen";
        device_info.push_back(temp_info);

        std::ofstream ofs(temp_info.dev_names.c_str(), std::ios::binary | std::ios::out);
        std::filesystem::path p = temp_info.dev_names.c_str();
        std::filesystem::resize_file(p, DISK_MAX_SIZE); // set the file size

        //                iomgr_obj = std::make_shared<iomgr::ioMgr>(2, num_threads);
        homestore::init_params params;
#ifndef NDEBUG
        params.open_flags = homestore::io_flag::BUFFERED_IO;
#else
        params.open_flags = homestore::io_flag::DIRECT_IO;
#endif
        params.min_virtual_page_size = 4096;
        params.app_mem_size = 5 * 1024 * 1024 * 1024ul;
        params.devices = device_info;
        params.init_done_cb = init_done_cb;
        params.drive_attr = iomgr::drive_attributes();
        params.drive_attr->phys_page_size = 4096;
        params.drive_attr->align_size = 512;
        params.drive_attr->atomic_phys_page_size = atomic_phys_page_size;
        params.vol_mounted_cb =
            std::bind(&DiskInitializer::vol_mounted_cb, this, std::placeholders::_1, std::placeholders::_2);
        params.vol_state_change_cb = std::bind(&DiskInitializer::vol_state_change_cb, this, std::placeholders::_1,
                                               std::placeholders::_2, std::placeholders::_3);
        params.vol_found_cb = std::bind(&DiskInitializer::vol_found_cb, this, std::placeholders::_1);
        boost::uuids::string_generator gen;
        // params.system_uuid = gen("01970496-0262-11e9-8eb2-f2801f1b9fd1");
        // uuid = params.system_uuid;
        homestore::VolInterface::init(params);
    }

    bool vol_found_cb(boost::uuids::uuid uuid) { return true; }

    void process_completions(const homestore::vol_interface_req_ptr& hb_req) {}

    void vol_mounted_cb(const homestore::VolumePtr& vol_obj, homestore::vol_state state) {
        vol_init(vol_obj);
        auto cb = [this](const homestore::vol_interface_req_ptr& vol_req) { process_completions(vol_req); };
        homestore::VolInterface::get_instance()->attach_vol_completion_cb(vol_obj, cb);
    }

    void vol_init(const homestore::VolumePtr& vol_obj) {
        open(homestore::VolInterface::get_instance()->get_name(vol_obj), O_RDWR);
    }

    void vol_state_change_cb(const homestore::VolumePtr& vol, homestore::vol_state old_state,
                             homestore::vol_state new_state) {
        assert(0);
    }
};
} // namespace loadgen
} // namespace homeds
