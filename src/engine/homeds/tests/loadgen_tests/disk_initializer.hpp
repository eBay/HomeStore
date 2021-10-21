#pragma once

#include <cassert>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <string>
#include <system_error>
#include <vector>

#ifdef __linux__
#include <fcntl.h>
#include <sys/stat.h>
#endif

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
private:
    std::vector< homestore::dev_info > device_info;
    std::string m_file_name{"file_load_gen"};
    // boost::uuids::uuid uuid;

public:
    DiskInitializer() = default;
    DiskInitializer(const DiskInitializer&) = delete;
    DiskInitializer& operator=(const DiskInitializer&) = delete;
    DiskInitializer(DiskInitializer&&) noexcept = delete;
    DiskInitializer& operator=(DiskInitializer&&) noexcept = delete;

    ~DiskInitializer() = default;

    void cleanup() {
        const auto success{homestore::VolInterface::shutdown()};
        assert(success);
        std::filesystem::remove(m_file_name);
    }
    void init(Executor& executor, init_done_callback init_done_cb, size_t atomic_phys_page_size = 2048) {
        start_homestore(init_done_cb, atomic_phys_page_size);
    }

    void start_homestore(init_done_callback init_done_cb, size_t atomic_phys_page_size) {
        /* start homestore */
        /* create files */

        const std::filesystem::path fpath{m_file_name};
        std::ofstream ofs{fpath.string(), std::ios::binary | std::ios::out};
        std::filesystem::resize_file(fpath, DISK_MAX_SIZE); // set the file size
        device_info.emplace_back(std::filesystem::canonical(fpath).string(), homestore::dev_info::Type::Data);

        //                iomgr_obj = std::make_shared<iomgr::ioMgr>(2, num_threads);
        homestore::init_params params;
#ifndef NDEBUG
        params.data_open_flags = homestore::io_flag::BUFFERED_IO;
#else
        params.data_open_flags = homestore::io_flag::DIRECT_IO;
#endif
        params.min_virtual_page_size = 4096;
        params.app_mem_size = static_cast< uint64_t >(5) * 1024 * 1024 * 1024;
        params.data_devices = device_info;
        params.init_done_cb = init_done_cb;
        params.data_drive_attr = iomgr::drive_attributes();
        params.data_drive_attr->phys_page_size = 4096;
        params.data_drive_attr->align_size = 512;
        params.data_drive_attr->atomic_phys_page_size = atomic_phys_page_size;
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

    bool vol_found_cb(const boost::uuids::uuid uuid) const { return true; }

    void process_completions(const homestore::vol_interface_req_ptr& hb_req) {}

    void vol_mounted_cb(const homestore::VolumePtr& vol_obj, const homestore::vol_state state) {
        vol_init(vol_obj);
        auto cb{[this](const homestore::vol_interface_req_ptr& vol_req) { process_completions(vol_req); }};
        homestore::VolInterface::get_instance()->attach_vol_completion_cb(vol_obj, cb);
    }

    void vol_init(const homestore::VolumePtr& vol_obj) {
        ::open(homestore::VolInterface::get_instance()->get_name(vol_obj), O_RDWR);
    }

    void vol_state_change_cb(const homestore::VolumePtr& vol, const homestore::vol_state old_state,
                             const homestore::vol_state new_state) {
        assert(false);
    }
};
} // namespace loadgen
} // namespace homeds
