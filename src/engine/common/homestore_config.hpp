
#ifndef _HOMESTORE_CONFIG_HPP_
#define _HOMESTORE_CONFIG_HPP_

#include <array>
#include <cassert>
#include <cstdint>
#include <sstream>
#include <vector>

#include <boost/intrusive_ptr.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/optional.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <iomgr/iomgr.hpp>
#include <nlohmann/json.hpp>
#include <sds_options/options.h>
#include <sisl/settings/settings.hpp>

#include "engine/common/error.h"
#include "engine/common/generated/homestore_config_generated.h"
#include "homestore_header.hpp"

SETTINGS_INIT(homestorecfg::HomeStoreSettings, homestore_config);

// DM info size depends on these three parameters. If below parameter changes then we have to add
// the code for upgrade/revert.

constexpr uint32_t MAX_CHUNKS{128};
constexpr uint32_t MAX_VDEVS{16};
constexpr uint32_t MAX_PDEVS{8};

namespace homestore {
#define HS_DYNAMIC_CONFIG_WITH(...) SETTINGS(homestore_config, __VA_ARGS__)
#define HS_DYNAMIC_CONFIG_THIS(...) SETTINGS_THIS(homestore_config, __VA_ARGS__)
#define HS_DYNAMIC_CONFIG_WITH_CAP(...) SETTINGS_THIS_CAP1(homestore_config, __VA_ARGS__)
#define HS_DYNAMIC_CONFIG(...) SETTINGS_VALUE(homestore_config, __VA_ARGS__)

#define HS_SETTINGS_FACTORY() SETTINGS_FACTORY(homestore_config)

#define HS_STATIC_CONFIG(cfg) homestore::HomeStoreStaticConfig::instance().cfg

// This is the optional parameteres which should be given by its consumers only when there is no
// system command to get these parameteres directly from disks. Or Consumer want to override
// the default values.

struct cap_attrs {
    uint64_t used_data_size{0};     // access-mgr should use this for used data size;
    uint64_t used_index_size{0};    // used size of index mgr store;
    uint64_t used_log_size{0};      // used size of logstore;
    uint64_t used_metablk_size{0};  // used size of meta blk store;
    uint64_t used_total_size{0};    // used total size including data and metadata;
    uint64_t initial_total_size{0}; // access-mgr uses this field to report to host for available user data capacity;
    uint64_t initial_total_data_meta_size{0}; // total capacity including data and metadata;
    std::string to_string() {
        std::ostringstream ss{};
        ss << "used_data_size = " << used_data_size << ", used_index_size = " << used_index_size
           << ", used_log_size = " << used_log_size << ", used_metablk_size = " << used_metablk_size
           << ", used_total_size = " << used_total_size << ", initial_total_size = " << initial_total_size
           << ", initial_total_data_meta_size = " << initial_total_data_meta_size;
        return ss.str();
    }
    void add(const cap_attrs& other) {
        used_data_size += other.used_data_size;
        used_index_size += other.used_index_size;
        used_log_size += other.used_log_size;
        used_metablk_size += other.used_metablk_size;
        used_total_size += other.used_total_size;
        initial_total_size += other.initial_total_size;
        initial_total_data_meta_size += other.initial_total_data_meta_size;
    }
};

struct hs_input_params {
public:
    std::vector< dev_info > data_devices;                                       // name of the data devices.
    iomgr::iomgr_drive_type data_device_type{iomgr::iomgr_drive_type::unknown}; // Type of the data device
    std::vector< dev_info > fast_devices;                                       // name of fast devices
    iomgr::iomgr_drive_type fast_device_type{iomgr::iomgr_drive_type::unknown}; // Type of the fast device
    bool is_file{false};                                                        // Are the devices a file or raw device
    boost::uuids::uuid system_uuid;                                             // Deprecated. UUID assigned to the system
    
    io_flag data_open_flags{io_flag::DIRECT_IO};
    io_flag fast_open_flags{io_flag::DIRECT_IO};

    uint32_t min_virtual_page_size{4096}; // minimum page size supported. Ideally it should be 4k.
    uint64_t app_mem_size{static_cast< uint64_t >(1024) * static_cast< uint64_t >(1024) *
                          static_cast< uint64_t >(1024)}; // memory available for the app (including cache)
    bool disk_init{false};                                // Deprecated. true if disk has to be initialized.
    bool is_read_only{false};                             // Is read only
    bool start_http{true};

#ifdef _PRERELEASE
    bool force_reinit{false};
#endif
    bool is_hdd{false};

    /* optional parameters - if provided will override the startup config */
    boost::optional< iomgr::drive_attributes > data_drive_attr;
    boost::optional< iomgr::drive_attributes > fast_drive_attr;

    bool fast_devices_present() const { return !fast_devices.empty(); }

    nlohmann::json to_json() const {
        nlohmann::json json;
        json["system_uuid"] = boost::uuids::to_string(system_uuid);
        json["data_devices"] = nlohmann::json::array();
        for (const auto& d : data_devices) {
            json["data_devices"].push_back(d.dev_names);
        }
        json["data_device_type"] = enum_name(data_device_type);
        json["data_open_flags"] = data_open_flags;
        if (fast_devices_present()) {
            json["fast_devices"] = nlohmann::json::array();
            for (const auto& d : fast_devices) {
                json["fast_devices"].push_back(d.dev_names);
            }
            json["fast_device_type"] = enum_name(fast_device_type);
            json["fast_open_flags"] = fast_open_flags;
        }
        json["is_read_only"] = is_read_only;

        json["min_virtual_page_size"] = min_virtual_page_size;
        json["app_mem_size"] = app_mem_size;

        return json;
    }
};

struct hs_engine_config {
    size_t min_io_size{8192};        // minimum io size supported by
    uint64_t max_chunks{MAX_CHUNKS}; // These 3 parameters can be ONLY changed with upgrade/revert from device manager
    uint64_t max_vdevs{MAX_VDEVS};
    uint64_t max_pdevs{MAX_PDEVS};
    uint64_t memvec_max_io_size{min_io_size};
    uint64_t max_vol_io_size{memvec_max_io_size};
    uint32_t max_blks_in_blkentry{1}; // Max blks a represents in a single BlkId entry

    nlohmann::json to_json() const {
        nlohmann::json json;
        json["min_io_size"] = min_io_size;
        json["max_chunks"] = max_chunks;
        json["max_vdevs"] = max_vdevs;
        json["max_pdevs"] = max_pdevs;
        json["memvec_max_io_size"] = memvec_max_io_size;
        json["max_vol_io_size"] = max_vol_io_size;
        json["max_blks_in_blkentry"] = max_blks_in_blkentry;
        return json;
    }
};

struct HomeStoreStaticConfig {
    static HomeStoreStaticConfig& instance() {
        static HomeStoreStaticConfig s_inst;
        return s_inst;
    }

    iomgr::drive_attributes data_drive_attr;
    bool fast_drive_present;
    iomgr::drive_attributes fast_drive_attr;
    hs_engine_config engine;
    hs_input_params input;

    nlohmann::json to_json() const {
        nlohmann::json json;
        json["DataDriveAttributes"] = data_drive_attr.to_json();
        if (fast_drive_present) { json["FastDriveAttributes"] = fast_drive_attr.to_json(); }
        json["GenericConfig"] = engine.to_json();
        json["InputParameters"] = input.to_json();
        return json;
    }

#ifndef NDEBUG
    void validate() {
        assert(data_drive_attr.phys_page_size >= data_drive_attr.atomic_phys_page_size);
        assert(data_drive_attr.phys_page_size >= engine.min_io_size);
        if (fast_drive_present) {
            assert(fast_drive_attr.phys_page_size >= fast_drive_attr.atomic_phys_page_size);
            assert(fast_drive_attr.phys_page_size >= engine.min_io_size);
        }
    }
#endif
};

class HomeStoreDynamicConfig {
public:
    static const std::array< double, 9 >& default_slab_distribution() {
        // Assuming blk_size=4K [4K, 8K, 16K, 32K, 64K, 128K, 256K, 512K, 1M ]
        static constexpr std::array< double, 9 > slab_distribution{15.0, 7.0, 7.0, 6.0, 10.0, 10.0, 10.0, 10.0, 25.0};
        return slab_distribution;
    }

    // This method sets up the default for settings factory when there is no override specified in the json
    // file and .fbs cannot specify default because they are not scalar.
    static void init_settings_default() {
        bool is_modified{false};

        HS_SETTINGS_FACTORY().modifiable_settings([&is_modified](auto& s) {
            // Setup slab config of blk alloc cache, if they are not set already - first time
            auto& slab_pct_dist{s.blkallocator.free_blk_slab_distribution};
            if (slab_pct_dist.size() == 0) {
                LOGINFO("Free Blks Slab distribution is not initialized, possibly first boot - setting with defaults");

                // Slab distribution is not initialized, defaults
                const auto& d{default_slab_distribution()};
                slab_pct_dist.insert(slab_pct_dist.begin(), std::cbegin(d), std::cend(d));
                is_modified = true;
            }
#ifndef NDEBUG
            s.generic.blkalloc_cp_timer_us = 1000000; // setting to 1 sec for debug build
            is_modified = true;
#endif
            // Any more default overrides or set non-scalar entries come here
        });

        if (is_modified) {
            LOGINFO("Some settings are defaultted or overridden explicitly in the code, saving the new settings");
            HS_SETTINGS_FACTORY().save();
        }
    }
};
constexpr uint32_t BLK_NUM_BITS{32};
constexpr uint32_t NBLKS_BITS{8};
constexpr uint32_t CHUNK_NUM_BITS{8};
constexpr uint32_t BLKID_SIZE_BITS{BLK_NUM_BITS + NBLKS_BITS + CHUNK_NUM_BITS};
constexpr uint32_t MEMPIECE_ENCODE_MAX_BITS{8};
constexpr uint64_t MAX_CHUNK_ID{
    ((static_cast< uint64_t >(1) << CHUNK_NUM_BITS) - 2)}; // one less to indicate invalid chunks
constexpr uint64_t BLKID_SIZE{(BLKID_SIZE_BITS / 8) + (((BLKID_SIZE_BITS % 8) != 0) ? 1 : 0)};
constexpr uint32_t BLKS_PER_PORTION{1024};
constexpr uint32_t TOTAL_SEGMENTS{8};
constexpr uint64_t MAX_BLK_NUM_BITS_PER_CHUNK{((static_cast< uint64_t >(1) << BLK_NUM_BITS) - 1)};

/* NOTE: it can give size more then the size passed in argument to make it aligned */
// #define ALIGN_SIZE(size, align) (((size % align) == 0) ? size : (size + (align - (size % align))))

/* NOTE: it can give size less then size passed in argument to make it aligned */
// #define ALIGN_SIZE_TO_LEFT(size, align) (((size % align) == 0) ? size : (size - (size % align)))

inline uint64_t MIN_DATA_CHUNK_SIZE() {
    return HS_STATIC_CONFIG(data_drive_attr.phys_page_size) * BLKS_PER_PORTION * TOTAL_SEGMENTS;
}
inline uint64_t MAX_DATA_CHUNK_SIZE() {
    return static_cast< uint64_t >(
        sisl::round_down((MAX_BLK_NUM_BITS_PER_CHUNK * HS_STATIC_CONFIG(engine.min_io_size)), MIN_DATA_CHUNK_SIZE()));
} // 16 TB
inline uint64_t MIN_FAST_CHUNK_SIZE() {
    return HS_STATIC_CONFIG(fast_drive_present)
        ? HS_STATIC_CONFIG(fast_drive_attr.phys_page_size) * BLKS_PER_PORTION * TOTAL_SEGMENTS
        : 0;
}
inline uint64_t MAX_FAST_CHUNK_SIZE() {
    return (MIN_FAST_CHUNK_SIZE() > 0)
        ? static_cast< uint64_t >(sisl::round_down((MAX_BLK_NUM_BITS_PER_CHUNK * HS_STATIC_CONFIG(engine.min_io_size)),
                                                   MIN_FAST_CHUNK_SIZE()))
        : 0;
}

// TODO: we store global unique ID in blkid. Instead it we only store chunk offset then
// max cacapity will increase from MAX_CHUNK_SIZE to MAX_CHUNKS * MAX_CHUNK_SIZE.
inline uint64_t MAX_DATA_SUPPORTED_CAP() { return MAX_CHUNKS * MAX_DATA_CHUNK_SIZE(); }
inline uint64_t MAX_FAST_SUPPORTED_CAP() { return MAX_CHUNKS * MAX_FAST_CHUNK_SIZE(); }

constexpr uint16_t MAX_UUID_LEN{128};

// 1 % of disk space is reserved for volume sb chunks. With 8k page it
// will come out to be around 7 GB.
inline uint64_t MIN_DATA_DISK_CAP_SUPPORTED() { return MIN_DATA_CHUNK_SIZE() * 100 / 99 + MIN_DATA_CHUNK_SIZE(); }
// TODO: address proper caclulation here
inline uint64_t MIN_FAST_DISK_CAP_SUPPORTED() { return MIN_FAST_CHUNK_SIZE() * 100 / 99 + MIN_FAST_CHUNK_SIZE(); }
} // namespace homestore

#endif
