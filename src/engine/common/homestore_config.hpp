
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
#include <sisl/options/options.h>
#include <sisl/settings/settings.hpp>

#include "engine/common/error.h"
#include "engine/common/generated/homestore_config_generated.h"
#include "homestore_header.hpp"

SETTINGS_INIT(homestorecfg::HomeStoreSettings, homestore_config);

// DM info size depends on these three parameters. If below parameter changes then we have to add
// the code for upgrade/revert.

constexpr uint32_t MAX_CHUNKS{128};
constexpr uint32_t HDD_MAX_CHUNKS{254};
constexpr uint32_t HS_MAX_CHUNKS{HDD_MAX_CHUNKS};
constexpr uint32_t MAX_VDEVS{16};
constexpr uint32_t MAX_PDEVS{8};
static constexpr uint32_t INVALID_PDEV_ID{std::numeric_limits< uint32_t >::max()};
static constexpr uint32_t INVALID_VDEV_ID{std::numeric_limits< uint32_t >::max()};
static constexpr uint32_t INVALID_CHUNK_ID{std::numeric_limits< uint32_t >::max()};
static constexpr uint32_t INVALID_DEV_ID{std::numeric_limits< uint32_t >::max()};

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
    std::vector< dev_info > data_devices; // name of the data devices.
    boost::uuids::uuid system_uuid;       // Deprecated. UUID assigned to the system

    io_flag data_open_flags{io_flag::DIRECT_IO}; // All data drives open flags
    io_flag fast_open_flags{io_flag::DIRECT_IO}; // All index drives open flags

    uint32_t min_virtual_page_size{4096}; // minimum page size supported. Ideally it should be 4k.
    uint64_t app_mem_size{static_cast< uint64_t >(1024) * static_cast< uint64_t >(1024) *
                          static_cast< uint64_t >(1024)}; // memory available for the app (including cache)
    bool is_read_only{false};                             // Is read only
    bool start_http{true};

#ifdef _PRERELEASE
    bool force_reinit{false};
#endif

    nlohmann::json to_json() const {
        nlohmann::json json;
        json["system_uuid"] = boost::uuids::to_string(system_uuid);
        json["devices"] = nlohmann::json::array();
        for (const auto& d : data_devices) {
            json["devices"].push_back(d.to_string());
        }
        json["data_open_flags"] = data_open_flags;
        json["fast_open_flags"] = fast_open_flags;
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

    hs_engine_config engine;
    hs_input_params input;
    bool hdd_drive_present;

    nlohmann::json to_json() const {
        nlohmann::json json;
        json["GenericConfig"] = engine.to_json();
        json["InputParameters"] = input.to_json();
        return json;
    }
};

[[maybe_unused]] static bool is_data_drive_hdd() { return HomeStoreStaticConfig::instance().hdd_drive_present; }

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

inline uint64_t MIN_DATA_CHUNK_SIZE(const uint32_t page_size) { return page_size * BLKS_PER_PORTION * TOTAL_SEGMENTS; }
inline uint64_t MAX_DATA_CHUNK_SIZE(const uint32_t page_size) {
    return static_cast< uint64_t >(
        sisl::round_down((MAX_BLK_NUM_BITS_PER_CHUNK * page_size), MIN_DATA_CHUNK_SIZE(page_size)));
} // 16 TB

constexpr uint16_t MAX_UUID_LEN{128};

} // namespace homestore

#endif
