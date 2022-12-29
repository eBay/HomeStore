/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 *********************************************************************************/
#pragma once

#include <string>
#include <limits>

#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <sisl/utility/enum.hpp>
#include <sisl/fds/utils.hpp>

#ifdef _PRERELEASE
#include <sisl/flip/flip.hpp>
#endif
#include <spdlog/fmt/fmt.h>
#include <nlohmann/json.hpp>

namespace homestore {
////////////// All Typedefs ///////////////////
typedef uint32_t crc32_t;
typedef uint16_t csum_t;
typedef int64_t seq_id_t;
typedef boost::uuids::uuid uuid_t;
typedef time_t hs_uuid_t;

////////////// All Size Limits ///////////////////
constexpr uint32_t BLK_NUM_BITS{32};
constexpr uint32_t NBLKS_BITS{8};
constexpr uint32_t CHUNK_NUM_BITS{8};
constexpr uint32_t BLKID_SIZE_BITS{BLK_NUM_BITS + NBLKS_BITS + CHUNK_NUM_BITS};
constexpr uint64_t MAX_CHUNK_ID{((uint64_cast(1) << CHUNK_NUM_BITS) - 2)}; // one less to indicate invalid chunks
constexpr uint64_t BLKID_SIZE{(BLKID_SIZE_BITS / 8) + (((BLKID_SIZE_BITS % 8) != 0) ? 1 : 0)};
constexpr uint32_t BLKS_PER_PORTION{1024};
constexpr uint32_t TOTAL_SEGMENTS{8};
constexpr uint64_t MAX_BLK_NUM_BITS_PER_CHUNK{((uint64_cast(1) << BLK_NUM_BITS) - 1)};

inline uint64_t MIN_DATA_CHUNK_SIZE(uint32_t blk_size) { return blk_size * BLKS_PER_PORTION * TOTAL_SEGMENTS; }
inline uint64_t MAX_DATA_CHUNK_SIZE(uint32_t blk_size) {
    return uint64_cast(sisl::round_down((MAX_BLK_NUM_BITS_PER_CHUNK * blk_size), MIN_DATA_CHUNK_SIZE(blk_size)));
} // 16 TB

constexpr uint32_t MAX_CHUNKS{128};
constexpr uint32_t HDD_MAX_CHUNKS{254};
constexpr uint32_t HS_MAX_CHUNKS{HDD_MAX_CHUNKS};
constexpr uint32_t MAX_VDEVS{16};
constexpr uint32_t MAX_PDEVS{8};
static constexpr uint32_t INVALID_PDEV_ID{std::numeric_limits< uint32_t >::max()};
static constexpr uint32_t INVALID_VDEV_ID{std::numeric_limits< uint32_t >::max()};
static constexpr uint32_t INVALID_CHUNK_ID{std::numeric_limits< uint32_t >::max()};
static constexpr uint32_t INVALID_DEV_ID{std::numeric_limits< uint32_t >::max()};
constexpr uint16_t MAX_UUID_LEN{128};
static constexpr hs_uuid_t INVALID_SYSTEM_UUID{0};

///////////// All Enums //////////////////////////
ENUM(HSDevType, uint8_t, Data, Fast);
ENUM(Op_type, uint8_t, READ, WRITE, UNMAP);
VENUM(PhysicalDevGroup, uint8_t, DATA = 0, FAST = 1, META = 2);
ENUM(io_flag, uint8_t,
     BUFFERED_IO, // should be set if file system doesn't support direct IOs and we are working on a file as a
                  // disk. This option is enabled only on in debug build.
     DIRECT_IO,   // recommended mode
     READ_ONLY    // Read-only mode for post-mortem checks
);

struct dev_info {
    explicit dev_info(std::string name, HSDevType type = HSDevType::Data) :
            dev_names{std::move(name)}, dev_type{type} {}
    std::string to_string() const { return fmt::format("{} - {}", dev_names, enum_name(dev_type)); }

    std::string dev_names;
    HSDevType dev_type;
};

////////////// All num constants ///////////////////
const csum_t hs_init_crc_16 = 0x8005;
static constexpr crc32_t init_crc32 = 0x12345678;
static constexpr crc32_t INVALID_CRC32_VALUE = 0x0u;

////////////// Homestore input parameters ///////////////////
static std::string _format_decimals(double val, const char* suffix) {
    return (val != (uint64_t)val) ? fmt::format("{:.2f}{}", val, suffix) : fmt::format("{}{}", val, suffix);
}

static std::string in_bytes(uint64_t sz) {
    static constexpr std::array< std::pair< uint64_t, const char* >, 5 > arr{
        std::make_pair(1, ""), std::make_pair(1024, "kb"), std::make_pair(1048576, "mb"),
        std::make_pair(1073741824, "gb"), std::make_pair(1099511627776, "tb")};

    const double size = (double)sz;
    for (size_t i{1}; i < arr.size(); ++i) {
        if ((size / arr[i].first) < 1) { return _format_decimals(size / arr[i - 1].first, arr[i - 1].second); }
    }
    return _format_decimals(size / arr.back().first, arr.back().second);
}

struct hs_input_params {
public:
    std::vector< dev_info > data_devices; // name of the data devices.
    uuid_t system_uuid;                   // Deprecated. UUID assigned to the system

    io_flag data_open_flags{io_flag::DIRECT_IO}; // All data drives open flags
    io_flag fast_open_flags{io_flag::DIRECT_IO}; // All index drives open flags

    uint64_t app_mem_size{static_cast< uint64_t >(1024) * static_cast< uint64_t >(1024) *
                          static_cast< uint64_t >(1024)}; // memory available for the app (including cache)
    uint64_t hugepage_size{0};                            // memory available for the hugepage
    bool is_read_only{false};                             // Is read only
    bool auto_recovery{true};                             // Recovery of data is automatic or controlled by the caller

#ifdef _PRERELEASE
    bool force_reinit{false};
#endif

    nlohmann::json to_json() const;
    std::string to_string() const { return to_json().dump(4); }
    uint64_t io_mem_size() const { return (hugepage_size != 0) ? hugepage_size : app_mem_size; }
};

struct hs_engine_config {
    uint64_t max_chunks{MAX_CHUNKS}; // These 3 parameters can be ONLY changed with upgrade/revert from device manager
    uint64_t max_vdevs{MAX_VDEVS};
    uint64_t max_pdevs{MAX_PDEVS};
    uint32_t max_blks_in_blkentry{1}; // Max blks a represents in a single BlkId entry

    nlohmann::json to_json() const;
};

#if 0
struct cap_attrs {
    uint64_t used_data_size{0};    // consumer should use this for used data size;
    uint64_t used_index_size{0};   // used size of index mgr store;
    uint64_t used_log_size{0};     // used size of logstore;
    uint64_t used_metablk_size{0}; // used size of meta blk store;
    uint64_t used_total_size{0};   // used total size including data and metadata;
    uint64_t data_capacity{0};     // consumer uses this field to report to host for available user data capacity;
    uint64_t meta_capacity{0};     // Capacity of all other internal structure size (index, metablk, journal)
    std::string to_string() const;
};
#endif

////////////// Misc ///////////////////
#define HOMESTORE_LOG_MODS                                                                                             \
    btree_structures, btree_nodes, btree_generics, cache, device, blkalloc, vol_io_wd, volume, flip, cp, metablk,      \
        indx_mgr, logstore, replay, transient, IOMGR_LOG_MODS

} // namespace homestore
