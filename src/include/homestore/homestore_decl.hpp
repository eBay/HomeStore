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

//
// Note:
// This file should only include stuffs that are needed by both service layer and internal homestore components;
//

namespace homestore {
using crc32_t = uint32_t;
using csum_t = uint16_t;
using seq_id_t = int64_t;
using uuid_t = boost::uuids::uuid;
using hs_uuid_t = time_t;
using stream_id_t = uint32_t;

template < typename T >
using shared = std::shared_ptr< T >;

template < typename T >
using cshared = const std::shared_ptr< T >;

template < typename T >
using unique = const std::unique_ptr< T >;

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
ENUM(blk_allocator_type_t, uint8_t, none, fixed, varsize, append);
ENUM(chunk_selector_type_t, uint8_t, // What are the options to select chunk to allocate a block
     ROUND_ROBIN,                    // Pick round robin
     CUSTOM,                         // Controlled by the upper layer
     RANDOM,                         // Pick any chunk in uniformly random fashion
     MOST_AVAILABLE_SPACE,           // Pick the most available space
     ALWAYS_CALLER_CONTROLLED        // Expect the caller to always provide the specific chunkid
);

////////////// All structs ///////////////////
struct dev_info {
    explicit dev_info(std::string name, HSDevType type = HSDevType::Data) : dev_name{std::move(name)}, dev_type{type} {}
    std::string to_string() const { return fmt::format("{} - {} size={}", dev_name, enum_name(dev_type), dev_size); }

    std::string dev_name;
    HSDevType dev_type;
    uint64_t dev_size{0};
};

struct stream_info_t {
    uint32_t num_streams = 0;
    uint64_t stream_cur = 0;
    std::vector< stream_id_t > stream_id;
    std::vector< void* > chunk_list;
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

struct HS_SERVICE {
    static constexpr uint32_t META = 1 << 0;
    static constexpr uint32_t LOG_REPLICATED = 1 << 1;
    static constexpr uint32_t LOG_LOCAL = 1 << 2;
    static constexpr uint32_t DATA = 1 << 3;
    static constexpr uint32_t INDEX = 1 << 4;

    uint32_t svcs;

    HS_SERVICE() : svcs{META} {}
    HS_SERVICE(uint32_t val) : svcs{val} {
        svcs |= META; // Force meta to be present always
    }

    std::string list() const {
        std::string str;
        if (svcs & META) { str += "meta,"; }
        if (svcs & DATA) { str += "data,"; }
        if (svcs & INDEX) { str += "index,"; }
        if (svcs & LOG_REPLICATED) { str += "log_replicated,"; }
        if (svcs & LOG_LOCAL) { str += "log_local,"; }
        return str;
    }
};

struct hs_format_params {
    float size_pct;
    uint32_t num_chunks{1};
    blk_allocator_type_t alloc_type{blk_allocator_type_t::varsize};
    chunk_selector_type_t chunk_sel_type{chunk_selector_type_t::ROUND_ROBIN};
};

struct hs_input_params {
public:
    std::vector< dev_info > devices;             // name of the data devices.
    io_flag data_open_flags{io_flag::DIRECT_IO}; // All data drives open flags
    io_flag fast_open_flags{io_flag::DIRECT_IO}; // All index drives open flags

    uint64_t app_mem_size{static_cast< uint64_t >(1024) * static_cast< uint64_t >(1024) *
                          static_cast< uint64_t >(1024)}; // memory available for the app (including cache)
    uint64_t hugepage_size{0};                            // memory available for the hugepage
    bool is_read_only{false};                             // Is read only
    bool auto_recovery{true};                             // Recovery of data is automatic or controlled by the caller
    HS_SERVICE services;                                  // Services homestore is starting with

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
    btree_structures, btree_nodes, btree_generics, btree, cache, device, blkalloc, vol_io_wd, volume, flip, cp,        \
        metablk, indx_mgr, wbcache, logstore, replay, transient, IOMGR_LOG_MODS

} // namespace homestore
