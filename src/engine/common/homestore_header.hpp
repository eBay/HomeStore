/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 * Author/Developer(s): Harihara Kadayam
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
#ifndef _HOMESTORE_HEADER_HPP_
#define _HOMESTORE_HEADER_HPP_

#include <boost/preprocessor/control/if.hpp>
#include <boost/preprocessor/facilities/empty.hpp>
#include <boost/preprocessor/facilities/identity.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/vmd/is_empty.hpp>
#include <string>
#include <sisl/utility/enum.hpp>

#ifdef _PRERELEASE
#include <sisl/flip/flip.hpp>
#endif
#include <spdlog/fmt/fmt.h>

namespace homeds {
struct blob {
    uint8_t* bytes;
    uint32_t size;
};
} // namespace homeds

namespace homestore {
using hs_uuid_t = time_t;

ENUM(io_flag, uint8_t,
     BUFFERED_IO, // should be set if file system doesn't support direct IOs and we are working on a file as a
                  // disk. This option is enabled only on in debug build.
     DIRECT_IO,   // recommended mode
     READ_ONLY    // Read-only mode for post-mortem checks
);

ENUM(Op_type, uint8_t, READ, WRITE, UNMAP);

VENUM(PhysicalDevGroup, uint8_t, DATA = 0, FAST = 1, META = 2);

ENUM(HSDevType, uint8_t, Data, Fast);

struct dev_info {
    explicit dev_info(std::string name, const HSDevType type = HSDevType::Data) :
            dev_names{std::move(name)}, dev_type{type} {}
    std::string to_string() const { return fmt::format("{} - {}", dev_names, enum_name(dev_type)); }

    std::string dev_names;
    HSDevType dev_type;
};

#define METRICS_DUMP_MSG sisl::MetricsFarm::getInstance().get_result_in_json_string()

#ifndef NDEBUG
#define DEBUG_METRICS_DUMP_FORMAT METRICS_DUMP_FORMAT
#define DEBUG_METRICS_DUMP_MSG METRICS_DUMP_MSG

#define LOGMSG_METRICS_DUMP_FORMAT METRICS_DUMP_FORMAT
#define LOGMSG_METRICS_DUMP_MSG METRICS_DUMP_MSG

#define RELEASE_METRICS_DUMP_FORMAT METRICS_DUMP_FORMAT
#define RELEASE_METRICS_DUMP_MSG METRICS_DUMP_MSG
#else
#define DEBUG_METRICS_DUMP_FORMAT "{}"
#define DEBUG_METRICS_DUMP_MSG "N/A"

#define LOGMSG_METRICS_DUMP_FORMAT "{}"
#define LOGMSG_METRICS_DUMP_MSG "N/A"

#define RELEASE_METRICS_DUMP_FORMAT METRICS_DUMP_FORMAT
#define RELEASE_METRICS_DUMP_MSG METRICS_DUMP_MSG
#endif

#if 0
#define HS_LOG(buf, level, mod, req, f, ...)                                                                             \
    BOOST_PP_IF(BOOST_VMD_IS_EMPTY(req), BOOST_PP_EMPTY,                                                                 \
                BOOST_PP_IDENTITY(fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[req_id={}] "},                  \
                                                  fmt::make_format_args(req->request_id))))                              \
    ();,                       \
    fmt::vformat_to(fmt::appender{buf}, fmt::string_view{f}, fmt::make_format_args(##__VA_ARGS__);                     \
    fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"{}"}, fmt::make_format_args('\0'));                          \                                                                         \
    LOG##level##MOD(BOOST_PP_IF(BOOST_VMD_IS_EMPTY(mod), base, mod)(), "{}", buf.data());
#endif

#define HOMESTORE_LOG_MODS                                                                                             \
    btree_structures, btree_nodes, btree_generics, cache, device, blkalloc, vol_io_wd, volume, flip, cp, metablk,      \
        indx_mgr, logstore, replay, transient, IOMGR_LOG_MODS

template < typename T >
std::string to_hex(T i) {
    return fmt::format("{0:x}", i);
}

typedef uint32_t crc32_t;
typedef uint16_t csum_t;
typedef int64_t seq_id_t;
const csum_t init_crc_16 = 0x8005;

static constexpr crc32_t init_crc32 = 0x12345678;
static constexpr crc32_t INVALID_CRC32_VALUE = 0x0u;
} // namespace homestore
#endif
