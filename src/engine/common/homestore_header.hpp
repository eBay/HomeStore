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
#include <flip/flip.hpp>
#endif
#include <spdlog/fmt/fmt.h>

namespace homeds {
struct blob {
    uint8_t* bytes;
    uint32_t size;
};
} // namespace homeds

namespace homestore {

ENUM(io_flag, uint8_t,
     BUFFERED_IO, // should be set if file system doesn't support direct IOs and we are working on a file as a
                  // disk. This option is enabled only on in debug build.
     DIRECT_IO,   // recommended mode
     READ_ONLY    // Read-only mode for post-mortem checks
);

ENUM(Op_type, uint8_t, READ, WRITE, UNMAP);

struct dev_info {
    typedef enum class Type : uint8_t { Data, Fast } Type;
    explicit dev_info(std::string name, const Type type = Type::Data) : dev_names{std::move(name)}, dev_type{type} {}
    std::string dev_names;
    Type dev_type;
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
#define HS_LOG(buf, level, mod, req, f, ...)                                                                           \
    BOOST_PP_IF(BOOST_VMD_IS_EMPTY(req), BOOST_PP_EMPTY,                                                               \
                BOOST_PP_IDENTITY(fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[req_id={}] "},                \
                                                   fmt::make_format_args(req->request_id))))();,                       \
    fmt::vformat_to(fmt::appender{buf}, fmt::string_view{f}, fmt::make_format_args(##__VA_ARGS__);                     \
    fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"{}"}, fmt::make_format_args('\0'));                          \                                                                         \
    LOG##level##MOD(BOOST_PP_IF(BOOST_VMD_IS_EMPTY(mod), base, mod)(), "{}", buf.data());                              
#endif

#define HOMESTORE_LOG_MODS                                                                                             \
    btree_structures, btree_nodes, btree_generics, cache, device, httpserver_lmod, blkalloc, volume, flip, cp,         \
        metablk, indx_mgr, logstore, replay, transient, IOMGR_LOG_MODS

template < typename T >
std::string to_hex(T i) {
    return fmt::format("{0:x}", i);
}

} // namespace homestore
#endif
