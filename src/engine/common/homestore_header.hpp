#ifndef _HOMESTORE_HEADER_HPP_
#define _HOMESTORE_HEADER_HPP_

#include <boost/uuid/uuid.hpp>
#include <string>
#include <utility/enum.hpp>

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
    std::string dev_names;
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
    BOOST_PP_IF(BOOST_PP_IS_EMPTY(req), , fmt::format_to(_log_buf, "[req_id={}] ", req->request_id));                  \
    fmt::format_to(_log_buf, f, ##__VA_ARGS__);                                                                        \
    fmt::format_to(_log_buf, "{}", (char)0);                                                                           \
    LOG##level##MOD(BOOST_PP_IF(BOOST_PP_IS_EMPTY(mod), base, mod), "{}", _log_buf.data());
#endif

#define HOMESTORE_LOG_MODS                                                                                             \
    btree_structures, btree_nodes, btree_generics, cache, device, httpserver_lmod, blkalloc, volume, flip, cp,         \
        metablk, indx_mgr, logstore, transient, IOMGR_LOG_MODS

template < typename T >
std::string to_hex(T i) {
    return fmt::format("{0:x}", i);
}

#define NULL_LAMBDA [](auto... x) {}

} // namespace homestore
#endif
