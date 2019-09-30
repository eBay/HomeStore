#pragma once

#include <sds_logging/logging.h>
#include <spdlog/fmt/fmt.h>
#include <metrics/metrics.hpp>

namespace homestore {
// To Satisfy compiler
struct _dummy_req {
    uint64_t request_id = 0;
};

/***** HomeStore Logging Macro facility: Goal is to provide consistent logging capability
 *
 * HS_LOG: Use this log macro to simply log the message for a given logmod (without any request or other details)
 * Parameters are
 * level: log level to which this message is logged, Possible values are TRACE, DEBUG, INFO, WARN, ERROR, CRITICAL
 * logmod: Log module name. This parameter can be empty (upon which it uses base log module), which is on by default
 * msg: The actual message in fmt style where parameters are mentioned as {}
 * msg_params [optional]: Paramters for the above message if any.
 *
 *
 * HS_REQ_LOG: Use this log macro to log the message along with the request id. It will log of the format:
 * <Timestamp etc..>  [req_id=1234] <Actual message>
 * Parameters are
 * level: log level to which this message is logged, Possible values are TRACE, DEBUG, INFO, WARN, ERROR, CRITICAL
 * logmod: Log module name. This parameter can be empty (upon which it uses base log module), which is on by default
 * req: Request id value to log. It can be empty in which case this macro is exactly same as HS_LOG()
 * msg: The actual message in fmt style where parameters are mentioned as {}
 * msg_params [optional]: Paramters for the above message if any.
 *
 *
 * HS_SUBMOD_LOG: Use this macro to log the message with both request_id and submodule name and value. Log format is:
 * <Timestamp etc..>  [volume=<vol_name>] [req_id=1234] <Actual message>
 * Parameters are
 * level: log level to which this message is logged, Possible values are TRACE, DEBUG, INFO, WARN, ERROR, CRITICAL
 * logmod: Log module name. This parameter can be empty (upon which it uses base log module), which is on by default
 * req: Request id value to log. It can be empty in which it will not print req_id portion of the log
 * submod_name: Submodule name (for example volume or blkalloc or btree etc...)
 * submod_val: Submodule value (for example vol1 or chunk1 or mem_btree_1 etc...)
 * msg: The actual message in fmt style where parameters are mentioned as {}
 * msg_params [optional]: Paramters for the above message if any.
 */
#define HS_REQ_LOG(level, logmod, req, msg, ...)                                                                       \
    {                                                                                                                  \
        BOOST_PP_IF(BOOST_PP_IS_EMPTY(req), _dummy_req* r = nullptr, const auto& r = req);                             \
        LOG##level##MOD_FMT(BOOST_PP_IF(BOOST_PP_IS_EMPTY(logmod), base, logmod),                                      \
                            ([this, r](fmt::memory_buffer& buf, const char* m, auto&&... args) {                       \
                                fmt::format_to(buf, "[{}:{}] ", file_name(__FILE__), __LINE__);                        \
                                if (r)                                                                                 \
                                    fmt::format_to(buf, "[req_id={}] ", r->request_id);                                \
                                fmt::format_to(buf, m, args...);                                                       \
                            }),                                                                                        \
                            msg, ##__VA_ARGS__);                                                                       \
    }
#define HS_LOG(level, logmod, msg, ...) HS_REQ_LOG(level, logmod, , msg, ##__VA_ARGS__)
#define HS_SUBMOD_LOG(level, logmod, req, submod_name, submod_val, msg, ...)                                           \
    {                                                                                                                  \
        BOOST_PP_IF(BOOST_PP_IS_EMPTY(req), _dummy_req* r = nullptr, const auto& r = req);                             \
        LOG##level##MOD_FMT(BOOST_PP_IF(BOOST_PP_IS_EMPTY(logmod), base, logmod),                                      \
                            ([&](fmt::memory_buffer& buf, const char* m, auto&&... args) {                             \
                                fmt::format_to(buf, "[{}:{}] [{}={}] ", file_name(__FILE__), __LINE__, submod_name,    \
                                               submod_val);                                                            \
                                if (r)                                                                                 \
                                    fmt::format_to(buf, "[req_id={}] ", r->request_id);                                \
                                fmt::format_to(buf, m, args...);                                                       \
                            }),                                                                                        \
                            msg, ##__VA_ARGS__);                                                                       \
    }

/* HS Plain Assert and with and without request */
#define HS_REQ_ASSERT(assert_type, cond, req, msg, ...)                                                                \
    assert_type##_ASSERT_FMT(cond,                                                                                     \
                             [&](fmt::memory_buffer& buf, const char* m, auto&&... args) {                             \
                                 hs_assert_formatter(                                                                  \
                                     buf, m, BOOST_PP_IF(BOOST_PP_IS_EMPTY(req), "", req->to_string()), args...);      \
                             },                                                                                        \
                             msg, ##__VA_ARGS__)
#define HS_ASSERT(assert_type, cond, msg, ...) HS_REQ_ASSERT(assert_type, cond, , msg, ##__VA_ARGS__)
#define HS_SUBMOD_ASSERT(assert_type, cond, req, submod_name, submod_val, msg, ...)                                    \
    assert_type##_ASSERT_FMT(cond,                                                                                     \
                             [&](fmt::memory_buffer& buf, const char* m, auto&&... args) {                             \
                                 hs_submod_assert_formatter(buf, m,                                                    \
                                                            BOOST_PP_IF(BOOST_PP_IS_EMPTY(req), "", req->to_string()), \
                                                            submod_name, submod_val, args...);                         \
                             },                                                                                        \
                             msg, ##__VA_ARGS__)

/* HS Compare Assert and with and without request */
#define HS_REQ_ASSERT_CMP(assert_type, val1, cmp, val2, req, ...)                                                      \
    assert_type##_ASSERT_CMP(val1, cmp, val2,                                                                          \
                             [&](fmt::memory_buffer& buf, const char* m, auto&&... args) {                             \
                                 hs_cmp_assert_formatter(                                                              \
                                     buf, m, BOOST_PP_IF(BOOST_PP_IS_EMPTY(req), "", req->to_string()), args...);      \
                             },                                                                                        \
                             ##__VA_ARGS__)
#define HS_ASSERT_CMP(assert_type, val1, cmp, val2, ...)                                                               \
    HS_REQ_ASSERT_CMP(assert_type, val1, cmp, val2, , ##__VA_ARGS__)
#define HS_SUBMOD_ASSERT_CMP(assert_type, val1, cmp, val2, req, submod_name, submod_val, ...)                          \
    assert_type##_ASSERT_CMP(val1, cmp, val2,                                                                          \
                             [&](fmt::memory_buffer& buf, const char* m, auto&&... args) {                             \
                                 hs_submod_cmp_assert_formatter(                                                       \
                                     buf, m, BOOST_PP_IF(BOOST_PP_IS_EMPTY(req), "", req->to_string()), submod_name,   \
                                     submod_val, args...);                                                             \
                             },                                                                                        \
                             ##__VA_ARGS__)

/* Not null assert */
#define HS_REQ_ASSERT_NOTNULL(assert_type, val1, req, ...)                                                             \
    HS_REQ_ASSERT_CMP(assert_type, (void*)val1, !=, (void*)nullptr, req, ##__VA_ARGS__)
#define HS_ASSERT_NOTNULL(assert_type, val1, ...) HS_REQ_ASSERT_NOTNULL(assert_type, val1, , ##__VA_ARGS__)
#define HS_SUBMOD_ASSERT_NOTNULL(assert_type, val1, req, submod_name, submod_val, ...)                                 \
    HS_SUBMOD_ASSERT_CMP(assert_type, (void*)val1, !=, (void*)nullptr, req, submod_name, submod_val, ##__VA_ARGS__)

/* Null assert */
#define HS_REQ_ASSERT_NULL(assert_type, val1, req, ...)                                                                \
    HS_REQ_ASSERT_CMP(assert_type, (void*)val1, ==, (void*)nullptr, req, ##__VA_ARGS__)
#define HS_ASSERT_NULL(assert_type, val1, ...) HS_REQ_ASSERT_NULL(assert_type, val1, , ##__VA_ARGS__)
#define HS_SUBMOD_ASSERT_NULL(assert_type, val1, req, submod_name, submod_val, ...)                                    \
    HS_SUBMOD_ASSERT_CMP(assert_type, (void*)val1, ==, (void*)nullptr, req, submod_name, submod_val, ##__VA_ARGS__)

#if 0
template < typename... Args >
void hs_cmp_assert_formatter(fmt::memory_buffer& buf, const char* msg, const std::string& req_str, const Args&... args);

template < typename... Args >
void hs_assert_formatter(fmt::memory_buffer& buf, const char* msg, const std::string& req_str, const Args&... args);
#endif

template < typename... Args >
void hs_assert_formatter(fmt::memory_buffer& buf, const char* msg, const std::string& req_str, const Args&... args) {
    if (req_str.size()) {
        fmt::format_to(buf, "\n[request={}]", req_str);
    }
    fmt::format_to(buf, "\nMetrics = {}\n", sisl::MetricsFarm::getInstance().get_result_in_json_string());
}

template < typename... Args >
void hs_submod_assert_formatter(fmt::memory_buffer& buf, const char* msg, const std::string& req_str,
                                const char* submod_name, const std::string& submod_val, const Args&... args) {
    fmt::format_to(buf, "\n[{}={}]", submod_name, submod_val);
    hs_assert_formatter(buf, msg, req_str, args...);
}

template < typename... Args >
void hs_cmp_assert_formatter(fmt::memory_buffer& buf, const char* msg, const std::string& req_str,
                             const Args&... args) {
    sds_logging::default_cmp_assert_formatter(buf, msg, args...);
    hs_assert_formatter(buf, msg, req_str, args...);
}

template < typename... Args >
void hs_submod_cmp_assert_formatter(fmt::memory_buffer& buf, const char* msg, const std::string& req_str,
                                    const char* submod_name, const std::string& submod_val, const Args&... args) {
    fmt::format_to(buf, "\n[{}={}]", submod_name, submod_val);
    hs_cmp_assert_formatter(buf, msg, req_str, args...);
}
} // namespace homestore