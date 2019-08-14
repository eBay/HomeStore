#pragma once

#include <sds_logging/logging.h>
#include <spdlog/fmt/fmt.h>
#include <metrics/metrics.hpp>

namespace homestore {
// To Satisfy compiler
struct _dummy_req {
    uint64_t request_id = 0;
};

/* HS Log, Req log, plain log and submod+req logs */
#define HS_REQ_LOG(level, mod, req, msg, ...)                                                                          \
    {                                                                                                                  \
        BOOST_PP_IF(BOOST_PP_IS_EMPTY(req), _dummy_req* r = nullptr, const auto& r = req);                             \
        LOG##level##MOD_FMT(BOOST_PP_IF(BOOST_PP_IS_EMPTY(mod), base, mod),                                            \
                            ([this, r](fmt::memory_buffer& buf, const char* m, auto&&... args) {                       \
                                fmt::format_to(buf, "[{}:{}] ", file_name(__FILE__), __LINE__);                        \
                                if (r)                                                                                 \
                                    fmt::format_to(buf, "[req_id={}] ", r->request_id);                                \
                                fmt::format_to(buf, m, args...);                                                       \
                            }),                                                                                        \
                            msg, ##__VA_ARGS__);                                                                       \
    }
#define HS_LOG(level, mod, msg, ...) HS_REQ_LOG(level, mod, , msg, ##__VA_ARGS__)
#define HS_SUBMOD_LOG(level, mod, req, submod_name, submod_val, msg, ...)                                              \
    {                                                                                                                  \
        BOOST_PP_IF(BOOST_PP_IS_EMPTY(req), _dummy_req* r = nullptr, const auto& r = req);                             \
        LOG##level##MOD_FMT(BOOST_PP_IF(BOOST_PP_IS_EMPTY(mod), base, mod),                                            \
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