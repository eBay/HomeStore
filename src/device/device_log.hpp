#pragma once
#include <metrics/metrics.hpp>
#include <sds_logging/logging.h>

namespace homestore {

// Device logging macros

#define DEV_LOG(level, mod, fmt, ...)                                                                             \
    LOG##level##MOD(BOOST_PP_IF(BOOST_PP_IS_EMPTY(mod), base, mod),                                                    \
                    fmt,                                                                                   \
                    ##__VA_ARGS__)

#define _DEV_ASSERT_MSG(asserttype, ...) \
        "\n**********************************************************\n"                                               \
        "\nMetrics = {}\n" "{}"   \
        "\n**********************************************************\n",                                              \
        asserttype##_METRICS_DUMP_MSG,                                                                                 \
        sds_logging::format_log_msg(__VA_ARGS__)

#define DEV_ASSERT(asserttype, cond, fmt, ...)                                                                    \
        asserttype##_ASSERT(cond, _DEV_ASSERT_MSG(asserttype, fmt, ##__VA_ARGS__))

#define DEV_ASSERT_OP(asserttype, optype, val1, val2, ...)                                                        \
        asserttype##_ASSERT_##optype(val1, val2, _DEV_ASSERT_MSG(asserttype, ##__VA_ARGS__))

#define DEV_DEBUG_ASSERT(...) DEV_ASSERT(DEBUG, __VA_ARGS__)
#define DEV_RELEASE_ASSERT(...) DEV_ASSERT(RELEASE, __VA_ARGS__)
#define DEV_LOG_ASSERT(...) DEV_ASSERT(LOGMSG, __VA_ARGS__)

#define DEV_DEBUG_ASSERT_CMP(optype, ...) DEV_ASSERT_OP(DEBUG, optype, ##__VA_ARGS__)
#define DEV_RELEASE_ASSERT_CMP(optype, ...) DEV_ASSERT_OP(RELEASE, optype, ##__VA_ARGS__)
#define DEV_LOG_ASSERT_CMP(optype, ...) DEV_ASSERT_OP(LOGMSG, optype, ##__VA_ARGS__)
}
