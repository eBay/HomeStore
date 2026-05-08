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

#include <chrono>
#include <cstdint>
#include <functional>
#include <iterator>
#include <string>
#include <string_view>
#include <unordered_map>

#include <boost/preprocessor/control/if.hpp>
#include <boost/preprocessor/facilities/empty.hpp>
#include <boost/preprocessor/facilities/identity.hpp>
#include <boost/vmd/is_empty.hpp>
#include <sisl/fds/utils.hpp>
#include <sisl/metrics/metrics.hpp>
#include <sisl/logging/logging.h>
#include <spdlog/fmt/fmt.h>

// clang-format off
/***** HomeStore Logging Macro facility: Goal is to provide consistent logging capability
 * 
 * HS_LOG: Use this log macro to simply log the message for a given logmod (without any request or other details)
 * Parameters are
 * 1) level: log level to which this message is logged, Possible values are TRACE, DEBUG, INFO, WARN, ERROR, CRITICAL
 * 2) logmod: Log module name. This parameter can be empty (upon which it uses base log module), which is on by default
 * 3) msg: The actual message in fmt style where parameters are mentioned as {}
 * 4) msg_params [optional]: Paramters for the above message if any.
 *
 *
 * HS_REQ_LOG: Use this log macro to log the message along with the request id. It will log of the format:
 * <Timestamp etc..>  [req_id=1234] <Actual message>
 * Parameters are
 * 1) level: log level to which this message is logged, Possible values are TRACE, DEBUG, INFO, WARN, ERROR, CRITICAL
 * 2) logmod: Log module name. This parameter can be empty (upon which it uses base log module), which is on by default
 * 3) req: Request id value to log. It can be empty in which case this macro is exactly same as HS_LOG()
 * 4) msg: The actual message in fmt style where parameters are mentioned as {}
 * 5) msg_params [optional]: Paramters for the above message if any.
 *
 *
 * HS_SUBMOD_LOG: Use this macro to log the message with both request_id and submodule name and value. Log format is:
 * <Timestamp etc..>  [volume=<vol_name>] [req_id=1234] <Actual message>
 * Parameters are
 * 1) level: log level to which this message is logged, Possible values are TRACE, DEBUG, INFO, WARN, ERROR, CRITICAL
 * 2) logmod: Log module name. This parameter can be empty (upon which it uses base log module), which is on by default
 * 3) req: Request id value to log. It can be empty in which it will not print req_id portion of the log
 * 4) submod_name: Submodule name (for example volume or blkalloc or btree etc...)
 * 5) submod_val: Submodule value (for example vol1 or chunk1 or mem_btree_1 etc...)
 * 6) msg: The actual message in fmt style where parameters are mentioned as {}
 * 7) msg_params [optional]: Paramters for the above message if any.
 *
 * HS_DETAILED_LOG: Use this macro to log the message with request_id, submodule name/value and any additional info.
 * Log format is:
 * <Timestamp etc..>  [btree=<btree_name>] [req_id=1234] [node=<node_contents>] <Actual message>
 * Parameters are
 * 1) level: log level to which this message is logged, Possible values are TRACE, DEBUG, INFO, WARN, ERROR, CRITICAL
 * 2) logmod: Log module name. This parameter can be empty (upon which it uses base log module), which is on by default
 * 3) req: Request id value to log. It can be empty in which it will not print req_id portion of the log
 * 4) submod_name: Submodule name (for example volume or btree etc...). It can be empty in which case no modname/value
 *                 is added.
 * 5) submod_val: Submodule value (for example vol1 or mem_btree_1 etc...). It can be empty in which case no
 *                modname/value is added.
 * 6) detail_name: Name of the additional details, (example: node)
 * 7) detail_value: Additional value (example: node contents in string)
 * 8) msg: The actual message in fmt style where parameters are mentioned as {}
 * 9) msg_params [optional]: Paramters for the above message if any.
 */
// clang-format on
#define HS_PERIODIC_DETAILED_LOG(level, mod, submod_name, submod_val, detail_name, detail_val, msg, ...)               \
    {                                                                                                                  \
        LOG##level##MOD_FMT_USING_LOGGER(                                                                              \
            BOOST_PP_IF(BOOST_VMD_IS_EMPTY(mod), base, mod),                                                           \
            ([&](fmt::memory_buffer& buf, const char* const msgcb, auto&&... args) -> bool {                           \
                fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}:{}] "},                                      \
                                fmt::make_format_args(unmove(file_name(__FILE__)), unmove(__LINE__)));                 \
                BOOST_PP_IF(BOOST_VMD_IS_EMPTY(submod_name), BOOST_PP_EMPTY,                                           \
                            BOOST_PP_IDENTITY(fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}={}] "},        \
                                                              fmt::make_format_args(submod_name, submod_val))))        \
                ();                                                                                                    \
                BOOST_PP_IF(BOOST_VMD_IS_EMPTY(detail_name), BOOST_PP_EMPTY,                                           \
                            BOOST_PP_IDENTITY(fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}={}] "},        \
                                                              fmt::make_format_args(detail_name, detail_val))))        \
                ();                                                                                                    \
                fmt::vformat_to(fmt::appender{buf}, fmt::string_view{msgcb}, fmt::make_format_args(args...));          \
                return true;                                                                                           \
            }),                                                                                                        \
            homestore::HomeStore::periodic_logger(), msg, ##__VA_ARGS__);                                              \
    }
#define HS_PERIODIC_LOG(level, mod, msg, ...) HS_PERIODIC_DETAILED_LOG(level, mod, , , , , msg, ##__VA_ARGS__)

#define HS_DETAILED_LOG(level, mod, req, submod_name, submod_val, detail_name, detail_val, msg, ...)                   \
    {                                                                                                                  \
        LOG##level##MOD_FMT(                                                                                           \
            BOOST_PP_IF(BOOST_VMD_IS_EMPTY(mod), base, mod),                                                           \
            ([&](fmt::memory_buffer& buf, const char* const msgcb, auto&&... args) -> bool {                           \
                fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}:{}] "},                                      \
                                fmt::make_format_args(unmove(file_name(__FILE__)), unmove(__LINE__)));                 \
                BOOST_PP_IF(BOOST_VMD_IS_EMPTY(submod_name), BOOST_PP_EMPTY,                                           \
                            BOOST_PP_IDENTITY(fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}={}] "},        \
                                                              fmt::make_format_args(submod_name, submod_val))))        \
                ();                                                                                                    \
                BOOST_PP_IF(BOOST_VMD_IS_EMPTY(req), BOOST_PP_EMPTY,                                                   \
                            BOOST_PP_IDENTITY(fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[req_id={}] "},    \
                                                              fmt::make_format_args(req->request_id))))                \
                ();                                                                                                    \
                BOOST_PP_IF(BOOST_VMD_IS_EMPTY(detail_name), BOOST_PP_EMPTY,                                           \
                            BOOST_PP_IDENTITY(fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}={}] "},        \
                                                              fmt::make_format_args(detail_name, detail_val))))        \
                ();                                                                                                    \
                fmt::vformat_to(fmt::appender{buf}, fmt::string_view{msgcb}, fmt::make_format_args(args...));          \
                return true;                                                                                           \
            }),                                                                                                        \
            msg, ##__VA_ARGS__);                                                                                       \
    }

#define HS_DETAILED_LOG_EVERY_N(level, mod, freq, submod_name, submod_val, detail_name, detail_val, msg, ...)          \
    {                                                                                                                  \
        LOG##level##MOD_FMT(                                                                                           \
            BOOST_PP_IF(BOOST_VMD_IS_EMPTY(mod), base, mod),                                                           \
            ([&](fmt::memory_buffer& buf, const char* const msgcb, auto&&... args) -> bool {                           \
                fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}:{}] "},                                      \
                                fmt::make_format_args(unmove(file_name(__FILE__)), unmove(__LINE__)));                 \
                BOOST_PP_IF(BOOST_VMD_IS_EMPTY(submod_name), BOOST_PP_EMPTY,                                           \
                            BOOST_PP_IDENTITY(fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}={}] "},        \
                                                              fmt::make_format_args(submod_name, submod_val))))        \
                ();                                                                                                    \
                BOOST_PP_IF(BOOST_VMD_IS_EMPTY(detail_name), BOOST_PP_EMPTY,                                           \
                            BOOST_PP_IDENTITY(fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}={}] "},        \
                                                              fmt::make_format_args(detail_name, detail_val))))        \
                ();                                                                                                    \
                fmt::vformat_to(fmt::appender{buf}, fmt::string_view{msgcb}, fmt::make_format_args(args...));          \
                return check_and_format_log(buf, freq, 0);                                                                                          \
            }),                                                                                                        \
            msg, ##__VA_ARGS__);                                                                                       \
    }

#define HS_LOG_EVERY_N(level, mod, freq, msg, ...) HS_DETAILED_LOG_EVERY_N(level, mod, freq, , , , , msg, ##__VA_ARGS__)

#define HS_DETAILED_LOG_EVERY_N_SEC(level, mod, interval_sec, submod_name, submod_val, detail_name, detail_val, msg,   \
                                     ...)                                                                              \
    {                                                                                                                  \
        LOG##level##MOD_FMT(                                                                                           \
            BOOST_PP_IF(BOOST_VMD_IS_EMPTY(mod), base, mod),                                                           \
            ([&](fmt::memory_buffer& buf, const char* const msgcb, auto&&... args) -> bool {                           \
                fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}:{}] "},                                      \
                                fmt::make_format_args(unmove(file_name(__FILE__)), unmove(__LINE__)));                 \
                BOOST_PP_IF(BOOST_VMD_IS_EMPTY(submod_name), BOOST_PP_EMPTY,                                           \
                            BOOST_PP_IDENTITY(fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}={}] "},        \
                                                              fmt::make_format_args(submod_name, submod_val))))        \
                ();                                                                                                    \
                BOOST_PP_IF(BOOST_VMD_IS_EMPTY(detail_name), BOOST_PP_EMPTY,                                           \
                            BOOST_PP_IDENTITY(fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}={}] "},        \
                                                              fmt::make_format_args(detail_name, detail_val))))        \
                ();                                                                                                    \
                fmt::vformat_to(fmt::appender{buf}, fmt::string_view{msgcb}, fmt::make_format_args(args...));          \
                return check_and_format_log(buf, 0, interval_sec);                                                                                          \
            }),                                                                                                        \
            msg, ##__VA_ARGS__);                                                                                       \
    }

#define HS_LOG_EVERY_N_SEC(level, mod, interval_sec, msg, ...)                                                         \
    HS_DETAILED_LOG_EVERY_N_SEC(level, mod, interval_sec, , , , , msg, ##__VA_ARGS__)

#define HS_DETAILED_LOG_EVERY_N_OR_SEC(level, mod, freq, interval_sec, submod_name, submod_val, detail_name,          \
                                        detail_val, msg, ...)                                                          \
    {                                                                                                                  \
        LOG##level##MOD_FMT(                                                                                           \
            BOOST_PP_IF(BOOST_VMD_IS_EMPTY(mod), base, mod),                                                           \
            ([&](fmt::memory_buffer& buf, const char* const msgcb, auto&&... args) -> bool {                           \
                fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}:{}] "},                                      \
                                fmt::make_format_args(unmove(file_name(__FILE__)), unmove(__LINE__)));                 \
                BOOST_PP_IF(BOOST_VMD_IS_EMPTY(submod_name), BOOST_PP_EMPTY,                                           \
                            BOOST_PP_IDENTITY(fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}={}] "},        \
                                                              fmt::make_format_args(submod_name, submod_val))))        \
                ();                                                                                                    \
                BOOST_PP_IF(BOOST_VMD_IS_EMPTY(detail_name), BOOST_PP_EMPTY,                                           \
                            BOOST_PP_IDENTITY(fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}={}] "},        \
                                                              fmt::make_format_args(detail_name, detail_val))))        \
                ();                                                                                                    \
                fmt::vformat_to(fmt::appender{buf}, fmt::string_view{msgcb}, fmt::make_format_args(args...));          \
                return check_and_format_log(buf, freq, interval_sec);                                                                                          \
            }),                                                                                                        \
            msg, ##__VA_ARGS__);                                                                                       \
    }

#define HS_LOG_EVERY_N_OR_SEC(level, mod, freq, interval_sec, msg, ...)                                                \
    HS_DETAILED_LOG_EVERY_N_OR_SEC(level, mod, freq, interval_sec, , , , , msg, ##__VA_ARGS__)

#define HS_SUBMOD_LOG(level, mod, req, submod_name, submod_val, msg, ...)                                              \
    HS_DETAILED_LOG(level, mod, req, submod_name, submod_val, , , msg, ##__VA_ARGS__)
#define HS_REQ_LOG(level, mod, req, msg, ...) HS_SUBMOD_LOG(level, mod, req, , , msg, ##__VA_ARGS__)
#define HS_LOG(level, mod, msg, ...) HS_REQ_LOG(level, mod, , msg, ##__VA_ARGS__)

// clang-format off
/***** HomeStore Assert Macro facility: Goal is to provide consistent assert and gather crucial information
 *
 * HS_DETAILED_ASSERT: Use this macro to assert and also print the request_id, submodule name/value and any additional
 * info.
 * Example Assertlog format:
 * [btree=<btree_name>] [req_id=1234] [node=<node_contents>] [Metrics=<Metrics to diagnose>] <Actual message>
 *
 * Parameters are
 * 1) assert_type: Behavior in case asserting condition is not met. One of the following 3 types
 *   a) DEBUG - Prints the log and crashes the application (with stack trace) in debug build. In release build it is compiled out. 
 *   b) LOGMSG - Same behavior as DEBUG in debug build. In release build, it logs the message along with stack trace and moves on (no crashing) 
 *   c) RELEASE - Prints the log and crashes the application (with stack trace) on all build
 * 2) cond: Condition to validate. If result in false, program will behave as per the assert_type
 * 3) req: Request string for this assert. It can be empty in which it will not print req_id portion of the log
 * 4) submod_name: Submodule name (for example volume or btree etc...). It can be empty in which case no modname/value
 *                 is added.
 * 5) submod_val: Submodule value (for example vol1 or mem_btree_1 etc...). It can be empty in which case no
 *                modname/value is added.
 * 6) detail_name: Name of the additional details, (example: node)
 * 7) detail_value: Additional value (example: node contents in string)
 * 8) msg: The actual message in fmt style where parameters are mentioned as {}
 * 9) msg_params [optional]: Paramters for the above message if any.
 * 
 * HS_SUBMOD_ASSERT is similar to HS_DETAILED_ASSERT, except that detail_name and detail_value is not present.
 * HS_REQ_ASSERT is similar to HS_DETAILED_ASSERT, except that both detail name/value and submodule name/value is not present.
 * HS_ASSERT is barebone version of HS_DETAILED_ASSERT, where no request, submodule and details name/value is present. 
 */
// clang-format on

// No need of metrics dump in debug build
#ifdef DEBUG
#define HS_ASSERT_METRICS(buf)                                                                                         \
    fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"\n[Metrics = {}]\n"},                                        \
                    fmt::make_format_args(sisl::MetricsFarm::getInstance().get_result_in_json().dump(4)));
#else
#define HS_ASSERT_METRICS(buf)
#endif

#define HS_DETAILED_ASSERT(assert_type, cond, req, submod_name, submod_val, detail_name, detail_val, msg, ...)         \
    {                                                                                                                  \
        assert_type(                                                                                                   \
            cond, ([&](fmt::memory_buffer& buf, const char* const msgcb, auto&&... args) -> bool {                     \
                BOOST_PP_IF(BOOST_VMD_IS_EMPTY(submod_name), BOOST_PP_EMPTY,                                           \
                            BOOST_PP_IDENTITY(fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"\n[{}={}] "},      \
                                                              fmt::make_format_args(submod_name, submod_val))))        \
                ();                                                                                                    \
                BOOST_PP_IF(BOOST_VMD_IS_EMPTY(req), BOOST_PP_EMPTY,                                                   \
                            BOOST_PP_IDENTITY(fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"\n[request={}] "}, \
                                                              fmt::make_format_args(req->to_string()))))               \
                ();                                                                                                    \
                BOOST_PP_IF(BOOST_VMD_IS_EMPTY(detail_name), BOOST_PP_EMPTY,                                           \
                            BOOST_PP_IDENTITY(fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"\n[{}={}] "},      \
                                                              fmt::make_format_args(detail_name, detail_val))))        \
                ();                                                                                                    \
                HS_ASSERT_METRICS(buf)                                                                                 \
                fmt::vformat_to(fmt::appender{buf}, fmt::string_view{msgcb}, fmt::make_format_args(args...));          \
                return true;                                                                                           \
            }),                                                                                                        \
            msg, ##__VA_ARGS__);                                                                                       \
    }

#define HS_SUBMOD_ASSERT(assert_type, cond, req, submod_name, submod_val, msg, ...)                                    \
    HS_DETAILED_ASSERT(assert_type, cond, req, submod_name, submod_val, , , msg, ##__VA_ARGS__)
#define HS_REQ_ASSERT(assert_type, cond, req, msg, ...) HS_SUBMOD_ASSERT(assert_type, cond, req, , , msg, ##__VA_ARGS__)
#define HS_ASSERT(assert_type, cond, msg, ...) HS_REQ_ASSERT(assert_type, cond, , msg, ##__VA_ARGS__)

#define HS_DETAILED_ASSERT_CMP(assert_type, val1, cmp, val2, req, submod_name, submod_val, detail_name, detail_val,    \
                               ...)                                                                                    \
    {                                                                                                                  \
        assert_type(                                                                                                   \
            val1, cmp, val2,                                                                                           \
            [&](fmt::memory_buffer& buf, const char* const msgcb, auto&&... args) -> bool {                            \
                fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}:{}] "},                                      \
                                fmt::make_format_args(unmove(file_name(__FILE__)), unmove(__LINE__)));                 \
                sisl::logging::default_cmp_assert_formatter(buf, msgcb, args...);                                      \
                BOOST_PP_IF(BOOST_VMD_IS_EMPTY(submod_name), BOOST_PP_EMPTY,                                           \
                            BOOST_PP_IDENTITY(fmt::vformat_to(fmt::appender{buf}, fmt::string_view{" \n[{}={}] "},     \
                                                              fmt::make_format_args(submod_name, submod_val))))        \
                ();                                                                                                    \
                BOOST_PP_IF(BOOST_VMD_IS_EMPTY(req), BOOST_PP_EMPTY,                                                   \
                            BOOST_PP_IDENTITY(fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"\n[request={}] "}, \
                                                              fmt::make_format_args(req->to_string()))))               \
                ();                                                                                                    \
                BOOST_PP_IF(BOOST_VMD_IS_EMPTY(detail_name), BOOST_PP_EMPTY,                                           \
                            BOOST_PP_IDENTITY(fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"\n[{}={}] "},      \
                                                              fmt::make_format_args(detail_name, detail_val))))        \
                ();                                                                                                    \
                HS_ASSERT_METRICS(buf)                                                                                 \
                return true;                                                                                           \
            },                                                                                                         \
            ##__VA_ARGS__);                                                                                            \
    }

#define HS_SUBMOD_ASSERT_CMP(assert_type, val1, cmp, val2, req, submod_name, submod_val, ...)                          \
    HS_DETAILED_ASSERT_CMP(assert_type, val1, cmp, val2, req, submod_name, submod_val, , , ##__VA_ARGS__)
#define HS_REQ_ASSERT_CMP(assert_type, val1, cmp, val2, req, ...)                                                      \
    HS_SUBMOD_ASSERT_CMP(assert_type, val1, cmp, val2, req, , , ##__VA_ARGS__)
#define HS_ASSERT_CMP(assert_type, val1, cmp, val2, ...)                                                               \
    HS_REQ_ASSERT_CMP(assert_type, val1, cmp, val2, , ##__VA_ARGS__)

/* Not null assert */
#define HS_REQ_ASSERT_NOTNULL(assert_type, val1, req, ...)                                                             \
    HS_REQ_ASSERT_CMP(assert_type, static_cast< const void* >(val1), !=, nullptr, req, ##__VA_ARGS__)
#define HS_ASSERT_NOTNULL(assert_type, val1, ...) HS_REQ_ASSERT_NOTNULL(assert_type, val1, , ##__VA_ARGS__)
#define HS_SUBMOD_ASSERT_NOTNULL(assert_type, val1, req, submod_name, submod_val, ...)                                 \
    HS_SUBMOD_ASSERT_CMP(assert_type, static_cast< const void* >(val1) !=, nullptr, req, submod_name, submod_val,      \
                         ##__VA_ARGS__)

/* Null assert */
#define HS_REQ_ASSERT_NULL(assert_type, val1, req, ...)                                                                \
    HS_REQ_ASSERT_CMP(assert_type, static_cast< const void* >(val1), ==, nullptr, req, ##__VA_ARGS__)
#define HS_ASSERT_NULL(assert_type, val1, ...) HS_REQ_ASSERT_NULL(assert_type, val1, , ##__VA_ARGS__)
#define HS_SUBMOD_ASSERT_NULL(assert_type, val1, req, submod_name, submod_val, ...)                                    \
    HS_SUBMOD_ASSERT_CMP(assert_type, static_cast< const void* >(val1), ==, nullptr, req, submod_name, submod_val,     \
                         ##__VA_ARGS__)

#define HS_DBG_ASSERT(cond, ...) HS_ASSERT(DEBUG_ASSERT_FMT, cond, ##__VA_ARGS__)
#define HS_DBG_ASSERT_EQ(val1, val2, ...) HS_ASSERT_CMP(DEBUG_ASSERT_CMP, val1, ==, val2, ##__VA_ARGS__)
#define HS_DBG_ASSERT_NE(val1, val2, ...) HS_ASSERT_CMP(DEBUG_ASSERT_CMP, val1, !=, val2, ##__VA_ARGS__)
#define HS_DBG_ASSERT_LT(val1, val2, ...) HS_ASSERT_CMP(DEBUG_ASSERT_CMP, val1, <, val2, ##__VA_ARGS__)
#define HS_DBG_ASSERT_LE(val1, val2, ...) HS_ASSERT_CMP(DEBUG_ASSERT_CMP, val1, <=, val2, ##__VA_ARGS__)
#define HS_DBG_ASSERT_GT(val1, val2, ...) HS_ASSERT_CMP(DEBUG_ASSERT_CMP, val1, >, val2, ##__VA_ARGS__)
#define HS_DBG_ASSERT_GE(val1, val2, ...) HS_ASSERT_CMP(DEBUG_ASSERT_CMP, val1, >=, val2, ##__VA_ARGS__)
#define HS_DBG_ASSERT_NULL(val, ...) HS_ASSERT_NULL(DEBUG_ASSERT_CMP, val, ##__VA_ARGS__)
#define HS_DBG_ASSERT_NOTNULL(val, ...) HS_ASSERT_NOTNULL(DEBUG_ASSERT_CMP, val, ##__VA_ARGS__)

#define HS_LOG_ASSERT(cond, ...) HS_ASSERT(LOGMSG_ASSERT_FMT, cond, ##__VA_ARGS__)
#define HS_LOG_ASSERT_EQ(val1, val2, ...) HS_ASSERT_CMP(LOGMSG_ASSERT_CMP, val1, ==, val2, ##__VA_ARGS__)
#define HS_LOG_ASSERT_NE(val1, val2, ...) HS_ASSERT_CMP(LOGMSG_ASSERT_CMP, val1, !=, val2, ##__VA_ARGS__)
#define HS_LOG_ASSERT_LT(val1, val2, ...) HS_ASSERT_CMP(LOGMSG_ASSERT_CMP, val1, <, val2, ##__VA_ARGS__)
#define HS_LOG_ASSERT_LE(val1, val2, ...) HS_ASSERT_CMP(LOGMSG_ASSERT_CMP, val1, <=, val2, ##__VA_ARGS__)
#define HS_LOG_ASSERT_GT(val1, val2, ...) HS_ASSERT_CMP(LOGMSG_ASSERT_CMP, val1, >, val2, ##__VA_ARGS__)
#define HS_LOG_ASSERT_GE(val1, val2, ...) HS_ASSERT_CMP(LOGMSG_ASSERT_CMP, val1, >=, val2, ##__VA_ARGS__)
#define HS_LOG_ASSERT_NULL(val, ...) HS_ASSERT_NULL(LOGMSG_ASSERT_CMP, val, ##__VA_ARGS__)
#define HS_LOG_ASSERT_NOTNULL(val, ...) HS_ASSERT_NOTNULL(LOGMSG_ASSERT_CMP, val, ##__VA_ARGS__)

#define HS_REL_ASSERT(cond, ...) HS_ASSERT(RELEASE_ASSERT_FMT, cond, ##__VA_ARGS__)
#define HS_REL_ASSERT_EQ(val1, val2, ...) HS_ASSERT_CMP(RELEASE_ASSERT_CMP, val1, ==, val2, ##__VA_ARGS__)
#define HS_REL_ASSERT_NE(val1, val2, ...) HS_ASSERT_CMP(RELEASE_ASSERT_CMP, val1, !=, val2, ##__VA_ARGS__)
#define HS_REL_ASSERT_LT(val1, val2, ...) HS_ASSERT_CMP(RELEASE_ASSERT_CMP, val1, <, val2, ##__VA_ARGS__)
#define HS_REL_ASSERT_LE(val1, val2, ...) HS_ASSERT_CMP(RELEASE_ASSERT_CMP, val1, <=, val2, ##__VA_ARGS__)
#define HS_REL_ASSERT_GT(val1, val2, ...) HS_ASSERT_CMP(RELEASE_ASSERT_CMP, val1, >, val2, ##__VA_ARGS__)
#define HS_REL_ASSERT_GE(val1, val2, ...) HS_ASSERT_CMP(RELEASE_ASSERT_CMP, val1, >=, val2, ##__VA_ARGS__)
#define HS_REL_ASSERT_NULL(val, ...) HS_ASSERT_NULL(RELEASE_ASSERT_CMP, val, ##__VA_ARGS__)
#define HS_REL_ASSERT_NOTNULL(val, ...) HS_ASSERT_NOTNULL(RELEASE_ASSERT_CMP, val, ##__VA_ARGS__)

/**
 * Rate-limited logging helper with count-based and time-based controls.
 *
 * State is cleaned up every 300 seconds to prevent unbounded memory growth.
 * This means time-based rate limiting works correctly only when interval_sec < 300.
 * If interval_sec >= 300, the behavior effectively becomes "log first occurrence after each 5min reset."
 */
[[maybe_unused]] static bool check_and_format_log(fmt::memory_buffer& buf, uint64_t freq = 0,
                                                    uint64_t interval_sec = 0) {
    static constexpr uint64_t COUNTER_RESET_SEC{300}; // Reset every 5 minutes
    static thread_local Clock::time_point last_cleanup{Clock::now()};
    static thread_local std::unordered_map< size_t, std::pair< uint32_t, uint64_t > > log_map{};
    // hash -> (last_log_ms, count)

    // Warn once if interval_sec exceeds cleanup period
    if (interval_sec > COUNTER_RESET_SEC) {
        static thread_local bool warned = false;
        if (!warned) {
            LOGWARN("interval_sec={} exceeds cleanup period ({}s) - time-based rate limiting may not work as expected",
                    interval_sec, COUNTER_RESET_SEC);
            warned = true;
        }
    }

    const auto now = Clock::now();
    if (get_elapsed_time_sec(last_cleanup) > COUNTER_RESET_SEC) {
        std::unordered_map< size_t, std::pair< uint32_t, uint64_t > >().swap(log_map); // Actually release memory
        last_cleanup = now;
    }

    // Hash the buffer content BEFORE appending any suffix
    const std::string_view msg{buf.data(), buf.size()};
    const size_t msg_hash = std::hash< std::string_view >{}(msg);

    // Milliseconds since last cleanup (max ~49 days with uint32_t)
    const uint32_t now_ms =
        std::chrono::duration_cast< std::chrono::milliseconds >(now - last_cleanup).count();

    auto [it, happened] = log_map.emplace(msg_hash, std::make_pair(now_ms, 0));
    uint32_t elapsed_ms = 0;
    uint64_t count = 0;

    if (!happened) {
        // Entry exists - increment count and calculate elapsed time
        elapsed_ms = now_ms - it->second.first; // Time since last log emission
        it->second.second++;                    // Increment count
        count = it->second.second;
    }

    // Decide if we should log
    bool should_log = false;
    if (happened) {
        // Always log first occurrence (new entry)
        should_log = true;
    } else if (freq == 0 && interval_sec == 0) {
        // Both rate limiters disabled: always log (fallback behavior)
        should_log = true;
    } else if (freq > 0 && count % freq == 0) {
        // Count-based: log every Nth occurrence
        should_log = true;
    } else if (interval_sec > 0 && elapsed_ms >= static_cast< uint32_t >(interval_sec) * 1000) {
        // Time-based: log if enough time has passed since last emission
        should_log = true;
    }

    // If logging, update timestamp and append suffix
    if (should_log) {
        // Append formatted suffix if not first occurrence
        if (!happened && count > 0) {
            // Always show elapsed time and count since last log
            fmt::vformat_to(fmt::appender{buf}, fmt::string_view{" ...Last logged {}ms ago, {} occurrences"},
                            fmt::make_format_args(elapsed_ms, count));
        }

        // Update state after logging (so next log shows "since this log")
        if (!happened) {
            it->second.first = now_ms;  // Update timestamp
            it->second.second = 0;      // Reset count (next occurrence will be "1 since this log")
        }
    }

    return should_log;
}
