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
                                fmt::make_format_args(file_name(__FILE__), __LINE__));                                 \
                BOOST_PP_IF(BOOST_VMD_IS_EMPTY(submod_name), BOOST_PP_EMPTY,                                           \
                            BOOST_PP_IDENTITY(fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}={}] "},        \
                                                              fmt::make_format_args(submod_name, submod_val))))        \
                ();                                                                                                    \
                BOOST_PP_IF(BOOST_VMD_IS_EMPTY(detail_name), BOOST_PP_EMPTY,                                           \
                            BOOST_PP_IDENTITY(fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}={}] "},        \
                                                              fmt::make_format_args(detail_name, detail_val))))        \
                ();                                                                                                    \
                fmt::vformat_to(fmt::appender{buf}, fmt::string_view{msgcb},                                           \
                                fmt::make_format_args(std::forward< decltype(args) >(args)...));                       \
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
                                fmt::make_format_args(file_name(__FILE__), __LINE__));                                 \
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
                fmt::vformat_to(fmt::appender{buf}, fmt::string_view{msgcb},                                           \
                                fmt::make_format_args(std::forward< decltype(args) >(args)...));                       \
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
                                fmt::make_format_args(file_name(__FILE__), __LINE__));                                 \
                BOOST_PP_IF(BOOST_VMD_IS_EMPTY(submod_name), BOOST_PP_EMPTY,                                           \
                            BOOST_PP_IDENTITY(fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}={}] "},        \
                                                              fmt::make_format_args(submod_name, submod_val))))        \
                ();                                                                                                    \
                BOOST_PP_IF(BOOST_VMD_IS_EMPTY(detail_name), BOOST_PP_EMPTY,                                           \
                            BOOST_PP_IDENTITY(fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}={}] "},        \
                                                              fmt::make_format_args(detail_name, detail_val))))        \
                ();                                                                                                    \
                fmt::vformat_to(fmt::appender{buf}, fmt::string_view{msgcb},                                           \
                                fmt::make_format_args(std::forward< decltype(args) >(args)...));                       \
                const auto count{check_logged_already(buf)};                                                           \
                if (count % freq == 0) {                                                                               \
                    if (count) {                                                                                       \
                        fmt::vformat_to(fmt::appender{buf}, fmt::string_view{" ...Repeated {} times in this thread"},  \
                                        fmt::make_format_args(freq));                                                  \
                    }                                                                                                  \
                    return true;                                                                                       \
                }                                                                                                      \
                return false;                                                                                          \
            }),                                                                                                        \
            msg, ##__VA_ARGS__);                                                                                       \
    }

#define HS_LOG_EVERY_N(level, mod, freq, msg, ...) HS_DETAILED_LOG_EVERY_N(level, mod, freq, , , , , msg, ##__VA_ARGS__)

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
                fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"\n[Metrics = {}]\n"},                            \
                                fmt::make_format_args(sisl::MetricsFarm::getInstance().get_result_in_json().dump(4))); \
                fmt::vformat_to(fmt::appender{buf}, fmt::string_view{msgcb},                                           \
                                fmt::make_format_args(std::forward< decltype(args) >(args)...));                       \
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
                                fmt::make_format_args(file_name(__FILE__), __LINE__));                                 \
                sisl::logging::default_cmp_assert_formatter(buf, msgcb, std::forward< decltype(args) >(args)...);      \
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
                fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"\n[Metrics = {}]\n"},                            \
                                fmt::make_format_args(sisl::MetricsFarm::getInstance().get_result_in_json().dump(4))); \
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

[[maybe_unused]] static uint64_t check_logged_already(const fmt::memory_buffer& buf) {
    static constexpr uint64_t COUNTER_RESET_SEC{300}; // Reset every 5 minutes
    static thread_local std::unordered_map< std::string, std::pair< Clock::time_point, uint64_t > > log_map{};

    const std::string_view msg{buf.data()};
    auto [it, happened] = log_map.emplace(msg, std::make_pair(Clock::now(), 0));
    HS_REL_ASSERT(it != std::cend(log_map), "Expected entry to be either present or new insertion to succeed");
    auto& [tm, count] = it->second;
    count = (get_elapsed_time_sec(tm) > COUNTER_RESET_SEC) ? static_cast< decltype(count) >(0) : count + 1;
    tm = Clock::now();
    return count;
}
