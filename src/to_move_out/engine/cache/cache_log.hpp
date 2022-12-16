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
#pragma once
#include <sisl/metrics/metrics.hpp>
#include <sisl/logging/logging.h>

SISL_LOGGING_DECL(cache, cache_vmod_evict, cache_vmod_read, cache_vmod_write)

namespace homestore {

// Cache logging macros

#define CACHE_LOG(level, mod, fmt, ...)                                                                                \
    LOG##level##MOD(BOOST_PP_IF(BOOST_PP_IS_EMPTY(mod), base, mod), fmt, ##__VA_ARGS__)

#define _CACHE_ASSERT_MSG(asserttype, ...)                                                                             \
    "\n**********************************************************\n"                                                   \
    "\nMetrics = {}\n"                                                                                                 \
    "{}"                                                                                                               \
    "\n**********************************************************\n",                                                  \
        asserttype##_METRICS_DUMP_MSG, sisl::logging::format_log_msg(__VA_ARGS__)

#define CACHE_ASSERT(asserttype, cond, fmt, ...)                                                                       \
    asserttype##_ASSERT(cond, _CACHE_ASSERT_MSG(asserttype, fmt, ##__VA_ARGS__))

#define CACHE_ASSERT_OP(asserttype, optype, val1, val2, ...)                                                           \
    asserttype##_ASSERT_##optype(val1, val2, _CACHE_ASSERT_MSG(asserttype, ##__VA_ARGS__))

#define CACHE_DEBUG_ASSERT(...) CACHE_ASSERT(DEBUG, __VA_ARGS__)
#define CACHE_RELEASE_ASSERT(...) CACHE_ASSERT(RELEASE, __VA_ARGS__)
#define CACHE_LOG_ASSERT(...) CACHE_ASSERT(LOGMSG, __VA_ARGS__)

#define CACHE_DEBUG_ASSERT_CMP(optype, ...) CACHE_ASSERT_OP(DEBUG, optype, ##__VA_ARGS__)
#define CACHE_RELEASE_ASSERT_CMP(optype, ...) CACHE_ASSERT_OP(RELEASE, optype, ##__VA_ARGS__)
#define CACHE_LOG_ASSERT_CMP(optype, ...) CACHE_ASSERT_OP(LOGMSG, optype, ##__VA_ARGS__)
} // namespace homestore
