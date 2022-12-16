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

#include <cstdint>
#include <vector>

#include <sisl/logging/logging.h>
#include <sisl/utility/enum.hpp>

#include "homeds/utility/stats.hpp"

SISL_LOGGING_DECL(cache_vmod_evict, cache_vmod_read, cache_vmod_write)

namespace homestore {
#define CVALUES                                                                                                        \
    X(CACHE_STATS_OBJ_COUNT, COUNTER, STATS_INVALID_INDEX, "Cache Object Count")                                       \
    X(CACHE_STATS_HIT_COUNT, COUNTER, STATS_INVALID_INDEX, "Cache hit Count")                                          \
    X(CACHE_STATS_MISS_COUNT, COUNTER, STATS_INVALID_INDEX, "Cache miss Count")                                        \
    X(CACHE_STATS_EVICT_COUNT, COUNTER, STATS_INVALID_INDEX, "Cache evict Count")                                      \
    X(CACHE_STATS_FAILED_EVICT_COUNT, COUNTER, STATS_INVALID_INDEX, "Cache unable to evict countt")

#define X(ind, type, mean_of, desc) ind,
ENUM(cache_stats_type, uint32_t, CVALUES);
#undef X

#define X(ind, type, mean_of, desc) {ind, type, mean_of, desc},
static std::vector< homeds::stats_key > cache_stats_keys = {CVALUES};
#undef X

class CacheStats : public homeds::Stats {
public:
    CacheStats() :
            // Stats({CVALUES}) {}
            Stats{cache_stats_keys} {}

    CacheStats(const CacheStats&) = delete;
    CacheStats& operator=(const CacheStats&) = delete;
    CacheStats(CacheStats&&) noexcept = delete;
    CacheStats& operator=(CacheStats&&) noexcept = delete;
    ~CacheStats() = default;

    int get_hit_ratio() const {
        return static_cast< int >((get_hit_count() * 100) / (get_hit_count() + get_miss_count()));
    }

    uint64_t get_hit_count() const { return this->get(CACHE_STATS_HIT_COUNT); }

    uint64_t get_miss_count() const { return this->get(CACHE_STATS_MISS_COUNT); }

    uint64_t get_evict_count() const { return this->get(CACHE_STATS_EVICT_COUNT); }

    uint64_t get_failed_evict_count() const { return this->get(CACHE_STATS_FAILED_EVICT_COUNT); }
};
} // namespace homestore
