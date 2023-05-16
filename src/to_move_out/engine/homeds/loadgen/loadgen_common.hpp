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
#ifndef HOMESTORE_LOADGEN_COMMON_HPP
#define HOMESTORE_LOADGEN_COMMON_HPP

#include <chrono>
#include <cstdint>
#include <ctime>
#include <string>
#include <vector>

namespace homeds {
namespace loadgen {

constexpr uint64_t Ki{1024};
constexpr uint64_t Mi{Ki * Ki};
constexpr uint64_t Gi{Ki * Mi};
typedef std::chrono::steady_clock Clock;

class Param {
public:
    uint64_t NIO{}, NK{}, NRT{};              // total ios and total keys
    int PC{}, PR{}, PU{}, PD{}, PRU{}, PRQ{}; // total % for op
    uint64_t PRINT_INTERVAL{}, WST{};
    uint64_t WARM_UP_KEYS{0};
    size_t NT{0}; // num of threads
    Clock::time_point startTime;
    Clock::time_point print_startTime;
    Clock::time_point workload_shiftTime;
    uint8_t enable_write_log;
    std::vector< std::string > file_names;
};

enum class KeyPattern : uint8_t {
    SEQUENTIAL = 0,
    UNI_RANDOM,
    PSEUDO_RANDOM,
    OVERLAP,
    OUT_OF_BOUND,
    SAME_KEY,

    KEY_PATTERN_SENTINEL // Last option
};

enum class ValuePattern : uint8_t { SEQUENTIAL_VAL, RANDOM_BYTES };

template < typename K >
struct key_range_t {
    K& start_key;
    bool start_incl;

    K& end_key;
    bool end_incl;
};
} // namespace loadgen
} // namespace homeds
#endif // HOMESTORE_LOADGEN_COMMON_HPP
