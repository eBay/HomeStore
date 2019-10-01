//
// Created by Kadayam, Hari on 2/22/19.
//

#ifndef HOMESTORE_LOADGEN_COMMON_HPP
#define HOMESTORE_LOADGEN_COMMON_HPP

#include <chrono>
#include <ctime>
#include <string>

namespace homeds { 
namespace loadgen {

constexpr auto Ki = 1024ull;
constexpr auto Mi = Ki * Ki;
constexpr auto Gi = Ki * Mi;
using Clock = std::chrono::steady_clock;
class Param {
public:
    uint64_t          NIO{}, NK{}, NRT{};                   // total ios and total keys
    int               PC{}, PR{}, PU{}, PD{}, PRU{}, PRQ{}; // total % for op
    uint64_t          PRINT_INTERVAL{}, WST{};
    uint64_t          WARM_UP_KEYS = 0;
    uint8_t           NT = 0; // num of threads
    Clock::time_point startTime;
    Clock::time_point print_startTime;
    Clock::time_point workload_shiftTime;
    uint8_t           enable_write_log;
    std::vector<std::string> file_names;
};

enum KeyPattern {
    SEQUENTIAL = 0,
    UNI_RANDOM,
    PSEUDO_RANDOM,
    OVERLAP,
    OUT_OF_BOUND,
    SAME_KEY,

    KEY_PATTERN_SENTINEL // Last option
};

enum ValuePattern { SEQUENTIAL_VAL, RANDOM_BYTES };

template < typename K >
struct key_range_t {
    K&   start_key;
    bool start_incl;

    K&   end_key;
    bool end_incl;
};
} // namespace loadgen
} // namespace homeds
#endif // HOMESTORE_LOADGEN_COMMON_HPP
