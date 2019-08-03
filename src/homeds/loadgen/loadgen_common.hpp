//
// Created by Kadayam, Hari on 2/22/19.
//

#ifndef HOMESTORE_LOADGEN_COMMON_HPP
#define HOMESTORE_LOADGEN_COMMON_HPP

namespace homeds {
namespace loadgen {
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
