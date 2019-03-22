//
// Created by Kadayam, Hari on 2/22/19.
//

#ifndef HOMESTORE_LOADGEN_COMMON_HPP
#define HOMESTORE_LOADGEN_COMMON_HPP

namespace homeds { namespace loadgen {
enum KeyPattern {
    SEQUENTIAL,
    UNI_RANDOM,
    PSEUDO_RANDOM,
    OVERLAP,
    LAST
};

enum ValuePattern {
    RANDOM_BYTES
};
} } // namespace homeds::loadgen
#endif //HOMESTORE_LOADGEN_COMMON_HPP
