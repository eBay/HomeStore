//
// Created by Kadayam, Hari on 3/11/19.
//

#ifndef HOMESTORE_VALUE_SPEC_HPP
#define HOMESTORE_VALUE_SPEC_HPP

namespace homeds {
namespace loadgen {
class ValueSpec {
public:
    static uint64_t MAX_VALUES;
    virtual uint64_t get_hash_code() = 0;
};

uint64_t ValueSpec::MAX_VALUES = 0;

static const char alphanum[] = "0123456789"
                               "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                               "abcdefghijklmnopqrstuvwxyz";

void gen_random_string(std::vector< uint8_t >& s, const size_t len) {
    for (size_t i = 0u; i < len - 1; ++i) {
        // s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
        s.push_back(alphanum[rand() % (sizeof(alphanum) - 1)]);
    }
    s.push_back(0);
}

void gen_random_string(uint8_t* s, const size_t len) {
    for (size_t i = 0u; i < len - 1; ++i) {
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }
    s[len - 1] = 0;
}

} // namespace loadgen
} // namespace homeds
#endif // HOMESTORE_VALUE_SPEC_HPP
