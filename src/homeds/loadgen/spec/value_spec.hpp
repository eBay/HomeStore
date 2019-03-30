//
// Created by Kadayam, Hari on 3/11/19.
//

#ifndef HOMESTORE_VALUE_SPEC_HPP
#define HOMESTORE_VALUE_SPEC_HPP

namespace homeds {
namespace loadgen {

void gen_random_string(uint8_t *s, const size_t len) {
    static const char alphanum[] =
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz";

    for (size_t i = 0u; i < len-1; ++i) {
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }
    s[len-1] = 0;
}
} } // namespace homeds::loadgen
#endif // HOMESTORE_VALUE_SPEC_HPP
