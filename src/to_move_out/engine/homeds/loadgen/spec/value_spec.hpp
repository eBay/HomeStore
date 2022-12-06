//
// Created by Kadayam, Hari on 3/11/19.
//

#ifndef HOMESTORE_VALUE_SPEC_HPP
#define HOMESTORE_VALUE_SPEC_HPP

#include <array>
#include <cstdint>
#include <random>
#include <vector>

namespace homeds {
namespace loadgen {
class ValueSpec {
public:
    ValueSpec(const ValueSpec&) = default;
    ValueSpec& operator=(const ValueSpec&) = default;
    ValueSpec(ValueSpec&&) noexcept = default;
    ValueSpec& operator=(ValueSpec&&) noexcept = default;
    virtual ~ValueSpec() = default;

    static uint64_t MAX_VALUES;
    virtual uint64_t get_hash_code() const = 0;

protected:
    ValueSpec() = default;

    static constexpr std::array< const char, 62 > alphanum{
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K',
        'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};

    static void gen_random_string(std::vector< uint8_t >& s, const size_t len) {
        static thread_local std::random_device rd{};
        static thread_local std::default_random_engine re{rd()};
        std::uniform_int_distribution< size_t > rand_char{0, alphanum.size() - 1};
        for (size_t i{0}; i < len - 1; ++i) {
            s.push_back(alphanum[rand_char(re)]);
        }
        s.push_back(0);
    }

    static void gen_random_string(uint8_t* const s, const size_t len) {
        static thread_local std::random_device rd{};
        static thread_local std::default_random_engine re{rd()};
        std::uniform_int_distribution< size_t > rand_char{0, alphanum.size() - 1};
        for (size_t i{0}; i < len - 1; ++i) {
            s[i] = alphanum[rand_char(re)];
        }
        s[len - 1] = 0;
    }
};

uint64_t ValueSpec::MAX_VALUES = 0;

} // namespace loadgen
} // namespace homeds
#endif // HOMESTORE_VALUE_SPEC_HPP
