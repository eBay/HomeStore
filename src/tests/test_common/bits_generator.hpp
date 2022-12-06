#pragma once
#include <type_traits>
#include <cstdint>
#include <random>
#include <iostream>

namespace homestore {

class BitsGenerator {
public:
    static void gen_random_bits(size_t size, uint8_t* buf) {
        std::random_device rd;
        std::default_random_engine g(rd());
        std::uniform_int_distribution< unsigned long long > dis(std::numeric_limits< std::uint8_t >::min(),
                                                                std::numeric_limits< std::uint8_t >::max());
        for (size_t i = 0; i < size; ++i) {
            buf[i] = dis(g);
        }
    }

    static void gen_random_bits(sisl::blob& b) { gen_random_bits(b.size, b.bytes); }
};

}; // namespace homestore

