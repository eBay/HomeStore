/*
 * bitmap_test.cpp
 *
 *  Created on: Oct 9, 2015
 *      Author: hkadayam
 */
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <iostream>
#include "homeds/bitmap/bitword.hpp"

int count_zeros(uint32_t v) {
    int r;           // put the result in r
    static const int Mod37BitPosition[] = // map a bit value mod 37 to its position
            {
                    32, 0, 1, 26, 2, 23, 27, 0, 3, 16, 24, 30, 28, 11, 0, 13, 4,
                    7, 17, 0, 25, 22, 31, 15, 29, 10, 12, 6, 0, 21, 14, 9, 5,
                    20, 8, 19, 18
            };
    r = Mod37BitPosition[(-v & v) % 37];

    printf("count of zeros for %u = %d\n", v, r);

    return 0;
}

void print_bitset(const char *msg, homeds::Bitword<uint64_t> b) {
    uint64_t val = b.to_integer();
    printf("%-40s 0x%016lx ", msg ? msg : "", val);

    uint64_t mask = 0x8000000000000000UL;
    for (auto i = 0; i < 64; i++) {
        printf("%c", val & mask ? '1' : '0');
        mask = mask >>1;
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    homeds::Bitword<uint64_t> b;
    print_bitset("initial_bits", b);

    b.set_bits(2, 8);
    print_bitset("set bit 2 to 9", b);

    b.set_bits(30, 10);
    print_bitset("set bit 30 to 39", b);

    b.reset_bits(0, 3);
    print_bitset("reset bit 0 to 2", b);

    uint32_t count;
    int index = b.get_next_reset_bits(0, &count);
    std::cout << "Next reset bits from 0: index = " << index << " count = " << count << "\n";

    index = b.get_next_reset_bits(index+count, &count);
    std::cout << "Next reset bits: index = " << index << " count = " << count << "\n";

    index = b.get_next_reset_bits(index+count, &count);
    std::cout << "Next reset bits: index = " << index << " count = " << count << "\n";

    index = b.get_next_reset_bits(index+count, &count);
    std::cout << "Next reset bits: index = " << index << " count = " << count << "\n";

    index = b.get_max_contigous_reset_bits(0, &count);
    std::cout << "Max contigous reset bits index = " << index << " count = " << count << "\n";

    index = b.get_max_contigous_reset_bits(index+count, &count);
    std::cout << "Max contigous reset bits index = " << index << " count = " << count << "\n";
}



