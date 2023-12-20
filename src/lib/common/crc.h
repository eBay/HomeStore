#pragma once

#define MAX_ITER 8

extern "C" {
// crc16_t10dif reference function, slow crc16 from the definition.
static inline uint16_t crc16_t10dif(uint16_t seed, const unsigned char* buf, uint64_t len) {
    size_t rem = seed;
    unsigned int i, j;

    uint16_t poly = 0x8bb7; // t10dif standard

    for (i = 0; i < len; i++) {
        rem = rem ^ (buf[i] << 8);
        for (j = 0; j < MAX_ITER; j++) {
            rem = rem << 1;
            rem = (rem & 0x10000) ? rem ^ poly : rem;
        }
    }
    return rem;
}

// crc32_ieee reference function, slow crc32 from the definition.
static inline uint32_t crc32_ieee(uint32_t seed, const unsigned char* buf, uint64_t len) {
    uint64_t rem = ~seed;
    unsigned int i, j;

    uint32_t poly = 0x04C11DB7; // IEEE standard

    for (i = 0; i < len; i++) {
        rem = rem ^ ((uint64_t)buf[i] << 24);
        for (j = 0; j < MAX_ITER; j++) {
            rem = rem << 1;
            rem = (rem & 0x100000000ULL) ? rem ^ poly : rem;
        }
    }
    return ~rem;
}
}
