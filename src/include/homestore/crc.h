#pragma once

// Only x86 and x86_64 supported by Intel Storage Acceleration library
#ifndef NO_ISAL
#include <isa-l/crc.h>

#else

extern "C" {
// crc16_t10dif reference function, slow crc16 from the definition.
uint16_t crc16_t10dif(uint16_t seed, const unsigned char* buf, uint64_t len);

// crc32_ieee reference function, slow crc32 from the definition.
uint32_t crc32_ieee(uint32_t seed, const unsigned char* buf, uint64_t len);
}
#endif
