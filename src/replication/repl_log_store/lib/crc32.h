#pragma once

#include "storage_engine_buffer.h"

#include <cstdint>
#include <string>

namespace nukv {

class Crc32 {
public:
    static uint32_t get(const void* data, size_t len, uint32_t seed);

    static uint32_t get(const SEBuf& buf, uint32_t seed);

    static uint32_t get(const std::string& str, uint32_t seed);
};

}; // namespace nukv
