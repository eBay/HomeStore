#pragma once

#include "homestore_config.hpp"
#include <sisl/fds/buffer.hpp>

namespace homestore {
class hs_utils {
    static size_t m_btree_mempool_size;

public:
    static uint8_t* iobuf_alloc(const size_t size, const sisl::buftag tag, const size_t alignment);
    static void iobuf_free(uint8_t* const ptr, const sisl::buftag tag);
    static void set_btree_mempool_size(const size_t size);
    static void iobuf_free(uint8_t* const ptr, const sisl::buftag tag, const size_t size);
    static uint64_t aligned_size(const size_t size, const size_t alignment);
    static bool mod_aligned_sz(const size_t size_to_check, const size_t align_sz);
    static sisl::byte_view create_byte_view(const uint64_t size, const bool is_aligned_needed, const sisl::buftag tag,
                                            const size_t alignment);
    static sisl::io_blob create_io_blob(const uint64_t size, const bool is_aligned_needed, const sisl::buftag tag,
                                        const size_t alignment);
    static sisl::byte_array extract_byte_array(const sisl::byte_view& b, const bool is_aligned_needed,
                                               const size_t alignment);
    static sisl::byte_array make_byte_array(const uint64_t size, const bool is_aligned_needed, const sisl::buftag tag,
                                            const size_t alignment);
    static hs_uuid_t gen_system_uuid();
};
static constexpr hs_uuid_t INVALID_SYSTEM_UUID{0};

} // namespace homestore
