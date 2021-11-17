#pragma once

#include "homestore_config.hpp"
#include <sisl/fds/buffer.hpp>

namespace homestore {
class hs_utils {
public:
    static uint8_t* iobuf_alloc(const size_t size, const sisl::buftag tag,
                                const size_t alignment = HS_STATIC_CONFIG(data_drive_attr.align_size));
    static void iobuf_free(uint8_t* const ptr, const sisl::buftag tag);
    static uint64_t aligned_size(const size_t size,
                                 const size_t alignment = HS_STATIC_CONFIG(data_drive_attr.align_size));
    static bool mod_aligned_sz(const size_t size_to_check, const size_t align_sz);
    static sisl::byte_view create_byte_view(const uint64_t size, const bool is_aligned_needed, const sisl::buftag tag,
                                            const size_t alignment = HS_STATIC_CONFIG(data_drive_attr.align_size));
    static sisl::io_blob create_io_blob(const uint64_t size, const bool is_aligned_needed, const sisl::buftag tag,
                                        const size_t alignment = HS_STATIC_CONFIG(data_drive_attr.align_size));
    static sisl::byte_array extract_byte_array(const sisl::byte_view& b, const bool is_aligned_needed = true,
                                               const size_t alignment = HS_STATIC_CONFIG(data_drive_attr.align_size));
    static sisl::byte_array make_byte_array(const uint64_t size, const bool is_aligned_needed, const sisl::buftag tag,
                                            const size_t alignment = HS_STATIC_CONFIG(data_drive_attr.align_size));
    static hs_uuid_t gen_system_uuid();
};
static constexpr hs_uuid_t INVALID_SYSTEM_UUID{0};

} // namespace homestore
