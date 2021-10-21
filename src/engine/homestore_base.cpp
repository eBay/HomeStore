#include <sisl/fds/buffer.hpp>
#include <iomgr/iomgr.hpp>

#include "homestore_base.hpp"
#include "common/homestore_status_mgr.hpp"
#include "common/homestore_assert.hpp"

namespace homestore {
HomeStoreBase::~HomeStoreBase() = default;

void HomeStoreBase::set_instance(HomeStoreBaseSafePtr instance) { s_instance = instance; }

void HomeStoreBase::reset_instance() { s_instance.reset(); }

std::shared_ptr< spdlog::logger >& HomeStoreBase::periodic_logger() { return instance()->m_periodic_logger; }

HomeStoreStatusMgr* HomeStoreBase::status_mgr() { return m_status_mgr.get(); }

uint8_t* hs_utils::iobuf_alloc(const size_t size, const sisl::buftag tag, const size_t alignment) {
    auto buf = iomanager.iobuf_alloc(alignment, size, tag);
    HS_ASSERT_NOTNULL(RELEASE, buf, "io buf is null. probably going out of memory");
    return buf;
}

hs_uuid_t hs_utils::gen_system_uuid() { return std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()); }

void hs_utils::iobuf_free(uint8_t* const ptr, const sisl::buftag tag) { iomanager.iobuf_free(ptr, tag); }

uint64_t hs_utils::aligned_size(const size_t size, const size_t alignment) { return sisl::round_up(size, alignment); }

bool hs_utils::mod_aligned_sz(size_t size_to_check, size_t align_sz) {
    HS_DEBUG_ASSERT_EQ((align_sz & (align_sz - 1)), 0);
    return !(size_to_check & static_cast< size_t >(align_sz - 1)); // return true if it is aligned.
}

sisl::byte_view hs_utils::create_byte_view(const uint64_t size, const bool is_aligned_needed, const sisl::buftag tag, const size_t alignment) {
    return (is_aligned_needed) ? sisl::byte_view{static_cast<uint32_t>(aligned_size(size, alignment)), static_cast<uint32_t>(alignment), tag}
        : sisl::byte_view{static_cast<uint32_t>(size), 0, tag};
}

sisl::io_blob hs_utils::create_io_blob(const uint64_t size, const bool is_aligned_needed, const sisl::buftag tag,
                                       const size_t alignment) {
    return (is_aligned_needed) ? sisl::io_blob{size, static_cast<uint32_t>(alignment), tag}
                               : sisl::io_blob{size, 0, tag};
}

sisl::byte_array hs_utils::make_byte_array(const uint64_t size, const bool is_aligned_needed,
                                           const sisl::buftag tag, const size_t alignment) {
    return (is_aligned_needed) ? sisl::make_byte_array(static_cast< uint32_t >(aligned_size(size, alignment)), alignment, tag)
        : sisl::make_byte_array(static_cast<uint32_t>(size), 0, tag);
}

sisl::byte_array hs_utils::extract_byte_array(const sisl::byte_view& b, const bool is_aligned_needed,
                                              const size_t alignment) {
    return (is_aligned_needed) ? b.extract(alignment) : b.extract(0);
};
} // namespace homestore
