/*
 * blk.h
 *
 *  Created on: 03-Nov-2016
 *      Author: hkadayam
 */

#ifndef SRC_BLKALLOC_BLK_H_
#define SRC_BLKALLOC_BLK_H_

#include <cassert>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <limits>
#include <memory>
#include <sstream>

#include <fds/bitword.hpp>
#include <fds/thread_vector.hpp>
#include <fds/utils.hpp>

#include "engine/common/homestore_config.hpp"
#include "engine/homeds/array/flexarray.hpp"
#include "engine/homeds/memory/mempiece.hpp"

//#include "device/device.h"

namespace homestore {

typedef uint32_t blk_num_t;
typedef blk_num_t blk_cap_t;
static_assert(sizeof(blk_num_t) == (BLK_NUM_BITS - 1) / 8 + 1, "Expected blk_num_t to matching BLK_NUM_BITS");

typedef uint8_t blk_count_serialized_t;
typedef uint16_t blk_count_t;
static_assert(sizeof(blk_count_serialized_t) == (NBLKS_BITS - 1) / 8 + 1,
              "Expected blk_count_t to matching NBLKS_BITS");

typedef uint8_t chunk_num_t;
static_assert(sizeof(chunk_num_t) == (CHUNK_NUM_BITS - 1) / 8 + 1, "Expected blk_count_t to matching CHUNK_NUM_BITS");

typedef uint8_t blk_temp_t;

/* This structure represents the application wide unique block number. It also encomposses the number of blks. */

struct BlkId {
private:
    static constexpr uint64_t s_blk_num_mask{(static_cast< uint64_t >(1) << BLK_NUM_BITS) - 1};
    static constexpr uint64_t s_nblks_mask{(static_cast< uint64_t >(1) << NBLKS_BITS) - 1};
    static constexpr uint64_t s_chunk_num_mask{(static_cast< uint64_t >(1) << CHUNK_NUM_BITS) - 1};

public:
    [[nodiscard]] static constexpr blk_count_t max_blks_in_op() { return (1 << NBLKS_BITS); }
    [[nodiscard]] static constexpr uint64_t max_id_int() {
        return (1ull << (BLK_NUM_BITS + NBLKS_BITS + CHUNK_NUM_BITS)) - 1;
    }

    [[nodiscard]] static int compare(const BlkId& one, const BlkId& two) {
        if (one.m_chunk_num > two.m_chunk_num) {
            return -1;
        } else if (one.m_chunk_num < two.m_chunk_num) {
            return 1;
        }

        if (one.m_blk_num > two.m_blk_num) {
            return -1;
        } else if (one.m_blk_num < two.m_blk_num) {
            return 1;
        }

        if (one.m_nblks > two.m_nblks) {
            return -1;
        } else if (one.m_nblks < two.m_nblks) {
            return 1;
        }

        return 0;
    }

    [[nodiscard]] uint64_t to_integer() const {
        const uint64_t val{m_blk_num | (static_cast< uint64_t >(m_nblks) << BLK_NUM_BITS) |
                           (static_cast< uint64_t >(m_chunk_num) << (BLK_NUM_BITS + NBLKS_BITS))};
        return val;
    }

    explicit BlkId(const uint64_t id_int) { set(id_int); }
    BlkId(const blk_num_t blk_num, const blk_count_t nblks, const chunk_num_t chunk_num = 0) {
        set(blk_num, nblks, chunk_num);
    }
    BlkId() { invalidate(); }
    BlkId(const BlkId&) = default;
    BlkId& operator=(const BlkId&) = default;
    BlkId(BlkId&&) noexcept = default;
    BlkId& operator=(BlkId&&) noexcept = default;
    bool operator==(const BlkId& other) noexcept { return (compare(*this, other) == 0); }

    void invalidate() { set(blk_num_t{0}, blk_count_t{0}, s_chunk_num_mask); }

    [[nodiscard]] bool is_valid() const { return (m_chunk_num != s_chunk_num_mask); }

    [[nodiscard]] BlkId get_blkid_at(const uint32_t offset, const uint32_t pagesz) const {
        assert(offset % pagesz == 0);
        const uint32_t remaining_size{((get_nblks() - (offset / pagesz)) * pagesz)};
        return (get_blkid_at(offset, remaining_size, pagesz));
    }

    [[nodiscard]] BlkId get_blkid_at(const uint32_t offset, const uint32_t size, const uint32_t pagesz) const {
        assert(size % pagesz == 0);
        assert(offset % pagesz == 0);

        BlkId other;

        other.set_blk_num(get_blk_num() + (offset / pagesz));
        other.set_nblks(size / pagesz);
        other.set_chunk_num(get_chunk_num());

        assert(other.get_blk_num() < get_blk_num() + get_nblks());
        assert((other.get_blk_num() + other.get_nblks()) <= (get_blk_num() + get_nblks()));
        return other;
    }

    void set(const blk_num_t blk_num, const blk_count_t nblks, const chunk_num_t chunk_num = 0) {
        set_blk_num(blk_num);
        set_nblks(nblks);
        set_chunk_num(chunk_num);
    }

    void set(const BlkId& bid) { set(bid.get_blk_num(), bid.get_nblks(), bid.get_chunk_num()); }

    void set(const uint64_t id_int) {
        HS_DEBUG_ASSERT_LE(id_int, max_id_int());
        m_blk_num = (id_int & s_blk_num_mask);
        m_nblks = static_cast< blk_count_t >((id_int >> BLK_NUM_BITS) & s_nblks_mask);
        m_chunk_num = static_cast< chunk_num_t >((id_int >> (BLK_NUM_BITS + NBLKS_BITS)) & s_chunk_num_mask);
    }

    void set_blk_num(const blk_num_t blk_num) {
        HS_DEBUG_ASSERT_LE(blk_num, s_blk_num_mask);
        m_blk_num = blk_num;
    }
    [[nodiscard]] blk_num_t get_blk_num() const { return m_blk_num; }

    void set_nblks(const blk_count_t nblks) {
        HS_DEBUG_ASSERT_LE(nblks, max_blks_in_op());
        m_nblks = static_cast< blk_count_serialized_t >(nblks - 1);
    }
    [[nodiscard]] blk_count_t get_nblks() const { return static_cast< blk_count_t >(m_nblks) + 1; }

    void set_chunk_num(const chunk_num_t chunk_num) {
        HS_DEBUG_ASSERT_LE(chunk_num, s_chunk_num_mask);
        m_chunk_num = chunk_num;
    }
    [[nodiscard]] chunk_num_t get_chunk_num() const { return m_chunk_num; }

    /* A blkID represent a page size which is assigned to a blk allocator */
    [[nodiscard]] uint64_t data_size(const uint32_t page_size) const { return ((uint64_t)get_nblks() * page_size); }

    [[nodiscard]] std::string to_string() const {
        return is_valid() ? fmt::format("BlkNum={} nblks={} chunk={}", get_blk_num(), get_nblks(), get_chunk_num())
                          : "Invalid_Blkid";
    }

private:
    blk_num_t m_blk_num;            // Block number which is unique within the chunk
    blk_count_serialized_t m_nblks; // Number of blocks+1 for this blkid, don't directly acccess this - use get_nblks()
    chunk_num_t m_chunk_num;        // Chunk number - which is unique for the entire application
} __attribute__((__packed__));

[[nodiscard]] inline blk_num_t begin_of(const BlkId& bid) { return bid.get_blk_num(); }
[[nodiscard]] inline blk_num_t end_of(const BlkId& bid) { return bid.get_blk_num() + bid.get_nblks(); }

template < typename charT, typename traits >
std::basic_ostream< charT, traits >& operator<<(std::basic_ostream< charT, traits >& outStream, const BlkId& blk) {
    // copy the stream formatting
    std::basic_ostringstream< charT, traits > outStringStream;
    outStringStream.copyfmt(outStream);

    // print the stream
    outStringStream << blk.to_string();
    outStream << outStringStream.str();

    return outStream;
}

using blkid_list_ptr = std::shared_ptr< sisl::ThreadVector< BlkId > >;

VENUM(BlkAllocStatus, uint32_t,
      BLK_ALLOC_NONE = 0,   // No Action taken
      SUCCESS = 1ul << 0,     // Success
      FAILED = 1ul << 1,      // Failed to alloc/free
      REQ_MORE = 1ul << 2,    // Indicate that we need more
      SPACE_FULL = 1ul << 3,  // Space is full
      INVALID_DEV = 1ul << 4, // Invalid Device provided for alloc
      PARTIAL = 1ul << 5      // In case of multiple blks, only partial is alloced/freed
);
} // namespace homestore

// hash function definitions
namespace std {
template <>
struct hash< homestore::BlkId > {
    typedef homestore::BlkId argument_type;
    typedef size_t result_type;
    result_type operator()(const argument_type& bid) const noexcept {
        return std::hash< uint64_t >()(bid.to_integer());
    }
};
} // namespace std

namespace fmt {
template <>
struct formatter< homestore::BlkId > {
    template < typename ParseContext >
    constexpr auto parse(ParseContext& ctx) {
        return ctx.begin();
    }

    template < typename FormatContext >
    auto format(const homestore::BlkId& s, FormatContext& ctx) {
        return format_to(ctx.out(), s.to_string());
    }
};
} // namespace fmt
#endif /* SRC_BLKALLOC_BLK_H_ */
