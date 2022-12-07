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

#include <sisl/utility/enum.hpp>
#include <homestore/homestore_decl.hpp>

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
    static constexpr blk_count_t max_blks_in_op() { return (1 << NBLKS_BITS); }
    static constexpr uint64_t max_id_int() { return (1ull << (BLK_NUM_BITS + NBLKS_BITS + CHUNK_NUM_BITS)) - 1; }

    static int compare(const BlkId& one, const BlkId& two);
    uint64_t to_integer() const;

    explicit BlkId(uint64_t id_int);
    BlkId(blk_num_t blk_num, blk_count_t nblks, chunk_num_t chunk_num = 0);
    BlkId() { invalidate(); }
    BlkId(const BlkId&) = default;
    BlkId& operator=(const BlkId&) = default;
    BlkId(BlkId&&) noexcept = default;
    BlkId& operator=(BlkId&&) noexcept = default;
    bool operator==(const BlkId& other) noexcept { return (compare(*this, other) == 0); }

    void invalidate();
    bool is_valid() const;

    BlkId get_blkid_at(uint32_t offset, uint32_t pagesz) const;
    BlkId get_blkid_at(uint32_t offset, uint32_t size, uint32_t pagesz) const;

    void set(blk_num_t blk_num, blk_count_t nblks, chunk_num_t chunk_num = 0);
    void set(const BlkId& bid);
    void set(uint64_t id_int);

    void set_blk_num(blk_num_t blk_num);
    blk_num_t get_blk_num() const { return m_blk_num; }

    void set_nblks(blk_count_t nblks);
    blk_count_t get_nblks() const { return static_cast< blk_count_t >(m_nblks) + 1; }

    void set_chunk_num(const chunk_num_t chunk_num);
    chunk_num_t get_chunk_num() const { return m_chunk_num; }

    /* A blkID represent a page size which is assigned to a blk allocator */
    uint32_t data_size(const uint32_t page_size) const { return (get_nblks() * page_size); }

    std::string to_string() const;

    blk_num_t m_blk_num;            // Block number which is unique within the chunk
    blk_count_serialized_t m_nblks; // Number of blocks+1 for this blkid, don't directly acccess this - use get_nblks()
    chunk_num_t m_chunk_num;        // Chunk number - which is unique for the entire application
} __attribute__((__packed__));

VENUM(BlkAllocStatus, uint32_t,
      BLK_ALLOC_NONE = 0,       // No Action taken
      SUCCESS = 1ul << 0,       // Success
      FAILED = 1ul << 1,        // Failed to alloc/free
      REQ_MORE = 1ul << 2,      // Indicate that we need more
      SPACE_FULL = 1ul << 3,    // Space is full
      INVALID_DEV = 1ul << 4,   // Invalid Device provided for alloc
      PARTIAL = 1ul << 5,       // In case of multiple blks, only partial is alloced/freed
      INVALID_THREAD = 1ul << 6 // Not possible to alloc in this thread
);

static_assert(sizeof(BlkId) < 8);
#pragma pack(1)
struct BlkId8_t : public BlkId {
    uint8_t pad[8 - sizeof(BlkId)]{};

    BlkId8_t& operator=(const BlkId& rhs) {
        BlkId::operator=(rhs);
        return *this;
    }
};
#pragma pack()
static_assert(sizeof(BlkId8_t) == 8);

inline blk_num_t begin_of(const BlkId& bid) { return bid.get_blk_num(); }
inline blk_num_t end_of(const BlkId& bid) { return bid.get_blk_num() + bid.get_nblks(); }

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
