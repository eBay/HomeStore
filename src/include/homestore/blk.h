/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 *********************************************************************************/
#pragma once

#include <cassert>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <limits>
#include <memory>
#include <sstream>

#include <boost/icl/interval_map.hpp>
#include <sisl/utility/enum.hpp>
#include <sisl/fds/buffer.hpp>
#include <homestore/homestore_decl.hpp>

namespace homestore {

using chunk_num_t = uint16_t;
using blk_count_t = uint16_t;
using blk_num_t = uint32_t;
using blk_temp_t = uint16_t;
using allocator_id_t = chunk_num_t;

static constexpr size_t max_addressable_chunks() { return 1UL << (8 * sizeof(chunk_num_t)); }
static constexpr size_t max_blks_per_chunk() { return 1UL << (8 * sizeof(blk_num_t)); }
static constexpr size_t max_blks_per_blkid() { return (1UL << (8 * sizeof(blk_count_t))) - 1; }

#pragma pack(1)
struct BlkId {
protected:
    struct serialized {
        blk_num_t m_is_multi : 1; // Is it a part of multi blkid or not
        blk_num_t m_blk_num : 31; // Block number which is unique within the chunk
        blk_count_t m_nblks;      // Number of blocks+1 for this blkid, don't directly acccess this - use blk_count()
        chunk_num_t m_chunk_num;  // Chunk number - which is unique for the entire application

        serialized() : m_is_multi{0}, m_blk_num{0}, m_nblks{0}, m_chunk_num{0} {}
        serialized(bool is_multi, blk_num_t blk_num, blk_count_t nblks, chunk_num_t cnum) :
                m_is_multi{is_multi ? 0x1u : 0x0u}, m_blk_num{blk_num}, m_nblks{nblks}, m_chunk_num{cnum} {}
    };
    static_assert(sizeof(serialized) == sizeof(uint64_t), "Expected serialized size to 64 bits");

    serialized s;

public:
    BlkId() = default;
    explicit BlkId(uint64_t id_int);
    BlkId(blk_num_t blk_num, blk_count_t nblks, chunk_num_t chunk_num);
    BlkId(BlkId const&) = default;
    BlkId& operator=(BlkId const&) = default;
    BlkId(BlkId&&) noexcept = default;
    BlkId& operator=(BlkId&&) noexcept = default;

    bool operator==(BlkId const& other) const { return (compare(*this, other) == 0); }
    bool operator>(BlkId const& other) const { return (compare(*this, other) > 0); }
    bool operator<(BlkId const& other) const { return (compare(*this, other) < 0); }

    blk_num_t blk_num() const { return s.m_blk_num; }
    blk_count_t blk_count() const { return s.m_nblks; }
    chunk_num_t chunk_num() const { return s.m_chunk_num; }
    bool is_multi() const { return s.m_is_multi; }

    void invalidate();
    uint64_t to_integer() const;
    sisl::blob serialize(); // TODO: Consider making this const, perhaps returns const uint8_t version of blob
    void deserialize(sisl::blob const& b, bool copy);
    uint32_t serialized_size() const;
    std::string to_string() const;
    bool is_valid() const;
    static uint32_t expected_serialized_size();

    static int compare(BlkId const& one, BlkId const& two);
};
#pragma pack()

#pragma pack(1)
struct MultiBlkId : public BlkId {
    static constexpr uint32_t max_addln_pieces{5};
    static constexpr uint32_t max_pieces{max_addln_pieces + 1};

private:
    struct chain_blkid {
        blk_num_t m_blk_num;
        blk_count_t m_nblks{0};

        bool is_valid() const { return (m_nblks != 0); }
    };

    uint16_t n_addln_piece{0};
    std::array< chain_blkid, max_addln_pieces > addln_pieces;

public:
    MultiBlkId();
    MultiBlkId(BlkId const& b);
    MultiBlkId(blk_num_t blk_num, blk_count_t nblks, chunk_num_t chunk_num);
    MultiBlkId(MultiBlkId const&) = default;
    MultiBlkId& operator=(MultiBlkId const&) = default;
    MultiBlkId(MultiBlkId&&) noexcept = default;
    MultiBlkId& operator=(MultiBlkId&&) noexcept = default;

    void add(blk_num_t blk_num, blk_count_t nblks, chunk_num_t chunk_num);
    void add(BlkId const&);

    uint16_t num_pieces() const;
    blk_count_t blk_count() const;
    std::string to_string() const;

    bool operator==(MultiBlkId const& other) const { return (compare(*this, other) == 0); }
    bool operator>(MultiBlkId const& other) const { return (compare(*this, other) > 0); }
    bool operator<(MultiBlkId const& other) const { return (compare(*this, other) < 0); }

    sisl::blob serialize();
    uint32_t serialized_size() const;
    void deserialize(sisl::blob const& b, bool copy);

    bool has_room() const;
    BlkId to_single_blkid() const;

    static uint32_t expected_serialized_size(uint16_t num_pieces);
    static int compare(MultiBlkId const& one, MultiBlkId const& two);

    struct iterator {
        MultiBlkId const& mbid_;
        uint16_t next_blk_{0};

        iterator(MultiBlkId const& mb) : mbid_{mb} {}
        std::optional< BlkId > next() {
            if (next_blk_ == 0) {
                auto bid = r_cast< BlkId const& >(mbid_);
                ++next_blk_;
                return (bid.is_valid()) ? std::make_optional(bid) : std::nullopt;
            } else if (next_blk_ < mbid_.num_pieces()) {
                auto cbid = mbid_.addln_pieces[next_blk_ - 1];
                ++next_blk_;
                return std::make_optional(BlkId{cbid.m_blk_num, cbid.m_nblks, mbid_.chunk_num()});
            } else {
                return std::nullopt;
            }
        }
    };

    iterator iterate() const;
};
#pragma pack()

} // namespace homestore

///////////////////// hash function definitions /////////////////////
namespace std {
template <>
struct hash< homestore::BlkId > {
    size_t operator()(const homestore::BlkId& bid) const noexcept { return std::hash< uint64_t >()(bid.to_integer()); }
};

template <>
struct hash< homestore::MultiBlkId > {
    size_t operator()(const homestore::MultiBlkId& mbid) const noexcept {
        static constexpr size_t s_start_seed = 0xB504F333;
        size_t seed = s_start_seed;
        auto it = mbid.iterate();
        while (auto b = it.next()) {
            boost::hash_combine(seed, b->to_integer());
        }
        return seed;
    }
};
} // namespace std

///////////////////// formatting definitions /////////////////////
template < typename T >
struct fmt::formatter< T, std::enable_if_t< std::is_base_of< homestore::BlkId, T >::value, char > >
        : fmt::formatter< std::string > {
    auto format(const homestore::BlkId& a, format_context& ctx) const {
        return fmt::formatter< std::string >::format(a.to_string(), ctx);
    }
};

template < typename T >
struct fmt::formatter< T, std::enable_if_t< std::is_base_of< homestore::MultiBlkId, T >::value, char > >
        : fmt::formatter< std::string > {
    auto format(const homestore::MultiBlkId& a, format_context& ctx) const {
        return fmt::formatter< std::string >::format(a.to_string(), ctx);
    }
};

namespace boost {
template <>
struct hash< homestore::BlkId > {
    size_t operator()(const homestore::BlkId& bid) const noexcept { return std::hash< homestore::BlkId >()(bid); }
};
} // namespace boost

namespace homestore {
///////////////////// stream operation definitions /////////////////////
template < typename charT, typename traits, typename blkidT >
std::basic_ostream< charT, traits >& stream_op(std::basic_ostream< charT, traits >& outStream, blkidT const& blk) {
    // copy the stream formatting
    std::basic_ostringstream< charT, traits > outStringStream;
    outStringStream.copyfmt(outStream);

    // print the stream
    outStringStream << blk.to_string();
    outStream << outStringStream.str();

    return outStream;
}

template < typename charT, typename traits >
std::basic_ostream< charT, traits >& operator<<(std::basic_ostream< charT, traits >& outStream, BlkId const& blk) {
    return stream_op< charT, traits, BlkId >(outStream, blk);
}

template < typename charT, typename traits >
std::basic_ostream< charT, traits >& operator<<(std::basic_ostream< charT, traits >& outStream, MultiBlkId const& blk) {
    return stream_op< charT, traits, MultiBlkId >(outStream, blk);
}

///////////////////// Other common Blkd definitions /////////////////////
VENUM(BlkAllocStatus, uint32_t,
      BLK_ALLOC_NONE = 0,        // No Action taken
      SUCCESS = 1ul << 0,        // Success
      FAILED = 1ul << 1,         // Failed to alloc/free
      REQ_MORE = 1ul << 2,       // Indicate that we need more
      SPACE_FULL = 1ul << 3,     // Space is full
      INVALID_DEV = 1ul << 4,    // Invalid Device provided for alloc
      PARTIAL = 1ul << 5,        // In case of multiple blks, only partial is alloced/freed
      INVALID_THREAD = 1ul << 6, // Not possible to alloc in this thread
      INVALID_INPUT = 1ul << 7,  // Invalid input
      TOO_MANY_PIECES = 1ul << 8 // Allocation results in more pieces than passed on
);

struct blk_alloc_hints {
    blk_temp_t desired_temp{0};                  // Temperature hint for the device
    std::optional< uint32_t > pdev_id_hint;      // which physical device to pick (hint if any) -1 for don't care
    std::optional< chunk_num_t > chunk_id_hint;  // any specific chunk id to pick for this allocation
    std::optional< stream_id_t > stream_id_hint; // any specific stream to pick
    bool can_look_for_other_chunk{true};         // If alloc on device not available can I pick other device
    bool is_contiguous{true};                    // Should the entire allocation be one contiguous block
    bool partial_alloc_ok{false};   // ok to allocate only portion of nblks? Mutually exclusive with is_contiguous
    uint32_t min_blks_per_piece{1}; // blks allocated in a blkid should be atleast this size per entry
    uint32_t max_blks_per_piece{max_blks_per_blkid()}; // Number of blks on every entry
};

} // namespace homestore
