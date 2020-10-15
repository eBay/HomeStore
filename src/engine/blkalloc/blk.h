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

/* This structure represents the application wide unique block number. It also encomposses the number of blks. */

struct BlkId {
private:
    static constexpr uint64_t s_id_mask{(static_cast< uint64_t >(1) << ID_BITS) - 1};
    static constexpr uint64_t s_nblks_mask{(static_cast< uint64_t >(1) << NBLKS_BITS) - 1};
    static constexpr uint64_t s_chuck_num_mask{(static_cast< uint64_t >(1) << CHUNK_NUM_BITS) - 1};

public:
    uint32_t m_id;       // Block number which is unique within the chunk
    uint8_t m_nblks;     // Total number of blocks starting from previous block number
    uint8_t m_chunk_num; // Chunk number - which is unique for the entire application

    [[nodiscard]] static constexpr uint64_t invalid_internal_id() {
        return (static_cast< uint64_t >(1) << (ID_BITS + NBLKS_BITS + CHUNK_NUM_BITS)) - 1;
    }

    [[nodiscard]] static constexpr uint64_t max_blks_in_op() { return s_nblks_mask; }

    [[nodiscard]] static int compare(const BlkId& one, const BlkId& two) {
        if (one.m_chunk_num > two.m_chunk_num) {
            return -1;
        } else if (one.m_chunk_num < two.m_chunk_num) {
            return 1;
        }

        if (one.m_id > two.m_id) {
            return -1;
        } else if (one.m_id < two.m_id) {
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
        const uint64_t val{m_id | (static_cast< uint64_t >(m_nblks) << ID_BITS) |
                           (static_cast< uint64_t >(m_chunk_num) << (ID_BITS + NBLKS_BITS))};
        return val;
    }

    explicit BlkId(const uint64_t id) 
    {
        set(id & s_id_mask, static_cast<uint8_t>((id >> ID_BITS) & s_nblks_mask),
            static_cast<uint16_t>((id >> (ID_BITS + NBLKS_BITS)) & s_chuck_num_mask));
    }

    BlkId(const uint64_t id, const uint8_t nblks, const uint16_t chunk_num = 0) { set(id, nblks, chunk_num); }

    BlkId() {
        set(s_id_mask, static_cast<uint8_t>(s_nblks_mask), static_cast<uint16_t>(s_chuck_num_mask));
    }

    [[nodiscard]] BlkId get_blkid_at(const uint32_t offset, const uint32_t pagesz) const {
        assert(offset % pagesz == 0);
        const uint32_t remaining_size{((m_nblks - (offset / pagesz)) * pagesz)};
        return (get_blkid_at(offset, remaining_size, pagesz));
    }

    [[nodiscard]] BlkId get_blkid_at(const uint32_t offset, const uint32_t size, const uint32_t pagesz) const {
        assert(size % pagesz == 0);
        assert(offset % pagesz == 0);

        BlkId other;

        other.m_id = m_id + (offset / pagesz);
        other.m_nblks = (size / pagesz);
        other.m_chunk_num = m_chunk_num;

        assert(other.m_id < m_id + m_nblks);
        assert((other.m_id + other.m_nblks) <= (m_id + m_nblks));
        return other;
    }

    BlkId(const BlkId&) = default;
    BlkId& operator=(const BlkId&) = default;
    BlkId(BlkId&&) noexcept = default;
    BlkId& operator=(BlkId&&) noexcept = default;

    void set(const uint64_t id, const uint8_t nblks, const uint16_t chunk_num = 0) {
        ASSERT(id <= s_id_mask);
        ASSERT(nblks <= s_nblks_mask);
        ASSERT(chunk_num <= s_chuck_num_mask);
        m_id = id;
        m_nblks = nblks;
        m_chunk_num = static_cast<uint8_t>(chunk_num);
    }

    void set(const BlkId& bid) { set(bid.get_id(), bid.get_nblks(), bid.get_chunk_num()); }

    void set(const uint64_t bid) { set(bid & s_id_mask, static_cast<uint8_t>((bid >> ID_BITS) & s_nblks_mask), static_cast<uint16_t>((bid >> (ID_BITS + CHUNK_NUM_BITS)) & s_chuck_num_mask)); }

    void set_id(const uint64_t id) { 
        ASSERT(id <= s_id_mask);
        m_id = id;
    }

    [[nodiscard]] uint64_t get_id() const { return m_id; }

    void set_nblks(const uint8_t nblks) { m_nblks = nblks; }

    [[nodiscard]] uint8_t get_nblks() const { return m_nblks; }

    [[nodiscard]] uint16_t get_chunk_num() const { return m_chunk_num; }

    /* A blkID represent a page size which is assigned to a blk allocator */
    [[nodiscard]] uint32_t data_size(const uint32_t page_size) const { return (m_nblks * page_size); }

    [[nodiscard]] std::string to_string() const {
        return fmt::format("Id={} nblks={} chunk={}", m_id, m_nblks, m_chunk_num);
    }
} __attribute__((__packed__));

[[nodiscard]] inline uint64_t begin_of(const BlkId& bid) { return bid.get_id(); }
[[nodiscard]] inline uint64_t end_of(const BlkId& bid) { return bid.get_id() + bid.get_nblks(); }

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

constexpr uint32_t BLKID32_INVALID{std::numeric_limits< uint32_t >::max()};
constexpr uint64_t BLKID64_INVALID{std::numeric_limits< uint64_t >::max()};

using blkid_list_ptr = std::shared_ptr< sisl::ThreadVector< BlkId > >;
} // namespace homestore

// hash function definitions
namespace std {
template <>
struct hash<homestore::BlkId > {
    typedef homestore::BlkId argument_type;
    typedef size_t           result_type;
    result_type operator()(const argument_type& bid) const noexcept {
        return std::hash<uint64_t>()(bid.to_integer());
    }
};
} // namespace std

#endif /* SRC_BLKALLOC_BLK_H_ */
