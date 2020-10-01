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
    uint64_t m_id : ID_BITS;               // Block number which is unique within the chunk
    uint64_t m_nblks : NBLKS_BITS;         // Total number of blocks starting from previous block number
    uint64_t m_chunk_num : CHUNK_NUM_BITS; // Chunk number - which is unique for the entire application
    uint64_t m_rest : 64 - ID_BITS - NBLKS_BITS - CHUNK_NUM_BITS;

    // make these constexpr after rolling in sisl update
    [[nodicard]] static uint64_t constexpr invalid_internal_id() {
        return (static_cast< uint64_t >(1) << (ID_BITS + NBLKS_BITS + CHUNK_NUM_BITS)) - 1;
    }

    [[nodicard]] static uint64_t constexpr max_blks_in_op() { return s_nblks_mask; }

    // NOTE:  These functions below should be replace by a std::hash operator since that is their purpose
    [[nodicard]] static sisl::blob get_blob(BlkId& id) {
        static thread_local std::array< uint8_t, BLKID_SIZE > blob_array;
        const uint64_t val{id.to_integer()};
        uint8_t shift{0};
        for (uint8_t byte_num{0}; byte_num < BLKID_SIZE; ++byte_num, shift += 8) {
            blob_array[byte_num] = static_cast< uint8_t >((val >> shift) & 0xFF);
        }
        sisl::blob b{blob_array.data(), blob_array.size()};
        return b;
    }

    [[nodicard]] static sisl::blob get_blob(const BlkId& id) {
        static thread_local std::array< uint8_t, BLKID_SIZE > blob_array;
        const uint64_t val{id.to_integer()};
        uint8_t shift{0};
        for (uint8_t byte_num{0}; byte_num < BLKID_SIZE; ++byte_num, shift += 8) {
            blob_array[byte_num] = static_cast< uint8_t >((val >> shift) & 0xFF);
        }
        sisl::blob b{blob_array.data(), blob_array.size()};
        return b;
    }

#define begin_of(b) (b.m_id)
#define end_of(b) (b.m_id + b.m_nblks)

    [[nodicard]] static int compare(const BlkId& one, const BlkId& two) {
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

    [[nodicard]] uint64_t to_integer() const {
        const uint64_t val{m_id | (static_cast< uint64_t >(m_nblks) << ID_BITS) |
                           (static_cast< uint64_t >(m_chunk_num) << (ID_BITS + NBLKS_BITS))};
        return val;
    }

    explicit BlkId(const uint64_t id) {
        set(id & s_id_mask, (id >> ID_BITS) & s_nblks_mask, id >> (ID_BITS + NBLKS_BITS) & s_chuck_num_mask);
    }

    BlkId(const uint64_t id, const uint8_t nblks, const uint16_t chunk_num = 0) { set(id, nblks, chunk_num); }

    BlkId() {
        set(std::numeric_limits< uint64_t >::max(), std::numeric_limits< uint8_t >::max(),
            std::numeric_limits< uint16_t >::max());
    }

    [[nodiscard]] BlkId get_blkid_at(const uint32_t offset, const uint32_t pagesz) const {
        assert(offset % pagesz == 0);
        uint32_t remaining_size = ((m_nblks - (offset / pagesz)) * pagesz);
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
        m_id = id;
        m_nblks = nblks;
        m_chunk_num = chunk_num;
    }

    void set(const BlkId& bid) { set(bid.get_id(), bid.get_nblks(), bid.get_chunk_num()); }

    void set(const uint64_t bid) { set(bid, bid >> ID_BITS, bid >> (ID_BITS + CHUNK_NUM_BITS)); }

    void set_id(const uint64_t id) { m_id = id; }

    [[nodiscard]] uint64_t get_id() const { return m_id; }

    void set_nblks(const uint8_t nblks) { m_nblks = nblks; }

    [[nodiscard]] uint8_t get_nblks() const { return m_nblks; }

    [[nodiscard]] uint16_t get_chunk_num() const { return m_chunk_num; }

    /* A blkID represent a page size which is assigned to a blk allocator */
    [[nodiscard]] uint32_t data_size(const uint32_t page_size) const { return (m_nblks * page_size); }

    [[nodiscard]] std::string to_string() const {
        return fmt::format("Id={} nblks={} chunk={}", m_id, m_nblks, m_chunk_num);
    }

} // namespace homestore
__attribute__((__packed__));

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
#if 0
struct SingleBlk {
    BlkId m_blk_id;
    uint32_t  m_nblks;
    homeds::MemVector < 1 > m_mem;

    SingleBlk(uint64_t id, uint16_t chunk_num, uint32_t size) :
            m_blk_id(id, chunk_num),
            m_nblks(size) {}
    explicit SingleBlk(BlkId bid) :
            m_blk_id(bid),
            m_nblks(0) {
    }
    SingleBlk() : SingleBlk((uint64_t)-1, (uint16_t)-1, 0) {}

    BlkId get_id() const {
        return m_blk_id;
    }

    void set_id(uint64_t id, uint16_t chunk_num) {
        m_blk_id.set(id, chunk_num);
    }

    void set_id(const BlkId bid) {
        m_blk_id.m_internal_id = bid.m_internal_id;
    }

    homeds::MemVector<1> &get_mem() {
        return m_mem;
    }

    const homeds::MemVector<1> &get_mem_const() const {
        return m_mem;
    }

    void set_mem(sisl::blob b) {
        m_mem.set_piece(b);
    }

    uint32_t get_size() const {
        return m_nblks;
    }

    void set_size(uint32_t size) {
        m_nblks = size;
    }
};

#define EXPECTED_BLK_PIECES 1
#define EXPECTED_MEM_PIECE_PER_BLK 2

struct MemPiece {
    const uint8_t *m_mem;
    uint32_t m_nblks;

    MemPiece(const uint8_t *mem, uint32_t sz) {
        m_mem = mem; m_nblks = sz;
    }
};

class BlkPiece {
private:
    blkid64_t m_blk_id;
    uint32_t  m_nblks;   // Its actual size in this piece. Note: This can be more than pageSize

    uint32_t m_bufsize;
    homeds::FlexArray< MemPiece, EXPECTED_MEM_PIECE_PER_BLK > m_bufs;

public:
    BlkPiece(blkid64_t id, uint32_t size, uint8_t *mem) :
            m_blk_id(id),
            m_nblks(size),
            m_bufsize(size) {
        MemPiece m(mem, size);
        m_bufs.push_back(m);
    }

    BlkPiece(blkid64_t id, uint32_t size) :
            m_blk_id(id),
            m_nblks(size) {
        m_bufsize = 0;
    }

    BlkPiece() : BlkPiece(BLKID64_INVALID, 0, nullptr) {}

    void set_blk_id(blkid64_t id) {
        m_blk_id = id;
    }

    void set_size(uint32_t size) {
        m_nblks = size;
    }

    void set_buf(const uint8_t *mem, uint32_t mem_size) {
        assert(mem_size == m_nblks);
        assert(m_bufs.size() == 0);

        MemPiece m(mem, mem_size);
        m_bufs.push_back(m);
    }

    void add_buf(uint8_t *mem, uint32_t mem_size) {
        m_bufsize += mem_size;

        MemPiece m(mem, mem_size);
        m_bufs.push_back(m);
    }

    uint32_t get_size() const {
        return m_nblks;
    }

    blkid64_t get_blk_id() const {
        return m_blk_id;
    }

    uint32_t get_buf(uint8_t **mem) const {
        return 0;
    }
};

//#define toDynPieceNum(np) (np - MAX_STATIC_BLK_PIECES)
#define total_piece_size(np, b) ((np)*b->getSizeofPiece())

//#define dynPieceSize(np)  ((toDynPieceNum(np) - 1)/DYNAMIC_BLK_PIECE_CHUNK + 1) *


/* A Blk class represents a single cohesive unit of data we exchange. It could be
 * either in memory or ssd or anything in future. Underneath it can have multiple
 * pieces to form one unit, however allocation and freeing all happens as one unit.
 */
class Blk {
private:
    homeds::FlexArray< BlkPiece, EXPECTED_BLK_PIECES > m_pieces;

protected:
    homeds::FlexArray< BlkPiece, EXPECTED_BLK_PIECES > &get_pieces() {
        return m_pieces;
    }

public:
    Blk() = default;
    Blk(BlkPiece &piece) {
        add_piece(piece);
    }

    uint16_t get_npieces() {
        return m_pieces.size();
    }

    template< class... Args >
    uint32_t emplace_piece(Args &&... args) {
        return m_pieces.emplace_back(std::forward<Args>(args)...);
    }

    uint32_t add_piece(BlkPiece &piece) {
        return m_pieces.push_back(piece);
    }

    void merge(Blk &other) {
        for (auto i = 0; i < other.get_npieces(); i++) {
            add_piece(other.get_piece(i));
        }
    }

    virtual uint32_t get_total_size() {
        uint32_t size = 0;
        for (auto i = 0; i < m_pieces.size(); i++) {
            size += get_piece(i).get_size();
        }
        return size;
    }

    BlkPiece &get_piece(uint32_t num) {
        return m_pieces[num];
    }
};
#endif
} // namespace homestore
#endif /* SRC_BLKALLOC_BLK_H_ */
