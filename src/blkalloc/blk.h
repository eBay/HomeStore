/*
 * blk.h
 *
 *  Created on: 03-Nov-2016
 *      Author: hkadayam
 */

#ifndef SRC_BLKALLOC_BLK_H_
#define SRC_BLKALLOC_BLK_H_

#include <iostream>
#include <cassert>
#include <sstream>
#include <cstring>
#include "homeds/array/flexarray.hpp"
#include "homeds/memory/mempiece.hpp"
#include "homeds/utility/useful_defs.hpp"
#include "main/homestore_config.hpp"

//#include "device/device.h"

namespace homestore {

/* This structure represents the application wide unique block number. It also encomposses the number of blks. */

struct BlkId {
    uint64_t m_id : ID_BITS;               // Block number which is unique within the chunk
    uint64_t m_nblks : NBLKS_BITS;         // Total number of blocks starting from previous block number
    uint64_t m_chunk_num : CHUNK_NUM_BITS; // Chunk number - which is unique for the entire application

    static uint64_t invalid_internal_id() { return ((1ul << (BLKID_SIZE_BITS)) - 1); }

    static uint64_t constexpr max_blks_in_op() { return (uint64_t)(homeds::pow(2, NBLKS_BITS)); }

    static homeds::blob get_blob(const BlkId& id) {
        homeds::blob b;
        b.bytes = (uint8_t*)&id;
        b.size = BLKID_SIZE;

        return b;
    }

#define begin_of(b) (b.m_id)
#define end_of(b) (b.m_id + b.m_nblks)

    static int compare(const BlkId& one, const BlkId& two) {
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

    uint64_t to_integer() const {
        uint64_t i = 0;
        std::memcpy(&i, (const uint64_t*)this, sizeof(BlkId));
        return i;
    }

    explicit BlkId(uint64_t id) { set(id, id >> ID_BITS, id >> (ID_BITS + CHUNK_NUM_BITS)); }

    BlkId(uint64_t id, uint8_t nblks, uint16_t chunk_num = 0) { set(id, nblks, chunk_num); }

    BlkId() { set(UINT64_MAX, UINT8_MAX, UINT16_MAX); }

    BlkId(BlkId& other) = default;
    BlkId get_blkid_at(uint32_t offset, uint32_t pagesz) const {
        assert(offset % pagesz == 0);
        uint32_t remaining_size = ((m_nblks - (offset / pagesz)) * pagesz);
        return (get_blkid_at(offset, remaining_size, pagesz));
    }

    BlkId get_blkid_at(uint32_t offset, uint32_t size, uint32_t pagesz) const {
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

    BlkId(const BlkId& other) = default;
    BlkId& operator=(const BlkId& other) = default;

    void set(uint64_t id, uint8_t nblks, uint16_t chunk_num = 0) {
        m_id = id;
        m_nblks = nblks;
        m_chunk_num = chunk_num;
    }

    void set(BlkId& bid) { set(bid.get_id(), bid.get_nblks(), bid.get_chunk_num()); }

    void set(uint64_t bid) { set(bid, bid >> ID_BITS, bid >> (ID_BITS + CHUNK_NUM_BITS)); }

    void set_id(uint64_t id) { m_id = id; }

    uint64_t get_id() const { return m_id; }

    void set_nblks(uint8_t nblks) { m_nblks = nblks; }

    uint8_t get_nblks() const { return m_nblks; }

    uint16_t get_chunk_num() const { return m_chunk_num; }

    /* A blkID represent a page size which is assigned to a blk allocator */
    uint32_t data_size(uint32_t page_size) const { return (m_nblks * page_size); }

    std::string to_string() const {
        std::stringstream ss;
        ss << "Bid=" << m_id << " nblks=" << (uint32_t)m_nblks << " chunk=" << (uint32_t)m_chunk_num;
        return ss.str();
    }
    friend std::ostream& operator<<(std::ostream& os, const BlkId& ve) {
        os << ve.to_string();
        return os;
    }
} __attribute__((__packed__));

#define BLKID32_INVALID ((uint32_t)(-1))
#define BLKID64_INVALID ((uint64_t)(-1))

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

    void set_mem(homeds::blob b) {
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
