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
#include "omds/array/flexarray.hpp"
#include "omds/memory/mempiece.hpp"
#include "omds/utility/useful_defs.hpp"
//#include "blkdev/blkdev.h"

namespace omstore {

struct blk_id {

    static uint8_t constexpr id_bits() { return 48;}
    static uint8_t constexpr chunk_bits() {return 64-id_bits();}

    static uint64_t constexpr invalid_internal_id() {
        return ((uint64_t)-1);
    }

    static omds::blob get_blob(const blk_id &id) {
        omds::blob b;
        b.bytes = (uint8_t *)&id.m_internal_id;
        b.size = sizeof(uint64_t);

        return b;
    }

    static int compare(const blk_id &one, const blk_id &two) {
        if (one.m_internal_id == two.m_internal_id) {
            return 0;
        } else if (one.m_internal_id > two.m_internal_id) {
            return -1;
        } else {
            return 1;
        }
    }

    blk_id(uint64_t id, uint16_t chunk_num)  {
        set(id, chunk_num);
    }

    blk_id() {
        m_internal_id = invalid_internal_id();
    }

    blk_id(const blk_id &other) {
        m_internal_id = other.m_internal_id;
    }

    blk_id &operator=(const blk_id &other) = default;

    void set(uint64_t id, uint16_t chunk_num) {
        m_internal_id = id | chunk_num<<chunk_bits();
    }

    uint64_t get_id() const {
        return m_internal_id & omds::get_mask<chunk_bits()>();
    }

    uint16_t get_chunk_id() const {
        return ((m_internal_id >> chunk_bits()) & omds::get_mask<id_bits()>());
    }

    uint64_t m_internal_id;
};

#define BLKID32_INVALID ((uint32_t)(-1))
#define BLKID64_INVALID ((uint64_t)(-1))

class PhysicalDevChunk;

struct SingleBlk {
    blk_id m_blk_id;
    uint32_t  m_size;
    omds::MemPieces < 1 > m_mem;

    SingleBlk(uint64_t id, uint16_t chunk_num, uint32_t size) :
            m_blk_id(id, chunk_num),
            m_size(size) {}
    explicit SingleBlk(blk_id bid) :
            m_blk_id(bid),
            m_size(0) {
    }
    SingleBlk() : SingleBlk((uint64_t)-1, (uint16_t)-1, 0) {}

    blk_id get_id() const {
        return m_blk_id;
    }

    void set_id(uint64_t id, uint16_t chunk_num) {
        m_blk_id.set(id, chunk_num);
    }

    void set_id(const blk_id bid) {
        m_blk_id.m_internal_id = bid.m_internal_id;
    }

    omds::MemPieces<1> &get_mem() {
        return m_mem;
    }

    const omds::MemPieces<1> &get_mem_const() const {
        return m_mem;
    }

    void set_mem(omds::blob b) {
        m_mem.set_piece(b);
    }

    uint32_t get_size() const {
        return m_size;
    }

    void set_size(uint32_t size) {
        m_size = size;
    }
};

#if 0
#define EXPECTED_BLK_PIECES        1
#define EXPECTED_MEM_PIECE_PER_BLK 2

struct MemPiece {
    const uint8_t *m_mem;
    uint32_t m_size;

    MemPiece(const uint8_t *mem, uint32_t sz) {
        m_mem = mem; m_size = sz;
    }
};

class BlkPiece {
private:
    blkid64_t m_blk_id;
    uint32_t  m_size;   // Its actual size in this piece. Note: This can be more than pageSize

    uint32_t m_bufsize;
    omds::FlexArray< MemPiece, EXPECTED_MEM_PIECE_PER_BLK > m_bufs;

public:
    BlkPiece(blkid64_t id, uint32_t size, uint8_t *mem) :
            m_blk_id(id),
            m_size(size),
            m_bufsize(size) {
        MemPiece m(mem, size);
        m_bufs.push_back(m);
    }

    BlkPiece(blkid64_t id, uint32_t size) :
            m_blk_id(id),
            m_size(size) {
        m_bufsize = 0;
    }

    BlkPiece() : BlkPiece(BLKID64_INVALID, 0, nullptr) {}

    void set_blk_id(blkid64_t id) {
        m_blk_id = id;
    }

    void set_size(uint32_t size) {
        m_size = size;
    }

    void set_buf(const uint8_t *mem, uint32_t mem_size) {
        assert(mem_size == m_size);
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
        return m_size;
    }

    blkid64_t get_blk_id() const {
        return m_blk_id;
    }

    uint32_t get_buf(uint8_t **mem) const {
        return 0;
    }
};

//#define toDynPieceNum(np) (np - MAX_STATIC_BLK_PIECES)
#define total_piece_size(np, b) ((np) * b->getSizeofPiece())

//#define dynPieceSize(np)  ((toDynPieceNum(np) - 1)/DYNAMIC_BLK_PIECE_CHUNK + 1) *


/* A Blk class represents a single cohesive unit of data we exchange. It could be
 * either in memory or ssd or anything in future. Underneath it can have multiple
 * pieces to form one unit, however allocation and freeing all happens as one unit.
 */
class Blk {
private:
    omds::FlexArray< BlkPiece, EXPECTED_BLK_PIECES > m_pieces;

protected:
    omds::FlexArray< BlkPiece, EXPECTED_BLK_PIECES > &get_pieces() {
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
}
#endif /* SRC_BLKALLOC_BLK_H_ */
