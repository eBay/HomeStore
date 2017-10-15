/*
 * blk.h
 *
 *  Created on: 03-Nov-2016
 *      Author: hkadayam
 */

#ifndef SRC_BLKALLOC_BLK_H_
#define SRC_BLKALLOC_BLK_H_

#include <iostream>
#include <assert.h>
#include "omds/array/flexarray.hpp"

namespace omstorage {

typedef uint32_t blkid32_t;
typedef uint64_t blkid64_t;
#define BLKID32_INVALID ((blkid32_t)(-1))
#define BLKID64_INVALID ((blkid64_t)(-1))

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

    uint16_t m_offset; // Offset within the page
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

    void set_blk_id(blkid64_t id, uint32_t offset) {
        m_blk_id = id;
        m_offset = offset;
    }

    void set_size(uint32_t size) {
        m_size = size;
    }

    void set_offset(uint16_t off) {
        m_offset = off;
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

    uint16_t get_offset() const {
        return m_offset;
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
}
#endif /* SRC_BLKALLOC_BLK_H_ */
