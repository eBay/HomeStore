//
// Created by Kadayam, Hari on 27/10/17.
//

#ifndef OMSTORE_MEMPIECE_HPP
#define OMSTORE_MEMPIECE_HPP

#include "tagged_ptr.hpp"
#include "omds/utility/useful_defs.hpp"
#include <vector>
#include <cassert>

namespace omds {
#define round_off(val, rnd) ((((val)-1)/(rnd)) + 1)

template <int SizeMultiplier>
struct MemPiece {
    omds::tagged_ptr<uint8_t> m_mem;

    MemPiece(uint8_t *mem, uint32_t size) :
            m_mem(mem, (uint16_t)round_off(size, SizeMultiplier)) {}

    MemPiece() : MemPiece(nullptr, 0) {}

    void set_size(uint32_t size) {
        m_mem.set_tag((uint16_t)round_off(size, SizeMultiplier));
    }

    void set_ptr(uint8_t *ptr) {
        m_mem.set_ptr(ptr);
    }

    void set(uint8_t *ptr, uint32_t size) {
        m_mem.set(ptr, size);
    }

    int size() const {
        return m_mem.get_tag() * SizeMultiplier;
    }

    uint8_t *ptr() {
        return m_mem.get_ptr();
    }

    uint8_t *get(int *psize) {
        *psize = size();
        return ptr();
    }
} __attribute__((packed));

template <int SizeMultiplier>
struct MemPieces {
private:
    union u {
        u(uint8_t *ptr, uint32_t size) : m_piece(ptr, size) {}
        MemPiece< SizeMultiplier > m_piece;
        std::vector< MemPiece< SizeMultiplier > > *m_list;
    } m_u;

public:
    MemPieces(uint8_t *ptr, uint32_t size) :
            m_u(ptr, size) {
        assert(size || (ptr == nullptr));
    }
    MemPieces() : m_u(nullptr, 0) {}

    ~MemPieces() {
        if (m_u.m_piece.size() == 0) {
            if (m_u.m_list) {
                delete(m_u.m_list);
            }
        }
    }
    int npieces() const {
        if (m_u.m_piece.size() == 0) {
            return m_u.m_list ? m_u.m_list->size() : 0;
        } else {
            return 1;
        }
    }

    void set_piece(uint8_t *ptr, uint32_t size) {
        m_u.m_piece.set(ptr, size);
    }

    void set_piece(omds::blob &b) {
        set_piece(b.bytes, b.size);
    }

    void add_piece(uint8_t *ptr, uint32_t size) {
        if (m_u.m_piece.size() != 0) {
            // First move the current item to the list
            add_piece_to_list(m_u.m_piece.ptr(), m_u.m_piece.size());
            m_u.m_piece.set_size(0);
        }
        add_piece_to_list(ptr, size);
    }

    uint32_t size() const {
        auto s = m_u.m_piece.size();

        if (s == 0) {
            if (m_u.m_list != nullptr) {
                for (auto &p : *(m_u.m_list)) {
                    s += p.size();
                }
            }
        }
        return s;
    }

private:
    void add_piece_to_list(uint8_t *ptr, uint32_t size) {
        if (m_u.m_list == nullptr) {
            m_u.m_list = new std::vector< MemPiece< SizeMultiplier > >();
        }

        (*m_u.m_list).emplace_back(ptr, size);
    }
};
}
#endif //OMSTORE_MEMPIECE_HPP
