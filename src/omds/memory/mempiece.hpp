//
// Created by Kadayam, Hari on 27/10/17.
//

#ifndef OMSTORE_MEMPIECE_HPP
#define OMSTORE_MEMPIECE_HPP

#include "tagged_ptr.hpp"
#include "omds/utility/useful_defs.hpp"
#include <vector>
#include <cassert>
#include <cstdint>
#include <boost/optional.hpp>

namespace omds {
#define round_off(val, rnd) ((((val)-1)/(rnd)) + 1)

#if 0
#define FIRST_8BITS(n)    (n & 0x00ff)

#define gen_new_tag(size, offset) ((LeftShifts<8>()[encode(offset)]) | encode(size))
#define set_offset_in_tag(tag, offset) ((LeftShifts<8>()[encode(offset)]) | FIRST_8BITS(tag))
#define set_size_in_tag(tag, size) (((tag) & 0xff00) | encode(size))
#define get_offset_in_tag(tag) (actual_size(((tag) & 0xff00) >> 8))
#define get_size_in_tag(tag)  (actual_size((tag) & 0xff))
#endif

struct __mempiece_tag {
    uint16_t m_size:8;       /* Size shrinked by SizeMultipler */
    uint16_t m_offset:8;     /* Offset within the mem piece */

    uint16_t to_integer() {
        return *((uint16_t *)this);
    }
} __attribute((packed));

template <int SizeMultiplier>
struct MemPiece {
    omds::tagged_ptr<uint8_t> m_mem;

    MemPiece(uint8_t *mem, uint32_t size, uint32_t offset) :
            m_mem(mem, (uint16_t)gen_new_tag(encode(size), encode(offset))) {}

    MemPiece() : MemPiece(nullptr, 0, 0) {}
    MemPiece(const MemPiece &other) : m_mem(other.m_mem) {}

    void set_ptr(uint8_t *ptr) {
        m_mem.set_ptr(ptr);
    }

    void set_size(uint32_t size) {
        __mempiece_tag t = get_tag();
        t.m_size = encode(size);
        set_tag(t);
    }

    void set_offset(uint32_t offset) {
        __mempiece_tag t = get_tag();
        t.m_offset = encode(offset);
        set_tag(t);
    }

    void reset() {
        set(nullptr, 0, 0);
    }

    void set(uint8_t *ptr, uint32_t size, uint32_t offset) {
        __mempiece_tag t;
        t.m_size = encode(size);
        t.m_offset = encode(offset);
        m_mem.set(ptr, t.to_integer());
    }

    uint8_t *ptr() const {
        return m_mem.get_ptr();
    }

    uint32_t size() const {
        return (decode(get_tag().m_size));
    }

    uint32_t offset() const {
        return (decode(get_tag().m_offset));
    }

    uint32_t end_offset() const {
        __mempiece_tag t = get_tag();
        return decode(t.m_size + t.m_offset);
    }

    uint8_t *get(uint32_t *psize, uint8_t *poff) const {
        *psize = size();
        *poff = offset();
        return ptr();
    }

private:
    uint16_t gen_new_tag(uint32_t size, uint8_t offset) const {
        __mempiece_tag t;
        t.m_size = size; t.m_offset = offset;
        return t.to_integer();
    }

    __mempiece_tag get_tag() const {
        uint16_t i = m_mem.get_tag();
        return (*(__mempiece_tag *)&i);
    }

    void set_tag(__mempiece_tag t) {
        m_mem.set_tag(t.to_integer());
    }

    uint32_t decode(uint8_t encoded_size) const {
        return (encoded_size * SizeMultiplier);
    }

    uint8_t encode(uint32_t size) const {
        return round_off(size, SizeMultiplier);
    }
} __attribute__((packed));

template <int SizeMultiplier = 8192>
struct MemVector {
private:
    union u {
        u(uint8_t *ptr, uint32_t size, uint32_t offset) : m_piece(ptr, size, offset) {}

        MemPiece< SizeMultiplier > m_piece;
        std::vector< MemPiece< SizeMultiplier > > *m_list;
    } m_u;

public:
    MemVector(uint8_t *ptr, uint32_t size, uint32_t offset) :
            m_u(ptr, size, offset) {
        assert(size || (ptr == nullptr));
    }

    MemVector() : m_u(nullptr, 0, 0) {}

    ~MemVector() {
        if (m_u.m_piece.size() == 0) {
            if (m_u.m_list) {
                delete (m_u.m_list);
            }
        }
    }

    uint32_t npieces() const {
        if (m_u.m_piece.size() == 0) {
            return m_u.m_list ? m_u.m_list->size() : 0;
        } else {
            return 1;
        }
    }

    void set(uint8_t *ptr, uint32_t size, uint32_t offset) {
        if (m_u.m_piece.size() == 0) {
            if (m_u.m_list) {
                delete (m_u.m_list);
            }
        }
        m_u.m_piece.set(ptr, size, offset);
    }

    void set(const omds::blob &b, uint32_t offset = 0) {
        set(b.bytes, b.size, offset);
    }

    void get(omds::blob *outb, uint32_t offset = 0) const {
        uint32_t piece_size = m_u.m_piece.size();
        uint32_t piece_offset;
        int ind;

        outb->bytes = nullptr; outb->size = 0;
        if (piece_size != 0) {
            piece_offset = m_u.m_piece.offset();
            if ((offset >= piece_offset) && (offset < (piece_offset + piece_size))) {
                uint32_t delta = offset - piece_offset;
                outb->bytes = m_u.m_piece.ptr() + delta;
                outb->size  = piece_size - delta;
            }
        } else if ((m_u.m_list && bsearch(offset, -1, &ind))) {
            piece_offset = m_u.m_list->at(ind).offset();
            uint32_t delta = offset - piece_offset;
            outb->bytes = m_u.m_list->at(ind).ptr() + delta;
            outb->size  = m_u.m_list->at(ind).size() - delta;
        }
    }

    const MemPiece<SizeMultiplier> &get_nth_piece(uint8_t nth) const {
        if ((m_u.m_piece.size() == 0) && m_u.m_list) {
            assert(nth < m_u.m_list->size());
            return m_u.m_list->at(nth);
        } else {
            return m_u.m_piece;
        }
    }

    MemPiece<SizeMultiplier> &get_nth_piece_mutable(uint8_t nth) const {
        if ((m_u.m_piece.size() == 0) && m_u.m_list) {
            assert(nth < m_u.m_list->size());
            return m_u.m_list->at(nth);
        } else {
            return m_u.m_piece;
        }
    }

    /* This method will try to set or append the offset to the memory piece. However, if there is already an entry
     * within reach for given offset/size, it will reject the entry and return false. Else it sets or adds the entry */
    bool append(uint8_t *ptr, uint32_t offset, uint32_t size) {
        bool added = false;
        if (m_u.m_piece.size() != 0) {
            if (compare(offset, m_u.m_piece) == 0) {
                return added;
            }

            // First move the current item to the list
            MemPiece<SizeMultiplier> mp(m_u.m_piece.ptr(), m_u.m_piece.size(), m_u.m_piece.offset());
            m_u.m_piece.reset();
            added = add_piece_to_list(mp);
            assert(added);
            m_u.m_piece.set_size(0);
        }

        MemPiece<SizeMultiplier> mp(ptr, size, offset);
        added = add_piece_to_list(mp);
        return added;
    }

    void push_back(const MemPiece<SizeMultiplier> &piece) {
        if ((m_u.m_piece.size() == 0) && (m_u.m_list == nullptr)) {
            // First entry add to the in-core structure
            m_u.m_piece = piece;
        } else {
            if (m_u.m_list == nullptr) {
                auto mp = m_u.m_piece;
                m_u.m_list = new std::vector< MemPiece< SizeMultiplier > >();
                m_u.m_list->push_back(mp);
            }
            m_u.m_list->push_back(piece);
        }
    }

    MemPiece<SizeMultiplier> &insert_at(uint32_t ind, const MemPiece<SizeMultiplier> &piece) {
        if ((m_u.m_piece.size() == 0) && (m_u.m_list == nullptr)) {
            assert(ind == 0);
            m_u.m_piece = piece;
            return m_u.m_piece;
        } else {
            if (m_u.m_list == nullptr) {
                auto mp = m_u.m_piece;
                m_u.m_list = new std::vector< MemPiece< SizeMultiplier > >();
                m_u.m_list->push_back(mp);
            }
            auto it = m_u.m_list->emplace((m_u.m_list->begin() + ind), piece);
            return *it;
        }
    }

    MemPiece<SizeMultiplier> &insert_at(uint32_t ind, uint8_t *ptr, uint32_t size, uint32_t offset) {
        auto mp = MemPiece<SizeMultiplier>(ptr, size, offset);
        return insert_at(ind, mp);
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

    bool find_index(uint32_t offset, boost::optional<uint8_t> ind_hint, int *out_ind) const {
        *out_ind = 0;
        return (!m_u.m_piece.size() && m_u.m_list) ?
               bsearch(offset, ind_hint.get_value_or(-1), out_ind) :
               ((offset >= m_u.m_piece.offset()) && (offset < m_u.m_piece.size()));
    }

    struct cursor_t {
        cursor_t() : m_ind(-1) {}
        int m_ind;
    };

    boost::optional< MemPiece<SizeMultiplier> &> fill_next_missing_piece(cursor_t &c, uint32_t offset, uint32_t size) {
        int new_ind;
        bool found = find_index(offset, (uint8_t)c.m_ind, &new_ind);
        c.m_ind = new_ind;

        if (found) {
            // If we have already the offset in our piece, check if we really miss a piece.
            auto &mp = get_nth_piece(new_ind);
            if ((offset + size) <= mp.end_offset()) {
                // No missing piece
                return boost::none;
            }
            offset = mp.end_offset(); // Move the offset to the start of next mp.
        }

        uint32_t sz;
        if (new_ind+1 < npieces()) {
            auto &mp = get_nth_piece(new_ind+1);
            sz = mp.offset() - offset;
            assert(sz <= size);
        } else {
            // This is the last item in the vector, just fill the size
            sz = size - offset;
        }

        auto &mp = insert_at(new_ind, nullptr, offset, sz);
        return mp;
    }

private:
    bool add_piece_to_list(const MemPiece<SizeMultiplier> &mp) {
        if (m_u.m_list == nullptr) {
            m_u.m_list = new std::vector< MemPiece < SizeMultiplier > >();
        }

        int ind;
        // If we found an offset in search we got to fail the add
        if (bsearch(mp.offset(), -1, &ind)) {
            return false;
        }

        // If we overlap with the next entry where it is to be inserted, fail the add
        if ((ind < m_u.m_list->size()) && (mp.end_offset() > m_u.m_list->at(ind).offset())) {
            return false;
        }

        (*m_u.m_list).emplace((m_u.m_list->begin() + ind), mp);
        return true;
    }

    int compare(uint32_t search_offset, const MemPiece<SizeMultiplier> &mp) const {
        auto mp_offset = mp.offset();
        if (search_offset == mp_offset) {
            return 0;
        } else if (search_offset < mp_offset) {
            return 1;
        } else {
            return ((mp_offset + mp.size()) > search_offset) ? 0 /* Overlaps */ : -1;
        }
    }

    bool bsearch(uint32_t offset, int start, int *out_ind) const {
        int end = m_u.m_list->size();
        uint32_t mid = 0;

        while ((end - start) > 1) {
            mid = start + (end - start) / 2;
            int x = compare(offset, m_u.m_list->at(mid));
            if (x == 0) {
                *out_ind = mid;
                return true;
            } else if (x > 0) {
                end = mid;
            } else {
                start = mid;
            }
        }

        *out_ind = end;
        return false;
    }
};
}
#endif //OMSTORE_MEMPIECE_HPP
