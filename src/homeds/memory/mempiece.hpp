//
// Created by Kadayam, Hari on 27/10/17.
//

#ifndef OMSTORE_MEMPIECE_HPP
#define OMSTORE_MEMPIECE_HPP

#include "tagged_ptr.hpp"
#include "homeds/utility/useful_defs.hpp"
#include <vector>
#include <cassert>
#include <cstdint>
#include <boost/optional.hpp>
#include <sstream>
#include <mutex>

namespace homeds {
#define round_off(val, rnd) ((((val)-1)/(rnd)) + 1)

#if 0
#define FIRST_8BITS(n)    (n & 0x00ff)

#define gen_new_tag(size, offset) ((LeftShifts<8>()[encode(offset)]) | encode(size))
#define set_offset_in_tag(tag, offset) ((LeftShifts<8>()[encode(offset)]) | FIRST_8BITS(tag))
#define set_size_in_tag(tag, size) (((tag) & 0xff00) | encode(size))
#define get_offset_in_tag(tag) (actual_size(((tag) & 0xff00) >> 8))
#define get_size_in_tag(tag)  (actual_size((tag) & 0xff))
#endif

struct __attribute__((__may_alias__)) __mempiece_tag {
    uint16_t m_size:8;       /* Size shrinked by SizeMultipler */
    uint16_t m_offset:8;     /* Offset within the mem piece */

    uint16_t to_integer() {
        return *((uint16_t *)this);
    }
} __attribute((packed));

template <int SizeMultiplier>
struct MemPiece {
    homeds::tagged_ptr<uint8_t> m_mem;

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

    std::string to_string() const {
        std::stringstream ss; ss << "ptr = " << (void *)ptr() << " size = " << size() << " offset = " << offset();
        return ss.str();
    }
private:
    uint16_t gen_new_tag(uint32_t size, uint8_t offset) const {
        __mempiece_tag t;
        t.m_size = size; t.m_offset = offset;
        return t.to_integer();
    }

    __mempiece_tag get_tag() const {
        uint16_t i = m_mem.get_tag();
        return *reinterpret_cast<__mempiece_tag *>(&i);
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
    std::vector< MemPiece< SizeMultiplier > > m_list;
    mutable std::mutex m_mtx;

public:
    MemVector(uint8_t *ptr, uint32_t size, uint32_t offset) :
            m_list(), m_mtx() {
        MemPiece< SizeMultiplier > m(ptr, size, offset);
        m_list.push_back(m);
        assert(size || (ptr == nullptr));
    }

    MemVector() : m_list(), m_mtx() {}

    ~MemVector() {
            m_list.erase(m_list.begin(), m_list.end());
    }

    std::vector< MemPiece< SizeMultiplier > > get_m_list() const {
        return m_list;
    }
    void copy(const MemVector &other) {
        m_list = other.get_m_list();
    }
    uint32_t npieces() const {
        return (m_list.size());
    }

    void set(uint8_t *ptr, uint32_t size, uint32_t offset) {
        std::unique_lock<std::mutex> mtx(m_mtx);
        m_list.erase(m_list.begin(), m_list.end());
        MemPiece< SizeMultiplier > m(ptr, size, offset);
        m_list.push_back(m);
    }

    void set(const homeds::blob &b, uint32_t offset = 0) {
        set(b.bytes, b.size, offset);
    }

    void free_all_mem_pieces() {
        for (auto i = 0u; i < m_list.size(); i++) {
            free(m_list[i].ptr());
        }
    }

    void get(homeds::blob *outb, uint32_t offset = 0) const {
        uint32_t ind = 0;
        std::unique_lock<std::mutex> mtx(m_mtx);
        if ((m_list.size() && bsearch(offset, -1, &ind))) {
            auto piece_offset = m_list.at(ind).offset();
            assert(piece_offset <= offset);
            uint32_t delta = offset - piece_offset;
            assert(delta < m_list.at(ind).size());
            outb->bytes = m_list.at(ind).ptr() + delta;
            outb->size  = m_list.at(ind).size() - delta;
        } else {
            assert(0);
        }
    }

    const MemPiece<SizeMultiplier> &get_nth_piece(uint8_t nth) const {
        if (nth < m_list.size()) {
            return m_list.at(nth);
        } else {
            assert(0);
            return m_list.at(0);
        }
    }

    MemPiece<SizeMultiplier> &get_nth_piece_mutable(uint8_t nth) const {
        if (nth < m_list.size()) {
            return m_list->at(nth);
        } else {
            assert(0);
            return m_list.at(0);
        }
    }

    std::string to_string() const {
        auto n = npieces();
        std::stringstream ss;

        if (n > 1) ss << "Pieces = " << n << "\n";
        for (auto i = 0U; i < n; i++) {
            auto &p = get_nth_piece(i);
            ss << "MemPiece[" << i << "]: " << p.to_string() << ((n > 1) ? "\n" : "");
        }
        return ss.str();
    }

    /* This method will try to set or append the offset to the memory piece. However, if there is already an entry
     * within reach for given offset/size, it will reject the entry and return false. Else it sets or adds the entry */
    bool append(uint8_t *ptr, uint32_t offset, uint32_t size) {
        std::unique_lock<std::mutex> mtx(m_mtx);
        bool added = false;
        MemPiece<SizeMultiplier> mp(ptr, size, offset);
        added = add_piece_to_list(mp);
        return added;
    }

    void push_back(const MemPiece<SizeMultiplier> &piece) {
            m_list.push_back(piece);
    }

    MemPiece<SizeMultiplier> &insert_at(uint32_t ind, const MemPiece<SizeMultiplier> &piece) {
            assert(ind <= m_list.size());
            auto it = m_list.emplace((m_list.begin() + ind), piece);
            return *it;
    }

    MemPiece<SizeMultiplier> &insert_at(uint32_t ind, uint8_t *ptr, uint32_t size, uint32_t offset) {
        auto mp = MemPiece<SizeMultiplier>(ptr, size, offset);
        return insert_at(ind, mp);
    }

    uint32_t size() const {
        uint32_t s = 0;
        for(auto it = m_list.begin(); it < m_list.end(); ++it) {
                    s += (*it).size();
        }
        return s;
    }

    bool find_index(uint32_t offset, boost::optional<int> ind_hint, uint32_t *out_ind) const {
        *out_ind = 0;
        return (bsearch(offset, ind_hint.get_value_or(-1), out_ind));
    }

    struct cursor_t {
        cursor_t() : m_ind(-1) {}
        int m_ind;
    };

    /* TODO :- mempeices are not protected by lock. We might need to take a lock
     * if there are multiple reads happening on a same blkid.
     */

    boost::optional< MemPiece<SizeMultiplier> &> fill_next_missing_piece(cursor_t &c, uint32_t size, uint32_t offset) {
        uint32_t new_ind;
        std::unique_lock<std::mutex> mtx(m_mtx);
        bool found = find_index(offset, c.m_ind, &new_ind);
        c.m_ind = new_ind;

        while (found) {
            // If we have already the offset in our piece, check if we really miss a piece.
            auto &mp = get_nth_piece(new_ind);
            if ((offset + size) <= mp.end_offset()) {
                // No missing piece
                return boost::none;
            }
            size = size - (mp.end_offset() - offset);
            offset = mp.end_offset(); // Move the offset to the start of next mp.
            found = find_index(offset, (uint8_t)c.m_ind, &new_ind);
            c.m_ind = new_ind;
        }

        uint32_t sz;
        if (new_ind < npieces()) {
            auto &mp = get_nth_piece(new_ind);
            sz = mp.offset() - offset;
            //assert(sz <= size);
        } else {
            // This is the last item in the vector, just fill the size
            sz = size;
        }

        auto &mp = insert_at(new_ind, nullptr, sz, offset);
        return mp;
    }

private:
    bool add_piece_to_list(const MemPiece<SizeMultiplier> &mp) {

        uint32_t ind;
        // If we found an offset in search we got to fail the add
        if (bsearch(mp.offset(), -1, &ind)) {
            return false;
        }

        // If we overlap with the next entry where it is to be inserted, fail the add
        if ((ind < m_list.size()) && (mp.end_offset() > m_list.at(ind).offset())) {
            return false;
        }

        m_list.emplace((m_list.begin() + ind), mp);
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

    /* it return the first index which is greater then or equal to offset. 
     * If is more then the last element in m_list.size() then it 
     * return m_list.size(). If it is smaller then first element, it return 
     * zero.
     */
    bool bsearch(uint32_t offset, int start, uint32_t *out_ind) const {
        int end = m_list.size();
        uint32_t mid = 0;

        while ((end - start) > 1) {
            mid = start + (end - start) / 2;
            int x = compare(offset, m_list.at(mid));
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
