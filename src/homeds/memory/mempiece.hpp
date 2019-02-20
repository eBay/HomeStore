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
#include <utility/atomic_counter.hpp>
#include <atomic>
#include <main/homestore_config.hpp>
#include <utility/obj_life_counter.hpp>

namespace homeds {
using namespace homestore;
#define round_off(val, rnd) ((((val)-1) / (rnd)) + 1)

#if 0
#define FIRST_8BITS(n) (n & 0x00ff)

#define gen_new_tag(size, offset) ((LeftShifts< 8 >()[encode(offset)]) | encode(size))
#define set_offset_in_tag(tag, offset) ((LeftShifts< 8 >()[encode(offset)]) | FIRST_8BITS(tag))
#define set_size_in_tag(tag, size) (((tag)&0xff00) | encode(size))
#define get_offset_in_tag(tag) (actual_size(((tag)&0xff00) >> 8))
#define get_size_in_tag(tag) (actual_size((tag)&0xff))
#endif

struct __attribute__((__may_alias__)) __mempiece_tag {
    uint16_t m_size : 8;   /* Size shrinked by SizeMultipler */
    uint16_t m_offset : 8; /* Offset within the mem piece */

    uint16_t to_integer() { return *((uint16_t*)this); }
} __attribute((packed));

constexpr int SizeMultiplier = 4096;

struct MemPiece : public sisl::ObjLifeCounter< MemPiece > {
    homeds::tagged_ptr<uint8_t> m_mem;

    MemPiece(uint8_t *mem, uint32_t size, uint32_t offset) :
            ObjLifeCounter(), m_mem(mem, (uint16_t)gen_new_tag(encode(size), encode(offset))) {}

    MemPiece() : MemPiece(nullptr, 0, 0) {}
    MemPiece(const MemPiece &other) : ObjLifeCounter(), m_mem(other.m_mem) {}
    ~MemPiece() {}

    void set_ptr(uint8_t* ptr) { m_mem.set_ptr(ptr); }

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

    void reset() { set(nullptr, 0, 0); }

    void set(uint8_t* ptr, uint32_t size, uint32_t offset) {
        __mempiece_tag t;
        t.m_size = encode(size);
        t.m_offset = encode(offset);
        m_mem.set(ptr, t.to_integer());
    }

    uint8_t* ptr() const { return m_mem.get_ptr(); }

    uint32_t size() const { return (decode(get_tag().m_size)); }

    uint32_t offset() const { return (decode(get_tag().m_offset)); }

    uint32_t end_offset() const {
        __mempiece_tag t = get_tag();
        return decode(t.m_size + t.m_offset);
    }

    uint8_t* get(uint32_t* psize, uint8_t* poff) const {
        *psize = size();
        *poff = offset();
        return ptr();
    }

    std::string to_string() const {
        std::stringstream ss;
        ss << "ptr = " << (void*)ptr() << " size = " << size() << " offset = " << offset();
        return ss.str();
    }

private:
    uint16_t gen_new_tag(uint32_t size, uint8_t offset) const {
        __mempiece_tag t;
        t.m_size = size;
        t.m_offset = offset;
        return t.to_integer();
    }

    __mempiece_tag get_tag() const {
        uint16_t i = m_mem.get_tag();
        return *reinterpret_cast< __mempiece_tag* >(&i);
    }

    void set_tag(__mempiece_tag t) { m_mem.set_tag(t.to_integer()); }

    uint32_t decode(uint8_t encoded_size) const { return (encoded_size * HomeStoreConfig::min_page_size); }

    uint8_t encode(uint32_t size) const {
        assert((size % HomeStoreConfig::min_page_size) == 0);
        assert((size / HomeStoreConfig::min_page_size >> 8) == 0);
        return round_off(size, HomeStoreConfig::min_page_size);
    }
} __attribute__((packed));

struct MemVector : public sisl::ObjLifeCounter< MemVector > {
private:
    std::vector< MemPiece > m_list;
    mutable std::mutex      m_mtx;
    std::atomic< uint8_t >  m_refcnt;

public:
    MemVector(uint8_t *ptr, uint32_t size, uint32_t offset) :
            ObjLifeCounter(), m_refcnt(0) {
        m_list.reserve(1);
        MemPiece m(ptr, size, offset);
        m_list.push_back(m);
        assert(size || (ptr == nullptr));
    }

    MemVector() : ObjLifeCounter(), m_refcnt(0) { m_list.reserve(1); }
    ~MemVector() { m_list.erase(m_list.begin(), m_list.end()); }

    friend void intrusive_ptr_add_ref(MemVector* mvec) { mvec->m_refcnt++; }

    friend void intrusive_ptr_release(MemVector* mvec) {
        if (mvec->m_refcnt.fetch_sub(1, std::memory_order_relaxed) != 1) {
            return;
        }
        for (auto i = 0u; i < mvec->m_list.size(); i++) {
            if (mvec->m_list[i].ptr() != nullptr) {
                free(mvec->m_list[i].ptr());
            } else {
                assert(0);
            }
        }
        delete (mvec);
    }

    std::vector< MemPiece > get_m_list() const { return m_list; }
    void                    copy(const MemVector& other) {
        assert(other.m_refcnt > 0);
        m_list = other.get_m_list();
    }
    uint32_t npieces() const { return (m_list.size()); }

    void set(uint8_t* ptr, uint32_t size, uint32_t offset) {
        std::unique_lock< std::mutex > mtx(m_mtx);
        m_list.erase(m_list.begin(), m_list.end());
        MemPiece m(ptr, size, offset);
        m_list.push_back(m);
    }

    void set(const homeds::blob& b, uint32_t offset = 0) { set(b.bytes, b.size, offset); }

    void get(homeds::blob* outb, uint32_t offset = 0) const {
        uint32_t                       ind = 0;
        std::unique_lock< std::mutex > mtx(m_mtx);
        if ((m_list.size() && bsearch(offset, -1, &ind))) {
            auto piece_offset = m_list.at(ind).offset();
            assert(piece_offset <= offset);
            uint32_t delta = offset - piece_offset;
            assert(delta < m_list.at(ind).size());
            outb->bytes = m_list.at(ind).ptr() + delta;
            outb->size = m_list.at(ind).size() - delta;
        } else {
            assert(0);
        }
    }

    const MemPiece& get_nth_piece(uint8_t nth) const {
        if (nth < m_list.size()) {
            return m_list.at(nth);
        } else {
            assert(0);
            return m_list.at(0);
        }
    }

    MemPiece& get_nth_piece_mutable(uint8_t nth) {
        if (nth < m_list.size()) {
            return m_list[nth];
        } else {
            assert(0);
            return m_list[0];
        }
    }

    std::string to_string() const {
        auto              n = npieces();
        std::stringstream ss;

        if (n > 1)
            ss << "Pieces = " << n << "\n";
        for (auto i = 0U; i < n; i++) {
            auto& p = get_nth_piece(i);
            ss << "MemPiece[" << i << "]: " << p.to_string() << ((n > 1) ? "\n" : "");
        }
        return ss.str();
    }

    /* This method will try to set or append the offset to the memory piece. However, if there is already an entry
     * within reach for given offset/size, it will reject the entry and return false. Else it sets or adds the entry */
    bool append(uint8_t* ptr, uint32_t offset, uint32_t size) {
        std::unique_lock< std::mutex > mtx(m_mtx);
        bool                           added = false;
        MemPiece                       mp(ptr, size, offset);
        added = add_piece_to_list(mp);
        return added;
    }

    void push_back(const MemPiece& piece) { m_list.push_back(piece); }

    MemPiece& insert_at(uint32_t ind, const MemPiece& piece) {
        assert(ind <= m_list.size());
        auto it = m_list.emplace((m_list.begin() + ind), piece);
        return *it;
    }

    MemPiece& insert_at(uint32_t ind, uint8_t* ptr, uint32_t size, uint32_t offset) {
        auto mp = MemPiece(ptr, size, offset);
        return insert_at(ind, mp);
    }

    uint32_t size(uint32_t offset, uint32_t size) const {
        std::unique_lock< std::mutex > mtx(m_mtx);
        uint32_t                       s = 0;
        uint32_t                       offset_read = 0;
        bool                           start = false;
        for (auto it = m_list.begin(); it < m_list.end(); ++it) {
            offset_read += (*it).offset();
            if ((offset_read + (*it).size()) >= offset && !start) {
                if (offset_read + (*it).size() >= (offset + size)) {
                    s = size;
                    break;
                } else {
                    s = (*it).size() - (offset - offset_read);
                    start = true;
                    continue;
                }
            } else if ((offset_read + (*it).size()) < offset) {
                continue;
            }

            assert(start);

            if ((offset_read + (*it).size()) >= (offset + size)) {
                if (offset_read >= (offset + size)) {
                    break;
                }
                s += (*it).size() - (offset_read + (*it).size() - (offset + size));
                break;
            }
            s = s + (*it).size();
        }
        return s;
    }

    uint32_t size() const {
        std::unique_lock< std::mutex > mtx(m_mtx);
        uint32_t                       s = 0;
        for (auto it = m_list.begin(); it < m_list.end(); ++it) {
            s += (*it).size();
        }
        return s;
    }

    bool find_index(uint32_t offset, boost::optional< int > ind_hint, uint32_t* out_ind) const {
        *out_ind = 0;
        return (bsearch(offset, ind_hint.get_value_or(-1), out_ind));
    }

    struct cursor_t {
        cursor_t() : m_ind(-1) {}
        int m_ind;
    };

    uint32_t insert_missing_pieces(uint32_t offset, uint32_t size,
                                   std::vector< std::pair< uint32_t, uint32_t > >& missing_mp) {
        uint32_t                       new_ind;
        std::unique_lock< std::mutex > mtx(m_mtx);
        cursor_t                       c;
        uint32_t                       inserted_size = 0;

#ifndef NDEBUG
        auto temp_offset = offset;
        auto temp_size = size;
#endif
        while (size != 0) {
            bool found = find_index(offset, c.m_ind, &new_ind);
            if (found) {
                auto& mp = get_nth_piece(new_ind);
                /* check for pointer */
                if (mp.ptr() == nullptr) {
                    /* add pair */
                    std::pair ret(mp.offset(), (mp.end_offset() - mp.offset()));
                    missing_mp.push_back(ret);
                }
                if ((offset + size) <= mp.end_offset()) {
                    offset += size;
                    size = 0;
                } else {
                    size = size - (mp.end_offset() - offset);
                    offset = mp.end_offset(); // Move the offset to the start of next mp.
                }

            } else if (new_ind < npieces()) {
                auto& mp = get_nth_piece(new_ind);
                auto  sz = mp.offset() - offset;
                if (size < sz) {
                    sz = size;
                }
                insert_at(new_ind, nullptr, sz, offset);
                inserted_size += sz;

                /* add pair */
                std::pair ret(offset, sz);
                missing_mp.push_back(ret);

                size -= sz;
                offset = offset + sz;
            } else {
                insert_at(new_ind, nullptr, size, offset);
                inserted_size += size;
                std::pair ret(offset, size);
                /* add pair */
                missing_mp.push_back(ret);

                offset += size;
                size = 0;
            }
            c.m_ind = new_ind;
        }
#ifndef NDEBUG
        assert(offset == (temp_offset + temp_size));
#endif
        return inserted_size;
    }

    bool update_missing_piece(uint32_t offset, uint32_t size, uint8_t* ptr) {
        uint32_t                       new_ind;
        bool                           inserted = false;
        std::unique_lock< std::mutex > mtx(m_mtx);
        bool                           found = find_index(offset, -1, &new_ind);
        assert(found);
        auto& mp = get_nth_piece_mutable(new_ind);
        if (mp.ptr() == nullptr) {
            mp.set_ptr(ptr);
            inserted = true;
        }
        assert(size == mp.size());
        return inserted;
    }

private:
    bool add_piece_to_list(const MemPiece& mp) {

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

    int compare(uint32_t search_offset, const MemPiece& mp) const {
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
    bool bsearch(uint32_t offset, int start, uint32_t* out_ind) const {
        int      end = m_list.size();
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
} // namespace homeds
#endif // OMSTORE_MEMPIECE_HPP
