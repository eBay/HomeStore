//
// Created by Kadayam, Hari on 27/10/17.
//

#ifndef OMSTORE_MEMPIECE_HPP
#define OMSTORE_MEMPIECE_HPP

#include <algorithm>
#include <atomic>
#include <cassert>
#include <cstdint>
#include <iterator>
#include <limits>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <type_traits>
#include <vector>

#include <sisl/fds/buffer.hpp>
#include <iomgr/iomgr.hpp>
#include <sisl/utility/atomic_counter.hpp>
#include <sisl/utility/obj_life_counter.hpp>

#include "engine/common/homestore_assert.hpp"
#include "engine/common/homestore_config.hpp"
#include "engine/homestore_base.hpp"
//#include "tagged_ptr.hpp"
#include <sisl/metrics/metrics.hpp>

namespace homeds {
using namespace homestore; // NOTE: This needs to be removed as it pollutes namespace of all files where this header is
                           // used

#if 0
// Tagged pointer implementation of MemPiece
#define round_off(val, rnd) ((((val)-1) / (rnd)) + 1)

#pragma pack(1)
struct mempiece_tag {
    uint16_t m_size : 8;   /* Size shrinked by SizeMultipler */
    uint16_t m_offset : 8; /* Offset within the mem piece */

    uint16_t to_integer() { return *((uint16_t*)this); }
};
#pragma pack()

constexpr int SizeMultiplier = 4096;

class MemPieceMetrics : public sisl::MetricsGroup {
public:
    static MemPieceMetrics& get() {
        static MemPieceMetrics s_metrics;
        return s_metrics;
    }

    MemPieceMetrics() : sisl::MetricsGroup{"Mempiece", "Singleton"} {
        REGISTER_COUNTER(mempiece_overall_size, "Memory occupied by mempiece", sisl::_publish_as::publish_as_gauge);
        register_me_to_farm();
    }
};

struct MemPiece : public sisl::ObjLifeCounter< MemPiece > {
    homeds::tagged_ptr< uint8_t > m_mem;

    MemPiece(uint8_t* const mem, const uint32_t sz, const uint32_t offset) :
            ObjLifeCounter{}, m_mem{mem, static_cast<uint16_t>(gen_new_tag(encode(sz), encode(offset)))} {
        COUNTER_INCREMENT(MemPieceMetrics::get(), mempiece_overall_size, sz); 
    }

    MemPiece() : MemPiece(nullptr, 0, 0) {}
    MemPiece(const MemPiece& other) : ObjLifeCounter(), m_mem(other.m_mem) {
        COUNTER_INCREMENT(MemPieceMetrics::get(), mempiece_overall_size, size());
    }
    ~MemPiece() { COUNTER_DECREMENT(MemPieceMetrics::get(), mempiece_overall_size, size()); }

    void set_ptr(uint8_t* ptr) { m_mem.set_ptr(ptr); }

#if 0
    void set_size(uint32_t size) {
        __mempiece_tag t = get_tag();
        t.m_size = encode(size);
        set_tag(t);
    }
#endif

    void set_offset(uint32_t offset) {
        __mempiece_tag t = get_tag();
        t.m_offset = encode(offset);
        set_tag(t);
    }

    void reset() { set(nullptr, 0, 0); }

    void set(uint8_t* ptr, uint32_t sz, uint32_t offset) {
        COUNTER_INCREMENT(MemPieceMetrics::get(), mempiece_overall_size, sz - size());
        __mempiece_tag t;
        t.m_size = encode(sz);
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
        std::ostringstream ss;
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

    uint32_t decode(uint8_t encoded_size) const { return (encoded_size * HS_STATIC_CONFIG(engine.min_io_size)); }

    uint8_t encode(uint32_t size) const {
        assert((size % HS_STATIC_CONFIG(engine.min_io_size)) == 0);
        assert(((size / HS_STATIC_CONFIG(engine.min_io_size)) >> 8) == 0);
        return round_off(size, HS_STATIC_CONFIG(engine.min_io_size));
    }
} __attribute__((packed));
#endif

#if 1
// compressed with multiplier version of MemPiece
#pragma pack(1)
struct MemPiece : public sisl::ObjLifeCounter< MemPiece > {
    uint8_t* m_ptr;
    uint8_t m_size;   // Size shrinked by s_size_multiplier
    uint8_t m_offset; // Offset shrinked by s_size_multiplier

    MemPiece(uint8_t* const mem, const uint32_t size, const uint32_t offset) :
            ObjLifeCounter{}, m_ptr{mem}, m_size{encode(size)}, m_offset{encode(offset)} {}
    MemPiece() : MemPiece{nullptr, 0, 0} {}

    MemPiece(const MemPiece& other) :
            ObjLifeCounter{}, m_ptr{other.m_ptr}, m_size{other.m_size}, m_offset{other.m_offset} {}
    MemPiece& operator=(const MemPiece& rhs) {
        if (this != &rhs) {
            m_ptr = rhs.m_ptr;
            m_size = rhs.m_size;
            m_offset = rhs.m_offset;
        }
        return *this;
    }
    MemPiece(MemPiece&& other) noexcept :
            ObjLifeCounter{}, m_ptr{other.m_ptr}, m_size{other.m_size}, m_offset{other.m_offset} {
        other.m_ptr = nullptr;
        other.m_size = 0;
        other.m_offset = 0;
    }
    MemPiece& operator=(MemPiece&& rhs) noexcept {
        if (this != &rhs) {
            m_ptr = rhs.m_ptr;
            m_size = rhs.m_size;
            m_offset = rhs.m_offset;
            rhs.m_ptr = nullptr;
            rhs.m_size = 0;
            rhs.m_offset = 0;
        }
        return *this;
    };
    ~MemPiece() = default;

    void set_ptr(uint8_t* const ptr) { m_ptr = ptr; }

    void set_size(const uint32_t size) { m_size = encode(size); }

    void set_offset(const uint32_t offset) { m_offset = encode(offset); }

    void reset() { set(nullptr, 0, 0); }

    void set(uint8_t* const ptr, const uint32_t size, const uint32_t offset) {
        m_ptr = ptr;
        m_size = encode(size);
        m_offset = encode(offset);
    }

    uint8_t* ptr() const { return m_ptr; }

    uint32_t size() const { return decode(m_size); }
    uint32_t buffer_size() const { return (iomanager.iobuf_size(ptr())); }

    uint32_t offset() const { return decode(m_offset); }

    uint32_t end_offset() const { return decode(m_size + m_offset); }

    uint8_t* get(uint32_t* const psize, uint32_t* const poff) const {
        *psize = size();
        *poff = offset();
        return m_ptr;
    }

    std::string to_string() const {
        std::ostringstream ss;
        ss << "ptr = " << static_cast< const void* >(ptr()) << " size = " << size() << " offset = " << offset();
        return ss.str();
    }

private:
    static uint32_t multiplier() { return HS_STATIC_CONFIG(engine.min_io_size); }

    static uint32_t decode(const uint8_t encoded_size) { return (encoded_size * multiplier()); }

    static uint8_t encode(const uint32_t size) {
        HS_DEBUG_ASSERT_EQ((size % multiplier()), 0, "size {} multiplier{}", size,
                           multiplier()); // assure modulo of multiplier
        HS_DEBUG_ASSERT_EQ(((size / multiplier()) >> 8), 0, "size {} multuplier{}", size,
                           multiplier());                                              // assure fits in uint8_t
        return static_cast< uint8_t >((size > 0) ? (size - 1) / multiplier() + 1 : 0); // round to multiplier
    }
};
#pragma pack()
#endif

#if 0
// uncompressed MemPiece
#pragma pack(1)
struct MemPiece : public sisl::ObjLifeCounter< MemPiece > {
    uint8_t* m_ptr;
    uint32_t m_size;  
    uint32_t m_offset; 

    MemPiece(uint8_t* const mem, const uint32_t size, const uint32_t offset) :
            ObjLifeCounter{}, m_ptr{mem}, m_size{size}, m_offset{offset} {}
    MemPiece() : MemPiece{nullptr, 0, 0} {}

    MemPiece(const MemPiece& other) :
            ObjLifeCounter{}, m_ptr{other.m_ptr}, m_size{other.m_size}, m_offset{other.m_offset} {}
    MemPiece& operator=(const MemPiece& rhs) {
        if (this != &rhs) {
            m_ptr = rhs.m_ptr;
            m_size = rhs.m_size;
            m_offset = rhs.m_offset;
        }
        return *this;
    }
    MemPiece(MemPiece&& other) noexcept :
            ObjLifeCounter{}, m_ptr{other.m_ptr}, m_size{other.m_size}, m_offset{other.m_offset} {
        other.m_ptr = nullptr;
        other.m_size = 0;
        other.m_offset = 0;
    }
    MemPiece& operator=(MemPiece&& rhs) noexcept {
        if (this != &rhs) {
            m_ptr = rhs.m_ptr;
            m_size = rhs.m_size;
            m_offset = rhs.m_offset;
            rhs.m_ptr = nullptr;
            rhs.m_size = 0;
            rhs.m_offset = 0;
        }
        return *this;
    };
    ~MemPiece() = default;

    void set_ptr(uint8_t* const ptr) { m_ptr = ptr; }

    void set_size(const uint32_t size) { m_size = size; }

    void set_offset(const uint32_t offset) { m_offset = offset; }

    void reset() { set(nullptr, 0, 0); }

    void set(uint8_t* const ptr, const uint32_t size, const uint32_t offset) {
        m_ptr = ptr;
        m_size = size;
        m_offset = offset;
    }

    uint8_t* ptr() const { return m_ptr; }

    uint32_t size() const { return m_size; }

    uint32_t offset() const { return m_offset; }

    uint32_t end_offset() const { return m_size + m_offset; }

    uint8_t* get(uint32_t* const psize, uint32_t* const poff) const {
        *psize = size();
        *poff = offset();
        return m_ptr;
    }

    std::string to_string() const {
        std::ostringstream ss;
        ss << "ptr = " << static_cast< const void* >(ptr()) << " size = " << size() << " offset = " << offset();
        return ss.str();
    }
};
#pragma pack()
#endif

struct MemVector : public sisl::ObjLifeCounter< MemVector > {
private:
    std::vector< MemPiece > m_list;
    typedef std::recursive_mutex lock_type;
    mutable lock_type m_mtx;
    sisl::atomic_counter< uint16_t > m_refcnt; // Refcount
    sisl::buftag m_tag{sisl::buftag::common};

public:
    MemVector(uint8_t* const ptr, const uint32_t size, const uint32_t offset) : ObjLifeCounter{}, m_refcnt{0} {
        assert((size > 0) || !ptr);
        m_list.reserve(1);
        if (ptr) { m_list.emplace_back(ptr, size, offset); }
    }

    MemVector() : ObjLifeCounter{}, m_refcnt{0} { m_list.reserve(1); }
    MemVector(const MemVector&) = delete;
    MemVector& operator=(const MemVector&) = delete;
    MemVector(MemVector&&) noexcept = delete;
    MemVector& operator=(MemVector&&) noexcept = delete;

    ~MemVector() {
        std::lock_guard< lock_type > mtx{m_mtx};
        for (const auto& entry : m_list) {
            if (entry.ptr() != nullptr) {
                hs_utils::iobuf_free(entry.ptr(), get_tag());
            } else {
                assert(false);
            }
        }
        m_list.clear();
    }

    friend void intrusive_ptr_add_ref(MemVector* const mvec) {
        const uint32_t cnt{mvec->m_refcnt.increment()};
        HS_ASSERT_CMP(RELEASE, cnt, <=, static_cast< uint32_t >(std::numeric_limits< uint16_t >::max()));
    }

    friend void intrusive_ptr_release(MemVector* const mvec) {
        if (mvec->m_refcnt.decrement_testz()) {
            // free the record
            delete mvec;
        }
    }

    std::vector< MemPiece > get_m_list() const {
        std::lock_guard< lock_type > mtx{m_mtx};
        return m_list;
    }

    // perform deep copy
    void copy(const MemVector& other) {
        if (this != &other) {
            std::lock_guard< lock_type > mtx{m_mtx};
            assert(other.m_refcnt.get() > 0);
            m_list = other.get_m_list();
        }
    }

    uint32_t npieces() const {
        std::lock_guard< lock_type > mtx{m_mtx};
        return m_list.size();
    }

    void set(uint8_t* const ptr, const uint32_t size, const uint32_t offset) {
        std::lock_guard< lock_type > mtx{m_mtx};
        m_list.clear();
        m_list.emplace_back(ptr, size, offset);
    }

    void set(const sisl::blob& b, const uint32_t offset = 0) { set(b.bytes, b.size, offset); }
    void set_tag(const sisl::buftag tag) { m_tag = tag; }
    sisl::buftag get_tag() const { return m_tag; }

    void get(sisl::blob* const outb, const uint32_t offset = 0) const {
        std::lock_guard< lock_type > mtx{m_mtx};
        size_t ind{0};
        if (bsearch(offset, 0, &ind)) {
            const auto& entry{m_list[ind]};
            const auto piece_offset{entry.offset()};
            assert(piece_offset <= offset);
            const uint32_t delta{static_cast< uint32_t >(offset - piece_offset)};
            assert(delta < entry.size());
            outb->bytes = entry.ptr() + delta;
            outb->size = entry.size() - delta;
        } else {
            assert(false);
        }
    }

    const MemPiece& get_nth_piece(const size_t nth) const {
        std::lock_guard< lock_type > mtx{m_mtx};
        assert(nth < m_list.size());
        return m_list[nth];
    }

    MemPiece& get_nth_piece(const size_t nth) {
        std::lock_guard< lock_type > mtx{m_mtx};
        assert(nth < m_list.size());
        return m_list[nth];
    }

    std::string to_string() const {
        std::ostringstream ss;
        {
            std::lock_guard< lock_type > mtx{m_mtx};
            if (!m_list.empty()) {
                ss << "Pieces = " << m_list.size() << std::endl;
                size_t index{0};
                for (const auto& entry : m_list) {
                    ss << "MemPiece[" << index++ << "]: " << entry.to_string() << std::endl;
                }
            }
        }
        return ss.str();
    }

    /* This method will try to set or append the offset to the memory piece. However, if there is already an entry
     * within reach for given offset/size, it will reject the entry and return false. Else it sets or adds the entry */
    bool append(uint8_t* const ptr, const uint32_t offset, const uint32_t size) {
        std::lock_guard< lock_type > mtx{m_mtx};
        MemPiece mp{ptr, size, offset};
        const bool added{add_piece_to_list(std::move(mp))};
        return added;
    }

    template < typename InputType,
               typename = std::enable_if_t< std::is_convertible_v< std::decay_t< InputType >, MemPiece > > >
    void push_back(InputType&& piece) {
        std::lock_guard< lock_type > mtx{m_mtx};
        m_list.push_back(std::forward< InputType >(piece));
    }

    template < typename InputType,
               typename = std::enable_if_t< std::is_convertible_v< std::decay_t< InputType >, MemPiece > > >
    MemPiece& insert_at(const size_t ind, InputType&& piece) {
        std::lock_guard< lock_type > mtx{m_mtx};
        assert(ind <= m_list.size());
        const auto it{m_list.insert(std::next(std::begin(m_list), ind), std::forward< InputType >(piece))};
        return *it;
    }

    MemPiece& insert_at(const size_t ind, uint8_t* const ptr, const uint32_t size, const uint32_t offset) {
        return insert_at(ind, MemPiece{ptr, size, offset});
    }

    uint32_t size(const uint32_t offset, const uint32_t size) const {
        std::lock_guard< lock_type > mtx{m_mtx};
        uint32_t s{0};
        uint32_t offset_read{0};
        bool start{false};
        for (const auto& entry : m_list) {
            offset_read += entry.offset();
            if ((offset_read + entry.size()) >= offset && !start) {
                if (offset_read + entry.size() >= (offset + size)) {
                    s = size;
                    break;
                } else {
                    s = entry.size() - (offset - offset_read);
                    start = true;
                    continue;
                }
            } else if ((offset_read + entry.size()) < offset) {
                continue;
            }

            assert(start);

            if ((offset_read + entry.size()) >= (offset + size)) {
                if (offset_read >= (offset + size)) { break; }
                s += entry.size() - (offset_read + entry.size() - (offset + size));
                break;
            }
            s = s + entry.size();
        }
        return s;
    }

    uint32_t size() const {
        std::lock_guard< lock_type > mtx{m_mtx};
        uint32_t s{0};
        for (const auto& entry : m_list) {
            s += entry.size();
        }
        return s;
    }

    uint32_t get_buffer_size() const {
        std::lock_guard< lock_type > mtx{m_mtx};
        uint32_t s{0};
        for (const auto& entry : m_list) {
            s += entry.buffer_size();
        }
        return s;
    }

    uint32_t insert_missing_pieces(const uint32_t offset_in, const uint32_t size_in,
                                   std::vector< std::pair< uint32_t, uint32_t > >& missing_mp) {
        std::lock_guard< lock_type > mtx{m_mtx};
        uint32_t offset{offset_in};
        uint32_t size{size_in};
        size_t new_ind{0};
        size_t old_ind{0};
        uint32_t inserted_size{0};

#ifndef NDEBUG
        auto temp_offset{offset};
        auto temp_size{size};
#endif
        while (size != 0) {
            const bool found{find_index(offset, old_ind, &new_ind)};
            if (found) {
                auto& mp{m_list[new_ind]};
                /* check for pointer */
                if (mp.ptr() == nullptr) {
                    /* add pair */
                    missing_mp.emplace_back(mp.offset(), (mp.end_offset() - mp.offset()));
                }
                if ((offset + size) <= mp.end_offset()) {
                    offset += size;
                    size = 0;
                } else {
                    size -= (mp.end_offset() - offset);
                    offset = mp.end_offset(); // Move the offset to the start of next mp.
                }
            } else if (new_ind < m_list.size()) {
                auto& mp{m_list[new_ind]};
                const uint32_t sz{std::min< uint32_t >(size, mp.offset() - offset)};
                m_list.emplace(std::next(std::begin(m_list), new_ind), nullptr, sz, offset);
                inserted_size += sz;

                /* add pair */
                missing_mp.emplace_back(offset, sz);

                size -= sz;
                offset = offset + sz;
            } else {
                m_list.emplace(std::next(std::begin(m_list), new_ind), nullptr, size, offset);
                inserted_size += size;

                /* add pair */
                missing_mp.emplace_back(offset, size);

                offset += size;
                size = 0;
            }
            old_ind = new_ind;
        }
#ifndef NDEBUG
        assert(offset == (temp_offset + temp_size));
#endif
        return inserted_size;
    }

    template < typename InitCallbackType >
    bool update_missing_piece(const uint32_t offset, const size_t size, uint8_t* const ptr,
                              InitCallbackType&& init_callback) {
        std::lock_guard< lock_type > mtx{m_mtx};
        size_t new_ind{0};
        bool inserted{false};
        const bool found{find_index(offset, 0, &new_ind)};
        assert(found);
        auto& mp{m_list[new_ind]};
        if (mp.ptr() == nullptr) {
            mp.set_ptr(ptr);
            inserted = true;
            std::forward< InitCallbackType >(init_callback)();
        }
        assert(size == mp.size());
        return inserted;
    }

private:
    // NOTE: must be called with a lock
    bool find_index(const uint32_t offset, const std::optional< size_t >& ind_hint, size_t* const out_ind) const {
        *out_ind = 0;
        return bsearch(offset, ind_hint.value_or(0), out_ind);
    }

    // NOTE: must be called with a lock
    bool add_piece_to_list(MemPiece&& mp) {
        size_t ind{0};
        // If we found an offset in search we got to fail the add
        if (bsearch(mp.offset(), 0, &ind)) { return false; }

        // If we overlap with the next entry where it is to be inserted, fail the add
        if ((ind < m_list.size()) && (mp.end_offset() > m_list[ind].offset())) { return false; }

        // insert at proper position
        m_list.insert(std::next(std::begin(m_list), ind), std::move(mp));
        return true;
    }

    int compare(const uint32_t search_offset, const MemPiece& mp) const {
        const auto mp_offset{mp.offset()};
        if (search_offset == mp_offset) {
            return 0;
        } else if (search_offset < mp_offset) {
            return 1;
        } else {
            return (mp.end_offset() > search_offset) ? 0 /* Overlaps */ : -1;
        }
    }

    // NOTE: must be called with a lock
    /* it return the first index which is greater then or equal to offset.
     * If is more then the last element in m_list.size() then it
     * return m_list.size(). If it is smaller then first element, it return
     * zero.
     */
    bool bsearch(const uint32_t offset, const size_t start_in, size_t* const out_ind) const {
        size_t end{m_list.size()};
        size_t start{start_in};
        size_t mid{0};

        while (start < end) {
            mid = start + (end - start) / 2;
            const int cmp{compare(offset, m_list[mid])};
            switch (cmp) {
            case -1: // m_list[mid] < offset and does not contain
                start = mid + 1;
                break;
            case 1: // m_list[mid] > offset
                end = mid;
                break;
            case 0: // m_list[mid] contains offset
                *out_ind = mid;
                return true;
            default:
                assert(false);
            }
        }
        *out_ind = end;
        return false;
    }
};

} // namespace homeds
#endif // OMSTORE_MEMPIECE_HPP
