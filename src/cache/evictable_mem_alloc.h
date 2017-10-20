//
// Created by Kadayam, Hari on 19/10/17.
//

#include "libutils/omds/memory/tagged_ptr.hpp"
#include <boost/intrusive/list.hpp>
#include <mutex>

#ifndef OMSTORAGE_EVICTABLEMEMALLOCATOR_HPP
#define OMSTORAGE_EVICTABLEMEMALLOCATOR_HPP

namespace omstore {

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


// Min and Max of blocks on a single piece of memory
#define EVICT_MEMALLOC_MIN_SIZE 4096
#define EVICT_MEMALLOC_MAX_SIZE EVICT_MEMALLOC_MIN_SIZE * pow()

typedef MemPieces< EVICT_MEMALLOC_MIN_SIZE > EvictMemBlk;

// This structure represents each entry into the evictable location
struct EvictEntry : public boost::intrusive::list_base_hook<> {
    EvictMemBlk m_mem;
    // uint8_t m_rank; // In case we need rank, uncomment this line
};

typedef std::function< bool(EvictEntry *) > CanEvictCallback;
typedef std::function< EvictEntry *(void) > AllocEvictCallback;

class EvictableMemAllocator {
private:
    static constexpr int64_t ipow(int64_t base, int exp, int64_t result = 1) {
        return exp < 1 ? result : ipow(base*base, exp/2, (exp % 2) ? result*base : result);
    }

    static constexpr uint64_t max_alloc_size() {
        return (uint64_t)(EVICT_MEMALLOC_MIN_SIZE * ipow(2, 16));
    }

public:
    EvictableMemAllocator(uint64_t mem_size, CanEvictCallback &can_evict_cb, AllocEvictCallback &alloc_cb);

    /* Allocates the memory for requested size. The memory could be provided in multiple pieces upto max_pieces
     * specified. In-order to allocate, it will evict less used pages. If it could not find any pages within
     * the size, it will throw std::bad_alloc exception.
     */
    bool alloc(uint32_t size, uint32_t max_pieces, EvictEntry *out_entry);

    /* Deallocates the memory and put the pages as top candidate for reuse */
    void dealloc(EvictEntry &mem);

    /* Upvote the allocated memory. This depends on the current rank will move up and thus reduce the chances of
     * getting evicted. In case of LRU allocation, it moves to the tail end of the list */
    void upvote(EvictEntry &mem);

    /* Downvote the entry */
    void downvote(EvictEntry &mem);

private:
    std::mutex m_list_guard;
    boost::intrusive::list< EvictEntry > m_list;
    CanEvictCallback m_evict_cb;
    AllocEvictCallback m_alloc_cb;
    std::unique_ptr< uint8_t[] > m_buf; // Buffer that covers all the size
};

}

#endif //OMSTORAGE_EVICTABLEMEMALLOCATOR_HPP
