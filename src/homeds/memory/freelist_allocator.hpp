//
// Created by Kadayam, Hari on 30/10/17.
//
#ifndef OMSTORE_CACHELISTALLOCATOR_HPP
#define OMSTORE_CACHELISTALLOCATOR_HPP

#include <utility>
#include <iostream>
#include <algorithm>
#include <folly/ThreadLocal.h>
#include "homeds/utility/useful_defs.hpp"

namespace homeds {

struct free_list_header {
    free_list_header *next;
};

template <uint16_t MaxListCount, std::size_t Size>
class FreeListAllocatorImpl {
private:
    free_list_header *m_head;
    int64_t m_list_count;

public:
    FreeListAllocatorImpl() :
            m_head(nullptr),
            m_list_count(0) {
    }

    ~FreeListAllocatorImpl() {
        free_list_header *hdr = m_head;
        while (hdr) {
            free_list_header *next = hdr->next;
            free((uint8_t *)hdr);
            hdr = next;
        }
    }

    uint8_t *allocate(uint32_t size_needed) {
        uint8_t *ptr;
        if (m_head == nullptr) {
            ptr = (uint8_t *)malloc(size_needed);
        } else {
            ptr = (uint8_t *)m_head;
            m_head = m_head->next;
        }

        m_list_count--;
        return ptr;
    }

    bool deallocate(uint8_t *mem, uint32_t size_alloced) {
    /* TODO: it is not working correcly as we are freeing the buffer
     * from cache even if the cache buffer is of different type.
     */
//        if ((size_alloced != Size) || (m_list_count == MaxListCount)) {
            free(mem);
            return true;
  //      }
#if 0
        auto *hdr = (free_list_header *)mem;
        hdr->next = m_head;
        m_head = hdr;
        m_list_count++;
        return true;
#endif
    }
};

template <uint16_t MaxListCount, std::size_t Size>
class FreeListAllocator {
private:
    folly::ThreadLocalPtr< FreeListAllocatorImpl< MaxListCount, Size > > m_impl;

public:
    static_assert((Size >= sizeof(uint8_t *)), "Size requested should be atleast a pointer size");

    FreeListAllocator() {
        m_impl.reset(nullptr);
    }

    ~FreeListAllocator() {
        m_impl.reset(nullptr);
    }

    uint8_t *allocate(uint32_t size_needed)  {
        if (unlikely(m_impl.get() == nullptr)) {
            m_impl.reset(new FreeListAllocatorImpl< MaxListCount, Size >());
        }

        return (m_impl->allocate(size_needed));
    }

    bool deallocate(uint8_t *mem, uint32_t size_alloced) {
        if (unlikely(m_impl.get() == nullptr)) {
            m_impl.reset(new FreeListAllocatorImpl< MaxListCount, Size >());
        }

        return m_impl->deallocate(mem, size_alloced);
    }

    bool owns(uint8_t *mem) const {
        return true;
    }

    bool is_thread_safe_allocator() const {
        return true;
    }
};
}

#endif //OMSTORE_CACHELISTALLOCATOR_HPP
