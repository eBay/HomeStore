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
#include <metrics/metrics.hpp>

namespace homeds {

struct free_list_header {
    free_list_header *next;
};

class FreeListAllocatorMetrics : public sisl::MetricsGroupWrapper {
public:
    explicit FreeListAllocatorMetrics() : sisl::MetricsGroupWrapper("FreeListAllocator") {
        REGISTER_COUNTER(freelist_alloc_hit, "Number of allocs from cache");
        REGISTER_COUNTER(freelist_alloc_miss, "Number of allocs from system");
        REGISTER_COUNTER(freelist_dealloc_passthru, "Number of dealloc not cached because of size mismatch");

        register_me_to_farm();
    }
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

    uint8_t *allocate(uint32_t size_needed, FreeListAllocatorMetrics& metrics) {
        uint8_t *ptr;
        if (m_head == nullptr) {
            ptr = (uint8_t *)malloc(size_needed);
            COUNTER_INCREMENT(metrics, freelist_alloc_miss, 1);
        } else {
            ptr = (uint8_t *)m_head;
            COUNTER_INCREMENT(metrics, freelist_alloc_hit, 1);
            m_head = m_head->next;
        }

        m_list_count--;
        return ptr;
    }

    bool deallocate(uint8_t *mem, uint32_t size_alloced, FreeListAllocatorMetrics& metrics) {
        if ((size_alloced != Size) || (m_list_count == MaxListCount)) {
            if (size_alloced != Size) { COUNTER_INCREMENT(metrics, freelist_dealloc_passthru, 1); }
            free(mem);
            return true;
        }
        auto *hdr = (free_list_header *)mem;
        hdr->next = m_head;
        m_head = hdr;
        m_list_count++;
        return true;
    }
};

template <uint16_t MaxListCount, std::size_t Size>
class FreeListAllocator {
private:
    folly::ThreadLocalPtr< FreeListAllocatorImpl< MaxListCount, Size > > m_impl;
    FreeListAllocatorMetrics m_metrics;

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

        return (m_impl->allocate(size_needed, m_metrics));
    }

    bool deallocate(uint8_t *mem, uint32_t size_alloced) {
        if (unlikely(m_impl.get() == nullptr)) {
            m_impl.reset(new FreeListAllocatorImpl< MaxListCount, Size >());
        }

        return m_impl->deallocate(mem, size_alloced, m_metrics);
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
