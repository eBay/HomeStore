//
// Created by Kadayam, Hari on 21/09/17.
//

#ifndef LIBUTILS_FREELIST_ALLOCATOR_HPP
#define LIBUTILS_FREELIST_ALLOCATOR_HPP

#include <cstdint>
#include <utility>
#include <iostream>
#include <array>
#include <algorithm>
#include "mem_allocator.hpp"
#include <folly/ThreadLocal.h>
#include "omds/memory/tagged_ptr.hpp"

namespace omds {

struct free_list_bucket {
    std::size_t m_size;
    uint16_t m_head_index;
};

template <uint16_t MaxListCount, std::size_t... Ranges>
class GenericFreelistAllocatorImpl {
private:
    std::array<free_list_bucket, sizeof...(Ranges)> m_buckets;
    omds::tagged_ptr< uint8_t> *m_slot_head;
    omds::tagged_ptr<uint8_t> m_bufptr[MaxListCount];

public:
    GenericFreelistAllocatorImpl() {
        auto i = 0;
        std::array<std::size_t, sizeof...(Ranges)> arr = {{Ranges...}};
        std::sort(arr.begin(), arr.end());
        for (auto s : arr) {
            m_buckets[i].m_size = s;
            m_buckets[i].m_head_index = (uint16_t)-1;
            i++;
        }

        auto prev_index = (uint16_t)(-1);
        for (auto s = MaxListCount-1; s >= 0; s--) {
            m_bufptr[s].set(nullptr, prev_index);
            prev_index = s;
        }
        m_slot_head = &m_bufptr[0];
    }

    free_list_bucket *find_bucket(uint32_t size) {
        for (auto i = 0; i < m_buckets.size(); i++) {
            if (size <= m_buckets[i].m_size) {
                return &m_buckets[i];
            }
        }
        return nullptr;
    }

    free_list_bucket *find_exact_bucket(uint32_t size) {
        for (auto i = 0; i < m_buckets.size(); i++) {
            if (size == m_buckets[i].m_size) {
                return &m_buckets[i];
            }
        }
        return nullptr;
    }

    omds::tagged_ptr< uint8_t > *alloc_new_slot() {
        if (m_slot_head == nullptr) {
            return nullptr;
        }

        omds::tagged_ptr< uint8_t > *slot = m_slot_head;
        uint16_t tag = m_slot_head->get_tag();
        m_slot_head = (tag == (uint16_t)-1) ? nullptr : &m_bufptr[tag];
        return slot;
    }

    uint16_t get_index(omds::tagged_ptr< uint8_t > *pslot) const {
        return (uint16_t)(pslot - m_bufptr);
    }

    omds::tagged_ptr< uint8_t > *get_slot(uint16_t index) {
        return &m_bufptr[index];
    }
};

template <uint16_t MaxListCount, std::size_t... Ranges>
class GenericFreelistAllocator : public AbstractMemAllocator {

private:
    folly::ThreadLocalPtr< GenericFreelistAllocatorImpl< MaxListCount, Ranges... > > m_impl;

public:
    GenericFreelistAllocator() = default;

    uint8_t *allocate(uint32_t size_needed, uint8_t **meta_blk, uint32_t *out_meta_size) override {
        if (m_impl.get() == nullptr) {
            m_impl.reset(new GenericFreelistAllocatorImpl<MaxListCount, Ranges...>());
        }

        free_list_bucket *b = m_impl->find_bucket(size_needed);
        if ((b == nullptr) || (b->m_head_index == (uint16_t)-1)) {
            return (uint8_t *)malloc(size_needed);
            //return nullptr;
        }

        omds::tagged_ptr< uint8_t > *p = m_impl->get_slot(b->m_head_index);
        b->m_head_index = p->get_tag();

        //std::cout << "FreeListAllocator: Allocating " << size_needed << " sized mem from freelist bucket " << b << "\n";

        if (meta_blk && out_meta_size) {
            *meta_blk = (uint8_t *)p;
            *out_meta_size = sizeof(omds::tagged_ptr< uint8_t>);
        }
        return p->get_ptr();
    }

    bool deallocate(uint8_t *mem, uint32_t size_alloced) override {
        if (size_alloced == 0) {
            free(mem); return true;
            //return false;
        }

        free_list_bucket *b = m_impl->find_exact_bucket(size_alloced);
        if (b == nullptr) {
            free(mem); return true;
            //return false;
        }

        // Get a new slot and put the memory in it
        omds::tagged_ptr< uint8_t > *slot = m_impl->alloc_new_slot();
        if (slot == nullptr) {
            free(mem); return true;
            // No room for any more
            //return false;
        }

        //std::cout << "FreeListAllocator: Adding " << size_alloced << " sized mem to freelist bucket " << b << "\n";
        slot->set(mem, b->m_head_index);
        b->m_head_index = m_impl->get_index(slot);
        return true;
    }

    bool owns(uint8_t *mem) const override {
        return true;
    }

    bool is_thread_safe_allocator() const override {
        return true;
    }
};
}
#endif //LIBUTILS_FREELIST_ALLOCATOR_HPP
