//
// Created by Kadayam, Hari on 19/10/17.
//
#include "evictable_mem_alloc.h"

namespace omstore {
template <ssize_t MinAllocSize>
EvictableMemAllocator::EvictableMemAllocator(uint64_t mem_size, CanEvictCallback &can_evict_cb,
                                             AllocEvictCallback &alloc_cb) :
        m_evict_cb(can_evict_cb),
        m_alloc_cb(alloc_cb) {

    // First add all entries as max alloc cbs
    m_buf = std::make_unique<uint8_t[]>(mem_size);
    uint8_t *ptr = m_buf.get();
    uint32_t npieces = mem_size/max_alloc_size();

    // Allocate n EvictEntries with each entry of maximum size and add to the list.
    for (auto i = 0U; i < npieces; i++) {
        EvictRecord *e = m_alloc_cb();
        e->m_mem.set_piece(ptr, max_alloc_size());
        m_list.push_back(*e);
        ptr += max_alloc_size();
    }
}

// TODO: There is a corner case which is not covered here. After allocation the refcount is not incremented here.
// The scenario is as follows:
// Thread 1 has allocated the memory, but refcount is not incremented here. So it is added to the end of the list without
// incrementing the refcount.
// Thread 2 is looking for memory and all the elements in the list is not evictable and it picked the entry allocated
// for Thread 1, which means 2 thread gets the same reference.
template <ssize_t MinAllocSize>
bool EvictableMemAllocator::alloc(uint32_t size, uint32_t max_pieces, EvictRecord *out_entry) {
    bool found = false;

    {
        std::lock_guard< decltype(m_list_guard) > guard(m_list_guard);
        for (auto it = m_list.begin(); it != m_list.end(); ++it) {
            if (m_evict_cb(&*it)) {
                m_list.erase(it);
                *out_entry = *it;
                found = true;
                m_list.push_back(*out_entry);
                break;
            }
        }
    }

    if (!found) {
        throw std::bad_alloc();
    }
    return found;
}

template <ssize_t MinAllocSize>
void EvictableMemAllocator::dealloc(EvictRecord &mem) {
    downvote(mem);
}

template <ssize_t MinAllocSize>
void EvictableMemAllocator::upvote(EvictRecord &mem) {
    std::lock_guard< decltype(m_list_guard) > guard(m_list_guard);
    m_list.erase(m_list.iterator_to(mem));
    m_list.push_back(mem);
}

template <ssize_t MinAllocSize>
void EvictableMemAllocator::downvote(EvictRecord &mem) {
    std::lock_guard< decltype(m_list_guard) > guard(m_list_guard);
    m_list.erase(m_list.iterator_to(mem));
    m_list.push_front(mem);
}

} // namespace omstore