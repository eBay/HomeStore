/*
 * ChunkMemAllocator.hpp
 *
 *  Created on: 16-May-2016
 *      Author: hkadayam
 */

//  Copyright © 2016 Kadayam, Hari. All rights reserved.

#pragma once

#include <iostream>
#include <atomic>
#include <assert.h>
#include <limits.h>
#include "mem_allocator.hpp"

using namespace std;

namespace homeds {
struct chunk_pool_header {
public:
#ifdef DEBUG
    uint32_t id;
#endif
    uint32_t next;
} __attribute__((packed));

inline uint64_t form_top_id(uint32_t gen, uint32_t id) { return (((uint64_t)gen) << 32 | id); }

inline uint32_t get_gen_from_topid(uint64_t top_id) { return (uint32_t)(top_id >> 32); }

inline uint32_t get_id_from_top_id(uint64_t top_id) { return (uint32_t)(top_id); }

template < uint32_t ChunkSize >
class ChunkMemAllocator {
private:
    uint8_t* m_base_ptr;      // Base Ptr of this chunk allocation
    atomic< uint64_t > m_top; // Top Id which maintains the free entry
    atomic< uint32_t > m_gen; // This is tag approach to avoid ABA
    uint32_t m_nchunks;       // Total number of chunks

#define per_chunk_size() (ChunkSize + sizeof(chunk_pool_header))
#define CHUNKID_INVALID ((uint32_t)-1)

public:
    ChunkMemAllocator(uint32_t total_size) : m_base_ptr(nullptr), m_top(form_top_id(0, CHUNKID_INVALID)), m_gen(0) {
        uint32_t nentries = total_size / per_chunk_size();
        m_base_ptr = new uint8_t[total_size];
        m_nchunks = nentries;

        uint8_t* ptr = m_base_ptr;
        for (uint32_t i = 0; i < nentries; i++) {
            uint8_t* entry = (uint8_t*)(ptr + sizeof(chunk_pool_header));

            chunk_pool_header* hdr = (chunk_pool_header*)ptr;
#ifdef DEBUG
            hdr->id = i;
#endif
            free_header(hdr);
            ptr += per_chunk_size();
        }
    }

    virtual ~ChunkMemAllocator() {
        if (m_base_ptr) {
            delete[](m_base_ptr);
        }
    }

    // Provides the metadata blk size. This metadata blk can be used by the caller to put anything it wants after
    // allocating the block.
    uint32_t get_metablk_size() const { return sizeof(chunk_pool_header); }

    /* Allocate the required size of memory and returns a memory block, which contains the address, size
     * and the id information. There is an optional second parameter, if provided will be filled in with
     * metadata block, which can be reused for any other meta information the caller is intenting to use
     *
     * NOTE: Throws std::bad_alloc if there is no memory available.
     */
    uint8_t* allocate(uint32_t size_needed, uint8_t** meta_blk = nullptr) {
        MemBlk blk;

        if (size_needed > ChunkSize) {
            return nullptr;
        }

        chunk_pool_header* hdr = nullptr;
        hdr = alloc_header();
        if (hdr == nullptr) {
            return hdr;
        }

#ifdef CHUNK_MEMPOOL_DEBUG
        printf("%p: ChunkMemAllocator: %p Alloc id=0x%x refcnt=%d size=%u top=0x%llx\n", pthread_self(), this, hdr->id,
               hdr->refcnt.load(), m_entrySize, m_top.load());
#endif

        if (meta_blk) {
            *meta_blk = (uint8_t*)hdr;
        }
        return hdr_to_mem(hdr);
    }

    void deallocate(uint8_t* mem) {
        assert(owns(mem));
        chunk_pool_header* hdr = mem_to_hdr(mem);
        free_header(hdr);
    }

    bool owns(uint8_t* mem) { return ((mem >= m_base_ptr) && (mem < (m_base_ptr + (m_nchunks * per_chunk_size())))); }

    bool is_thread_safe_allocator() { return true; }

private:
    uint8_t* hdr_to_mem(chunk_pool_header* hdr) { return ((uint8_t*)(((uint8_t*)hdr) + sizeof(chunk_pool_header))); }

    chunk_pool_header* mem_to_hdr(uint8_t* entry) {
        return ((chunk_pool_header*)((uint8_t*)entry - sizeof(chunk_pool_header)));
    }

    uint32_t hdr_to_id(chunk_pool_header* hdr) { return ((((uint8_t*)hdr) - m_base_ptr) / ChunkSize); }

    chunk_pool_header* id_to_hdr(uint32_t id) { return ((chunk_pool_header*)(m_base_ptr + (ChunkSize * id))); }

    chunk_pool_header* alloc_header() {
        chunk_pool_header* hdr;
        uint64_t next_id;
        uint64_t top_id;

        // No objects available
        do {
            top_id = m_top.load(std::memory_order_release);
            uint32_t id = get_id_from_top_id(top_id);

            if (id == CHUNKID_INVALID) {
                return nullptr;
            }

            hdr = id_to_hdr(id);
            uint32_t gen = m_gen.fetch_add(1, std::memory_order_acq_rel);
            next_id = form_top_id(gen, hdr->next);
        } while (!(m_top.compare_exchange_weak(top_id, next_id, std::memory_order_acq_rel)));

        return hdr;
    }

    void free_header(chunk_pool_header* hdr) {
        uint64_t top_id;
        uint64_t new_top_id;
        uint32_t id = hdr_to_id(hdr);

        do {
            top_id = m_top.load(std::memory_order_release);
            uint32_t next_id = get_id_from_top_id(top_id);
            hdr->next = next_id;

            uint32_t gen = m_gen.fetch_add(1, std::memory_order_acq_rel);
            new_top_id = form_top_id(gen, id);
        } while (!(m_top.compare_exchange_weak(top_id, new_top_id, std::memory_order_acq_rel)));
    }
};

} // namespace homeds
