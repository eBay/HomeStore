/*
 * memallocator.h
 *
 *  Created on: 21-Dec-2016
 *      Author: hkadayam
 */

//  Copyright © 2016 Kadayam, Hari. All rights reserved.
#pragma once

#include <vector>
#include <tuple>
#include "chunk_allocator.hpp"

namespace omds {

#define MAX_MEM_POOLS 256

struct pool_config
{
	uint32_t pool_size;
	uint32_t obj_size;
	mempool *pool;
};

class AbstractMemAllocator
{
public:
    uint8_t *allocate(uint32_t size_needed, uint8_t **meta_blk = nullptr) = 0;
    bool deallocate(uint8_t *mem) = 0;
    bool owns(uint8_t *mem) = 0;
    bool is_thread_safe_allocator() = 0;
};

struct allocator_args
{
	uint8_t *rawptr;
	size_t size;
	mem_id_t mem_id;
};

#define KB(x) (x * 1024)
#define MB(x) (KB(x) * 1024)
#define GB(x) (MB(x) * 1024)

static std::vector<pool_config> default_cfg = {
		{MB(2), 12, nullptr},
		{MB(2), 128, nullptr}};

class mem_allocator
{
public:
	mem_allocator() : mem_allocator(default_cfg)
	{
	}

	mem_allocator(std::vector<pool_config> &cfgs, bool is_malloc_ok = true)
	{
		m_pools = cfgs;

		for (auto i = 0; i < m_pools.size(); i++) {
			pool_config *cfg = &m_pools[i];
			assert((i <= 0) || (m_pools[i-1].obj_size <= m_pools[i].obj_size));

			if (cfg->pool == nullptr) {
				cfg->pool = new fast_mempool(cfg->pool_size/cfg->obj_size, cfg->obj_size, i);
			}
		}

		m_malloc_ok = is_malloc_ok;
		if (m_malloc_ok) {
			pool_config cfg;
			cfg.obj_size = UINT32_MAX;
			cfg.pool_size = UINT32_MAX;
			cfg.pool = new system_mempool(m_pools.size());
			m_pools.push_back(cfg);
		}
	}

	virtual ~mem_allocator()
	{
		for (auto &cfg : m_pools) {
			delete(cfg.pool);
		}
	}

	uint8_t *alloc(size_t size)
	{
		return alloc(size, nullptr);
	}

	uint8_t *alloc(size_t size, mem_blk *outblk)
	{
		uint8_t *mem = nullptr;
		mem_id_t id_m;

		for (auto i = get_closest_pool(size); i < m_pools.size(); i++) {
			mem = m_pools[i].pool->alloc(size, &id_m);
			if (mem != nullptr) {
				if (outblk != nullptr) {
					outblk->mem_id = id_m;
					outblk->rawptr = mem;
					outblk->size = size;
				}
				break;
			}
		}
		return mem;
	}

	void free(uint8_t *mem)
	{
		assert(mem != nullptr);

		mempool *pool = get_owner_pool(mem);
		if (pool) {
			return pool->free(mem);
		} else {
			assert(0);
		}
	}

	// Faster way to free if caller can maintain the mem_blk.
	inline void free(mem_blk &blk)
	{
		mempool *pool = get_owner_pool(blk.mem_id);
		if (pool) {
			return pool->free(blk.rawptr);
		} else {
			assert(0);
		}
	}

	//// Fast_Mempool related methods. These are unsafe methods /////
	void free(mempool_header *hdr)
	{
		fast_mempool *pool = get_owner_pool(hdr);
		if (pool) {
			return pool->free(hdr);
		}
	}

	mem_id_t to_id(uint8_t *mem)
	{
		fast_mempool *pool = get_owner_pool(mem);
		if (pool) {
			return pool->to_mem_id(mem);
		}
		return mem_id_t::form(INVALID_MEM_ID);
	}

	mempool_header *to_hdr(uint8_t *mem)
	{
		fast_mempool *pool = get_owner_pool(mem);
		return (pool ? pool->to_hdr(mem) : nullptr);
	}

	mempool_header *to_hdr(mem_id_t id_m)
	{
		assert(id_m.pool_no < m_pools.size());
		fast_mempool *pool = m_pools[id_m.pool_no].pool;
		return pool->to_hdr(id_m);
	}

	uint8_t *to_rawptr(mem_id_t id_m)
	{
		assert(id_m.pool_no < m_pools.size());
		fast_mempool *pool = m_pools[id_m.pool_no].pool;
		return pool->mem_get(id_m);
	}

	uint8_t *to_rawptr(mempool_header *hdr)
	{
		fast_mempool *pool = get_owner_pool(hdr);
		return (pool ? pool->to_rawptr(hdr) : nullptr);
	}

private:
	int get_closest_pool(size_t req_size)
	{
		bool found = false;
		return bsearch(-1, m_pools.size(), req_size, &found);
	}

	uint32_t bsearch(int start, int end, size_t size, bool *isFound)
	{
		int mid = 0;
		*isFound = false;
		pool_config *midpool;

		while ( (end - start) > 1) {
			mid = start + (end - start) / 2;
			midpool = &m_pools[mid];

			if (midpool->obj_size == size) {
				*isFound = true;
				return mid;
			} else if (midpool->obj_size < size) {
				end = mid;
			} else {
				start = mid;
			}
		}

		return (end);
	}

	mempool *get_owner_pool(uint8_t *mem)
	{
		for (auto i = 0; i < m_pools.size(); i++) {
			if (m_pools[i].pool->owns(mem)) {
				return (m_pools[i].pool);
			}
		}
		return nullptr;
	}

	inline mempool *get_owner_pool(mem_id_t &id)
	{
		return (&m_pools[id.pool_no].pool);
	}

	/*/////////////////////////
	 * fast_mempool related methods. These are unsafe methods, because of
	 * usage of static_cast
	 */
	fast_mempool *get_owner_pool(mempool_header *hdr)
	{
		for (auto i = 0; i < m_pools.size(); i++) {
			if (m_pools[i].pool->owns(hdr)) {
				return (m_pools[i].pool);
			}
		}
		return nullptr;
	}
private:
	std::vector<pool_config> m_pools;
	bool m_malloc_ok;
};
}
