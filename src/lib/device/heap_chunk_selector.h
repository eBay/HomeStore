/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 *********************************************************************************/

#pragma once

#include "device/chunk_selector.h"

#include <queue>
#include <vector>
#include <mutex>

#include "device/chunk.h"

namespace homestore {
class HeapChunkSelector : public ChunkSelector {
public:
    HeapChunkSelector() = default;
    HeapChunkSelector(const HeapChunkSelector&) = delete;
    HeapChunkSelector(HeapChunkSelector&&) noexcept = delete;
    HeapChunkSelector& operator=(const HeapChunkSelector&) = delete;
    HeapChunkSelector& operator=(HeapChunkSelector&&) noexcept = delete;
    ~HeapChunkSelector() = default;

    void add_chunk(cshared< Chunk >& chunk) override;

    Chunk* select(blk_count_t nblks, const blk_alloc_hints& hints) override;
    
    void foreach_chunks(std::function< void(cshared< Chunk >&) >&& cb) override;

    void remove_chunk(cshared< Chunk >& chunk) override;

    class ChunkComparator {
    public:
        bool operator()(cshared< Chunk >& a, cshared< Chunk >& b) {
            return a->get_available_blks() < b->get_available_blks();
        }
    };

private:
    std::mutex lock;
    std::priority_queue<shared< Chunk >, std::vector<shared< Chunk >>, ChunkComparator> m_chunk_heap;
};
}