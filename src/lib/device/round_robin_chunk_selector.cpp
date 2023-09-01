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
#include "device/chunk_selector.hpp"
#include "device/chunk.h"

namespace homestore {
RoundRobinChunkSelector::RoundRobinChunkSelector(bool dynamic_chunk_add) : m_dynamic_chunk_add{dynamic_chunk_add} {
    RELEASE_ASSERT_EQ(dynamic_chunk_add, false,
                      "Dynamically adding chunk to chunkselector is not supported, need RCU to make it thread safe");
}

void RoundRobinChunkSelector::add_chunk(cshared< Chunk >& chunk) { m_chunks.push_back(chunk); }

Chunk* RoundRobinChunkSelector::select(blk_count_t, const blk_alloc_hints&) {
    if (*m_next_chunk_index >= m_chunks.size()) { *m_next_chunk_index = 0; }
    return m_chunks[(*m_next_chunk_index)++].get();
}

void RoundRobinChunkSelector::foreach_chunks(std::function< void(cshared< Chunk >&) >&& cb) {
    for (auto& chunk : m_chunks) {
        cb(chunk);
    }
}
} // namespace homestore