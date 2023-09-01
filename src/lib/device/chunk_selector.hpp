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

#include <vector>
#include <folly/ThreadLocal.h>
#include <sisl/logging/logging.h>

#include <homestore/homestore_decl.hpp>
#include <homestore/blk.h>

namespace homestore {
class Chunk;

class ChunkSelector {
public:
    ChunkSelector() = default;
    virtual void add_chunk(cshared< Chunk >& chunk) = 0;
    virtual void foreach_chunks(std::function< void(cshared< Chunk >&) >&& cb) = 0;
    virtual Chunk* select(blk_count_t nblks, const blk_alloc_hints& hints) = 0;

    virtual ~ChunkSelector() = default;
};

class RoundRobinChunkSelector : public ChunkSelector {
public:
    RoundRobinChunkSelector(bool dynamic_chunk_add = false);
    RoundRobinChunkSelector(const RoundRobinChunkSelector&) = delete;
    RoundRobinChunkSelector(RoundRobinChunkSelector&&) noexcept = delete;
    RoundRobinChunkSelector& operator=(const RoundRobinChunkSelector&) = delete;
    RoundRobinChunkSelector& operator=(RoundRobinChunkSelector&&) noexcept = delete;
    ~RoundRobinChunkSelector() = default;

    void add_chunk(cshared< Chunk >& chunk) override;

    Chunk* select(blk_count_t nblks, const blk_alloc_hints& hints) override;

    void foreach_chunks(std::function< void(cshared< Chunk >&) >&& cb) override;

private:
    std::vector< shared< Chunk > > m_chunks;
    folly::ThreadLocal< uint32_t > m_next_chunk_index;
    bool m_dynamic_chunk_add; // Can we add chunk dynamically
};

} // namespace homestore