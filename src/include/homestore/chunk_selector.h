/*********************************************************************************
 * Modifications Copyright 2017-2023 eBay Inc.
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

#include <homestore/vchunk.h>

namespace homestore {
class Chunk;
class ChunkSelector {
public:
    ChunkSelector() = default;
    virtual void add_chunk(VChunk chunk) = 0;
    virtual void foreach_chunks(std::function< void(VChunk&) >&& cb) = 0;
    virtual Chunk* select_chunk(blk_count_t nblks, const blk_alloc_hints& hints) = 0;

    virtual ~ChunkSelector() = default;
};
} // namespace homestore
