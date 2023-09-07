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

#include <sisl/fds/buffer.hpp>
#include <homestore/blk.h>
#include <homestore/homestore_decl.hpp>

namespace homestore {
class Chunk;

class VChunk {
public:
    VChunk(cshared< Chunk >&);
    ~VChunk() = default;

    void set_user_private(const sisl::blob& data);
    uint8_t* get_user_private();
    blk_cap_t available_blks();
    uint32_t getPdevID();
    cshared< Chunk > getInternalChunk();

private:
    cshared< Chunk > internalChunk;
};
}// namespace homestore
