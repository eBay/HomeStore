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
#include <homestore/vchunk.h>
#include "blkalloc/blk_allocator.h"
#include "device/chunk.h"

namespace homestore {
    VChunk::VChunk(cshared< Chunk >& chunk) : internalChunk(chunk){}

    void VChunk::set_user_private(const sisl::blob& data){
        internalChunk->set_user_private(data);
    }

    uint8_t* VChunk::get_user_private() {
        return internalChunk->user_private();
    };

    blk_cap_t VChunk::available_blks() {
        return internalChunk->blk_allocator()->available_blks();
    }

    uint32_t VChunk::getPdevID() {
        return internalChunk->physical_dev()->pdev_id();
    }

    cshared< Chunk > VChunk::getInternalChunk() {return internalChunk;}
}// namespace homestore
