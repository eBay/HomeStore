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
VChunk::VChunk(cshared< Chunk >& chunk) : m_internal_chunk(chunk) {}

void VChunk::set_user_private(const sisl::blob& data) { m_internal_chunk->set_user_private(data); }

const uint8_t* VChunk::get_user_private() const { return m_internal_chunk->user_private(); };

blk_num_t VChunk::get_total_blks() const { return m_internal_chunk->blk_allocator()->get_total_blks(); }

blk_num_t VChunk::available_blks() const { return m_internal_chunk->blk_allocator()->available_blks(); }

blk_num_t VChunk::get_freeable_nblks() const { return m_internal_chunk->blk_allocator()->get_freeable_nblks(); }

blk_num_t VChunk::get_defrag_nblks() const { return m_internal_chunk->blk_allocator()->get_defrag_nblks(); }

uint32_t VChunk::get_pdev_id() const { return m_internal_chunk->physical_dev()->pdev_id(); }

uint16_t VChunk::get_chunk_id() const { return m_internal_chunk->chunk_id(); }

cshared< Chunk > VChunk::get_internal_chunk() const { return m_internal_chunk; }
} // namespace homestore
