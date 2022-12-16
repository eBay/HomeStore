/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
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
#include <homestore/blk.h>
#include <homestore/homestore_decl.hpp>

namespace homestore {
typedef std::function< void(int status, void* cookie) > io_completion_cb_t;

class VirtualDev;
struct vdev_info_block;

class BlkDataService {
public:
    BlkDataService(uint64_t size, uint32_t page_size, blk_allocator_type_t blkalloc_type, bool cache = false);
    BlkDataService(vdev_info_block* vb, blk_allocator_type_t blkalloc_type, bool cache = false);

    void async_write(const sg_list& sgs, const blk_alloc_hints& hints, std::vector< BlkId >& out_blkids,
                     const io_completion_cb_t& cb);
    void async_read(const BlkId& bid, sg_list& sgs, uint32_t size, const io_completion_cb_t& cb);

    void commit_blks(const BlkId& bid);
    void async_free_blks(const BlkId& bid, const io_completion_cb_t& cb);

private:
    std::unique_ptr< VirtualDev > m_vdev;
    uint32_t m_page_size;
};
} // namespace homestore
