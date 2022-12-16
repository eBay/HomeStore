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
#include "blkalloc_cp.hpp"
#include "engine/homestore_base.hpp"
#include "engine/blkalloc/blk_allocator.h"
#include "engine/device/device.h" // TODO: Remove this once we make chunk accessible as common

namespace homestore {

blkalloc_cp::blkalloc_cp() : m_hs{HomeStoreBase::safe_instance()} {}

void blkalloc_cp::free_blks(const blkid_list_ptr& list) {
    auto it{list->begin(true /* latest */)};
    const BlkId* bid;
    while ((bid = list->next(it)) != nullptr) {
        const auto chunk_num{bid->get_chunk_num()};
        auto* const chunk{m_hs->get_device_manager()->get_chunk_mutable(chunk_num)};
        auto ba{chunk->get_blk_allocator_mutable()};
        ba->free_on_disk(*bid);
    }
    free_blkid_list_vector.push_back(list);
}

blkalloc_cp::~blkalloc_cp() {
    /* free all the blkids in the cache */
    for (auto& list : free_blkid_list_vector) {
        auto it{list->begin(false /* latest */)};
        const BlkId* bid;
        while ((bid = list->next(it)) != nullptr) {
            const auto chunk_num{bid->get_chunk_num()};
            auto* const chunk{m_hs->get_device_manager()->get_chunk_mutable(chunk_num)};
            chunk->get_blk_allocator_mutable()->free(*bid);
            const auto page_size{chunk->get_blk_allocator()->get_config().get_blk_size()};
            if (m_notify_free) { m_notify_free(bid->data_size(page_size)); }
        }
        list->clear();
    }
}
} // namespace homestore
