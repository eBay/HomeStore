#include "blkalloc_cp.hpp"
#include "homestore.hpp"
#include "blkalloc/blk_allocator.h"
#include "device/device.h" // TODO: Remove this once we make chunk accessible as common

namespace homestore {

blkalloc_cp::blkalloc_cp() : m_hs{HomeStore::safe_instance()} {}

void blkalloc_cp::free_blks(const blkid_list_ptr& list) {
    auto it{list->begin(true /* latest */)};
    const BlkId* bid;
    while ((bid = list->next(it)) != nullptr) {
        const auto chunk_num{bid->get_chunk_num()};
        auto* const chunk{m_hs->get_device_manager()->get_chunk_mutable(chunk_num)};
        auto ba{chunk->blk_allocator_mutable()};
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
