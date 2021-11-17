#include "blkalloc_cp.hpp"
#include "engine/homestore_base.hpp"
#include "engine/blkalloc/blk_allocator.h"
#include "engine/device/device.h" // TODO: Remove this once we make chunk accessible as common

namespace homestore {

blkalloc_cp::blkalloc_cp() : m_hs{HomeStoreBase::safe_instance()} {}

void blkalloc_cp::free_blks(const blkid_list_ptr& list) {
    auto it{list->begin(true /* latest */)};
    const std::pair< BlkId, PhysicalDevGroup >* bid_pair;
    while ((bid_pair = list->next(it)) != nullptr) {
        const auto chunk_num{bid_pair->first.get_chunk_num()};
        auto* const chunk{m_hs->get_device_manager()->get_chunk_mutable(chunk_num, bid_pair->second)};
        auto ba{chunk->get_blk_allocator_mutable()};
        ba->free_on_disk(bid_pair->first);
    }
    free_blkid_list_vector.push_back(list);
}

blkalloc_cp::~blkalloc_cp() {
    /* free all the blkids in the cache */
    for (auto& list : free_blkid_list_vector) {
        const std::pair< BlkId, PhysicalDevGroup >* bid_pair;
        auto it{list->begin(false /* latest */)};
        while ((bid_pair = list->next(it)) != nullptr) {
            const auto chunk_num{bid_pair->first.get_chunk_num()};
            auto* const chunk{m_hs->get_device_manager()->get_chunk_mutable(chunk_num, bid_pair->second)};
            chunk->get_blk_allocator_mutable()->free(bid_pair->first);
            const auto page_size{chunk->get_blk_allocator()->get_config().get_blk_size()};
            if (m_notify_free) { m_notify_free(bid_pair->first.data_size(page_size)); }
        }
        list->clear();
    }
}
} // namespace homestore
