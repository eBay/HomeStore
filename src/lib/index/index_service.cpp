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
#include <homestore/homestore.hpp>
#include <homestore/index_service.hpp>
#include <homestore/index/index_internal.hpp>
#include "index/wb_cache.hpp"
#include "index/index_cp.hpp"
#include "common/homestore_utils.hpp"
#include "device/virtual_dev.hpp"
#include "device/physical_dev.hpp"

namespace homestore {
IndexService& index_service() { return hs()->index_service(); }

IndexService::IndexService(std::unique_ptr< IndexServiceCallbacks > cbs) : m_svc_cbs{std::move(cbs)} {
    meta_service().register_handler(
        "index",
        [this](meta_blk* mblk, sisl::byte_view buf, size_t size) {
            meta_blk_found(std::move(buf), voidptr_cast(mblk));
        },
        nullptr);
}

void IndexService::create_vdev(uint64_t size) {
    auto const atomic_page_size = hs()->device_mgr()->atomic_page_size({PhysicalDevGroup::FAST});

    struct blkstore_blob blob;
    blob.type = blkstore_type::INDEX_STORE;
    m_vdev =
        std::make_shared< VirtualDev >(hs()->device_mgr(), "index", PhysicalDevGroup::FAST, blk_allocator_type_t::fixed,
                                       size, 0, true, atomic_page_size, (char*)&blob, sizeof(blkstore_blob), true);
}

void IndexService::open_vdev(vdev_info_block* vb) {
    m_vdev = std::make_shared< VirtualDev >(hs()->device_mgr(), "index", vb, PhysicalDevGroup::FAST,
                                            blk_allocator_type_t::fixed, vb->is_failed(), true);
    if (vb->is_failed()) {
        LOGINFO("index vdev is in failed state");
        throw std::runtime_error("vdev in failed state");
    }
}

void IndexService::meta_blk_found(const sisl::byte_view& buf, void* meta_cookie) {
    // We have found an index table superblock. Notify the callback which should convert the superblock into actual
    // IndexTable instance
    superblk< index_table_sb > sb;
    sb.load(buf, meta_cookie);
    add_index_table(m_svc_cbs->on_index_table_found(sb));
}

void IndexService::start() {
    // Start Writeback cache
    m_wb_cache = std::make_unique< IndexWBCache >(m_vdev, hs()->evictor(),
                                                  hs()->device_mgr()->atomic_page_size({PhysicalDevGroup::FAST}));

    // Register to CP for flush dirty buffers
    hs()->cp_mgr().register_consumer(cp_consumer_t::INDEX_SVC,
                                     std::move(std::make_unique< IndexCPCallbacks >(m_wb_cache.get())));
}

void IndexService::add_index_table(const std::shared_ptr< IndexTableBase >& tbl) {
    std::unique_lock lg(m_index_map_mtx);
    m_index_map.insert(std::make_pair(tbl->uuid(), tbl));
}

uint32_t IndexService::node_size() const { return hs()->device_mgr()->atomic_page_size({PhysicalDevGroup::FAST}); }

uint64_t IndexService::used_size() const {
    auto size{0};
    std::unique_lock lg{m_index_map_mtx};
    for (auto& [id, table] : m_index_map) {
        size += table->used_size();
    }
    return size;
}

IndexBuffer::IndexBuffer(BlkId blkid, uint32_t buf_size, uint32_t align_size) :
        m_node_buf{hs_utils::iobuf_alloc(buf_size, sisl::buftag::btree_node, align_size)}, m_blkid{blkid} {}

IndexBuffer::~IndexBuffer() {
    hs_utils::iobuf_free(m_node_buf, sisl::buftag::btree_node);
}

} // namespace homestore
