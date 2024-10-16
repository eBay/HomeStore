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
#include <homestore/btree/detail/btree_node.hpp>
#include "index/wb_cache.hpp"
#include "index/index_cp.hpp"
#include "common/homestore_utils.hpp"
#include "common/homestore_assert.hpp"
#include "device/virtual_dev.hpp"
#include "device/physical_dev.hpp"
#include "device/chunk.h"

namespace homestore {
IndexService& index_service() { return hs()->index_service(); }

IndexService::IndexService(std::unique_ptr< IndexServiceCallbacks > cbs) : m_svc_cbs{std::move(cbs)} {
    m_ordinal_reserver = std::make_unique< sisl::IDReserver >();
    meta_service().register_handler(
        "index",
        [this](meta_blk* mblk, sisl::byte_view buf, size_t size) {
            m_itable_sbs.emplace_back(std::pair{mblk, std::move(buf)});
        },
        nullptr);

    meta_service().register_handler(
        "wb_cache",
        [this](meta_blk* mblk, sisl::byte_view buf, size_t size) { m_wbcache_sb = std::pair{mblk, std::move(buf)}; },
        nullptr);
}

void IndexService::create_vdev(uint64_t size, HSDevType devType, uint32_t num_chunks) {
    auto const atomic_page_size = hs()->device_mgr()->atomic_page_size(devType);
    hs_vdev_context vdev_ctx;
    vdev_ctx.type = hs_vdev_type_t::INDEX_VDEV;

    hs()->device_mgr()->create_vdev(vdev_parameters{.vdev_name = "index",
                                                    .vdev_size = size,
                                                    .num_chunks = num_chunks,
                                                    .blk_size = atomic_page_size,
                                                    .dev_type = devType,
                                                    .alloc_type = blk_allocator_type_t::fixed,
                                                    .chunk_sel_type = chunk_selector_type_t::ROUND_ROBIN,
                                                    .multi_pdev_opts = vdev_multi_pdev_opts_t::ALL_PDEV_STRIPED,
                                                    .context_data = vdev_ctx.to_blob()});
}

shared< VirtualDev > IndexService::open_vdev(const vdev_info& vinfo, bool load_existing) {
    m_vdev =
        std::make_shared< VirtualDev >(*(hs()->device_mgr()), vinfo, nullptr /* event_cb */, true /* auto_recovery */);
    return m_vdev;
}

uint32_t IndexService::reserve_ordinal() { return m_ordinal_reserver->reserve(); }

void IndexService::start() {
    // Start Writeback cache
    m_wb_cache = std::make_unique< IndexWBCache >(m_vdev, m_wbcache_sb, hs()->evictor(),
                                                  hs()->device_mgr()->atomic_page_size(HSDevType::Fast));

    // Load any index tables which are to loaded from meta blk
    for (auto const& [meta_cookie, buf] : m_itable_sbs) {
        superblk< index_table_sb > sb;
        sb.load(buf, meta_cookie);
        add_index_table(m_svc_cbs->on_index_table_found(std::move(sb)));
    }

    // Recover the writeback cache, which in-turns recovers any index table nodes
    m_wb_cache->recover(m_wbcache_sb.second);

    // Notify each table that we have completed recovery
    std::unique_lock lg(m_index_map_mtx);
    for (const auto& [_, tbl] : m_index_map) {
        tbl->recovery_completed();
    }
}

void IndexService::stop() { m_wb_cache.reset(); }

uint64_t IndexService::num_tables() {
    std::unique_lock lg(m_index_map_mtx);
    return m_index_map.size();
}

void IndexService::add_index_table(const std::shared_ptr< IndexTableBase >& tbl) {
    std::unique_lock lg(m_index_map_mtx);
    m_index_map.insert(std::make_pair(tbl->uuid(), tbl));
    m_ordinal_index_map.insert(std::make_pair(tbl->ordinal(), tbl));
}

void IndexService::remove_index_table(const std::shared_ptr< IndexTableBase >& tbl) {
    std::unique_lock lg(m_index_map_mtx);
    m_index_map.erase(tbl->uuid());
    m_ordinal_index_map.erase(tbl->ordinal());
}

std::shared_ptr< IndexTableBase > IndexService::get_index_table(uuid_t uuid) const {
    std::unique_lock lg(m_index_map_mtx);
    auto const it = m_index_map.find(uuid);
    return (it != m_index_map.cend()) ? it->second : nullptr;
}

std::shared_ptr< IndexTableBase > IndexService::get_index_table(uint32_t ordinal) const {
    std::unique_lock lg(m_index_map_mtx);
    auto const it = m_ordinal_index_map.find(ordinal);
    return (it != m_ordinal_index_map.cend()) ? it->second : nullptr;
}

void IndexService::repair_index_node(uint32_t ordinal, IndexBufferPtr const& node_buf) {
    auto tbl = get_index_table(ordinal);
    if (tbl) {
        tbl->repair_node(node_buf);
    } else {
        HS_DBG_ASSERT(false, "Index corresponding to ordinal={} has not been loaded yet, unexpected", ordinal);
    }
}

uint32_t IndexService::node_size() const { return m_vdev->atomic_page_size(); }

uint64_t IndexService::used_size() const {
    auto size{0};
    std::unique_lock lg{m_index_map_mtx};
    for (auto& [id, table] : m_index_map) {
        size += table->used_size();
    }
    return size;
}

/////////////////////// IndexBuffer methods //////////////////////////
IndexBuffer::IndexBuffer(BlkId blkid, uint32_t buf_size, uint32_t align_size) :
        m_blkid{blkid}, m_bytes{hs_utils::iobuf_alloc(buf_size, sisl::buftag::btree_node, align_size)} {}

IndexBuffer::IndexBuffer(uint8_t* raw_bytes, BlkId blkid) : m_blkid(blkid), m_bytes{raw_bytes} {}

IndexBuffer::~IndexBuffer() {
    if (m_bytes) { hs_utils::iobuf_free(m_bytes, sisl::buftag::btree_node); }
}

std::string IndexBuffer::to_string() const {
    if (m_is_meta_buf) {
        return fmt::format("Buf={} [Meta] index={} state={} create/dirty_cp={}/{} down_wait#={} freed={}",
                           voidptr_cast(const_cast< IndexBuffer* >(this)), m_index_ordinal, int_cast(state()),
                           m_created_cp_id, m_dirtied_cp_id, m_wait_for_down_buffers.get(), m_node_freed);
    } else {
        // store m_down_buffers in a string
        std::string down_bufs = "";
#ifndef NDEBUG
        for (auto const& down_buf : m_down_buffers) {
            if (auto ptr = down_buf.lock()) {
                fmt::format_to(std::back_inserter(down_bufs), "[{}]", voidptr_cast(ptr.get()));
            }
        }
#endif

        return fmt::format("Buf={} index={} state={} create/dirty_cp={}/{} down_wait#={}{} up={} node=[{}] down=[{}]",
                           voidptr_cast(const_cast< IndexBuffer* >(this)), m_index_ordinal, int_cast(state()),
                           m_created_cp_id, m_dirtied_cp_id, m_wait_for_down_buffers.get(),
                           m_node_freed ? " Freed" : "", voidptr_cast(const_cast< IndexBuffer* >(m_up_buffer.get())),
                           (m_bytes == nullptr) ? "not attached yet"
                                                : r_cast< persistent_hdr_t const* >(m_bytes)->to_compact_string(),
                           down_bufs);
    }
}
std::string IndexBuffer::to_string_dot() const {
    auto str = fmt::format("IndexBuffer {} ", reinterpret_cast< void* >(const_cast< IndexBuffer* >(this)));
    if (m_bytes == nullptr) {
        fmt::format_to(std::back_inserter(str), " node_buf=nullptr ");
    } else {
        fmt::format_to(std::back_inserter(str), " node_buf={} {} created/dirtied={}/{} {}  down_wait#={}",
                       static_cast< void* >(m_bytes), m_is_meta_buf ? "[META]" : "", m_created_cp_id, m_dirtied_cp_id,
                       m_node_freed ? "FREED" : "", m_wait_for_down_buffers.get());
    }
    return str;
}

MetaIndexBuffer::MetaIndexBuffer(superblk< index_table_sb >& sb) : IndexBuffer{nullptr, BlkId{}}, m_sb{sb} {
    m_is_meta_buf = true;
}

MetaIndexBuffer::MetaIndexBuffer(shared< MetaIndexBuffer > const& other) :
        IndexBuffer{nullptr, BlkId{}}, m_sb{other->m_sb} {
    m_is_meta_buf = true;
    m_bytes = hs_utils::iobuf_alloc(m_sb.size(), sisl::buftag::metablk, meta_service().align_size());
    copy_sb_to_buf();
}

MetaIndexBuffer::~MetaIndexBuffer() {
    if (m_bytes) {
        hs_utils::iobuf_free(m_bytes, sisl::buftag::metablk);
        m_bytes = nullptr;
    }
}

void MetaIndexBuffer::copy_sb_to_buf() { std::memcpy(m_bytes, m_sb.raw_buf()->cbytes(), m_sb.size()); }
} // namespace homestore
