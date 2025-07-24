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
#include <memory>
#include <unordered_map>
#include <vector>

#include <iomgr/iomgr.hpp>
#include <sisl/fds/id_reserver.hpp>
#include <homestore/homestore_decl.hpp>
#include <homestore/index/index_internal.hpp>
#include <homestore/superblk_handler.hpp>
#include <homestore/index/wb_cache_base.hpp>

namespace homestore {

class IndexWBCacheBase;
class IndexTableBase;
class VirtualDev;
class ChunkSelector;

class IndexServiceCallbacks {
public:
    virtual ~IndexServiceCallbacks() = default;
    virtual std::shared_ptr< IndexTableBase > on_index_table_found(superblk< index_table_sb >&&) {
        assert(0);
        return nullptr;
    }
};

class IndexService {
private:
    std::unique_ptr< IndexServiceCallbacks > m_svc_cbs;
    std::unique_ptr< IndexWBCacheBase > m_wb_cache;
    std::shared_ptr< VirtualDev > m_vdev;
    std::pair< meta_blk*, sisl::byte_view > m_wbcache_sb{
        std::pair< meta_blk*, sisl::byte_view >{nullptr, sisl::byte_view{}}};
    std::vector< std::pair< meta_blk*, sisl::byte_view > > m_itable_sbs;
    std::unique_ptr< sisl::IDReserver > m_ordinal_reserver;
    std::shared_ptr< ChunkSelector > m_custom_chunk_selector;

    mutable std::mutex m_index_map_mtx;
    std::map< uuid_t, std::shared_ptr< IndexTableBase > > m_index_map;
    std::unordered_map< uint32_t, std::shared_ptr< IndexTableBase > > m_ordinal_index_map;

public:
    IndexService(std::unique_ptr< IndexServiceCallbacks > cbs, shared< ChunkSelector > custom_chunk_selector = nullptr);
    ~IndexService();

    // Creates the vdev that is needed to initialize the device
    void create_vdev(uint64_t size, HSDevType devType, uint32_t num_chunks,
                     chunk_selector_type_t chunk_sel_type = chunk_selector_type_t::ROUND_ROBIN);
    // Open the existing vdev which is represnted by the vdev_info_block
    shared< VirtualDev > open_vdev(const vdev_info& vb, bool load_existing);
    std::shared_ptr< ChunkSelector > get_chunk_selector() { return m_custom_chunk_selector; };
    // for now, we don't support start after stop and there is no use case for this.
    // TODO: support start after stop if necessary

    //  Start the Index Service
    void start();

    // Stop the Index Service
    void stop();

    // Add/Remove Index Table to/from the index service
    uint64_t num_tables();
    bool add_index_table(const std::shared_ptr< IndexTableBase >& tbl);
    bool remove_index_table(const std::shared_ptr< IndexTableBase >& tbl);
    std::shared_ptr< IndexTableBase > get_index_table(uuid_t uuid) const;
    std::shared_ptr< IndexTableBase > get_index_table(uint32_t ordinal) const;
    void write_sb(uint32_t ordinal);
    bool sanity_check(const uint32_t index_ordinal, const IndexBufferPtrList& bufs) const;

    // Reserve/unreserve an ordinal for the index table
    uint32_t reserve_ordinal();
    bool reserve_ordinal(uint32_t ordinal);
    bool unreserve_ordinal(uint32_t ordinal);

    uint64_t used_size() const;
    uint32_t node_size() const;

    // the following methods are used wb_cache , which will not used by upper layer. so graceful shutdown just skips
    // them for now.
    void repair_index_node(uint32_t ordinal, IndexBufferPtr const& node_buf);
    void parent_recover(uint32_t ordinal, IndexBufferPtr const& node_buf);
    void update_root(uint32_t ordinal, IndexBufferPtr const& node_buf);

    IndexWBCacheBase& wb_cache() {
        if (!m_wb_cache) { throw std::runtime_error("Attempted to access a null pointer wb_cache"); }
        return *m_wb_cache;
    }

private:
    // graceful shutdown related
    std::atomic_bool m_stopping{false};
    mutable std::atomic_uint64_t pending_request_num{0};

    bool is_stopping() const { return m_stopping.load(); }
    void start_stopping() { m_stopping = true; }

    uint64_t get_pending_request_num() const { return pending_request_num.load(); }

    void incr_pending_request_num() const { pending_request_num++; }
    void decr_pending_request_num() const { pending_request_num--; }
};

extern IndexService& index_service();
extern IndexWBCacheBase& wb_cache();

} // namespace homestore
