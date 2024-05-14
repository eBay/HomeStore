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
#include <homestore/homestore_decl.hpp>
#include <homestore/index/index_internal.hpp>
#include <homestore/superblk_handler.hpp>
#include <homestore/index/wb_cache_base.hpp>
namespace homestore {

class IndexWBCacheBase;
class IndexTableBase;
class VirtualDev;

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

    mutable std::mutex m_index_map_mtx;
    std::map< uuid_t, std::shared_ptr< IndexTableBase > > m_index_map;

public:
    IndexService(std::unique_ptr< IndexServiceCallbacks > cbs);

    // Creates the vdev that is needed to initialize the device
    void create_vdev(uint64_t size, HSDevType devType, uint32_t num_chunks);

    // Open the existing vdev which is represnted by the vdev_info_block
    shared< VirtualDev > open_vdev(const vdev_info& vb, bool load_existing);

    // Start the Index Service
    void start();

    // Stop the Index Service
    void stop();

    // Add/Remove Index Table to/from the index service
    void add_index_table(const std::shared_ptr< IndexTableBase >& tbl);
    void remove_index_table(const std::shared_ptr< IndexTableBase >& tbl);

    uint64_t used_size() const;
    uint32_t node_size() const;

    IndexWBCacheBase& wb_cache() { return *m_wb_cache; }

private:
    void itable_meta_blk_found(const sisl::byte_view& buf, void* meta_cookie);
};

extern IndexService& index_service();
extern IndexWBCacheBase& wb_cache();

} // namespace homestore
