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

namespace homestore {

class IndexWBCache;
class IndexTableBase;
class VirtualDev;

class IndexServiceCallbacks {
public:
    virtual std::shared_ptr< IndexTableBase > on_index_table_found(const superblk< index_table_sb >& cb) = 0;
};

class IndexService {
private:
    std::unique_ptr< IndexServiceCallbacks > m_svc_cbs;
    std::unique_ptr< IndexWBCache > m_wb_cache;
    std::shared_ptr< VirtualDev > m_vdev;
    std::vector< iomgr::io_thread_t > m_btree_write_thread_ids; // user io threads for btree write
    uint32_t m_btree_write_thrd_idx{0};

    mutable std::mutex m_index_map_mtx;
    std::map< uuid_t, std::shared_ptr< IndexTableBase > > m_index_map;

public:
    IndexService(std::unique_ptr< IndexServiceCallbacks > cbs);

    // Creates the vdev that is needed to initialize the device
    void create_vdev(uint64_t size);

    // Open the existing vdev which is represnted by the vdev_info_block
    void open_vdev(vdev_info_block* vb);

    // Start the Index Service
    void start();

    // Add/Remove Index Table to/from the index service
    void add_index_table(const std::shared_ptr< IndexTableBase >& tbl);
    void remove_index_table(const std::shared_ptr< IndexTableBase >& tbl);

    uint64_t used_size() const;

    iomgr::io_thread_t get_next_btree_write_thread();
    IndexWBCache& wb_cache() { return *m_wb_cache; }

private:
    void meta_blk_found(const sisl::byte_view& buf, void* meta_cookie);
    void start_threads();
};

extern IndexService& index_service();
extern IndexWBCache& wb_cache();

} // namespace homestore
