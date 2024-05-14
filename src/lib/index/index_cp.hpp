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
#include <atomic>
#include <sisl/fds/concurrent_insert_vector.hpp>
#include <homestore/blk.h>
#include <homestore/index/index_internal.hpp>
#include <homestore/index_service.hpp>
#include <homestore/checkpoint/cp_mgr.hpp>
#include <homestore/checkpoint/cp.hpp>
#include <homestore/btree/detail/btree_node.hpp>
#include "device/virtual_dev.hpp"

SISL_LOGGING_DECL(wbcache)

namespace homestore {
class BtreeNode;
struct IndexCPContext : public VDevCPContext {
public:
    using compact_blkid_t = std::pair< blk_num_t, chunk_num_t >;
    using inplace_new_pair_t = std::pair< compact_blkid_t, compact_blkid_t >;
#pragma pack(1)
    struct new_blks_sb_t {
        cp_id_t cp_id;
        uint32_t num_blks{0};
        inplace_new_pair_t blks[1]; // C++ std probhits 0 size array
    };
#pragma pack()

public:
    std::atomic< uint64_t > m_num_nodes_added{0};
    std::atomic< uint64_t > m_num_nodes_removed{0};
    sisl::ConcurrentInsertVector< IndexBufferPtr > m_dirty_buf_list;
    sisl::atomic_counter< int64_t > m_dirty_buf_count{0};
    std::mutex m_flush_buffer_mtx;
    sisl::ConcurrentInsertVector< IndexBufferPtr >::iterator m_dirty_buf_it;

    iomgr::FiberManagerLib::mutex m_new_blk_mtx;
    sisl::io_blob_safe m_new_blk_buf;

public:
    IndexCPContext(CP* cp);
    virtual ~IndexCPContext() = default;

    void track_new_blk(BlkId const& inplace_blkid, BlkId const& new_blkid);
    void add_to_dirty_list(const IndexBufferPtr& buf);
    bool any_dirty_buffers() const;
    void prepare_flush_iteration();
    std::optional< IndexBufferPtr > next_dirty();
    std::string to_string();
    std::string to_string_with_dags();
    void check_cycle();
    void check_cycle_recurse(IndexBufferPtr buf, std::set< IndexBuffer* >& visited) const;
    void check_wait_for_leaders();
    sisl::io_blob_safe const& new_blk_buf() const { return m_new_blk_buf; }
    void log_dags();
};

class IndexWBCache;
class IndexCPCallbacks : public CPCallbacks {
public:
    IndexCPCallbacks(IndexWBCache* wb_cache);
    virtual ~IndexCPCallbacks() = default;

public:
    std::unique_ptr< CPContext > on_switchover_cp(CP* cur_cp, CP* new_cp) override;
    folly::Future< bool > cp_flush(CP* cp) override;
    void cp_cleanup(CP* cp) override;
    int cp_progress_percent() override;

private:
    IndexWBCache* m_wb_cache;
};
} // namespace homestore
