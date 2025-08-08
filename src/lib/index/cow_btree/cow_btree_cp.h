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
#include <string>
#include <memory>
#include <vector>

#include <folly/futures/Future.h>
#include <sisl/fds/concurrent_insert_vector.hpp>
#include <sisl/utility/atomic_counter.hpp>
#include <homestore/checkpoint/cp_mgr.hpp>
#include <homestore/checkpoint/cp.hpp>
#include <iomgr/fiber_lib.hpp>
#include "device/virtual_dev.hpp"
#include "index/cow_btree/cow_btree_store.h"
#include "index/cow_btree/cow_btree.h"

namespace homestore {
class Index;
class COWBtree;

class COWBtreeCPCallbacks : public CPCallbacks {
public:
    COWBtreeCPCallbacks(COWBtreeStore* store);
    virtual ~COWBtreeCPCallbacks() = default;

public:
    std::unique_ptr< CPContext > on_switchover_cp(CP* cur_cp, CP* new_cp) override;
    folly::Future< bool > cp_flush(CP* cp) override;
    void cp_cleanup(CP* cp) override;
    int cp_progress_percent() override;

private:
    COWBtreeStore* m_bt_store;
};

struct COWBtreeCPContext : public CPContext {
public:
    sisl::atomic_counter< int64_t > m_dirty_size{0};
    sisl::atomic_counter< int64_t > m_pending_free_size{0};
    sisl::atomic_counter< int64_t > m_flushing_fibers_count{0};
    uint32_t const m_parallel_flushers_count;

    bool m_is_full_map_flush{false};
    iomgr::FiberManagerLib::shared_mutex m_bt_list_mtx;
    std::vector< shared< Index > > m_all_btrees;
    uint32_t m_flushed_btrees_count{0};
    std::vector< std::pair< shared< Index >, folly::Promise< folly::Unit > > > m_destroyed_btrees;
    std::vector< COWBtree* > m_active_btree_list;
    sisl::buf_builder m_merged_journal_buf;
    COWBtreeStore::Journal* m_journal_header;
    uint64_t m_max_dirty_size;
    uint64_t m_max_pending_free_size;

public:
    COWBtreeCPContext(CP* cp, COWBtreeStore* bt_store);
    virtual ~COWBtreeCPContext() = default;
    bool need_full_map_flush() const;
    void increment_dirty_size(uint32_t size);
    void increment_pending_free_size(uint32_t size);
    void prepare_to_flush(bool full_map_flush);

    void flushed_a_btree(COWBtree* cow_btree, COWBtree::Journal const* journal);
    folly::Future< folly::Unit > add_to_destroyed_list(shared< Index > btree);
    void actual_destroy_btrees();
    bool any_dirty_nodes() const { return (!m_dirty_size.testz() || !m_pending_free_size.testz()); }
    void append_btree_journal(sisl::io_blob_safe const& btree_journal_buf);
    sisl::byte_view store_journal() const;
    std::string to_string() const;
};
} // namespace homestore
