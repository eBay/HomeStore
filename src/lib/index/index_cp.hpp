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
#include <sisl/fds/thread_vector.hpp>
#include <homestore/blk.h>
#include <homestore/index/index_internal.hpp>
#include <homestore/checkpoint/cp_mgr.hpp>

#include "checkpoint/cp.hpp"

SISL_LOGGING_DECL(wbcache)

namespace homestore {
struct flush_buffer_iterator {
    sisl::thread_vector_iterator dirty_buf_list_it;
    sisl::thread_vector_iterator free_node_list_it;
};

struct IndexCPContext : public CPContext {
public:
    std::atomic< uint64_t > m_num_nodes_added{0};
    std::atomic< uint64_t > m_num_nodes_removed{0};
    sisl::ThreadVector< IndexBufferPtr >* m_dirty_buf_list{nullptr};
    sisl::ThreadVector< BlkId >* m_free_node_blkid_list{nullptr};
    sisl::atomic_counter< int64_t > m_dirty_buf_count{0};
    IndexBufferPtr m_last_in_chain;
    std::mutex m_flush_buffer_mtx;
    flush_buffer_iterator m_buf_it;

public:
    IndexCPContext(cp_id_t cp_id, sisl::ThreadVector< IndexBufferPtr >* dirty_list,
                   sisl::ThreadVector< BlkId >* free_blkid_list) :
            CPContext(cp_id), m_dirty_buf_list{dirty_list}, m_free_node_blkid_list{free_blkid_list} {}

    virtual ~IndexCPContext() {
        auto it = m_dirty_buf_list->begin(true /* latest */);
        IndexBufferPtr *tmp = nullptr;
        while((tmp = m_dirty_buf_list->next(it)) != nullptr) {
            tmp->reset();
        }
        m_dirty_buf_list->clear();
        m_free_node_blkid_list->clear();
    }

    void prepare_flush_iteration() {
        m_buf_it.dirty_buf_list_it = m_dirty_buf_list->begin(true /* latest */);
        m_buf_it.free_node_list_it = m_free_node_blkid_list->begin(true /* latest */);
    }

    void add_to_dirty_list(const IndexBufferPtr& buf) {
        buf->m_buf_state = index_buf_state_t::DIRTY;
        m_dirty_buf_list->push_back(buf);
        m_dirty_buf_count.increment(1);
        m_last_in_chain = buf;
        LOGTRACEMOD(wbcache, "{}", buf->to_string());
    }

    void add_to_free_node_list(BlkId blkid) { m_free_node_blkid_list->push_back(blkid); }

    bool any_dirty_buffers() const { return !m_dirty_buf_count.testz(); }

    IndexBufferPtr* next_dirty() { return m_dirty_buf_list->next(m_buf_it.dirty_buf_list_it); }
    BlkId* next_blkid() { return m_free_node_blkid_list->next(m_buf_it.free_node_list_it); }
    std::string to_string() const {
        std::string str{
            fmt::format("IndexCPContext cpid={} dirty_buf_count={} dirty_buf_list_size={} blkid_list_size={}", id(),
                        m_dirty_buf_count.get(), m_dirty_buf_list->size(), m_free_node_blkid_list->size())};

        // TODO dump all index buffers.
        return str;
    }
};

class IndexWBCache;
class IndexCPCallbacks : public CPCallbacks {
public:
    IndexCPCallbacks(std::unique_ptr< IndexWBCache > wb_cache);
    virtual ~IndexCPCallbacks() = default;

public:
    std::unique_ptr< CPContext > on_switchover_cp(CP* cur_cp, CP* new_cp) override;
    folly::Future< bool > cp_flush(CP* cp) override;
    void cp_cleanup(CP* cp) override;
    int cp_progress_percent() override;

private:
    std::unique_ptr< IndexWBCache > m_wb_cache;
};
} // namespace homestore
