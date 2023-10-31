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
#include <homestore/checkpoint/cp_mgr.hpp>

#include "checkpoint/cp.hpp"
#include "device/virtual_dev.hpp"

SISL_LOGGING_DECL(wbcache)

namespace homestore {
struct IndexCPContext : public VDevCPContext {
public:
    std::atomic< uint64_t > m_num_nodes_added{0};
    std::atomic< uint64_t > m_num_nodes_removed{0};
    sisl::ConcurrentInsertVector< IndexBufferPtr > m_dirty_buf_list;
    sisl::atomic_counter< int64_t > m_dirty_buf_count{0};
    IndexBufferPtr m_last_in_chain;
    std::mutex m_flush_buffer_mtx;
    sisl::ConcurrentInsertVector< IndexBufferPtr >::iterator m_dirty_buf_it;

public:
    IndexCPContext(CP* cp) : VDevCPContext(cp) {}
    virtual ~IndexCPContext() = default;

    void add_to_dirty_list(const IndexBufferPtr& buf) {
        buf->m_buf_state = index_buf_state_t::DIRTY;
        m_dirty_buf_list.push_back(buf);
        m_dirty_buf_count.increment(1);
        m_last_in_chain = buf;
        LOGTRACEMOD(wbcache, "{}", buf->to_string());
    }

    bool any_dirty_buffers() const { return !m_dirty_buf_count.testz(); }

    void prepare_flush_iteration() { m_dirty_buf_it = m_dirty_buf_list.begin(); }

    std::optional< IndexBufferPtr > next_dirty() {
        if (m_dirty_buf_it == m_dirty_buf_list.end()) { return std::nullopt; }
        IndexBufferPtr ret = *m_dirty_buf_it;
        ++m_dirty_buf_it;
        return ret;
    }

    std::string to_string() const {
        std::string str{fmt::format("IndexCPContext cpid={} dirty_buf_count={} dirty_buf_list_size={}", m_cp->id(),
                                    m_dirty_buf_count.get(), m_dirty_buf_list.size())};

        // TODO dump all index buffers.
        return str;
    }
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
