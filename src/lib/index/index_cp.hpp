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

#include "device/virtual_dev.hpp"

SISL_LOGGING_DECL(wbcache)

namespace homestore {
struct IndexCPContext : public VDevCPContext {
public:
    std::atomic< uint64_t > m_num_nodes_added{0};
    std::atomic< uint64_t > m_num_nodes_removed{0};
    sisl::ConcurrentInsertVector< IndexBufferPtr > m_dirty_buf_list;
    sisl::atomic_counter< int64_t > m_dirty_buf_count{0};
    std::mutex m_flush_buffer_mtx;
    sisl::ConcurrentInsertVector< IndexBufferPtr >::iterator m_dirty_buf_it;

public:
    IndexCPContext(CP* cp) : VDevCPContext(cp) {}
    virtual ~IndexCPContext() = default;

    void add_to_dirty_list(const IndexBufferPtr& buf) {
        m_dirty_buf_list.push_back(buf);
        buf->set_state(index_buf_state_t::DIRTY);
        m_dirty_buf_count.increment(1);
    }

    bool any_dirty_buffers() const { return !m_dirty_buf_count.testz(); }

    void prepare_flush_iteration() { m_dirty_buf_it = m_dirty_buf_list.begin(); }

    std::optional< IndexBufferPtr > next_dirty() {
        if (m_dirty_buf_it == m_dirty_buf_list.end()) { return std::nullopt; }
        IndexBufferPtr ret = *m_dirty_buf_it;
        ++m_dirty_buf_it;
        return ret;
    }

    std::string to_string() {
        std::string str{fmt::format("IndexCPContext cpid={} dirty_buf_count={} dirty_buf_list_size={}", m_cp->id(),
                                    m_dirty_buf_count.get(), m_dirty_buf_list.size())};

        // Mapping from a node to all its parents in the graph.
        // Display all buffers and its dependencies and state.
        std::unordered_map< IndexBuffer*, std::vector< IndexBuffer* > > parents;

        auto it = m_dirty_buf_list.begin();
        while (it != m_dirty_buf_list.end()) {
            // Add this buf to his children.
            IndexBufferPtr buf = *it;
            parents[buf->m_next_buffer.lock().get()].emplace_back(buf.get());
            ++it;
        }

        it = m_dirty_buf_list.begin();
        while (it != m_dirty_buf_list.end()) {
            IndexBufferPtr buf = *it;
            fmt::format_to(std::back_inserter(str), "{}", buf->to_string());
            auto first = true;
            for (const auto& p : parents[buf.get()]) {
                if (first) {
                    fmt::format_to(std::back_inserter(str), "\nDepends:");
                    first = false;
                }
                fmt::format_to(std::back_inserter(str), " {}({})", r_cast< void* >(p), s_cast< int >(p->state()));
            }
            fmt::format_to(std::back_inserter(str), "\n");
            ++it;
        }

        return str;
    }

    void check_cycle() {
        // Use dfs to find if the graph is cycle
        auto it = m_dirty_buf_list.begin();
        while (it != m_dirty_buf_list.end()) {
            IndexBufferPtr buf = *it;
            ;
            std::set< IndexBuffer* > visited;
            check_cycle_recurse(buf, visited);
            ++it;
        }
    }

    void check_cycle_recurse(IndexBufferPtr buf, std::set< IndexBuffer* >& visited) const {
        if (visited.count(buf.get()) != 0) {
            LOGERROR("Cycle found for {}", buf->to_string());
            for (auto& x : visited) {
                LOGERROR("Path : {}", x->to_string());
            }
            return;
        }

        visited.insert(buf.get());
        if (buf->m_next_buffer.lock()) { check_cycle_recurse(buf->m_next_buffer.lock(), visited); }
    }

    void check_wait_for_leaders() {
        // Use the next buffer as indegree to find if wait_for_leaders is invalid.
        std::unordered_map< IndexBuffer*, int > wait_for_leaders;
        IndexBufferPtr buf;

        // Store the wait for leader count for each buffer.
        auto it = m_dirty_buf_list.begin();
        while (it != m_dirty_buf_list.end()) {
            buf = *it;
            wait_for_leaders[buf.get()] = buf->m_wait_for_leaders.get();
            ++it;
        }

        // Decrement the count using the next buffer.
        it = m_dirty_buf_list.begin();
        while (it != m_dirty_buf_list.end()) {
            buf = *it;
            auto next_buf = buf->m_next_buffer.lock();
            if (next_buf.get() == nullptr) continue;
            wait_for_leaders[next_buf.get()]--;
            ++it;
        }

        bool issue = false;
        for (const auto& [buf, waits] : wait_for_leaders) {
            // Any value other than zero means the dependency graph is invalid.
            if (waits != 0) {
                issue = true;
                LOGERROR("Leaders wait not zero cp {} buf {} waits {}", id(), buf->to_string(), waits);
            }
        }

        RELEASE_ASSERT_EQ(issue, false, "Found issue with wait_for_leaders");
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
