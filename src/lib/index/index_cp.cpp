#include <stack>
#include <unordered_map>

#include "index/index_cp.hpp"
#include "index/wb_cache.hpp"

namespace homestore {
IndexCPCallbacks::IndexCPCallbacks(IndexWBCache* wb_cache) : m_wb_cache{wb_cache} {}

std::unique_ptr< CPContext > IndexCPCallbacks::on_switchover_cp(CP* cur_cp, CP* new_cp) {
    return std::make_unique< IndexCPContext >(new_cp);
}

folly::Future< bool > IndexCPCallbacks::cp_flush(CP* cp) {
    auto ctx = s_cast< IndexCPContext* >(cp->context(cp_consumer_t::INDEX_SVC));
    return m_wb_cache->async_cp_flush(ctx);
}

void IndexCPCallbacks::cp_cleanup(CP* cp) {}

int IndexCPCallbacks::cp_progress_percent() { return 100; }

/////////////////////// IndexCPContext section ///////////////////////////
IndexCPContext::IndexCPContext(CP* cp) : VDevCPContext(cp) {}

void IndexCPContext::track_new_blk(BlkId const& inplace_blkid, BlkId const& new_blkid) {
    static constexpr uint32_t initial_count = 100;
    auto size_for_count = [](uint32_t count) {
        return sizeof(new_blks_sb_t) + ((count - 1) * sizeof(inplace_new_pair_t));
    };

    std::unique_lock< iomgr::FiberManagerLib::mutex > lg{m_new_blk_mtx};
    if (m_new_blk_buf.bytes() == nullptr) {
        m_new_blk_buf = std::move(sisl::io_blob_safe{size_for_count(initial_count), 512, sisl::buftag::metablk});
        new_blks_sb_t* sb = new (m_new_blk_buf.bytes()) new_blks_sb_t();
        sb->cp_id = id();
    }

    new_blks_sb_t* sb = r_cast< new_blks_sb_t* >(m_new_blk_buf.bytes());
    if (m_new_blk_buf.size() < size_for_count(sb->num_blks + 1)) {
        m_new_blk_buf.buf_realloc(m_new_blk_buf.size() + size_for_count(sb->num_blks * 2), 512, sisl::buftag::metablk);
        sb = r_cast< new_blks_sb_t* >(m_new_blk_buf.bytes());
    }
    sb->blks[sb->num_blks++] = std::pair(std::pair(inplace_blkid.blk_num(), inplace_blkid.chunk_num()),
                                         std::pair(new_blkid.blk_num(), new_blkid.chunk_num()));
}

void IndexCPContext::add_to_dirty_list(const IndexBufferPtr& buf) {
    m_dirty_buf_list.push_back(buf);
    buf->set_state(index_buf_state_t::DIRTY);
    m_dirty_buf_count.increment(1);
}

bool IndexCPContext::any_dirty_buffers() const { return !m_dirty_buf_count.testz(); }

void IndexCPContext::prepare_flush_iteration() { m_dirty_buf_it = m_dirty_buf_list.begin(); }

std::optional< IndexBufferPtr > IndexCPContext::next_dirty() {
    if (m_dirty_buf_it == m_dirty_buf_list.end()) { return std::nullopt; }
    IndexBufferPtr ret = *m_dirty_buf_it;
    ++m_dirty_buf_it;
    return ret;
}

std::string IndexCPContext::to_string() {
    std::string str{fmt::format("IndexCPContext cpid={} dirty_buf_count={} dirty_buf_list_size={}", m_cp->id(),
                                m_dirty_buf_count.get(), m_dirty_buf_list.size())};

    // Mapping from a node to all its parents in the graph.
    // Display all buffers and its dependencies and state.
    std::unordered_map< IndexBuffer*, std::vector< IndexBuffer* > > parents;

    m_dirty_buf_list.foreach_entry([&parents](IndexBufferPtr buf) {
        // Add this buf to his children.
        parents[buf->m_up_buffer.lock().get()].emplace_back(buf.get());
    });

    m_dirty_buf_list.foreach_entry([&str, &parents](IndexBufferPtr buf) {
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
    });
    return str;
}

std::string IndexCPContext::to_string_with_dags() {
    struct DagNode {
        IndexBufferPtr buf;
        std::vector< shared< DagNode > > children;
    };
    std::vector< shared< DagNode > > group_roots;
    std::unordered_map< IndexBufferPtr, shared< DagNode > > buf_to_dag_node;

    auto get_insert_buf = [&buf_to_dag_node](IndexBufferPtr buf) {
        auto it = buf_to_dag_node.find(buf);
        if (it == buf_to_dag_node.end()) {
            auto dgn = std::make_shared< DagNode >();
            dgn->buf = buf;
            buf_to_dag_node[buf] = dgn;
            return dgn;
        }
        return it->second;
    };

    std::unique_lock lg{m_flush_buffer_mtx};
    // Create the graph
    m_dirty_buf_list.foreach_entry([&get_insert_buf, &group_roots](IndexBufferPtr buf) {
        auto parent_buf = buf->m_up_buffer.lock();
        if (parent_buf == nullptr) {
            auto dgn = get_insert_buf(buf);
            group_roots.emplace_back(dgn);
        } else {
            auto dgn = get_insert_buf(buf);
            auto parent_dgn = get_insert_buf(parent_buf);
            parent_dgn->children.emplace_back(dgn);
        }
    });

    // Now walk through the list of graphs and prepare formatted string
    std::string str{fmt::format("IndexCPContext cpid={} dirty_buf_count={} dirty_buf_list_size={} #_of_dags={}\n",
                                m_cp->id(), m_dirty_buf_count.get(), m_dirty_buf_list.size(), group_roots.size())};
    for (const auto& root : group_roots) {
        std::vector< std::pair< std::shared_ptr< DagNode >, int > > stack;
        stack.emplace_back(root, 0);
        while (!stack.empty()) {
            auto [node, level] = stack.back();
            stack.pop_back();
            fmt::format_to(std::back_inserter(str), "{}{} \n", std::string(level * 4, ' '), node->buf->to_string());
            for (const auto& child : node->children) {
                stack.emplace_back(child, level + 1);
            }
        }
    }

    return str;
}

void IndexCPContext::log_dags() {
    LOGINFO("{}", to_string_with_dags());
    sisl::logging::GetLogger()->flush();
}

#if 0
void IndexCPContext::check_cycle() {
    // Use dfs to find if the graph is cycle
    auto it = m_dirty_buf_list.begin();
    while (it != m_dirty_buf_list.end()) {
        IndexBufferPtr buf = *it;
        std::set< IndexBuffer* > visited;
        check_cycle_recurse(buf, visited);
        ++it;
    }
}

void IndexCPContext::check_cycle_recurse(IndexBufferPtr buf, std::set< IndexBuffer* >& visited) const {
    if (visited.count(buf.get()) != 0) {
        LOGERROR("Cycle found for {}", buf->to_string());
        for (auto& x : visited) {
            LOGERROR("Path : {}", x->to_string());
        }
        return;
    }

    visited.insert(buf.get());
    if (buf->m_up_buffer.lock()) { check_cycle_recurse(buf->m_up_buffer.lock(), visited); }
}

void IndexCPContext::check_wait_for_leaders() {
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
#endif

#if 0
/////////////////////// NewBlkTracker section ///////////////////////////
IndexCPContext::NewBlkTracker::NewBlkTracker(cp_id_t cp_id, superblk< void >& sb) : m_sb{sb} {
    if (sb.is_empty()) {
        sb.create(initial_size());
    } else {
        serialized* s = r_cast< serialized* >(sb.raw_buf().bytes());
        if (s->cp_id == cp_id) {
            // We are loading the same cp as it is previously. Walk through all blks and add it to the list
            LOGINFOMOD(wbcache, "Prior to restart allocated {} new blks, tracking them", s->num_blks);
            for (auto i = 0u; i < m_s->num_blks; ++i) {
                m_new_blks.insert(BlkId{s->blks[i].first, 1 /* num_blks */, s->blks[i].second});
            }
            s->num_blks = 0; // Reset the count, since everything is loaded
        } else {
            // We are loading a new cp. Reset the sb.
            HD_DBG_ASSERT_GT(cp_id, s->cp_id, "New cp_id is less than the existing cp_id in wbcache sb");
            s->cp_id = cp_id;
            s->num_blks = 0;
        }
    }
}

void IndexCPContext::NewBlkTracker::add(BlkId const& blkid) {
    std::unique_lock< iomgr::FiberManagerLib::mutex > lg{m_mtx};
    serialized* s = r_cast< serialized* >(sb.raw_buf().bytes());
    if (!has_room(1u)) {
        m_sb.resize(m_sb.size() + size_for_count(s->num_blks * 2));
        s = r_cast< serialized* >(m_sb.raw_buf().bytes());
    }
    s->blks[s->num_blks++] = std::pair(blkid.blk_num(), blkid.chunk_num());
}

std::unordered_set< BlkId > IndexCPContext::NewBlkTracker::move_all() {
    std::unique_lock< iomgr::FiberManagerLib::mutex > lg{m_mtx};
    return std::move(m_new_blks);
}

void IndexCPContext::NewBlkTracker::flush() { m_sb.write(); }
#endif

} // namespace homestore
