#include <stack>
#include <unordered_map>

#include <homestore/checkpoint/cp_mgr.hpp>
#include "index/index_cp.hpp"
#include "index/wb_cache.hpp"
#include "common/homestore_assert.hpp"

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

void IndexCPContext::add_to_txn_journal(uint32_t index_ordinal, const IndexBufferPtr& parent_buf,
                                        const IndexBufferPtr& left_child_buf, const IndexBufferPtrList& created_bufs,
                                        const IndexBufferPtrList& freed_bufs) {
    auto record_size = txn_record::size_for_num_ids(created_bufs.size() + freed_bufs.size() + (left_child_buf ? 1 : 0) +
                                                    (parent_buf ? 1 : 0));
    std::unique_lock< iomgr::FiberManagerLib::mutex > lg{m_txn_journal_mtx};
    if (m_txn_journal_buf.bytes() == nullptr) {
        m_txn_journal_buf =
            std::move(sisl::io_blob_safe{std::max(sizeof(txn_journal), 512ul), 512, sisl::buftag::metablk});
        txn_journal* tj = new (m_txn_journal_buf.bytes()) txn_journal();
        tj->cp_id = id();
    }

    txn_journal* tj = r_cast< txn_journal* >(m_txn_journal_buf.bytes());
    if (m_txn_journal_buf.size() < tj->size + record_size) {
        m_txn_journal_buf.buf_realloc(m_txn_journal_buf.size() + std::max(tj->size + record_size, 512u), 512,
                                      sisl::buftag::metablk);
        tj = r_cast< txn_journal* >(m_txn_journal_buf.bytes());
    }

    {
        auto rec = tj->append_record(index_ordinal);
        if (parent_buf) {
            rec->append(op_t::parent_inplace, parent_buf->blkid());
            if (parent_buf->is_meta_buf()) { rec->is_parent_meta = 0x1; }
        }
        if (left_child_buf && (left_child_buf != parent_buf)) {
            rec->append(op_t::child_inplace, left_child_buf->blkid());
        }
        for (auto const& buf : created_bufs) {
            rec->append(op_t::child_new, buf->blkid());
        }
        for (auto const& buf : freed_bufs) {
            rec->free_node_level = buf->m_node_level;
            rec->append(op_t::child_freed, buf->blkid());
        }
    }
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

std::string IndexCPContext::to_string_small() {
    return fmt::format("IndexCPContext cpid={}, dirty_buf_count={}, dirty_buf_list_size={}", m_cp->id(), m_dirty_buf_count.get(), 
                       m_dirty_buf_list.size());
}

std::string IndexCPContext::to_string() {
    std::string str{fmt::format("IndexCPContext cpid={} dirty_buf_count={} dirty_buf_list_size={}\n", m_cp->id(),
                                m_dirty_buf_count.get(), m_dirty_buf_list.size())};

    // Mapping from a node to all its parents in the graph.
    // Display all buffers and its dependencies and state.
    std::unordered_map< IndexBuffer*, std::vector< IndexBuffer* > > parents;

    m_dirty_buf_list.foreach_entry([&parents](IndexBufferPtr buf) {
        // Add this buf to his children.
        parents[buf->m_up_buffer.get()].emplace_back(buf.get());
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

void IndexCPContext::to_string_dot(const std::string& filename) {
    std::ofstream file(filename);
    if (!file.is_open()) { throw std::runtime_error("Failed to open file: " + filename); }

    file << "digraph G {\n";

    // Mapping from a node to all its parents in the graph.
    std::unordered_map< IndexBuffer*, std::vector< IndexBuffer* > > parents;

    m_dirty_buf_list.foreach_entry([&parents](IndexBufferPtr buf) {
        // Add this buf to his children.
        parents[buf->m_up_buffer.get()].emplace_back(buf.get());
    });
    m_dirty_buf_list.foreach_entry([&file, &parents, this](IndexBufferPtr buf) {
        std::vector< std::string > colors = {"lightgreen", "lightcoral", "lightyellow"};
        auto sbuf = BtreeNode::to_string_buf(buf->raw_buffer());
        auto pos = sbuf.find("LEAF");
        if (pos != std::string::npos) {
            sbuf.insert(pos + 4, "<br/>");
        } else {
            pos = sbuf.find("INTERIOR");
            if (pos != std::string::npos) { sbuf.insert(pos + 8, "<br/>"); }
        }
        file << fmt::format(
            "\"{}\" [shape={}, label=< <b>{}</b><br/>{} >, fillcolor=\"{}\", style=\"filled\", fontname=\"bold\"];\n",
            r_cast< void* >(buf.get()), m_cp->id() == buf->m_created_cp_id ? "ellipse" : "box", buf->to_string_dot(),
            sbuf, colors[s_cast< int >(buf->state())]);
        for (const auto& p : parents[buf.get()]) {
            file << fmt::format("\"{}\" -> \"{}\";\n", r_cast< void* >(p), r_cast< void* >(buf.get()));
        }
    });
    file << "}\n";

    file.close();
    LOGINFO("cp dag is stored in file {}", filename);
}

uint16_t IndexCPContext::num_dags() {
    // count number of buffers whose up_buffers are nullptr
    uint16_t count = 0;
    std::unique_lock lg{m_flush_buffer_mtx};
    m_dirty_buf_list.foreach_entry([&count](IndexBufferPtr buf) {
        if (buf->m_up_buffer == nullptr) { count++; }
    });
    return count;
}

std::string IndexCPContext::to_string_with_dags() {
    struct DagNode {
        IndexBufferPtr buf;
        std::vector< shared< DagNode > > down_nodes;
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
        if (buf->m_up_buffer == nullptr) {
            auto dgn = get_insert_buf(buf);
            group_roots.emplace_back(dgn);
        } else {
            auto dgn = get_insert_buf(buf);
            auto up_dgn = get_insert_buf(buf->m_up_buffer);
            up_dgn->down_nodes.emplace_back(dgn);
        }
    });

    // Now walk through the list of graphs and prepare formatted string
    std::string str{fmt::format("IndexCPContext cpid={} dirty_buf_count={} dirty_buf_list_size={} #_of_dags={}\n",
                                m_cp->id(), m_dirty_buf_count.get(), m_dirty_buf_list.size(), group_roots.size())};
    int cnt = 1;
    for (const auto& root : group_roots) {
        std::vector< std::tuple< std::shared_ptr< DagNode >, int, int > > stack;
        stack.emplace_back(root, 0, cnt++);
        while (!stack.empty()) {
            auto [node, level, index] = stack.back();
            stack.pop_back();
            fmt::format_to(std::back_inserter(str), "{}{}-{} \n", std::string(level * 4, ' '), index,
                           node->buf->to_string());
            int c = node->down_nodes.size();
            for (const auto& d : node->down_nodes) {
                stack.emplace_back(d, level + 1, c--);
            }
        }
    }

    return str;
}

void IndexCPContext::log_dags() {
    LOGINFO("{}", to_string_with_dags());
    sisl::logging::GetLogger()->flush();
}

std::map< BlkId, IndexBufferPtr > IndexCPContext::recover(sisl::byte_view sb) {
    txn_journal const* tj = r_cast< txn_journal const* >(sb.bytes());
    if (tj->cp_id != id()) {
        // On clean shutdown, cp_id would be lesser than the current cp_id, in that case ignore this sb
        HS_DBG_ASSERT_LT(tj->cp_id, id(), "Persisted cp in wb txn journal is more than current cp");
        return {};
    }
    HS_DBG_ASSERT_GT(tj->num_txns, 0, "Invalid txn_journal, num_txns is zero");
    HS_DBG_ASSERT_GT(tj->size, 0, "Invalid txn_journal, size of records is zero");

    std::map< BlkId, IndexBufferPtr > buf_map;
    uint8_t const* cur_ptr = r_cast< uint8_t const* >(tj) + sizeof(txn_journal);

    for (uint32_t t{0}; t < tj->num_txns; ++t) {
        txn_record const* rec = r_cast< txn_record const* >(cur_ptr);
        HS_DBG_ASSERT_GT(rec->total_ids(), 0, "Invalid txn_record, has no ids in it");

        process_txn_record(rec, buf_map);
        cur_ptr += rec->size();
        LOGTRACEMOD(wbcache, "Recovered txn record: {}: {}", t, rec->to_string());
    }
    auto modifyBuffer = [](IndexBufferPtr& buffer) {
        IndexBufferPtr up_buf = buffer->m_up_buffer;
        auto real_up_buf = up_buf;
        while (real_up_buf && real_up_buf->m_node_freed) {
            real_up_buf = real_up_buf->m_up_buffer;
        }
        if (real_up_buf != up_buf) {
            up_buf->remove_down_buffer(buffer);
            buffer->m_up_buffer = real_up_buf;
            real_up_buf->add_down_buffer(buffer);
            LOGTRACEMOD(wbcache, "Change upbuffer from {} to {}", up_buf->to_string(),
                        buffer->m_up_buffer->to_string());
        }
    };
#if 0
        auto dag_print = [](const std::map< BlkId, IndexBufferPtr >& dags, std::string delimiter) {
            int index = 1;
            for (const auto& [blkid, bufferPtr] : dags) {
                LOGTRACEMOD(wbcache, "{}{} - blkid {} buffer {} ", delimiter, index++, blkid.to_integer(),
                            bufferPtr->to_string());
            }
        };
        LOGTRACEMOD(wbcache,"Before modify : \n ");
        dag_print(buf_map, "Before: ");
#endif
    for (auto& [blkid, bufferPtr] : buf_map) {
        modifyBuffer(bufferPtr);
    }
    //    LOGTRACEMOD(wbcache,"\n\n\nAFTER modify : \n ");
    //    dag_print(buf_map, "After: ");

    auto sanityCheck = [](const std::map< BlkId, IndexBufferPtr >& dags) {
        for (const auto& [blkid, bufferPtr] : dags) {
            auto up_buffer = bufferPtr->m_up_buffer;
            if (up_buffer) {
                HS_REL_ASSERT(
                    !up_buffer->m_node_freed,
                    "Sanity check failed: Buffer {} blkdid {} has an up_buffer {} blkid that is marked as freed.",
                    bufferPtr->to_string(), blkid.to_integer(), up_buffer->to_string(),
                    up_buffer->blkid().to_integer());
                HS_REL_ASSERT_EQ(up_buffer->m_created_cp_id, -1,
                                 "Sanity check failed: Buffer {} has an up_buffer {} that just created",
                                 bufferPtr->to_string(), up_buffer->to_string());
                HS_REL_ASSERT_EQ(up_buffer->m_index_ordinal, bufferPtr->m_index_ordinal,
                                 "Sanity check failed: Buffer {} has an up_buffer {} that has different index_ordinal.",
                                 bufferPtr->to_string(), up_buffer->to_string());
                HS_REL_ASSERT(!bufferPtr->is_meta_buf(),
                              "Sanity check failed: down buffer {} is meta buffer of up buffer {}",
                              bufferPtr->to_string(), up_buffer->to_string());
                HS_REL_ASSERT(
                    !up_buffer->m_wait_for_down_buffers.testz(),
                    "Sanity check failed: Buffer {} has an up_buffer {} that has zero m_wait_for_down_buffers.",
                    bufferPtr->to_string(), up_buffer->to_string());
#ifdef _PRERELEASE
                HS_DBG_ASSERT(up_buffer->is_in_down_buffers(bufferPtr),
                              "Sanity check failed: up_buffer {} has't {} as a down_buffer.", up_buffer->to_string(),
                              bufferPtr->to_string());
#endif
            }
            HS_REL_ASSERT(!bufferPtr->m_node_freed || bufferPtr->m_wait_for_down_buffers.testz(),
                          "Sanity check failed: Freed buffer {} has non-zero m_wait_for_down_buffers.",
                          bufferPtr->to_string());
#ifdef _PRERELEASE
            HS_DBG_ASSERT(bufferPtr->m_wait_for_down_buffers.test_eq(bufferPtr->m_down_buffers.size()),
                          "Sanity check failed: Buffer {} has a mismatch between down_buffers_count and "
                          "m_wait_for_down_buffers.",
                          bufferPtr->to_string());
#endif
        }
    };

    sanityCheck(buf_map);
    return buf_map;
}

void IndexCPContext::process_txn_record(txn_record const* rec, std::map< BlkId, IndexBufferPtr >& buf_map) {
    auto cpg = cp_mgr().cp_guard();

    auto const rec_to_buf = [&buf_map, &cpg](txn_record const* rec, bool is_meta, BlkId const& bid,
                                             IndexBufferPtr const& up_buf) -> IndexBufferPtr {
        IndexBufferPtr buf;
        auto it = buf_map.find(bid);
        if (it == buf_map.end()) {
            if (is_meta) {
                superblk< index_table_sb > tmp_sb;
                buf = std::make_shared< MetaIndexBuffer >(tmp_sb);
            } else {
                buf = std::make_shared< IndexBuffer >(nullptr, bid);
            }

            [[maybe_unused]] auto [it2, happened] = buf_map.insert(std::make_pair(bid, buf));
            DEBUG_ASSERT(happened, "buf_map insert failed");

            buf->m_dirtied_cp_id = cpg->id();
            buf->m_index_ordinal = rec->index_ordinal;
        } else {
            buf = it->second;
        }

        if (up_buf) {
            auto real_up_buf = up_buf;
            if (up_buf->m_created_cp_id == cpg->id()) {
                real_up_buf = up_buf->m_up_buffer;
            } else if (up_buf->m_node_freed) {
                real_up_buf = up_buf->m_up_buffer;
                LOGTRACEMOD(wbcache, "\n\n change upbuffer from {} to {}\n\n", up_buf->to_string(),
                            real_up_buf->to_string());
            }

#ifndef NDEBUG
            //  if (!is_sibling_link || (buf->m_up_buffer == real_up_buf)) { return buf;}
            //  Already linked with same buf or its not a sibling link to override
            if (real_up_buf->is_in_down_buffers(buf)) { return buf; }
#endif

            if (buf->m_up_buffer != real_up_buf) {
                if (buf->m_up_buffer) { buf->m_up_buffer->remove_down_buffer(buf); }
                real_up_buf->add_down_buffer(buf);
                buf->m_up_buffer = real_up_buf;
            }
        }
        return buf;
    };

    uint32_t cur_idx = 0;
    IndexBufferPtr parent_buf{nullptr};
    if (rec->has_inplace_parent) { parent_buf = rec_to_buf(rec, rec->is_parent_meta, rec->blk_id(cur_idx++), nullptr); }

    IndexBufferPtr inplace_child_buf{nullptr};
    if (rec->has_inplace_child) {
        inplace_child_buf = rec_to_buf(rec, false /* is_meta */, rec->blk_id(cur_idx++), parent_buf);
    }

    for (uint8_t idx{0}; idx < rec->num_new_ids; ++idx) {
        auto new_buf = rec_to_buf(rec, false /* is_meta */, rec->blk_id(cur_idx++),
                                  inplace_child_buf ? inplace_child_buf : parent_buf);
        new_buf->m_created_cp_id = cpg->id();
    }

    for (uint8_t idx{0}; idx < rec->num_freed_ids; ++idx) {
        auto freed_buf = rec_to_buf(rec, false /* is_meta */, rec->blk_id(cur_idx++),
                                    inplace_child_buf ? inplace_child_buf : parent_buf);
        freed_buf->m_node_level = rec->free_node_level;
        freed_buf->m_node_freed = true;
    }
}

void IndexCPContext::txn_journal::log_records() const { LOGINFO("{}", to_string()); }

std::string IndexCPContext::txn_journal::to_string() const {
    std::string str = fmt::format("cp_id={}, num_txns={}, size={}", cp_id, num_txns, size);
    uint8_t const* cur_ptr = r_cast< uint8_t const* >(this) + sizeof(txn_journal);
    for (uint32_t t{0}; t < num_txns; ++t) {
        txn_record const* rec = r_cast< txn_record const* >(cur_ptr);
        fmt::format_to(std::back_inserter(str), "\n  {}: {}", t, rec->to_string());
        cur_ptr += rec->size();
    }
    return str;
}

std::string IndexCPContext::txn_record::to_string() const {
    auto add_to_string = [this](std::string& str, uint8_t& idx, uint8_t id_count) {
        if (id_count == 0) {
            fmt::format_to(std::back_inserter(str), "empty]");
        } else {
            for (uint8_t i{0}; i < id_count; ++i) {
                fmt::format_to(std::back_inserter(str), "[{}],", blk_id(idx++).to_integer());
            }
            fmt::format_to(std::back_inserter(str), "]");
        }
    };

    std::string str = fmt::format("ordinal={}, parent=[{}], in_place_child=[{}]", index_ordinal, parent_id_string(),
                                  child_id_string(), num_new_ids, num_freed_ids);

    uint8_t idx = ((has_inplace_parent == 0x1) ? 1 : 0) + ((has_inplace_child == 0x1) ? 1 : 0);
    fmt::format_to(std::back_inserter(str), ", new_ids=[");
    add_to_string(str, idx, num_new_ids);

    fmt::format_to(std::back_inserter(str), ", freed_ids=[");
    add_to_string(str, idx, num_freed_ids);
    if (num_freed_ids) {
        fmt::format_to(std::back_inserter(str), ", freed_node_level= {}", (uint8_t)(free_node_level));
    };
    fmt::format_to(std::back_inserter(str), "{}", (is_parent_meta ? ", parent is meta" : ""));
    return str;
}
} // namespace homestore
