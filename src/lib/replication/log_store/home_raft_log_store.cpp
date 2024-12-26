/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
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

#include "home_raft_log_store.h"
#include "storage_engine_buffer.h"
#include <sisl/fds/utils.hpp>
#include "common/homestore_assert.hpp"
#include <homestore/homestore.hpp>
#include <iomgr/iomgr_flip.hpp>

using namespace homestore;

SISL_LOGGING_DECL(replication)

#define REPL_STORE_LOG(level, msg, ...)                                                                                \
    LOG##level##MOD_FMT(replication, ([&](fmt::memory_buffer& buf, const char* msgcb, auto&&... args) -> bool {        \
                            fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}:{}] "},                          \
                                            fmt::make_format_args(file_name(__FILE__), __LINE__));                     \
                            fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"[{}={}] "},                          \
                                            fmt::make_format_args("replstore", m_logstore_id));                        \
                            fmt::vformat_to(fmt::appender{buf}, fmt::string_view{msgcb},                               \
                                            fmt::make_format_args(std::forward< decltype(args) >(args)...));           \
                            return true;                                                                               \
                        }),                                                                                            \
                        msg, ##__VA_ARGS__);

namespace homestore {
static constexpr logstore_seq_num_t to_store_lsn(uint64_t raft_lsn) {
    return static_cast< logstore_seq_num_t >(raft_lsn - 1);
}
static constexpr logstore_seq_num_t to_store_lsn(repl_lsn_t repl_lsn) {
    return static_cast< logstore_seq_num_t >(repl_lsn - 1);
}

static uint64_t extract_term(const log_buffer& log_bytes) {
    uint8_t const* raw_ptr = log_bytes.bytes();
    return (*r_cast< uint64_t const* >(raw_ptr));
}

#if 0
// Since truncate_lsn can not accross compact_lsn passed down by raft server
// and compact will truncate logs upto compact_lsn, we don't need to re-truncate in this function now.
void HomeRaftLogStore::truncate(uint32_t num_reserved_cnt, repl_lsn_t compact_lsn) {
    auto const last_lsn = last_index();
    auto const start_lsn = start_index();

    // compact_lsn will be zero on first time boot, so we should not truncate in that case.
    if (compact_lsn == 0 || (start_lsn + num_reserved_cnt >= last_lsn)) {
        REPL_STORE_LOG(DEBUG,
                       "Store={} LogDev={}: Skipping truncating because of reserved logs entries is not enough or "
                       "compact_lsn is zero. "
                       "start_lsn={}, resv_cnt={}, last_lsn={}, compact_lsn={}",
                       m_logstore_id, m_logdev_id, start_lsn, num_reserved_cnt, last_lsn, compact_lsn);
        return;
    } else {
        //
        // truncate_lsn can not accross compact_lsn passed down by raft server;
        //
        // When will it happen:
        // compact_lsn can be smaller than last_lsn - num_reserved_cnt, when raft is configured with
        // snapshot_distance of a large value, and dynamic config "resvered log entries" a smaller value.
        //
        auto truncate_lsn = std::min(last_lsn - num_reserved_cnt, (ulong)to_store_lsn(compact_lsn));

        REPL_STORE_LOG(INFO, "LogDev={}: Truncating log entries from {} to {}, compact_lsn={}, last_lsn={}",
                       m_logdev_id, start_lsn, truncate_lsn, compact_lsn, last_lsn);
        // this will only truncate in memory.
        // we rely on resrouce mgr timer to trigger real truncate for all log stores in system;
        // this will be friendly for multiple logstore on same logdev;
        m_log_store->truncate(truncate_lsn);
    }
}
#endif

HomeRaftLogStore::HomeRaftLogStore(logdev_id_t logdev_id, logstore_id_t logstore_id, log_found_cb_t const& log_found_cb,
                                   log_replay_done_cb_t const& log_replay_done_cb) :
        // TODO: make this capacity configurable if necessary
        // repl_lsn starts from 1, so we set lsn 0 to be dummy
        m_log_entry_cache(100, std::make_pair(0, nullptr)) {
    m_dummy_log_entry = nuraft::cs_new< nuraft::log_entry >(0, nuraft::buffer::alloc(0), nuraft::log_val_type::app_log);

    if (logstore_id == UINT32_MAX) {
        m_logdev_id = logstore_service().create_new_logdev();
        m_log_store = logstore_service().create_new_log_store(m_logdev_id, true);
        if (!m_log_store) { throw std::runtime_error("Failed to create log store"); }
        m_logstore_id = m_log_store->get_store_id();
        LOGDEBUGMOD(replication, "Opened new home log_dev={} log_store={}", m_logdev_id, m_logstore_id);
    } else {
        m_logdev_id = logdev_id;
        m_logstore_id = logstore_id;
        LOGDEBUGMOD(replication, "Opening existing home log_dev={} log_store={}", m_logdev_id, logstore_id);
        logstore_service().open_logdev(m_logdev_id);
        m_log_store_future = logstore_service()
                                 .open_log_store(m_logdev_id, logstore_id, true, log_found_cb, log_replay_done_cb)
                                 .thenValue([this](auto log_store) {
                                     m_log_store = std::move(log_store);
                                     DEBUG_ASSERT_EQ(m_logstore_id, m_log_store->get_store_id(),
                                                     "Mismatch in passed and create logstore id");
                                     REPL_STORE_LOG(DEBUG, "Home Log store created/opened successfully");
                                 });
    }
}

void HomeRaftLogStore::remove_store() {
    REPL_STORE_LOG(DEBUG, "Logstore is being physically removed");
    logstore_service().remove_log_store(m_logdev_id, m_logstore_id);
    m_log_store.reset();
}

ulong HomeRaftLogStore::next_slot() const {
    uint64_t next_slot = to_repl_lsn(m_log_store->get_contiguous_issued_seq_num(m_last_durable_lsn)) + 1;
    return next_slot;
}

ulong HomeRaftLogStore::last_index() const {
    uint64_t last_index = to_repl_lsn(m_log_store->get_contiguous_completed_seq_num(m_last_durable_lsn));
    return last_index;
}

ulong HomeRaftLogStore::start_index() const {
    // start_index starts from 1.
    ulong start_index = std::max((repl_lsn_t)1, to_repl_lsn(m_log_store->truncated_upto()) + 1);
    return start_index;
}

nuraft::ptr< nuraft::log_entry > HomeRaftLogStore::last_entry() const {
    store_lsn_t max_seq = m_log_store->get_contiguous_issued_seq_num(m_last_durable_lsn);
    if (max_seq < 0) { return m_dummy_log_entry; }
    ulong lsn = to_repl_lsn(max_seq);
    auto position_in_cache = lsn % m_log_entry_cache.size();
    {
        std::shared_lock lk(m_mutex);
        auto nle = m_log_entry_cache[position_in_cache];
        if (nle.first == lsn) return nle.second;
    }

    nuraft::ptr< nuraft::log_entry > nle;
    try {
        auto log_bytes = m_log_store->read_sync(max_seq);
        nle = to_nuraft_log_entry(log_bytes);
    } catch (const std::exception& e) {
        // all the log entries are truncated, so we should return a dummy log entry.
        REPL_STORE_LOG(ERROR, "last_entry() out_of_range={}, {}", max_seq, e.what());
        // according to the contract, we should return a dummy log entry if the index is out of range.
        // https://github.com/eBay/NuRaft/blob/50e2f949503081262cb21923e633eaa8dacad8fa/include/libnuraft/log_store.hxx#L56
        nle = m_dummy_log_entry;
    }

    return nle;
}

ulong HomeRaftLogStore::append(nuraft::ptr< nuraft::log_entry >& entry) {
    REPL_STORE_LOG(TRACE, "append entry term={}, log_val_type={} size={}", entry->get_term(),
                   static_cast< uint32_t >(entry->get_val_type()), entry->get_buf().size());
    auto buf = entry->serialize();
    auto const next_seq =
        m_log_store->append_async(sisl::io_blob{buf->data_begin(), uint32_cast(buf->size()), false /* is_aligned */},
                                  nullptr /* cookie */, [buf](int64_t, sisl::io_blob&, logdev_key, void*) {});
    ulong lsn = to_repl_lsn(next_seq);

    auto position_in_cache = lsn % m_log_entry_cache.size();
    {
        std::unique_lock lk(m_mutex);
        m_log_entry_cache[position_in_cache] = std::make_pair(lsn, entry);
    }
    return lsn;
}

void HomeRaftLogStore::write_at(ulong index, nuraft::ptr< nuraft::log_entry >& entry) {
    auto buf = entry->serialize();

    m_log_store->rollback(to_store_lsn(index) - 1);

    // we need to reset the durable lsn, because its ok to set to lower number as it will be updated on next flush
    // calls, but it is dangerous to set higher number.
    m_last_durable_lsn = -1;

    m_log_store->append_async(sisl::io_blob{buf->data_begin(), uint32_cast(buf->size()), false /* is_aligned */},
                              nullptr /* cookie */, [buf](int64_t, sisl::io_blob&, logdev_key, void*) {});

    auto position_in_cache = index % m_log_entry_cache.size();
    {
        std::unique_lock lk(m_mutex);
        m_log_entry_cache[position_in_cache] = std::make_pair(index, entry);

        // remove all cached entries after this index
        for (size_t i{0}; i < m_log_entry_cache.size(); ++i) {
            if (m_log_entry_cache[i].first > index) { m_log_entry_cache[i] = std::make_pair(0, nullptr); }
        }
    }

    // flushing the log before returning to ensure new(over-written) log is persisted to disk.
    end_of_append_batch(index, 1);
}

void HomeRaftLogStore::end_of_append_batch(ulong start, ulong cnt) {
    auto end_lsn = to_store_lsn(start + cnt - 1);
    m_log_store->flush(end_lsn);
    m_last_durable_lsn = end_lsn;
    REPL_STORE_LOG(TRACE, "end_of_append_batch flushed upto start={} cnt={} lsn={}", start, cnt, start + cnt - 1);
}

nuraft::ptr< std::vector< nuraft::ptr< nuraft::log_entry > > > HomeRaftLogStore::log_entries(ulong start, ulong end) {
    auto out_vec = std::make_shared< std::vector< nuraft::ptr< nuraft::log_entry > > >();
    m_log_store->foreach (to_store_lsn(start), [end, &out_vec](store_lsn_t cur, const log_buffer& entry) -> bool {
        bool ret = (cur < to_store_lsn(end) - 1);
        if (cur < to_store_lsn(end)) {
            // REPL_STORE_LOG(TRACE, "log_entries lsn={}", cur + 1);
            out_vec->emplace_back(to_nuraft_log_entry(entry));
        }
        return ret;
    });
    REPL_STORE_LOG(TRACE, "Num log entries start={} end={} num_entries={}", start, end, out_vec->size());
    return out_vec;
}

nuraft::ptr< std::vector< nuraft::ptr< nuraft::log_entry > > >
HomeRaftLogStore::log_entries_ext(ulong start, ulong end, int64_t batch_size_hint_in_bytes) {
    // WARNING: we interpret batch_size_hint_in_bytes as count as of now.
    auto batch_size_hint_cnt = batch_size_hint_in_bytes;
    auto new_end = end;
    // batch_size_hint_in_bytes < 0 indicats that follower is busy now and do not want to receive any more log entry.
    if (batch_size_hint_cnt < 0)
        new_end = start;
    else if (batch_size_hint_cnt > 0) {
        // limit to the hint, also prevent overflow by a huge batch_size_hint_cnt
        if (sisl_unlikely(start + (uint64_t)batch_size_hint_cnt < start)) {
            new_end = end;
        } else {
            new_end = start + (uint64_t)batch_size_hint_cnt;
        }
        // limit to original end
        new_end = std::min(new_end, end);
    }
    DEBUG_ASSERT(new_end <= end, "new end {} should be <= original end {}", new_end, end);
    DEBUG_ASSERT(start <= new_end, "start {} should be <= new_end {}", start, new_end);
    REPL_STORE_LOG(TRACE, "log_entries_ext, start={} end={}, hint {}, adjusted range {} ~ {}, cnt {}", start, end,
                   batch_size_hint_cnt, start, new_end, new_end - start);
    return log_entries(start, new_end);
}

nuraft::ptr< nuraft::log_entry > HomeRaftLogStore::entry_at(ulong index) {
    auto positio_in_cache = index % m_log_entry_cache.size();
    {
        std::shared_lock lk(m_mutex);
        auto nle = m_log_entry_cache[positio_in_cache];
        if (nle.first == index) return nle.second;
    }

    nuraft::ptr< nuraft::log_entry > nle;
    try {
        auto log_bytes = m_log_store->read_sync(to_store_lsn(index));
        nle = to_nuraft_log_entry(log_bytes);
    } catch (const std::exception& e) {
        REPL_STORE_LOG(ERROR, "entry_at({}) index out_of_range start {} end {}", index, start_index(), last_index());
        throw e;
    }
    return nle;
}

ulong HomeRaftLogStore::term_at(ulong index) {
    auto positio_in_cache = index % m_log_entry_cache.size();
    {
        std::shared_lock lk(m_mutex);
        auto nle = m_log_entry_cache[positio_in_cache];
        if (nle.first == index) return nle.second->get_term();
    }

    ulong term;
    try {
        auto log_bytes = m_log_store->read_sync(to_store_lsn(index));
        term = extract_term(log_bytes);
    } catch (const std::exception& e) {
        REPL_STORE_LOG(ERROR, "term_at({}) index out_of_range start {} end {}", index, start_index(), last_index());
        throw e;
    }
    return term;
}

raft_buf_ptr_t HomeRaftLogStore::pack(ulong index, int32_t cnt) {
    static constexpr size_t estimated_record_size = 128;
    size_t estimated_size = cnt * estimated_record_size + sizeof(uint32_t);

    //   << Format >>
    // # records (N)        4 bytes
    // +---
    // | log length (X)     4 bytes
    // | log data           X bytes
    // +--- repeat N
    raft_buf_ptr_t out_buf = nuraft::buffer::alloc(estimated_size);
    out_buf->put(cnt);

    int32_t remain_cnt = cnt;
    m_log_store->foreach (
        to_store_lsn(index),
        [this, &out_buf, &remain_cnt]([[maybe_unused]] store_lsn_t cur, const log_buffer& entry) mutable -> bool {
            size_t const total_entry_size = entry.size() + sizeof(uint32_t);
            if (remain_cnt-- > 0) {
                size_t avail_size = out_buf->size() - out_buf->pos();
                // available size of packing buffer should be able to hold entry.size() and the length of this entry
                if (avail_size < total_entry_size) {
                    avail_size += std::max(out_buf->size() * 2, total_entry_size);
                    out_buf = nuraft::buffer::expand(*out_buf, avail_size);
                }
                REPL_STORE_LOG(TRACE, "packing lsn={} of size={}, avail_size in buffer={}", to_repl_lsn(cur),
                               entry.size(), avail_size);
                out_buf->put(entry.bytes(), entry.size());
            }
            return (remain_cnt > 0);
        });
    return out_buf;
}

void HomeRaftLogStore::apply_pack(ulong index, nuraft::buffer& pack) {
    pack.pos(0);
    auto num_entries = pack.get_int();

    auto slot = next_slot();
    if (index < slot) {
        // We are asked to apply/insert data behind next slot, so we must rollback before index and then append
        m_log_store->rollback(to_store_lsn(index) - 1);
    } else if (index > slot) {
        // We are asked to apply/insert data after next slot, so we need to fill in with dummy entries upto the slot
        // before append the entries
        REPL_STORE_LOG(WARN,
                       "RaftLogStore is asked to apply pack on lsn={}, but current lsn={} is behind, will be filling "
                       "with dummy data to make it functional, however, this could result in inconsistent data",
                       index, to_store_lsn(slot));
        while (index++ < slot) {
            append(m_dummy_log_entry);
        }
    }

    for (int i{0}; i < num_entries; ++i) {
        size_t entry_len;
        auto* entry = pack.get_bytes(entry_len);
        sisl::blob b{entry, uint32_cast(entry_len)};

        auto nle = to_nuraft_log_entry(b);
        this->append(nle);
        REPL_STORE_LOG(TRACE, "unpacking nth_entry={} of size={}, lsn={}", i + 1, entry_len, slot + i);
    }
    this->end_of_append_batch(slot, num_entries);
}

bool HomeRaftLogStore::compact(ulong compact_lsn) {
    auto cur_max_lsn = m_log_store->get_contiguous_issued_seq_num(m_last_durable_lsn);
    if (cur_max_lsn < to_store_lsn(compact_lsn)) {
        // release this assert if for some use case, we should tolorant this case;
        // for now, don't expect this case to happen.
        // RELEASE_ASSERT(false, "compact_lsn={} is beyond the current max_lsn={}", compact_lsn, cur_max_lsn);
        REPL_STORE_LOG(DEBUG, "Adding dummy entries during compact from={} upto={}", cur_max_lsn + 1,
                       to_store_lsn(compact_lsn));
        // We need to fill the remaining entries with dummy data.
        for (auto lsn{cur_max_lsn + 1}; lsn <= to_store_lsn(compact_lsn); ++lsn) {
            append(m_dummy_log_entry);
        }
    }
    m_log_store->truncate(to_store_lsn(compact_lsn));
    return true;
}

bool HomeRaftLogStore::flush() {
    m_log_store->flush();
    return true;
}

ulong HomeRaftLogStore::last_durable_index() {
    m_last_durable_lsn = m_log_store->get_contiguous_completed_seq_num(m_last_durable_lsn);
    return to_repl_lsn(m_last_durable_lsn);
}

void HomeRaftLogStore::wait_for_log_store_ready() { m_log_store_future.wait(); }

void HomeRaftLogStore::set_last_durable_lsn(repl_lsn_t lsn) { m_last_durable_lsn = to_store_lsn(lsn); }

} // namespace homestore
