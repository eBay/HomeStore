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
static constexpr store_lsn_t to_store_lsn(uint64_t raft_lsn) { return s_cast< store_lsn_t >(raft_lsn) - 1; }
static constexpr store_lsn_t to_store_lsn(repl_lsn_t repl_lsn) { return repl_lsn - 1; }
static constexpr repl_lsn_t to_repl_lsn(store_lsn_t store_lsn) { return store_lsn + 1; }

static nuraft::ptr< nuraft::log_entry > to_nuraft_log_entry(sisl::blob const& log_blob) {
    uint8_t const* raw_ptr = log_blob.cbytes();
    uint64_t term = *r_cast< uint64_t const* >(raw_ptr);
    raw_ptr += sizeof(uint64_t);
    nuraft::log_val_type type = static_cast< nuraft::log_val_type >(*raw_ptr);
    raw_ptr += sizeof(nuraft::log_val_type);

    size_t data_len = log_blob.size() - sizeof(uint64_t) - sizeof(nuraft::log_val_type);
    auto nb = nuraft::buffer::alloc(data_len);
    nb->put_raw(raw_ptr, data_len);
    return nuraft::cs_new< nuraft::log_entry >(term, nb, type);
}

static nuraft::ptr< nuraft::log_entry > to_nuraft_log_entry(const log_buffer& log_bytes) {
    return to_nuraft_log_entry(log_bytes.get_blob());
}

static uint64_t extract_term(const log_buffer& log_bytes) {
    uint8_t const* raw_ptr = log_bytes.bytes();
    return (*r_cast< uint64_t const* >(raw_ptr));
}

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
        m_log_store->truncate(truncate_lsn);
    }
}

HomeRaftLogStore::HomeRaftLogStore(logdev_id_t logdev_id, logstore_id_t logstore_id) {
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
        logstore_service().open_log_store(m_logdev_id, logstore_id, true).thenValue([this](auto log_store) {
            m_log_store = std::move(log_store);
            DEBUG_ASSERT_EQ(m_logstore_id, m_log_store->get_store_id(), "Mismatch in passed and create logstore id");
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
    uint64_t last_index = m_log_store->get_contiguous_completed_seq_num(m_last_durable_lsn);
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

    nuraft::ptr< nuraft::log_entry > nle;
    try {
        auto log_bytes = m_log_store->read_sync(max_seq);
        nle = to_nuraft_log_entry(log_bytes);
    } catch (const std::exception& e) {
        REPL_STORE_LOG(ERROR, "last_entry() out_of_range={}", max_seq);
        throw e;
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
    return to_repl_lsn(next_seq);
}

void HomeRaftLogStore::write_at(ulong index, nuraft::ptr< nuraft::log_entry >& entry) {
    auto buf = entry->serialize();

    m_log_store->rollback_async(to_store_lsn(index) - 1, nullptr);

    // we need to reset the durable lsn, because its ok to set to lower number as it will be updated on next flush
    // calls, but it is dangerous to set higher number.
    m_last_durable_lsn = -1;

    m_log_store->append_async(sisl::io_blob{buf->data_begin(), uint32_cast(buf->size()), false /* is_aligned */},
                              nullptr /* cookie */, [buf](int64_t, sisl::io_blob&, logdev_key, void*) {});
}

void HomeRaftLogStore::end_of_append_batch(ulong start, ulong cnt) {
    store_lsn_t end_lsn = to_store_lsn(start + cnt - 1);
    m_log_store->flush_sync(end_lsn);
    m_last_durable_lsn = end_lsn;
}

nuraft::ptr< std::vector< nuraft::ptr< nuraft::log_entry > > > HomeRaftLogStore::log_entries(ulong start, ulong end) {
    auto out_vec = std::make_shared< std::vector< nuraft::ptr< nuraft::log_entry > > >();
    m_log_store->foreach (to_store_lsn(start), [end, &out_vec](store_lsn_t cur, const log_buffer& entry) -> bool {
        bool ret = (cur < to_store_lsn(end) - 1);
        if (cur < to_store_lsn(end)) { out_vec->emplace_back(to_nuraft_log_entry(entry)); }
        return ret;
    });
    return out_vec;
}

nuraft::ptr< nuraft::log_entry > HomeRaftLogStore::entry_at(ulong index) {
    nuraft::ptr< nuraft::log_entry > nle;
    try {
        auto log_bytes = m_log_store->read_sync(to_store_lsn(index));
        nle = to_nuraft_log_entry(log_bytes);
    } catch (const std::exception& e) {
        REPL_STORE_LOG(ERROR, "entry_at({}) index out_of_range", index);
        throw e;
    }
    return nle;
}

ulong HomeRaftLogStore::term_at(ulong index) {
    ulong term;
    try {
        auto log_bytes = m_log_store->read_sync(to_store_lsn(index));
        term = extract_term(log_bytes);
    } catch (const std::exception& e) {
        REPL_STORE_LOG(ERROR, "term_at({}) index out_of_range", index);
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
            if (remain_cnt-- > 0) {
                size_t avail_size = out_buf->size() - out_buf->pos();
                if (avail_size < entry.size()) {
                    avail_size += std::max(out_buf->size() * 2, (size_t)entry.size());
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
        m_log_store->rollback_async(to_store_lsn(index) - 1, nullptr);
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
        RELEASE_ASSERT(false, "compact_lsn={} is beyond the current max_lsn={}", compact_lsn, cur_max_lsn);

        // We need to fill the remaining entries with dummy data.
        for (auto lsn{cur_max_lsn + 1}; lsn <= to_store_lsn(compact_lsn); ++lsn) {
            append(m_dummy_log_entry);
        }
    }

    m_log_store->flush_sync(to_store_lsn(compact_lsn));

    // we rely on resrouce mgr timer to trigger truncate for all log stores in system;
    // this will be friendly for multiple logstore on same logdev;

    // m_log_store->truncate(to_store_lsn(compact_lsn));

    return true;
}

bool HomeRaftLogStore::flush() {
    m_log_store->flush_sync();
    return true;
}

ulong HomeRaftLogStore::last_durable_index() {
    m_last_durable_lsn = m_log_store->get_contiguous_completed_seq_num(m_last_durable_lsn);
    return to_repl_lsn(m_last_durable_lsn);
}
} // namespace homestore
