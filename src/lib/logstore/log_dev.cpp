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
#include <algorithm>
#include <condition_variable>
#include <cstring>
#include <iterator>

#include <sisl/fds/vector_pool.hpp>
#include <iomgr/iomgr_flip.hpp>

#include <homestore/logstore_service.hpp>
#include <homestore/meta_service.hpp>
#include <homestore/homestore.hpp>

#include "log_dev.hpp"
#include "device/journal_vdev.hpp"
#include "common/homestore_assert.hpp"
#include "common/homestore_config.hpp"
#include "common/homestore_utils.hpp"
#include "common/crash_simulator.hpp"

namespace homestore {

SISL_LOGGING_DECL(logstore)

#define THIS_LOGDEV_LOG(level, msg, ...) HS_SUBMOD_LOG(level, logstore, , "log_dev", m_logdev_id, msg, __VA_ARGS__)
#define THIS_LOGDEV_PERIODIC_LOG(level, msg, ...)                                                                      \
    HS_PERIODIC_DETAILED_LOG(level, logstore, "log_dev", m_logdev_id, , , msg, __VA_ARGS__)

static bool has_data_service() { return HomeStore::instance()->has_data_service(); }
// static BlkDataService& data_service() { return HomeStore::instance()->data_service(); }

LogDev::LogDev(const logdev_id_t id, JournalVirtualDev* vdev) : m_logdev_id{id}, m_vdev(vdev) {
    m_flush_size_multiple = HS_DYNAMIC_CONFIG(logstore->flush_size_multiple_logdev);
    // Each logdev has one journal descriptor.
    m_vdev_jd = m_vdev->open(m_logdev_id);
    RELEASE_ASSERT(m_vdev_jd, "Journal descriptor is null");
}

LogDev::~LogDev() = default;

void LogDev::start(bool format) {
    if (m_flush_size_multiple == 0) { m_flush_size_multiple = m_vdev->optimal_page_size(); }
    THIS_LOGDEV_LOG(INFO, "Initializing logdev with flush size multiple={}", m_flush_size_multiple);

    for (uint32_t i = 0; i < max_log_group; ++i) {
        m_log_group_pool[i].start(m_flush_size_multiple, m_vdev->align_size());
    }
    m_log_records = std::make_unique< sisl::StreamTracker< log_record > >();
    m_stopped = false;

    // First read the info block
    if (format) {
        HS_LOG_ASSERT(m_logdev_meta.is_empty(), "Expected meta to be not present");
        m_logdev_meta.create(m_logdev_id);
        m_vdev_jd->update_data_start_offset(0);
    } else {
        HS_LOG_ASSERT(!m_logdev_meta.is_empty(), "Expected meta data to be read already before loading");
        auto const store_list = m_logdev_meta.load();

        // Notify to the caller that a new log store was reserved earlier and it is being loaded, with its meta info
        for (const auto& spair : store_list) {
            on_log_store_found(spair.first, spair.second);
        }

        THIS_LOGDEV_LOG(INFO, "get start vdev offset during recovery {} log indx {} ",
                        m_logdev_meta.get_start_dev_offset(), m_logdev_meta.get_start_log_idx());

        m_vdev_jd->update_data_start_offset(m_logdev_meta.get_start_dev_offset());
        m_log_idx = m_logdev_meta.get_start_log_idx();
        do_load(m_logdev_meta.get_start_dev_offset());
        m_log_records->reinit(m_log_idx);
        m_last_flush_idx = m_log_idx - 1;
    }

    start_timer();
    handle_unopened_log_stores(format);

    {
        // Also call the logstore to inform that start/replay is completed.
        folly::SharedMutexWritePriority::WriteHolder holder(m_store_map_mtx);
        if (!format) {
            for (auto& p : m_id_logstore_map) {
                auto& lstore{p.second.log_store};
                if (lstore && lstore->get_log_replay_done_cb()) {
                    lstore->get_log_replay_done_cb()(lstore, lstore->seq_num() - 1);
                    lstore->truncate(lstore->truncated_upto());
                }
            }
        }
    }
}

void LogDev::stop() {
    THIS_LOGDEV_LOG(INFO, "Logdev stopping log_dev={}", m_logdev_id);
    HS_LOG_ASSERT((m_pending_flush_size == 0), "LogDev stop attempted while writes to logdev are pending completion");
    const bool locked_now = run_under_flush_lock([this]() {
        {
            std::unique_lock< std::mutex > lk{m_block_flush_q_mutex};
            m_stopped = true;
        }
        m_block_flush_q_cv.notify_one();
        return true;
    });

    if (!locked_now) { THIS_LOGDEV_LOG(INFO, "LogDev stop is queued because of pending flush or truncation ongoing"); }

    {
        // Wait for the stopped to be completed
        std::unique_lock< std::mutex > lk{m_block_flush_q_mutex};
        m_block_flush_q_cv.wait(lk, [&] { return m_stopped; });
    }

    stop_timer();

    {
        folly::SharedMutexWritePriority::WriteHolder holder(m_store_map_mtx);
        m_id_logstore_map.clear();
    }

    m_log_records = nullptr;
    m_logdev_meta.reset();
    m_log_idx.store(0);
    m_pending_flush_size.store(0);
    m_is_flushing.store(false);
    m_last_flush_idx = -1;
    m_last_truncate_idx = -1;
    m_last_crc = INVALID_CRC32_VALUE;
    if (m_block_flush_q != nullptr) {
        sisl::VectorPool< flush_blocked_callback >::free(m_block_flush_q, false /* no_cache */);
    }
    for (size_t i{0}; i < max_log_group; ++i) {
        m_log_group_pool[i].stop();
    }

    THIS_LOGDEV_LOG(INFO, "LogDev stopped successfully id {}", m_logdev_id);
    m_hs.reset();
}

void LogDev::destroy() {
    THIS_LOGDEV_LOG(INFO, "Logdev destroy metablks log_dev={}", m_logdev_id);
    m_logdev_meta.destroy();
}

void LogDev::start_timer() {
    // Currently only tests set it to 0.
    if (HS_DYNAMIC_CONFIG(logstore.flush_timer_frequency_us) == 0) { return; }

    iomanager.run_on_wait(logstore_service().flush_thread(), [this]() {
        m_flush_timer_hdl = iomanager.schedule_thread_timer(HS_DYNAMIC_CONFIG(logstore.flush_timer_frequency_us) * 1000,
                                                            true /* recurring */, nullptr /* cookie */,
                                                            [this](void*) { flush_if_needed(); });
    });
}

void LogDev::stop_timer() {
    if (m_flush_timer_hdl != iomgr::null_timer_handle) {
        // cancel the timer
        iomanager.run_on_wait(logstore_service().flush_thread(),
                              [this]() { iomanager.cancel_timer(m_flush_timer_hdl, true); });
    }
}

void LogDev::do_load(const off_t device_cursor) {
    log_stream_reader lstream{device_cursor, m_vdev, m_vdev_jd, m_flush_size_multiple};
    logid_t loaded_from{-1};
    off_t group_dev_offset = 0;

    THIS_LOGDEV_LOG(TRACE, "LogDev::do_load start log_dev={} ", m_logdev_id);

    do {
        const auto buf = lstream.next_group(&group_dev_offset);
        if (buf.size() == 0) {
            THIS_LOGDEV_LOG(INFO, "LogDev loaded log_idx in range of [{} - {}]", loaded_from, m_log_idx - 1);
            break;
        }

        auto* header = r_cast< const log_group_header* >(buf.bytes());
        if (loaded_from == -1 && header->start_idx() < m_log_idx) {
            // log dev is truncated completely
            assert_next_pages(lstream);
            THIS_LOGDEV_LOG(INFO, "LogDev loaded log_idx in range of [{} - {}]", loaded_from, m_log_idx - 1);
            break;
        }

        THIS_LOGDEV_LOG(DEBUG, "Found log group header offset=0x{} header {}", to_hex(group_dev_offset), *header);
        HS_REL_ASSERT_EQ(header->start_idx(), m_log_idx.load(), "log indx is not the expected one");
        if (loaded_from == -1) { loaded_from = header->start_idx(); }

        // Loop through each record within the log group and do a callback
        decltype(header->nrecords()) i{0};
        HS_REL_ASSERT_GT(header->nrecords(), 0, "nrecords greater then zero");
        const auto flush_ld_key =
            logdev_key{header->start_idx() + header->nrecords() - 1, group_dev_offset + header->total_size()};
        while (i < header->nrecords()) {
            const auto* rec = header->nth_record(i);
            const uint32_t data_offset = (rec->offset + (rec->get_inlined() ? 0 : header->oob_data_offset));

            // Do a callback on the found log entry
            sisl::byte_view b = buf;
            b.move_forward(data_offset);
            b.set_size(rec->size);
            if (m_last_truncate_idx == -1) { m_last_truncate_idx = header->start_idx() + i; }
            // Validate if the id is present in rollback info
            if (m_logdev_meta.is_rolled_back(rec->store_id, header->start_idx() + i)) {
                THIS_LOGDEV_LOG(DEBUG,
                                "logstore_id[{}] log_idx={}, lsn={} has been rolledback, not notifying the logstore",
                                rec->store_id, (header->start_idx() + i), rec->store_seq_num);
            } else {
                THIS_LOGDEV_LOG(TRACE, "seq num {}, log indx {}, group dev offset {} size {}", rec->store_seq_num,
                                (header->start_idx() + i), group_dev_offset, rec->size);
                on_logfound(rec->store_id, rec->store_seq_num, {header->start_idx() + i, group_dev_offset},
                            flush_ld_key, b, (header->nrecords() - (i + 1)));
            }

            ++i;
        }

        m_log_idx = header->start_idx() + i;
        m_last_crc = header->cur_grp_crc;
    } while (true);

    // Update the tail offset with where we finally end up loading, so that new append entries can be written from
    // here.
    m_vdev_jd->update_tail_offset(group_dev_offset);
    THIS_LOGDEV_LOG(TRACE, "LogDev::do_load end {} ", m_logdev_id);
}

void LogDev::assert_next_pages(log_stream_reader& lstream) {
    THIS_LOGDEV_LOG(INFO,
                    "Logdev reached offset, which has invalid header, because of end of stream. Validating if it is "
                    "indeed the case or there is any corruption");
    for (uint32_t i{0}; i < HS_DYNAMIC_CONFIG(logstore->recovery_max_blks_read_for_additional_check); ++i) {
        const auto buf = lstream.group_in_next_page();
        if (buf.size() != 0) {
            auto* header = r_cast< const log_group_header* >(buf.bytes());
            HS_REL_ASSERT_GT(m_log_idx.load(std::memory_order_acquire), header->start_idx(),
                             "Found a header with future log_idx after reaching end of log. Hence rbuf which was read "
                             "must have been corrupted, logdev id {} Header: {}",
                             m_logdev_id, *header);
        }
    }
}

int64_t LogDev::append_async(const logstore_id_t store_id, const logstore_seq_num_t seq_num, const sisl::io_blob& data,
                             void* cb_context, bool flush_wait) {
    auto prev_size = m_pending_flush_size.fetch_add(data.size(), std::memory_order_relaxed);
    const auto idx = m_log_idx.fetch_add(1, std::memory_order_acq_rel);
    auto threshold_size = LogDev::flush_data_threshold_size();
    m_log_records->create(idx, store_id, seq_num, data, cb_context);

    if (HS_DYNAMIC_CONFIG(logstore.flush_threshold_size) == 0) {
        // This is set in tests to disable implicit flush. This will be removed in future.
        return idx;
    }

    if (flush_wait ||
        ((prev_size < threshold_size && ((prev_size + data.size()) >= threshold_size) &&
          !m_is_flushing.load(std::memory_order_relaxed)))) {
        flush_if_needed(flush_wait ? 1 : -1);
    }
    return idx;
}

log_buffer LogDev::read(const logdev_key& key, serialized_log_record& return_record_header) {
    auto buf = sisl::make_byte_array(initial_read_size, m_flush_size_multiple, sisl::buftag::logread);
    auto ec = m_vdev_jd->sync_pread(buf->bytes(), initial_read_size, key.dev_offset);
    if (ec) {
        LOGERROR("Failed to read from ournal vdev log_dev={} {} {}", m_logdev_id, ec.value(), ec.message());
        return {};
    }

    auto* header = r_cast< const log_group_header* >(buf->cbytes());
    // THIS_LOGDEV_LOG(TRACE, "Logdev read log group header {}", *header);
    HS_REL_ASSERT_EQ(header->magic_word(), LOG_GROUP_HDR_MAGIC, "Log header corrupted with magic mismatch! {} {}",
                     m_logdev_id, *header);
    HS_REL_ASSERT_EQ(header->get_version(), log_group_header::header_version, "Log header version mismatch!  {} {}",
                     m_logdev_id, *header);
    HS_REL_ASSERT_LE(header->start_idx(), key.idx, "log key offset does not match with log_idx {} }{}", m_logdev_id,
                     *header);
    HS_REL_ASSERT_GT((header->start_idx() + header->nrecords()), key.idx,
                     "log key offset does not match with log_idx {} {}", m_logdev_id, *header);
    HS_LOG_ASSERT_GE(header->total_size(), header->_inline_data_offset(), "Inconsistent size data in log group {} {}",
                     m_logdev_id, *header);

    // We can only do crc match in read if we have read all the blocks. We don't want to aggressively read more data
    // than we need to just to compare CRC for read operation. It can be done during recovery.
    if (header->total_size() <= initial_read_size) {
        crc32_t const crc = crc32_ieee(init_crc32, (buf->cbytes() + sizeof(log_group_header)),
                                       header->total_size() - sizeof(log_group_header));
        HS_REL_ASSERT_EQ(header->this_group_crc(), crc, "CRC mismatch on read data");
    }
    auto record_header = header->nth_record(key.idx - header->start_log_idx);
    uint32_t const data_offset = (record_header->offset + (record_header->get_inlined() ? 0 : header->oob_data_offset));

    sisl::byte_view ret_view;
    if ((data_offset + record_header->size) < initial_read_size) {
        ret_view = sisl::byte_view{buf, data_offset, record_header->size};
    } else {
        auto const rounded_data_offset = sisl::round_down(data_offset, m_vdev->align_size());
        auto const rounded_size =
            sisl::round_up(record_header->size + data_offset - rounded_data_offset, m_vdev->align_size());
        auto new_buf = sisl::make_byte_array(rounded_size, m_vdev->align_size(), sisl::buftag::logread);
        m_vdev_jd->sync_pread(new_buf->bytes(), rounded_size, key.dev_offset + rounded_data_offset);
        ret_view = sisl::byte_view{new_buf, s_cast< uint32_t >(data_offset - rounded_data_offset), record_header->size};
    }

    return_record_header =
        serialized_log_record(record_header->size, record_header->offset, record_header->get_inlined(),
                              record_header->store_seq_num, record_header->store_id);

    return ret_view;
}

logstore_id_t LogDev::reserve_store_id() {
    std::unique_lock lg{m_meta_mutex};
    return m_logdev_meta.reserve_store(true /* persist_now */);
}

void LogDev::unreserve_store_id(const logstore_id_t store_id) {
    std::unique_lock lg{m_meta_mutex};

    /* Get the current log_idx as marker and insert into garbage store id. Upon device truncation, these ids will
     * be reclaimed */
    auto const log_id = m_log_idx.load(std::memory_order_acquire) - 1;
    m_garbage_store_ids.emplace(log_id, store_id);
}

void LogDev::get_registered_store_ids(std::vector< logstore_id_t >& registered, std::vector< logstore_id_t >& garbage) {
    std::unique_lock lg{m_meta_mutex};
    for (const auto& id : m_logdev_meta.reserved_store_ids()) {
        registered.push_back(id);
    }

    garbage.clear();
    for (const auto& elem : m_garbage_store_ids) {
        garbage.push_back(elem.second);
    }
}

/*
 * This method prepares the log records to be flushed and returns the log_group which is fully prepared
 */
LogGroup* LogDev::prepare_flush(const int32_t estimated_records) {
    int64_t flushing_upto_idx{-1};

    assert(estimated_records > 0);
    auto* lg = make_log_group(static_cast< uint32_t >(estimated_records));
    m_log_records->foreach_contiguous_active(m_last_flush_idx + 1,
                                             [&](int64_t idx, int64_t, log_record& record) -> bool {
                                                 if (lg->add_record(record, idx)) {
                                                     flushing_upto_idx = idx;
                                                     return true;
                                                 } else {
                                                     return false;
                                                 }
                                             });

    lg->finish(m_logdev_id, get_prev_crc());
    if (sisl_unlikely(flushing_upto_idx == -1)) { return nullptr; }
    lg->m_flush_log_idx_from = m_last_flush_idx + 1;
    lg->m_flush_log_idx_upto = flushing_upto_idx;
    HS_DBG_ASSERT_GE(lg->m_flush_log_idx_upto, lg->m_flush_log_idx_from, "log indx upto is smaller then log indx from");

    HS_DBG_ASSERT_GT(lg->header()->oob_data_offset, 0);

    THIS_LOGDEV_LOG(DEBUG, "Flushing upto log_idx={}", flushing_upto_idx);
    return lg;
}

bool LogDev::can_flush_in_this_thread() {
    if (iomanager.am_i_io_reactor() && (iomanager.iofiber_self() == logstore_service().flush_thread())) { return true; }
    return (!HS_DYNAMIC_CONFIG(logstore.flush_only_in_dedicated_thread) && iomanager.am_i_worker_reactor());
}

// This method checks if in case we were to add a record of size provided, do we enter into a state which exceeds
// our threshold. If so, it first flushes whats accumulated so far and then add the pending flush size counter with
// the new record size
bool LogDev::flush_if_needed(int64_t threshold_size) {
    {
        std::unique_lock< std::mutex > lk{m_block_flush_q_mutex};
        if (m_stopped) { return false; }
    }

    // If after adding the record size, if we have enough to flush or if its been too much time before we actually
    // flushed, attempt to flush by setting the atomic bool variable.
    if (threshold_size < 0) { threshold_size = LogDev::flush_data_threshold_size(); }

    const auto elapsed_time = get_elapsed_time_us(m_last_flush_time);
    auto const pending_sz = m_pending_flush_size.load(std::memory_order_relaxed);
    bool const flush_by_size = (pending_sz >= threshold_size);
    bool const flush_by_time =
        !flush_by_size && pending_sz && (elapsed_time > HS_DYNAMIC_CONFIG(logstore.max_time_between_flush_us));

    if (flush_by_size || flush_by_time) {
        // First off, check if we can flush in this thread itself, if not, schedule it into different thread
        if (!can_flush_in_this_thread()) {
            iomanager.run_on_forget(logstore_service().flush_thread(),
                                    [this, threshold_size]() { flush_if_needed(threshold_size); });
            return false;
        }

        bool expected_flushing{false};
        if (!m_is_flushing.compare_exchange_strong(expected_flushing, true, std::memory_order_acq_rel)) {
            return false;
        }
        THIS_LOGDEV_LOG(TRACE,
                        "Flushing now because either pending_size={} is greater than data_threshold={} or "
                        "elapsed time since last flush={} us is greater than max_time_between_flush={} us",
                        pending_sz, threshold_size, elapsed_time,
                        HS_DYNAMIC_CONFIG(logstore.max_time_between_flush_us));

        m_last_flush_time = Clock::now();
        // We were able to win the flushing competition and now we gather all the flush data and reserve a slot.
        auto new_idx = m_log_idx.load(std::memory_order_relaxed) - 1;
        if (m_last_flush_idx >= new_idx) {
            THIS_LOGDEV_LOG(TRACE, "Log idx {} is just flushed", new_idx);
            unlock_flush(false);
            return false;
        }

        auto* lg = prepare_flush(new_idx - m_last_flush_idx + 4); // Estimate 4 more extra in case of parallel writes
        if (sisl_unlikely(!lg)) {
            THIS_LOGDEV_LOG(TRACE, "Log idx {} last_flush_idx {} prepare flush failed", new_idx, m_last_flush_idx);
            unlock_flush(false);
            return false;
        }
        auto sz = m_pending_flush_size.fetch_sub(lg->actual_data_size(), std::memory_order_relaxed);
        HS_REL_ASSERT_GE((sz - lg->actual_data_size()), 0, "size {} lg size{}", sz, lg->actual_data_size());

        off_t offset = m_vdev_jd->alloc_next_append_blk(lg->header()->total_size());
        lg->m_log_dev_offset = offset;
        HS_REL_ASSERT_NE(lg->m_log_dev_offset, INVALID_OFFSET, "log dev is full");
        THIS_LOGDEV_LOG(TRACE, "Flushing log group data size={} at offset=0x{} log_group={}", lg->actual_data_size(),
                        to_hex(offset), *lg);
        // THIS_LOGDEV_LOG(DEBUG, "Log Group: {}", *lg);
        do_flush(lg);
        return true;
    } else {
        return false;
    }
}

void LogDev::do_flush(LogGroup* lg) {
#ifdef _PRERELEASE
    if (iomgr_flip::instance()->delay_flip< int >(
            "simulate_log_flush_delay", [this, lg]() { do_flush_write(lg); }, m_logdev_id)) {
        THIS_LOGDEV_LOG(INFO, "Delaying flush by rescheduling the async write");
        return;
    }
#endif

    // if (has_data_service() && data_service().is_fsync_needed()) {
    //     data_service().fsync([this, lg]() { do_flush_write(lg); })
    // } else {
    //     do_flush_write(lg);
    // }
    do_flush_write(lg);
}

void LogDev::do_flush_write(LogGroup* lg) {
    HISTOGRAM_OBSERVE(logstore_service().m_metrics, logdev_flush_records_distribution, lg->nrecords());
    HISTOGRAM_OBSERVE(logstore_service().m_metrics, logdev_flush_size_distribution, lg->actual_data_size());
    THIS_LOGDEV_LOG(TRACE, "vdev offset={} log group total size={}", lg->m_log_dev_offset, lg->header()->total_size());

    // write log
    m_vdev_jd->async_pwritev(lg->iovecs().data(), int_cast(lg->iovecs().size()), lg->m_log_dev_offset)
        .thenValue([this, lg](auto) { on_flush_completion(lg); });
}

void LogDev::on_flush_completion(LogGroup* lg) {
    lg->m_flush_finish_time = Clock::now();
    lg->m_post_flush_msg_rcvd_time = Clock::now();
    THIS_LOGDEV_LOG(TRACE, "Flush completed for logid[{} - {}]", lg->m_flush_log_idx_from, lg->m_flush_log_idx_upto);

    m_log_records->complete(lg->m_flush_log_idx_from, lg->m_flush_log_idx_upto);
    m_last_flush_idx = lg->m_flush_log_idx_upto;
    const auto flush_ld_key = logdev_key{m_last_flush_idx, lg->m_log_dev_offset + lg->header()->total_size()};
    m_last_crc = lg->header()->cur_grp_crc;

    auto from_indx = lg->m_flush_log_idx_from;
    auto upto_indx = lg->m_flush_log_idx_upto;
    auto dev_offset = lg->m_log_dev_offset;
    for (auto idx = from_indx; idx <= upto_indx; ++idx) {
        auto& record = m_log_records->at(idx);
        on_io_completion(record.store_id, logdev_key{idx, dev_offset}, flush_ld_key, upto_indx - idx, record.context);
    }
    lg->m_post_flush_process_done_time = Clock::now();

    HISTOGRAM_OBSERVE(logstore_service().m_metrics, logdev_flush_done_msg_time_ns,
                      get_elapsed_time_us(lg->m_flush_finish_time, lg->m_post_flush_msg_rcvd_time));
    HISTOGRAM_OBSERVE(logstore_service().m_metrics, logdev_post_flush_processing_latency,
                      get_elapsed_time_us(lg->m_post_flush_msg_rcvd_time, lg->m_post_flush_process_done_time));
    free_log_group(lg);
    unlock_flush();
}

bool LogDev::run_under_flush_lock(const flush_blocked_callback& cb) {
    {
        std::unique_lock lk{m_block_flush_q_mutex};
        if (m_stopped) {
            THIS_LOGDEV_LOG(WARN, "Trying to lock a flush on a stopped logdev, not locking the flush");
            return false;
        }

        bool expected_flushing{false};
        if (!m_is_flushing.compare_exchange_strong(expected_flushing, true, std::memory_order_acq_rel)) {
            // Flushing is blocked already, add it to the callback q
            if (m_block_flush_q == nullptr) { m_block_flush_q = sisl::VectorPool< flush_blocked_callback >::alloc(); }
            m_block_flush_q->emplace_back(cb);
            return false;
        }
    }

    // the contract here is if cb return falses, it means it will unlock_flush by itself (in another thread);
    if (cb()) { unlock_flush(); }
    return true;
}

void LogDev::unlock_flush(bool do_flush) {
    std::vector< flush_blocked_callback >* flush_q{nullptr};
    {
        std::unique_lock lk{m_block_flush_q_mutex};
        if (m_block_flush_q != nullptr) {
            flush_q = m_block_flush_q;
            m_block_flush_q = nullptr;
        }
    }

    if (flush_q) {
        for (auto it = flush_q->begin(); it != flush_q->end(); ++it) {
            auto& cb = *it;
            if (m_stopped) {
                THIS_LOGDEV_LOG(INFO, "Logdev is stopped and thus not processing outstanding flush_lock_q");
                return;
            }
            if (!cb()) {
                // NOTE: Under this if condition DO NOT ASSUME flush lock is still being held. This is because
                // callee is saying, I will unlock the flush lock on my own and before returning from cb to here,
                // the callee could have schedule a job in other thread and unlock the flush.
                std::unique_lock lk{m_block_flush_q_mutex};
                THIS_LOGDEV_LOG(DEBUG,
                                "flush cb wanted to hold onto the flush lock, so putting the {} remaining entries back "
                                "to the q at head position which already has {} entries",
                                std::distance(flush_q->begin(), it), m_block_flush_q ? m_block_flush_q->size() : 0);

                flush_q->erase(flush_q->begin(), it + 1);
                if (m_block_flush_q == nullptr) {
                    m_block_flush_q = flush_q;
                } else {
                    m_block_flush_q->insert(m_block_flush_q->begin(), flush_q->begin(), flush_q->end());
                }

                return;
            }
        }
        sisl::VectorPool< flush_blocked_callback >::free(flush_q);
    }
    m_is_flushing.store(false, std::memory_order_release);

    // Try to do chain flush if its really needed.
    THIS_LOGDEV_LOG(TRACE, "Unlocked the flush, try doing chain flushing if needed");
    // send a message to see if a new flush can be triggered
    if (do_flush) { flush_if_needed(); }
}

uint64_t LogDev::truncate(const logdev_key& key) {
    HS_DBG_ASSERT_GE(key.idx, m_last_truncate_idx);
    uint64_t const num_records_to_truncate = static_cast< uint64_t >(key.idx - m_last_truncate_idx);
    THIS_LOGDEV_LOG(DEBUG, "LogDev::truncate num {} idx {}", num_records_to_truncate, key.idx);
    if (num_records_to_truncate > 0) {
        HS_PERIODIC_LOG(INFO, logstore,
                        "Truncating log device upto log_dev={} log_id={} vdev_offset={} truncated {} log records",
                        m_logdev_id, key.idx, key.dev_offset, num_records_to_truncate);
        m_log_records->truncate(key.idx);
        off_t new_offset = m_vdev_jd->truncate(key.dev_offset);
        THIS_LOGDEV_LOG(DEBUG, "LogDev::truncate done {} offset old {} new {}", key.idx, key.dev_offset, new_offset);
        m_last_truncate_idx = key.idx;

        {
            std::unique_lock< std::mutex > lk{m_meta_mutex};

            // Update the start offset to be read upon restart
            m_logdev_meta.set_start_dev_offset(new_offset, key.idx + 1, false /* persist_now */);

            // Now that store is truncated, we can reclaim the store ids which are garbaged (if any) earlier
#ifdef _PRERELEASE
            bool garbage_collect = false;
#endif
            for (auto it{std::cbegin(m_garbage_store_ids)}; it != std::cend(m_garbage_store_ids);) {
                if (it->first > key.idx) break;

                HS_PERIODIC_LOG(DEBUG, logstore, "Garbage collecting the log_dev={} log_store={} log_idx={}",
                                m_logdev_id, it->second, it->first);
                m_logdev_meta.unreserve_store(it->second, false /* persist_now */);
                it = m_garbage_store_ids.erase(it);
#ifdef _PRERELEASE
                garbage_collect = true;
#endif
            }

            // We can remove the rollback records of those upto which logid is getting truncated
            m_logdev_meta.remove_rollback_record_upto(key.idx, false /* persist_now */);
            THIS_LOGDEV_LOG(DEBUG, "LogDev::truncate remove rollback {}", key.idx);
            m_logdev_meta.persist();
#ifdef _PRERELEASE
            if (garbage_collect && iomgr_flip::instance()->test_flip("logdev_abort_after_garbage")) {
                THIS_LOGDEV_LOG(INFO, "logdev aborting after unreserving garbage ids");
                hs()->crash_simulator().crash();
                return num_records_to_truncate;
            }
#endif
        }
    }
    return num_records_to_truncate;
}

void LogDev::update_store_superblk(logstore_id_t store_id, const logstore_superblk& lsb, bool persist_now) {
    std::unique_lock lg{m_meta_mutex};
    m_logdev_meta.update_store_superblk(store_id, lsb, persist_now);
}

void LogDev::rollback(logstore_id_t store_id, logid_range_t id_range) {
    std::unique_lock lg{m_meta_mutex};
    m_logdev_meta.add_rollback_record(store_id, id_range, true);
}

/////////////////////////////// LogStore Section ///////////////////////////////////////

void LogDev::handle_unopened_log_stores(bool format) {
    for (auto it{std::begin(m_unopened_store_io)}; it != std::end(m_unopened_store_io); ++it) {
        LOGINFO("skip log entries for store id {}-{}, ios {}", m_logdev_id, it->first, it->second);
    }
    m_unopened_store_io.clear();

    // If there are any unopened storeids found, loop and check again if they are indeed open later. Unopened log
    // store could be possible if the ids are deleted, but it is delayed to remove from store id reserver. In that
    // case, do the remove from store id reserver now.
    // TODO: At present we are assuming all unopened store ids could be removed. In future have a callback to this
    // start routine, which takes the list of unopened store ids and can return a new set, which can be removed.
    {
        folly::SharedMutexWritePriority::WriteHolder holder(m_store_map_mtx);
        for (auto it{std::begin(m_unopened_store_id)}; it != std::end(m_unopened_store_id);) {
            if (m_id_logstore_map.find(*it) == m_id_logstore_map.end()) {
                // Not opened even on second time check, simply unreserve id
                unreserve_store_id(*it);
            }
            it = m_unopened_store_id.erase(it);
        }
    }
}

std::shared_ptr< HomeLogStore > LogDev::create_new_log_store(bool append_mode) {
    auto const store_id = reserve_store_id();
    std::shared_ptr< HomeLogStore > lstore;
    lstore = std::make_shared< HomeLogStore >(shared_from_this(), store_id, append_mode, 0);

    {
        folly::SharedMutexWritePriority::WriteHolder holder(m_store_map_mtx);
        const auto it = m_id_logstore_map.find(store_id);
        HS_REL_ASSERT((it == m_id_logstore_map.end()), "store_id {}-{} already exists", m_logdev_id, store_id);
        m_id_logstore_map.insert(std::pair(store_id, logstore_info{.log_store = lstore, .append_mode = append_mode}));
    }
    HS_LOG(INFO, logstore, "Created log store log_dev={} log_store={}", m_logdev_id, store_id);
    return lstore;
}

folly::Future< shared< HomeLogStore > > LogDev::open_log_store(logstore_id_t store_id, bool append_mode) {
    folly::SharedMutexWritePriority::WriteHolder holder(m_store_map_mtx);
    auto it = m_id_logstore_map.find(store_id);
    if (it == m_id_logstore_map.end()) {
        bool happened;
        std::tie(it, happened) = m_id_logstore_map.insert(std::pair(store_id,
                                                                    logstore_info{
                                                                        .log_store = nullptr,
                                                                        .append_mode = append_mode,
                                                                    }));
        HS_REL_ASSERT_EQ(happened, true, "Unable to insert logstore into id_logstore_map");
    }
    return it->second.promise.getFuture();
}

void LogDev::remove_log_store(logstore_id_t store_id) {
    LOGINFO("Removing log_dev={} log_store={}", m_logdev_id, store_id);
    {
        folly::SharedMutexWritePriority::WriteHolder holder(m_store_map_mtx);
        auto ret = m_id_logstore_map.erase(store_id);
        HS_REL_ASSERT((ret == 1), "try to remove invalid store_id {}-{}", m_logdev_id, store_id);
    }
    unreserve_store_id(store_id);
}

void LogDev::device_truncate_under_lock(const std::shared_ptr< truncate_req > treq) {
    run_under_flush_lock([this, treq]() {
        iomanager.run_on_forget(logstore_service().truncate_thread(), [this, treq]() {
            const logdev_key trunc_upto = do_device_truncate(treq->dry_run);
            bool done{false};
            if (treq->cb || treq->wait_till_done) {
                {
                    std::lock_guard< std::mutex > lk{treq->mtx};
                    done = (--treq->trunc_outstanding == 0);
                    treq->m_trunc_upto_result[m_logdev_id] = trunc_upto;
                }
            }
            if (done) {
                if (treq->cb) { treq->cb(treq->m_trunc_upto_result); }
                if (treq->wait_till_done) { treq->cv.notify_one(); }
            }

            unlock_flush();
        });
        return false; // Do not release the flush lock yet, the scheduler will unlock it.
    });
}

void LogDev::on_log_store_found(logstore_id_t store_id, const logstore_superblk& sb) {
    folly::SharedMutexWritePriority::ReadHolder holder(m_store_map_mtx);
    auto it = m_id_logstore_map.find(store_id);
    if (it == m_id_logstore_map.end()) {
        LOGERROR("Store Id {}-{} found but not opened yet, it will be discarded after logstore is started", m_logdev_id,
                 store_id);
        m_unopened_store_id.insert(store_id);
        m_unopened_store_io.insert(std::make_pair<>(store_id, 0));
        return;
    }

    LOGINFO("Found a logstore log_dev={} log_store={} with start seq_num={}, Creating a new HomeLogStore instance",
            m_logdev_id, store_id, sb.m_first_seq_num);
    logstore_info& info = it->second;
    info.log_store =
        std::make_shared< HomeLogStore >(shared_from_this(), store_id, info.append_mode, sb.m_first_seq_num);
    info.promise.setValue(info.log_store);
}

static thread_local std::vector< std::shared_ptr< HomeLogStore > > s_cur_flush_batch_stores;

void LogDev::on_io_completion(logstore_id_t id, logdev_key ld_key, logdev_key flush_ld_key,
                              uint32_t nremaining_in_batch, void* ctx) {
    auto* req = s_cast< logstore_req* >(ctx);
    HomeLogStore* log_store = req->log_store;

    if (req->is_write) {
        HS_LOG_ASSERT_EQ(log_store->get_store_id(), id, "Expecting store id in log store and io completion to match");
        log_store->on_write_completion(req, ld_key);
        on_batch_completion(log_store, nremaining_in_batch, flush_ld_key);
    } else {
        log_store->on_read_completion(req, ld_key);
    }
}

void LogDev::on_logfound(logstore_id_t id, logstore_seq_num_t seq_num, logdev_key ld_key, logdev_key flush_ld_key,
                         log_buffer buf, uint32_t nremaining_in_batch) {
    HomeLogStore* log_store{nullptr};

    {
        folly::SharedMutexWritePriority::ReadHolder holder(m_store_map_mtx);
        auto const it = m_id_logstore_map.find(id);
        if (it == m_id_logstore_map.end()) {
            auto [unopened_it, inserted] = m_unopened_store_io.insert(std::make_pair<>(id, 0));
            if (inserted) {
                // HS_REL_ASSERT(0, "log id  {}-{} not found", m_logdev_id, id);
            }
            ++unopened_it->second;
            return;
        }
        log_store = it->second.log_store.get();
    }
    if (!log_store) { return; }
    log_store->on_log_found(seq_num, ld_key, flush_ld_key, buf);
    on_batch_completion(log_store, nremaining_in_batch, flush_ld_key);
}

void LogDev::on_batch_completion(HomeLogStore* log_store, uint32_t nremaining_in_batch, logdev_key flush_ld_key) {
    /* check if it is a first update on this log store */
    auto id = log_store->get_store_id();
    const auto it = m_last_flush_info.find(id);
    if ((it == std::end(m_last_flush_info)) || (it->second != flush_ld_key.idx)) {
        // first time completion in this batch for a given store_id
        m_last_flush_info.insert_or_assign(id, flush_ld_key.idx);
        if (it == std::end(m_last_flush_info)) { s_cur_flush_batch_stores.push_back(log_store->shared_from_this()); }
    }
    if (nremaining_in_batch == 0) {
        // This batch is completed, call all log stores participated in this batch about the end of batch
        HS_LOG_ASSERT_GT(s_cur_flush_batch_stores.size(), 0U, "Expecting one store to be flushed in batch");

        for (auto& l : s_cur_flush_batch_stores) {
            l->on_batch_completion(flush_ld_key);
        }
        s_cur_flush_batch_stores.clear();
        m_last_flush_info.clear();
    }
}

logdev_key LogDev::do_device_truncate(bool dry_run) {
    static thread_local std::vector< std::shared_ptr< HomeLogStore > > m_min_trunc_stores;
    static thread_local std::vector< std::shared_ptr< HomeLogStore > > m_non_participating_stores;

    m_min_trunc_stores.clear();
    m_non_participating_stores.clear();
    logdev_key min_safe_ld_key = logdev_key::out_of_bound_ld_key();

    std::string dbg_str{"Format [store_id:trunc_lsn:logidx:dev_trunc_pending?:active_writes_in_trucate?] "};

    {
        folly::SharedMutexWritePriority::ReadHolder holder(m_store_map_mtx);
        for (auto& id_logstore : m_id_logstore_map) {
            auto& store_ptr = id_logstore.second.log_store;
            const auto& trunc_info = store_ptr->pre_device_truncation();

            if (!trunc_info.pending_dev_truncation && !trunc_info.active_writes_not_part_of_truncation) {
                // This log store neither has any pending device truncation nor active logstore io going on for now.
                // Ignore this log store for min safe boundary calculation.
                fmt::format_to(std::back_inserter(dbg_str), "[{}:None] ", store_ptr->get_store_id());
                m_non_participating_stores.push_back(store_ptr);
                continue;
            }

            fmt::format_to(std::back_inserter(dbg_str), "[{}:{}:{}:{}:{}] ", store_ptr->get_store_id(),
                           trunc_info.seq_num.load(), trunc_info.ld_key.idx, trunc_info.pending_dev_truncation,
                           trunc_info.active_writes_not_part_of_truncation);
            if (trunc_info.ld_key.idx > min_safe_ld_key.idx) { continue; }

            if (trunc_info.ld_key.idx < min_safe_ld_key.idx) {
                // New minimum safe l entry
                min_safe_ld_key = trunc_info.ld_key;
                m_min_trunc_stores.clear();
            }
            m_min_trunc_stores.push_back(store_ptr);
        }
    }

    if ((min_safe_ld_key == logdev_key::out_of_bound_ld_key()) || (min_safe_ld_key.idx < 0)) {
        HS_PERIODIC_LOG(DEBUG, logstore,
                        "[log_dev={}] No log store append on any log stores, skipping device truncation, "
                        "all_logstore_info:<{}>",
                        m_logdev_id, dbg_str);
        return min_safe_ld_key;
    }

    // Got the safest log id to truncate and actually truncate upto the safe log idx to the log device
    if (!dry_run) { truncate(min_safe_ld_key); }
    HS_PERIODIC_LOG(INFO, logstore,
                    "[log_dev={}] LogDevice truncate, all_logstore_info:<{}> safe log dev key to truncate={}",
                    m_logdev_id, dbg_str, min_safe_ld_key);

    // We call post device truncation only to the log stores whose prepared truncation points are fully
    // truncated or to stores which didn't particpate in this device truncation.
    for (auto& store_ptr : m_min_trunc_stores) {
        store_ptr->post_device_truncation(min_safe_ld_key);
    }
    for (auto& store_ptr : m_non_participating_stores) {
        store_ptr->post_device_truncation(min_safe_ld_key);
    }
    m_min_trunc_stores.clear(); // Not clearing here, would cause a shared_ptr ref holding.
    m_non_participating_stores.clear();

    return min_safe_ld_key;
}

nlohmann::json LogDev::dump_log_store(const log_dump_req& dump_req) {
    nlohmann::json json_dump{}; // create root object
    if (dump_req.log_store == nullptr) {
        folly::SharedMutexWritePriority::ReadHolder holder(m_store_map_mtx);
        for (auto& id_logstore : m_id_logstore_map) {
            auto store_ptr{id_logstore.second.log_store};
            const std::string id{std::to_string(store_ptr->get_store_id())};
            // must use operator= construction as copy construction results in error
            nlohmann::json val = store_ptr->dump_log_store(dump_req);
            json_dump[id] = std::move(val);
        }
    } else {
        const std::string id{std::to_string(dump_req.log_store->get_store_id())};
        // must use operator= construction as copy construction results in error
        nlohmann::json val = dump_req.log_store->dump_log_store(dump_req);
        json_dump[id] = std::move(val);
    }
    return json_dump;
}

nlohmann::json LogDev::get_status(int verbosity) const {
    nlohmann::json js;
    auto unopened = nlohmann::json::array();
    for (const auto& l : m_unopened_store_id) {
        unopened.push_back(l);
    }
    js["logstores_unopened"] = std::move(unopened);

    // Logdev status
    js["current_log_idx"] = m_log_idx.load(std::memory_order_relaxed);
    js["last_flush_log_idx"] = m_last_flush_idx;
    js["last_truncate_log_idx"] = m_last_truncate_idx;
    js["time_since_last_log_flush_ns"] = get_elapsed_time_ns(m_last_flush_time);
    if (verbosity == 2) {
        js["logdev_stopped?"] = m_stopped;
        js["is_log_flushing_now?"] = m_is_flushing.load(std::memory_order_relaxed);
        js["logdev_sb_start_offset"] = m_logdev_meta.get_start_dev_offset();
        js["logdev_sb_num_stores_reserved"] = m_logdev_meta.num_stores_reserved();
    }

    // All logstores
    {
        folly::SharedMutexWritePriority::ReadHolder holder(m_store_map_mtx);
        for (const auto& [id, lstore] : m_id_logstore_map) {
            js["logstore_id_" + std::to_string(id)] = lstore.log_store->get_status(verbosity);
        }
    }
    return js;
}

/////////////////////////////// LogDevMetadata Section ///////////////////////////////////////
LogDevMetadata::LogDevMetadata() : m_sb{logdev_sb_meta_name}, m_rollback_sb{logdev_rollback_sb_meta_name} {}

logdev_superblk* LogDevMetadata::create(logdev_id_t id) {
    logdev_superblk* sb = m_sb.create(logdev_sb_size_needed(0));
    rollback_superblk* rsb = m_rollback_sb.create(rollback_superblk::size_needed(1));

    auto* sb_area = m_sb->get_logstore_superblk();
    std::fill_n(sb_area, store_capacity(), logstore_superblk::default_value());

    m_id_reserver = std::make_unique< sisl::IDReserver >();
    m_sb->logdev_id = id;
    m_sb.write();

    m_rollback_sb->logdev_id = id;
    m_rollback_sb.write();
    return sb;
}

void LogDevMetadata::destroy() {
    m_rollback_sb.destroy();
    m_sb.destroy();
}

void LogDevMetadata::reset() {
    m_id_reserver.reset();
    m_store_info.clear();
}

void LogDevMetadata::logdev_super_blk_found(const sisl::byte_view& buf, void* meta_cookie) {

    m_sb.load(buf, meta_cookie);
    LOGINFO("Logdev superblk found log_dev={}", m_sb->logdev_id);
    HS_REL_ASSERT_EQ(m_sb->get_magic(), logdev_superblk::LOGDEV_SB_MAGIC, "Invalid logdev metablk, magic mismatch");
    HS_REL_ASSERT_EQ(m_sb->get_version(), logdev_superblk::LOGDEV_SB_VERSION, "Invalid version of logdev metablk");
}

void LogDevMetadata::rollback_super_blk_found(const sisl::byte_view& buf, void* meta_cookie) {
    m_rollback_sb.load(buf, meta_cookie);
    HS_REL_ASSERT_EQ(m_rollback_sb->get_magic(), rollback_superblk::ROLLBACK_SB_MAGIC, "Rollback sb magic mismatch");
    HS_REL_ASSERT_EQ(m_rollback_sb->get_version(), rollback_superblk::ROLLBACK_SB_VERSION,
                     "Rollback sb version mismatch");
}

std::vector< std::pair< logstore_id_t, logstore_superblk > > LogDevMetadata::load() {
    std::vector< std::pair< logstore_id_t, logstore_superblk > > ret_list;
    ret_list.reserve(1024);
    if (store_capacity()) {
        m_id_reserver = std::make_unique< sisl::IDReserver >(store_capacity());
    } else {
        // use default value (1024) if store_capacity is zero
        m_id_reserver = std::make_unique< sisl::IDReserver >();
    }

    HS_REL_ASSERT_EQ(m_sb.is_empty(), false, "Load called without getting metadata");
    HS_REL_ASSERT_LE(m_sb->get_version(), logdev_superblk::LOGDEV_SB_VERSION, "Logdev super blk version mismatch");

    const logstore_superblk* store_sb = m_sb->get_logstore_superblk();
    logstore_id_t idx{0};
    decltype(m_sb->num_stores) n{0};
    while (n < m_sb->num_stores) {
        if (logstore_superblk::is_valid(store_sb[idx])) {
            m_store_info.insert(idx);
            m_id_reserver->reserve(idx);
            ret_list.push_back(std::make_pair<>(idx, store_sb[idx]));
            ++n;
        }
        ++idx;
    }

    for (uint32_t i{0}; i < m_rollback_sb->num_records; ++i) {
        const auto& rec = m_rollback_sb->at(i);
        m_rollback_info.insert({rec.store_id, rec.idx_range});
    }

    return ret_list;
}

logstore_id_t LogDevMetadata::reserve_store(bool persist_now) {
    auto const idx = m_id_reserver->reserve(); // Search the id reserver and alloc an idx;
    m_store_info.insert(idx);

    // Write the meta inforation on-disk meta
    resize_logdev_sb_if_needed(); // In case the idx falls out of the alloc boundary, resize them

    logstore_superblk* sb_area = m_sb->get_logstore_superblk();
    logstore_superblk::init(sb_area[idx]);
    ++m_sb->num_stores;
    if (persist_now) { m_sb.write(); }

    return idx;
}

void LogDevMetadata::persist() {
    m_sb.write();
    if (m_rollback_info_dirty) {
        m_rollback_sb.write();
        m_rollback_info_dirty = false;
    }
}

void LogDevMetadata::unreserve_store(logstore_id_t store_id, bool persist_now) {
    m_id_reserver->unreserve(store_id);
    m_store_info.erase(store_id);
    remove_all_rollback_records(store_id, persist_now);

    resize_logdev_sb_if_needed();
    if (store_id < *m_store_info.rbegin()) {
        HS_LOG(DEBUG, logstore, "logdev meta not shrunk log_idx={} highest indx {}", store_id, *m_store_info.rbegin(),
               m_sb->num_stores);
        // We have not shrunk the store info, so we need to explicitly clear the store meta in on-disk meta
        logstore_superblk* sb_area = m_sb->get_logstore_superblk();
        logstore_superblk::clear(sb_area[store_id]);
    }
    --m_sb->num_stores;
    if (persist_now) { m_sb.write(); }
}

void LogDevMetadata::update_store_superblk(logstore_id_t idx, const logstore_superblk& sb, bool persist_now) {
    // Update the in-memory copy
    m_store_info.insert(idx);

    // Update the on-disk copy
    resize_logdev_sb_if_needed();

    logstore_superblk* sb_area = m_sb->get_logstore_superblk();
    sb_area[idx] = sb;

    if (persist_now) { m_sb.write(); }
}

const logstore_superblk& LogDevMetadata::store_superblk(logstore_id_t idx) const {
    const logstore_superblk* sb_area = m_sb->get_logstore_superblk();
    return sb_area[idx];
}

logstore_superblk& LogDevMetadata::mutable_store_superblk(logstore_id_t idx) {
    logstore_superblk* sb_area = m_sb->get_logstore_superblk();
    return sb_area[idx];
}

void LogDevMetadata::set_start_dev_offset(off_t offset, logid_t key_idx, bool persist_now) {
    m_sb->set_start_offset(offset);
    m_sb->key_idx = key_idx;
    if (persist_now) { m_sb.write(); }
}

logid_t LogDevMetadata::get_start_log_idx() const { return m_sb->key_idx; }

bool LogDevMetadata::resize_logdev_sb_if_needed() {
    auto req_sz = logdev_sb_size_needed((m_store_info.size() == 0) ? 0u : *m_store_info.rbegin() + 1);
    if (meta_service().is_aligned_buf_needed(req_sz)) { req_sz = sisl::round_up(req_sz, meta_service().align_size()); }
    if (req_sz != m_sb.size()) {
        const auto old_buf = m_sb.raw_buf();

        m_sb.create(req_sz);
        logstore_superblk* sb_area = m_sb->get_logstore_superblk();
        std::fill_n(sb_area, store_capacity(), logstore_superblk::default_value());

        std::memcpy(voidptr_cast(m_sb.raw_buf()->bytes()), static_cast< const void* >(old_buf->cbytes()),
                    std::min(old_buf->size(), m_sb.size()));
        return true;
    } else {
        return false;
    }
}

uint32_t LogDevMetadata::store_capacity() const {
    return (m_sb.size() - sizeof(logdev_superblk)) / sizeof(logstore_superblk);
}

void LogDevMetadata::add_rollback_record(logstore_id_t store_id, logid_range_t id_range, bool persist_now) {
    m_rollback_info.insert({store_id, id_range});
    resize_rollback_sb_if_needed();
    m_rollback_sb->add_record(store_id, id_range);

    if (persist_now) { m_rollback_sb.write(); }
    m_rollback_info_dirty = !persist_now;
}

void LogDevMetadata::remove_rollback_record_upto(logid_t upto_id, bool persist_now) {
    uint32_t n_removed{0};
    for (auto i = m_rollback_sb->num_records; i > 0; --i) {
        auto& rec = m_rollback_sb->at(i - 1);
        HS_LOG(TRACE, logstore, "Removing record sb {} {}", rec.idx_range.second, upto_id);
        if (rec.idx_range.second <= upto_id) {
            m_rollback_sb->remove_ith_record(i - 1);
            ++n_removed;
        }
    }

    if (n_removed) {
        for (auto it = m_rollback_info.begin(); it != m_rollback_info.end();) {
            HS_LOG(TRACE, logstore, "Removing info {} {}", it->second.second, upto_id);
            if (it->second.second <= upto_id) {
                it = m_rollback_info.erase(it);
            } else {
                ++it;
            }
        }
        resize_rollback_sb_if_needed();
        if (persist_now) { m_rollback_sb.write(); }
        m_rollback_info_dirty = !persist_now;
    }
}

void LogDevMetadata::remove_all_rollback_records(logstore_id_t store_id, bool persist_now) {
    uint32_t n_removed{0};
    for (auto i = m_rollback_sb->num_records; i > 0; --i) {
        auto& rec = m_rollback_sb->at(i - 1);
        if (rec.store_id == store_id) {
            m_rollback_sb->remove_ith_record(i - 1);
            ++n_removed;
        }
    }
    if (n_removed) {
        m_rollback_info.erase(store_id);
        resize_rollback_sb_if_needed();
        if (persist_now) { m_rollback_sb.write(); }
        m_rollback_info_dirty = !persist_now;
    }
}

uint32_t LogDevMetadata::num_rollback_records(logstore_id_t store_id) const {
    HS_DBG_ASSERT_EQ(m_rollback_sb->num_records, m_rollback_info.size(),
                     "Rollback record count mismatch between sb and in-memory");
    return m_rollback_info.count(store_id);
}

bool LogDevMetadata::is_rolled_back(logstore_id_t store_id, logid_t logid) const {
    auto it_pair = m_rollback_info.equal_range(store_id);
    for (auto it = it_pair.first; it != it_pair.second; ++it) {
        const logid_range_t& log_id_range = it->second;
        if ((logid >= log_id_range.first) && (logid <= log_id_range.second)) { return true; }
    }
    return false;
}

bool LogDevMetadata::resize_rollback_sb_if_needed() {
    auto req_sz = rollback_superblk::size_needed(m_rollback_info.size());
    if (meta_service().is_aligned_buf_needed(req_sz)) { req_sz = sisl::round_up(req_sz, meta_service().align_size()); }

    if (req_sz != m_rollback_sb.size()) {
        const auto old_buf = m_rollback_sb.raw_buf();

        m_rollback_sb.create(req_sz);
        std::memcpy(voidptr_cast(m_rollback_sb.raw_buf()->bytes()), static_cast< const void* >(old_buf->cbytes()),
                    std::min(old_buf->size(), m_rollback_sb.size()));
        return true;
    } else {
        return false;
    }
}
} // namespace homestore
