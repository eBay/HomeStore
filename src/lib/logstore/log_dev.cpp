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
#include <isa-l/crc.h>

#include <homestore/logstore_service.hpp>
#include <homestore/meta_service.hpp>
#include <homestore/homestore.hpp>

#include "log_dev.hpp"
#include "device/journal_vdev.hpp"
#include "common/homestore_assert.hpp"
#include "common/homestore_config.hpp"
#include "common/homestore_flip.hpp"
#include "common/homestore_utils.hpp"

namespace homestore {

SISL_LOGGING_DECL(logstore)

#define THIS_LOGDEV_LOG(level, msg, ...) HS_SUBMOD_LOG(level, logstore, , "logdev", m_family_id, msg, __VA_ARGS__)
#define THIS_LOGDEV_PERIODIC_LOG(level, msg, ...)                                                                      \
    HS_PERIODIC_DETAILED_LOG(level, logstore, "logdev", m_family_id, , , msg, __VA_ARGS__)

static bool has_data_service() { return HomeStore::instance()->has_data_service(); }
// static BlkDataService& data_service() { return HomeStore::instance()->data_service(); }

LogDev::LogDev(const logstore_family_id_t f_id, const std::string& logdev_name) :
        m_family_id{f_id}, m_logdev_meta{logdev_name} {
    m_flush_size_multiple = 0;
    if (f_id == LogStoreService::DATA_LOG_FAMILY_IDX) {
        m_flush_size_multiple = HS_DYNAMIC_CONFIG(logstore->flush_size_multiple_data_logdev);
    } else if (f_id == LogStoreService::CTRL_LOG_FAMILY_IDX) {
        m_flush_size_multiple = HS_DYNAMIC_CONFIG(logstore->flush_size_multiple_ctrl_logdev);
    }
}

LogDev::~LogDev() = default;

void LogDev::start(bool format, JournalVirtualDev* vdev) {
    HS_LOG_ASSERT((m_append_comp_cb != nullptr), "Expected Append callback to be registered");
    HS_LOG_ASSERT((m_store_found_cb != nullptr), "Expected Log store found callback to be registered");
    HS_LOG_ASSERT((m_logfound_cb != nullptr), "Expected Logs found callback to be registered");

    m_vdev = vdev;
    if (m_flush_size_multiple == 0) { m_flush_size_multiple = m_vdev->phys_page_size(); }
    THIS_LOGDEV_LOG(INFO, "Initializing logdev with flush size multiple={}", m_flush_size_multiple);

    for (uint32_t i = 0; i < max_log_group; ++i) {
        m_log_group_pool[i].start(m_flush_size_multiple, m_vdev->align_size());
    }
    m_log_records = std::make_unique< sisl::StreamTracker< log_record > >();
    m_stopped = false;

    // First read the info block
    if (format) {
        HS_LOG_ASSERT(m_logdev_meta.is_empty(), "Expected meta to be not present");
        m_logdev_meta.create();
        m_vdev->update_data_start_offset(0);
    } else {
        HS_LOG_ASSERT(!m_logdev_meta.is_empty(), "Expected meta data to be read already before loading");
        auto const store_list = m_logdev_meta.load();

        // Notify to the caller that a new log store was reserved earlier and it is being loaded, with its meta info
        for (const auto& spair : store_list) {
            m_store_found_cb(spair.first, spair.second);
        }

        THIS_LOGDEV_LOG(INFO, "get start vdev offset during recovery {} log indx {} ",
                        m_logdev_meta.get_start_dev_offset(), m_logdev_meta.get_start_log_idx());

        m_vdev->update_data_start_offset(m_logdev_meta.get_start_dev_offset());
        m_log_idx = m_logdev_meta.get_start_log_idx();
        do_load(m_logdev_meta.get_start_dev_offset());
        m_log_records->reinit(m_log_idx);
        m_last_flush_idx = m_log_idx - 1;
    }
    m_flush_timer_hdl = iomanager.schedule_global_timer(
        HS_DYNAMIC_CONFIG(logstore.flush_timer_frequency_us) * 1000, true, nullptr, iomgr::thread_regex::all_worker,
        [this](void* cookie) {
            if (m_pending_flush_size.load() && !m_is_flushing.load(std::memory_order_relaxed)) { flush_if_needed(); }
        });
}

void LogDev::stop() {
    HS_LOG_ASSERT((m_pending_flush_size == 0), "LogDev stop attempted while writes to logdev are pending completion");
    const bool locked_now = try_lock_flush([this]() {
        {
            std::unique_lock< std::mutex > lk{m_block_flush_q_mutex};
            m_stopped = true;
        }
        m_block_flush_q_cv.notify_one();
    });

    if (!locked_now) { THIS_LOGDEV_LOG(INFO, "LogDev stop is queued because of pending flush or truncation ongoing"); }

    {
        // Wait for the stopped to be completed
        std::unique_lock< std::mutex > lk{m_block_flush_q_mutex};
        m_block_flush_q_cv.wait(lk, [&] { return m_stopped; });
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

    THIS_LOGDEV_LOG(INFO, "LogDev stopped successfully");
    // cancel the timer
    iomanager.cancel_timer(m_flush_timer_hdl);
    m_hs.reset();
}

void LogDev::do_load(const off_t device_cursor) {
    log_stream_reader lstream{device_cursor, m_vdev, m_flush_size_multiple};
    logid_t loaded_from{-1};

    off_t group_dev_offset;
    do {
        const auto buf = lstream.next_group(&group_dev_offset);
        if (buf.size() == 0) {
            assert_next_pages(lstream);
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

        HS_REL_ASSERT_EQ(header->start_idx(), m_log_idx, "log indx is not the expected one");
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
            if (m_logfound_cb) {
                // Validate if the id is present in rollback info
                if (m_logdev_meta.is_rolled_back(rec->store_id, header->start_idx() + i)) {
                    THIS_LOGDEV_LOG(
                        DEBUG, "logstore_id[{}] log_idx={}, lsn={} has been rolledback, not notifying the logstore",
                        rec->store_id, (header->start_idx() + i), rec->store_seq_num);
                } else {
                    THIS_LOGDEV_LOG(TRACE, "seq num {}, log indx {}, group dev offset {} size {}", rec->store_seq_num,
                                    (header->start_idx() + i), group_dev_offset, rec->size);
                    m_logfound_cb(rec->store_id, rec->store_seq_num, {header->start_idx() + i, group_dev_offset},
                                  flush_ld_key, b, (header->nrecords() - (i + 1)));
                }
            }
            ++i;
        }
        m_log_idx = header->start_idx() + i;
        m_last_crc = header->cur_grp_crc;
    } while (true);

    // Update the tail offset with where we finally end up loading, so that new append entries can be written from
    // here.
    m_vdev->update_tail_offset(group_dev_offset);
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
                             "must have been corrupted, Header: {}",
                             *header);
        }
    }
}

int64_t LogDev::append_async(const logstore_id_t store_id, const logstore_seq_num_t seq_num, const sisl::io_blob& data,
                             void* cb_context) {
    auto prev_size = m_pending_flush_size.fetch_add(data.size, std::memory_order_relaxed);
    const auto idx = m_log_idx.fetch_add(1, std::memory_order_acq_rel);
    auto threshold_size = LogDev::flush_data_threshold_size();
    m_log_records->create(idx, store_id, seq_num, data, cb_context);

    if (prev_size < threshold_size && ((prev_size + data.size) >= threshold_size) &&
        !m_is_flushing.load(std::memory_order_relaxed)) {
        flush_if_needed();
    }
    return idx;
}

log_buffer LogDev::read(const logdev_key& key, serialized_log_record& return_record_header) {
    static thread_local sisl::aligned_unique_ptr< uint8_t, sisl::buftag::logread > read_buf;

    // First read the offset and read the log_group. Then locate the log_idx within that and get the actual data
    // Read about 4K of buffer
    if (!read_buf) {
        read_buf = sisl::aligned_unique_ptr< uint8_t, sisl::buftag::logread >::make_sized(m_flush_size_multiple,
                                                                                          initial_read_size);
    }
    auto rbuf = read_buf.get();
    auto const size = m_vdev->sync_pread(rbuf, initial_read_size, key.dev_offset);
    HS_REL_ASSERT_EQ(size, initial_read_size, "it is not completely read");

    auto* header = r_cast< const log_group_header* >(rbuf);
    HS_REL_ASSERT_EQ(header->magic_word(), LOG_GROUP_HDR_MAGIC, "Log header corrupted with magic mismatch!");
    HS_REL_ASSERT_EQ(header->get_version(), log_group_header::header_version, "Log header version mismatch!");
    HS_REL_ASSERT_LE(header->start_idx(), key.idx, "log key offset does not match with log_idx");
    HS_REL_ASSERT_GT((header->start_idx() + header->nrecords()), key.idx, "log key offset does not match with log_idx");
    HS_LOG_ASSERT_GE(header->total_size(), header->_inline_data_offset(), "Inconsistent size data in log group");

    // We can only do crc match in read if we have read all the blocks. We don't want to aggressively read more data
    // than we need to just to compare CRC for read operation. It can be done during recovery.
    if (header->total_size() <= initial_read_size) {
        crc32_t const crc = crc32_ieee(init_crc32, reinterpret_cast< const uint8_t* >(rbuf) + sizeof(log_group_header),
                                       header->total_size() - sizeof(log_group_header));
        HS_REL_ASSERT_EQ(header->this_group_crc(), crc, "CRC mismatch on read data");
    }

    auto record_header = header->nth_record(key.idx - header->start_log_idx);
    uint32_t const data_offset = (record_header->offset + (record_header->get_inlined() ? 0 : header->oob_data_offset));

    log_buffer const b{static_cast< uint32_t >(record_header->size)};
    if ((data_offset + b.size()) < initial_read_size) {
        std::memcpy(static_cast< void* >(b.bytes()), static_cast< const void* >(rbuf + data_offset),
                    b.size()); // Already read them enough, copy the data
    } else {
        // Round them data offset to dma boundary in-order to make sure pread on direct io succeed. We need to skip
        // the rounded portion while copying to user buffer
        auto const rounded_data_offset = sisl::round_down(data_offset, m_vdev->align_size());
        auto const rounded_size = sisl::round_up(b.size() + data_offset - rounded_data_offset, m_vdev->align_size());

        // Allocate a fresh aligned buffer, if size cannot fit standard size
        if (rounded_size > initial_read_size) {
            rbuf = hs_utils::iobuf_alloc(rounded_size, sisl::buftag::logread, m_vdev->align_size());
        }

        THIS_LOGDEV_LOG(TRACE,
                        "Addln read as data resides outside initial_read_size={} key.idx={} key.group_dev_offset={} "
                        "data_offset={} size={} rounded_data_offset={} rounded_size={}",
                        initial_read_size, key.idx, key.dev_offset, data_offset, b.size(), rounded_data_offset,
                        rounded_size);
        m_vdev->sync_pread(rbuf, rounded_size, key.dev_offset + rounded_data_offset);
        std::memcpy(static_cast< void* >(b.bytes()),
                    static_cast< const void* >(rbuf + data_offset - rounded_data_offset), b.size());

        // Free the buffer in case we allocated above
        if (rounded_size > initial_read_size) { hs_utils::iobuf_free(rbuf, sisl::buftag::logread); }
    }
    return_record_header =
        serialized_log_record(record_header->size, record_header->offset, record_header->get_inlined(),
                              record_header->store_seq_num, record_header->store_id);
    return b;
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
    m_log_records->foreach_active(m_last_flush_idx + 1, [&](int64_t idx, int64_t upto_idx, log_record& record) -> bool {
        if (lg->add_record(record, idx)) {
            flushing_upto_idx = idx;
            return true;
        } else {
            return false;
        }
    });

    lg->finish(get_prev_crc());
    if (sisl_unlikely(flushing_upto_idx == -1)) { return nullptr; }
    lg->m_flush_log_idx_from = m_last_flush_idx + 1;
    lg->m_flush_log_idx_upto = flushing_upto_idx;
    HS_DBG_ASSERT_GE(lg->m_flush_log_idx_upto, lg->m_flush_log_idx_from, "log indx upto is smaller then log indx from");

    HS_DBG_ASSERT_GT(lg->header()->oob_data_offset, 0);

    THIS_LOGDEV_LOG(DEBUG, "Flushing upto log_idx={}", flushing_upto_idx);
    THIS_LOGDEV_LOG(DEBUG, "Log Group: {}", *lg);
    return lg;
}

bool LogDev::can_flush_in_this_thread() {
    if (iomanager.am_i_io_reactor() && (iomanager.iothread_self() == logstore_service().flush_thread())) {
        return true;
    }
    return (!HS_DYNAMIC_CONFIG(logstore.flush_only_in_dedicated_thread) && iomanager.am_i_worker_reactor());
}

// This method checks if in case we were to add a record of size provided, do we enter into a state which exceeds
// our threshold. If so, it first flushes whats accumulated so far and then add the pending flush size counter with
// the new record size
bool LogDev::flush_if_needed(int64_t threshold_size) {
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
            iomanager.run_on(logstore_service().flush_thread(),
                             [this]([[maybe_unused]] const io_thread_addr_t addr) { flush_if_needed(); });
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

        off_t offset = m_vdev->alloc_next_append_blk(lg->header()->total_size());
        lg->m_log_dev_offset = offset;
        HS_REL_ASSERT_NE(lg->m_log_dev_offset, INVALID_OFFSET, "log dev is full");
        THIS_LOGDEV_LOG(TRACE, "Flush prepared, flushing data size={} at offset={}", lg->actual_data_size(), offset);
        do_flush(lg);
        return true;
    } else {
        return false;
    }
}

void LogDev::do_flush(LogGroup* lg) {
    // if (has_data_service() && data_service().is_fsync_needed()) {
    //     data_service().fsync([this, lg]() { do_flush_write(lg); })
    // } else {
    //     do_flush_write(lg);
    // }
    do_flush_write(lg);
}

void LogDev::do_flush_write(LogGroup* lg) {
#ifdef _PRERELEASE
    if (homestore_flip->delay_flip< int >(
            "simulate_log_flush_delay", [this, lg]() { do_flush_write(lg); }, m_family_id)) {
        THIS_LOGDEV_LOG(INFO, "Delaying flush by rescheduling the async write");
    }
#endif

    HISTOGRAM_OBSERVE(logstore_service().m_metrics, logdev_flush_records_distribution, lg->nrecords());
    HISTOGRAM_OBSERVE(logstore_service().m_metrics, logdev_flush_size_distribution, lg->actual_data_size());
    THIS_LOGDEV_LOG(TRACE, "vdev offset={} log group total size={}", lg->m_log_dev_offset, lg->header()->total_size());

    // write log
    m_vdev->async_pwritev(lg->iovecs().data(), int_cast(lg->iovecs().size()), lg->m_log_dev_offset,
                          [this, lg](std::error_condition err) {
                              if (err != no_error) {
                                  HS_DBG_ASSERT(false, "Error in writing the journal log - {}", err.message());
                                  throw std::runtime_error("Error in writing the journal log - " + err.message());
                              }
                              on_flush_completion(lg);
                          });
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
        m_append_comp_cb(record.store_id, logdev_key{idx, dev_offset}, flush_ld_key, upto_indx - idx, record.context);
    }
    lg->m_post_flush_process_done_time = Clock::now();

    HISTOGRAM_OBSERVE(logstore_service().m_metrics, logdev_flush_done_msg_time_ns,
                      get_elapsed_time_us(lg->m_flush_finish_time, lg->m_post_flush_msg_rcvd_time));
    HISTOGRAM_OBSERVE(logstore_service().m_metrics, logdev_post_flush_processing_latency,
                      get_elapsed_time_us(lg->m_post_flush_msg_rcvd_time, lg->m_post_flush_process_done_time));
    free_log_group(lg);
    unlock_flush();
}

bool LogDev::try_lock_flush(const flush_blocked_callback& cb) {
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

    cb();
    return true;
}

void LogDev::unlock_flush(bool do_flush) {
    std::vector< flush_blocked_callback >* flush_q{nullptr};

    if (m_block_flush_q != nullptr) {
        std::unique_lock lk{m_block_flush_q_mutex};
        flush_q = m_block_flush_q;
        m_block_flush_q = nullptr;
    }

    if (flush_q) {
        for (auto& cb : *flush_q) {
            if (m_stopped) {
                THIS_LOGDEV_LOG(INFO, "Logdev is stopped and thus not processing outstanding flush_lock_q");
                return;
            }
            cb();
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
    if (num_records_to_truncate > 0) {
        HS_PERIODIC_LOG(INFO, logstore, "Truncating log device upto log_id={} vdev_offset={} truncated {} log records",
                        key.idx, key.dev_offset, num_records_to_truncate);
        m_log_records->truncate(key.idx);
        m_vdev->truncate(key.dev_offset);
        m_last_truncate_idx = key.idx;

        {
            std::unique_lock< std::mutex > lk{m_meta_mutex};

            // Update the start offset to be read upon restart
            m_logdev_meta.set_start_dev_offset(key.dev_offset, key.idx + 1, false /* persist_now */);

            // Now that store is truncated, we can reclaim the store ids which are garbaged (if any) earlier
#ifdef _PRERELEASE
            bool garbage_collect = false;
#endif
            for (auto it{std::cbegin(m_garbage_store_ids)}; it != std::cend(m_garbage_store_ids);) {
                if (it->first > key.idx) break;

                HS_PERIODIC_LOG(INFO, logstore, "Garbage collecting the log store id {} log_idx={}", it->second,
                                it->first);
                m_logdev_meta.unreserve_store(it->second, false /* persist_now */);
                it = m_garbage_store_ids.erase(it);
#ifdef _PRERELEASE
                garbage_collect = true;
#endif
            }

            // We can remove the rollback records of those upto which logid is getting truncated
            m_logdev_meta.remove_rollback_record_upto(key.idx, false /* persist_now */);

            m_logdev_meta.persist();
#ifdef _PRERELEASE
            if (garbage_collect && homestore_flip->test_flip("logdev_abort_after_garbage")) {
                LOGINFO("logdev aborting after unreserving garbage ids");
                raise(SIGKILL);
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

void LogDev::get_status(const int verbosity, nlohmann::json& js) const {
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
}

/////////////////////////////// LogDevMetadata Section ///////////////////////////////////////
LogDevMetadata::LogDevMetadata(const std::string& logdev_name) :
        m_sb{logdev_name + "_logdev_sb"}, m_rollback_sb{logdev_name + "_rollback_sb"} {
    meta_service().register_handler(
        logdev_name + "_logdev_sb",
        [this](meta_blk* mblk, sisl::byte_view buf, size_t size) {
            logdev_super_blk_found(std::move(buf), voidptr_cast(mblk));
        },
        nullptr);

    meta_service().register_handler(
        logdev_name + "_rollback_sb",
        [this](meta_blk* mblk, sisl::byte_view buf, size_t size) {
            rollback_super_blk_found(std::move(buf), voidptr_cast(mblk));
        },
        nullptr);
}

logdev_superblk* LogDevMetadata::create() {
    logdev_superblk* sb = m_sb.create(logdev_sb_size_needed(0));
    rollback_superblk* rsb = m_rollback_sb.create(rollback_superblk::size_needed(1));

    auto* sb_area = m_sb->get_logstore_superblk();
    std::fill_n(sb_area, store_capacity(), logstore_superblk::default_value());

    m_id_reserver = std::make_unique< sisl::IDReserver >();
    m_sb.write();
    m_rollback_sb.write();
    return sb;
}

void LogDevMetadata::reset() {
    m_id_reserver.reset();
    m_store_info.clear();
}

void LogDevMetadata::logdev_super_blk_found(const sisl::byte_view& buf, void* meta_cookie) {
    m_sb.load(buf, meta_cookie);
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

        std::memcpy(voidptr_cast(m_sb.raw_buf()->bytes), static_cast< const void* >(old_buf->bytes),
                    std::min(old_buf->size, m_sb.size()));
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
        if (rec.idx_range.second <= upto_id) {
            m_rollback_sb->remove_ith_record(i - 1);
            ++n_removed;
        }
    }

    if (n_removed) {
        for (auto it = m_rollback_info.begin(); it != m_rollback_info.end();) {
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
        std::memcpy(voidptr_cast(m_rollback_sb.raw_buf()->bytes), static_cast< const void* >(old_buf->bytes),
                    std::min(old_buf->size, m_rollback_sb.size()));
        return true;
    } else {
        return false;
    }
}
} // namespace homestore
