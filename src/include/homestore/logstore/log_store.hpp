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
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <set>
#include <unordered_map>
#include <vector>
#include <tuple>

#include <sisl/fds/buffer.hpp>
#include <sisl/fds/stream_tracker.hpp>
#include <folly/Synchronized.h>
#include <nlohmann/json.hpp>

#include <homestore/logstore/log_store_internal.hpp>

namespace homestore {

class LogDev;
class LogStoreServiceMetrics;

static constexpr logstore_seq_num_t invalid_lsn() { return std::numeric_limits< logstore_seq_num_t >::min(); }
typedef std::function< void(logstore_seq_num_t) > on_rollback_cb_t;

class HomeLogStore : public std::enable_shared_from_this< HomeLogStore > {
public:
    HomeLogStore(std::shared_ptr< LogDev > logdev, logstore_id_t id, bool append_mode, logstore_seq_num_t start_lsn);
    HomeLogStore(const HomeLogStore&) = delete;
    HomeLogStore(HomeLogStore&&) noexcept = delete;
    HomeLogStore& operator=(const HomeLogStore&) = delete;
    HomeLogStore& operator=(HomeLogStore&&) noexcept = delete;
    ~HomeLogStore() = default;

    /**
     * @brief Register default request completion callback. In case every write does not carry a callback, this
     * callback will be used to report completions.
     * @param cb
     */
    void register_req_comp_cb(const log_req_comp_cb_t& cb) { m_comp_cb = cb; }

    /**
     * @brief Register callback upon a new log entry is found during recovery. Failing to register for log_found
     * callback is ok as long as log entries are not required to replayed during recovery.
     *
     * @param cb
     */
    void register_log_found_cb(const log_found_cb_t& cb) { m_found_cb = cb; }

    /**
     * @brief Register callback to indicate the replay is done during recovery. Failing to register for log_replay
     * callback is ok as long as user of the log store knows when all logs are replayed.
     *
     * @param cb
     */
    void register_log_replay_done_cb(const log_replay_done_cb_t& cb) { m_replay_done_cb = cb; }

    /**
     * @brief Register callback to indicate the replay is done during recovery. Failing to register for log_replay
     * callback is ok as long as user of the log store knows when all logs are replayed.
     *
     * @param cb
     */
    log_replay_done_cb_t get_log_replay_done_cb() const { return m_replay_done_cb; }

    /**
     * @brief Write the blob at the user specified seq number - prepared as a request in async fashion.
     *
     * @param req The fully formed request which has the seqnum and data blob already prepared.
     * @param cb [OPTIONAL] Callback if caller wants specific callback as against common/default callback registed.
     * The callback returns the request back with status of execution
     */
    void write_async(logstore_req* req, const log_req_comp_cb_t& cb = nullptr);

    /**
     * @brief Write the blob at the user specified seq number
     *
     * @param seq_num: Seq number to write to
     * @param b : Blob of data
     * @param cookie : Any cookie or context which will passed back in the callback
     * @param cb Callback upon completion which is called with the status, seq_num and cookie that was passed.
     */
    void write_async(logstore_seq_num_t seq_num, const sisl::io_blob& b, void* cookie, const log_write_comp_cb_t& cb);

    /**
     * @brief This method appends the blob into the log and makes a callback at the end of the append.
     *
     * @param b Blob of data to append
     * @param cookie Passed as is to the completion callback
     * @param completion_cb Completion callback which contains the seqnum, status and cookie
     *
     * Note that: completion_cb will be executed in background fibers, so different completion_cbs probabaly be executed
     * concurrently. also, logstore does not guarantee the order of completion_cb execution. that means, the caller
     * should:
     *
     * 1 add lock in the completion_cb if the caller wants to make sure the safety of concurrent execution.
     * 2 keep in mind that the completion_cb probabaly be executed in different order than the append order.
     *
     * @return internally generated sequence number
     */
    logstore_seq_num_t append_async(const sisl::io_blob& b, void* cookie, const log_write_comp_cb_t& completion_cb);

    /**
     * @brief Write the blob at the user specified seq number and flush, just like write_sync
     *
     * @param seq_num: Seq number to write to
     * @param b : Blob of data
     */
    void write_and_flush(logstore_seq_num_t seq_num, const sisl::io_blob& b);

    /**
     * @brief Read the log provided the sequence number synchronously. This is not the most efficient way to read
     * as reader will be blocked until read is completed. In addition, it is built on-top of async system by doing
     * a single mutex/cv pair (which adds some cost)
     *
     * Throws: std::out_of_range exception if seq_num is already truncated or never inserted before
     *
     * @param seq_num
     * @return log_buffer Returned log_buffer (which is a safe smart ptr) that contains the data blob.
     */
    log_buffer read_sync(logstore_seq_num_t seq_num);

    /**
     * @brief Truncate the logs for this log store upto the seq_num provided (inclusive). Once truncated, the reads
     * on seq_num <= upto_seq_num will return an error. The truncation in general is a 2 step process, where first
     * in-memory structure of the logs are truncated and then logdevice actual space is truncated.
     *
     * @param upto_seq_num: Seq num upto which logs are to be truncated
     * @param in_memory_truncate_only If set to false, it will force to truncate the device right away. Its better
     * to set this to true on cases where there are multiple log stores, so that once all in-memory truncation is
     * completed, a device truncation can be triggered for all the logstores. The device truncation is more
     * expensive and grouping them together yields better results.
     *
     * Note: this flag currently is not used, meaning all truncate is in memory only;
     */
    void truncate(logstore_seq_num_t upto_seq_num, bool in_memory_truncate_only = true);

    /**
     * @brief Fill the gap in the seq_num with a dummy value. This ensures that get_contiguous_issued and completed
     * seq_num methods move forward. The filled data is not readable and any attempt to read this seq_num will
     * result in out_of_range exception.
     *
     * @param seq_num: Seq_num to fill to.
     */
    void fill_gap(logstore_seq_num_t seq_num);

    /**
     * @brief Get the last truncated seqnum upto which we have truncated. If called after recovery, it returns the
     * first seq_num it has seen-1.
     *
     * @return the last truncated seqnum upto which we have truncated
     */
    logstore_seq_num_t truncated_upto() const { return m_start_lsn.load(std::memory_order_acquire) - 1; }

    logdev_key get_trunc_ld_key() const { return m_trunc_ld_key; }

    /**
     * @brief Get the truncation information for this log store. It is called during log device truncation
     *
     * @return tuple of (start_lsn, trunc_ld_key, tail_lsn) If the log store is empty, it will return
     * an out_of_bound_ld_key as trunc_ld_key.
     *
     * @note ensure that no new logs are flushed between calling this function and completing the truncation,
     * as this could result in an inaccurate out_of_bound_ld_key.
     * */
    std::tuple< logstore_seq_num_t, logdev_key, logstore_seq_num_t > truncate_info() const;

    sisl::StreamTracker< logstore_record >& log_records() { return m_records; }

    /**
     * @brief iterator to get all the log buffers;
     *
     * @param start_idx  idx to start with;
     * @param cb called with current idx and log buffer.
     * Return value of the cb: true means proceed, false means stop;
     */
    void foreach (int64_t start_idx, const std::function< bool(logstore_seq_num_t, log_buffer) >& cb);

    /**
     * @brief Get the store id of this HomeLogStore
     *
     * @return logstore_id_t
     */
    logstore_id_t get_store_id() const { return m_store_id; }

    /**
     * @brief Get the next contiguous seq num which are already issued from the given start seq number.
     *
     * @param from The seqnum from which contiguous search begins (exclusive). In other words, if from is say 5, it
     * looks for contiguous seq number from 6 and ignores 5.
     * @return logstore_seq_num_t Returns upto the seqnum upto which contiguous number is issued (inclusive). If it
     * is same as input `from`, then there are no more new contiguous issued.
     */
    logstore_seq_num_t get_contiguous_issued_seq_num(logstore_seq_num_t from) const;

    /**
     * @brief Get the next contiguous seq num which are already completed from the given start seq number.
     *
     * @param from The seqnum from which contiguous search begins (exclusive). In other words, if from is say 5, it
     * looks for contiguous seq number from 6 and ignores 5.
     * @return logstore_seq_num_t Returns upto the seqnum upto which contiguous number is completed (inclusive). If
     * it is same as input `from`, then there are no more new contiguous completed.
     */
    logstore_seq_num_t get_contiguous_completed_seq_num(logstore_seq_num_t from) const;

    /**
     * @brief Flush this log store (write/sync to disk) up to the sequence number
     *
     * @param seq_num Sequence number upto which logs are to be flushed. If not provided, will wait to flush all seq
     * numbers issued prior.
     */
    void flush(logstore_seq_num_t upto_seq_num = invalid_lsn());

    /**
     * @brief Rollback the given instance to the given sequence number
     *
     * @param to_lsn Sequence number back which logs are to be rollbacked
     * the to_lsn will be the tail_lsn after rollback.
     * @return True on success
     */
    bool rollback(logstore_seq_num_t to_lsn);

    auto start_lsn() const { return m_start_lsn.load(std::memory_order_acquire); }
    auto tail_lsn() const { return m_tail_lsn.load(std::memory_order_acquire); }
    auto next_lsn() const { return m_next_lsn.load(std::memory_order_acquire); }

    nlohmann::json dump_log_store(const log_dump_req& dump_req = log_dump_req());

    nlohmann::json get_status(int verbosity) const;

    /**
     * Handles the completion of a write operation in the log store.
     *
     * @param req The logstore_req object representing the completed write operation.
     * @param ld_key The logdev_key associated with the completed write operation.
     * @param flush_ld_key when we truncate to req, which position we should truncate in the logdev.
     */
    void on_write_completion(logstore_req* req, const logdev_key& ld_key, const logdev_key& flush_ld_key);

    /**
     * @brief Handles the event when a log is found.
     *
     * This function is called when a log is found in the log store. It takes the sequence number of the log,
     * the log device key, the flush log device key, and the log buffer as parameters.
     *
     * During LogDev::do_load during recovery boot, whenever a log is found, the associated logstore's on_log_found
     * method is called.
     *
     * @param seq_num The sequence number of the log.
     * @param ld_key The log device key.
     * @param flush_ld_key The flush log device key.
     * @param buf The log buffer.
     */
    void on_log_found(logstore_seq_num_t seq_num, const logdev_key& ld_key, const logdev_key& flush_ld_key,
                      log_buffer buf);

    std::shared_ptr< LogDev > get_logdev() { return m_logdev; }

    auto get_comp_cb() const { return m_comp_cb; }

private:
    logstore_id_t m_store_id;
    std::shared_ptr< LogDev > m_logdev;
    sisl::StreamTracker< logstore_record > m_records;
    bool m_append_mode{false};
    log_req_comp_cb_t m_comp_cb;
    log_found_cb_t m_found_cb;
    log_replay_done_cb_t m_replay_done_cb;
    // the first seq_num that is in the log store
    std::atomic< logstore_seq_num_t > m_start_lsn;
    // the next seq_num that will be put into the log store
    std::atomic< logstore_seq_num_t > m_next_lsn;
    // the last seq_num that is in the log store
    std::atomic< logstore_seq_num_t > m_tail_lsn;
    std::string m_fq_name;
    LogStoreServiceMetrics& m_metrics;

    logdev_key m_trunc_ld_key{0, 0};
};
} // namespace homestore
