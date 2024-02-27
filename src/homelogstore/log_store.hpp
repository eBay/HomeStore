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

#include <sisl/fds/buffer.hpp>
#include <folly/Synchronized.h>
#include <nlohmann/json.hpp>

#include "logstore_header.hpp"
#include "log_store_family.hpp"
#include <sisl/sobject/sobject.hpp>

namespace homestore {

struct log_dump_req {
    log_dump_req(log_dump_verbosity level = log_dump_verbosity::HEADER,
                 std::shared_ptr< HomeLogStore > logstore = nullptr, logstore_seq_num_t s_seq = 0,
                 logstore_seq_num_t e_seq = std::numeric_limits< int64_t >::max()) :
            verbosity_level{level}, log_store{logstore}, start_seq_num{s_seq}, end_seq_num{e_seq} {}
    log_dump_verbosity verbosity_level;        // How much information we need of log file (entire content or header)
    std::shared_ptr< HomeLogStore > log_store; // if null all log stores are dumped
    logstore_seq_num_t start_seq_num;          // empty_key if from start of log file
    logstore_seq_num_t end_seq_num;            // empty_key if till last log entry
    logstore_seq_num_t batch_size = 0;         // Size of the output batch.
};

struct logstore_record {
    logdev_key m_dev_key;

    logstore_record() = default;
    logstore_record(const logdev_key& key) : m_dev_key{key} {}
};

struct logstore_req {
    HomeLogStore* log_store; // Backpointer to the log store. We are not storing shared_ptr as user should not destroy
                             // it until all ios are not completed.
    logstore_seq_num_t seq_num; // Log store specific seq_num (which could be monotonically increaseing with logstore)
    sisl::io_blob data;         // Data blob containing data
    void* cookie;               // User generated cookie (considered as opaque)
    bool is_write;              // Directon of IO
    bool is_internal_req;       // If the req is created internally by HomeLogStore itself
    log_req_comp_cb_t cb;       // Callback upon completion of write (overridden than default)
    Clock::time_point start_time;

    logstore_req(const logstore_req&) = delete;
    logstore_req& operator=(const logstore_req&) = delete;
    logstore_req(logstore_req&&) noexcept = delete;
    logstore_req& operator=(logstore_req&&) noexcept = delete;
    ~logstore_req() = default;

    // Get the size of the read or written record
    [[nodiscard]] size_t size() const {
        // TODO: Implement this method
        return 0;
    }
    [[nodiscard]] static logstore_req* make(HomeLogStore* const store, const logstore_seq_num_t seq_num,
                                            const sisl::io_blob& data, const bool is_write_req = true) {
        logstore_req* const req{sisl::ObjectAllocator< logstore_req >::make_object()};
        req->log_store = store;
        req->seq_num = seq_num;
        req->data = data;
        req->is_write = is_write_req;
        req->is_internal_req = true;
        req->cb = nullptr;

        return req;
    }

    static void free(logstore_req* const req) {
        if (req->is_internal_req) { sisl::ObjectAllocator< logstore_req >::deallocate(req); }
    }

    friend class sisl::ObjectAllocator< logstore_req >;

private:
    logstore_req() = default;
};

struct seq_ld_key_pair {
    logstore_seq_num_t seq_num{-1};
    logdev_key ld_key;
};

struct truncation_info {
    // Safe log dev location upto which it is truncatable
    logdev_key ld_key{std::numeric_limits< logid_t >::min(), 0};

    // LSN of this log store upto which it is truncated
    std::atomic< logstore_seq_num_t > seq_num{-1};

    // Is there any entry which is already store truncated but waiting for device truncation
    bool pending_dev_truncation{false};

    // Any truncation entries/barriers which are not part of this truncation
    bool active_writes_not_part_of_truncation{false};
};

class HomeLogStoreMgrMetrics : public sisl::MetricsGroup {
public:
    HomeLogStoreMgrMetrics();
    HomeLogStoreMgrMetrics(const HomeLogStoreMgrMetrics&) = delete;
    HomeLogStoreMgrMetrics(HomeLogStoreMgrMetrics&&) noexcept = delete;
    HomeLogStoreMgrMetrics& operator=(const HomeLogStoreMgrMetrics&) = delete;
    HomeLogStoreMgrMetrics& operator=(HomeLogStoreMgrMetrics&&) noexcept = delete;
};

class HomeLogStore;

class HomeLogStoreMgr {
    friend class HomeLogStore;
    friend class LogStoreFamily;
    friend class LogDev;

    HomeLogStoreMgr();

public:
    static constexpr logstore_family_id_t DATA_LOG_FAMILY_IDX{0};
    static constexpr logstore_family_id_t CTRL_LOG_FAMILY_IDX{1};
    static constexpr size_t num_log_families = CTRL_LOG_FAMILY_IDX + 1;
    typedef std::function< void(const std::array< logdev_key, num_log_families >&) > device_truncate_cb_t;

    HomeLogStoreMgr(const HomeLogStoreMgr&) = delete;
    HomeLogStoreMgr(HomeLogStoreMgr&&) noexcept = delete;
    HomeLogStoreMgr& operator=(const HomeLogStoreMgr&) = delete;
    HomeLogStoreMgr& operator=(HomeLogStoreMgr&&) noexcept = delete;

    [[nodiscard]] static HomeLogStoreMgr& instance();
    static void data_meta_blk_found_cb(meta_blk* const mblk, const sisl::byte_view buf, const size_t size);
    static void ctrl_meta_blk_found_cb(meta_blk* const mblk, const sisl::byte_view buf, const size_t size);
    static void fake_reboot();

    /**
     * @brief Start the entire HomeLogStore set and does recover the existing logstores. Really this is the first
     * method to be executed on log store.
     *
     * @param format If set to true, will not recover, but create a fresh log store set.
     */
    void start(const bool format);

    /**
     * @brief Stop the HomeLogStore. It resets all parameters and can be restarted with start method.
     *
     */
    void stop();

    /**
     * @brief Create a brand new log store (both in-memory and on device) and returns its instance. It also book
     * keeps the created log store and user can get this instance of log store by using logstore_d
     *
     * @param family_id: Logstores can be created on different log_devs. As of now we only support data log_dev and
     * ctrl log dev. The idx indicates which log device it is from. Its a mandatory parameter
     * @param append_mode: If the log store have to be in append mode, in that case, user can call append_async
     * and do not need to maintain the log_idx. Else user is expected to keep track of the log idx. Default to false
     *
     * @return std::shared_ptr< HomeLogStore >
     */
    [[nodiscard]] std::shared_ptr< HomeLogStore > create_new_log_store(const logstore_family_id_t family_id,
                                                                       const bool append_mode = false);

    /**
     * @brief Open an existing log store and does a recovery. It then creates an instance of this logstore and
     * returns
     *
     * @param store_id: Store ID of the log store to open
     * @return std::shared_ptr< HomeLogStore >
     */
    void open_log_store(const logstore_family_id_t family_id, const logstore_id_t store_id, const bool append_mode,
                        const log_store_opened_cb_t& on_open_cb);

    /**
     * @brief Close the log store instance and free-up the resources
     *
     * @param store_id: Store ID of the log store to close
     * @return true on success
     */
    [[nodiscard]] bool close_log_store(const logstore_family_id_t family_id, const logstore_id_t store_id) {
        // TODO: Implement this method
        return true;
    }

    /**
     * @brief Remove an existing log store. It removes in-memory and schedule to reuse the store id after device
     * truncation.
     *
     * @param store_id
     */
    void remove_log_store(const logstore_family_id_t family_id, const logstore_id_t store_id);

    /**
     * @brief Schedule a truncate all the log stores physically on the device.
     *
     * @param cb [OPTIONAL] Callback once truncation is completed, if provided (Default no callback)
     * @param wait_till_done [OPTIONAL] Wait for the truncation to complete before returning from this method.
     * Default to false
     * @param dry_run: If the truncate is a real one or just dry run to simulate the truncation
     */
    void device_truncate(const device_truncate_cb_t& cb = nullptr, const bool wait_till_done = false,
                         const bool dry_run = false);
    void send_flush_msg();

    [[nodiscard]] nlohmann::json dump_log_store(const log_dump_req& dum_req);
    [[nodiscard]] sisl::status_response get_status(const sisl::status_request& request) const;

    LogStoreFamily* data_log_family() { return m_logstore_families[DATA_LOG_FAMILY_IDX].get(); }
    LogStoreFamily* ctrl_log_family() { return m_logstore_families[CTRL_LOG_FAMILY_IDX].get(); }
    LogStoreFamily* get_family(std::string family_name);

    static LogDev& data_logdev() { return HomeLogStoreMgr::instance().data_log_family()->logdev(); }
    static LogDev& ctrl_logdev() { return HomeLogStoreMgr::instance().ctrl_log_family()->logdev(); }

private:
    void start_threads();
    void flush_if_needed();
    void stop_flush_thread();
    uint64_t num_try_flush_iteration();

private:
    boost::intrusive_ptr< HomeStoreBase > m_hb; // Back pointer to homestore
    std::mutex m_mtx;                           // mutex to protect m_logstore_families pointer
    std::array< std::unique_ptr< LogStoreFamily >, num_log_families > m_logstore_families;
    std::mutex m_cv_mtx;
    std::condition_variable m_flush_thread_cv; // cv to wait for flush thread to stop
    HomeLogStoreMgrMetrics m_metrics;
    iomgr::io_thread_t m_truncate_thread;
    iomgr::io_thread_t m_flush_thread;
    bool m_flush_thread_stopped = false;
    sisl::sobject_ptr m_sobject;
};

static HomeLogStoreMgr& HomeLogStoreMgrSI() { return HomeLogStoreMgr::instance(); }

struct truncate_req {
    std::mutex mtx;
    std::condition_variable cv;
    bool wait_till_done{false};
    bool dry_run{false};
    HomeLogStoreMgr::device_truncate_cb_t cb;
    std::array< logdev_key, HomeLogStoreMgr::num_log_families > m_trunc_upto_result;
    int trunc_outstanding{0};
};

class HomeLogStore : public std::enable_shared_from_this< HomeLogStore > {
public:
    friend class HomeLogStoreMgr;
    friend class LogStoreFamily;

    HomeLogStore(LogStoreFamily& family, const logstore_id_t id, const bool append_mode,
                 const logstore_seq_num_t start_lsn);
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
     * @brief Write the blob at the user specified seq number in sync manner. Under the covers it will call async
     * write and then wait for its completion. As such this is much lesser performing than async version since it
     * involves mutex/cv combination
     *
     * @param seq_num : Sequence number to insert data
     * @param b : Data blob to write to log
     *
     * @return is write completed successfully.
     */
    bool write_sync(const logstore_seq_num_t seq_num, const sisl::io_blob& b);

    /**
     * @brief Write the blob at the user specified seq number - prepared as a request in async fashion.
     *
     * @param req The fully formed request which has the seqnum and data blob already prepared.
     * @param cb [OPTIONAL] Callback if caller wants specific callback as against common/default callback registed.
     * The callback returns the request back with status of execution
     */
    void write_async(logstore_req* const req, const log_req_comp_cb_t& cb = nullptr);

    /**
     * @brief Write the blob at the user specified seq number
     *
     * @param seq_num: Seq number to write to
     * @param b : Blob of data
     * @param cookie : Any cookie or context which will passed back in the callback
     * @param cb Callback upon completion which is called with the status, seq_num and cookie that was passed.
     */
    void write_async(const logstore_seq_num_t seq_num, const sisl::io_blob& b, void* const cookie,
                     const log_write_comp_cb_t& cb);

    /**
     * @brief This method appends the blob into the log and it returns the generated seq number
     *
     * @param b Blob of data to append
     * @return logstore_seq_num_t Returns the seqnum generated by the log
     */
    // This method is not implemented yet
    logstore_seq_num_t append_sync(const sisl::io_blob& b);

    /**
     * @brief This method appends the blob into the log and makes a callback at the end of the append.
     *
     * @param b Blob of data to append
     * @param cookie Passed as is to the completion callback
     * @param completion_cb Completion callback which contains the seqnum, status and cookie
     * @return internally generated sequence number
     */
    logstore_seq_num_t append_async(const sisl::io_blob& b, void* const cookie,
                                    const log_write_comp_cb_t& completion_cb);

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
    [[nodiscard]] log_buffer read_sync(const logstore_seq_num_t seq_num);

    /**
     * @brief Read the log based on the logstore_req prepared. In case callback is supplied, it uses the callback
     * to provide the data it has read. If not overridden, use default callback registered during initialization.
     *
     * @param req Request containing seq_num
     * @param cb [OPTIONAL] Callback to get the data back, if it needs to be different from the default registered
     * one.
     */
    void read_async(logstore_req* const req, const log_found_cb_t& cb = nullptr);

    /**
     * @brief Read the log for the seq_num and make the callback with the data
     *
     * @param seq_num Seqnumber to read the log from
     * @param cookie Any cookie or context which will passed back in the callback
     * @param cb Callback which contains seq_num, cookie and
     */
    void read_async(const logstore_seq_num_t seq_num, void* const cookie, const log_found_cb_t& cb);

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
     * @return number of records to truncate
     */
    void truncate(const logstore_seq_num_t upto_seq_num, const bool in_memory_truncate_only = true);

    /**
     * @brief Truncate the logs for this log store upto the seq_num provided (inclusive) and persist the metablock
     * before returning. If the next available slot is less than upto_seq_num, it will fill the gaps.
     * This API makes sure the log idx is durable after the truncation.
     * See above truncate method for more details on parameters
     */
    void sync_truncate(const logstore_seq_num_t upto_seq_num, const bool in_memory_truncate_only = true);

    /**
     * @brief Fill the gap in the seq_num with a dummy value. This ensures that get_contiguous_issued and completed
     * seq_num methods move forward. The filled data is not readable and any attempt to read this seq_num will
     * result in out_of_range exception.
     *
     * @param seq_num: Seq_num to fill to.
     */
    void fill_gap(const logstore_seq_num_t seq_num);

    /**
     * @brief Get the safe truncation log dev key from this log store perspective. Please note that the safe idx is
     * not globally safe, but it is safe from this log store perspective only. To get global safe id, one should
     * access all log stores and get the minimum of them before truncating.
     *
     * It could return invalid logdev_key which indicates that this log store does not have any valid logdev key
     * to truncate. This could happen when there were no ios on this logstore since last truncation or at least no
     * ios are flushed yet. The caller should simply ignore this return value.
     *
     * @return truncation_entry_t: Which contains the logdev key and its corresponding seq_num to truncate and also
     * is that entry represents the entire log store.
     */
    // truncation_entry_t get_safe_truncation_boundary() const;

    /**
     * @brief Get the last truncated seqnum upto which we have truncated. If called after recovery, it returns the
     * first seq_num it has seen-1.
     *
     * @return logstore_seq_num_t
     */
    [[nodiscard]] logstore_seq_num_t truncated_upto() const {
        const auto ts{m_safe_truncation_boundary.seq_num.load(std::memory_order_acquire)};
        return (ts == std::numeric_limits< logstore_seq_num_t >::max()) ? -1 : ts;
    }

    /**
     * @brief iterator to get all the log buffers;
     *
     * @param start_idx  idx to start with;
     * @param cb called with current idx and log buffer.
     * Return value of the cb: true means proceed, false means stop;
     */
    void foreach (const int64_t start_idx, const std::function< bool(logstore_seq_num_t, log_buffer) >& cb);

    /**
     * @brief Get the store id of this HomeLogStore
     *
     * @return logstore_id_t
     */
    [[nodiscard]] logstore_id_t get_store_id() const { return m_store_id; }

    /**
     * @brief Get the next contiguous seq num which are already issued from the given start seq number.
     *
     * @param from The seqnum from which contiguous search begins (exclusive). In other words, if from is say 5, it
     * looks for contiguous seq number from 6 and ignores 5.
     * @return logstore_seq_num_t Returns upto the seqnum upto which contiguous number is issued (inclusive). If it
     * is same as input `from`, then there are no more new contiguous issued.
     */
    [[nodiscard]] logstore_seq_num_t get_contiguous_issued_seq_num(const logstore_seq_num_t from) const;

    /**
     * @brief Get the next contiguous seq num which are already completed from the given start seq number.
     *
     * @param from The seqnum from which contiguous search begins (exclusive). In other words, if from is say 5, it
     * looks for contiguous seq number from 6 and ignores 5.
     * @return logstore_seq_num_t Returns upto the seqnum upto which contiguous number is completed (inclusive). If
     * it is same as input `from`, then there are no more new contiguous completed.
     */
    [[nodiscard]] logstore_seq_num_t get_contiguous_completed_seq_num(const logstore_seq_num_t from) const;

    /**
     * @brief Flush this log store (write/sync to disk) up to the sequence number
     *
     * @param seq_num Sequence number upto which logs are to be flushed
     * @return True on success
     */
    bool flush_logs(const logstore_seq_num_t seq_num) {
        // TODO: Implement this method
        return true;
    }

    /**
     * @brief Sync the log store to disk
     *
     * @param
     * @return True on success
     */
    bool sync() {
        // TODO: Implement this method
        return true;
    }

    /**
     * @brief Rollback the given instance to the given sequence number
     *
     * @param seq_num Sequence number back which logs are to be rollbacked
     * @return True on success
     */
    bool rollback(const logstore_seq_num_t seq_num) {
        // TODO: Implement this method
        return true;
    }

    [[nodiscard]] LogStoreFamily& get_family() { return m_logstore_family; }

    [[nodiscard]] nlohmann::json dump_log_store(const log_dump_req& dump_req = log_dump_req());
    [[nodiscard]] sisl::status_response get_status(const sisl::status_request& request);
    sisl::sobject_ptr sobject() { return m_sobject; }

private:
    [[nodiscard]] const truncation_info& pre_device_truncation();
    void post_device_truncation(const logdev_key& trunc_upto_key);
    void on_write_completion(logstore_req* const req, const logdev_key ld_key);
    void on_read_completion(logstore_req* const req, const logdev_key ld_key);
    void on_log_found(const logstore_seq_num_t seq_num, const logdev_key ld_key, const logdev_key flush_ld_key,
                      const log_buffer buf);
    void on_batch_completion(const logdev_key& flush_batch_ld_key);
    void do_truncate(const logstore_seq_num_t upto_seq_num, const bool persist_now);
    [[nodiscard]] int search_max_le(const logstore_seq_num_t input_sn);

private:
    logstore_id_t m_store_id;
    LogStoreFamily& m_logstore_family;
    LogDev& m_logdev;
    sisl::StreamTracker< logstore_record > m_records;
    bool m_append_mode{false};
    log_req_comp_cb_t m_comp_cb;
    log_found_cb_t m_found_cb;
    log_replay_done_cb_t m_replay_done_cb;
    std::atomic< logstore_seq_num_t > m_seq_num;
    std::string m_fq_name;

    // seq_ld_key_pair m_flush_batch_max = {-1, {0, 0}}; // The maximum seqnum we have seen in the prev flushed
    // batch
    logstore_seq_num_t m_flush_batch_max_lsn{std::numeric_limits< logstore_seq_num_t >::min()};

    std::vector< seq_ld_key_pair > m_truncation_barriers; // List of truncation barriers
    truncation_info m_safe_truncation_boundary;
    sisl::sobject_ptr m_sobject;
};

#pragma pack(1)
struct logstore_superblk {
    logstore_superblk(const logstore_seq_num_t seq_num = 0) : m_first_seq_num{seq_num} {}
    logstore_superblk(const logstore_superblk&) = default;
    logstore_superblk(logstore_superblk&&) noexcept = default;
    logstore_superblk& operator=(const logstore_superblk&) = default;
    logstore_superblk& operator=(logstore_superblk&&) noexcept = default;
    ~logstore_superblk() = default;

    [[nodiscard]] static logstore_superblk default_value();
    static void init(logstore_superblk& m);
    static void clear(logstore_superblk& m);
    [[nodiscard]] static bool is_valid(const logstore_superblk& m);

    logstore_seq_num_t m_first_seq_num{0};
};
#pragma pack()
} // namespace homestore
