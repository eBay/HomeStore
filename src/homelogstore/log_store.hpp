#pragma once
#include <cstdint>
#include "log_dev.hpp"
#include <fds/utils.hpp>
#include <folly/Synchronized.h>

namespace homestore {

struct logstore_record {
    logdev_key m_dev_key;

    logstore_record() = default;
    logstore_record(const logdev_key& key) : m_dev_key(key) {}
};

class logstore_req;
class HomeLogStore;
using log_req_comp_cb_t = std::function< void(logstore_req*, logdev_key) >;
using log_write_comp_cb_t = std::function< void(logstore_seq_num_t, sisl::io_blob&, logdev_key, void*) >;
using log_found_cb_t = std::function< void(logstore_seq_num_t, log_buffer, void*) >;
using log_store_opened_cb_t = std::function< void(std::shared_ptr< HomeLogStore >) >;
using log_replay_done_cb_t = std::function< void(std::shared_ptr< HomeLogStore >) >;

struct logstore_req {
    HomeLogStore* log_store;    // Backpointer to the log store
    logstore_seq_num_t seq_num; // Log store specific seq_num (which could be monotonically increaseing with logstore)
    sisl::io_blob data;         // Data blob containing data
    void* cookie;               // User generated cookie (considered as opaque)
    bool is_write;              // Directon of IO
    bool is_internal_req;       // If the req is created internally by HomeLogStore itself
    log_req_comp_cb_t cb;       // Callback upon completion of write (overridden than default)

    static logstore_req* make(HomeLogStore* store, logstore_seq_num_t seq_num, const sisl::io_blob& data,
                              bool is_write_req = true) {
        logstore_req* req = sisl::ObjectAllocator< logstore_req >::make_object();
        req->log_store = store;
        req->seq_num = seq_num;
        req->data = data;
        req->is_write = is_write_req;
        req->is_internal_req = true;
        req->cb = nullptr;

        return req;
    }

    static void free(logstore_req* req) {
        if (req->is_internal_req) { sisl::ObjectAllocator< logstore_req >::deallocate(req); }
    }
};

struct truncation_entry_t {
    logstore_seq_num_t seq_num;
    logdev_key ld_key;
};

struct logstore_info_t {
    std::shared_ptr< HomeLogStore > m_log_store;
    log_store_opened_cb_t m_on_log_store_opened;
};

class HomeLogStore;
class HomeLogStoreMgr {
    friend class HomeLogStore;

public:
    static HomeLogStoreMgr& instance() {
        static HomeLogStoreMgr inst;
        return inst;
    }

    static LogDev& logdev() { return HomeLogStoreMgr::instance().m_log_dev; }
    static void meta_blk_found_cb(meta_blk* mblk, sisl::byte_view buf, size_t size);

    /**
     * @brief Start the entire HomeLogStore set and does recover the existing logstores. Really this is the first
     * method to be executed on log store.
     *
     * @param format If set to true, will not recover, but create a fresh log store set.
     */
    void start(bool format);

    /**
     * @brief Stop the HomeLogStore. It resets all parameters and can be restarted with start method.
     *
     */
    void stop();

    /**
     * @brief Create a brand new log store (both in-memory and on device) and returns its instance. It also book keeps
     * the created log store and user can get this instance of log store by using logstore_d
     *
     * @return std::shared_ptr< HomeLogStore >
     */
    std::shared_ptr< HomeLogStore > create_new_log_store();

    /**
     * @brief Open an existing log store and does a recovery. It then creates an instance of this logstore and returns
     *
     * @param store_id: Store ID of the log store to open
     * @return std::shared_ptr< HomeLogStore >
     */
    void open_log_store(logstore_id_t store_id, const log_store_opened_cb_t& on_open_cb);
    // std::shared_ptr< HomeLogStore > open_log_store(logstore_id_t store_id);

    /**
     * @brief Remove an existing log store. It removes in-memory and schedule to reuse the store id after device
     * truncation.
     *
     * @param store_id
     */
    void remove_log_store(logstore_id_t store_id);

    /**
     * @brief Truncate all the log stores physically on the device.
     *
     * @param dry_run: If the truncate is a real one or just dry run to simulate the truncation
     * @return logdev_key: Log dev key upto which the device is truncated.
     */
    logdev_key device_truncate(bool dry_run = false);

    /**
     * @brief Register a callback upon opening a new log store during recovery. As soon as HomeLogStoreMgr::start is
     * called without format, the recovery will start and will create log stores automatically. Without calling this
     * method before calling start, consumer will not be able to get callback on data.
     *
     * @param cb
     */
    void register_log_store_opened_cb(const log_store_opened_cb_t& cb) { m_log_store_opened_cb = cb; }

private:
    void __on_log_store_found(logstore_id_t store_id);
    void __on_io_completion(logstore_id_t id, logdev_key ld_key, logdev_key flush_idx, uint32_t nremaining_in_batch,
                            void* ctx);
    void __on_logfound(logstore_id_t id, logstore_seq_num_t seq_num, logdev_key ld_key, log_buffer buf);

    void truncate_after_flush_lock(logstore_id_t store_id, logstore_id_t upto_seq_num);

private:
    folly::Synchronized< std::map< logstore_id_t, logstore_info_t > > m_id_logstore_map;
    std::set< logstore_id_t > m_unopened_store_id;
    log_store_opened_cb_t m_log_store_opened_cb;
    LogDev m_log_dev;
};

#define home_log_store_mgr HomeLogStoreMgr::instance()

class HomeLogStore : public std::enable_shared_from_this< HomeLogStore > {
public:
    friend class HomeLogStoreMgr;

    HomeLogStore(uint32_t store_id);

    /**
     * @brief Register default request completion callback. In case every write does not carry a callback, this callback
     * will be used to report completions.
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
    bool write_sync(logstore_seq_num_t seq_num, const sisl::io_blob& b);

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
     * @brief This method appends the blob into the log and it returns the generated seq number
     *
     * @param b Blob of data to append
     * @return logstore_seq_num_t Returns the seqnum generated by the log
     */
    logstore_seq_num_t append_sync(const sisl::io_blob& b);

    /**
     * @brief This method appends the blob into the log and makes a callback at the end of the append.
     *
     * @param b Blob of data to append
     * @param cookie Passed as is to the completion callback
     * @param completion_cb Completion callback which contains the seqnum, status and cookie
     * @return internally generated sequence number
     */
    logstore_seq_num_t append_async(const sisl::io_blob& b, void* cookie, const log_write_comp_cb_t& completion_cb);

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
     * @brief Read the log based on the logstore_req prepared. In case callback is supplied, it uses the callback
     * to provide the data it has read. If not overridden, use default callback registered during initialization.
     *
     * @param req Request containing seq_num
     * @param cb [OPTIONAL] Callback to get the data back, if it needs to be different from the default registered one.
     */
    void read_async(logstore_req* req, const log_found_cb_t& cb = nullptr);

    /**
     * @brief Read the log for the seq_num and make the callback with the data
     *
     * @param seq_num Seqnumber to read the log from
     * @param cookie Any cookie or context which will passed back in the callback
     * @param cb Callback which contains seq_num, cookie and
     */
    void read_async(logstore_seq_num_t seq_num, void* cookie, const log_found_cb_t& cb);

    /**
     * @brief Truncate the logs for this log store upto the seq_num provided (inclusive). Once truncated, the reads
     * on seq_num <= upto_seq_num will return an error. The truncation in general is a 2 step process, where first
     * in-memory structure of the logs are truncated and then logdevice actual space is truncated.
     *
     * @param upto_seq_num: Seq num upto which logs are to be truncated
     * @param in_memory_truncate_only If set to false, it will force to truncate the device right away. Its better to
     * set this to true on cases where there are multiple log stores, so that once all in-memory truncation is
     * completed, a device truncation can be triggered for all the logstores. The device truncation is more expensive
     * and grouping them together yields better results.
     */
    void truncate(logstore_seq_num_t upto_seq_num, bool in_memory_truncate_only = true);

    /**
     * @brief Get the safe truncation log dev key from this log store perspective. Please note that the safe idx is not
     * globally safe, but it is safe from this log store perspective only. To get global safe id, one should access all
     * log stores and get the minimum of them before truncating.
     *
     * @return logdev_key
     */
    logdev_key get_safe_truncation_log_dev_key() const {
        auto ld_key = *(m_safe_truncate_ld_key.rlock());
        return ld_key;
    }

    /**
     * @brief Get the last truncated seqnum upto which we have truncated. If called after recovery, it returns the
     * first seq_num it has seen-1.
     *
     * @return logstore_seq_num_t
     */
    logstore_seq_num_t truncated_upto() const {
        auto ts = m_last_truncated_seq_num.load(std::memory_order_acquire);
        return (ts == std::numeric_limits< logstore_seq_num_t >::max()) ? -1 : ts;
    }

    /**
     * @brief iterator to get all the log buffers;
     *
     * @param start_idx  idx to start with;
     * @param cb called with current idx and log buffer.
     * Return value of the cb: true means proceed, false means stop;
     */
    void foreach (int64_t start_idx, const auto& cb);

    /**
     * @brief Get the store id of this HomeLogStore
     *
     * @return logstore_id_t
     */
    logstore_id_t get_store_id() const { return m_store_id; }

    /**
     * @brief Get the next contigous seq num which are already issued from the given start seq number.
     *
     * @param from The seqnum from which contiguous search begins (exclusive). In other words, if from is say 5, it
     * looks for contigous seq number from 6 and ignores 5.
     * @return logstore_seq_num_t Returns upto the seqnum upto which contigous number is issued (inclusive). If it is
     * same as input `from`, then there are no more new contigous issued.
     */
    logstore_seq_num_t get_contiguous_issued_seq_num(logstore_seq_num_t from);

    /**
     * @brief Get the next contigous seq num which are already completed from the given start seq number.
     *
     * @param from The seqnum from which contiguous search begins (exclusive). In other words, if from is say 5, it
     * looks for contigous seq number from 6 and ignores 5.
     * @return logstore_seq_num_t Returns upto the seqnum upto which contigous number is completed (inclusive). If it is
     * same as input `from`, then there are no more new contigous completed.
     */
    logstore_seq_num_t get_contiguous_completed_seq_num(logstore_seq_num_t from);

    static bool is_aligned_buf_needed(size_t size) { return (log_record::is_size_inlineable(size) == false); }

private:
    void on_write_completion(logstore_req* req, logdev_key ld_key, logdev_key flush_idx, uint32_t nremaining_in_batch);
    void on_read_completion(logstore_req* req, logdev_key ld_key);
    void on_log_found(logstore_seq_num_t seq_num, logdev_key ld_key, log_buffer buf);
    void do_truncate(logstore_seq_num_t upto_seq_num);
    void create_truncation_barrier(void);
    int search_max_le(logstore_seq_num_t input_sn);

private:
    logstore_id_t m_store_id;
    sisl::StreamTracker< logstore_record > m_records;
    log_req_comp_cb_t m_comp_cb;
    log_found_cb_t m_found_cb;
    log_replay_done_cb_t m_replay_done_cb;
    std::atomic< logstore_seq_num_t > m_seq_num = 0;

    logdev_key m_last_flush_ldkey = {0, 0};              // The log id of the last flushed batch.
    truncation_entry_t m_flush_batch_max = {-1, {0, 0}}; // The maximum seqnum we have seen in the prev flushed batch

    // Logdev key determined to be safe to truncate from this log store perspective.
    folly::Synchronized< logdev_key > m_safe_truncate_ld_key;

    // std::atomic< logid_t > m_safe_truncate_log_idx =
    //    std::numeric_limits< logid_t >::max(); // Logid determined to be safe to truncate from this log store
    std::vector< truncation_entry_t > m_truncation_barriers; // List of truncation barriers

    std::atomic< logstore_seq_num_t > m_last_truncated_seq_num = std::numeric_limits< logstore_seq_num_t >::max();
};

} // namespace homestore
