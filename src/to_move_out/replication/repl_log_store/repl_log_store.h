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
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#if defined __clang__ or defined __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif
#include <libnuraft/nuraft.hxx>
#if defined __clang__ or defined __GNUC__
#pragma GCC diagnostic pop
#endif
#undef auto_lock

#if defined __clang__ or defined __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wattributes"
#endif
#include <homelogstore/log_store.hpp>
#if defined __clang__ or defined __GNUC__
#pragma GCC diagnostic pop
#endif

namespace homestore {
class ReplLogStore : public nuraft::log_store {
public:
    struct Options {
        Options()
                // : maxEntriesInLogFile(64*1024)
                // , maxLogFileSize(32*1024*1024)
                // , maxKeepingMemtables(8)
                :
                maxCacheSizeBytes((uint64_t)512 * 1024 * 1024),
                maxCachedLogs(10000),
                compression(false),
                strongDurability(false),
                flushThreadSleepTimeUs(500) {}
        // uint64_t maxEntriesInLogFile;
        // uint64_t maxLogFileSize;
        // uint64_t maxKeepingMemtables;
        uint64_t maxCacheSizeBytes;
        uint64_t maxCachedLogs;
        bool compression;

        /**
         * If `true`, all dirty Raft logs are flushed
         * for the end of each batch.
         */
        bool strongDurability;

        /**
         * If non-zero, we will enable a periodic
         * flush thread, whose sleep time will be this value
         * in micro-seconds.
         */
        uint32_t flushThreadSleepTimeUs;
    };

    static void removeLogStore(homestore::logstore_id_t logstore_id);

    explicit ReplLogStore(const homestore::logstore_id_t logstore_id = UINT32_MAX,
                          const Options& opt = ReplLogStore::Options());
    virtual ~ReplLogStore();

    /**
     * Must be called prior to using the logstore itself
     */
    std::error_condition get();
    __nocopy__(ReplLogStore);

    /**
     * The first available slot of the store, starts with 1.
     *
     * @return Last log index number + 1
     */
    virtual ulong next_slot() const override;

    /**
     * The start index of the log store, at the very beginning, it must be 1.
     * However, after some compact actions, this could be anything
     * greater or equals to one.
     *
     * @return Starting log index number.
     */
    virtual ulong start_index() const override;

    /**
     * The last log entry in store.
     *
     * @return If no log entry exists: a dummy constant entry with
     *         value set to null and term set to zero.
     */
    virtual ptr< nuraft::log_entry > last_entry() const override;

    /**
     * Append a log entry to store
     *
     * @param entry Log entry
     * @return Log index number.
     */
    virtual ulong append(ptr< nuraft::log_entry >& entry) override;

    /**
     * Overwrite a log entry at the given `index`.
     *
     * @param index Log index number to overwrite.
     * @param entry New log entry to overwrite.
     */
    virtual void write_at(ulong index, ptr< nuraft::log_entry >& entry) override;

    /**
     * Invoked after a batch of logs is written as a part of
     * a single append_entries request.
     *
     * @param start The start log index number (inclusive)
     * @param cnt The number of log entries written.
     */
    virtual void end_of_append_batch(ulong start, ulong cnt) override;

    /**
     * Get log entries with index [start, end).
     *
     * @param start The start log index number (inclusive).
     * @param end The end log index number (exclusive).
     * @return The log entries between [start, end).
     */
    virtual ptr< std::vector< ptr< nuraft::log_entry > > > log_entries(ulong start, ulong end) override;

    /**
     * Get the log entry at the specified log index number.
     *
     * @param index Should be equal to or greater than 1.
     * @return The log entry or null if index >= this->next_slot().
     */
    virtual ptr< nuraft::log_entry > entry_at(ulong index) override;

    /**
     * Get the term for the log entry at the specified index
     * Suggest to stop the system if the index >= this->next_slot()
     *
     * @param index Should be equal to or greater than 1.
     * @return The term for the specified log entry, or
     *         0 if index < this->start_index().
     */
    virtual ulong term_at(ulong index) override;

    /**
     * Pack cnt log items starts from index
     *
     * @param index The start log index number (inclusive).
     * @param cnt The number of logs to pack.
     * @return log pack
     */
    virtual ptr< buffer > pack(ulong index, int32 cnt) override;

    /**
     * Apply the log pack to current log store, starting from index.
     *
     * @param index The start log index number (inclusive).
     * @param pack
     */
    virtual void apply_pack(ulong index, buffer& pack);

    /**
     * Compact the log store by purging all log entries,
     * including the log at the last_log_index.
     *
     * If current max log idx is smaller than given `last_log_index`,
     * set start log idx to `last_log_index + 1`.
     *
     * @param last_log_index Log index number that will be purged up to (inclusive).
     * @return True on success.
     */
    virtual bool compact(ulong last_log_index) override;

    /**
     * Synchronously flush all log entries in this log store to the backing storage
     * so that all log entries are guaranteed to be durable upon process crash.
     *
     * @return `true` on success.
     */
    virtual bool flush() override;

    /**
     * Close the log store. It will make all dirty data durable on disk
     * before closing.
     */
    void close();

    /**
     * Rollback log store to given index number.
     *
     * @param to Log index number that will be the last log after rollback,
     *           that means the log corresponding to `to` will be preserved.
     * @return void.
     */
    void rollback(ulong to);

    /**
     * Free all resources used for Jungle.
     */
    static void shutdown();

    /**
     * Get log store id
     */
    homestore::logstore_id_t getLogstoreId() const;

private:
    struct log_cache;

    struct FlushElem;

    void write_at_internal(ulong index, ptr< log_entry >& entry);

    ssize_t getCompMaxSize(homestore::HomeLogStore* db, const homestore::log_buffer& rec);

    ssize_t compress(homestore::HomeLogStore* db, const homestore::log_buffer& src, homestore::log_buffer& dst);

    ssize_t decompress(homestore::HomeLogStore* db, const homestore::log_buffer& src, homestore::log_buffer& dst);

    void flushLoop();

    void on_log_found(homestore::logstore_seq_num_t lsn, homestore::log_buffer buf, void* ctx);

    /**
     * Directory path.
     */
    std::string logDir;

    /**
     * Dummy log entry for invalid request.
     */
    ptr< log_entry > dummyLogEntry;

    /**
     * Jungle is basically lock-free for both read & write,
     * but use write lock to be safe.
     */
    std::recursive_mutex writeLock;

    /**
     * DB instance.
     */
    std::shared_ptr< HomeLogStore > m_log_store;
    homestore::logstore_id_t m_logstore_id{-1};

    /**
     * List of awaiting flush requests.
     */
    std::list< std::shared_ptr< FlushElem > > flushReqs;

    /**
     * Mutex for `flushReqs`.
     */
    std::mutex flushReqsLock;

    /**
     * Initialization sync
     */
    std::mutex m_wait_lock;
    std::condition_variable m_wait_cv;
    bool m_done{false};

    /**
     * The index number of the last durable Raft log.
     */
    std::atomic< uint64_t > lastDurableLogIdx;

    /**
     * Local copy of options.
     */
    Options m_opt;
};

} // namespace homestore
