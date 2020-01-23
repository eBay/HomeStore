#pragma once

#include "log_config.hpp"
#include "iterator.hpp"
#include "keyvalue.hpp"
#include "record.hpp"
#include "status.hpp"

#include <functional>
#include <list>
#include <string>

namespace homestore {

class FlushOptions {
public:
    FlushOptions() : purgeOnly(false), syncOnly(false), callFsync(false), beyondLastSync(false), numFilesLimit(0) {}

    /**
     * Note : For home_logstore,
     * Assert(purgeOnly = true and syncOnly = true, callFsync = true, beyondLastSync = true, numFilesLimit = 0)
     * All options are provided to be compatible with Jungle logstore. But wont be implemented.
     * To be removed soon.
     */
    // If `true`, records will not be stored in back-end table,
    // but just will be purged from log.
    bool purgeOnly;

    // (Only in async flush)
    // If `true`, records will be written to log file only,
    // will not be flushed to table section.
    bool syncOnly;

    // (Only in async flush)
    // If `true`, call `fsync()` on log files before flushing
    // to table section.
    bool callFsync;

    // If `true`, flush all logs currently exist,
    // including logs not explicitly synced yet.
    // If `false`, flushing only happens upto the last synced log.
    bool beyondLastSync;

    // Limit the number of log files to be flushed at once.
    // Disabled if 0.
    uint32_t numFilesLimit;
};

/**
 * General terminology for Junle
 *  - records are initially written to skiplist in memory
 *  - when sync(false) is called , it syncs those to file system , pwrite
 *  - when sync(true) is called, it syncs those to file system(pwrite) and calls fsync as well
 *  - when flush/async flush is called, if log is backed by backend table, it flushes log records till provided lsn
 *      Some options it provides:
 *      - purgeOnly:true - means purge till lsn provided (logical purge, physical purge happens in async thread)
 *      - syncOnly:true - means pwrite till lsn provided
 *      - callFsync:true - means if sync is set to true, then it will call fsync also after pwrite
 *  - last synced seq num - seq num till which pwrite is done
 *  - last flushed seq num - seq num till which flush is done
 */
using UserHandler = std::function< void(Status, void*) >;

class LogStore {

public:
    /********* Newly defined API for homestore usecases */

    /*
     * Append the kv at end of log and emit out_seq_num
     * Jungle implementation of this is not thread safe, client should hold lock
     * Homestore implementation will make this thread safe, so no client lock is needed
     */
    Status append(uint64_t& out_seq_num, const KV& kv);

    /*
     * Init iterator with records from min_seq to max_seq
     */
    Status init_iterator_sn(Iterator& iterator, const uint64_t min_seq = -1, const uint64_t max_seq = -1);

    /********* Apis used by homestore raft */

    /**
     * Set kv at seq num
     */
    Status setSN(const uint64_t seq_num, const KV& kv);
    /**
     * Get Kv at seq num
     */
    Status getSN(const uint64_t seq_num, KV& kv_out);
    /*
     * Get lowest seq num present in log store
     *  min seqnum == last flushed seqnum + 1
     */
    Status getMinSeqNum(uint64_t& seq_num_out);
    /*
     * Get highest seq num present in log store
     */
    Status getMaxSeqNum(uint64_t& seq_num_out);
    /*
     * Rollback logstore to seqnum_upto. Any logs after this seqnum will be truncated.
     */
    Status rollback(uint64_t seqnum_upto);
    /*
     * fsync operation
     * Assert(call_fsync=true) for home logstore
     */
    Status sync(bool call_fsync = true);
    /*
     * Flush logs upto seq_num if provided
     */
    Status flushLogs(const FlushOptions& options, const uint64_t seq_num = -1);
    /*
     * Same def as flushLogs() except async
     */
    Status flushLogsAsync(const FlushOptions& options, UserHandler handler, void* ctx, const uint64_t seq_num = -1);

    static Status open(LogStore** ptr_out, const std::string& path, const LogConfig& db_config);
    static Status close(LogStore* db);
    static Status shutdown();

    /*********** Other Apis  - May not be neccesary to implement*/

    Status set(const KV& kv);
    Status setRecord(const Record& rec);
    Status setRecordByKey(const Record& rec);
    Status setRecordByKeyMulti(std::list< Record* >& batch, bool last_batch = false);
    Status get(const SizedBuf& key, SizedBuf& value_out);
    Status getRecord(const uint64_t seq_num, Record& rec_out);
    Status getRecordByKey(const SizedBuf& key, Record& rec_out, bool meta_only = false);
    Status del(const SizedBuf& key);
    Status delSN(const uint64_t seq_num, const SizedBuf& key);
    Status delRecord(const Record& rec);
    Status getLastFlushedSeqNum(uint64_t& seq_num_out);
    Status getLastSyncedSeqNum(uint64_t& seq_num_out);
    Status syncNoWait(bool call_fsync = true);
    void   setLogLevel(int new_level);
    int    getLogLevel() const;

private:
    LogStore(const std::string& journal_uuid, const LogConfig& log_config);
    ~LogStore();
    
    void* m_inst;
};
}