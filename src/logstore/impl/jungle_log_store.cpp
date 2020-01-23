#include "logstore/include/log_store.hpp"
#include <libjungle/jungle.h>
#include <cassert>

namespace homestore {

/**
 * Jungle Log store implementation
 * This acts as adapter layer between home logstore interface and jungle logstore implementation
 */
static void update_config(const LogConfig& log_config, jungle::DBConfig& db_config) {
    db_config.allowOverwriteSeqNum = log_config.allowOverwriteSeqNum;
    db_config.logSectionOnly = log_config.logSectionOnly;
    db_config.logFileTtl_sec = log_config.logFileTtl_sec;
    db_config.maxEntriesInLogFile = log_config.maxEntriesInLogFile;
    db_config.maxLogFileSize = log_config.maxLogFileSize;
    db_config.pureLsmMode = log_config.pureLsmMode;
}

LogStore::LogStore(const std::string& journal_uuid, const homestore::LogConfig& log_config) {
    jungle::Status   s;
    jungle::DBConfig db_cfg;
    update_config(log_config, db_cfg);
    jungle::DB** db_inst = (jungle::DB**)&m_inst;
    s = jungle::DB::open(db_inst, journal_uuid, db_cfg);
    assert(s.ok());
}

LogStore::~LogStore() {}

homestore::Status LogStore::setSN(const uint64_t seq_num, const homestore::KV& kv) {
    jungle::SizedBuf key(kv.key.size, kv.key.data);
    jungle::SizedBuf value(kv.value.size, kv.value.data);
    jungle::KV jkv(key, value);

    jungle::DB**   db_inst = (jungle::DB**)&m_inst;
    jungle::Status jstatus = (*db_inst)->setSN(seq_num, jkv);
    return homestore::Status(jstatus.getValue());
}

homestore::Status LogStore::getMaxSeqNum(uint64_t& seq_num_out) {
    jungle::DB**   db_inst = (jungle::DB**)&m_inst;
    jungle::Status jstatus = (*db_inst)->getMaxSeqNum(seq_num_out);
    return homestore::Status(jstatus.getValue());
}

homestore::Status LogStore::sync(bool call_fsync) {
    jungle::DB** db_inst = (jungle::DB**)&m_inst;

    jungle::Status jstatus = (*db_inst)->sync(call_fsync);
    return homestore::Status(jstatus.getValue());
}

homestore::Status LogStore::open(LogStore** ptr_out, const std::string& journal_uuid,
                                 const homestore::LogConfig& log_config) {
    LogStore* logstore = new LogStore(journal_uuid, log_config);
    *ptr_out = logstore;

    return homestore::Status::OK;
}

Status LogStore::append(uint64_t& out_seq_num, const KV& kv) {
    jungle::DB** db_inst = (jungle::DB**)&m_inst;
    jungle::Status s = (*db_inst)->getMaxSeqNum(out_seq_num);
    if (s) {
        out_seq_num += 1;
    } else {
        // no logs so far case
        assert(s.getValue() == jungle::Status::NO_LOGS);
        out_seq_num = 1;
    }
    uint64_t log_id = out_seq_num;

    jungle::SizedBuf key(kv.key.size, kv.key.data);
    jungle::SizedBuf value(kv.value.size, kv.value.data);
    jungle::KV jkv(key, value);
    
    s = (*db_inst)->setSN(log_id, jkv);
    return homestore::Status(s.getValue());
}

Status LogStore::init_iterator_sn(Iterator& iterator, const uint64_t min_seq, const uint64_t max_seq) {
    jungle::DB** db_inst = (jungle::DB**)&m_inst;
//    return iterator.init(db_inst, min_seq, max_seq);
    return Status::OK;
}


homestore::Status LogStore::close(homestore::LogStore* log_store) {
    jungle::DB** db_inst = (jungle::DB**)&(log_store->m_inst);
    jungle::DB::close(*db_inst);
    delete (log_store);
    return homestore::Status::OK;
}

homestore::Status LogStore::shutdown() { return homestore::Status::OK; }

static inline homestore::Status shutdown() { return LogStore::shutdown(); }

}