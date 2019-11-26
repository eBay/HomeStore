#include "logstore/include/log_store.hpp"

namespace homestore {
/**
 * Home Log store implementation
 */
LogStore::LogStore(const std::string& journal_uuid, const LogConfig& log_config) {}

LogStore::~LogStore() {}

Status LogStore::setSN(const uint64_t seq_num, const KV& kv) { return Status::OK; }

Status LogStore::getMaxSeqNum(uint64_t& seq_num_out) { return Status::OK; }

Status LogStore::sync(bool call_fsync) { return Status::OK; }

Status append(uint64_t& out_seq_num, const KV& kv) { return Status::OK; }

Status init_iterator_sn(Iterator& iterator, const uint64_t min_seq = -1, const uint64_t max_seq = -1) {
    return Status::OK;
}

Status LogStore::open(LogStore** ptr_out, const std::string& path, const LogConfig& log_config) {
    *ptr_out = new LogStore();
    return Status::OK;
}

Status LogStore::close(LogStore* log_store) {
    delete (log_store);
    return Status::OK;
}

Status LogStore::shutdown() { return Status::OK; }

static inline Status shutdown() {
    (void)shutdown;
    return LogStore::shutdown();
}

}