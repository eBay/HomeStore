#pragma once

#include "keyvalue.hpp"
#include "status.hpp"
#include "record.hpp"

namespace homestore {

class LogStore;
class Iterator {
public:
    Iterator();
    ~Iterator();

    enum SeekOption {
        GREATER = 0,
        SMALLER = 1,
    };

    /** Additional Api for homestore use case */
    Status get(KV& kv_out);
    
    /* Existing jungle APIs */
    Status init(LogStore* _db, const SizedBuf& start_key = SizedBuf(), const SizedBuf& end_key = SizedBuf());
    Status initSN(LogStore* _db, const uint64_t min_seq = -1, const uint64_t max_seq = -1);
    Status get(Record& rec_out);
    Status prev();
    Status next();
    Status seek(const SizedBuf& key, SeekOption opt = GREATER);
    Status seekSN(const uint64_t seqnum, SeekOption opt = GREATER);
    Status gotoBegin();
    Status gotoEnd();
    Status close();

private:
    class IteratorInternal;
    IteratorInternal* const p;
    using ItrInt = Iterator::IteratorInternal;
};

} // namespace homestore