#pragma once

#include "record.hpp"

#include <functional>
#include <vector>

#include <stddef.h>
#include <stdint.h>

namespace homestore {

typedef int (*CustomCmpFunc)(void* a, size_t len_a, void* b, size_t len_b, void* user_param);

class LogConfig {
public:
    LogConfig() :
            allowOverwriteSeqNum(false),
            logSectionOnly(false),
            logFileTtl_sec(0),
            maxKeepingMemtables(0),
            maxEntriesInLogFile(16384) // 16K
            ,
            maxLogFileSize(4194304) // 4MB
            ,
            cmpFunc(nullptr),
            cmpFuncParam(nullptr),
            pureLsmMode(false),
            readOnly(false) {}

    bool isValid() const;

    uint64_t getMaxTableSize(size_t level) const;

    // Allow overwriting logs that already exist.
    bool allowOverwriteSeqNum;

    // Disable table section and use logging part only.
    bool logSectionOnly;

    // (Only when `logSectionOnly == true`)
    // TTL for log file in second.
    // If it is non-zero, the mem-table of the log file will
    // be purged once that file is not accessed for the given time.
    uint32_t logFileTtl_sec;

    // (Only when `logSectionOnly == true`)
    // Number of memtables kept in memory at the same time.
    // If it is non-zero, and if the number of memtables exceeds
    // this number, the oldest memtable will be purged from memory
    // even before the TTL of corresponding log file.
    uint32_t maxKeepingMemtables;

    // Max number of logs in a file.
    uint32_t maxEntriesInLogFile;

    // Max size of a log file.
    uint32_t maxLogFileSize;

    // Custom comparison function.
    CustomCmpFunc cmpFunc;

    // Parameter for custom comparison function.
    void* cmpFuncParam;

    // WARNING: EXPERIMENTAL feature.
    // If `true`, working as a pure LSM-tree.
    bool pureLsmMode;

    // If `true`, read-only mode. No modify, recovery, and compaction.
    bool readOnly;
};

} // namespace homestore