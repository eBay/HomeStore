#pragma once

#include "homeds/array/blob_array.h"
#include "logstore/include/log_store.hpp"

namespace homestore {

/**
 * We will have one volume journal instance per volume.
 * Underlying physical storage would be same in home log store implementation
 * Currently jungle logstore has seperate physical log per volume
 *
 * out_log_id is auto generated mono-increasing seq num created by logstore
 * Key is going to be vol_id, psn (basically anything we want to keep index on)
 * Value is blob array of lba_blk_entry
 */
/**
 * Persistent entry structures in log
 */
struct Lba_Blk_Entry {
    Lba_Blk_Entry(uint64_t lba_start, int n_lba, BlkId blkId) :
            m_lba_start(lba_start),
            m_n_lba(n_lba),
            m_blkId(blkId) {}
    uint64_t m_lba_start : LBA_BITS; // start of lba range
    uint64_t m_n_lba : NBLKS_BITS;   // number of lba's from start(inclusive)
    BlkId    m_blkId;                // corresponding mapped blkId, offset is always 0

    homeds::blob    get_blob() const { return {(uint8_t*)this, get_fixed_size()}; }
    static uint32_t get_fixed_size() { return sizeof(Lba_Blk_Entry); }

} __attribute__((__packed__));

struct VolumeJournalKey {
    uint64_t m_lsn;
    char     m_vol_uuid[MAX_UUID_LEN]; // uuid converted to char array

    VolumeJournalKey() {}

    void set(uint64_t lsn, const char* vol_uuid) {
        m_lsn = lsn;
        strncpy(m_vol_uuid, vol_uuid, MAX_UUID_LEN - 1);
    }

    SizedBuf get_buf() {
        SizedBuf sb;
        sb.set(sizeof(VolumeJournalKey), (uint8_t*)this);
        return sb;
    }
} __attribute__((__packed__));

struct VolumeJournalValue {
    homeds::Blob_Array< Lba_Blk_Entry > m_lba_blk_entries;

    VolumeJournalValue() {}
    void set(std::vector< Lba_Blk_Entry >& lbes) { m_lba_blk_entries.set_elements(lbes); }

    SizedBuf get_buf() {
        SizedBuf sb;
        sb.set(m_lba_blk_entries.get_size(), (uint8_t*)m_lba_blk_entries.get_mem());
        return sb;
    }
};

class VolumeJournal {

public:
    /**
     * Initialize journal uniquely identified by uuid.
     * If doesnt exists, creates one.
     */
    VolumeJournal(const std::string& journal_uuid) : logInst(nullptr) {
        // TODO - some configs can come from config file
        homestore::LogConfig config;
        config.allowOverwriteSeqNum = true;
        config.logSectionOnly = true;
        config.logFileTtl_sec = 60;
        config.maxEntriesInLogFile = 256 * 1024;
        config.maxLogFileSize = 32 * 1024 * 1024;
        config.pureLsmMode = false;

        homestore::Status s;
        s = homestore::LogStore::open(&logInst, journal_uuid, config);
        assert(s.ok());
    }

    ~VolumeJournal() {
        logInst->shutdown();
        homestore::Status s;
        s = homestore::LogStore::close(logInst);
        assert(s.ok());
    }

    /**
     * Appends log entry and returns corresponding log id.
     * Log is flushed to storage synchronously
     */
    void append_sync(VolumeJournalKey& key, VolumeJournalValue& value, uint64_t& out_log_id) {
        // TODO : jungle needs this write lock, when homestore impl is done, we should remove this
        std::lock_guard< std::mutex > l(writeLock);

        Status        s;
        homestore::KV kv(key.get_buf(), value.get_buf());
        s = logInst->append(out_log_id, kv);
        assert(s.ok());

        // Call fsync
        s = logInst->sync(true);
        assert(s.ok());
    }

private:
    // Logstore instance.
    LogStore* logInst;
    // LogStore is basically lock-free for both read & write,
    // but use write lock to be safe.
    std::mutex writeLock;
};
}