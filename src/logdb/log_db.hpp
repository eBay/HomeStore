#pragma once

#include <sds_logging/logging.h>
#include <volume/home_blks.hpp>
#include <blkstore/blkstore.hpp>

SDS_LOGGING_DECL(logdb) 

namespace homestore {

const uint32_t init_crc32 = 0x12345678;
const uint32_t LOG_DB_RECORD_HDR_MAGIC = 0xdeadbeaf;
const uint32_t LOG_DB_RECORD_HDR_VER = 0x1;
const uint32_t INVALID_CRC32_VALUE = 0x0;

// 
//  LogDB Layout: 
// 
// First Record               Last Record
//  |                             |
//  |                             |          
//  ------------------------------------------ 
//  |H| data |F|H| data |F|  ...  |H| data |F| ... 
//  ------------------------------------------
//  |<-- 1 --> | <-- 2 -->|  ...  |<-- N --> |   
//
struct LogDBRecordHeader {
    uint8_t     m_version;
    uint32_t    m_magic;
    uint32_t    m_crc;      // crc of this record; 
    uint32_t    m_len;      // len of data for this record;
};

struct LogDBRecordFooter {
    uint32_t    m_prev_crc;  // crc of previous record
};

//
// We have only one LogDB instance serving all the volume log write requests;
//
// LogDB exposes APIs to LogStore layer.
//  
//
class LogDB {
    
public:
    LogDB();
    ~LogDB();
    
    static LogDB* instance();
    
    // return offset 
    bool append_write(void* buf, uint64_t len, uint64_t& offset);
    
    // Read
    
    // Group Commit 
   
    // Compact

private:

private:
    homestore::BlkStore< homestore::VdevVarSizeBlkAllocatorPolicy >*    m_blkstore;
    uint64_t                                                            m_write_size;   
    uint32_t                                                            m_last_crc;
    std::mutex                                                          m_mtx;
    static LogDB*                                                       _instance;
    // support group commit 

}; // LogDB
} // homestore
