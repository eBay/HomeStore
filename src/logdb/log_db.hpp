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
//  LogDev Layout: 
// 
// First Record               Last Record
//  |                             |
//  |                             |          
//  ------------------------------------------ 
//  |H| data |F|H| data |F|  ...  |H| data |F| ... 
//  ------------------------------------------
//  |<-- 1 --> | <-- 2 -->|  ...  |<-- N --> |   
//
struct LogDevRecordHeader {
    uint8_t     m_version;
    uint32_t    m_magic;
    uint32_t    m_crc;      // crc of this record; 
    uint32_t    m_len;      // len of data for this record;
};

struct LogDevRecordFooter {
    uint32_t    m_prev_crc;  // crc of previous record
};

struct logdev_req;
typedef boost::intrusive_ptr< logdev_req > logdev_req_ptr;

struct logdev_req : public blkstore_req< BlkBuffer > {
public:
    static boost::intrusive_ptr< logdev_req > make_request() {
        return boost::intrusive_ptr< logdev_req >(homeds::ObjectAllocator< logdev_req >::make_object());
    }

    virtual void free_yourself() override { homeds::ObjectAllocator< logdev_req >::deallocate(this); }

    virtual ~logdev_req() = default;

    // virtual size_t get_your_size() const override { return sizeof(ssd_loadgen_req); }

    static logdev_req_ptr cast(const boost::intrusive_ptr< blkstore_req< BlkBuffer > >& bs_req) {
        return boost::static_pointer_cast< logdev_req >(bs_req);
    }

protected:
    friend class homeds::ObjectAllocator< logdev_req >;
};

//
// We have only one LogDev instance serving all the volume log write requests;
//
// LogDev exposes APIs to LogStore layer.
//  
// TODO:
// 3. generate log_id
// 4. Recovery support : journal superblock;
// 5. Handle multiple chunk in blkstore layer
// 
// 5. Remove mutex because only one will write (Group Commit)
// 6. LogDevReq and re-use this one for later write;
//
class LogDev {
    
public:
    LogDev();
    ~LogDev();
    
    static LogDev* instance();
    
    static void process_log_data_completions(const boost::intrusive_ptr< blkstore_req< BlkBuffer > >& bs_req);

    // returns offset 
    bool append_write(boost::intrusive_ptr< homeds::MemVector > mvec, uint64_t& offset, boost::intrusive_ptr< logdev_req > req);
    
    // return true if the given offset is a valid start of a record
    bool read(const homeds::MemPiece& mp, uint64_t offset, boost::intrusive_ptr< logdev_req > req);
    
    // Group Commit 
   
    // Compact

private:
    uint32_t cal_crc(boost::intrusive_ptr< homeds::MemVector > mvec);

private:
    homestore::BlkStore< homestore::VdevVarSizeBlkAllocatorPolicy >*    m_blkstore;
    uint64_t                                                            m_write_size;   
    uint32_t                                                            m_last_crc;
    static LogDev*                                                       _instance;

}; // LogDev
} // homestore
