#pragma once

#include <sds_logging/logging.h>
#include <volume/home_blks.hpp>
#include <blkstore/blkstore.hpp>

SDS_LOGGING_DECL(logdev) 

namespace homestore {

typedef uint32_t crc_type_t;

const uint32_t init_crc32 = 0x12345678;
const uint32_t LOG_DEV_RECORD_HDR_MAGIC = 0xdeadbeaf;
const uint32_t LOG_DEV_RECORD_HDR_VER = 0x1;
const uint32_t INVALID_CRC32_VALUE = 0x0;
const uint32_t LOGDEV_BLKSIZE = 512;          // device write iov_len minum size is 512 bytes;
const uint64_t LOGDEV_ALIGN_SIZE = HomeStoreConfig::align_size;

#define to_logdev_req(req) boost::static_pointer_cast< logdev_req >(req)

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
struct LogDevRecordHeader_t {
    uint8_t     m_version;
    uint32_t    m_magic;
    crc_type_t  m_crc;        // crc of this record; 
    crc_type_t  m_prev_crc;   // crc of this record; 
    uint32_t    m_len;        // len of data for this record;
};

typedef union {
    struct LogDevRecordHeader_t h;
    unsigned char padding[LOGDEV_BLKSIZE];
} LogDevRecordHeader;

static_assert(sizeof(LogDevRecordHeader) == LOGDEV_BLKSIZE, "LogDevRecordHeader must be LOGDEV_SIZE bytes");

struct logdev_req;
typedef boost::intrusive_ptr< logdev_req > logdev_req_ptr;

typedef std::function< void(const logdev_req_ptr& req) > logdev_comp_callback;

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
// 1. Handle multiple chunk in blkstore layer
// 2. Recovery support : journal superblock;
//
class LogDev {
    
public:
    LogDev();
    ~LogDev();
    
    static LogDev* instance();
    static void del_instance();
    
    // callback from blkstore, registered at blkstore creation;
    void process_logdev_completions(const boost::intrusive_ptr< blkstore_req< BlkBuffer > >& bs_req);

    // returns offset 
    bool append_write(struct iovec* iov, int iovcnt, uint64_t& out_offset, logdev_comp_callback cb);
    
    bool write_at_offset(const uint64_t offset, struct iovec* iov, int iovcnt, logdev_comp_callback cb);

    // 
    // Reserve offset, 
    // Current assumption is single threaded;
    //
    uint64_t reserve(const uint64_t size);

    // 
    // read is sync
    // return actual bytes read on success or -1 on failure
    //
    ssize_t read(const uint64_t offset, const uint64_t size, const void* buf);
    
    ssize_t readv(const uint64_t offset, struct iovec* iov, int iovcnt);

    // truncate
    void truncate(const uint64_t offset);

    void start_recovery();
    // Group Commit 
   
private:
    uint64_t get_header_size() { return sizeof(LogDevRecordHeader); }

    // header verification
    bool header_verify(LogDevRecordHeader* hdr);

    // copy iov pointers and len
    bool copy_iov(struct iovec* dest, struct iovec* src, int iovcnt);

private:
    crc_type_t get_crc_and_len(struct iovec* iov, int iovcnt, uint64_t& len);

private:
    uint32_t                                                            m_last_crc;
    static LogDev*                                                       _instance;
    logdev_comp_callback                                                m_comp_cb;

}; // LogDev
} // homestore
