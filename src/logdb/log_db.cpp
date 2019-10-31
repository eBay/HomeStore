#include "log_db.hpp"

namespace homestore {

LogDev* LogDev::_instance = nullptr;

LogDev::LogDev() {
    m_comp_cb = nullptr;
    m_last_crc = INVALID_CRC32_VALUE;
    m_write_size = 0;
}

LogDev::~LogDev() {

}

void LogDev::del_instance() {
    delete _instance;
}

LogDev* LogDev::instance() {
    static std::once_flag f;
    std::call_once(f, []() { _instance = new LogDev(); });
    return _instance;
}

// 
// calculate crc based on input buffers splitted in multiple buffers in MemVector;
//
uint32_t LogDev::get_crc_and_len(struct iovec* iov, int iovcnt, uint64_t& len) {
    uint32_t crc = init_crc32;
    len = 0;
    for (int i = 0; i < iovcnt; i++) {
        crc = crc32_ieee(crc, (unsigned char*)(iov[i].iov_base), iov[i].iov_len);
        len += iov[i].iov_len;
    }

    return crc;
}

// 
// append_write is serialized
//
// With group commit, the through put will be much better;
//
// Note:
// 1. This routine is supposed to be called by group commit, which is single threaded. 
//    Hence no lock is needed. 
//    If group commit design has changed to support Multi-threading, update this routine with lock protection;
// 2. mvec can take multiple data buffer, and crc will be calculated for all the buffers;
//
// TODO:
// 1. Avoid new and Memory should come from pre-allocated buffer when group-commit kicks in
//
bool LogDev::append_write(struct iovec* iov_i, int iovcnt_i, uint64_t& out_offset, logdev_comp_callback cb) {
    m_comp_cb = cb;
    uint64_t len = 0; 
    uint32_t crc = get_crc_and_len(iov_i, iovcnt_i, len);

    size_t data_sz = sizeof(LogDevRecordHeader) + len + sizeof(LogDevRecordFooter);
    uint64_t blkstore_sz = HomeBlks::instance()->get_logdev_blkstore()->get_size();

    // validate size being written;
    if (m_write_size + data_sz > blkstore_sz) {
        HS_LOG(ERROR, logdev, "Fail to write to logdev. No space left: {}, {}, {}", m_write_size, data_sz, len);
        return false;
    }
    
    const int iovcnt = iovcnt_i + 2;
    struct iovec iov[iovcnt];

    LogDevRecordHeader *hdr = nullptr;
    int ret = posix_memalign((void**)&hdr, LOGDEV_BLKSIZE, LOGDEV_BLKSIZE);
    
    std::memset((void*)hdr, 0, sizeof(LogDevRecordHeader));
    
    if (ret != 0 ) {
        throw std::bad_alloc();
    }

    hdr->h.m_version = LOG_DB_RECORD_HDR_VER;
    hdr->h.m_magic = LOG_DB_RECORD_HDR_MAGIC;
    hdr->h.m_crc = crc;
    hdr->h.m_len = len;

    iov[0].iov_base = (uint8_t*)hdr;
    iov[0].iov_len = LOGDEV_BLKSIZE;

    // move pointer from input iov_i to iov;
    for (int i = 0, j = 1; i < iovcnt_i; i++, j++) {
        iov[j].iov_base = iov_i[i].iov_base;
        iov[j].iov_len = iov_i[i].iov_len;

#ifdef _PRERELEASE
        if (iov_i[i].iov_len % LOGDEV_BLKSIZE) {
            HS_LOG(ERROR, logdev, "Invalid iov_len, must be {} aligned. ", LOGDEV_BLKSIZE);
            return false;
        }
#endif
    }

    LogDevRecordFooter* ft = nullptr;
    ret = posix_memalign((void**)&ft, LOGDEV_BLKSIZE, sizeof(LogDevRecordFooter));
    
    std::memset((void*)ft, 0, sizeof(LogDevRecordFooter));
    
    if (ret != 0 ) {
        throw std::bad_alloc();
    }

    ft->t.m_prev_crc = m_last_crc;

    iov[iovcnt-1].iov_base = (uint8_t*)ft;
    iov[iovcnt-1].iov_len = LOGDEV_BLKSIZE;

    m_last_crc = hdr->h.m_crc;

    auto req = logdev_req::make_request();

    out_offset = m_write_size;
    
    HomeBlks::instance()->get_logdev_blkstore()->write_at_offset(iov, iovcnt, m_write_size, to_wb_req(req));

    m_write_size += data_sz;

    free(hdr);
    free(ft);
    return true;
}

//
bool LogDev::read(uint64_t offset, boost::intrusive_ptr< logdev_req > req) {
    // To be implemented
    return true;
}

void LogDev::process_logdev_completions(const boost::intrusive_ptr< blkstore_req< BlkBuffer > >& bs_req) {
    auto req = to_logdev_req(bs_req);
    if (!req->is_read) {
       // update logdev read metrics; 
    } else {
       // update logdev write metrics;
    }
    
    m_comp_cb(req);
}

}
