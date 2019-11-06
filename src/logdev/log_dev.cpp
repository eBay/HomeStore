#include "log_dev.hpp"

namespace homestore {

LogDev* LogDev::_instance = nullptr;

LogDev::LogDev() {
    m_comp_cb = nullptr;
    m_last_crc = INVALID_CRC32_VALUE;
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

bool LogDev::write_at_offset(const uint64_t offset, struct iovec* iov_i, int iovcnt_i, logdev_comp_callback cb) {

    m_comp_cb = cb;
    uint64_t len = 0; 
    uint32_t crc = get_crc_and_len(iov_i, iovcnt_i, len);

    const int iovcnt = iovcnt_i + 1;  // add header slot
    struct iovec iov[iovcnt];

    LogDevRecordHeader *hdr = nullptr;
    int ret = posix_memalign((void**)&hdr, LOGDEV_BLKSIZE, LOGDEV_BLKSIZE);
    if (ret != 0 ) {
        throw std::bad_alloc();
    }

    std::memset((void*)hdr, 0, sizeof(LogDevRecordHeader));

    hdr->h.m_version = LOG_DEV_RECORD_HDR_VER;
    hdr->h.m_magic = LOG_DEV_RECORD_HDR_MAGIC;
    hdr->h.m_crc = crc;
    hdr->h.m_prev_crc = m_last_crc;
    hdr->h.m_len = len;

    iov[0].iov_base = (uint8_t*)hdr;
    iov[0].iov_len = LOGDEV_BLKSIZE;

    if (!copy_iov(&iov[1], iov_i, iovcnt_i)) {
        return false;
    }
    
    m_last_crc = hdr->h.m_crc;

    auto req = logdev_req::make_request();

    bool success = HomeBlks::instance()->get_logdev_blkstore()->write_at_offset(offset, iov, iovcnt, to_wb_req(req));

    free(hdr);
    return success;
}
#if 0
bool LogDev::append_write(struct iovec* iov_i, int iovcnt_i, uint64_t& out_offset, logdev_comp_callback cb) {
    m_comp_cb = cb;
    uint64_t len = 0; 
    uint32_t crc = get_crc_and_len(iov_i, iovcnt_i, len);

    const int iovcnt = iovcnt_i + 1;  // add header slot
    struct iovec iov[iovcnt];

    LogDevRecordHeader *hdr = nullptr;
    int ret = posix_memalign((void**)&hdr, LOGDEV_BLKSIZE, LOGDEV_BLKSIZE);
    if (ret != 0 ) {
        throw std::bad_alloc();
    }

    std::memset((void*)hdr, 0, sizeof(LogDevRecordHeader));

    hdr->h.m_version = LOG_DEV_RECORD_HDR_VER;
    hdr->h.m_magic = LOG_DEV_RECORD_HDR_MAGIC;
    hdr->h.m_crc = crc;
    hdr->h.m_prev_crc = m_last_crc;
    hdr->h.m_len = len;

    iov[0].iov_base = (uint8_t*)hdr;
    iov[0].iov_len = LOGDEV_BLKSIZE;

    copy_iov(&iov[1], iov_i, iovcnt_i);
    
    m_last_crc = hdr->h.m_crc;

    auto req = logdev_req::make_request();

    bool success = HomeBlks::instance()->get_logdev_blkstore()->append_write(iov, iovcnt, out_offset, to_wb_req(req));

    free(hdr);
    return success;
}
#endif
// 
// Reserve size of offset 
//
uint64_t LogDev::reserve(const uint64_t size) {
    return HomeBlks::instance()->get_logdev_blkstore()->reserve(size);
}

// 
// truncate 
//
void LogDev::truncate(const uint64_t offset) {
    HomeBlks::instance()->get_logdev_blkstore()->truncate(offset); 
}

ssize_t LogDev::readv(const uint64_t offset, struct iovec* iov_i, int iovcnt_i) {
    int iovcnt = iovcnt_i + 1;
    struct iovec iov[iovcnt];
    
    LogDevRecordHeader *hdr = nullptr;
    int ret = posix_memalign((void**)&hdr, LOGDEV_BLKSIZE, LOGDEV_BLKSIZE);
    if (ret != 0 ) {
        throw std::bad_alloc();
    }
    std::memset((void*)hdr, 0, sizeof(LogDevRecordHeader));

    iov[0].iov_base = (uint8_t*) hdr;
    iov[0].iov_len = sizeof(LogDevRecordHeader);

    // copy pointers and length
    copy_iov(&iov[1], iov_i, iovcnt_i);

    HomeBlks::instance()->get_logdev_blkstore()->readv(offset, iov, iovcnt);
    
    if (!header_verify(hdr)) {
        HS_ASSERT(DEBUG, 0, "Log header corrupted!");
        return -1;
    }

    auto len = hdr->h.m_len;
    free(hdr);
    return len;
}

bool LogDev::copy_iov(struct iovec* dest, struct iovec* src, int iovcnt) {
    for (int i = 0; i < iovcnt; i++) {
        dest[i].iov_base = src[i].iov_base;
        dest[i].iov_len = src[i].iov_len;

#ifndef NDEBUG
        if (src[i].iov_len % LOGDEV_BLKSIZE) {
            HS_LOG(ERROR, logdev, "Invalid iov_len, must be {} aligned. ", LOGDEV_BLKSIZE);
            return false;
        }
#endif
    }
    return true;
}

bool LogDev::header_verify(LogDevRecordHeader* hdr) {
     // header version and crc verification
    if ((hdr->h.m_version != LOG_DEV_RECORD_HDR_VER) || (hdr->h.m_magic != LOG_DEV_RECORD_HDR_MAGIC)) {
        return false;
    }

    return true;
}

// 
// read
//
ssize_t LogDev::read(const uint64_t offset, const uint64_t size, const void* buf) {
    HomeBlks::instance()->get_logdev_blkstore()->read(offset, size, buf);
    
    LogDevRecordHeader* hdr = (LogDevRecordHeader*)((unsigned char*)buf + sizeof(LogDevRecordHeader));

    if (!header_verify(hdr)) {
        HS_ASSERT(DEBUG, 0, "Log header corrupted!");
        return -1;
    }

    // skip header and caculate crc of the data buffer
    uint32_t crc = crc32_ieee(init_crc32, (unsigned char*)((char*)buf + sizeof(LogDevRecordHeader)), hdr->h.m_len);
   
    HS_ASSERT_CMP(DEBUG, hdr->h.m_len, ==, size, "Log size mismatch from input size: {} : {}", hdr->h.m_len, size);
    HS_ASSERT_CMP(DEBUG, hdr->h.m_crc, ==, crc, "Log header CRC mismatch: {} : {}", hdr->h.m_crc, crc);

    return hdr->h.m_len;
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
