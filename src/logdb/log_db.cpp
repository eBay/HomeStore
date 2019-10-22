#include "log_db.hpp"

namespace homestore {

LogDB* LogDB::_instance = nullptr;

LogDB::LogDB() {
    m_last_crc = INVALID_CRC32_VALUE;
    m_write_size = 0;
    m_blkstore = HomeBlks::instance()->get_logdb_blkstore();
    //HS_ASSERT_CMP(DEBUG, m_blkstore, !=, nullptr);
}

LogDB::~LogDB() {

}

LogDB* LogDB::instance() {
    static std::once_flag f;
    std::call_once(f, []() { _instance = new LogDB(); });
    return _instance;
}


// 
// Append_write is serialized
//
// With group commit, the through put will be much better;
//
bool LogDB::append_write(void* buf, uint64_t len, uint64_t& out_offset) {
    std::lock_guard<std::mutex> l(m_mtx);

    size_t data_sz = sizeof(LogDBRecordHeader) + len + sizeof(LogDBRecordFooter);

    // validate size being written;
    if (m_write_size + data_sz > m_blkstore->get_size()) {
        HS_LOG(ERROR, logdb, "Fail to write to logdb. No space left: {}, {}, {}", m_write_size, data_sz, len);
        return false;
    }
    
    // buf will be freed automatcially after ref drops to 0
    boost::intrusive_ptr< homeds::MemVector > mvec(new homeds::MemVector());

    LogDBRecordHeader *hdr = new LogDBRecordHeader();

    hdr->m_version = LOG_DB_RECORD_HDR_VER;
    hdr->m_magic = LOG_DB_RECORD_HDR_MAGIC;
    hdr->m_crc = crc32_ieee(init_crc32, (unsigned char*)buf, len);
    hdr->m_len = len;

    // send the write request with MemVector to avoid data copy
    MemPiece mp_hdr((uint8_t*)hdr, (uint32_t)sizeof(LogDBRecordHeader), 0ul);
    mvec->push_back(mp_hdr);

    MemPiece mp_data((uint8_t*)buf, (uint32_t)len, 0ul);
    mvec->push_back(mp_data);

    LogDBRecordFooter* ft = new LogDBRecordFooter();

    ft->m_prev_crc = m_last_crc;

    MemPiece mp_ft((uint8_t*)ft, (uint32_t)sizeof(LogDBRecordFooter), 0ul);
    mvec->push_back(mp_ft);

    m_last_crc = hdr->m_crc;

    out_offset = m_blkstore->write_at_offset(mvec, m_write_size);

    m_write_size += data_sz;
    return true;
}
}
