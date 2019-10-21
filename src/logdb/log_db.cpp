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
    std::vector<uint8_t>  data;

    size_t data_sz = sizeof(LogDBRecordHeader) + len + sizeof(LogDBRecordFooter);

    // validate size being written;
    if (m_write_size + data_sz > m_blkstore->get_size()) {
        HS_LOG(ERROR, logdb, "Fail to write to logdb. No space left: {}, {}, {}", m_write_size, data_sz, len);
        return false;
    }

    m_write_size += data_sz;

    data.reserve(data_sz);
    fill(data.begin(), data.end(), 0);
    
    LogDBRecordHeader* hdr = (LogDBRecordHeader*)&data[0];

    hdr->m_version = LOG_DB_RECORD_HDR_VER;
    hdr->m_magic = LOG_DB_RECORD_HDR_MAGIC;
    hdr->m_crc = crc32_ieee(init_crc32, (unsigned char*)buf, len);
    hdr->m_len = len;

    // do buf copy
    std::memcpy(hdr + sizeof(LogDBRecordHeader), buf, len);
    
    // save the previous crc in the footer;
    LogDBRecordFooter* ft = (LogDBRecordFooter*)&data[data_sz - sizeof(LogDBRecordFooter)];
    ft->m_prev_crc = m_last_crc;

    m_last_crc = hdr->m_crc;

    out_offset = m_blkstore->append_write((void*)&data[0], data_sz);

    return true;
}
}
