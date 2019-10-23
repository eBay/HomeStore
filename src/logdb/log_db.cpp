#include "log_db.hpp"

namespace homestore {

LogDev* LogDev::_instance = nullptr;

LogDev::LogDev() {
    m_last_crc = INVALID_CRC32_VALUE;
    m_write_size = 0;
    m_blkstore = HomeBlks::instance()->get_logdb_blkstore();
    //HS_ASSERT_CMP(DEBUG, m_blkstore, !=, nullptr);
}

LogDev::~LogDev() {

}

LogDev* LogDev::instance() {
    static std::once_flag f;
    std::call_once(f, []() { _instance = new LogDev(); });
    return _instance;
}

// 
// calculate crc based on input buffers splitted in multiple buffers in MemVector;
//
uint32_t LogDev::cal_crc(boost::intrusive_ptr< homeds::MemVector > mvec) {
    uint32_t crc = init_crc32;
    for (size_t i = 0; i < mvec->npieces(); i++) {
        crc = crc32_ieee(crc, (unsigned char*)mvec->get_nth_piece(i).ptr(), mvec->get_nth_piece(i).size());
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
bool LogDev::append_write(boost::intrusive_ptr< homeds::MemVector > mvec, uint64_t& out_offset,  boost::intrusive_ptr< logdev_req > req) {
    size_t data_sz = sizeof(LogDevRecordHeader) + mvec->size() + sizeof(LogDevRecordFooter);

    // validate size being written;
    if (m_write_size + data_sz > m_blkstore->get_size()) {
        HS_LOG(ERROR, logdb, "Fail to write to logdb. No space left: {}, {}, {}", m_write_size, data_sz, mvec->size());
        return false;
    }
    
    LogDevRecordHeader *hdr = new LogDevRecordHeader();
    
    hdr->m_version = LOG_DB_RECORD_HDR_VER;
    hdr->m_magic = LOG_DB_RECORD_HDR_MAGIC;
    hdr->m_crc = cal_crc(mvec);
    hdr->m_len = mvec->size();

    // insert header portion before the data buffer
    MemPiece mp_hdr((uint8_t*)hdr, (uint32_t)sizeof(LogDevRecordHeader), 0ul);
    mvec->insert_at(0, mp_hdr);

    LogDevRecordFooter* ft = new LogDevRecordFooter();

    ft->m_prev_crc = m_last_crc;

    // push back the footer portion
    MemPiece mp_ft((uint8_t*)ft, (uint32_t)sizeof(LogDevRecordFooter), 0ul);
    mvec->push_back(mp_ft);

    m_last_crc = hdr->m_crc;

    out_offset = m_blkstore->write_at_offset(mvec, m_write_size, to_wb_req(req));

    m_write_size += data_sz;
    return true;
}

//
bool LogDev::read(const homeds::MemPiece& mp, uint64_t offset, boost::intrusive_ptr< logdev_req > req) {
    // To be implemented
    return true;
}

void LogDev::process_log_data_completions(const boost::intrusive_ptr< blkstore_req< BlkBuffer > >& bs_req) {

}

}
