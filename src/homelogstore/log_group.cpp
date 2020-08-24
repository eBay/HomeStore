#include "log_dev.hpp"
#include "log_store.hpp"

namespace homestore {
SDS_LOGGING_DECL(logstore)

LogGroup::LogGroup() {
    m_iovecs.reserve(estimated_iovs);
    m_log_buf =
        sisl::aligned_unique_ptr< uint8_t >::make_sized(HS_STATIC_CONFIG(disk_attr.align_size), inline_log_buf_size);
}

void LogGroup::reset(uint32_t max_records) {
    m_cur_log_buf = m_log_buf.get();
    m_cur_buf_len = inline_log_buf_size;
    m_record_slots = (serialized_log_record*)(m_cur_log_buf + sizeof(log_group_header));
    m_inline_data_pos = sizeof(log_group_header) + (sizeof(serialized_log_record) * max_records);
    m_oob_data_pos = 0;

    m_overflow_log_buf = nullptr;
    m_nrecords = 0;
    m_max_records = std::min(max_records, max_records_in_a_batch);
    m_actual_data_size = 0;

    m_iovecs.clear();
    m_iovecs.emplace_back((void*)m_cur_log_buf, m_inline_data_pos);
}

void LogGroup::create_overflow_buf(uint32_t min_needed) {
    auto new_len = sisl::round_up(std::max(min_needed, m_cur_buf_len * 2), dma_boundary);
    auto new_buf = sisl::aligned_unique_ptr< uint8_t >::make_sized(dma_boundary, new_len);
    std::memcpy((void*)new_buf.get(), (void*)m_cur_log_buf, m_cur_buf_len);

    m_overflow_log_buf = std::move(new_buf);
    m_cur_log_buf = m_overflow_log_buf.get();
    m_cur_buf_len = new_len;
    m_record_slots = (serialized_log_record*)(m_cur_log_buf + sizeof(log_group_header));

    m_iovecs[0].iov_base = m_cur_log_buf;
}

bool LogGroup::add_record(const log_record& record, int64_t log_idx) {
    if (m_nrecords >= m_max_records) {
        LOGDEBUGMOD(logstore,
                    "Will exceed estimated records={} if we add idx={} record. Hence stopping adding in this batch",
                    m_max_records, log_idx);
        return false;
    }

    m_actual_data_size += record.size;
    if ((m_inline_data_pos + record.size) >= m_cur_buf_len) { create_overflow_buf(m_inline_data_pos + record.size); }

    // We use log_idx reference in the header as we expect each slot record is in order.
    if (m_nrecords == 0) { header()->start_log_idx = log_idx; }

    // assert(header()->start_log_idx - log_idx);

    // Fill the slots
    m_record_slots[m_nrecords].size = record.size;
    m_record_slots[m_nrecords].store_id = record.store_id;
    m_record_slots[m_nrecords].store_seq_num = record.seq_num;
    if (record.is_inlineable()) {
        m_record_slots[m_nrecords].offset = m_inline_data_pos;
        m_record_slots[m_nrecords].is_inlined = true;
        std::memcpy((void*)(m_cur_log_buf + m_inline_data_pos), record.data_ptr, record.size);
        m_inline_data_pos += record.size;
        m_iovecs[0].iov_len = m_inline_data_pos;
    } else {
        // We do not round it now, it will be rounded during finish
        m_record_slots[m_nrecords].offset = m_oob_data_pos;
        m_record_slots[m_nrecords].is_inlined = false;
        m_iovecs.emplace_back((void*)record.data_ptr, record.size);
        m_oob_data_pos += record.size;
    }
    m_nrecords++;

    return true;
}

const iovec_array& LogGroup::finish() {
    m_iovecs[0].iov_len = sisl::round_up(m_iovecs[0].iov_len, dma_boundary);

    log_group_header* hdr = header();
    hdr->magic = LOG_GROUP_HDR_MAGIC;
    hdr->n_log_records = m_nrecords;
    hdr->prev_grp_crc = HomeLogStoreMgr::logdev().get_prev_crc();
    hdr->inline_data_offset = sizeof(log_group_header) + (m_max_records * sizeof(serialized_log_record));
    hdr->oob_data_offset = m_iovecs[0].iov_len;
    hdr->group_size = hdr->oob_data_offset + m_oob_data_pos;
    hdr->cur_grp_crc = compute_crc();

    return m_iovecs;
}

crc32_t LogGroup::compute_crc() {
    crc32_t crc = crc32_ieee(init_crc32, (unsigned char*)(m_iovecs[0].iov_base) + sizeof(log_group_header),
                             m_iovecs[0].iov_len - sizeof(log_group_header));
    for (auto i = 1u; i < m_iovecs.size(); ++i) {
        crc = crc32_ieee(crc, (unsigned char*)(m_iovecs[i].iov_base), m_iovecs[i].iov_len);
    }

    return crc;
}

} // namespace homestore
