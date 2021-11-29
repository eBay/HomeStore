#include <cstring>

#include "log_dev.hpp"
#include "log_store.hpp"

namespace homestore {
SDS_LOGGING_DECL(logstore)

LogGroup::LogGroup() = default;
void LogGroup::start(const uint64_t flush_multiple_size, const uint32_t align_size) {
    m_iovecs.reserve(estimated_iovs);
    m_flush_multiple_size = flush_multiple_size;

    // TO DO: Might need to differentiate based on data or fast type
    m_cur_buf_len = sisl::round_up(inline_log_buf_size, flush_multiple_size);
    m_log_buf = sisl::aligned_unique_ptr< uint8_t, sisl::buftag::logwrite >::make_sized(align_size, m_cur_buf_len);

    m_footer_buf_len = sisl::round_up(sizeof(log_group_footer), flush_multiple_size);
    m_footer_buf =
        sisl::aligned_unique_ptr< uint8_t, sisl::buftag::logwrite >::make_sized(align_size, m_footer_buf_len);
}

void LogGroup::stop() {
    m_log_buf.reset();
    m_overflow_log_buf.reset();
    m_footer_buf.reset();
}

void LogGroup::reset(const uint32_t max_records) {
    m_cur_buf_len = sisl::round_up(inline_log_buf_size, m_flush_multiple_size);
    m_cur_log_buf = m_log_buf.get();
    m_record_slots = reinterpret_cast< serialized_log_record* >(m_cur_log_buf + sizeof(log_group_header));
    m_inline_data_pos = sizeof(log_group_header) + (sizeof(serialized_log_record) * max_records);
    m_oob_data_pos = 0;

    m_overflow_log_buf = nullptr;
    m_nrecords = 0;
    m_max_records = std::min(max_records, max_records_in_a_batch);
    m_actual_data_size = 0;

    m_iovecs.clear();
    m_iovecs.emplace_back(static_cast< void* >(m_cur_log_buf), m_inline_data_pos);
}

void LogGroup::create_overflow_buf(const uint32_t min_needed) {
    const auto new_len{sisl::round_up(std::max(min_needed, m_cur_buf_len * 2), m_flush_multiple_size)};
    auto new_buf{
        sisl::aligned_unique_ptr< uint8_t, sisl::buftag::logwrite >::make_sized(m_flush_multiple_size, new_len)};
    std::memcpy(static_cast< void* >(new_buf.get()), static_cast< const void* >(m_cur_log_buf), m_cur_buf_len);

    m_overflow_log_buf = std::move(new_buf);
    m_cur_log_buf = m_overflow_log_buf.get();
    m_cur_buf_len = new_len;
    m_record_slots = reinterpret_cast< serialized_log_record* >(m_cur_log_buf + sizeof(log_group_header));

    m_iovecs[0].iov_base = m_cur_log_buf;
}

bool LogGroup::add_record(const log_record& record, const int64_t log_idx) {
    if (m_nrecords >= m_max_records) {
        LOGDEBUGMOD(logstore,
                    "Will exceed estimated records={} if we add idx={} record. Hence stopping adding in this batch",
                    m_max_records, log_idx);
        return false;
    }

    m_actual_data_size += record.data.size;
    if ((m_inline_data_pos + record.data.size) >= m_cur_buf_len) {
        create_overflow_buf(m_inline_data_pos + record.data.size);
    }

    // We use log_idx reference in the header as we expect each slot record is in order.
    if (m_nrecords == 0) { header()->start_log_idx = log_idx; }

    // assert(header()->start_log_idx - log_idx);

    // Fill the slots
    m_record_slots[m_nrecords].size = record.data.size;
    m_record_slots[m_nrecords].store_id = record.store_id;
    m_record_slots[m_nrecords].store_seq_num = record.seq_num;
    if (record.is_inlineable(m_flush_multiple_size)) {
        m_record_slots[m_nrecords].offset = m_inline_data_pos;
        m_record_slots[m_nrecords].set_inlined(true);
        std::memcpy(static_cast< void* >(m_cur_log_buf + m_inline_data_pos),
                    static_cast< const void* >(record.data.bytes), record.data.size);
        m_inline_data_pos += record.data.size;
        m_iovecs[0].iov_len = m_inline_data_pos;
    } else {
        // We do not round it now, it will be rounded during finish
        m_record_slots[m_nrecords].offset = m_oob_data_pos;
        m_record_slots[m_nrecords].set_inlined(false);
        m_iovecs.emplace_back(static_cast< void* >(record.data.bytes), record.data.size);
        m_oob_data_pos += record.data.size;
    }
    ++m_nrecords;

    return true;
}

bool LogGroup::new_iovec_for_footer() const {
    return ((m_inline_data_pos + sizeof(log_group_footer)) >= m_cur_buf_len || m_oob_data_pos != 0);
}

const iovec_array& LogGroup::finish(const crc32_t prev_crc) {
    // add footer
    auto footer = add_and_get_footer();

    m_iovecs[0].iov_len = sisl::round_up(m_iovecs[0].iov_len, m_flush_multiple_size);

    log_group_header* hdr{new (header()) log_group_header{}};
    hdr->n_log_records = m_nrecords;
    hdr->prev_grp_crc = prev_crc;
    hdr->inline_data_offset = sizeof(log_group_header) + (m_max_records * sizeof(serialized_log_record));
    hdr->oob_data_offset = m_iovecs[0].iov_len;
    if (new_iovec_for_footer()) {
        hdr->footer_offset = hdr->oob_data_offset + m_oob_data_pos;
        hdr->group_size = hdr->footer_offset + m_footer_buf_len;
    } else {
        hdr->footer_offset = m_inline_data_pos;
        hdr->group_size = hdr->oob_data_offset;
    }
    HS_DEBUG_ASSERT_LE((hdr->footer_offset + sizeof(log_group_footer)), hdr->group_size);

#ifndef NDEBUG
    uint64_t len = 0;
    for (auto const& iv : m_iovecs) {
        len += iv.iov_len;
    }
    HS_DEBUG_ASSERT_EQ(hdr->group_size, len, "length is not same");
#endif

    footer->start_log_idx = hdr->start_log_idx;
    hdr->cur_grp_crc = compute_crc();

    return m_iovecs;
}

log_group_footer* LogGroup::add_and_get_footer() {
    log_group_footer* footer;
    if (new_iovec_for_footer()) {
        // allocate a new iovec if there are out of band buffers or inline buffer doesn't have enough space
        m_iovecs.emplace_back(static_cast< void* >(m_footer_buf.get()), m_footer_buf_len);
        footer = new (m_footer_buf.get()) log_group_footer();
    } else {
        footer = new ((void*)((uint8_t*)m_iovecs[0].iov_base + m_inline_data_pos)) log_group_footer();
        m_iovecs[0].iov_len += sizeof(log_group_footer);
    }
    return footer;
}

crc32_t LogGroup::compute_crc() {
    crc32_t crc{crc32_ieee(init_crc32,
                           static_cast< const unsigned char* >(m_iovecs[0].iov_base) + sizeof(log_group_header),
                           m_iovecs[0].iov_len - sizeof(log_group_header))};
    for (size_t i{1}; i < m_iovecs.size(); ++i) {
        crc = crc32_ieee(crc, static_cast< const unsigned char* >(m_iovecs[i].iov_base), m_iovecs[i].iov_len);
    }

    return crc;
}

} // namespace homestore
