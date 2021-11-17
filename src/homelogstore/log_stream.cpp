#include "engine/common/homestore_assert.hpp"
#include "engine/homestore_base.hpp"
#include "log_dev.hpp"

namespace homestore {
SDS_LOGGING_DECL(logstore)

log_stream_reader::log_stream_reader(const off_t device_cursor, JournalVirtualDev* store,
                                     const uint64_t read_size_multiple) :
        m_hb{HomeStoreBase::safe_instance()},
        m_blkstore{store},
        m_first_group_cursor{device_cursor},
        m_read_size_multiple{read_size_multiple} {
    m_blkstore->lseek(m_first_group_cursor);
}

sisl::byte_view log_stream_reader::next_group(off_t* const out_dev_offset) {
    const uint64_t bulk_read_size{
        static_cast< uint64_t >(sisl::round_up(HS_DYNAMIC_CONFIG(logstore.bulk_read_size), m_read_size_multiple))};
    uint64_t min_needed{m_read_size_multiple};
    sisl::byte_view ret_buf;

read_again:
    if (m_cur_log_buf.size() < min_needed) {
        do {
            m_cur_log_buf = read_next_bytes(std::max(min_needed, bulk_read_size));
        } while (m_cur_log_buf.size() < sizeof(log_group_header));
        min_needed = 0;
    }

    HS_RELEASE_ASSERT_GE(m_cur_log_buf.size(), m_read_size_multiple);
    const auto* const header{reinterpret_cast< log_group_header* >(m_cur_log_buf.bytes())};
    if (header->magic_word() != LOG_GROUP_HDR_MAGIC) {
        LOGINFOMOD(logstore, "Logdev data not seeing magic at pos {}, must have come to end of logdev",
                   m_blkstore->get_dev_offset(m_cur_read_bytes));
        *out_dev_offset = m_blkstore->get_dev_offset(m_cur_read_bytes);

        // move it by dma boundary if header is not valid
        m_prev_crc = 0;
        m_cur_read_bytes += m_read_size_multiple;
        return ret_buf;
    }

    if (header->total_size() > m_cur_log_buf.size()) {
        LOGINFOMOD(logstore, "Logstream group size {} is more than available buffer size {}, reading from store",
                   header->total_size(), m_cur_log_buf.size());
        // Bigger group size than needed bytes, read again
        min_needed = sisl::round_up(header->total_size(), m_read_size_multiple);
        goto read_again;
    }

    LOGTRACEMOD(logstore,
                "Logstream read log group of size={} nrecords={} m_cur_log_dev_offset {} buf size "
                "remaining {} ",
                header->total_size(), header->nrecords(), m_blkstore->get_dev_offset(m_cur_read_bytes),
                m_cur_log_buf.size());

    // compare it with prev crc
    if (m_prev_crc != 0 && m_prev_crc != header->prev_grp_crc) {
        // we reached at the end
        LOGINFOMOD(logstore, "we have reached the end. crc doesn't match with the prev crc {}",
                   m_blkstore->get_dev_offset(m_cur_read_bytes));
        *out_dev_offset = m_blkstore->get_dev_offset(m_cur_read_bytes);

        // move it by dma boundary if header is not valid
        m_prev_crc = 0;
        m_cur_read_bytes += m_read_size_multiple;
        return ret_buf;
    }

    // At this point data seems to be valid. Lets see if a data is written completely by comparing the footer
    const auto* const footer{
        reinterpret_cast< log_group_footer* >((uint64_t)m_cur_log_buf.bytes() + header->footer_offset)};
    if (footer->magic != LOG_GROUP_FOOTER_MAGIC || footer->start_log_idx != header->start_log_idx) {
        LOGINFOMOD(logstore,
                   "last write is not completely written. footer magic {} footer start_log_idx {} header log indx {}",
                   footer->magic, footer->start_log_idx, header->start_log_idx);
        *out_dev_offset = m_blkstore->get_dev_offset(m_cur_read_bytes);

        // move it by dma boundary if header is not valid
        m_prev_crc = 0;
        m_cur_read_bytes += m_read_size_multiple;
        return ret_buf;
    }
    HS_DEBUG_ASSERT_EQ(footer->version, log_group_footer::footer_version, "Log footer version mismatch");

    // verify crc with data
    const crc32_t cur_crc{
        crc32_ieee(init_crc32, static_cast< const unsigned char* >(m_cur_log_buf.bytes()) + sizeof(log_group_header),
                   (header->total_size() - sizeof(log_group_header)))};
    if (cur_crc != header->cur_grp_crc) {
        /* This is a valid entry so crc should match */
        HS_RELEASE_ASSERT(0, "data is corrupted");
        LOGINFOMOD(logstore, "crc doesn't match {}", m_blkstore->get_dev_offset(m_cur_read_bytes));
        *out_dev_offset = m_blkstore->get_dev_offset(m_cur_read_bytes);

        // move it by dma boundary if header is not valid
        m_prev_crc = 0;
        m_cur_read_bytes += m_read_size_multiple;
        return ret_buf;
    }

    // store cur crc in prev crc
    m_prev_crc = cur_crc;

    ret_buf = m_cur_log_buf;
    *out_dev_offset = m_blkstore->get_dev_offset(m_cur_read_bytes);
    m_cur_read_bytes += header->total_size();
    m_cur_log_buf.move_forward(header->total_size());

    return ret_buf;
}

sisl::byte_view log_stream_reader::group_in_next_page() {
    off_t dev_offset;
    if (m_cur_log_buf.size() > m_read_size_multiple) { m_cur_log_buf.move_forward(m_read_size_multiple); }
    return next_group(&dev_offset);
}

sisl::byte_view log_stream_reader::read_next_bytes(const uint64_t nbytes) {
    // TO DO: Might need to address alignment based on data or fast type
    auto out_buf{hs_utils::create_byte_view(nbytes + m_cur_log_buf.size(), true, sisl::buftag::logread)};
    auto ret_buf = out_buf;
    if (m_cur_log_buf.size()) {
        memcpy(out_buf.bytes(), m_cur_log_buf.bytes(), m_cur_log_buf.size());
        out_buf.move_forward(m_cur_log_buf.size());
    }

    const auto prev_pos{m_blkstore->seeked_pos()};
    auto actual_read{m_blkstore->read(static_cast< void* >(out_buf.bytes()), nbytes)};
    HS_RELEASE_ASSERT_NE(actual_read, 0, "zero bytes are read");
    LOGINFOMOD(logstore, "LogStream read {} bytes from vdev offset {} and vdev cur offset {}", actual_read, prev_pos,
               m_blkstore->seeked_pos());
    ret_buf.set_size(actual_read + m_cur_log_buf.size());
    return ret_buf;
}
} // namespace homestore
