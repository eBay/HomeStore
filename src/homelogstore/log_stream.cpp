#include "engine/common/homestore_assert.hpp"
#include "engine/homestore_base.hpp"
#include "log_dev.hpp"

namespace homestore {
SDS_LOGGING_DECL(logstore)

log_stream_reader::log_stream_reader(uint64_t device_cursor) {
    m_hb = HomeStoreBase::safe_instance();
    m_first_group_cursor = device_cursor;
    m_cur_group_cursor = device_cursor;
}

sisl::byte_view log_stream_reader::next_group(uint64_t* out_dev_offset) {
    uint64_t min_needed = dma_boundary;
    sisl::byte_view ret_buf;

read_again:
    if (m_cur_log_buf.size() == 0 || m_cur_log_buf.size() < min_needed) {
        m_hb->get_logdev_blkstore()->lseek(m_cur_group_cursor);
        m_cur_log_buf = read_next_bytes(std::max(min_needed, HS_DYNAMIC_CONFIG(logstore.bulk_read_size)));
        min_needed = 0;
    }
    if (m_cur_log_buf.size() == 0) { return m_cur_log_buf; } // No more data available.

    assert(m_cur_log_buf.size() >= dma_boundary);
    auto header = (log_group_header*)m_cur_log_buf.bytes();
    if (header->magic_word() != LOG_GROUP_HDR_MAGIC) {
        LOGINFOMOD(logstore, "Logdev data not seeing magic at pos {}, must have come to end of logdev",
                   m_cur_group_cursor);
        return ret_buf;
    }

    if (header->total_size() > m_cur_log_buf.size()) {
        LOGINFOMOD(logstore, "Logstream group size {} is more than available buffer size {}, reading from store",
                   header->total_size(), m_cur_log_buf.size());
        // Bigger group size than needed bytes, read again
        min_needed = sisl::round_up(header->total_size(), dma_boundary);
        goto read_again;
    }

    LOGTRACEMOD(logstore, "Logstream read log group of size={} nrecords={} from device offset={}", header->total_size(),
                header->nrecords(), m_cur_group_cursor);

    // verify crc with data
    crc32_t cur_crc = crc32_ieee(init_crc32, (unsigned char*)(m_cur_log_buf.bytes()) + sizeof(log_group_header),
                                 (header->total_size() - sizeof(log_group_header)));
    if (cur_crc != header->cur_grp_crc) {
        LOGINFOMOD(logstore, "crc doesn't match {}", m_cur_group_cursor);
        return ret_buf;
    }

    // compare it with prev crc
    if (m_first_group_cursor != m_cur_group_cursor && m_prev_crc != header->prev_grp_crc) {
        // we reached at the end
        LOGINFOMOD(logstore, "crc doesn't match with the prev crc {}", m_cur_group_cursor);
        return ret_buf;
    }

    // store cur crc in prev crc
    m_prev_crc = cur_crc;

    ret_buf = m_cur_log_buf;
    *out_dev_offset = m_cur_group_cursor;
    m_cur_group_cursor += header->total_size();
    m_cur_log_buf.move_forward(header->total_size());

    return ret_buf;
}

sisl::byte_view log_stream_reader::group_in_next_page() {
    uint64_t dev_offset;
    if (m_cur_log_buf.size() > dma_boundary) { m_cur_log_buf.move_forward(dma_boundary); }
    m_cur_group_cursor += dma_boundary;
    return next_group(&dev_offset);
}

sisl::byte_view log_stream_reader::read_next_bytes(uint64_t nbytes) {
    auto buf = sisl::byte_view(nbytes, dma_boundary);
    auto store = m_hb->get_logdev_blkstore();

    auto prev_pos = store->seeked_pos();
    auto actual_read = store->read((void*)buf.bytes(), nbytes);
    LOGTRACEMOD(logstore, "LogStream read {} bytes from offset {} ", actual_read, prev_pos);
    if (actual_read != 0) {
        buf.set_size(actual_read);
        return buf;
    }

    // We have come to the end of the device, seek to start, if we are already not start
    LOGINFOMOD(logstore,
               "LogStream not read enough bytes from offset {}, must be end of device, wrap around and try reading",
               prev_pos);
    store->lseek(0);
    m_cur_group_cursor = 0;
    actual_read = store->read((void*)buf.bytes(), nbytes);
    LOGINFOMOD(logstore, "LogStream read {} bytes from offset 0 ", actual_read);
    buf.set_size(actual_read);
    return buf;
}
} // namespace homestore
