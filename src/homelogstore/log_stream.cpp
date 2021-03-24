#include "engine/common/homestore_assert.hpp"
#include "engine/homestore_base.hpp"
#include "log_dev.hpp"

namespace homestore {
SDS_LOGGING_DECL(logstore)

log_stream_reader::log_stream_reader(const off_t device_cursor) {
    m_hb = HomeStoreBase::safe_instance();
    m_first_group_cursor = device_cursor;
    m_hb->get_logdev_blkstore()->lseek(m_first_group_cursor);
}

sisl::byte_view log_stream_reader::next_group(off_t* const out_dev_offset) {
    const uint64_t bulk_read_size{static_cast< uint64_t >(
        sisl::round_up(HS_DYNAMIC_CONFIG(logstore.bulk_read_size), log_record::dma_boundary()))};
    uint64_t min_needed{log_record::dma_boundary()};
    sisl::byte_view ret_buf;
    auto store{m_hb->get_logdev_blkstore()};

read_again:
    if (m_cur_log_buf.size() < min_needed) {
        do {
            m_cur_log_buf = read_next_bytes(std::max(min_needed, bulk_read_size));
        } while (m_cur_log_buf.size() < sizeof(log_group_header));
        min_needed = 0;
    }
    HS_ASSERT_CMP(RELEASE, m_cur_log_buf.size(), !=, 0);

    assert(m_cur_log_buf.size() >= log_record::dma_boundary());
    const auto* const header{reinterpret_cast< log_group_header* >(m_cur_log_buf.bytes())};
    if (header->magic_word() != LOG_GROUP_HDR_MAGIC) {
        LOGINFOMOD(logstore, "Logdev data not seeing magic at pos {}, must have come to end of logdev offset {}",
                   store->seeked_pos(), store->logdev_offset_to_vdev_offset(m_cur_logdev_offset));
        *out_dev_offset = store->logdev_offset_to_vdev_offset(m_cur_logdev_offset);

        // move it by dma boundary if header is not valid
        m_cur_logdev_offset += log_record::dma_boundary();
        m_cur_log_buf.move_forward(log_record::dma_boundary());
        return ret_buf;
    }

    if (header->total_size() > m_cur_log_buf.size()) {
        LOGINFOMOD(logstore, "Logstream group size {} is more than available buffer size {}, reading from store",
                   header->total_size(), m_cur_log_buf.size());
        // Bigger group size than needed bytes, read again
        min_needed = sisl::round_up(header->total_size(), log_record::dma_boundary());
        goto read_again;
    }

    LOGTRACEMOD(
        logstore,
        "Logstream read log group of size={} nrecords={} from device offset={} m_cur_log_dev_offset {} buf size "
        "remaining {} ",
        header->total_size(), header->nrecords(), store->seeked_pos(),
        store->logdev_offset_to_vdev_offset(m_cur_logdev_offset), m_cur_log_buf.size());

    // verify crc with data
    const crc32_t cur_crc{
        crc32_ieee(init_crc32, static_cast< const unsigned char* >(m_cur_log_buf.bytes()) + sizeof(log_group_header),
                   (header->total_size() - sizeof(log_group_header)))};
    if (cur_crc != header->cur_grp_crc) {
        LOGINFOMOD(logstore, "crc doesn't match {}", store->seeked_pos());
        *out_dev_offset = store->logdev_offset_to_vdev_offset(m_cur_logdev_offset);

        // move it by dma boundary if header is not valid
        m_cur_logdev_offset += log_record::dma_boundary();
        m_cur_log_buf.move_forward(log_record::dma_boundary());
        return ret_buf;
    }

    // compare it with prev crc
    if (m_prev_crc != 0 && m_prev_crc != header->prev_grp_crc) {
        // we reached at the end
        LOGINFOMOD(logstore, "crc doesn't match with the prev crc {}", store->seeked_pos());
        *out_dev_offset = store->logdev_offset_to_vdev_offset(m_cur_logdev_offset);

        // move it by dma boundary if header is not valid
        m_cur_logdev_offset += log_record::dma_boundary();
        m_cur_log_buf.move_forward(log_record::dma_boundary());
        return ret_buf;
    }

    // store cur crc in prev crc
    m_prev_crc = cur_crc;

    ret_buf = m_cur_log_buf;
    *out_dev_offset = store->logdev_offset_to_vdev_offset(m_cur_logdev_offset);
    m_cur_logdev_offset += header->total_size();
    m_cur_log_buf.move_forward(header->total_size());

    return ret_buf;
}

sisl::byte_view log_stream_reader::group_in_next_page() {
    off_t dev_offset;
    if (m_cur_log_buf.size() > log_record::dma_boundary()) { m_cur_log_buf.move_forward(log_record::dma_boundary()); }
    return next_group(&dev_offset);
}

sisl::byte_view log_stream_reader::read_next_bytes(const uint64_t nbytes) {
    auto out_buf{sisl::byte_view(nbytes + m_cur_log_buf.size(), dma_address_boundary)};
    auto ret_buf = out_buf;
    auto store{m_hb->get_logdev_blkstore()};
    if (m_cur_log_buf.size()) {
        memcpy(out_buf.bytes(), m_cur_log_buf.bytes(), m_cur_log_buf.size());
        out_buf.move_forward(m_cur_log_buf.size());
    }

    const auto prev_pos{store->seeked_pos()};
    auto actual_read{store->read(static_cast< void* >(out_buf.bytes()), nbytes)};
    LOGINFOMOD(logstore, "LogStream read {} bytes from offset {} ", actual_read, prev_pos);
    ret_buf.set_size(actual_read + m_cur_log_buf.size());
    return ret_buf;
}
} // namespace homestore
