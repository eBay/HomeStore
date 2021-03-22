#include "engine/common/homestore_assert.hpp"
#include "engine/homestore_base.hpp"
#include "log_dev.hpp"

namespace homestore {
SDS_LOGGING_DECL(logstore)

log_stream_reader::log_stream_reader(const uint64_t device_cursor) {
    m_hb = HomeStoreBase::safe_instance();
    m_first_group_cursor = device_cursor;
    m_hb->get_logdev_blkstore()->lseek(m_first_group_cursor);
}

sisl::byte_view log_stream_reader::next_group() {
    const uint64_t bulk_read_size{static_cast< uint64_t >(
        sisl::round_up(HS_DYNAMIC_CONFIG(logstore.bulk_read_size), log_record::dma_boundary()))};
    uint64_t min_needed{log_record::dma_boundary()};
    sisl::byte_view ret_buf;

read_again:
    if (m_cur_log_buf.size() < min_needed) {
        do {
            auto m_cur_log_buf = read_next_bytes(std::max(min_needed, bulk_read_size));
        } while (m_cur_log_buf.size() < sizeof(log_group_header));
        min_needed = 0;
    }
    HS_ASSERT_CMP(RELEASE, m_cur_log_buf.size(), !=, 0);

    assert(m_cur_log_buf.size() >= log_record::dma_boundary());
    const auto* const header{reinterpret_cast< log_group_header* >(m_cur_log_buf.bytes())};
    if (header->magic_word() != LOG_GROUP_HDR_MAGIC) {
        LOGINFOMOD(logstore, "Logdev data not seeing magic at pos {}, must have come to end of logdev",
                   store->seeked_pos());
        return ret_buf;
    }

    if (header->total_size() > m_cur_log_buf.size()) {
        LOGINFOMOD(logstore, "Logstream group size {} is more than available buffer size {}, reading from store",
                   header->total_size(), m_cur_log_buf.size());
        // Bigger group size than needed bytes, read again
        min_needed = sisl::round_up(header->total_size(), log_record::dma_boundary());
        goto read_again;
    }

    LOGTRACEMOD(logstore, "Logstream read log group of size={} nrecords={} from device offset={}", header->total_size(),
                header->nrecords(), store->seeked_pos());

    // verify crc with data
    const crc32_t cur_crc{
        crc32_ieee(init_crc32, static_cast< const unsigned char* >(m_cur_log_buf.bytes()) + sizeof(log_group_header),
                   (header->total_size() - sizeof(log_group_header)))};
    if (cur_crc != header->cur_grp_crc) {
        LOGINFOMOD(logstore, "crc doesn't match {}", store->seeked_pos());
        return ret_buf;
    }

    // compare it with prev crc
    if (m_first_group_cursor != store->seeked_pos() && m_prev_crc != header->prev_grp_crc) {
        // we reached at the end
        LOGINFOMOD(logstore, "crc doesn't match with the prev crc {}", store->seeked_pos());
        return ret_buf;
    }

    // store cur crc in prev crc
    m_prev_crc = cur_crc;

    ret_buf = m_cur_log_buf;
    m_cur_log_buf.move_forward(header->total_size());

    return ret_buf;
}

sisl::byte_view log_stream_reader::group_in_next_page() {
    if (m_cur_log_buf.size() > log_record::dma_boundary()) { m_cur_log_buf.move_forward(log_record::dma_boundary()); }
    return next_group();
}

sisl::byte_view log_stream_reader::read_next_bytes(const uint64_t nbytes) {
    auto out_buf{sisl::byte_view(nbytes + m_cur_log_buf.size(), log_record::dma_boundary())};
    auto store{m_hb->get_logdev_blkstore()};
    memcpy(out_buf.bytes(), m_cur_log_buf.bytes(), m_cur_log_buf.size());

    const auto prev_pos{store->seeked_pos()};
    auto actual_read{store->read(static_cast< void* >(out_buf.bytes() + in_buf.size()), nbytes)};
    LOGTRACEMOD(logstore, "LogStream read {} bytes from offset {} ", actual_read, prev_pos);
    out_buf.set_size(actual_read + in_buf.size());
    return out_buf;
}
} // namespace homestore
