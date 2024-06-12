/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 *********************************************************************************/
#include "device/chunk.h"
#include "common/homestore_assert.hpp"
#include "common/homestore_config.hpp"
#include "common/homestore_utils.hpp"
#include "log_dev.hpp"
#include "device/journal_vdev.hpp"

namespace homestore {
SISL_LOGGING_DECL(logstore)

log_stream_reader::log_stream_reader(off_t device_cursor, JournalVirtualDev* vdev,
                                     shared< JournalVirtualDev::Descriptor > vdev_jd, uint64_t read_size_multiple) :
        m_vdev{vdev},
        m_vdev_jd{std::move(vdev_jd)},
        m_first_group_cursor{device_cursor},
        m_read_size_multiple{read_size_multiple} {
    // We set the journal descriptor seek_cursor here so that
    // sync_next_read reads from the seek_cursor.
    m_vdev_jd->lseek(m_first_group_cursor);
}

sisl::byte_view log_stream_reader::next_group(off_t* out_dev_offset) {
    const uint64_t bulk_read_size =
        uint64_cast(sisl::round_up(HS_DYNAMIC_CONFIG(logstore.bulk_read_size), m_read_size_multiple));
    uint64_t min_needed{m_read_size_multiple};
    sisl::byte_view ret_buf;
    *out_dev_offset = m_vdev_jd->dev_offset(m_cur_read_bytes);

read_again:
    if (m_cur_log_buf.size() < min_needed) {
        do {
            m_cur_log_buf = read_next_bytes(std::max(min_needed, bulk_read_size));
            if (m_cur_log_buf.size() == 0) {
                LOGINFOMOD(logstore, "Logdev data empty log_dev={}", m_vdev_jd->logdev_id());
                return {};
            }
        } while (m_cur_log_buf.size() < sizeof(log_group_header));
        min_needed = 0;
    }

    HS_REL_ASSERT_GE(m_cur_log_buf.size(), m_read_size_multiple);
    const auto* header = r_cast< log_group_header const* >(m_cur_log_buf.bytes());
    if (header->magic_word() != LOG_GROUP_HDR_MAGIC) {
        LOGINFOMOD(logstore, "Logdev data not seeing magic at pos {}, must have come to end of log_dev={}",
                   m_vdev_jd->dev_offset(m_cur_read_bytes), m_vdev_jd->logdev_id());
        *out_dev_offset = m_vdev_jd->dev_offset(m_cur_read_bytes);
        // move it by dma boundary if header is not valid
        m_prev_crc = 0;
        m_cur_read_bytes += m_read_size_multiple;
        return ret_buf;
    }

    // Because reuse chunks without cleaning up, we could get chunks used by other logdev's
    // and it can happen that log group headers couldnt match. In that case check we dont error
    // if its the last chunk or not with is_offset_at_last_chunk else raise assert.
    // compare it with prev crc
    if (m_prev_crc != 0 && m_prev_crc != header->prev_grp_crc) {
        // we reached at the end
        LOGINFOMOD(logstore,
                   "we have reached the end. crc doesn't match offset {} prev crc {} header prev crc {} log_dev={}",
                   m_vdev_jd->dev_offset(m_cur_read_bytes), header->prev_grp_crc, m_prev_crc, m_vdev_jd->logdev_id());
        *out_dev_offset = m_vdev_jd->dev_offset(m_cur_read_bytes);
        if (!m_vdev_jd->is_offset_at_last_chunk(*out_dev_offset)) {
            HS_REL_ASSERT(0, "data is corrupted {}", m_vdev_jd->logdev_id());
        }
        // move it by dma boundary if header is not valid
        m_prev_crc = 0;
        m_cur_read_bytes += m_read_size_multiple;
        return ret_buf;
    }

    if (header->total_size() > m_cur_log_buf.size()) {
        LOGTRACEMOD(logstore, "Logstream group size {} is more than available buffer size {}, reading from log_dev={}",
                    header->total_size(), m_cur_log_buf.size(), m_vdev_jd->logdev_id());
        // Bigger group size than needed bytes, read again
        min_needed = sisl::round_up(header->total_size(), m_read_size_multiple);
        goto read_again;
    }

    LOGTRACEMOD(logstore,
                "Logstream read log group of size={} nrecords={} journal_dev_offset {} cur_read_bytes {} buf size "
                "remaining {} log_dev={}",
                header->total_size(), header->nrecords(), m_vdev_jd->dev_offset(m_cur_read_bytes), m_cur_read_bytes,
                m_cur_log_buf.size(), m_vdev_jd->logdev_id());

    // At this point data seems to be valid. Lets see if a data is written completely by comparing the footer
    const auto* footer = r_cast< log_group_footer* >((uint64_t)m_cur_log_buf.bytes() + header->footer_offset);
    if (footer->magic != LOG_GROUP_FOOTER_MAGIC || footer->start_log_idx != header->start_log_idx) {
        LOGINFOMOD(logstore,
                   "last write is not completely written. footer magic {} footer start_log_idx {} header log indx {} "
                   "log_dev={}",
                   footer->magic, footer->start_log_idx, header->start_log_idx, m_vdev_jd->logdev_id());
        *out_dev_offset = m_vdev_jd->dev_offset(m_cur_read_bytes);
        // move it by dma boundary if header is not valid
        m_prev_crc = 0;
        m_cur_read_bytes += m_read_size_multiple;
        if (!m_vdev_jd->is_offset_at_last_chunk(*out_dev_offset)) {
            HS_REL_ASSERT(0, "data is corrupted {}", m_vdev_jd->logdev_id());
        }
        return ret_buf;
    }

    HS_DBG_ASSERT_EQ(footer->version, log_group_footer::footer_version, "Log footer version mismatch");

    // verify crc with data
    const crc32_t cur_crc =
        crc32_ieee(init_crc32, s_cast< const uint8_t* >(m_cur_log_buf.bytes()) + sizeof(log_group_header),
                   (header->total_size() - sizeof(log_group_header)));
    if (cur_crc != header->cur_grp_crc) {
        /* This is a valid entry so crc should match */
        LOGERRORMOD(logstore, "crc doesn't match {} log_dev={}", m_vdev_jd->dev_offset(m_cur_read_bytes),
                    m_vdev_jd->logdev_id());
        HS_REL_ASSERT(0, "data is corrupted {}", m_vdev_jd->logdev_id());
        *out_dev_offset = m_vdev_jd->dev_offset(m_cur_read_bytes);

        // move it by dma boundary if header is not valid
        m_prev_crc = 0;
        m_cur_read_bytes += m_read_size_multiple;
        return ret_buf;
    }

    // store cur crc in prev crc
    m_prev_crc = cur_crc;

    ret_buf = m_cur_log_buf;
    *out_dev_offset = m_vdev_jd->dev_offset(m_cur_read_bytes);
    m_cur_read_bytes += header->total_size();
    m_cur_log_buf.move_forward(header->total_size());

    return ret_buf;
}

sisl::byte_view log_stream_reader::group_in_next_page() {
    off_t dev_offset;
    if (m_cur_log_buf.size() > m_read_size_multiple) { m_cur_log_buf.move_forward(m_read_size_multiple); }
    return next_group(&dev_offset);
}

sisl::byte_view log_stream_reader::read_next_bytes(uint64_t nbytes) {
    // TO DO: Might need to address alignment based on data or fast type
    const auto prev_pos = m_vdev_jd->seeked_pos();
    auto sz_to_read = m_vdev_jd->sync_next_read(nullptr, nbytes);
    if (sz_to_read == 0) { return sisl::byte_view{m_cur_log_buf}; }

    auto out_buf =
        hs_utils::make_byte_array(sz_to_read + m_cur_log_buf.size(), true, sisl::buftag::logread, m_vdev->align_size());
    if (m_cur_log_buf.size()) { memcpy(out_buf->bytes(), m_cur_log_buf.bytes(), m_cur_log_buf.size()); }

    auto sz_read = m_vdev_jd->sync_next_read(out_buf->bytes() + m_cur_log_buf.size(), sz_to_read);
    assert(sz_read == sz_to_read);

    LOGTRACEMOD(logstore,
                "LogStream read {} bytes req bytes {} from vdev prev offset {} and vdev cur offset {} log_dev={}",
                sz_read, nbytes, prev_pos, m_vdev_jd->seeked_pos(), m_vdev_jd->logdev_id());
    return sisl::byte_view{out_buf};
}
} // namespace homestore
