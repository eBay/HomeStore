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
#include <cassert>
#include <cstdint>
#include <functional>
#include <iterator>
#include <limits>
#include <memory>

#include <sisl/logging/logging.h>
#include <iomgr/iomgr_flip.hpp>
#include <homestore/homestore.hpp>
#include "device/chunk.h"
#include "device/device.h"
#include "device/physical_dev.hpp"
#include "device/journal_vdev.hpp"
#include "common/error.h"
#include "common/homestore_assert.hpp"
#include "common/homestore_utils.hpp"
#include "common/resource_mgr.hpp"

namespace homestore {
JournalVirtualDev::JournalVirtualDev(DeviceManager& dmgr, const vdev_info& vinfo, vdev_event_cb_t event_cb) :
        VirtualDev{dmgr, vinfo, blk_allocator_type_t::none, chunk_selector_type_t::ROUND_ROBIN, std::move(event_cb),
                   false /* is_auto_recovery */} {}

off_t JournalVirtualDev::alloc_next_append_blk(size_t sz) {
    if (used_size() + sz > size()) {
        // not enough space left;
        HS_LOG(ERROR, device, "No space left! m_write_sz_in_total: {}, m_reserved_sz: {}", m_write_sz_in_total.load(),
               m_reserved_sz);
        return INVALID_OFFSET;
    }

#ifdef _PRERELEASE
    iomgr_flip::test_and_abort("abort_before_update_eof_cur_chunk");
#endif

    const off_t ds_off = data_start_offset();
    const off_t end_offset = tail_offset();

    auto const [chunk, offset_in_chunk] = offset_to_chunk(end_offset);

#ifndef NDEBUG
    if (end_offset < ds_off) { HS_DBG_ASSERT_EQ(size() - used_size(), static_cast< uint64_t >(ds_off - end_offset)); }
#endif
    // works for both "end_offset >= ds_off" and "end_offset < ds_off";
    if (offset_in_chunk + sz <= chunk->size()) {
        // not acrossing boundary, nothing to do;
    } else if ((used_size() + (chunk->size() - offset_in_chunk) + sz) <= size()) {
        // across chunk boundary, still enough space;

        // Update the overhead to total write size;
        m_write_sz_in_total.fetch_add(chunk->size() - offset_in_chunk, std::memory_order_relaxed);

        // If across chunk boundary, update the chunk super-block of the chunk size
        chunk->update_end_of_chunk(offset_in_chunk);

#ifdef _PRERELEASE
        iomgr_flip::test_and_abort("abort_after_update_eof_cur_chunk");
#endif
        // get next chunk handle
        auto next_chunk = get_next_chunk(chunk);
        if (next_chunk != chunk) {
            // Since we are re-using a new chunk, update this chunk's end as its original size;
            next_chunk->update_end_of_chunk(chunk->size());
        }
    } else {
        // across chunk boundary and no space left;
        HS_LOG(ERROR, device, "No space left! m_write_sz_in_total: {}, m_reserved_sz: {}", m_write_sz_in_total.load(),
               m_reserved_sz);
        return INVALID_OFFSET;
        // m_reserved_sz stays sthe same;
    }

    // if we made a successful reserve, return the tail offset;
    const off_t offset = tail_offset();

    // update reserved size;
    m_reserved_sz += sz;

    high_watermark_check();

#ifdef _PRERELEASE
    iomgr_flip::test_and_abort("abort_after_update_eof_next_chunk");
#endif
    // assert that returnning logical offset is in good range;
    HS_DBG_ASSERT_LE(static_cast< uint64_t >(offset), size());
    return offset;
}

bool JournalVirtualDev::validate_append_size(size_t count) const {
    if (used_size() + count > size()) {
        // not enough space left;
        HS_LOG(ERROR, device, "No space left! m_write_sz_in_total: {}, m_reserved_sz: {}", m_write_sz_in_total.load(),
               m_reserved_sz);
        return false;
    }

    if (m_reserved_sz != 0) {
        HS_LOG(ERROR, device, "write can't be served when m_reserved_sz:{} is not comsumed by pwrite yet.",
               m_reserved_sz);
        return false;
    }
    return true;
}

auto JournalVirtualDev::process_pwrite_offset(size_t len, off_t offset) {
    // convert logical offset to chunk and its offset
    auto const chunk_details = offset_to_chunk(offset);
    auto const [chunk, offset_in_chunk] = chunk_details;

    // this assert only valid for pwrite/pwritev, which calls alloc_next_append_blk to get the offset to do the
    // write, which guarantees write will with the returned offset will not accross chunk boundary.
    HS_REL_ASSERT_GE(chunk->size() - offset_in_chunk, len, "Writing size: {} crossing chunk is not allowed!", len);
    m_write_sz_in_total.fetch_add(len, std::memory_order_relaxed);

    HS_LOG(TRACE, device, "Writing in chunk: {}, offset: {}, m_write_sz_in_total: {}, start off: {}", chunk->chunk_id(),
           to_hex(offset_in_chunk), to_hex(m_write_sz_in_total.load()), to_hex(data_start_offset()));

    return chunk_details;
}

/////////////////////////////// Write Section //////////////////////////////////
folly::Future< bool > JournalVirtualDev::async_append(const uint8_t* buf, size_t size) {
    if (!validate_append_size(size)) {
        return folly::makeFuture< bool >(std::system_error(std::make_error_code(std::errc::no_space_on_device)));
    } else {
        auto const [chunk, offset_in_chunk] = process_pwrite_offset(size, m_seek_cursor);
        m_seek_cursor += size;
        return async_write(r_cast< const char* >(buf), size, chunk, offset_in_chunk);
    }
}

/**
 * @brief : writes up to count bytes from the buffer starting at buf at offset offset.
 * The cursor is not changed.
 * pwrite always use offset returned from alloc_next_append_blk to do the write;
 * pwrite should not across chunk boundaries because alloc_next_append_blk guarantees offset returned always doesn't
 * across chunk boundary;
 *
 * @param buf : buffer pointing to the data being written
 * @param size : size of buffer to be written
 * @param offset : offset to be written
 * @param cb : callback after write is completed, can be null
 *
 */
folly::Future< bool > JournalVirtualDev::async_pwrite(const uint8_t* buf, size_t size, off_t offset) {
    HS_REL_ASSERT_LE(size, m_reserved_sz, "Write size: larger then reserved size is not allowed!");
    m_reserved_sz -= size; // update reserved size

    auto const [chunk, offset_in_chunk] = process_pwrite_offset(size, offset);
    return async_write(r_cast< const char* >(buf), size, chunk, offset_in_chunk);
}

folly::Future< bool > JournalVirtualDev::async_pwritev(const iovec* iov, int iovcnt, off_t offset) {
    auto const size = VirtualDev::get_len(iov, iovcnt);

    // if size is smaller than reserved size, it means write will never be overlapping start offset;
    // it is guaranteed by alloc_next_append_blk api;
    HS_REL_ASSERT_LE(size, m_reserved_sz, "Write size: larger then reserved size: is not allowed!");

    m_reserved_sz -= size;
    auto const [chunk, offset_in_chunk] = process_pwrite_offset(size, offset);
    return async_writev(iov, iovcnt, chunk, offset_in_chunk);
}

void JournalVirtualDev::sync_pwrite(const uint8_t* buf, size_t size, off_t offset) {
    HS_REL_ASSERT_LE(size, m_reserved_sz, "Write size: larger then reserved size is not allowed!");
    m_reserved_sz -= size; // update reserved size

    auto const [chunk, offset_in_chunk] = process_pwrite_offset(size, offset);
    sync_write(r_cast< const char* >(buf), size, chunk, offset_in_chunk);
}

void JournalVirtualDev::sync_pwritev(const iovec* iov, int iovcnt, off_t offset) {
    auto const size = VirtualDev::get_len(iov, iovcnt);

    // if size is smaller than reserved size, it means write will never be overlapping start offset;
    // it is guaranteed by alloc_next_append_blk api;
    HS_REL_ASSERT_LE(size, m_reserved_sz, "Write size: larger then reserved size: is not allowed!");

    m_reserved_sz -= size;
    auto const [chunk, offset_in_chunk] = process_pwrite_offset(size, offset);
    sync_writev(iov, iovcnt, chunk, offset_in_chunk);
}

/////////////////////////////// Read Section //////////////////////////////////
void JournalVirtualDev::sync_next_read(uint8_t* buf, size_t size_rd) {
    auto const [chunk, offset_in_chunk] = offset_to_chunk(m_seek_cursor);
    auto const end_of_chunk = chunk->end_of_chunk();
    auto const chunk_size = std::min< uint64_t >(end_of_chunk, chunk->size());
    bool across_chunk{false};

    HS_REL_ASSERT_LE((uint64_t)end_of_chunk, chunk->size(), "Invalid end of chunk: {} detected on chunk num: {}",
                     end_of_chunk, chunk->chunk_id());
    HS_REL_ASSERT_LE((uint64_t)offset_in_chunk, chunk->size(),
                     "Invalid m_seek_cursor: {} which falls in beyond end of chunk: {}!", m_seek_cursor, end_of_chunk);

    // if read size is larger then what's left in this chunk
    if (size_rd >= (chunk->size() - offset_in_chunk)) {
        // truncate size to what is left;
        size_rd = chunk->size() - offset_in_chunk;
        across_chunk = true;
    }

    sync_pread(buf, size_rd, m_seek_cursor);

    // Update seek cursor after read;
    m_seek_cursor += size_rd;
    if (across_chunk) { m_seek_cursor += (chunk->size() - end_of_chunk); }
    m_seek_cursor = m_seek_cursor % size();
}

void JournalVirtualDev::sync_pread(uint8_t* buf, size_t size, off_t offset) {
    auto const [chunk, offset_in_chunk] = offset_to_chunk(offset);

    // if the read count is acrossing chunk, only return what's left in this chunk
    if (chunk->size() - offset_in_chunk < size) {
        // truncate requsted read length to end of chunk;
        size = chunk->size() - offset_in_chunk;
    }

    return sync_read(r_cast< char* >(buf), size, chunk, offset_in_chunk);
}

void JournalVirtualDev::sync_preadv(iovec* iov, int iovcnt, off_t offset) {
    uint64_t len = VirtualDev::get_len(iov, iovcnt);
    auto const [chunk, offset_in_chunk] = offset_to_chunk(offset);

    if (chunk->size() - offset_in_chunk < len) {
        if (iovcnt > 1) {
            throw std::out_of_range(
                "iovector more than 1 element is not supported when requested read len is acrossing chunk boundary");
        }

        // truncate requsted read length to end of chunk;
        len = chunk->size() - offset_in_chunk;
        iov[0].iov_len = len; // is this needed?
    }

    sync_readv(iov, iovcnt, chunk, offset_in_chunk);
}

off_t JournalVirtualDev::lseek(off_t offset, int whence) {
    switch (whence) {
    case SEEK_SET:
        m_seek_cursor = offset;
        break;
    case SEEK_CUR:
        m_seek_cursor += offset;
        break;
    case SEEK_END:
    default:
        HS_DBG_ASSERT(false, "Not supported seek type: {}", whence);
        break;
    }

    return m_seek_cursor;
}

/**
 * @brief :- it returns the vdev offset after nbytes from start offset
 */
off_t JournalVirtualDev::dev_offset(off_t nbytes) const {
    off_t vdev_offset = data_start_offset();
    uint32_t dev_id{0}, chunk_id{0};
    off_t offset_in_chunk{0};
    off_t cur_read_cur{0};

    while (cur_read_cur != nbytes) {
        auto const [chunk, offset_in_chunk] = offset_to_chunk(vdev_offset);

        auto const end_of_chunk = chunk->end_of_chunk();
        auto const chunk_size = std::min< uint64_t >(end_of_chunk, chunk->size());
        auto const remaining = nbytes - cur_read_cur;
        if (remaining >= (static_cast< off_t >(chunk->size()) - offset_in_chunk)) {
            cur_read_cur += (chunk->size() - offset_in_chunk);
            vdev_offset += (chunk->size() - offset_in_chunk);
            vdev_offset = vdev_offset % size();
        } else {
            vdev_offset += remaining;
            cur_read_cur = nbytes;
        }
    }
    return vdev_offset;
}

off_t JournalVirtualDev::tail_offset(bool reserve_space_include) const {
    off_t tail = static_cast< off_t >(data_start_offset() + m_write_sz_in_total.load(std::memory_order_relaxed));
    if (reserve_space_include) { tail += m_reserved_sz; }
    if (static_cast< uint64_t >(tail) >= size()) { tail -= size(); }

    return tail;
}

void JournalVirtualDev::update_tail_offset(off_t tail) {
    const off_t start = data_start_offset();
    HS_LOG(INFO, device, "total_size: {}, tail is being updated to: {}, start: {}", to_hex(size()), to_hex(tail),
           to_hex(start));

    if (tail >= start) {
        m_write_sz_in_total.store(tail - start, std::memory_order_relaxed);
    } else {
        m_write_sz_in_total.store(size() - start + tail, std::memory_order_relaxed);
    }
    lseek(tail);

    HS_LOG(INFO, device, "m_write_sz_in_total updated to: {}", to_hex(m_write_sz_in_total.load()));

    HS_REL_ASSERT(tail_offset() == tail, "tail offset mismatch after calculation {} : {}", tail_offset(), tail);
}

void JournalVirtualDev::truncate(off_t offset) {
    const off_t ds_off = data_start_offset();

    COUNTER_INCREMENT(m_metrics, vdev_truncate_count, 1);

    HS_PERIODIC_LOG(INFO, device, "truncating to logical offset: {}, start: {}, m_write_sz_in_total: {} ",
                    to_hex(offset), to_hex(ds_off), to_hex(m_write_sz_in_total.load()));

    uint64_t size_to_truncate{0};
    if (offset >= ds_off) {
        // the truncate offset is larger than current start offset
        size_to_truncate = offset - ds_off;
    } else {
        // the truncate offset is smaller than current start offset, meaning we are looping back to previous chunks;
        HS_PERIODIC_LOG(INFO, device,
                        "Loop-back truncating to logical offset: {} which is smaller than current data start "
                        "offset: {}, m_write_sz_in_total: {}",
                        to_hex(offset), to_hex(ds_off), to_hex(m_write_sz_in_total.load()));
        size_to_truncate = size() - (ds_off - offset);
        HS_REL_ASSERT_GE(m_write_sz_in_total.load(), size_to_truncate, "invalid truncate offset");
        HS_REL_ASSERT_GE(tail_offset(), offset);
    }

    // update in-memory total write size counter;
    m_write_sz_in_total.fetch_sub(size_to_truncate, std::memory_order_relaxed);

    // Update our start offset, to keep track of actual size
    update_data_start_offset(offset);

    HS_PERIODIC_LOG(INFO, device, "after truncate: m_write_sz_in_total: {}, start: {} ",
                    to_hex(m_write_sz_in_total.load()), to_hex(data_start_offset()));
    m_truncate_done = true;
}

#if 0
uint64_t JournalVirtualDev::get_offset_in_dev(uint32_t dev_id, uint32_t chunk_id, uint64_t offset_in_chunk) const {
    return get_chunk_start_offset(dev_id, chunk_id) + offset_in_chunk;
}

uint64_t JournalVirtualDev::get_chunk_start_offset(uint32_t dev_id, uint32_t chunk_id) const {
    return m_primary_pdev_chunks_list[dev_id].chunks_in_pdev[chunk_id]->start_offset();
}

uint64_t JournalVirtualDev::logical_to_dev_offset(off_t log_offset, uint32_t& dev_id, uint32_t& chunk_id,
                                                  off_t& offset_in_chunk) const {
    dev_id = 0;
    chunk_id = 0;
    offset_in_chunk = 0;

    uint64_t off_l{static_cast< uint64_t >(log_offset)};
    for (size_t d{0}; d < m_primary_pdev_chunks_list.size(); ++d) {
        for (size_t c{0}; c < m_primary_pdev_chunks_list[d].chunks_in_pdev.size(); ++c) {
            if (off_l >= m_chunk_size) {
                off_l -= m_chunk_size;
            } else {
                dev_id = d;
                chunk_id = c;
                offset_in_chunk = off_l;

                return get_offset_in_dev(dev_id, chunk_id, offset_in_chunk);
            }
        }
    }

    HS_DBG_ASSERT(false, "Input log_offset is invalid: {}, should be between 0 ~ {}", log_offset,
                  m_chunk_size * m_num_chunks);
    return 0;
}
#endif

std::pair< cshared< Chunk >&, off_t > JournalVirtualDev::offset_to_chunk(off_t log_offset) const {
    uint64_t off_l{static_cast< uint64_t >(log_offset)};
    for (const auto& chunk : m_all_chunks) {
        if (off_l >= chunk->size()) {
            off_l -= chunk->size();
        } else {
            return std::pair< cshared< Chunk >&, off_t >(chunk, off_l);
        }
    }

    HS_DBG_ASSERT(false, "Input log_offset is invalid: {}", log_offset);
    return std::pair(nullptr, 0);
}

void JournalVirtualDev::high_watermark_check() {
    if (resource_mgr().check_journal_size(used_size(), size())) {
        COUNTER_INCREMENT(m_metrics, vdev_high_watermark_count, 1);

        if (m_event_cb && m_truncate_done) {
            // don't send high watermark callback repeated until at least one truncate has been received;
            HS_LOG(INFO, device, "Callback to client for high watermark warning.");
            m_event_cb(*this, vdev_event_t::SIZE_THRESHOLD_REACHED, "High watermark reached");
            m_truncate_done = false;
        }
    }
}

bool JournalVirtualDev::is_alloc_accross_chunk(size_t size) const {
    auto const [chunk, offset_in_chunk] = offset_to_chunk(tail_offset());
    return (offset_in_chunk + size > chunk->size());
}

nlohmann::json JournalVirtualDev::get_status(int log_level) const {
    nlohmann::json j;
    j["VirtualDev"] = VirtualDev::get_status(log_level);
    j["JournalVirtualDev"]["m_seek_cursor"] = m_seek_cursor;
    j["JournalVirtualDev"]["data_start_offset"] = m_data_start_offset;
    j["JournalVirtualDev"]["write_size"] = m_write_sz_in_total.load(std::memory_order_relaxed);
    j["JournalVirtualDev"]["truncate_done"] = m_truncate_done;
    j["JournalVirtualDev"]["reserved_size"] = m_reserved_sz;
    return j;
}
} // namespace homestore
