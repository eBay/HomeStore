#include <array>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <functional>
#include <iterator>
#include <limits>
#include <memory>
#include <map>
#include <mutex>
#include <string>
#include <system_error>
#include <type_traits>
#include <vector>

#include <sisl/fds/buffer.hpp>
#include <sisl/metrics/metrics.hpp>
#include <sds_logging/logging.h>
#include <sisl/utility/atomic_counter.hpp>

#include "api/meta_interface.hpp"
#include "device.h"
#include "engine/blkalloc/blk_allocator.h"
#include "engine/blkalloc/varsize_blk_allocator.h"
#include "engine/common/error.h"
#include "engine/common/homestore_assert.hpp"
#include "engine/common/homestore_config.hpp"
#include "engine/common/homestore_header.hpp"
#include "engine/common/homestore_flip.hpp"
#include "engine/homestore_base.hpp"
#include "journal_vdev.hpp"
#include "engine/common/resource_mgr.hpp"

namespace homestore {

off_t JournalVirtualDev::alloc_next_append_blk(const size_t size, const bool chunk_overlap_ok) {
    HS_DEBUG_ASSERT_EQ(chunk_overlap_ok, false);

    if (get_used_size() + size > get_size()) {
        // not enough space left;
        HS_LOG(ERROR, device, "No space left! m_write_sz_in_total: {}, m_reserved_sz: {}", m_write_sz_in_total.load(),
               m_reserved_sz);
        return INVALID_OFFSET;
    }

#ifdef _PRERELEASE
    HomeStoreFlip::test_and_abort("abort_before_update_eof_cur_chunk");
#endif

    const off_t ds_off{data_start_offset()};
    const off_t end_offset{get_tail_offset()};
    off_t offset_in_chunk{0};
    uint32_t dev_id{0}, chunk_id{0};

    const auto dev_in_offset{logical_to_dev_offset(end_offset, dev_id, chunk_id, offset_in_chunk)};

#ifndef NDEBUG
    if (end_offset < ds_off) {
        HS_DEBUG_ASSERT_EQ(get_size() - get_used_size(), static_cast< uint64_t >(ds_off - end_offset));
    }
#endif
    // works for both "end_offset >= ds_off" and "end_offset < ds_off";
    if (offset_in_chunk + size <= m_chunk_size) {
        // not acrossing boundary, nothing to do;
    } else if ((get_used_size() + (m_chunk_size - offset_in_chunk) + size) <= get_size()) {
        // across chunk boundary, still enough space;

        // Update the overhead to total write size;
        m_write_sz_in_total.fetch_add(m_chunk_size - offset_in_chunk, std::memory_order_relaxed);

        // If across chunk boudary, update the chunk super-block of the chunk size
        auto* chunk{m_primary_pdev_chunks_list[dev_id].chunks_in_pdev[chunk_id]};
        m_mgr->update_end_of_chunk(chunk, offset_in_chunk);

#ifdef _PRERELEASE
        HomeStoreFlip::test_and_abort("abort_after_update_eof_cur_chunk");
#endif
        // get next chunk handle
        auto* next_chunk{get_next_chunk(dev_id, chunk_id)};
        if (next_chunk != chunk) {
            // Since we are re-using a new chunk, update this chunk's end as its original size;
            m_mgr->update_end_of_chunk(next_chunk, m_chunk_size);
        }
    } else {
        // across chunk boundary and no space left;
        HS_LOG(ERROR, device, "No space left! m_write_sz_in_total: {}, m_reserved_sz: {}", m_write_sz_in_total.load(),
               m_reserved_sz);
        return INVALID_OFFSET;
        // m_reserved_sz stays sthe same;
    }

    // if we made a successful reserve, return the tail offset;
    const off_t offset{get_tail_offset()};

    // update reserved size;
    m_reserved_sz += size;

    high_watermark_check();

#ifdef _PRERELEASE
    HomeStoreFlip::test_and_abort("abort_after_update_eof_next_chunk");
#endif
    // assert that returnning logical offset is in good range;
    HS_DEBUG_ASSERT_LE(static_cast< uint64_t >(offset), get_size());
    return offset;
}

ssize_t JournalVirtualDev::write(const void* buf, const size_t count,
                                 const boost::intrusive_ptr< virtualdev_req >& req) {
    if (get_used_size() + count > get_size()) {
        // not enough space left;
        HS_LOG(ERROR, device, "No space left! m_write_sz_in_total: {}, m_reserved_sz: {}", m_write_sz_in_total.load(),
               m_reserved_sz);
        return -1;
    }

    if (m_reserved_sz != 0) {
        HS_LOG(ERROR, device, "write can't be served when m_reserved_sz:{} is not comsumed by pwrite yet.",
               m_reserved_sz);
        return -1;
    }

    const auto bytes_written{do_pwrite(buf, count, m_seek_cursor, req)};
    m_seek_cursor += bytes_written;

    return bytes_written;
}

/**
 * @brief : writes up to count bytes from the buffer starting at buf at offset offset.
 * The cursor is not changed.
 * pwrite always use offset returned from alloc_next_append_blk to do the write;
 * pwrite should not across chunk boundaries because alloc_next_append_blk guarantees offset returned always doesn't
 * across chunk boundary;
 *
 * @param buf : buffer pointing to the data being written
 * @param count : size of buffer to be written
 * @param offset : offset to be written
 * @param req : async req
 *
 * @return : On success, the number of bytes read or written is returned, or -1 on error.
 */
ssize_t JournalVirtualDev::pwrite(const void* buf, const size_t count, const off_t offset,
                                  const boost::intrusive_ptr< virtualdev_req >& req) {
    HS_RELEASE_ASSERT_LE(count, m_reserved_sz, "Write size: larger then reserved size is not allowed!");

    // update reserved size
    m_reserved_sz -= count;

    // pwrite works with alloc_next_append_blk which already do watermark check;
    return do_pwrite(buf, count, offset, req);
}

ssize_t JournalVirtualDev::pwritev(const iovec* iov, const int iovcnt, const off_t offset,
                                   const boost::intrusive_ptr< virtualdev_req >& req) {
    uint32_t dev_id{0}, chunk_id{0};
    const auto len{VirtualDev::get_len(iov, iovcnt)};

    // if len is smaller than reserved size, it means write will never be overlapping start offset;
    // it is guaranteed by alloc_next_append_blk api;
    HS_RELEASE_ASSERT_LE(len, m_reserved_sz, "Write size:{} larger then reserved size: {} is not allowed!", len,
                         m_reserved_sz);

    m_reserved_sz -= len;

    const auto offset_in_dev{process_pwrite_offset(len, offset, dev_id, chunk_id, req)};

    ssize_t bytes_written{0};
    try {
        PhysicalDevChunk* chunk{m_primary_pdev_chunks_list[dev_id].chunks_in_pdev[chunk_id]};
        auto* pdev{m_primary_pdev_chunks_list[dev_id].pdev};

        LOGDEBUG("Writing in device: {}, offset: {}, m_write_sz_in_total: {}, start off: {}", to_hex(dev_id),
                 to_hex(offset_in_dev), to_hex(m_write_sz_in_total.load()), to_hex(data_start_offset()));

        bytes_written = do_pwritev_internal(pdev, chunk, iov, iovcnt, len, offset_in_dev, req);

        // bytes written should always equal to requested write size, since alloc_next_append_blk handles offset
        // which will never across chunk boundary;
        HS_DEBUG_ASSERT_EQ((uint64_t)bytes_written, len, "Bytes written not equal to input len!");

    } catch (const std::exception& e) { HS_ASSERT(DEBUG, 0, "{}", e.what()); }

    return bytes_written;
}

ssize_t JournalVirtualDev::read(void* buf, const size_t count_in) {
    size_t count{count_in};
    uint32_t dev_id{0}, chunk_id{0};
    off_t offset_in_chunk{0};

    logical_to_dev_offset(m_seek_cursor, dev_id, chunk_id, offset_in_chunk);

    auto* chunk{m_primary_pdev_chunks_list[dev_id].chunks_in_pdev[chunk_id]};
    const auto end_of_chunk{chunk->get_end_of_chunk()};
    const auto chunk_size{std::min< uint64_t >(end_of_chunk, m_chunk_size)};

    bool across_chunk{false};

    HS_RELEASE_ASSERT_LE((uint64_t)end_of_chunk, m_chunk_size, "Invalid end of chunk: {} detected on chunk num: {}",
                         end_of_chunk, chunk->get_chunk_id());
    HS_RELEASE_ASSERT_LE((uint64_t)offset_in_chunk, chunk_size,
                         "Invalid m_seek_cursor: {} which falls in beyond end of chunk: {}!", m_seek_cursor,
                         end_of_chunk);

    // if read size is larger then what's left in this chunk
    if (count >= (chunk_size - offset_in_chunk)) {
        // truncate size to what is left;
        count = chunk_size - offset_in_chunk;
        across_chunk = true;
    }

    const auto bytes_read{pread(buf, count, m_seek_cursor)};

    if (bytes_read != -1) {
        // Update seek cursor after read;
        HS_RELEASE_ASSERT_EQ((size_t)bytes_read, count, "bytes_read returned: {} must be equal to requested size: {}!",
                             bytes_read, count);
        m_seek_cursor += bytes_read;
        if (across_chunk) { m_seek_cursor += (m_chunk_size - end_of_chunk); }
        m_seek_cursor = m_seek_cursor % get_size();
    }

    return bytes_read;
}

ssize_t JournalVirtualDev::pread(void* buf, const size_t count_in, const off_t offset,
                                 const boost::intrusive_ptr< virtualdev_req >& req) {
    size_t count{count_in};
    uint32_t dev_id{0}, chunk_id{0};
    off_t offset_in_chunk{0};

    const uint64_t offset_in_dev{logical_to_dev_offset(offset, dev_id, chunk_id, offset_in_chunk)};

    // if the read count is acrossing chunk, only return what's left in this chunk
    if (m_chunk_size - offset_in_chunk < count) {
        // truncate requsted rean length to end of chunk;
        count = m_chunk_size - offset_in_chunk;
    }

    auto* pdev{m_primary_pdev_chunks_list[dev_id].pdev};
    auto* pchunk{m_primary_pdev_chunks_list[dev_id].chunks_in_pdev[chunk_id]};

    return do_read_internal(pdev, pchunk, offset_in_dev, reinterpret_cast< char* >(buf), count);
}

ssize_t JournalVirtualDev::preadv(iovec* iov, const int iovcnt, const off_t offset,
                                  const boost::intrusive_ptr< virtualdev_req >& req) {
    uint32_t dev_id{0}, chunk_id{0};
    off_t offset_in_chunk{0};

    uint64_t len{VirtualDev::get_len(iov, iovcnt)};
    const uint64_t offset_in_dev{logical_to_dev_offset(offset, dev_id, chunk_id, offset_in_chunk)};

    if (m_chunk_size - offset_in_chunk < len) {
        HS_DEBUG_ASSERT_EQ(
            iovcnt, 1,
            "iovector more than 1 element is not supported when requested read len is acrossing chunk boundary.");
        if (iovcnt > 1) { return -1; }

        // truncate requsted read length to end of chunk;
        len = m_chunk_size - offset_in_chunk;

        iov[0].iov_len = len; // is this needed?
    }

    auto* pdev{m_primary_pdev_chunks_list[dev_id].pdev};
    auto* chunk{m_primary_pdev_chunks_list[dev_id].chunks_in_pdev[chunk_id]};

    return do_preadv_internal(pdev, chunk, offset_in_dev, iov, iovcnt, len, req);
}

off_t JournalVirtualDev::lseek(const off_t offset, const int whence) {
    switch (whence) {
    case SEEK_SET:
        m_seek_cursor = offset;
        break;
    case SEEK_CUR:
        m_seek_cursor += offset;
        break;
    case SEEK_END:
    default:
        HS_ASSERT(DEBUG, false, "Not supported seek type: {}", whence);
        break;
    }

    return m_seek_cursor;
}

/**
 * @brief :- it returns the vdev offset after nbytes from start offset
 */
off_t JournalVirtualDev::get_dev_offset(const off_t nbytes) const {
    off_t vdev_offset{data_start_offset()};
    uint32_t dev_id{0}, chunk_id{0};
    off_t offset_in_chunk{0};
    off_t cur_read_cur{0};

    while (cur_read_cur != nbytes) {
        logical_to_dev_offset(vdev_offset, dev_id, chunk_id, offset_in_chunk);

        auto* chunk{m_primary_pdev_chunks_list[dev_id].chunks_in_pdev[chunk_id]};
        const auto end_of_chunk{chunk->get_end_of_chunk()};
        const auto chunk_size{std::min< uint64_t >(end_of_chunk, m_chunk_size)};
        const auto remaining{nbytes - cur_read_cur};
        if (remaining >= (static_cast< off_t >(chunk_size) - offset_in_chunk)) {
            cur_read_cur += (chunk_size - offset_in_chunk);
            vdev_offset += (m_chunk_size - offset_in_chunk);
            vdev_offset = vdev_offset % get_size();
        } else {
            vdev_offset += remaining;
            cur_read_cur = nbytes;
        }
    }
    return vdev_offset;
}

off_t JournalVirtualDev::get_tail_offset(const bool reserve_space_include) const {
    off_t tail{static_cast< off_t >(data_start_offset() + m_write_sz_in_total.load(std::memory_order_relaxed))};
    if (reserve_space_include) { tail += m_reserved_sz; }
    if (static_cast< uint64_t >(tail) >= get_size()) { tail -= get_size(); }

    return tail;
}

void JournalVirtualDev::update_tail_offset(const off_t tail) {
    const off_t start{data_start_offset()};
    HS_LOG(INFO, device, "total_size: {}, tail is being updated to: {}, start: {}", to_hex(get_size()), to_hex(tail),
           to_hex(start));

    if (tail >= start) {
        m_write_sz_in_total.store(tail - start, std::memory_order_relaxed);
    } else {
        m_write_sz_in_total.store(get_size() - start + tail, std::memory_order_relaxed);
    }
    lseek(tail);

    HS_LOG(INFO, device, "m_write_sz_in_total updated to: {}", to_hex(m_write_sz_in_total.load()));

    HS_ASSERT(RELEASE, get_tail_offset() == tail, "tail offset mismatch after calculation {} : {}", get_tail_offset(),
              tail);
}

void JournalVirtualDev::truncate(const off_t offset) {
    const off_t ds_off{data_start_offset()};

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
        size_to_truncate = get_size() - (ds_off - offset);
        HS_RELEASE_ASSERT_GE(m_write_sz_in_total.load(), size_to_truncate, "invalid truncate offset");
        HS_RELEASE_ASSERT_GE(get_tail_offset(), offset);
    }

    // update in-memory total write size counter;
    m_write_sz_in_total.fetch_sub(size_to_truncate, std::memory_order_relaxed);

    // Update our start offset, to keep track of actual size
    update_data_start_offset(offset);

    HS_PERIODIC_LOG(INFO, device, "after truncate: m_write_sz_in_total: {}, start: {} ",
                    to_hex(m_write_sz_in_total.load()), to_hex(data_start_offset()));
    m_truncate_done = true;
}

off_t JournalVirtualDev::process_pwrite_offset(const size_t len, const off_t offset, uint32_t& dev_id,
                                               uint32_t& chunk_id, const boost::intrusive_ptr< virtualdev_req >& req) {
    off_t offset_in_chunk{0};

    if (req) {
        req->outstanding_cb.set(1);
        req->outstanding_cbs = true;
    }

    // convert logical offset to dev offset
    const uint64_t offset_in_dev{logical_to_dev_offset(offset, dev_id, chunk_id, offset_in_chunk)};

    // this assert only valid for pwrite/pwritev, which calls alloc_next_append_blk to get the offset to do the
    // write, which guarantees write will with the returned offset will not accross chunk boundary.
    HS_RELEASE_ASSERT_GE(m_chunk_size - offset_in_chunk, len, "Writing size: {} crossing chunk is not allowed!", len);

    m_write_sz_in_total.fetch_add(len, std::memory_order_relaxed);

    PhysicalDevChunk* chunk{m_primary_pdev_chunks_list[dev_id].chunks_in_pdev[chunk_id]};
    if (req) {
        req->version = 0xDEAD;
        req->cb = std::bind(&VirtualDev::process_completions, this, std::placeholders::_1);
        req->size = len;
        req->chunk = chunk;
    }

    return offset_in_dev;
}

ssize_t JournalVirtualDev::do_pwrite(const void* buf, const size_t count, const off_t offset,
                                     const boost::intrusive_ptr< virtualdev_req >& req) {
    uint32_t dev_id{0}, chunk_id{0};

    const auto offset_in_dev{process_pwrite_offset(count, offset, dev_id, chunk_id, req)};

    ssize_t bytes_written{0};
    try {
        PhysicalDevChunk* chunk{m_primary_pdev_chunks_list[dev_id].chunks_in_pdev[chunk_id]};

        auto* pdev{m_primary_pdev_chunks_list[dev_id].pdev};

        HS_LOG(TRACE, device, "Writing in device: {}, offset: {}", dev_id, offset_in_dev);

        bytes_written =
            do_pwrite_internal(pdev, chunk, reinterpret_cast< const char* >(buf), count, offset_in_dev, req);

        // bytes written should always equal to requested write size, since alloc_next_append_blk handles offset
        // which will never across chunk boundary;
        HS_DEBUG_ASSERT_EQ(static_cast< size_t >(bytes_written), count, "Bytes written not equal to input len!");

    } catch (const std::exception& e) { HS_ASSERT(DEBUG, 0, "{}", e.what()); }

    return bytes_written;
}

uint64_t JournalVirtualDev::get_offset_in_dev(const uint32_t dev_id, const uint32_t chunk_id,
                                              const uint64_t offset_in_chunk) const {
    return get_chunk_start_offset(dev_id, chunk_id) + offset_in_chunk;
}

uint64_t JournalVirtualDev::get_chunk_start_offset(const uint32_t dev_id, const uint32_t chunk_id) const {
    return m_primary_pdev_chunks_list[dev_id].chunks_in_pdev[chunk_id]->get_start_offset();
}

uint64_t JournalVirtualDev::logical_to_dev_offset(const off_t log_offset, uint32_t& dev_id, uint32_t& chunk_id,
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

    HS_ASSERT(DEBUG, false, "Input log_offset is invalid: {}, should be between 0 ~ {}", log_offset,
              m_chunk_size * m_num_chunks);
    return 0;
}

void JournalVirtualDev::high_watermark_check() {
    if (ResourceMgrSI().check_journal_size(get_used_size(), get_size())) {
        COUNTER_INCREMENT(m_metrics, vdev_high_watermark_count, 1);

        if (m_hwm_cb && m_truncate_done) {
            // don't send high watermark callback repeated until at least one truncate has been received;
            HS_LOG(INFO, device, "Callback to client for high watermark warning.");
            m_hwm_cb();
            m_truncate_done = false;
        }
    }
}

nlohmann::json JournalVirtualDev::get_status(const int log_level) const {
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
