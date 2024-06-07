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
#include <homestore/logstore_service.hpp>
#include <homestore/replication_service.hpp>
#include "replication/repl_dev/raft_repl_dev.h"
#include "device/chunk.h"
#include "device/device.h"
#include "device/physical_dev.hpp"
#include "device/journal_vdev.hpp"
#include "common/error.h"
#include "common/homestore_assert.hpp"
#include "common/homestore_utils.hpp"
#include "common/resource_mgr.hpp"
#include "common/crash_simulator.hpp"

SISL_LOGGING_DECL(journalvdev)

namespace homestore {
JournalVirtualDev::JournalVirtualDev(DeviceManager& dmgr, const vdev_info& vinfo, vdev_event_cb_t event_cb) :
        VirtualDev{dmgr, vinfo, std::move(event_cb), false /* is_auto_recovery */} {

    // Private data stored when chunks are created.
    m_init_private_data = std::make_shared< JournalChunkPrivate >();
    m_chunk_pool = std::make_unique< ChunkPool >(
        dmgr,
        ChunkPool::Params{HS_DYNAMIC_CONFIG(generic.journal_chunk_pool_capacity),
                          [this]() {
                              m_init_private_data->created_at = get_time_since_epoch_ms();
                              m_init_private_data->end_of_chunk = m_vdev_info.chunk_size;
                              sisl::blob private_blob{r_cast< uint8_t* >(m_init_private_data.get()),
                                                      sizeof(JournalChunkPrivate)};
                              return private_blob;
                          },
                          m_vdev_info.hs_dev_type, m_vdev_info.vdev_id, m_vdev_info.chunk_size});

    resource_mgr().register_journal_vdev_exceed_cb([this]([[maybe_unused]] int64_t dirty_buf_count, bool critical) {
        // either it is critical or non-critical, call cp_flush;
        hs()->cp_mgr().trigger_cp_flush(false /* force */);

        if (critical) {
            LOGINFO("Critical journal vdev size threshold reached. Triggering truncate.");
            resource_mgr().trigger_truncate();
        }
    });
}

JournalVirtualDev::~JournalVirtualDev() {}

void JournalVirtualDev::init() {
    struct HeadChunk {
        chunk_num_t chunk_num{};
        uint64_t created_at{};
    };

    // Create a mapp of logdev_id to the head chunk and chunk_id to chunk.
    std::unordered_map< logdev_id_t, HeadChunk > logdev_head_map;
    std::unordered_map< chunk_num_t, shared< Chunk > > chunk_map;
    std::unordered_set< chunk_num_t > visited_chunks;

    // Traverse the chunks and find the heads of the logdev_id's.
    for (auto& [_, chunk] : m_all_chunks) {
        auto* data = r_cast< JournalChunkPrivate* >(const_cast< uint8_t* >(chunk->user_private()));
        auto chunk_id = chunk->chunk_id();
        auto logdev_id = data->logdev_id;
        // Create index for chunks.
        chunk_map[chunk_id] = chunk;
        if (data->is_head) {
            // Store the head which has the latest creation timestamp.
            if (data->created_at > logdev_head_map[logdev_id].created_at) {
                logdev_head_map[logdev_id] = HeadChunk{chunk_id, data->created_at};
            }
        }
    }

    for (auto& [logdev_id, head] : logdev_head_map) {
        // Create descriptor for each logdev_id
        auto journal_desc = std::make_shared< JournalVirtualDev::Descriptor >(*this, logdev_id);
        m_journal_descriptors.emplace(logdev_id, journal_desc);
        LOGINFOMOD(journalvdev, "Loading descriptor log_dev={}", logdev_id);
        // Traverse the list starting from the head and add those chunks
        // in order to the journal descriptor. next_chunk is stored in private_data.
        // Last chunk will have next_chunk as 0.
        auto chunk_num = head.chunk_num;
        while (chunk_num != 0) {
            auto& c = chunk_map[chunk_num];
            RELEASE_ASSERT(c, "Invalid chunk found log_dev={} chunk={}", logdev_id, c->to_string());
            journal_desc->m_journal_chunks.push_back(c);
            visited_chunks.insert(chunk_num);
            LOGINFOMOD(journalvdev, "Loading log_dev={} chunk={}", logdev_id, c->to_string());

            // Increase the the total size.
            journal_desc->m_total_size += c->size();

            auto data = r_cast< JournalChunkPrivate* >(const_cast< uint8_t* >(c->user_private()));
            chunk_num = data->next_chunk;
        }
    }

    // Chunks which are not in visited set are orphans and needs to be cleaned up.
    // Remove chunk will affect the m_all_chunks so keep a separate list.
    std::vector< shared< Chunk > > orphan_chunks;
    for (auto& [_, chunk] : m_all_chunks) {
        if (!visited_chunks.count(chunk->chunk_id())) { orphan_chunks.push_back(chunk); }
    }

    // Remove the orphan chunks.
    if (!orphan_chunks.empty()) {
        LOGINFOMOD(journalvdev, "Removing orphan chunks");
        remove_journal_chunks(orphan_chunks);
    }

    // Start the chunk pool.
    m_chunk_pool->start();
    LOGINFO("Journal vdev init done");
}

void JournalVirtualDev::remove_journal_chunks(std::vector< shared< Chunk > >& chunks) {
    for (auto& chunk : chunks) {
        auto* data = r_cast< JournalChunkPrivate* >(const_cast< uint8_t* >(chunk->user_private()));
        auto chunk_id = chunk->chunk_id();
        auto logdev_id = data->logdev_id;
        auto next_chunk = data->next_chunk;

        // Clear the private chunk data.
        *data = JournalChunkPrivate{};
        update_chunk_private(chunk, data);

        LOGINFOMOD(journalvdev, "Removing chunk {} found for logdev {} next {}.", chunk_id, logdev_id, next_chunk);
        m_dmgr.remove_chunk_locked(chunk);
    }
}

void JournalVirtualDev::update_chunk_private(shared< Chunk >& chunk, JournalChunkPrivate* private_data) {
    sisl::blob private_blob{r_cast< uint8_t* >(private_data), sizeof(JournalChunkPrivate)};
    chunk->set_user_private(private_blob);
}

uint64_t JournalVirtualDev::get_end_of_chunk(shared< Chunk >& chunk) const {
    auto* private_data = r_cast< JournalChunkPrivate* >(const_cast< uint8_t* >(chunk->user_private()));
    return private_data->end_of_chunk;
}

shared< JournalVirtualDev::Descriptor > JournalVirtualDev::open(logdev_id_t logdev_id) {
    auto it = m_journal_descriptors.find(logdev_id);
    if (it == m_journal_descriptors.end()) {
        auto journal_desc = std::make_shared< JournalVirtualDev::Descriptor >(*this, logdev_id);
        m_journal_descriptors.emplace(logdev_id, journal_desc);
        return journal_desc;
    }

    LOGINFOMOD(journalvdev, "Opened journal vdev descriptor log_dev={}", logdev_id);
    for (auto& chunk : it->second->m_journal_chunks) {
        LOGINFOMOD(journalvdev, " log_dev={} end_of_chunk={} chunk={}", logdev_id, get_end_of_chunk(chunk),
                   chunk->to_string());
    }
    return it->second;
}

void JournalVirtualDev::destroy(logdev_id_t logdev_id) {
    auto it = m_journal_descriptors.find(logdev_id);
    if (it == m_journal_descriptors.end()) {
        LOGERROR("logdev not found log_dev={}", logdev_id);
        return;
    }

    // Remove all the chunks.
    remove_journal_chunks(it->second->m_journal_chunks);
    m_journal_descriptors.erase(it);
    LOGINFOMOD(journalvdev, "Journal vdev destroyed log_dev={}", logdev_id);
}

void JournalVirtualDev::Descriptor::append_chunk() {
    // Get a new chunk from the pool.
    auto new_chunk = m_vdev.m_chunk_pool->dequeue();

    // Increase the right window and total size.
    m_total_size += new_chunk->size();
    m_end_offset += new_chunk->size();

    if (!m_journal_chunks.empty()) {
        // If there are already chunks in the m_journal_chunks list, append this new chunk to the end of the list. Write
        // the next_chunk of the last chunk in the list to point to this new chunk. If already there are no chunks make
        // the new chunk as the head.
        auto last_chunk = m_journal_chunks.back();
        auto* last_chunk_private = r_cast< JournalChunkPrivate* >(const_cast< uint8_t* >(last_chunk->user_private()));

        // Set the next chunk with the newly created chunk id.
        last_chunk_private->next_chunk = new_chunk->chunk_id();

        // Append the new chunk
        m_journal_chunks.push_back(new_chunk);
        auto chunk_size = m_vdev.info().chunk_size;
        auto offset_in_chunk = (tail_offset() % chunk_size);
        if (offset_in_chunk != 0) {
            // Update the overhead to total write size
            m_write_sz_in_total.fetch_add(last_chunk->size() - offset_in_chunk, std::memory_order_relaxed);
            last_chunk_private->end_of_chunk = offset_in_chunk;
        }
        m_vdev.update_chunk_private(last_chunk, last_chunk_private);
        LOGINFOMOD(journalvdev, "Added chunk new {} last {} desc {}", new_chunk->to_string(), last_chunk->chunk_id(),
                   to_string());

    } else {
        // If the list is empty, update the new chunk as the head. Only head chunk contains the logdev_id.
        auto* new_chunk_private = r_cast< JournalChunkPrivate* >(const_cast< uint8_t* >(new_chunk->user_private()));
        new_chunk_private->is_head = true;
        new_chunk_private->logdev_id = m_logdev_id;
        new_chunk_private->end_of_chunk = m_vdev.info().chunk_size;
        // Append the new chunk
        m_journal_chunks.push_back(new_chunk);
        m_vdev.update_chunk_private(new_chunk, new_chunk_private);
        LOGINFOMOD(journalvdev, "Added head chunk={} desc {}", new_chunk->to_string(), to_string());
    }
}

off_t JournalVirtualDev::Descriptor::alloc_next_append_blk(size_t sz) {
    // We currently assume size requested is less than chunk_size.
    auto chunk_size = m_vdev.info().chunk_size;
    RELEASE_ASSERT_LT(sz, chunk_size, "Size requested greater than chunk size");

    if ((tail_offset() + static_cast< off_t >(sz)) >= m_end_offset) {
        // not enough space left, add a new chunk.
        LOGDEBUGMOD(journalvdev, "No space left for size {} Creating chunk desc {}", sz, to_string());

#ifdef _PRERELEASE
        if (hs()->crash_simulator().crash_if_flip_set("abort_before_update_eof_cur_chunk")) { return tail_offset(); }
#endif

        // Append a chunk to m_journal_chunks list. This will increase the m_end_offset.
        append_chunk();

#ifdef _PRERELEASE
        if (hs()->crash_simulator().crash_if_flip_set("abort_after_update_eof_next_chunk")) { return tail_offset(); }
#endif

        RELEASE_ASSERT((tail_offset() + static_cast< off_t >(sz)) < m_end_offset, "No space for append blk");
    }

    // if we made a successful reserve, return the tail offset;
    const off_t start_offset = data_start_offset();
    const off_t tail_off = tail_offset();
    RELEASE_ASSERT(tail_off >= start_offset, "Invalid start and tail offset");

    // update reserved size;
    m_reserved_sz += sz;

    high_watermark_check();

    // assert that returnning logical offset is in good range
    HS_DBG_ASSERT_LE(tail_off, m_end_offset);
    LOGDEBUGMOD(journalvdev, "returned tail_off 0x{} tail_off {} size {} desc {}", to_hex(tail_off), tail_off, sz,
                to_string());
    return tail_off;
}

bool JournalVirtualDev::Descriptor::validate_append_size(size_t req_sz) const {
    if (used_size() + req_sz > size()) {
        // not enough space left;
        HS_LOG(ERROR, device, "No space left! req_sz {} desc {}", req_sz, to_string());
        return false;
    }

    if (m_reserved_sz != 0) {
        HS_LOG(ERROR, device, "write can't be served when m_reserved_sz is not comsumed by pwrite yet {}", to_string());
        return false;
    }
    return true;
}

auto JournalVirtualDev::Descriptor::process_pwrite_offset(size_t len, off_t offset) {
    // convert logical offset to chunk and its offset
    auto const chunk_details = offset_to_chunk(offset);
    auto const [chunk, _, offset_in_chunk] = chunk_details;

    LOGTRACEMOD(journalvdev, "writing in chunk: {}, offset: 0x{} len: {} offset_in_chunk: 0x{} chunk_sz: {} desc {}",
                chunk->chunk_id(), to_hex(offset), len, to_hex(offset_in_chunk), chunk->size(), to_string());

    // this assert only valid for pwrite/pwritev, which calls alloc_next_append_blk to get the offset to do the
    // write, which guarantees write will with the returned offset will not accross chunk boundary.
    HS_REL_ASSERT_GE(chunk->size() - offset_in_chunk, len, "Writing size: {} crossing chunk is not allowed!", len);
    m_write_sz_in_total.fetch_add(len, std::memory_order_relaxed);

    return chunk_details;
}

/////////////////////////////// Write Section //////////////////////////////////
folly::Future< std::error_code > JournalVirtualDev::Descriptor::async_append(const uint8_t* buf, size_t size) {
    if (!validate_append_size(size)) {
        return folly::makeFuture< std::error_code >(std::make_error_code(std::errc::no_space_on_device));
    } else {
        auto const [chunk, _, offset_in_chunk] = process_pwrite_offset(size, m_seek_cursor);
        m_seek_cursor += size;
        return m_vdev.async_write(r_cast< const char* >(buf), size, chunk, offset_in_chunk);
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
folly::Future< std::error_code > JournalVirtualDev::Descriptor::async_pwrite(const uint8_t* buf, size_t size,
                                                                             off_t offset) {
    HS_REL_ASSERT_LE(size, m_reserved_sz, "Write size: larger then reserved size is not allowed!");
    m_reserved_sz -= size; // update reserved size

    auto const [chunk, _, offset_in_chunk] = process_pwrite_offset(size, offset);
    return m_vdev.async_write(r_cast< const char* >(buf), size, chunk, offset_in_chunk);
}

folly::Future< std::error_code > JournalVirtualDev::Descriptor::async_pwritev(const iovec* iov, int iovcnt,
                                                                              off_t offset) {
    auto const size = VirtualDev::get_len(iov, iovcnt);

    // if size is smaller than reserved size, it means write will never be overlapping start offset;
    // it is guaranteed by alloc_next_append_blk api;
    HS_REL_ASSERT_LE(size, m_reserved_sz, "Write size: larger then reserved size: is not allowed!");

    m_reserved_sz -= size;
    auto const [chunk, _, offset_in_chunk] = process_pwrite_offset(size, offset);
    return m_vdev.async_writev(iov, iovcnt, chunk, offset_in_chunk);
}

void JournalVirtualDev::Descriptor::sync_pwrite(const uint8_t* buf, size_t size, off_t offset) {

    HS_REL_ASSERT_LE(size, m_reserved_sz, "Write size: larger then reserved size is not allowed!");
    m_reserved_sz -= size; // update reserved size

    auto const [chunk, index, offset_in_chunk] = process_pwrite_offset(size, offset);
    m_vdev.sync_write(r_cast< const char* >(buf), size, chunk, offset_in_chunk);
}

void JournalVirtualDev::Descriptor::sync_pwritev(const iovec* iov, int iovcnt, off_t offset) {
    auto const size = VirtualDev::get_len(iov, iovcnt);

    // if size is smaller than reserved size, it means write will never be overlapping start offset;
    // it is guaranteed by alloc_next_append_blk api;
    HS_REL_ASSERT_LE(size, m_reserved_sz, "Write size: larger then reserved size: is not allowed!");

    m_reserved_sz -= size;
    auto const [chunk, _, offset_in_chunk] = process_pwrite_offset(size, offset);
    m_vdev.sync_writev(iov, iovcnt, chunk, offset_in_chunk);
}

/////////////////////////////// Read Section //////////////////////////////////
size_t JournalVirtualDev::Descriptor::sync_next_read(uint8_t* buf, size_t size_rd) {
    if (m_journal_chunks.empty()) { return 0; }

    HS_REL_ASSERT_LE(m_seek_cursor, m_end_offset, "seek_cursor {} exceeded end_offset {}", m_seek_cursor, m_end_offset);
    if (m_seek_cursor >= m_end_offset) {
        LOGTRACEMOD(journalvdev, "sync_next_read reached end of chunks");
        return 0;
    }

    auto [chunk, _, offset_in_chunk] = offset_to_chunk(m_seek_cursor);
    auto const end_of_chunk = m_vdev.get_end_of_chunk(chunk);
    auto const chunk_size = std::min< uint64_t >(end_of_chunk, chunk->size());
    bool across_chunk{false};

    // LOGINFO("sync_next_read size_rd {} chunk {} seek_cursor {} end_of_chunk {} {}", size_rd, chunk->to_string(),
    //         m_seek_cursor, end_of_chunk, chunk_size);

    HS_REL_ASSERT_LE((uint64_t)end_of_chunk, chunk->size(), "Invalid end of chunk: {} detected on chunk num: {}",
                     end_of_chunk, chunk->chunk_id());
    HS_REL_ASSERT_LE((uint64_t)offset_in_chunk, chunk->size(),
                     "Invalid m_seek_cursor: {} which falls in beyond end of chunk: {}!", m_seek_cursor, end_of_chunk);

    // if read size is larger then what's left in this chunk
    if (size_rd >= (end_of_chunk - offset_in_chunk)) {
        // truncate size to what is left;
        size_rd = end_of_chunk - offset_in_chunk;
        across_chunk = true;
    }

    if (buf == nullptr) { return size_rd; }

    auto ec = sync_pread(buf, size_rd, m_seek_cursor);
    // TODO: Check if we can have tolerate this error and somehow start homestore without replaying or in degraded mode?
    HS_REL_ASSERT(!ec, "Error in reading next stream of bytes, proceeding could cause some inconsistency, exiting");

    // Update seek cursor after read;
    m_seek_cursor += size_rd;
    if (across_chunk) {
        m_seek_cursor += (chunk->size() - end_of_chunk);
        LOGTRACEMOD(journalvdev, "Across size_rd {} chunk {} seek_cursor {} end_of_chunk {}", size_rd,
                    chunk->to_string(), m_seek_cursor, end_of_chunk);
    }
    return size_rd;
}

std::error_code JournalVirtualDev::Descriptor::sync_pread(uint8_t* buf, size_t size, off_t offset) {
    auto [chunk, index, offset_in_chunk] = offset_to_chunk(offset);

    // if the read count is acrossing chunk, only return what's left in this chunk
    if (chunk->size() - offset_in_chunk < size) {
        // truncate requsted read length to end of chunk;
        size = chunk->size() - offset_in_chunk;
    }

    LOGTRACEMOD(journalvdev, "offset: 0x{} size: {} chunk: {} index: {} offset_in_chunk: 0x{} desc {}", to_hex(offset),
                size, chunk->chunk_id(), index, to_hex(offset_in_chunk), to_string());
    return m_vdev.sync_read(r_cast< char* >(buf), size, chunk, offset_in_chunk);
}

std::error_code JournalVirtualDev::Descriptor::sync_preadv(iovec* iov, int iovcnt, off_t offset) {
    uint64_t len = VirtualDev::get_len(iov, iovcnt);
    auto [chunk, index, offset_in_chunk] = offset_to_chunk(offset);

    if (chunk->size() - offset_in_chunk < len) {
        if (iovcnt > 1) {
            throw std::out_of_range(
                "iovector more than 1 element is not supported when requested read len is acrossing chunk boundary");
        }

        // truncate requsted read length to end of chunk;
        len = chunk->size() - offset_in_chunk;
        iov[0].iov_len = len; // is this needed?
    }

    LOGTRACEMOD(journalvdev, "offset: 0x{} iov: {} len: {} chunk: {} index: {} offset_in_chunk: 0x{} desc {}",
                to_hex(offset), iovcnt, len, chunk->chunk_id(), index, to_hex(offset_in_chunk), to_string());

    return m_vdev.sync_readv(iov, iovcnt, chunk, offset_in_chunk);
}

off_t JournalVirtualDev::Descriptor::lseek(off_t offset, int whence) {
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

    LOGINFOMOD(journalvdev, "lseek desc {} offset 0x{} whence {} ", to_string(), to_hex(offset), whence);
    return m_seek_cursor;
}

/**
 * @brief :- it returns the vdev offset after nbytes from start offset
 */
off_t JournalVirtualDev::Descriptor::dev_offset(off_t nbytes) const {
    if (nbytes == 0 || m_journal_chunks.empty()) {
        // If no chunks return start offset.
        return data_start_offset();
    }

    off_t vdev_offset = data_start_offset();
    auto chunk_size = m_vdev.info().chunk_size;
    uint64_t remaining = nbytes;
    auto start_offset = data_start_offset() % chunk_size;

    // data_start_offset coulde be anywhere in the first chunk.
    // because when we truncate and data_start_offset lies in first chunk
    // we dont delete that first chunk. other chunks will have start_offset as 0.
    for (auto chunk : m_journal_chunks) {
        uint64_t end_of_chunk = std::min< uint64_t >(m_vdev.get_end_of_chunk(chunk), chunk_size);

        auto num_data_bytes = end_of_chunk - start_offset;
        if (remaining < num_data_bytes) {
            vdev_offset += remaining;
            break;
        }

        remaining -= num_data_bytes;
        vdev_offset += (chunk_size - start_offset);
        start_offset = 0;
    }
    return vdev_offset;
}

void JournalVirtualDev::Descriptor::update_data_start_offset(off_t offset) {
    if (!m_journal_chunks.empty()) {
        m_data_start_offset = offset;
        auto data_start_offset_aligned = sisl::round_down(m_data_start_offset, m_vdev.info().chunk_size);
        m_end_offset = data_start_offset_aligned + m_journal_chunks.size() * m_vdev.info().chunk_size;
        LOGINFOMOD(journalvdev, "Updated data start offset off 0x{} {}", to_hex(offset), to_string());
        RELEASE_ASSERT_EQ(m_end_offset - data_start_offset_aligned, m_total_size, "offset size mismatch {}",
                          to_string());
    } else {
        // If there are no chunks, we round up to the next chunk size.
        m_data_start_offset = sisl::round_up(offset, m_vdev.info().chunk_size);
        m_end_offset = m_data_start_offset;
        LOGINFOMOD(journalvdev, "No chunks, updated data start offset off 0x{} {}", to_hex(offset), to_string());
    }
}

off_t JournalVirtualDev::Descriptor::tail_offset(bool reserve_space_include) const {
    off_t tail = static_cast< off_t >(data_start_offset() + m_write_sz_in_total.load(std::memory_order_relaxed));
    if (reserve_space_include) { tail += m_reserved_sz; }
    HS_REL_ASSERT(static_cast< int64_t >(tail) <= m_end_offset, "tail is more than offset tail {} offset {}", tail,
                  m_end_offset);
    return tail;
}

void JournalVirtualDev::Descriptor::update_tail_offset(off_t tail) {
    const off_t start = data_start_offset();

    if (tail >= start) {
        m_write_sz_in_total.store(tail - start, std::memory_order_relaxed);
    } else if (tail != 0) {
        LOGERROR("tail {} less than start offset {} desc {}", tail, start, to_string());
        RELEASE_ASSERT(false, "Invalid tail offset");
    }
    lseek(tail);

    LOGINFOMOD(journalvdev, "Updated tail offset arg 0x{} desc {} ", to_hex(tail), to_string());
}

void JournalVirtualDev::Descriptor::truncate(off_t truncate_offset) {
    const off_t ds_off = data_start_offset();

    COUNTER_INCREMENT(m_vdev.m_metrics, vdev_truncate_count, 1);

    HS_PERIODIC_LOG(DEBUG, journalvdev, "truncating to logical offset: 0x{} desc {}", to_hex(truncate_offset),
                    to_string());

    uint64_t size_to_truncate{0};
    if (truncate_offset >= ds_off) {
        // the truncate offset is larger than current start offset
        size_to_truncate = truncate_offset - ds_off;
    } else {
        RELEASE_ASSERT(false, "Loop-back not supported");
    }

    // Find the chunk which has the truncation offset. This will be the new
    // head chunk in the list. We first update the is_head is true of this chunk.
    // So if a crash happens after this, we could have two chunks which has is_head
    // true in the list and during recovery we select head with the highest creation
    // timestamp and reuse or cleanup the other.
    auto [new_head_chunk, _, offset_in_chunk] = offset_to_chunk(truncate_offset);
    auto* private_data = r_cast< JournalChunkPrivate* >(const_cast< uint8_t* >(new_head_chunk->user_private()));
    private_data->is_head = true;
    private_data->logdev_id = m_logdev_id;
    m_vdev.update_chunk_private(new_head_chunk, private_data);

    // Find all chunks which needs to be removed from the start of m_journal_chunks.
    // We stop till the truncation offset. Start from the old data_start_offset.
    // Align the data_start_offset to the chunk_size as we deleting chunks and
    // all chunks are same size in a journal vdev.
    uint32_t start = sisl::round_down(ds_off, m_vdev.info().chunk_size);
    for (auto it = m_journal_chunks.begin(); it != m_journal_chunks.end();) {
        auto chunk = *it;
        start += chunk->size();

        // Also if its the last chunk and there is no data after truncate, we release chunk.
        auto write_sz_in_total = m_write_sz_in_total.load(std::memory_order_relaxed);
        if (start >= truncate_offset) { break; }

        m_total_size -= chunk->size();
        it = m_journal_chunks.erase(it);

        // Clear the private chunk data before adding to pool.
        auto* data = r_cast< JournalChunkPrivate* >(const_cast< uint8_t* >(chunk->user_private()));
        *data = JournalChunkPrivate{};
        m_vdev.update_chunk_private(chunk, data);

        // We ideally want to zero out chunks as chunks are reused after free across
        // logdev's. But zero out chunk is very expensive, We look at crc mismatches
        // to know the end offset of the log dev during recovery.
        // Format and add back to pool.
        m_vdev.m_chunk_pool->enqueue(chunk);
        LOGINFOMOD(journalvdev, "After truncate released chunk {}", chunk->to_string());
    }

    // Update our start offset, to keep track of actual size
    HS_REL_ASSERT_LE(truncate_offset, m_end_offset, "truncate offset less than end offset");
    update_data_start_offset(truncate_offset);

    // update in-memory total write size counter;
    m_write_sz_in_total.fetch_sub(size_to_truncate, std::memory_order_relaxed);
    m_truncate_done = true;

    HS_PERIODIC_LOG(INFO, journalvdev, "After truncate desc {}", to_string());
}

#if 0
uint64_t JournalVirtualDev::Descriptor::get_offset_in_dev(uint32_t dev_id, uint32_t chunk_id, uint64_t offset_in_chunk) const {
    return get_chunk_start_offset(dev_id, chunk_id) + offset_in_chunk;
}

uint64_t JournalVirtualDev::Descriptor::get_chunk_start_offset(uint32_t dev_id, uint32_t chunk_id) const {
    return m_primary_pdev_chunks_list[dev_id].chunks_in_pdev[chunk_id]->start_offset();
}

uint64_t JournalVirtualDev::Descriptor::logical_to_dev_offset(off_t log_offset, uint32_t& dev_id, uint32_t& chunk_id,
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

std::tuple< shared< Chunk >, uint32_t, off_t > JournalVirtualDev::Descriptor::offset_to_chunk(off_t log_offset,
                                                                                              bool check) const {
    uint64_t chunk_aligned_offset = sisl::round_down(m_data_start_offset, m_vdev.info().chunk_size);
    uint64_t off_l{static_cast< uint64_t >(log_offset) - chunk_aligned_offset};
    uint32_t index = 0;
    for (auto& chunk : m_journal_chunks) {
        if (off_l >= chunk->size()) {
            off_l -= chunk->size();
            index++;
        } else {
            return {chunk, index, off_l};
        }
    }

    if (check) { HS_DBG_ASSERT(false, "Input log_offset is invalid: {} {}", log_offset, to_string()); }
    return {nullptr, 0L, 0L};
}

bool JournalVirtualDev::Descriptor::is_offset_at_last_chunk(off_t bytes_offset) {
    auto [chunk, chunk_index, _] = offset_to_chunk(bytes_offset, false);
    if (chunk == nullptr) return true;
    if (chunk_index == m_journal_chunks.size() - 1) { return true; }
    return false;
}

//
// This API is ways called in single thread
//
void JournalVirtualDev::Descriptor::high_watermark_check() {
#if 0
    // high watermark check for the individual journal descriptor;
    if (resource_mgr().check_journal_descriptor_size(used_size())) {
        // the next resource manager audit will call truncation for this descriptor;
        set_ready_for_truncate();
    }
#endif

    // high watermark check for the entire journal vdev;
    if (resource_mgr().check_journal_vdev_size(m_vdev.used_size(), m_vdev.size())) {
        COUNTER_INCREMENT(m_vdev.m_metrics, vdev_high_watermark_count, 1);

        if (m_vdev.m_event_cb && m_truncate_done) {
            // don't send high watermark callback repeated until at least one truncate has been received;
            HS_LOG(INFO, device, "Callback to client for high watermark warning.");
            m_vdev.m_event_cb(m_vdev, vdev_event_t::SIZE_THRESHOLD_REACHED, "High watermark reached");
            m_truncate_done = false;
        }
    }
}

bool JournalVirtualDev::Descriptor::is_alloc_accross_chunk(size_t size) const {
    auto [chunk, _, offset_in_chunk] = offset_to_chunk(tail_offset());
    return (offset_in_chunk + size > chunk->size());
}

nlohmann::json JournalVirtualDev::Descriptor::get_status(int log_level) const {
    nlohmann::json j;
    j["logdev"] = m_logdev_id;
    j["seek_cursor"] = m_seek_cursor;
    j["data_start_offset"] = m_data_start_offset;
    j["end_offset"] = m_end_offset;
    j["write_size"] = m_write_sz_in_total.load(std::memory_order_relaxed);
    j["truncate_done"] = m_truncate_done;
    j["reserved_size"] = m_reserved_sz;
    j["num_chunks"] = m_journal_chunks.size();
    j["total_size"] = m_total_size;
    if (log_level >= 3) {
        nlohmann::json chunk_js = nlohmann::json::array();
        for (const auto& chunk : m_journal_chunks) {
            nlohmann::json c;
            auto* private_data = r_cast< JournalChunkPrivate* >(const_cast< uint8_t* >(chunk->user_private()));
            c["chunk_id"] = chunk->chunk_id();
            c["logdev"] = private_data->logdev_id;
            c["is_head"] = private_data->is_head;
            c["end_of_chunk"] = private_data->end_of_chunk;
            c["next_chunk"] = private_data->next_chunk;
            chunk_js.push_back(move(c));
        }
        j["chunks"] = std::move(chunk_js);
    }

    LOGINFO("{}", j.dump(2, ' '));
    return j;
}

std::string JournalVirtualDev::Descriptor::to_string() const {
    off_t tail =
        static_cast< off_t >(data_start_offset() + m_write_sz_in_total.load(std::memory_order_relaxed)) + m_reserved_sz;
    std::string str{fmt::format("log_dev={};ds=0x{};end=0x{};writesz={};tail=0x{};"
                                "rsvdsz={};chunks={};trunc={};total={};seek=0x{} ",
                                m_logdev_id, to_hex(m_data_start_offset), to_hex(m_end_offset),
                                m_write_sz_in_total.load(std::memory_order_relaxed), to_hex(tail), m_reserved_sz,
                                m_journal_chunks.size(), m_truncate_done, m_total_size, to_hex(m_seek_cursor))};
    return str;
}

uint64_t JournalVirtualDev::used_size() const {
    std::lock_guard lock{m_mutex};
    uint64_t total_size = 0;
    for (const auto& [id, jd] : m_journal_descriptors) {
        total_size += jd->used_size();
    }
    return total_size;
}

uint64_t JournalVirtualDev::available_blks() const { return (size() - used_size()) / block_size(); }

nlohmann::json JournalVirtualDev::get_status(int log_level) const {
    std::lock_guard lock{m_mutex};
    nlohmann::json j;
    j["num_descriptors"] = std::to_string(m_journal_descriptors.size());
    for (const auto& [logdev_id, descriptor] : m_journal_descriptors) {
        j["journalvdev_logdev_id_" + std::to_string(logdev_id)] = descriptor->get_status(log_level);
    }
    return j;
}

} // namespace homestore
