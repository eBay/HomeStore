/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
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
#include <cstring>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <system_error>

#include <folly/Exception.h>
#include <iomgr/iomgr.hpp>
#include <iomgr/iomgr_flip.hpp>
#include <sisl/fds/utils.hpp>

#include <homestore/homestore_decl.hpp>
#include "device/chunk.h"
#include "device/physical_dev.hpp"
#include "device/device.h"
#include "common/homestore_utils.hpp"
#include "common/homestore_assert.hpp"

namespace homestore {

static std::mutex s_cached_dev_mtx;
static std::unordered_map< std::string, iomgr::io_device_ptr > s_cached_opened_devs;

__attribute__((no_sanitize_address)) static auto get_current_time() { return Clock::now(); }

iomgr::io_device_ptr open_and_cache_dev(const std::string& devname, int oflags) {
    std::unique_lock lg(s_cached_dev_mtx);

    auto it = s_cached_opened_devs.find(devname);
    if (it == s_cached_opened_devs.end()) {
        auto iodev = iomgr::DriveInterface::open_dev(devname, oflags);
        if (iodev == nullptr) {
            HS_LOG(ERROR, device, "device open failed errno {} dev_name {}", errno, devname);
            throw std::system_error(errno, std::system_category(), "error while opening the device");
        }
        bool happened;
        std::tie(it, happened) = s_cached_opened_devs.insert(std::pair{devname, iodev});
    }
    return it->second;
}

void close_and_uncache_dev(const std::string& devname, iomgr::io_device_ptr iodev) {
    {
        std::unique_lock lg(s_cached_dev_mtx);
        s_cached_opened_devs.erase(devname);
    }
    iodev->drive_interface()->close_dev(iodev);
}

first_block PhysicalDev::read_first_block(const std::string& devname, int oflags) {
    auto iodev = open_and_cache_dev(devname, oflags);

    first_block ret;
    auto buf = hs_utils::iobuf_alloc(first_block::s_io_fb_size, sisl::buftag::superblk, 512);
    iodev->drive_interface()->sync_read(iodev.get(), r_cast< char* >(buf), first_block::s_io_fb_size,
                                        hs_super_blk::first_block_offset());

    ret = *(r_cast< first_block* >(buf));
    hs_utils::iobuf_free(buf, sisl::buftag::superblk);

    return ret;
}

uint64_t PhysicalDev::get_dev_size(const std::string& devname) {
    auto iodev = open_and_cache_dev(devname, O_RDWR | O_CREAT);
    return iomgr::DriveInterface::get_size(iodev.get());
}

PhysicalDev::PhysicalDev(const dev_info& dinfo, int oflags, const pdev_info_header& pinfo) :
        m_metrics{dinfo.dev_name},
        m_devname{dinfo.dev_name},
        m_dev_type{dinfo.dev_type},
        m_dev_info{dinfo},
        m_pdev_info{pinfo} {
    LOGINFO("Opening device {} with {} mode.", m_devname, oflags & O_DIRECT ? "DIRECT_IO" : "BUFFERED_IO");

    m_iodev = open_and_cache_dev(m_devname, oflags);
    m_drive_iface = m_iodev->drive_interface();

    // Get the device size
    auto dev_size = m_drive_iface->get_size(m_iodev.get());
    if (dev_size == 0) {
        auto const s = fmt::format("Device {} size={} is too small", m_devname, dev_size);
        HS_LOG_ASSERT(0, s.c_str());
        throw homestore::homestore_exception(s, homestore_error::min_size_not_avail);
    }

    m_dev_info.dev_size = (m_dev_info.dev_size == 0) ? dev_size : std::min(dev_size, m_dev_info.dev_size);

    m_devsize = sisl::round_down(m_dev_info.dev_size, pinfo.dev_attr.phys_page_size);
    if (m_devsize != m_dev_info.dev_size) {
        LOGWARN("device size={} is not the multiple of physical page adjusted size to {}",
                in_bytes(m_dev_info.dev_size), in_bytes(m_devsize));
    }

    LOGINFO("Device {} opened with dev_id={} size={}", m_devname, m_iodev->dev_id(), in_bytes(m_devsize));

    // Create stream instance for the reported number
    for (uint32_t i{0}; i < pinfo.dev_attr.num_streams; ++i) {
        m_streams.emplace_back(i);
    }
    m_super_blk_in_footer = m_pdev_info.mirror_super_block;
}

PhysicalDev::~PhysicalDev() { close_device(); }

void PhysicalDev::write_super_block(uint8_t const* buf, uint32_t sb_size, uint64_t offset) {
    auto err_c = m_drive_iface->sync_write(m_iodev.get(), c_charptr_cast(buf), sb_size, offset);

    if (m_super_blk_in_footer) {
        auto t_offset = data_end_offset() + offset;
        err_c = m_drive_iface->sync_write(m_iodev.get(), c_charptr_cast(buf), sb_size, t_offset);
    }

    HS_REL_ASSERT(!err_c, "Super block write failed on dev={} at size={} offset={}, homestore will go down", m_devname,
                  sb_size, offset);
}

std::error_code PhysicalDev::read_super_block(uint8_t* buf, uint32_t sb_size, uint64_t offset) {
    return m_drive_iface->sync_read(m_iodev.get(), charptr_cast(buf), sb_size, offset);
}

void PhysicalDev::close_device() { close_and_uncache_dev(m_devname, m_iodev); }

folly::Future< std::error_code > PhysicalDev::async_write(const char* data, uint32_t size, uint64_t offset,
                                                          bool part_of_batch) {
    auto const start_time = get_current_time();
    return m_drive_iface->async_write(m_iodev.get(), data, size, offset, part_of_batch)
        .thenValue([this, start_time, size](std::error_code ec) {
            HISTOGRAM_OBSERVE(m_metrics, write_io_sizes, (((size - 1) / 1024) + 1));
            HISTOGRAM_OBSERVE(m_metrics, drive_write_latency, get_elapsed_time_us(start_time));
            COUNTER_INCREMENT(m_metrics, drive_async_write_count, 1);
            return ec;
        });
}

folly::Future< std::error_code > PhysicalDev::async_writev(const iovec* iov, int iovcnt, uint32_t size, uint64_t offset,
                                                           bool part_of_batch) {
    auto const start_time = get_current_time();
    return m_drive_iface->async_writev(m_iodev.get(), iov, iovcnt, size, offset, part_of_batch)
        .thenValue([this, start_time, size](std::error_code ec) {
            HISTOGRAM_OBSERVE(m_metrics, write_io_sizes, (((size - 1) / 1024) + 1));
            HISTOGRAM_OBSERVE(m_metrics, drive_write_latency, get_elapsed_time_us(start_time));
            COUNTER_INCREMENT(m_metrics, drive_async_write_count, 1);
            return ec;
        });
}

folly::Future< std::error_code > PhysicalDev::async_read(char* data, uint32_t size, uint64_t offset,
                                                         bool part_of_batch) {
    auto const start_time = get_current_time();
    return m_drive_iface->async_read(m_iodev.get(), data, size, offset, part_of_batch)
        .thenValue([this, start_time, size](std::error_code ec) {
            HISTOGRAM_OBSERVE(m_metrics, read_io_sizes, (((size - 1) / 1024) + 1));
            HISTOGRAM_OBSERVE(m_metrics, drive_read_latency, get_elapsed_time_us(start_time));
            COUNTER_INCREMENT(m_metrics, drive_async_read_count, 1);
            return ec;
        });
}

folly::Future< std::error_code > PhysicalDev::async_readv(iovec* iov, int iovcnt, uint32_t size, uint64_t offset,
                                                          bool part_of_batch) {
    auto const start_time = get_current_time();
    return m_drive_iface->async_readv(m_iodev.get(), iov, iovcnt, size, offset, part_of_batch)
        .thenValue([this, start_time, size](std::error_code ec) {
            HISTOGRAM_OBSERVE(m_metrics, read_io_sizes, (((size - 1) / 1024) + 1));
            HISTOGRAM_OBSERVE(m_metrics, drive_read_latency, get_elapsed_time_us(start_time));
            COUNTER_INCREMENT(m_metrics, drive_async_read_count, 1);
            return ec;
        });
}

folly::Future< std::error_code > PhysicalDev::async_write_zero(uint64_t size, uint64_t offset) {
    return m_drive_iface->async_write_zero(m_iodev.get(), size, offset);
}

#if 0
folly::Future< std::error_code > PhysicalDev::async_write_zero(uint64_t size, uint64_t offset) {
    return m_drive_iface->async_write_zero(m_iodev.get(), size, offset).thenError([this](auto const& e) -> bool {
        LOGERROR("Error on async_write_zero: exception={}", e.what());
        device_manager_mutable()->handle_error(this);
        return false;
    });
}
#endif

folly::Future< std::error_code > PhysicalDev::queue_fsync() { return m_drive_iface->queue_fsync(m_iodev.get()); }

std::error_code PhysicalDev::sync_write(const char* data, uint32_t size, uint64_t offset) {
    auto const start_time = get_current_time();
    auto const ret = m_drive_iface->sync_write(m_iodev.get(), data, size, offset);
    HISTOGRAM_OBSERVE(m_metrics, drive_write_latency, get_elapsed_time_us(start_time));
    HISTOGRAM_OBSERVE(m_metrics, write_io_sizes, (((size - 1) / 1024) + 1));
    COUNTER_INCREMENT(m_metrics, drive_sync_write_count, 1);
    return ret;
}

std::error_code PhysicalDev::sync_writev(const iovec* iov, int iovcnt, uint32_t size, uint64_t offset) {
    auto const start_time = Clock::now();
    auto const ret = m_drive_iface->sync_writev(m_iodev.get(), iov, iovcnt, size, offset);
    HISTOGRAM_OBSERVE(m_metrics, drive_write_latency, get_elapsed_time_us(start_time));
    HISTOGRAM_OBSERVE(m_metrics, write_io_sizes, (((size - 1) / 1024) + 1));
    COUNTER_INCREMENT(m_metrics, drive_sync_write_count, 1);

    return ret;
}

std::error_code PhysicalDev::sync_read(char* data, uint32_t size, uint64_t offset) {
    auto const start_time = Clock::now();
    auto const ret = m_drive_iface->sync_read(m_iodev.get(), data, size, offset);
    HISTOGRAM_OBSERVE(m_metrics, drive_read_latency, get_elapsed_time_us(start_time));
    HISTOGRAM_OBSERVE(m_metrics, read_io_sizes, (((size - 1) / 1024) + 1));
    COUNTER_INCREMENT(m_metrics, drive_sync_read_count, 1);
    return ret;
}

std::error_code PhysicalDev::sync_readv(iovec* iov, int iovcnt, uint32_t size, uint64_t offset) {
    auto const start_time = Clock::now();
    auto const ret = m_drive_iface->sync_readv(m_iodev.get(), iov, iovcnt, size, offset);
    HISTOGRAM_OBSERVE(m_metrics, drive_read_latency, get_elapsed_time_us(start_time));
    HISTOGRAM_OBSERVE(m_metrics, read_io_sizes, (((size - 1) / 1024) + 1));
    COUNTER_INCREMENT(m_metrics, drive_sync_read_count, 1);
    return ret;
}

std::error_code PhysicalDev::sync_write_zero(uint64_t size, uint64_t offset) {
    auto const start_time = Clock::now();
    auto const ret = m_drive_iface->sync_write_zero(m_iodev.get(), size, offset);
    HISTOGRAM_OBSERVE(m_metrics, drive_write_latency, get_elapsed_time_us(start_time));
    HISTOGRAM_OBSERVE(m_metrics, wirte_io_size, (((size - 1) / 1024) + 1));
    COUNTER_INCREMENT(m_metrics, drive_sync_write_count, 1);
    return ret;
}

void PhysicalDev::submit_batch() { m_drive_iface->submit_batch(); }

//////////////////////////// Chunk Creation/Load related methods /////////////////////////////////////////
void PhysicalDev::format_chunks() {
    m_chunk_info_slots = std::make_unique< sisl::Bitset >(std::max(1u, hs_super_blk::max_chunks_in_pdev(m_dev_info)),
                                                          /* align size */ 4096);
    auto bitmap_mem = m_chunk_info_slots->serialize(/* align size */ 4096);
    HS_REL_ASSERT_LE(bitmap_mem->size(), hs_super_blk::chunk_info_bitmap_size(m_dev_info),
                     "Chunk info serialized bitmap mismatch with expected size");
    write_super_block(bitmap_mem->cbytes(), bitmap_mem->size(), hs_super_blk::chunk_sb_offset());
}

std::vector< shared< Chunk > > PhysicalDev::create_chunks(const std::vector< uint32_t >& chunk_ids, uint32_t vdev_id,
                                                          uint64_t size) {
    std::vector< shared< Chunk > > ret_chunks;
    std::unique_lock lg{m_chunk_op_mtx};
    auto chunks_remaining = chunk_ids.size();
    uint32_t cit{0};
    uint8_t* buf{nullptr};

    try {
        while (chunks_remaining > 0) {
            auto b = m_chunk_info_slots->get_next_contiguous_n_reset_bits(0u, std::nullopt, 1u, chunks_remaining);
            if (b.nbits == 0) { throw std::out_of_range("System has no room for additional chunk"); }

            buf = hs_utils::iobuf_alloc(chunk_info::size * b.nbits, sisl::buftag::superblk,
                                        m_pdev_info.dev_attr.align_size);
            auto ptr = buf;
            for (auto cslot = b.start_bit; cslot < b.start_bit + b.nbits; ++cslot, ++cit, ptr += chunk_info::size) {
                chunk_info* cinfo = new (ptr) chunk_info();
                populate_chunk_info(cinfo, vdev_id, size, chunk_ids[cit], cit, {});

                auto chunk = std::make_shared< Chunk >(this, *cinfo, cslot);
                ret_chunks.push_back(chunk);
                get_stream(chunk).m_chunks_map.insert(std::pair{chunk_ids[cit], chunk});
                HS_LOG(INFO, device, "Creating chunk {}", chunk->to_string());
                cinfo->~chunk_info();
            }

            m_chunk_info_slots->set_bits(b.start_bit, b.nbits);
            write_super_block(buf, chunk_info::size * b.nbits, chunk_info_offset_nth(b.start_bit));

            hs_utils::iobuf_free(buf, sisl::buftag::superblk);
            buf = nullptr;
            chunks_remaining -= b.nbits;
        }

        // Finally serialize the entire bitset and persist the chunk info bitmap itself
        auto bitmap_mem = m_chunk_info_slots->serialize(m_pdev_info.dev_attr.align_size);
        write_super_block(bitmap_mem->cbytes(), bitmap_mem->size(), hs_super_blk::chunk_sb_offset());
    } catch (const std::out_of_range& e) {
        LOGERROR("Creation of chunks failed because of space, removing {} partially created chunks", ret_chunks.size());
        // exception is thrown out by populate_chunk_info
        if (buf) hs_utils::iobuf_free(buf, sisl::buftag::superblk);
        for (auto& chunk : ret_chunks) {
            do_remove_chunk(chunk);
        }
        throw(e);
    }
    return ret_chunks;
}

shared< Chunk > PhysicalDev::create_chunk(uint32_t chunk_id, uint32_t vdev_id, uint64_t size, uint32_t ordinal,
                                          const sisl::blob& user_private) {
    std::unique_lock lg{m_chunk_op_mtx};

    // We need to alloc a slot to store the chunk_info in the super blk
    auto cslot = m_chunk_info_slots->get_next_reset_bit(0u);
    if (cslot == sisl::Bitset::npos) { throw std::out_of_range("System has no room for additional chunk"); }
    m_chunk_info_slots->set_bit(cslot);

    // Populate the chunk info
    auto buf = hs_utils::iobuf_alloc(chunk_info::size, sisl::buftag::superblk, m_pdev_info.dev_attr.align_size);
    chunk_info* cinfo = new (buf) chunk_info();
    shared< Chunk > chunk;

    try {
        populate_chunk_info(cinfo, vdev_id, size, chunk_id, ordinal, user_private);

        // Locate and write the chunk info in the super blk area
        write_super_block(buf, chunk_info::size, chunk_info_offset_nth(cslot));

        chunk = std::make_shared< Chunk >(this, *cinfo, cslot);
        get_stream(chunk).m_chunks_map.insert(std::pair{chunk_id, chunk});

        auto bitmap_mem = m_chunk_info_slots->serialize(m_pdev_info.dev_attr.align_size);
        write_super_block(bitmap_mem->cbytes(), bitmap_mem->size(), hs_super_blk::chunk_sb_offset());
        HS_LOG(INFO, device, "Created chunk {}", chunk->to_string());

        cinfo->~chunk_info();
        hs_utils::iobuf_free(buf, sisl::buftag::superblk);
    } catch (std::out_of_range const& e) {
        cinfo->~chunk_info();
        hs_utils::iobuf_free(buf, sisl::buftag::superblk);
        throw e;
    }
    return chunk;
}

std::pair< uint64_t, uint64_t > get_next_contiguous_set_bit(const sisl::Bitset& bm, uint64_t search_start_bit) {
    uint64_t first_set_bit{sisl::Bitset::npos};
    uint64_t set_count{0};
    uint64_t b;
    while ((b = bm.get_next_set_bit(search_start_bit)) != sisl::Bitset::npos) {
        if (first_set_bit == sisl::Bitset::npos) {
            first_set_bit = b;
        } else if (b > search_start_bit) {
            break;
        }
        ++set_count;
        search_start_bit = b + 1;
    }

    return std::pair(first_set_bit, set_count);
}

void PhysicalDev::load_chunks(std::function< bool(cshared< Chunk >&) >&& chunk_found_cb) {
    std::unique_lock lg{m_chunk_op_mtx};

    // Read the chunk info bitmap area from super block and load them into in-memory bitmap of chunk slots
    auto buf_arr = make_byte_array(hs_super_blk::chunk_info_bitmap_size(m_dev_info), m_pdev_info.dev_attr.align_size,
                                   sisl::buftag::superblk);
    read_super_block(buf_arr->bytes(), buf_arr->size(), hs_super_blk::chunk_sb_offset());
    m_chunk_info_slots = std::make_unique< sisl::Bitset >(buf_arr);

    // Walk through each of the chunk info and create corresponding chunks

    uint64_t prev_bit = 0;
    do {
        auto const [b, nbits] = get_next_contiguous_set_bit(*m_chunk_info_slots, prev_bit);
        if (nbits == 0) { break; } // No more chunk slots are occupied
        prev_bit = b + nbits;

        auto buf =
            hs_utils::iobuf_alloc(nbits * chunk_info::size, sisl::buftag::superblk, m_pdev_info.dev_attr.align_size);
        read_super_block(buf, nbits * chunk_info::size, chunk_info_offset_nth(b));
        auto ptr = buf;

        for (auto cslot = b; cslot < b + nbits; ++cslot, ptr += chunk_info::size) {
            auto cinfo = r_cast< chunk_info* >(ptr);

            auto info_crc = cinfo->checksum;
            cinfo->checksum = 0;
            auto crc = crc16_t10dif(hs_init_crc_16, r_cast< const unsigned char* >(cinfo), sizeof(chunk_info));
            if (crc != info_crc) {
                // TODO: Need a way to handle checksum mismatch and still proceed to read from the footer as well.
                // For now, it is simply asserting
                RELEASE_ASSERT(false, "Checksum mismatch for chunk info in slot {}", cslot);
            }
            cinfo->checksum = info_crc;

            auto chunk = std::make_shared< Chunk >(this, *cinfo, cslot);
            m_chunk_data_area.insert(
                ChunkInterval::right_open(cinfo->chunk_start_offset, cinfo->chunk_start_offset + cinfo->chunk_size));
            if (chunk_found_cb(chunk)) { get_stream(chunk).m_chunks_map.insert(std::pair{cinfo->chunk_id, chunk}); }
        }
        hs_utils::iobuf_free(buf, sisl::buftag::superblk);
    } while (true);
}

void PhysicalDev::remove_chunks(std::vector< shared< Chunk > >& chunks) {
    std::unique_lock lg{m_chunk_op_mtx};
    for (auto& chunk : chunks) {
        do_remove_chunk(chunk);
    }
}

void PhysicalDev::remove_chunk(cshared< Chunk >& chunk) {
    std::unique_lock lg{m_chunk_op_mtx};
    do_remove_chunk(chunk);
}

void PhysicalDev::do_remove_chunk(cshared< Chunk >& chunk) {
    auto buf = hs_utils::iobuf_alloc(chunk_info::size, sisl::buftag::superblk, m_pdev_info.dev_attr.align_size);
    chunk_info* cinfo = new (buf) chunk_info();
    *cinfo = chunk->info();
    free_chunk_info(cinfo);

    // Locate and write the chunk info in the super blk area
    write_super_block(buf, chunk_info::size, chunk_info_offset_nth(chunk->slot_number()));

    // Reset the info slot and write it to super block
    m_chunk_info_slots->reset_bit(chunk->slot_number());
    auto bitmap_mem = m_chunk_info_slots->serialize(m_pdev_info.dev_attr.align_size);
    write_super_block(bitmap_mem->cbytes(), bitmap_mem->size(), hs_super_blk::chunk_sb_offset());

    get_stream(chunk).m_chunks_map.erase(chunk->chunk_id());
    cinfo->~chunk_info();
    hs_utils::iobuf_free(buf, sisl::buftag::superblk);
    HS_LOG(DEBUG, device, "Removed chunk {}", chunk->to_string());
}

uint64_t PhysicalDev::chunk_info_offset_nth(uint32_t slot) const {
    return hs_super_blk::chunk_sb_offset() + hs_super_blk::chunk_info_bitmap_size(m_dev_info) +
        (slot * chunk_info::size);
}

void PhysicalDev::populate_chunk_info(chunk_info* cinfo, uint32_t vdev_id, uint64_t size, uint32_t chunk_id,
                                      uint32_t ordinal, const sisl::blob& private_data) {
    // Find the free area for chunk data within between data_start_offset() and data_end_offset()
    auto ival = find_next_chunk_area(size);
    m_chunk_data_area.insert(ival);

    cinfo->chunk_start_offset = ival.lower();
    cinfo->chunk_size = size;
    cinfo->vdev_id = vdev_id;
    cinfo->chunk_id = chunk_id;
    cinfo->chunk_ordinal = ordinal;
    cinfo->set_allocated();
    cinfo->set_user_private(private_data);
    cinfo->compute_checksum();
    auto [_, inserted] = m_chunk_start.insert(cinfo->chunk_start_offset);
    RELEASE_ASSERT(inserted, "Duplicate start offset {} for chunk {}", cinfo->chunk_start_offset, cinfo->chunk_id);
}

void PhysicalDev::free_chunk_info(chunk_info* cinfo) {
    auto ival = ChunkInterval::right_open(cinfo->chunk_start_offset, cinfo->chunk_start_offset + cinfo->chunk_size);
    m_chunk_data_area.erase(ival);
    m_chunk_start.erase(cinfo->chunk_start_offset);

    cinfo->set_free();
    cinfo->checksum = 0;
    cinfo->checksum = crc16_t10dif(hs_init_crc_16, r_cast< const unsigned char* >(cinfo), sizeof(chunk_info));
}

ChunkInterval PhysicalDev::find_next_chunk_area(uint64_t size) const {
    auto ins_ival = ChunkInterval::right_open(data_start_offset(), data_start_offset() + size);
    for (auto& exist_ival : m_chunk_data_area) {
        if (ins_ival.upper() <= exist_ival.lower()) { break; }
        ins_ival = ChunkInterval::right_open(exist_ival.upper(), exist_ival.upper() + size);
    }

    if (ins_ival.upper() > data_end_offset()) {
        throw std::out_of_range("Physical dev has no room for additional chunk");
    }
    return ins_ival;
}

uint32_t PhysicalDev::chunk_to_stream_id(const chunk_info& cinfo) const {
    // Right now we decide the stream only based on its offset within the pdev. In future some expansive scheme could be
    // built based on the underlying physical device
    auto const stream_id = cinfo.chunk_start_offset / (m_devsize / num_streams());
    RELEASE_ASSERT_LT(stream_id, m_streams.size(), "Stream ID for chunk creation exceeded num streams");
    return stream_id;
}

uint32_t PhysicalDev::chunk_to_stream_id(cshared< Chunk >& chunk) const { return chunk_to_stream_id(chunk->info()); }

Stream& PhysicalDev::get_stream(cshared< Chunk >& chunk) { return get_stream_mutable(chunk->stream_id()); }

} // namespace homestore
