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
#pragma once
#include <vector>
#include <string>
#include "hs_super_blk.h"

#ifdef __linux__
#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>
#endif

#include <boost/icl/split_interval_set.hpp>
#include <nlohmann/json.hpp>
#include <isa-l/crc.h>
#include <sisl/metrics/metrics.hpp>
#include <sisl/logging/logging.h>
#include <homestore/homestore_decl.hpp>

#include "hs_super_blk.h"
SISL_LOGGING_DECL(device)

namespace homestore {
class PhysicalDevMetrics : public sisl::MetricsGroupWrapper {
public:
    explicit PhysicalDevMetrics(const std::string& devname) : sisl::MetricsGroupWrapper{"PhysicalDev", devname} {
        REGISTER_COUNTER(drive_sync_write_count, "Drive sync write count");
        REGISTER_COUNTER(drive_sync_read_count, "Drive sync read count");
        REGISTER_COUNTER(drive_async_write_count, "Drive async write count");
        REGISTER_COUNTER(drive_async_read_count, "Drive async read count");
        REGISTER_COUNTER(drive_write_vector_count, "Total Count of buffer provided for write");
        REGISTER_COUNTER(drive_read_vector_count, "Total Count of buffer provided for read");
        REGISTER_COUNTER(drive_read_errors, "Total drive read errors");
        REGISTER_COUNTER(drive_write_errors, "Total drive write errors");
        REGISTER_COUNTER(drive_spurios_events, "Total number of spurious events per drive");
        REGISTER_COUNTER(drive_skipped_chunk_bm_writes, "Total number of skipped writes for chunk bitmap");

        REGISTER_HISTOGRAM(drive_write_latency, "BlkStore drive write latency in us");
        REGISTER_HISTOGRAM(drive_read_latency, "BlkStore drive read latency in us");

        REGISTER_HISTOGRAM(write_io_sizes, "Write IO Sizes", "io_sizes", {"io_direction", "write"},
                           HistogramBucketsType(ExponentialOfTwoBuckets));
        REGISTER_HISTOGRAM(read_io_sizes, "Read IO Sizes", "io_sizes", {"io_direction", "read"},
                           HistogramBucketsType(ExponentialOfTwoBuckets));

        register_me_to_farm();
    }

    PhysicalDevMetrics(const PhysicalDevMetrics&) = delete;
    PhysicalDevMetrics(PhysicalDevMetrics&&) noexcept = delete;
    PhysicalDevMetrics& operator=(const PhysicalDevMetrics&) = delete;
    PhysicalDevMetrics& operator=(PhysicalDevMetrics&&) noexcept = delete;

    ~PhysicalDevMetrics() { deregister_me_from_farm(); }
};

class Chunk;
using ChunkIntervalSet = boost::icl::split_interval_set< uint64_t >;
using ChunkInterval = ChunkIntervalSet::interval_type;

#pragma pack(1)
struct chunk_info {
    static constexpr size_t size = 512;
    static constexpr size_t user_private_size = 128;
    static constexpr size_t selector_private_size = 64;

    uint64_t chunk_start_offset{0}; // 0: Start offset of the chunk within a pdev
    uint64_t chunk_size{0};         // 8: Chunk size
    uint64_t end_of_chunk_size{0};  // 16: The offset indicates end of chunk.
    uint32_t vdev_id{0};            // 24: Virtual device id this chunk hosts. UINT32_MAX if chunk is free
    uint32_t chunk_id{0};           // 28: ID for this chunk - unique for entire homestore across devices
    uint32_t chunk_ordinal{0};      // 32: Chunk ordinal within the vdev on this pdev
    uint8_t chunk_allocated{0x00};  // 36: Is chunk allocated or free
    uint16_t checksum{0};           // 37: checksum of this chunk info
    uint8_t padding[25]{};          // 39: pad to make it 128 bytes total
    uint8_t chunk_selector_private[selector_private_size]{}; // 64: Chunk selector private area
    uint8_t user_private[user_private_size]{};               // 128: Opaque user of the chunk information

    uint64_t get_chunk_size() const { return chunk_size; }
    uint32_t get_chunk_id() const { return chunk_id; }
    bool is_allocated() const { return (chunk_allocated != 0x00); }
    void set_allocated() { chunk_allocated = 0x01; }
    void set_free() { chunk_allocated = 0x00; }

    void set_selector_private(const sisl::blob& data) {
        std::memcpy(&chunk_selector_private, data.bytes, std::min(data.size, uint32_cast(selector_private_size)));
    }
    void set_user_private(const sisl::blob& data) {
        std::memcpy(&user_private, data.bytes, std::min(data.size, uint32_cast(user_private_size)));
    }

    void compute_checksum() {
        checksum = 0;
        checksum = crc16_t10dif(hs_init_crc_16, r_cast< const unsigned char* >(this), sizeof(chunk_info));
    }
};
#pragma pack()

static_assert(sizeof(chunk_info) <= chunk_info::size, "Chunk info sizeof() mismatch");

struct Stream {
    uint32_t m_stream_id;
    std::map< uint32_t, shared< Chunk > > m_chunks_map; // Chunks within the stream of the physical device

    Stream(uint32_t stream_id) : m_stream_id{stream_id} {}
};

class PhysicalDev {
private:
    iomgr::io_device_ptr m_iodev;
    iomgr::DriveInterface* m_drive_iface; // Interface to do IO
    PhysicalDevMetrics m_metrics;
    std::string m_devname;        // Physical device path
    HSDevType m_dev_type;         // Device type
    dev_info m_dev_info;          // Input device info
    pdev_info_header m_pdev_info; // Persistent information about this physical device
    uint64_t m_devsize{0};        // Actual device size
    bool m_super_blk_in_footer;   // Indicate if the super blk is stored in the footer as well

    std::mutex m_chunk_op_mtx;                          // Mutex for all chunk related operations
    std::vector< Stream > m_streams;                    // List of streams in the system
    ChunkIntervalSet m_chunk_data_area;                 // Range of chunks data area created
    std::unique_ptr< sisl::Bitset > m_chunk_info_slots; // Slots to write the chunk info
    uint32_t m_chunk_sb_size{0};                        // Total size of the chunk sb at present

public:
    PhysicalDev(const dev_info& dinfo, int oflags, const pdev_info_header& pinfo);
    PhysicalDev(const PhysicalDev&) = delete;
    PhysicalDev(PhysicalDev&&) noexcept = delete;
    PhysicalDev& operator=(const PhysicalDev&) = delete;
    PhysicalDev& operator=(PhysicalDev&&) noexcept = delete;
    virtual ~PhysicalDev();

    /////////// Super Block related methods /////////////
    static first_block read_first_block(const std::string& devname, int oflags);
    static uint64_t get_dev_size(const std::string& devname);

    void read_super_block(uint8_t* buf, uint32_t sb_size, uint64_t offset);
    void write_super_block(uint8_t* buf, uint32_t sb_size, uint64_t offset);
    void close_device();

    //////////////////////////// Chunk Creation/Load related methods /////////////////////////////////////////

    /// @brief Create multiple same sized chunks on this device. In case of unavailable space it throws the exception,
    /// but cleans up any partially created chunks.
    ///
    /// @param chunk_ids: List of chunk ids to be created. The ordinal of the chunks are assigned in the order of this
    /// list, thus first chunk id is assigned with ordinal 0, then next with 1 etc..
    /// @param vdev_id: Vdev this chunk should be part of.
    /// @param size: Size of each chunk
    /// @return Vector of chunks that are created
    std::vector< shared< Chunk > > create_chunks(const std::vector< uint32_t >& chunk_ids, uint32_t vdev_id,
                                                 uint64_t size);

    /// @brief Create a chunks on this device. In case of unavailable space it throws the std::out_of_range exception
    ///
    /// @param chunk_ids: Chunk ID for the chunk to be created. This ID is expected to be system wide unique
    /// @param vdev_id: Vdev this chunk should be part of.
    /// @param size: Size of each chunk
    /// @param ordinal: Ordinal for a pdev within the vdev. This is useful to match similar vdevs from different pdevs
    /// for mirroring
    /// @return Shared instance of chunk class created
    shared< Chunk > create_chunk(uint32_t chunk_id, uint32_t vdev_id, uint64_t size, uint32_t ordinal);

    void load_chunks(std::function< void(cshared< Chunk >&) >&& chunk_found_cb);
    void remove_chunks(std::vector< shared< Chunk > >& chunks);
    void remove_chunk(cshared< Chunk >& chunk);
    void format_chunks();

    //////////////////////////// Stream access methods ////////////////////////////
    Stream& get_stream_mutable(uint32_t stream_id) { return m_streams[stream_id]; }
    const Stream& get_stream(uint32_t stream_id) const { return m_streams[stream_id]; };
    uint32_t num_streams() const { return uint32_cast(m_streams.size()); }
    uint32_t chunk_to_stream_id(const chunk_info& cinfo) const;
    uint32_t chunk_to_stream_id(cshared< Chunk >& chunk) const;
    Stream& get_stream(cshared< Chunk >& chunk);

    ///////////// Pointer Getters ///////////////////////
    PhysicalDevMetrics& metrics() { return m_metrics; }
    iomgr::DriveInterface* drive_iface() const { return m_drive_iface; }
    uint32_t pdev_id() const { return m_pdev_info.pdev_id; }
    const std::string& get_devname() const { return m_devname; }

    /////////////////////////////////////// IO Methods //////////////////////////////////////////
    folly::Future< bool > async_write(const char* data, uint32_t size, uint64_t offset, bool part_of_batch = false);
    folly::Future< bool > async_writev(const iovec* iov, int iovcnt, uint32_t size, uint64_t offset,
                                       bool part_of_batch = false);
    folly::Future< bool > async_read(char* data, uint32_t size, uint64_t offset, bool part_of_batch = false);
    folly::Future< bool > async_readv(iovec* iov, int iovcnt, uint32_t size, uint64_t offset,
                                      bool part_of_batch = false);
    folly::Future< bool > async_write_zero(uint64_t size, uint64_t offset);
    folly::Future< bool > queue_fsync();

    void sync_write(const char* data, uint32_t size, uint64_t offset);
    void sync_writev(const iovec* iov, int iovcnt, uint32_t size, uint64_t offset);
    void sync_read(char* data, uint32_t size, uint64_t offset);
    void sync_readv(iovec* iov, int iovcnt, uint32_t size, uint64_t offset);
    void sync_write_zero(uint64_t size, uint64_t offset);
    void submit_batch();

    ///////////// Parameters Getters ///////////////////////
    uint32_t optimal_page_size() const { return m_pdev_info.dev_attr.phys_page_size; }
    uint32_t align_size() const { return m_pdev_info.dev_attr.align_size; }
    uint32_t atomic_page_size() const { return m_pdev_info.dev_attr.atomic_phys_page_size; }

    uint64_t data_start_offset() const { return m_pdev_info.data_offset; }
    uint64_t data_end_offset() const {
        return m_super_blk_in_footer ? (m_devsize - m_pdev_info.data_offset) : m_devsize;
    }

    uint64_t data_size() const { return data_end_offset() - data_start_offset(); }

    uint64_t chunk_info_offset_nth(uint32_t slot) const;

private:
    void do_remove_chunk(cshared< Chunk >& chunk);
    void populate_chunk_info(chunk_info* cinfo, uint32_t vdev_id, uint64_t size, uint32_t chunk_id, uint32_t ordinal);
    void free_chunk_info(chunk_info* cinfo);
    ChunkInterval find_next_chunk_area(uint64_t size) const;
};
} // namespace homestore
