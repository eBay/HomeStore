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
#pragma once
#include <vector>
#include <string>

#ifdef __linux__
#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>
#endif

#include <nlohmann/json.hpp>
#include <sisl/metrics/metrics.hpp>
#include <sisl/fds/bitset.hpp>
#include <sisl/logging/logging.h>

#include <homestore/homestore_decl.hpp>
#include "common/homestore_assert.hpp"
#include "common/homestore_utils.hpp"

SISL_LOGGING_DECL(device)

namespace homestore {
static constexpr uint32_t MAGIC{0xCEEDDEEB};
#define PRODUCT_NAME "OmStore"

/************* Super Block definition ******************/
static constexpr uint32_t SUPERBLOCK_VERSION_1_2{1}; // XXX: we need a cooler name
static constexpr uint32_t SUPERBLOCK_VERSION_1_3{3}; // we bumped the version twice in 1.3
static constexpr uint32_t CURRENT_SUPERBLOCK_VERSION{3};
static constexpr uint32_t CURRENT_DM_INFO_VERSION{1};

/*******************************************************************************************************
 *  _______________________             _________________________________________________________      *
 * |                       |           |                  |            |             |            |    *
 * |  Super block header   |---------->| Super Block info | Pdev Block | Chunk Block | Vdev Block |    *
 * |_______________________|           |__________________|____________|_____________|____________|    *
 *                                                                                                     *
 *******************************************************************************************************/

//////////////////////////// Physical Device Info Block definition ////////////////////////
#pragma pack(1)
struct pdevs_block {
    uint64_t magic{0};         // Header magic expected to be at the top of block
    uint32_t num_phys_devs{0}; // Total number of physical devices in the entire system
    uint32_t max_phys_devs{0};
    uint64_t info_offset{0};

    uint64_t get_magic() const { return magic; }
    uint32_t get_num_phys_devs() const { return num_phys_devs; }
};
#pragma pack()

#pragma pack(1)
struct pdev_info_block {
    uint32_t dev_num{0};        // Device ID for this store instance.
    uint32_t first_chunk_id{0}; // First chunk id for this physical device
    uint64_t dev_offset{0};     // Start offset of the device in global offset

    uint32_t get_dev_num() const { return dev_num; }
    uint32_t get_first_chunk_id() const { return first_chunk_id; }
    uint64_t get_dev_offset() const { return dev_offset; }
};
#pragma pack()

//////////////////////////// chunk Info Block definition ////////////////////////////

#pragma pack(1)
struct chunks_block {
    uint64_t magic{0};      // Header magic expected to be at the top of block
    uint32_t num_chunks{0}; // Number of physical chunks for this block
    uint32_t max_num_chunks{0};
    uint64_t info_offset{0};

    uint64_t get_magic() const { return magic; }
    uint32_t get_num_chunks() const { return num_chunks; }
};
#pragma pack()

#pragma pack(1)
struct chunk_info_block {
    uint64_t chunk_start_offset{0}; // Start offset of the chunk within a pdev
    uint64_t chunk_size{0};         // Chunk size
    uint32_t chunk_id{0};           // Chunk id in global scope. It is the index in the array of chunk_info_blks
    uint32_t pdev_id{0};            // Physical device id this chunk is hosted on
    uint32_t vdev_id{0};            // Virtual device id this chunk hosts. UINT32_MAX if chunk is free
    uint32_t prev_chunk_id{0};      // Prev pointer in the chunk
    uint32_t next_chunk_id{0};      // Next pointer in the chunk
    uint32_t primary_chunk_id{0};   // Valid chunk id if this is a mirror of some chunk
    int64_t end_of_chunk_size{0};   // The offset indicates end of chunk. off_t is ambiguous size
    uint8_t slot_allocated{0};      // Is this slot allocated for any chunks.
    uint8_t sb_chunk{0};            // This chunk is not assigned to any vdev but super block
    uint8_t pad[6]{};               // pad to 8 byte total alignment

    uint64_t get_chunk_size() const { return chunk_size; }
    uint32_t get_chunk_id() const { return chunk_id; }
    void set_slot_allocated(const bool allocated) { slot_allocated = static_cast< uint8_t >(allocated ? 0x01 : 0x00); };
    bool is_slot_allocated() const { return (slot_allocated == 0x01); }
    void set_sb_chunk(const bool chunk) { sb_chunk = static_cast< uint8_t >(chunk ? 0x01 : 0x00); }
    bool is_sb_chunk() const { return (sb_chunk == 0x01); }
    void update_start_offset(const uint64_t offset) {
        HS_REL_ASSERT_GE(offset, chunk_start_offset);
        chunk_size -= (offset - chunk_start_offset);
        HS_REL_ASSERT_GT(chunk_size, 0);
        chunk_start_offset = offset;
    }
};
#pragma pack()

/************* Vdev Info Block definition ******************/
#pragma pack(1)
struct vdevs_block {
    uint64_t magic{0};     // Header magic expected to be at the top of block
    uint32_t num_vdevs{0}; // Number of virtual devices
    uint32_t max_num_vdevs{0};
    uint32_t first_vdev_id{0}; // First vdev id / Head of the vdev list;
    uint32_t context_data_size{0};
    uint64_t info_offset{0};

    uint32_t get_num_vdevs() const { return num_vdevs; }
    uint64_t get_magic() const { return magic; }
    uint32_t get_first_vdev_id() const { return first_vdev_id; }
};
#pragma pack()

static constexpr size_t MAX_VDEV_INFO_BLOCK_SZ{4096};
static constexpr size_t MAX_VDEV_INFO_BLOCK_HDR_SZ{512};
static constexpr size_t MAX_CONTEXT_DATA_SZ{MAX_VDEV_INFO_BLOCK_SZ - MAX_VDEV_INFO_BLOCK_HDR_SZ};

#pragma pack(1)
struct vdev_info_block {
    uint64_t size{0};               // 0: Size of the vdev
    uint32_t vdev_id{0};            // 8: Id for this vdev. It is a index in the array of vdev_info_blk
    uint32_t num_mirrors{0};        // 12: Total number of mirrors
    uint32_t blk_size{0};           // 16: IO block size for this vdev
    uint32_t prev_vdev_id{0};       // 20: Prev pointer of vdevice list
    uint32_t next_vdev_id{0};       // 24: Next pointer of vdevice list
    uint32_t num_primary_chunks{0}; // 28: number of primary chunks
    uint8_t slot_allocated{0};      // 32: Is this current slot allocated
    uint8_t failed{0};              // 33: set to true if disk is replaced

    uint8_t
        padding[MAX_VDEV_INFO_BLOCK_HDR_SZ - 34]{}; // Ugly hardcode will be removed after moving to superblk blkstore
    uint8_t context_data[MAX_CONTEXT_DATA_SZ]{};

    uint32_t get_vdev_id() const { return vdev_id; }
    uint64_t get_size() const { return size; }

    void set_slot_allocated(const bool allocated) { slot_allocated = static_cast< uint8_t >(allocated ? 0x01 : 0x00); };
    bool is_slot_allocated() const { return (slot_allocated == 0x01); }
    void set_failed(const bool failed_state) { failed = static_cast< uint8_t >(failed_state ? 0x01 : 0x00); };
    bool is_failed() const { return (failed == 0x01); }

    static constexpr size_t max_context_size() { return MAX_CONTEXT_DATA_SZ; }
};
#pragma pack()

// This assert is trying catch mistakes of overlaping the header to context_data portion.
static_assert(offsetof(vdev_info_block, context_data) == MAX_VDEV_INFO_BLOCK_HDR_SZ,
              "vdev info block header size should be size of 512 bytes!");

static_assert(sizeof(vdev_info_block) == MAX_VDEV_INFO_BLOCK_SZ, "vdev info block size should be 4096 bytes!");

//////////////////////////// Super Block Definition ////////////////////////////

/* This header should be atomically written to the disks. It should always be smaller then ssd atomic page size */
static constexpr size_t SUPERBLOCK_PAYLOAD_OFFSET{4096};

#pragma pack(1)
struct disk_attr {
    // all fields in this structure are a copy from iomgr::drive_attributes;
    uint32_t phys_page_size{0};        // Physical page size of flash ssd/nvme. This is optimal size to do IO
    uint32_t align_size{0};            // size alignment supported by drives/kernel
    uint32_t atomic_phys_page_size{0}; // atomic page size of the drive_sync_write_count
    uint32_t num_streams{0};

    bool is_valid() const {
        return is_page_valid(phys_page_size) && is_page_valid(align_size) && is_page_valid(atomic_phys_page_size);
    }

    bool is_page_valid(uint32_t page_size) const {
        if (page_size == 0 || (page_size & (page_size - 1)) != 0) {
            return false;
        } else {
            return true;
        }
    }

    std::string to_string() const {
        return fmt::format("disk_attr: phys_page_size: {}, align_size: {}, atomic_phys_page_size: {}, num_streams: {}",
                           in_bytes(phys_page_size), in_bytes(align_size), in_bytes(atomic_phys_page_size),
                           num_streams);
    }
};

struct super_block {
    static constexpr uint32_t s_min_sb_size{SUPERBLOCK_PAYLOAD_OFFSET +
                                            512}; // only needed for first time read of super block; increase 512 to
                                                  // actual size if in the future super_block can be larger;
    static constexpr size_t s_num_dm_chunks{2};
    static_assert((s_num_dm_chunks & (s_num_dm_chunks - 1)) == 0,
                  "Size must be power of 2 for optimizations of & vs modulo");
    uint8_t empty_buf[SUPERBLOCK_PAYLOAD_OFFSET]{}; // don't write anything to first 4096 bytes.
    uint64_t magic{0};                              // Header magic expected to be at the top of block
    uint64_t gen_cnt{0};
    uint32_t version{0}; // Version Id of this structure
    int32_t cur_indx{0};
    static constexpr size_t s_product_name_size{64};
    char product_name[s_product_name_size]{};     // Product name
    uint8_t init_done{0};                         // homestore init completed flag
    uint8_t pad[7]{};                             // pad to 64 bit
    pdev_info_block this_dev_info{0};             // Info about this device itself
    chunk_info_block dm_chunk[s_num_dm_chunks]{}; // chunk info blocks
    uint64_t system_uuid{0};                      // homestore system uuid.  hs_uuid_t(time_t) is an ambiguous typedef
    disk_attr dev_attr;                           // device attributes (from iomgr);

    void set_init_done(const bool done) { init_done = static_cast< uint8_t >(done ? 0x01 : 0x00); }
    bool is_init_done() const { return (init_done == 0x01); }

    uint64_t get_magic() const { return magic; }
    const char* get_product_name() const { return product_name; }
    uint32_t get_version() const { return version; }
    void set_system_uuid(const hs_uuid_t uuid) { system_uuid = static_cast< uint64_t >(uuid); }
    hs_uuid_t get_system_uuid() const { return static_cast< hs_uuid_t >(system_uuid); }
    std::string to_string() const {
        auto str = fmt::format("magic {:#x}, gen_cnt {}, version {}, cur_indx {}, product_name {}, init_done {}, "
                               "system_uuid {}, dev_attr {}",
                               get_magic(), gen_cnt, get_version(), cur_indx, get_product_name(), init_done,
                               get_system_uuid(), dev_attr.to_string());
        return str;
    }
};

static_assert(sizeof(super_block) <= super_block::s_min_sb_size);
inline size_t SUPERBLOCK_SIZE(const uint32_t phys_page_sz) { return sisl::round_up(sizeof(super_block), phys_page_sz); }

/********************************************** dm_info ***************************************************/
// NOTE: After this structure in memory follows pdev_info_block followed by chunk_info_block array
// followed by vdev_info_block array
struct dm_info {
    /* header of pdev, chunk and vdev */
    uint64_t magic{0};    // Header magic expected to be at the top of block
    uint16_t checksum{0}; // Payload Checksum
    uint8_t pad[2]{};     // pad to 4 byte alignment
    uint32_t version{0};
    uint64_t size{0};

    pdevs_block pdev_hdr{};
    chunks_block chunk_hdr{};
    vdevs_block vdev_hdr{};

    uint64_t get_magic() const { return magic; }
    uint64_t get_size() const { return size; }
    uint32_t get_version() const { return version; }
    uint16_t get_checksum() const { return checksum; }

    static const size_t s_pdev_info_blocks_size;
    static size_t s_chunk_info_blocks_size;
    static const size_t s_vdev_info_blocks_size;
    static size_t s_dm_info_block_size;

    pdev_info_block* get_pdev_info_blocks() {
        return reinterpret_cast< pdev_info_block* >(reinterpret_cast< uint8_t* >(this) + sizeof(dm_info));
    }
    chunk_info_block* get_chunk_info_blocks() {
        return reinterpret_cast< chunk_info_block* >(reinterpret_cast< uint8_t* >(this) + sizeof(dm_info) +
                                                     s_pdev_info_blocks_size);
    }
    vdev_info_block* get_vdev_info_blocks() {
        return reinterpret_cast< vdev_info_block* >(reinterpret_cast< uint8_t* >(this) + sizeof(dm_info) +
                                                    s_pdev_info_blocks_size + s_chunk_info_blocks_size);
    }

    static constexpr size_t s_dm_payload_offset{12}; // offset to version entry of dm_info
};
#pragma pack()

class PhysicalDev;
class BlkAllocator;
class meta_blk;
class DeviceManager;

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

class PhysicalDevChunk {
public:
    friend class DeviceManager;

    PhysicalDevChunk(PhysicalDev* pdev, chunk_info_block* cinfo);
    PhysicalDevChunk(PhysicalDev* pdev, uint32_t chunk_id, uint64_t start_offset, uint64_t size,
                     chunk_info_block* cinfo);

    PhysicalDevChunk(const PhysicalDevChunk&) = delete;
    PhysicalDevChunk(PhysicalDevChunk&&) noexcept = delete;
    PhysicalDevChunk& operator=(const PhysicalDevChunk&) = delete;
    PhysicalDevChunk& operator=(PhysicalDevChunk&&) noexcept = delete;
    ~PhysicalDevChunk();

    /////////////// Pointer Getters ////////////////////
    const PhysicalDev* physical_dev() const { return m_pdev; }
    PhysicalDev* physical_dev_mutable() { return m_pdev; };
    const DeviceManager* device_manager() const;
    DeviceManager* device_manager_mutable();

    void set_blk_allocator(std::shared_ptr< BlkAllocator > alloc) { m_allocator = alloc; }
    std::shared_ptr< const BlkAllocator > blk_allocator() const { return m_allocator; }
    std::shared_ptr< BlkAllocator > blk_allocator_mutable() { return m_allocator; }

    const PhysicalDevChunk* next_chunk() const;
    PhysicalDevChunk* next_chunk_mutable();
    const PhysicalDevChunk* prev_chunk() const;
    PhysicalDevChunk* prev_chunk_mutable();
    const PhysicalDevChunk* primary_chunk() const;
    PhysicalDevChunk* primary_chunk_mutable();
    const chunk_info_block* chunk_info() const { return m_chunk_info; }
    chunk_info_block* chunk_info_mutbale() { return m_chunk_info; }

    /////////////// Setters ////////////////////
    void set_sb_chunk() { m_chunk_info->set_sb_chunk(true); }
    void set_start_offset(uint64_t offset) { m_chunk_info->chunk_start_offset = offset; }
    void set_size(uint64_t size) { m_chunk_info->chunk_size = size; }
    void set_vdev_id(uint32_t vdev_id) { m_chunk_info->vdev_id = vdev_id; }
    void set_next_chunk_id(uint32_t next_chunk_id) { m_chunk_info->next_chunk_id = next_chunk_id; }
    void set_next_chunk(PhysicalDevChunk* next_chunk) {
        set_next_chunk_id(next_chunk ? next_chunk->chunk_id() : INVALID_CHUNK_ID);
    }
    void set_free() {
        set_vdev_id(INVALID_VDEV_ID);
        m_chunk_info->primary_chunk_id = INVALID_CHUNK_ID;
        m_chunk_info->set_sb_chunk(false);
    }
    void set_prev_chunk_id(uint32_t prev_chunk_id) { m_chunk_info->prev_chunk_id = prev_chunk_id; }
    void set_prev_chunk(PhysicalDevChunk* prev_chunk) {
        set_prev_chunk_id(prev_chunk ? prev_chunk->chunk_id() : INVALID_CHUNK_ID);
    }
    void set_primary_chunk_id(uint32_t primary_id) { m_chunk_info->primary_chunk_id = primary_id; }
    void free_slot() { m_chunk_info->set_slot_allocated(false); }
    void update_end_of_chunk(uint64_t sz) { m_chunk_info->end_of_chunk_size = int64_cast(sz); }
    void update_start_offset(uint64_t start_offset) { m_chunk_info->update_start_offset(start_offset); }

    /////////////// Getters ////////////////////
    uint64_t start_offset() const { return m_chunk_info->chunk_start_offset; }
    uint64_t size() const { return m_chunk_info->chunk_size; }
    bool is_busy() const { return (m_chunk_info->vdev_id != INVALID_VDEV_ID || m_chunk_info->is_sb_chunk()); }
    uint32_t vdev_id() const { return m_chunk_info->vdev_id; }
    uint32_t next_chunk_id() const { return m_chunk_info->next_chunk_id; }
    uint32_t prev_chunk_id() const { return m_chunk_info->prev_chunk_id; }
    uint16_t chunk_id() const { return static_cast< uint16_t >(m_chunk_info->chunk_id); }
    off_t end_of_chunk() const { return s_cast< off_t >(m_chunk_info->end_of_chunk_size); }

    std::string to_string() const;
    nlohmann::json get_status([[maybe_unused]] int log_level) const;

    /////////////// Recovery and CP related ////////////////////
    void recover(std::unique_ptr< sisl::Bitset > recovered_bm, meta_blk* mblk);
    void recover();
    void cp_flush();

private:
    chunk_info_block* m_chunk_info;
    PhysicalDev* m_pdev;
    std::shared_ptr< BlkAllocator > m_allocator;
    uint64_t m_vdev_metadata_size;
    void* m_meta_blk_cookie = nullptr;
    std::unique_ptr< sisl::Bitset > m_recovered_bm;
};

class PhysicalDev {
    friend class PhysicalDevChunk;
    friend class DeviceManager;

public:
    PhysicalDev(const std::string& devname, int oflags);

    /**
     * @brief
     *
     * @param mgr
     * @param devname
     * @param oflags
     * @param uuid :
     *  if is_init is set to true, this uuid will be used to set to pdev's superblock;
     *  if is_init is set to false, this uuid will be used to for varification with this pdev's stored system uuid;
     * @param dev_num
     * @param dev_offset
     * @param is_init :  true if this is a first time boot, false if this is not a first time boot
     * @param dm_info_size
     * @param is_inited :
     *  if this is set to true in a recovery boot, then it means this is a spare/new disk.
     *  if this is set to false in a recovery boot, it is expected.
     *  this field will not be changed if is_init is set to true(first-time-boot)
     */
    PhysicalDev(DeviceManager* mgr, const std::string& devname, int oflags, const hs_uuid_t& uuid, uint32_t dev_num,
                uint64_t dev_offset, bool is_init, uint64_t dm_info_size, bool* is_inited);

    PhysicalDev(const PhysicalDev&) = delete;
    PhysicalDev(PhysicalDev&&) noexcept = delete;
    PhysicalDev& operator=(const PhysicalDev&) = delete;
    PhysicalDev& operator=(PhysicalDev&&) noexcept = delete;
    ~PhysicalDev();

    void update(uint32_t dev_num, uint64_t dev_offset, uint32_t first_chunk_id);
    void attach_superblock_chunk(PhysicalDevChunk* chunk);
    uint64_t sb_gen_cnt();

    //////////////// Getters ////////////////////
    const std::string& get_devname() const { return m_devname; }
    uint64_t size() const { return m_devsize; }
    uint32_t first_chunk_id() const { return m_info_blk.first_chunk_id; }
    uint64_t dev_offset() const { return m_info_blk.dev_offset; }
    uint32_t dev_id() const { return m_info_blk.dev_num; }
    size_t total_cap() const;
    uint64_t stream_aligned_offset() const;
    uint32_t page_size() const;
    uint32_t atomic_page_size() const;
    uint32_t align_size() const;
    uint32_t num_streams() const;
    std::string to_string() const;

    ///////////// Pointer Getters ///////////////////////
    const DeviceManager* device_manager() const { return m_mgr; }
    DeviceManager* device_manager_mutable() { return m_mgr; }
    PhysicalDevMetrics& metrics() { return m_metrics; }
    iomgr::DriveInterface* drive_iface() const { return m_drive_iface; }

    void set_dev_offset(uint64_t offset) { m_info_blk.dev_offset = offset; }
    void set_dev_id(uint32_t id) { m_info_blk.dev_num = id; }

    /* Attach the given chunk to the list of chunks in the physical device. Parameter after provides the position
     * it needs to attach after. If null, attach to the end */
    void attach_chunk(PhysicalDevChunk* chunk, PhysicalDevChunk* after);

    /* Merge previous and next chunk from the chunk, if either one or both of them free. Returns the array of
     * chunk id which were merged and can be freed if needed */
    std::array< uint32_t, 2 > merge_free_chunks(PhysicalDevChunk* chunk);

    /* Find a free chunk which closestly match for the required size */
    PhysicalDevChunk* find_free_chunk(uint64_t req_size);

    //////////// IO Methods /////////////////////
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

    pdev_info_block get_info_blk();
    void read_dm_chunk(char* mem, uint64_t size);
    void write_dm_chunk(uint64_t gen_cnt, const char* mem, uint64_t size);
    uint64_t inc_error_cnt() { return (m_error_cnt.increment(1)); }

    /**
     * @brief: zero the super block;
     */
    void zero_superblock();

    /**
     * @brief: check whether there is formated homestore super block
     *
     * @return: true if there is formated homestore super block, false if not;
     */
    bool has_valid_superblock(hs_uuid_t& out_uuid);

    void init_done();

    bool is_hdd() const;
    void close_device();

    hs_uuid_t sys_uuid() { return m_super_blk->get_system_uuid(); }

    /**
     * @brief : Get the stream size reported by iomgr;
     *
     * @return : return stream size reported by iomgr of this device;
     */
    uint64_t raw_stream_size() const;

#if 0
    uint32_t page_size() const { return (page_size(m_devname)); }
    uint32_t atomic_page_size() const { return (atomic_page_size(m_devname)); }
    uint32_t align_size() const { return (align_size(m_devname)); }

    static uint32_t page_size(const std::string& devname);
    static uint32_t atomic_page_size(const std::string& devname);
    static uint32_t align_size(const std::string& devname);
#endif

public:
    static void zero_boot_sbs(const std::vector< dev_info >& devices, int oflags);

private:
    void write_superblock();
    void read_superblock();
    void read_and_fill_superblock(int oflags);

    void alloc_superblock(uint32_t sb_size, uint32_t align_sz);
    void free_superblock();

    bool resize_superblock_if_needed(uint32_t atomic_page_sz, uint32_t align_sz);

    bool is_init_done() const { return m_super_blk->is_init_done(); }

    /* Load the physical device info from persistent storage. If its not a valid device, it will throw
     * std::system_exception. Returns true if the device has already formatted for Omstore, false otherwise. */
    bool load_super_block(const hs_uuid_t& system_uuid);

    /* Format the physical device info. Intended to use first time or anytime we need to reformat the drives. Throws
     * std::system_exception if there is any write errors */
    void write_super_block(uint64_t gen_cnt);

    /* Validate if this device is a homestore validated device. If there is any corrupted device, then it
     * throws std::system_exception */
    bool validate_device() const;

    /*
     * return true if we are upgrading from some version that is supported for upgrade;
     * return false if not;
     * */
    bool is_from_upgradable_version() const;

private:
    DeviceManager* m_mgr; // Back pointer to physical device
    iomgr::io_device_ptr m_iodev;
    iomgr::DriveInterface* m_drive_iface; // Interface to do IO
    std::string m_devname;
    super_block* m_super_blk{nullptr}; // Persisent header block
    uint64_t m_devsize{0};
    pdev_info_block m_info_blk;
    std::array< PhysicalDevChunk*, super_block::s_num_dm_chunks > m_dm_chunk;
    static constexpr size_t s_dm_chunk_mask{super_block::s_num_dm_chunks - 1};
    PhysicalDevMetrics m_metrics; // Metrics instance per physical device
    int32_t m_cur_indx{0};
    bool m_superblock_valid{false};
    sisl::atomic_counter< uint64_t > m_error_cnt{0};
};
} // namespace homestore
