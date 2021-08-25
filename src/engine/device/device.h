/*
 * device.h
 *
 *  Created on: 05-Aug-2016
 *      Author: Hari Kadayam
 */

#pragma once

#define BOOST_UUID_RANDOM_PROVIDER_FORCE_POSIX 1

#include <array>
#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#ifdef __linux__
#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>
#endif

#include <boost/intrusive/list.hpp>
#include <boost/uuid/uuid.hpp>            // uuid class
#include <boost/uuid/uuid_generators.hpp> // generators
#include <boost/uuid/uuid_io.hpp>         // streaming operators etc.
#include <fds/buffer.hpp>
#include <fds/sparse_vector.hpp>
#include <fds/utils.hpp>
#include <iomgr/iomgr.hpp>
#include <isa-l/crc.h>
#include <sds_logging/logging.h>

#include <engine/homestore_base.hpp>

#include "api/meta_interface.hpp"

using namespace iomgr;
SDS_LOGGING_DECL(device, DEVICE_MANAGER)

namespace homestore {
class BlkAllocator;
struct blkalloc_cp;

static constexpr uint32_t MAGIC{0xCEEDDEEB};
#define PRODUCT_NAME "OmStore"

/************* Super Block definition ******************/

static constexpr uint32_t CURRENT_SUPERBLOCK_VERSION{1};
static constexpr uint32_t CURRENT_DM_INFO_VERSION{1};

/*******************************************************************************************************
 *  _______________________             _________________________________________________________      *
 * |                       |           |                  |            |             |            |    *
 * |  Super block header   |---------->| Super Block info | Pdev Block | Chunk Block | Vdev Block |    *
 * |_______________________|           |__________________|____________|_____________|____________|    *
 *                                                                                                     *
 *******************************************************************************************************/

/************* Physical Device Info Block definition ******************/

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

/************* chunk Info Block definition ******************/

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
};
#pragma pack()

/************* Vdev Info Block definition ******************/
#pragma pack(1)
struct vdevs_block {
    uint64_t magic{0};         // Header magic expected to be at the top of block
    uint32_t num_vdevs{0};     // Number of virtual devices
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
    uint32_t page_size{0};          // 16: IO block size for this vdev
    uint32_t prev_vdev_id{0};       // 20: Prev pointer of vdevice list
    uint32_t next_vdev_id{0};       // 24: Next pointer of vdevice list
    uint32_t num_primary_chunks{0}; // 28: number of primary chunks
    uint8_t slot_allocated{0};      // 32: Is this current slot allocated
    uint8_t failed{0};              // 33: set to true if disk is replaced

    uint8_t padding[MAX_VDEV_INFO_BLOCK_HDR_SZ - 34]{}; // Ugly hardcode will be removed after moving to superblk blkstore
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

/*******************Super Block Definition*******************/

/* This header should be atomically written to the disks. It should always be smaller then ssd atomic page size */
static constexpr size_t SUPERBLOCK_PAYLOAD_OFFSET{4096};

#pragma pack(1)
struct super_block {
    static constexpr size_t s_num_dm_chunks{2};
    static_assert((s_num_dm_chunks & (s_num_dm_chunks - 1)) == 0,
                  "Size must be power of 2 for optimizations of & vs modulo");
    uint8_t empty_buf[SUPERBLOCK_PAYLOAD_OFFSET]{}; // don't write anything to first 4096 bytes.
    uint64_t magic{0};                              // Header magic expected to be at the top of block
    uint64_t gen_cnt{0};
    uint32_t version{0};                            // Version Id of this structure
    int32_t cur_indx{0};
    static constexpr size_t s_product_name_size{64};
    char product_name[s_product_name_size]{}; // Product name
    uint8_t init_done{0};             // homestore init completed flag
    uint8_t pad[7]{};                 // pad to 64 bit
    pdev_info_block this_dev_info{0}; // Info about this device itself
    chunk_info_block dm_chunk[s_num_dm_chunks]{}; // chunk info blocks
    uint64_t system_uuid{0};                    // homestore system uuid.  hs_uuid_t(time_t) is an ambiguous type

    void set_init_done(const bool done) { init_done = static_cast< uint8_t >(done ? 0x01 : 0x00); }
    bool is_init_done() const { return (init_done == 0x01); }

    uint64_t get_magic() const { return magic; }
    const char* get_product_name() const { return product_name; }
    uint32_t get_version() const { return version; }
    void set_system_uuid(const hs_uuid_t uuid) { system_uuid = static_cast< uint64_t >(uuid); }
    hs_uuid_t get_system_uuid() const { return static_cast< hs_uuid_t >(system_uuid); }
};
#pragma pack()

static const size_t SUPERBLOCK_SIZE{sisl::round_up(std::max(sizeof(super_block), HS_STATIC_CONFIG(drive_attr.atomic_phys_page_size) + SUPERBLOCK_PAYLOAD_OFFSET), HS_STATIC_CONFIG(drive_attr.atomic_phys_page_size))};

#pragma pack(1)
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
    static const size_t s_chunk_info_blocks_size;
    static const size_t s_vdev_info_blocks_size;
    static const size_t dm_info_block_size;

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

   	static constexpr size_t s_dm_payload_offset{12};  // offset to version entry of dm_info
};
#pragma pack()

static constexpr uint32_t INVALID_PDEV_ID{std::numeric_limits< uint32_t >::max()};
static constexpr uint32_t INVALID_VDEV_ID{std::numeric_limits< uint32_t >::max()};
static constexpr uint32_t INVALID_CHUNK_ID{std::numeric_limits< uint32_t >::max()};
static constexpr uint32_t INVALID_DEV_ID{std::numeric_limits< uint32_t >::max()};

class PhysicalDev;

class DeviceManager;
typedef std::function< void(int status, uint8_t* cookie) > comp_callback;

class PhysicalDevChunk {
public:
    friend class DeviceManager;

    PhysicalDevChunk(PhysicalDev* const pdev, chunk_info_block* const cinfo);
    PhysicalDevChunk(PhysicalDev* const pdev, const uint32_t chunk_id, const uint64_t start_offset, const uint64_t size,
                     chunk_info_block* const cinfo);

    PhysicalDevChunk(const PhysicalDevChunk&) = delete;
    PhysicalDevChunk(PhysicalDevChunk&&) noexcept = delete;
    PhysicalDevChunk& operator=(const PhysicalDevChunk&) = delete;
    PhysicalDevChunk& operator=(PhysicalDevChunk&&) noexcept = delete;
    ~PhysicalDevChunk();

    const PhysicalDev* get_physical_dev() const { return m_pdev; }

    PhysicalDev* get_physical_dev_mutable() { return m_pdev; };

    const DeviceManager* device_manager() const;

    DeviceManager* device_manager_mutable();

    void set_blk_allocator(std::shared_ptr< homestore::BlkAllocator > alloc) { m_allocator = alloc; }

    std::shared_ptr< const BlkAllocator > get_blk_allocator() const { return m_allocator; }

    std::shared_ptr< BlkAllocator > get_blk_allocator_mutable() { return m_allocator; }

    void set_sb_chunk() { m_chunk_info->set_sb_chunk(true); }
    void set_start_offset(const uint64_t offset) { m_chunk_info->chunk_start_offset = offset; }

    uint64_t get_start_offset() const { return m_chunk_info->chunk_start_offset; }

    void set_size(const uint64_t size) { m_chunk_info->chunk_size = size; }

    uint64_t get_size() const { return m_chunk_info->chunk_size; }

    bool is_busy() const { return (m_chunk_info->vdev_id != INVALID_VDEV_ID || m_chunk_info->is_sb_chunk()); }

    void set_free() {
        set_vdev_id(INVALID_VDEV_ID);
        m_chunk_info->primary_chunk_id = INVALID_CHUNK_ID;
        m_chunk_info->set_sb_chunk(false);
    }

    uint32_t get_vdev_id() const { return m_chunk_info->vdev_id; }

    void set_vdev_id(const uint32_t vdev_id) { m_chunk_info->vdev_id = vdev_id; }

    void set_next_chunk_id(const uint32_t next_chunk_id) { m_chunk_info->next_chunk_id = next_chunk_id; }

    void set_next_chunk(PhysicalDevChunk* const next_chunk) {
        set_next_chunk_id(next_chunk ? next_chunk->get_chunk_id() : INVALID_CHUNK_ID);
    }

    uint32_t get_next_chunk_id() const { return m_chunk_info->next_chunk_id; }

    const PhysicalDevChunk* get_next_chunk() const;

    PhysicalDevChunk* get_next_chunk_mutable();

    void set_prev_chunk_id(const uint32_t prev_chunk_id) { m_chunk_info->prev_chunk_id = prev_chunk_id; }

    void set_prev_chunk(PhysicalDevChunk* const prev_chunk) {
        set_prev_chunk_id(prev_chunk ? prev_chunk->get_chunk_id() : INVALID_CHUNK_ID);
    }

    uint32_t get_prev_chunk_id() const { return m_chunk_info->prev_chunk_id; }

    const PhysicalDevChunk* get_prev_chunk() const;

    PhysicalDevChunk* get_prev_chunk_mutable();

    const chunk_info_block* get_chunk_info() const { return m_chunk_info; }

    chunk_info_block* get_chunk_info_mutbale() { return m_chunk_info; }

    uint16_t get_chunk_id() const { return static_cast< uint16_t >(m_chunk_info->chunk_id); }

    void free_slot() { m_chunk_info->set_slot_allocated(false); }

    const PhysicalDevChunk* get_primary_chunk() const;

    PhysicalDevChunk* get_primary_chunk_mutable();

    void set_primary_chunk_id(const uint32_t primary_id) { m_chunk_info->primary_chunk_id = primary_id; }

    std::string to_string() const {
        std::ostringstream ss;
        ss << "chunk_id = " << get_chunk_id() << " pdev_id = " << m_chunk_info->pdev_id
           << " vdev_id = " << m_chunk_info->vdev_id << " start_offset = " << m_chunk_info->chunk_start_offset
           << " size = " << m_chunk_info->chunk_size << " prev_chunk_id = " << m_chunk_info->prev_chunk_id
           << " next_chunk_id = " << m_chunk_info->next_chunk_id << " busy? = " << is_busy()
           << " slot_allocated? = " << m_chunk_info->is_slot_allocated();
        return ss.str();
    }

    void update_end_of_chunk(const uint64_t size) {
        LOGINFOMOD(device, "chunk id {}, end size {} actual size {}", get_chunk_id(), size, get_size());
        m_chunk_info->end_of_chunk_size = static_cast<int64_t>(size);
    }
    off_t get_end_of_chunk() const { return static_cast< off_t >(m_chunk_info->end_of_chunk_size); }

    void recover(std::unique_ptr< sisl::Bitset > recovered_bm, meta_blk* const mblk);

    void recover();

    void cp_start(std::shared_ptr< blkalloc_cp > ba_cp);

    static std::shared_ptr< blkalloc_cp > attach_prepare_cp(std::shared_ptr< blkalloc_cp > cur_ba_cp);

    // void cp_done(std::shared_ptr< blkalloc_cp > ba_cp);

private:
    chunk_info_block* m_chunk_info;
    PhysicalDev* m_pdev;
    std::shared_ptr< BlkAllocator > m_allocator;
    uint64_t m_vdev_metadata_size;
    void* m_meta_blk_cookie = nullptr;
    std::unique_ptr< sisl::Bitset > m_recovered_bm;
};

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

class PhysicalDev {
    friend class PhysicalDevChunk;
    friend class DeviceManager;

public:
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
     * @param drive_type
     * @param is_init :  true if this is a first time boot, false if this is not a first time boot
     * @param dm_info_size
     * @param is_inited :
     *  if this is set to true in a recovery boot, then it means this is a spare/new disk.
     *  if this is set to false in a recovery boot, it is expected.
     *  this field will not be changed if is_init is set to true(first-time-boot)
     */
    PhysicalDev(DeviceManager* const mgr, const std::string& devname, const int oflags, const hs_uuid_t& uuid,
                const uint32_t dev_num, const uint64_t dev_offset, const iomgr::iomgr_drive_type drive_type,
                const bool is_init, const uint64_t dm_info_size, bool* const is_inited);

    PhysicalDev(DeviceManager* const mgr, const std::string& devname, const int oflags, const iomgr::iomgr_drive_type drive_type);

    PhysicalDev(const PhysicalDev&) = delete;
    PhysicalDev(PhysicalDev&&) noexcept = delete;
    PhysicalDev& operator=(const PhysicalDev&) = delete;
    PhysicalDev& operator=(PhysicalDev&&) noexcept = delete;
    ~PhysicalDev();

    void update(const uint32_t dev_num, const uint64_t dev_offset, const uint32_t first_chunk_id);
    void attach_superblock_chunk(PhysicalDevChunk* const chunk);
    uint64_t sb_gen_cnt();
    size_t get_total_cap();

    const std::string& get_devname() const { return m_devname; }
    uint64_t get_size() const { return m_devsize; }
    uint32_t get_first_chunk_id() const { return m_info_blk.first_chunk_id; }
    uint64_t get_dev_offset() const { return m_info_blk.dev_offset; }
    uint32_t get_dev_id() const { return m_info_blk.dev_num; }
    PhysicalDevMetrics& get_metrics() { return m_metrics; }

    void set_dev_offset(const uint64_t offset) { m_info_blk.dev_offset = offset; }
    void set_dev_id(const uint32_t id) { m_info_blk.dev_num = id; }

    const DeviceManager* device_manager() const { return m_mgr; }

    DeviceManager* device_manager_mutable() { return m_mgr; }

    std::string to_string();
    /* Attach the given chunk to the list of chunks in the physical device. Parameter after provides the position
     * it needs to attach after. If null, attach to the end */
    void attach_chunk(PhysicalDevChunk* const chunk, PhysicalDevChunk* const after);

    /* Merge previous and next chunk from the chunk, if either one or both of them free. Returns the array of
     * chunk id which were merged and can be freed if needed */
    std::array< uint32_t, 2 > merge_free_chunks(PhysicalDevChunk* const chunk);

    /* Find a free chunk which closestly match for the required size */
    PhysicalDevChunk* find_free_chunk(const uint64_t req_size);

    void write(const char* const data, const uint32_t size, const uint64_t offset, uint8_t* const cookie, const bool part_of_batch = false);
    void writev(const iovec* const iov, const int iovcnt, const uint32_t size, const uint64_t offset, uint8_t* const cookie,
                const bool part_of_batch = false);
    void write_zero(const uint64_t size, const uint64_t offset, uint8_t* const cookie);

    void read(char* const data, const uint32_t size, const uint64_t offset, uint8_t* const cookie, const bool part_of_batch = false);
    void readv(iovec* const iov, const int iovcnt, const uint32_t size, const uint64_t offset, uint8_t* const cookie,
               const bool part_of_batch = false);

    ssize_t sync_write(const char* const data, const uint32_t size, const uint64_t offset);
    ssize_t sync_writev(const iovec* const iov, const int iovcnt, const uint32_t size, const uint64_t offset);

    ssize_t sync_read(char* const data, const uint32_t size, const uint64_t offset);
    ssize_t sync_readv(iovec* const iov, const int iovcnt, const uint32_t size, const uint64_t offset);
    pdev_info_block get_info_blk();
    void read_dm_chunk(char* const mem, const uint64_t size);
    void write_dm_chunk(const uint64_t gen_cnt, const char* const mem, const uint64_t size);
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

    void close_device();

    hs_uuid_t get_sys_uuid() { return m_super_blk->get_system_uuid(); }

public:
    static void zero_boot_sbs(const std::vector< dev_info >& devices, const iomgr_drive_type drive_type, const int oflags);

private:
    inline void write_superblock();
    inline void read_superblock();

    bool is_init_done() const { return m_super_blk->is_init_done(); }

    /* Load the physical device info from persistent storage. If its not a valid device, it will throw
     * std::system_exception. Returns true if the device has already formatted for Omstore, false otherwise. */
    bool load_super_block(const hs_uuid_t& system_uuid);

    /* Format the physical device info. Intended to use first time or anytime we need to reformat the drives. Throws
     * std::system_exception if there is any write errors */
    void write_super_block(const uint64_t gen_cnt);

    /* Validate if this device is a homestore validated device. If there is any corrupted device, then it
     * throws std::system_exception */
    bool validate_device();

private:
    DeviceManager* m_mgr; // Back pointer to physical device
    io_device_ptr m_iodev;
    std::string m_devname;
    super_block* m_super_blk{nullptr}; // Persisent header block
    uint64_t m_devsize{0};
    struct pdev_info_block m_info_blk;
    std::array< PhysicalDevChunk*, super_block::s_num_dm_chunks > m_dm_chunk;
    static constexpr size_t s_dm_chunk_mask{super_block::s_num_dm_chunks - 1};
    PhysicalDevMetrics m_metrics; // Metrics instance per physical device
    int32_t m_cur_indx{0};
    bool m_superblock_valid{false};
    sisl::atomic_counter< uint64_t > m_error_cnt{0};
};

class AbstractVirtualDev {
public:
    AbstractVirtualDev() = default;
    AbstractVirtualDev(const AbstractVirtualDev& other) = delete;
    AbstractVirtualDev& operator=(const AbstractVirtualDev& other) = delete;
    AbstractVirtualDev(AbstractVirtualDev&&) noexcept = delete;
    AbstractVirtualDev& operator=(AbstractVirtualDev&&) noexcept = delete;
    virtual ~AbstractVirtualDev() = default;

    virtual void add_chunk(PhysicalDevChunk* const chunk) = 0;
};

class DeviceManager {
    typedef std::function< void(DeviceManager*, vdev_info_block*) > NewVDevCallback;
    typedef std::function< void(PhysicalDevChunk*) > chunk_add_callback;
    typedef std::function< void(vdev_info_block*) > vdev_error_callback;

    friend class PhysicalDev;
    friend class PhysicalDevChunk;

public:
    DeviceManager(NewVDevCallback vcb, const uint32_t vdev_metadata_size,
                  const iomgr::io_interface_comp_cb_t& io_comp_cb, const iomgr::iomgr_drive_type drive_type,
                  const vdev_error_callback& vdev_error_cb);

    DeviceManager(const DeviceManager& other) = delete;
    DeviceManager& operator=(const DeviceManager& other) = delete;
    DeviceManager(DeviceManager&&) noexcept = delete;
    DeviceManager& operator=(DeviceManager&&) noexcept = delete;
    ~DeviceManager();

    /**
     * @brief : Initial routine to call upon bootup or everytime new physical devices to be added dynamically
     * @param devices
     *
     * @return :
     *  true if it is first time boot, meaning there is no valid sb on device
     *  false if it is recovery reboot, meaning there is valid sb found on device
     */
    bool add_devices(const std::vector< dev_info >& devices);
    size_t get_total_cap() const;
    void handle_error(PhysicalDev* const pdev);

    /* This is not very efficient implementation of get_all_devices(), however, this is expected to be called during
     * the start of the devices and for that purpose its efficient enough */
    std::vector< PhysicalDev* > get_all_devices() {
        std::vector< PhysicalDev* > vec;
        std::lock_guard< decltype(m_dev_mutex) > lock(m_dev_mutex);

        vec.reserve(m_pdevs.size());
        for (auto& pdev : m_pdevs) {
            if (pdev) vec.push_back(pdev.get());
        }
        return vec;
    }

    /* Allocate a chunk for required size on the given physical dev and associate the chunk to provide virtual device.
     * Returns the allocated PhysicalDevChunk */
    PhysicalDevChunk* alloc_chunk(PhysicalDev* const pdev, const uint32_t vdev_id, const uint64_t req_size, const uint32_t primary_id);

    /* Free the chunk for later user */
    void free_chunk(PhysicalDevChunk* const chunk);

    /* Allocate a new vdev for required size */
    vdev_info_block* alloc_vdev(const uint32_t req_size, const uint32_t nmirrors, const uint32_t blk_size, const uint32_t nchunks, char* const blob,
                                const uint64_t size);

    /* Free up the vdev_id */
    void free_vdev(vdev_info_block* const vb);

    /* Given an ID, get the chunk */
    const PhysicalDevChunk* get_chunk(const uint32_t chunk_id) const {
        return (chunk_id == INVALID_CHUNK_ID) ? nullptr : m_chunks[chunk_id].get();
    }

    PhysicalDevChunk* get_chunk_mutable(const uint32_t chunk_id) {
        return (chunk_id == INVALID_CHUNK_ID) ? nullptr : m_chunks[chunk_id].get();
    }

    PhysicalDev* get_pdev(const uint32_t pdev_id) {
        return (pdev_id == INVALID_PDEV_ID) ? nullptr : m_pdevs[pdev_id].get();
    }

    void add_chunks(const uint32_t vid, const chunk_add_callback& cb);
    void inited();
    void write_info_blocks();
    void update_vb_context(const uint32_t vdev_id, const sisl::blob& ctx_data);
    void get_vb_context(const uint32_t vdev_id, const sisl::blob& ctx_data);
    void update_end_of_chunk(PhysicalDevChunk* const chunk, const off_t offset);
    void init_done();
    void close_devices();
    bool is_first_time_boot() const { return m_first_time_boot; }
    // void zero_pdev_sbs();

public:
    static void zero_boot_sbs(const std::vector< dev_info >& devices, const iomgr_drive_type drive_type, const io_flag oflags);

private:
    void load_and_repair_devices(const std::vector< dev_info >& devices, const hs_uuid_t& system_uuid);
    void init_devices(const std::vector< dev_info >& devices);
    void read_info_blocks(const uint32_t dev_id);

    chunk_info_block* alloc_new_chunk_slot(uint32_t* const pslot_num);
    vdev_info_block* alloc_new_vdev_slot();

    PhysicalDevChunk* create_new_chunk(PhysicalDev* const pdev, const uint64_t start_offset, const uint64_t size,
                                       PhysicalDevChunk* const prev_chunk);
    void remove_chunk(const uint32_t chunk_id);
    void blk_alloc_meta_blk_found_cb(meta_blk* const mblk, const sisl::byte_view buf, const size_t size);

    static int get_open_flags(const io_flag oflags);

private:
    int m_open_flags;
    NewVDevCallback m_new_vdev_cb;
    std::atomic< uint64_t > m_gen_cnt{0};
    iomgr::iomgr_drive_type m_drive_type;

    char* m_chunk_memory{nullptr};

    /* This memory is carved out of chunk memory. Any changes in any of the block should end up writing all the blocks
     * on disk.
     */
    dm_info* m_dm_info{nullptr};
    pdevs_block* m_pdev_hdr{nullptr};
    chunks_block* m_chunk_hdr{nullptr};
    vdevs_block* m_vdev_hdr{nullptr};
    pdev_info_block* m_pdev_info{nullptr};
    chunk_info_block* m_chunk_info{nullptr};
    vdev_info_block* m_vdev_info{nullptr};

    std::mutex m_dev_mutex;

    sisl::sparse_vector< std::unique_ptr< PhysicalDev > > m_pdevs;
    sisl::sparse_vector< std::unique_ptr< PhysicalDevChunk > > m_chunks;
    sisl::sparse_vector< AbstractVirtualDev* > m_vdevs;
    uint32_t m_last_vdevid{INVALID_VDEV_ID};
    uint32_t m_vdev_metadata_size; // Appln metadata size for vdev
    uint32_t m_pdev_id{0};
    bool m_scan_cmpltd{false};
    uint64_t m_dm_info_size{0};
    vdev_error_callback m_vdev_error_cb;
    bool m_first_time_boot{true};
}; // class DeviceManager

} // namespace homestore
