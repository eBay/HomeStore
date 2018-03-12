/*
 * device.h
 *
 *  Created on: 05-Aug-2016
 *      Author: Hari Kadayam
 */

#ifndef BLKDEV_BLKDEV_H_
#define BLKDEV_BLKDEV_H_

#include <boost/intrusive/list.hpp>
#include <sys/uio.h>
#include <unistd.h>
#include <exception>
#include <string>
#include <glog/logging.h>
#include <fcntl.h>
#include "blkalloc/blk_allocator.h"
#include <boost/uuid/uuid.hpp>            // uuid class
#include <boost/uuid/uuid_generators.hpp> // generators
#include <boost/uuid/uuid_io.hpp>         // streaming operators etc.
#include "omds/array/sparse_vector.hpp"

namespace omstore {

#define MAGIC                            0xCEEDDEEB
#define PRODUCT_NAME                     "OmStore"

/************* Super Block definition ******************/
struct pdev_info_block {
    boost::uuids::uuid uuid;                 // UUID for the physical device
    uint32_t           dev_num;              // Device ID for this store instance.
    uint32_t           first_chunk_id;       // First chunk id for this physical device
    uint64_t           dev_offset;           // Start offset of the device in global offset
} __attribute((packed));

#define CURRENT_SUPERBLOCK_VERSION           1
#define SUPERBLOCK_MAX_HEADER_SIZE           1024
#define SUPERBLOCK_SIZE                      32768   // Entire superblock size

struct super_block_header {
    uint64_t            magic;                // Header magic expected to be at the top of block
    char                product_name[64];     // Product name
    uint32_t            version;              // Version Id of this structure
    pdev_info_block     this_dev_info;        // Info about this device itself
    uint64_t            pdevs_block_offset;   // Offset from 0 where pdevs information is stored
    uint64_t            chunks_block_offset;  // Offset from 0 where chunks information is stored
    uint64_t            vdevs_block_offset;   // Offset from 0 where vdevs information is stored
} __attribute__((aligned(SUPERBLOCK_MAX_HEADER_SIZE)));

/************* Physical Device Info Block definition ******************/
#define PDEVS_BLOCK_MAX_SIZE                1024
#define CURRENT_PDEV_INFO_BLOCK_VERSION     1

struct pdevs_block {
    uint32_t          version;
    uint32_t          num_phys_devs;     // Total number of physical devices in the entire system
    pdev_info_block   pdev_info_blks[0]; // Info about every physical devices
} __attribute__((aligned(PDEVS_BLOCK_MAX_SIZE)));

/************* Vdev Info Block definition ******************/
#define CHUNKS_BLOCK_MAX_SIZE              8192
#define CURRENT_CHUNK_INFO_BLOCK_VERSION   1
struct chunk_info_block {
    uint64_t     chunk_start_offset;  // Start offset of the chunk within a pdev
    uint64_t     chunk_size;          // Chunk size
    uint32_t     chunk_id;            // Chunk id in global scope
    uint32_t     pdev_id;             // Physical device id this chunk is hosted on
    uint32_t     vdev_id;             // Virtual device id this chunk hosts. UINT32_MAX if chunk is free
    uint32_t     prev_chunk_id;       // Prev pointer in the chunk
    uint32_t     next_chunk_id;       // Next pointer in the chunk
    uint32_t     primary_chunk_id;     // Valid chunk id if this is a mirror of some chunk
    bool         slot_allocated;      // Is this slot allocated for any chunks.
} __attribute((packed));

struct chunks_block {
    uint32_t          version;
    uint32_t          num_chunks;     // Number of physical chunks for this block
    uint64_t          revision_num;   // Revision number of chunks_block, to load only if all devices has same revision
    chunk_info_block  chunks[0];      // Array of chunks
} __attribute__((aligned(CHUNKS_BLOCK_MAX_SIZE)));

/************* Vdev Info Block definition ******************/
#define VDEVS_BLOCK_MAX_SIZE              8192
#define CURRENT_VDEV_INFO_BLOCK_VERSION   1
struct vdev_info_block {
    uint32_t      vdev_id;            // Id for this vdev
    uint64_t      size;               // Size of the vdev
    uint32_t      num_mirrors;        // Total number of mirrors
    uint32_t      blk_size;           // IO block size for this vdev
    uint32_t      prev_vdev_id;       // Prev pointer of vdevice list
    uint32_t      next_vdev_id;       // Next pointer of vdevice list
    bool          slot_allocated;     // Is this current slot allocated
    char          context_data[0];    // Application dependent context data
} __attribute((packed));

struct vdevs_block {
    uint32_t        version;
    uint32_t        num_vdevs;         // Number of virtual devices
    uint32_t        first_vdev_id;     // First vdev id / Head of the vdev list
    uint32_t        context_data_size; // Size of the appln context size
    vdev_info_block vdevs[0];          // Array of vdevs
} __attribute__((aligned(VDEVS_BLOCK_MAX_SIZE)));

/*
struct vol_header_block {
    uint32_t          num_volumes;     // Number of physical chunks across the entire system
    chunk_info_block  chunks[0];      // Array of chunks
} __attribute__((aligned(CHUNK_HEADER_BLOCK_MAX_SIZE)));;
*/

#define INVALID_PDEV_ID   UINT32_MAX
#define INVALID_VDEV_ID   UINT32_MAX
#define INVALID_CHUNK_ID  UINT32_MAX

#if 0
struct chunk_header_block {
    uint32_t          version;
    uint32_t          num_chunks;     // Number of physical chunks across the entire system
    chunk_info_block  chunks[0];      // Array of chunks
} __attribute__((aligned(CHUNK_INFO_BLOCK_MAX_SIZE)));

struct phys_chunk_header {
    uint64_t     chunk_start_offset;
    uint64_t     chunk_size;
    uint32_t     next_chunk_slot;
    bool         chunk_busy;
    bool         slot_allocated;
} __attribute((packed));

// Header block format store in each physical device about the current size info
struct phys_dev_header_block {
    uint64_t           magic;                // Header magic expected to be at the top of block
    char               product_name[64];     // Product name
    uint32_t           version;              // Version Id of this structure
    boost::uuids::uuid uuid;                 // UUID for the physical device
    uint32_t           dev_num;              // Device ID for this store instance.
    uint64_t           dev_offset;           // Start offset of the device in global offset
    uint32_t           super_block_chunk_id; // Chunk number of the super block of product
    uint32_t           num_chunks;           // Number of physical chunks including this header
    phys_chunk_header  chunks[0];            // Array of chunks
} __attribute__((aligned(PHYS_DEV_PERSISTENT_HEADER_SIZE)));

static_assert(sizeof(phys_dev_header_block) == PHYS_DEV_PERSISTENT_HEADER_SIZE,
              "Size of phys_dev_header_block is not same as PHYS_DEV_PERSISTENT_HEADER_SIZE");
#endif

class PhysicalDev;

class DeviceException : public std::exception
{
public:
    inline static std::string const& to_string(std::string const& s) { return s; }

    template<typename ... Args>
    DeviceException(Args const&... args) {
        // using ::to_string;
        using std::to_string;
        int unpack[]{0, (m_what += DeviceException::to_string(args), 0)...};
        static_cast<void>(unpack);

        m_what += "\n";
        //m_what.append(Backtrace());
    }

    virtual const char* what() const noexcept {
        LOG(ERROR) << "Exception is " << m_what.c_str();
        return m_what.c_str();
    }

    virtual std::string *what_str() {
        return &m_what;
    }

private:
    std::string m_what;
};

class DeviceManager;

class PhysicalDevChunk {
public:
    friend class DeviceManager;

    PhysicalDevChunk(PhysicalDev *pdev, chunk_info_block *cinfo);
    PhysicalDevChunk(PhysicalDev *pdev, uint32_t chunk_id, uint64_t start_offset, uint64_t size, chunk_info_block *cinfo);

    const PhysicalDev *get_physical_dev() const {
        return m_pdev;
    }

    DeviceManager *device_manager() const;

    PhysicalDev *get_physical_dev_mutable() {
        return m_pdev;
    };

    void set_blk_allocator(std::shared_ptr< BlkAllocator > alloc) {
        m_allocator = std::move(alloc);
    }

    BlkAllocator *get_blk_allocator() {
        return m_allocator.get();
    }

    virtual BlkAllocator *get_blk_allocator_const() const {
        return m_allocator.get();
    }

    void set_start_offset(uint64_t offset) {
        m_chunk_info->chunk_start_offset = offset;
    }

    uint64_t get_start_offset() const {
        return m_chunk_info->chunk_start_offset;
    }

    void set_size(uint64_t size) {
        m_chunk_info->chunk_size = size;
    }

    uint64_t get_size() const {
        return m_chunk_info->chunk_size;
    }

    bool is_busy() const {
        return (m_chunk_info->vdev_id != INVALID_VDEV_ID);
    }

    void set_free() {
        set_vdev_id(INVALID_VDEV_ID);
        m_chunk_info->primary_chunk_id = INVALID_CHUNK_ID;
    }

    uint32_t get_vdev_id() const {
        return m_chunk_info->vdev_id;
    }

    void set_vdev_id(uint32_t vdev_id) {
        m_chunk_info->vdev_id = vdev_id;
    }

    void set_next_chunk_id(uint32_t next_chunk_id) {
        m_chunk_info->next_chunk_id = next_chunk_id;
    }

    void set_next_chunk(PhysicalDevChunk *next_chunk) {
        set_next_chunk_id(next_chunk ? next_chunk->get_chunk_id() : INVALID_CHUNK_ID);
    }

    uint32_t get_next_chunk_id() const {
        return m_chunk_info->next_chunk_id;
    }

    PhysicalDevChunk *get_next_chunk() const;

    void set_prev_chunk_id(uint32_t prev_chunk_id) {
        m_chunk_info->prev_chunk_id = prev_chunk_id;
    }

    void set_prev_chunk(PhysicalDevChunk *prev_chunk) {
        set_prev_chunk_id(prev_chunk ? prev_chunk->get_chunk_id() : INVALID_CHUNK_ID);
    }

    uint32_t get_prev_chunk_id() const {
        return m_chunk_info->prev_chunk_id;
    }

    PhysicalDevChunk *get_prev_chunk() const;

    uint16_t get_chunk_id() const {
        return (uint16_t)m_chunk_info->chunk_id;
    }

    void free_slot() {
        m_chunk_info->slot_allocated = false;
    }

    void set_primary_chunk(const PhysicalDevChunk *mchunk) {
        m_chunk_info->primary_chunk_id = mchunk->get_chunk_id();
    }

    PhysicalDevChunk *get_primary_chunk() const;

    std::string to_string() {
        std::stringstream ss;
        ss << "chunk_id = " << get_chunk_id() << " pdev_id = " << m_chunk_info->pdev_id
           << " vdev_id = " << m_chunk_info->vdev_id << " start_offset = " << m_chunk_info->chunk_start_offset
           << " size = " << m_chunk_info->chunk_size << " prev_chunk_id = " << m_chunk_info->prev_chunk_id
           << " next_chunk_id = " << m_chunk_info->next_chunk_id << " busy? = " << is_busy()
           << " slot_allocated? = " << m_chunk_info->slot_allocated;
        return ss.str();
    }

private:
    chunk_info_block *m_chunk_info;
    PhysicalDev *m_pdev;
    std::shared_ptr<BlkAllocator> m_allocator;
};

class PhysicalDev {
    friend class PhysicalDevChunk;
    friend class DeviceManager;
public:
    static std::unique_ptr<PhysicalDev> load(DeviceManager *dev_mgr, std::string devname, int oflags, bool *is_new);

    PhysicalDev(DeviceManager *mgr, std::string devname, int oflags);
    ~PhysicalDev() = default;

    int get_devfd() const {
        return m_devfd;
    }

    std::string get_devname() const {
        return m_devname;
    }

    uint64_t get_size() const {
        return m_devsize;
    }

    boost::uuids::uuid get_uuid() const {
        return m_super_blk_header.this_dev_info.uuid;
    }

    void set_dev_offset(uint64_t offset) {
        m_super_blk_header.this_dev_info.dev_offset = offset;
    }

    uint64_t get_dev_offset() const {
        return m_super_blk_header.this_dev_info.dev_offset;
    }

    void set_dev_id(uint32_t id) {
        m_super_blk_header.this_dev_info.dev_num = id;
    }

    uint32_t get_dev_id() const {
        return m_super_blk_header.this_dev_info.dev_num;
    }

    super_block_header *get_super_block_header() {
        return &m_super_blk_header;
    }

    DeviceManager *device_manager() const {
        return m_mgr;
    }

    std::string to_string();
    /* Attach the given chunk to the list of chunks in the physical device. Parameter after provides the position
     * it needs to attach after. If null, attach to the end */
    void attach_chunk(PhysicalDevChunk *chunk, PhysicalDevChunk *after);

    /* Merge previous and next chunk from the chunk, if either one or both of them free. Returns the array of
     * chunk id which were merged and can be freed if needed */
    std::array<uint32_t, 2> merge_free_chunks(PhysicalDevChunk *chunk);

    /* Find a free chunk which closestly match for the required size */
    PhysicalDevChunk *find_free_chunk(uint64_t req_size);

    void write(const char *data, uint32_t size, uint64_t offset);
    void writev(const struct iovec *iov, int iovcnt, uint32_t size, uint64_t offset);

    void read(char *data, uint32_t size, uint64_t offset);
    void readv(const struct iovec *iov, int iovcnt, uint32_t size, uint64_t offset);

private:
    inline void write_superblock_header();
    inline void read_superblock_header();

    /* Load the physical device info from persistent storage. If its not a valid device, it will throw
     * std::system_exception. Returns true if the device has already formatted for Omstore, false otherwise. */
    bool load_super_block();

    /* Format the physical device info. Intended to use first time or anytime we need to reformat the drives. Throws
     * std::system_exception if there is any write errors */
    void format_super_block(uint32_t dev_id, uint64_t dev_offset);

    /* Validate if this device is a omstore validated device. If there is any corrupted device, then it
     * throws std::system_exception */
    bool validate_device();

private:
    DeviceManager     *m_mgr;              // Back pointer to physical device
    int                m_devfd;
    std::string        m_devname;
    super_block_header m_super_blk_header; // Persisent header block
    uint64_t           m_devsize;
};

class AbstractVirtualDev {
public:
    virtual void add_chunk(PhysicalDevChunk *chunk) = 0;
};

class DeviceManager {
    typedef std::function< AbstractVirtualDev *(vdev_info_block *) > NewVDevCallback;
    //typedef std::function< void(PhysicalDevChunk *) > NewChunkCallback;

    friend class PhysicalDev;
    friend class PhysicalDevChunk;

public:
    DeviceManager(NewVDevCallback vcb, uint32_t vdev_metadata_size);
    virtual ~DeviceManager() = default;

    /* Initial routine to call upon bootup or everytime new physical devices to be added dynamically */
    void add_devices(std::vector< std::string > &dev_names);

    /* This is not very efficient implementation of get_all_devices(), however, this is expected to be called during
     * the start of the devices and for that purpose its efficient enough */
    std::vector< PhysicalDev *> get_all_devices() {
        std::vector< PhysicalDev *> vec;
        std::lock_guard<decltype(m_chunk_mutex)> lock(m_chunk_mutex);

        vec.reserve(m_pdevs.size());
        for (auto &pdev : m_pdevs) {
            if (pdev) vec.push_back(pdev.get());
        }
        return vec;
    }

    /* Allocate a chunk for required size on the given physical dev and associate the chunk to provide virtual device.
     * Returns the allocated PhysicalDevChunk */
    PhysicalDevChunk *alloc_chunk(PhysicalDev *pdev, uint32_t vdev_id, uint64_t req_size);

    /* Free the chunk for later user */
    void free_chunk(PhysicalDevChunk *chunk);

    /* Allocate a new vdev for required size */
    vdev_info_block *alloc_vdev(uint64_t req_size, uint32_t nmirrors, uint32_t blk_size);

    /* Free up the vdev_id */
    void free_vdev(vdev_info_block *vb);

    /* Given an ID, get the chunk */
    PhysicalDevChunk *get_chunk(uint32_t chunk_id) const {
        return (chunk_id == INVALID_CHUNK_ID) ? nullptr : m_chunks[chunk_id].get();
    }

    PhysicalDevChunk *get_chunk_mutable(uint32_t chunk_id) {
        return (chunk_id == INVALID_CHUNK_ID) ? nullptr : m_chunks[chunk_id].get();
    }

    PhysicalDev *get_pdev(uint32_t pdev_id) const {
        return (pdev_id == INVALID_PDEV_ID) ? nullptr : m_pdevs[pdev_id].get();
    }

private:
    void read_info_blocks(PhysicalDev *pdev);
    void write_info_blocks(PhysicalDev *pdev);
    void load_vdev(PhysicalDev *pdev);

    chunk_info_block *alloc_new_chunk_slot(uint32_t *pslot_num);
    vdev_info_block *alloc_new_vdev_slot();

    PhysicalDevChunk *create_new_chunk(PhysicalDev *pdev, uint64_t start_offset, uint64_t size,
                                       PhysicalDevChunk *prev_chunk);
    void remove_chunk(uint32_t chunk_id);

    static constexpr uint32_t max_chunk_slots() {
        return ((sizeof(chunks_block) - offsetof(chunks_block, chunks))/sizeof(chunk_info_block));
    }

    uint32_t vdev_info_block_size() {
        return (sizeof(vdev_info_block) + m_vdev_info.context_data_size);
    }

    vdev_info_block *get_next_info_block(vdev_info_block *vb) {
        uint8_t *ptr = ((uint8_t *)vb) + vdev_info_block_size();
        uint8_t *maxptr = ((uint8_t *)&m_vdev_info) + VDEVS_BLOCK_MAX_SIZE;
        if (ptr >= maxptr) {
            return nullptr;
        }
        return (vdev_info_block *)(ptr);
    }

    vdev_info_block *get_prev_info_block(vdev_info_block *vb) {
        uint8_t *ptr = ((uint8_t *)vb) - vdev_info_block_size();
        uint8_t *minptr = (uint8_t *)&m_vdev_info;
        if (ptr < minptr) {
            return nullptr;
        }
        return (vdev_info_block *)(ptr);
    }

    vdev_info_block *get_vdev_info_block(uint32_t vdev_id) {
        return (vdev_info_block *)(((uint8_t *)&m_vdev_info.vdevs[0]) + (vdev_info_block_size() * vdev_id));
    }

#if 0
    const std::vector< std::unique_ptr< PhysicalDev > > &get_all_devices() const {
        return m_devices;
    }

    uint64_t get_devices_count() {
        return m_devices.size();
    }

    PhysicalDevChunk *create_new_chunk(PhysicalDev *pdev, uint64_t start_offset, uint64_t size,
                                              PhysicalDevChunk *prev_chunk) {
        uint32_t slot;
        phys_chunk_header *h = pdev->alloc_new_slot(&slot);

        auto chunk = new PhysicalDevChunk(pdev, start_offset, size, h);
        if (prev_chunk) {
            chunk->set_next_chunk_slot(prev_chunk->get_next_chunk_slot());
            prev_chunk->set_next_chunk_slot(slot);
            auto it = pdev->m_chunks.iterator_to(*prev_chunk);
            pdev->m_chunks.insert(++it, *chunk);
        }
        m_all_chunks[chunk->get_chunk_id()] = chunk;
        pdev->m_pers_hdr_block.num_chunks++;
        return chunk;
    }

    void remove_chunk(PhysicalDevChunk *chunk) {
        PhysicalDev *pdev = chunk->m_pdev;
        auto it = pdev->m_chunks.iterator_to(*chunk);
        if (it != pdev->m_chunks.begin()) {
            auto prev_chunk = &*(--it);
            prev_chunk->set_next_chunk_slot(chunk->get_next_chunk_slot());
            ++it;
        } else {
            assert(0); // We don't expect first chunk to be deleted.
        }

        pdev->m_pers_hdr_block.num_chunks--;
        chunk->free_slot();
        pdev->m_chunks.erase(it);
        m_all_chunks[chunk->get_chunk_id()] = nullptr;
        delete(chunk);
    }

    const PhysicalDevChunk *get_chunk(uint16_t chunk_id) const {
        return m_all_chunks[chunk_id];
    }

    PhysicalDevChunk *get_chunk_mutable(uint16_t chunk_id) {
        return m_all_chunks[chunk_id];
    }
#endif

private:
    int          m_open_flags;

    pdevs_block  m_pdev_info;
    chunks_block m_chunk_info;
    vdevs_block  m_vdev_info;

    std::mutex   m_chunk_mutex;
    std::mutex   m_vdev_mutex;

    omds::sparse_vector< std::unique_ptr< PhysicalDev > > m_pdevs;
    omds::sparse_vector< std::unique_ptr< PhysicalDevChunk > > m_chunks;
    omds::sparse_vector< AbstractVirtualDev * > m_vdevs;
    uint32_t m_last_vdevid;
    uint32_t m_vdev_metadata_size; // Appln metadata size for vdev

    NewVDevCallback  m_new_vdev_cb;
};

/*
template <typename Allocator, typename DefaultDeviceSelector>
class VirtualDev {
public:
    VirtualDev(uint64_t size, uint32_t nmirror, bool is_stripe, uint32_t dev_blk_size,
               std::vector< std::unique_ptr< PhysicalDev > > &phys_dev_list);

    virtual ~VirtualDev();

    // Getters and Setters
    void set_size(uint64_t size) {
        m_nblks = size;
    }

    uint64_t get_size() const {
        return m_nblks;
    }

#if 0
    BlkAllocStatus alloc(uint32_t size, vdev_hint *phint, BlkSeries *blkSeries);
    BlkAllocStatus alloc(uint32_t size, vdev_hint *pHint, pageid64_t *outBlkNum);
    void free(uint64_t blkNum, uint32_t size);
#endif

    BlkAllocStatus alloc(uint32_t size, vdev_hint *phint, Blk *out_blk);
    void free(Blk &b);
    BlkOpStatus write(SSDBlk &b);
    BlkOpStatus read(SSDBlk &b);

#if 0
    BlkOpStatus write(const char *data, uint64_t blkNum, uint32_t size);
    BlkOpStatus writev(const struct iovec *iov, int iovcnt, pageid64_t blkNum, uint32_t size);
    BlkOpStatus read(char *data, uint64_t blkNum, uint32_t size);
#endif

private:
    BlkAllocator *createAllocator(uint64_t size, bool isDynamicAlloc);

    inline PhysicalDevChunk *createDevChunk(uint32_t physInd, uint64_t chunkSize, BlkAllocator *ba);

    inline void pageNumToChunk(uint64_t blkNum, uint64_t *chunkNum, uint64_t *chunkOffset);

    uint32_t getPagesPerChunk() {
        return m_chunkSize / m_devPageSize;
    }
    //int createIOVPerPage(Blk &b, uint32_t bpiece, MemBlk *mbList, struct iovec *iov, int *piovcnt);
private:
    uint64_t m_nblks;
    uint32_t m_nmirrors;
    uint64_t m_chunk_size;
    std::atomic< uint64_t > m_total_allocations;
    uint32_t m_dev_blk_size;
    BlkAllocConfig m_baCfg;

    std::vector< std::unique_ptr< PhysicalDev > > m_phys_dev_list;
    std::vector< PhysicalDevChunk * > m_primaryChunks;
    std::vector< PhysicalDevChunk * > *m_mirrorChunks;
};
*/
} // namespace omstore
#endif /* BLKDEV_BLKDEV_H_ */
