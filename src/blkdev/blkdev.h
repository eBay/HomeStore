/*
 * blkdev.h
 *
 *  Created on: 05-Aug-2016
 *      Author: Hari Kadayam
 */

#ifndef BLKDEV_BLKDEV_H_
#define BLKDEV_BLKDEV_H_

#include <boost/intrusive/list.hpp>
#include "blkalloc/blk_allocator.h"
#include <sys/uio.h>
#include <unistd.h>
#include <string>
#include <boost/uuid/uuid.hpp>            // uuid class
#include <boost/uuid/uuid_generators.hpp> // generators
#include <boost/uuid/uuid_io.hpp>         // streaming operators etc.

namespace omstore {
class PhysicalDev;
class VirtualDev;

#define INVALID_CHUNK_ID    ((uint32_t)-1)

class DeviceException : public std::exception
{
public:
    inline static std::string const& to_string(std::string const& s) { return s; }

    template<typename ... Args>
    DeviceException(Args const&... args) {
        using ::to_string;
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

struct phys_chunk_header {
    uint64_t     chunk_start_offset;
    uint64_t     chunk_size;
    uint32_t     next_chunk_slot;
    bool         chunk_busy;
    bool         slot_allocated;
} __attribute((packed));

class PhysicalDevChunk : public boost::intrusive::list_base_hook<> {
public:
    static PhysicalDevChunk *create_new_chunk(PhysicalDev *pdev, uint64_t start_offset, uint64_t size,
                                         PhysicalDevChunk *prev_chunk);
    static void remove_chunk(PhysicalDevChunk *chunk);

    PhysicalDevChunk(PhysicalDev *pdev, uint64_t start_offset, uint64_t size, phys_chunk_header *hdr) :
            m_pdev(pdev),
            m_vdev(nullptr),
            m_header(hdr),
            m_blk_allocator(nullptr) {
        hdr->chunk_start_offset = start_offset;
        hdr->chunk_size = size;
        hdr->chunk_busy = true;
        hdr->next_chunk_slot = INVALID_CHUNK_ID;
    }

    PhysicalDev *get_physical_dev() {
        return m_pdev;
    }

    const PhysicalDev *get_physical_dev_const() const {
        return m_pdev;
    };

    void set_virtual_dev(VirtualDev *vdev) {
        m_vdev = vdev;
    }

    VirtualDev *get_virtual_dev() {
        return m_vdev;
    }

    const VirtualDev *get_virtual_dev_const() const {
        return m_vdev;
    }

    void set_start_offset(uint64_t offset) {
        m_header->chunk_start_offset = offset;
    }

    uint64_t get_start_offset() const {
        return m_header->chunk_start_offset;
    }

    void set_size(uint64_t size) {
        m_header->chunk_size = size;
    }

    uint64_t get_size() const {
        return m_header->chunk_size;
    }

    void set_busy(bool busy) {
        m_header->chunk_busy = busy;
    }

    bool is_busy() const {
        return m_header->chunk_busy;
    }

    void set_next_chunk_slot(uint32_t next_chunk_slot) {
        m_header->next_chunk_slot = next_chunk_slot;
    }

    uint32_t get_next_chunk_slot() const {
        return m_header->next_chunk_slot;
    }

    void free_slot() {
        m_header->slot_allocated = false;
    }

    void set_blk_allocator(BlkAllocator *ba) {
        m_blk_allocator = ba;
    }

    BlkAllocator *get_blk_allocator() {
        return m_blk_allocator;
    }

private:
    PhysicalDev *m_pdev;
    VirtualDev  *m_vdev;
    phys_chunk_header *m_header;
    BlkAllocator *m_blk_allocator;
};

#define PHYS_DEV_PERSISTENT_HEADER_SIZE  2048
#define MAGIC                            0xCEEDDEEB
#define PRODUCT_NAME                     "OmStore"

// Header block format store in each physical device about the current size info
struct phys_dev_header_block {
    uint64_t           magic;                // Header magic expected to be at the top of block
    char               product_name[64];     // Product name
    uint32_t           version;              // Version Id of this structure
    boost::uuids::uuid uuid;                 // UUID for the physical device
    uint32_t           num_chunks;           // Number of physical chunks including this header
    uint32_t           super_block_chunk_id; // Chunk number of the super block of product
    phys_chunk_header  chunks[0];            // Array of chunks
} __attribute__((aligned(PHYS_DEV_PERSISTENT_HEADER_SIZE)));

static_assert(sizeof(phys_dev_header_block) == PHYS_DEV_PERSISTENT_HEADER_SIZE);

class PhysicalDev {
    friend class PhysicalDevChunk;

public:
    PhysicalDev(std::string devname, int oflags);
    virtual ~PhysicalDev();

    PhysicalDevChunk *alloc_chunk(uint64_t req_size);
    void free_chunk(PhysicalDevChunk *chunk);

    int get_devfd() const {
        return m_devfd;
    }

    void set_devfd(int devfd) {
        m_devfd = devfd;
    }

    std::string get_devname() const {
        return m_devname;
    }

    boost::uuids::uuid get_uuid() const {
        return m_pers_hdr_block.uuid;
    }

    void write(const char *data, uint32_t size, uint64_t offset);
    void writev(const struct iovec *iov, int iovcnt, uint32_t size, uint64_t offset);

    void read(char *data, uint32_t size, uint64_t offset);
    void readv(const struct iovec *iov, int iovcnt, uint32_t size, uint64_t offset);

private:
    inline void write_header_block();
    inline void read_header_block();

    /* Load the physical device info from persistent storage. If its not a valid device, it will throw
     * std::system_exception. Returns true if the device has already formatted for Omstore, false otherwise. */
    bool load(bool from_persistent_area = true);

    /* Format the physical device info. Intended to use first time or anytime we need to reformat the drives. Throws
     * std::system_exception if there is any write errors */
    void format();

    /* Validate if this device is a omstore validated device. If there is any corrupted device, then it
     * throws std::system_exception */
    bool validate_device();

    PhysicalDevChunk *find_free_chunk(uint64_t req_size);
    phys_chunk_header *alloc_new_slot(uint32_t *pslot_num);

    static constexpr uint32_t max_slots() {
        return ((PHYS_DEV_PERSISTENT_HEADER_SIZE - sizeof(phys_dev_header_block))/sizeof(phys_chunk_header));
    }

private:
    std::string m_devname;
    int m_devfd;
    uint64_t m_devsize;
    std::mutex m_chunk_mutex;
    phys_dev_header_block m_pers_hdr_block; // Persisent header block
    boost::intrusive::list< PhysicalDevChunk > m_chunks;
};

class BlkDevManager {
public:
    BlkDevManager();

    virtual ~BlkDevManager();

    void add_device(string devName);

    vector< PhysicalDev * > get_all_devices();

    uint32_t get_devices_count();

    static void start_instance();

    static BlkDevManager *get_instance();

private:
    int m_open_flags;
    vector< PhysicalDev * > m_devices;
};

struct vdev_hint {
    uint32_t phys_devid;
    bool can_look_for_other_dev;
    uint32_t temperature;
};

class VirtualDev {
public:
    VirtualDev(uint64_t size, uint32_t nmirror, bool dynamic_alloc, bool is_stripe, uint32_t dev_blk_size,
               std::vector< PhysicalDev * > &phys_dev_list);

    virtual ~VirtualDev();

    // Getters and Setters
    void set_size(uint64_t size) {
        m_size = size;
    }

    uint64_t get_size() {
        return m_size;
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
    uint64_t m_size;
    uint32_t m_nMirrors;
    uint64_t m_chunkSize;
    std::atomic< uint64_t > m_total_allocations;
    uint32_t m_devPageSize;
    BlkAllocConfig m_baCfg;

    std::vector< PhysicalDev * > m_physDevList;
    std::vector< PhysicalDevChunk * > m_primaryChunks;
    std::vector< PhysicalDevChunk * > *m_mirrorChunks;
};

} // namespace omstore
#endif /* BLKDEV_BLKDEV_H_ */
