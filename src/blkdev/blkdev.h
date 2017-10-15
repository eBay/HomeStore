/*
 * blkdev.h
 *
 *  Created on: 05-Aug-2016
 *      Author: Hari Kadayam
 */

#ifndef BLKDEV_BLKDEV_H_
#define BLKDEV_BLKDEV_H_

#include <vector>
#include "blkallocator.h"
#include <sys/uio.h>
#include <unistd.h>

//namespace omstorage { name blkdev {
class PhysicalDev;
class VirtualDev;

#define MAX_OBJS_IN_BLK 64

class PhysicalDevChunk
{
public:
    PhysicalDevChunk(PhysicalDev *pdev, uint64_t startOffset, uint64_t size) {
        set_physical_dev(pdev);
        set_virtual_dev(NULL);
        set_start_offset(startOffset);
        set_size(size);
        set_busy(false);
        set_blk_allocator(null);
    }

    PhysicalDevChunk(void) : PhysicalDevChunk(NULL, 0, 0) {
    }

    void set_physical_dev(PhysicalDev *pdev) {
        m_pdev = pdev;
    }

    PhysicalDev *getPhysicalDev() {
        return m_pdev;
    }

    void set_virtual_dev(VirtualDev *vdev) {
        m_vdev = vdev;
    }

    VirtualDev *get_virtual_dev() {
        return m_vdev;
    }

	void set_start_offset(uint64_t offset) {
		m_start_offset = offset;
	}

	uint64_t get_start_offset()	{
		return m_start_offset;
	}

    void set_size(uint64_t size) {
        m_size = size;
    }

    uint64_t get_size() const {
        return m_size;
    }

    void set_busy(bool busy) {
        m_busy = busy;
    }

    bool isBusy() {
        return m_busy;
    }

    void set_blk_allocator(BlkAllocator *ba) {
        m_blk_allocator = ba;
    }

    BlkAllocator *get_blk_allocator() {
        return m_blk_allocator;
    }

private:
	PhysicalDev *m_pdev;
	VirtualDev *m_vdev;
	uint64_t m_start_offset;
	uint64_t m_size;
	bool m_busy;
	BlkAllocator *m_blk_allocator;
};

class PhysicalDev
{
public:
	PhysicalDev(string devname, int oflags);
	virtual ~PhysicalDev();

	PhysicalDevChunk *alloc_chunk(uint64_t size);
	void free_chunk(PhysicalDevChunk *pchunk);

    int get_devfd() const {
        return m_devfd;
    }

    void set_devfd(int devfd) {
        m_devfd = devfd;
    }

    string get_devname() const {
        return m_devname;
    }

    void setDevName(string devname) {
        m_devname = devname;
    }

	BlkOpStatus write(const char *data, uint32_t size, uint64_t offset);
	BlkOpStatus writev(const struct iovec *iov, int iovcnt, uint32_t size, uint64_t offset);

	BlkOpStatus read(char *data, uint32_t size, uint64_t offset);
	BlkOpStatus readv(const struct iovec *iov, int iovcnt, uint32_t size, uint64_t offset);

private:
	std::string m_devname;
	int m_devfd;
	//uint64_t m_uniqueId; // Unique ID to the device.

	std::vector<PhysicalDevChunk *> m_chunks;

	int find_free_chunk(uint64_t req_size);
	int chunk_to_ind(PhysicalDevChunk *chunk);
};

class BlkDevManager
{
public:
	BlkDevManager();
	virtual ~BlkDevManager();
	void add_device(string devName);
	vector<PhysicalDev *> get_all_devices();
	uint32_t get_devices_count();

	static void start_instance();
	static BlkDevManager *get_instance();

private:
	int m_open_flags;
	vector<PhysicalDev *> m_devices;
};

struct vdev_hint
{
	uint32_t phys_devid;
	bool can_look_for_other_dev;
	uint32_t temperature;
};

class VirtualDev
{

public:
	VirtualDev(uint64_t size, uint32_t nmirror, bool dynamic_alloc, bool is_stripe, uint32_t dev_blk_size,
	           vector<PhysicalDev *>& phys_dev_list);
	virtual ~VirtualDev();

	// Getters and Setters
	void set_size(uint64_t size)
	{
		m_size = size;
	}

	uint64_t get_size()
	{
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

	uint32_t getPagesPerChunk()
	{
		return m_chunkSize/m_devPageSize;
	}
	//int createIOVPerPage(Blk &b, uint32_t bpiece, MemBlk *mbList, struct iovec *iov, int *piovcnt);
private:
	uint64_t m_size;
	uint32_t m_nMirrors;
	uint64_t m_chunkSize;
	atomic<uint64_t> m_totalAllocations;
	uint32_t m_devPageSize;
	BlkAllocConfig m_baCfg;

	vector<PhysicalDev *> m_physDevList;
	vector<PhysicalDevChunk *> m_primaryChunks;
	vector<PhysicalDevChunk *> *m_mirrorChunks;
};

#endif /* BLKDEV_BLKDEV_H_ */
