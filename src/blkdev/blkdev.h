/*
 * BlkDev.h
 *
 *  Created on: 05-Aug-2016
 *      Author: Hari Kadayam
 */

#ifndef BLKDEV_BLKDEV_H_
#define BLKDEV_BLKDEV_H_

#include <vector>
#include "BlkAllocator.h"
#include <sys/uio.h>
#include <unistd.h>

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
		m_startOffset = offset;
	}

	uint64_t get_start_offset()	{
		return m_startOffset;
	}

    void set_size(uint64_t size) {
        m_size = size;
    }

    uint64_t get_size() const {
        return m_size;
    }

    void setBusy(bool busy) {
        m_busy = busy;
    }

    bool isBusy() {
        return m_busy;
    }

    void setBlkAllocator(BlkAllocator *ba) {
        m_blkAllocator = ba;
    }

    BlkAllocator *getBlkAllocator() {
        return m_blkAllocator;
    }

private:
	PhysicalDev *m_pdev;
	VirtualDev *m_vdev;
	uint64_t m_startOffset;
	uint64_t m_size;
	bool m_busy;
	BlkAllocator *m_blkAllocator;
};

class PhysicalDev
{
public:
	PhysicalDev(string devName, int oflags);
	virtual ~PhysicalDev();

	PhysicalDevChunk *allocChunk(uint64_t size);
	void freeChunk(PhysicalDevChunk *pchunk);

	int getDevfd() const
	{
		return m_devfd;
	}
	void setDevfd(int devfd)
	{
		m_devfd = devfd;
	}

	string getDevName() const
	{
		return m_devName;
	}
	void setDevName(string devName)
	{
		m_devName = devName;
	}

	BlkOpStatus write(const char *data, uint32_t size, uint64_t offset);
	BlkOpStatus writev(const struct iovec *iov, int iovcnt, uint32_t size, uint64_t offset);

	BlkOpStatus read(char *data, uint32_t size, uint64_t offset);
	BlkOpStatus readv(const struct iovec *iov, int iovcnt, uint32_t size, uint64_t offset);

private:
	string m_devName;
	int m_devfd;
	//uint64_t m_uniqueId; // Unique ID to the device.

	vector<PhysicalDevChunk *> m_chunks;

	int findFreeChunk(uint64_t reqSize);
	int chunkToInd(PhysicalDevChunk *chunk);
};

class BlkDevManager
{
public:
	BlkDevManager();
	virtual ~BlkDevManager();
	void addDevice(string devName);
	vector<PhysicalDev *> getAllDevices();
	uint32_t getDevicesCount();

	static void startInstance();
	static BlkDevManager *getInstance();

private:
	int m_openFlags;
	vector<PhysicalDev *> m_devices;
};

struct vdev_hint
{
	uint32_t physDevId;
	bool canLookForOtherDev;
	uint32_t temperature;
};

class VirtualDev
{

public:
	VirtualDev(uint64_t size, uint32_t nMirror, bool dynamicAlloc, bool isStripe, uint32_t devBlkSize,
	           vector<PhysicalDev *>& phyDevList);
	virtual ~VirtualDev();

	// Getters and Setters
	void setSize(uint64_t size)
	{
		m_size = size;
	}

	uint64_t getSize()
	{
		return m_size;
	}

#if 0
	BlkAllocStatus alloc(uint32_t size, vdev_hint *pHint, BlkSeries *blkSeries);
	BlkAllocStatus alloc(uint32_t size, vdev_hint *pHint, pageid64_t *outBlkNum);
	void free(uint64_t blkNum, uint32_t size);
#endif

	BlkAllocStatus alloc(uint32_t size, vdev_hint *pHint, Blk *outBlk);
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
