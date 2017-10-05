/*
 * PhysicalDev.cpp
 *
 *  Created on: 05-Aug-2016
 *      Author: hkadayam
 */

#include "BlkDev.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>
#include <iostream>

#ifdef __APPLE__
ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
	lseek(fd, offset, SEEK_SET);
	return ::readv(fd, iov, iovcnt);
}

ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
	lseek(fd, offset, SEEK_SET);
	return ::writev(fd, iov, iovcnt);
}
#endif

PhysicalDev::PhysicalDev(string devName, int oflags)
{
	uint64_t size;
	struct stat statBuf;

	stat(devName.c_str(), &statBuf);
	size = (uint64_t) statBuf.st_size;

	// Create a physical device chunk with full device
	setDevName(devName);
	setDevfd(open(devName.c_str(), oflags)); // TODO: Capture errors and throw exception

	// TODO: Get the unique ID of the device (UUID) and stash in here.
	// When persisting write that to the super block.
	PhysicalDevChunk *pchunk = new PhysicalDevChunk(this, 0, size);
	m_chunks.push_back(pchunk);
}

PhysicalDev::~PhysicalDev()
{
	// TODO: Do Persistence of the chunk info
	for (auto it = m_chunks.begin(); it < m_chunks.end(); it++) {
		delete (*it);
	}
}

PhysicalDevChunk *PhysicalDev::allocChunk(uint64_t reqSize)
{
	int ind = findFreeChunk(reqSize);
	if (ind == -1) {
		cout << "ERROR: No more free chunks on physical dev " << getDevName() << endl;
		return NULL;
	}

	PhysicalDevChunk *chunk = m_chunks[ind];
	assert(chunk->getSize() >= reqSize);
	chunk->setBusy(true);

	if (chunk->getSize() > reqSize) {
		// Create a new chunk to put remaining size;
		PhysicalDevChunk *newChunk = new PhysicalDevChunk(this, chunk->getStartOffset() + reqSize,
		                                                  chunk->getSize() - reqSize);
		chunk->setSize(reqSize);
		m_chunks.insert(m_chunks.begin() + ind + 1, newChunk);
	}

	return chunk;
}

void PhysicalDev::freeChunk(PhysicalDevChunk *chunk)
{
	int ind = chunkToInd(chunk);

	// Check if previous and next chunk are free, if so make it
	// contiguous chunk
	if (ind > 0) {
		PhysicalDevChunk *prevChunk = m_chunks[ind - 1];
		if (!prevChunk->isBusy()) {
			prevChunk->setSize(prevChunk->getSize() + chunk->getSize());
			m_chunks.erase(m_chunks.begin() + ind);
			free(chunk);

			chunk = prevChunk;
			ind--;
		}
	}

	if (ind < (m_chunks.size() - 1)) {
		PhysicalDevChunk *nextChunk = m_chunks[ind + 1];
		if (!nextChunk->isBusy()) {
			nextChunk->setSize(nextChunk->getSize() + chunk->getSize());
			m_chunks.erase(m_chunks.begin() + ind);
			free(chunk);
		}
	}
}

BlkOpStatus PhysicalDev::write(const char *data, uint32_t size, uint64_t offset)
{
	ssize_t writtenSize = pwrite(getDevfd(), data, (ssize_t) size, (off_t) offset);
	if (writtenSize != size) {
		perror("PhysicalDev::write error");
		cout << "Error trying to write offset " << offset << " size = " << size << endl;
		return BLK_OP_FAILED;
	}

	return BLK_OP_SUCCESS;
}

BlkOpStatus PhysicalDev::writev(const struct iovec *iov, int iovcnt, uint32_t size, uint64_t offset)
{
	ssize_t writtenSize = pwritev(getDevfd(), iov, iovcnt, offset);
	if (writtenSize != size) {
		perror("PhysicalDev:writev error");
		cout << "Error trying to write offset " << offset << " size to write = " << size << " size written = "
		     << writtenSize << endl;
		return BLK_OP_FAILED;
	}

	return BLK_OP_SUCCESS;
}

BlkOpStatus PhysicalDev::read(char *data, uint32_t size, uint64_t offset)
{
	ssize_t readSize = pread(getDevfd(), data, (ssize_t) size, (off_t) offset);
	if (readSize != size) {
		perror("PhysicalDev::read error");
		cout << "Error trying to read offset " << offset << " size = " << size << endl;
		return BLK_OP_FAILED;
	}

	return BLK_OP_SUCCESS;
}

BlkOpStatus PhysicalDev::readv(const struct iovec *iov, int iovcnt, uint32_t size, uint64_t offset)
{
	ssize_t readSize = preadv(getDevfd(), iov, iovcnt, (off_t) offset);
	if (readSize != size) {
		perror("PhysicalDev::read error");
		cout << "Error trying to read offset " << offset << " size to read = " << size << " size read = " << readSize
		     << endl;
		return BLK_OP_FAILED;
	}

	return BLK_OP_SUCCESS;
}

int PhysicalDev::chunkToInd(PhysicalDevChunk *chunk)
{
	int ind = 0;
	for (auto it = m_chunks.begin(); it < m_chunks.end(); it++, ind++) {
		if (*it == chunk) {
			return ind;
		}
	}

	return -1;
}

int PhysicalDev::findFreeChunk(uint64_t reqSize)
{
	// Get the slot with closest size;
	PhysicalDevChunk *closestChunk = NULL;
	int closestInd = -1;
	int i = 0;

	for (auto it = m_chunks.begin(); it < m_chunks.end(); it++, i++) {
		PhysicalDevChunk *chunk = *it;
		if (!chunk->isBusy() && (chunk->getSize() >= reqSize)) {
			if ( (closestChunk == NULL) || (chunk->getSize() < closestChunk->getSize())) {
				closestChunk = chunk;
				closestInd = i;
			}
		}
	}

	return closestInd;
}
