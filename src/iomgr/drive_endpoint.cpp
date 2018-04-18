//
// Created by Kadayam, Hari on 02/04/18.
//
#include "endpoint.hpp"
#include <folly/Exception.h>
#include <string>
#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>
#include <sys/uio.h>

namespace homeio {
#ifdef __APPLE__

ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset) {
    lseek(fd, offset, SEEK_SET);
    return ::readv(fd, iov, iovcnt);
}

ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset) {
    lseek(fd, offset, SEEK_SET);
    return ::writev(fd, iov, iovcnt);
}

#endif

DriveEndPoint::DriveEndPoint(std::string devname, int oflags) :
        EndPoint() {
    // Open 2 fds, one async and other sync
    folly::checkUnixError(m_fd = open(devname.c_str(), oflags));
    folly::checkUnixError(m_sync_fd = open(devname.c_str(), oflags));

    // Set the async fd as non blocking
    EndPoint::set_blocking(m_fd, false);
}

void DriveEndPoint::sync_write(const char *data, uint32_t size, uint64_t offset) {
    ssize_t written_size = pwrite(m_sync_fd, data, (ssize_t) size, (off_t) offset);
    if (written_size != size) {
        std::stringstream ss;
        ss << "Error trying to write offset " << offset << " size to write = " << size << " size written = "
           << written_size << "\n";
        folly::throwSystemError(ss.str());
    }
}

void DriveEndPoint::sync_writev(const struct iovec *iov, int iovcnt, uint32_t size, uint64_t offset) {
    ssize_t written_size = pwritev(m_sync_fd, iov, iovcnt, offset);
    if (written_size != size) {
        std::stringstream ss;
        ss << "Error trying to write offset " << offset << " size to write = " << size << " size written = "
           << written_size << "\n";
        folly::throwSystemError(ss.str());
    }
}

void DriveEndPoint::sync_read(char *data, uint32_t size, uint64_t offset) {
    ssize_t read_size = pread(m_sync_fd, data, (ssize_t) size, (off_t) offset);
    if (read_size != size) {
        std::stringstream ss;
        ss << "Error trying to read offset " << offset << " size to read = " << size << " size read = "
           << read_size << "\n";
        folly::throwSystemError(ss.str());
    }
}

void DriveEndPoint::sync_readv(const struct iovec *iov, int iovcnt, uint32_t size, uint64_t offset) {
    ssize_t read_size = preadv(m_sync_fd, iov, iovcnt, (off_t) offset);
    if (read_size != size) {
        std::stringstream ss;
        ss << "Error trying to read offset " << offset << " size to read = " << size << " size read = "
           << read_size << "\n";
        folly::throwSystemError(ss.str());
    }
}

}// namespace homeio