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
#include <iomgr.hpp>

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

thread_local int ev_fd = 0;
thread_local io_context_t ioctx = 0;
thread_local struct io_event events[MAX_COMPLETIONS] = {0};

DriveEndPoint::DriveEndPoint(ioMgr *iomgr, comp_callback cb) 
				: EndPoint(iomgr), comp_cb(cb) {
}

int 
DriveEndPoint::open(std::string devname, int oflags) {
	/* it doesn't need to keep track of any fds */
	return(open(devname.c_str(), oflags));
}

void
DriveEndPoint::init_local() {
	ev_fd = eventfd(0, 0);
	iomgr->add_local_fd(ev_fd, std::bind(process_completions, this);
	io_setup(MAX_OUTSTANDING_IO, &ioctx);	
}

void 
DriveEndPoint::process_completions(int fd, int event) {
	assert(fd == ev_fd);
	/* TODO need to handle the error events */

	int ret = io_getevents(ioctx, 1, MAX_COMPLETIONS, 
			events, NULL);
	if (ret < 1) {
		assert(0);
	}
	for (int i = 0; i < ret; i++) {
		comp_cb(events[i].status, events[i].cookie);
	}
}

void 
DriveEndPoint::async_write(int m_sync_fd, const char *data, 
			uint32_t size, uint64_t offset, 
			uint8_t *cookie) {
	struct iocb iocb;
	iocb.data = cookie;
	io_prep_pwrite(&iocb, m_sync_fd, data, size, offset);
	io_set_event_fd(&iocb, ev_fd);
	if (io_submit(ioctx, 1, &iocb)) {
		ss << "error while writing " << errno;
		folly::throwSystemError(ss.str());
	}
}

void 
DriveEndPoint::async_read(int m_sync_fd, char *data, 
				uint32_t size, uint64_t offset, 
				uint8_t *cookie) {
	struct iocb iocb;
	iocb.data = cookie;
	io_prep_pread(&iocb, m_sync_fd, data, size, offset);
	io_set_event_fd(&iocb, ev_fd);
	if (io_submit(ioctx, 1, &iocb)) {
		ss << "error while read " << errno;
		folly::throwSystemError(ss.str());
	}
}

void 
DriveEndPoint::async_writev(int m_sync_fd, const struct iovec *iov, 
				int iovcnt, uint32_t size, 
				uint64_t offset, uint8_t *cookie) {
	struct iocb iocb;
	iocb.data = cookie;
	io_prep_pwritev(&iocb, fd, iov, iovcnt, offset);
	io_set_event_fd(&iocb, ev_fd);
	if (io_submit(ioctx, 1, &iocb)) {
		ss << "error while writing " << errno;
		folly::throwSystemError(ss.str());
	}
}

void 
DriveEndPoint::async_readv(int m_sync_fd, const struct iovec *iov, 
				int iovcnt, uint32_t size, 
				uint64_t offset, uint8_t *cookie) {
	struct iocb iocb;
	iocb.data = cookie;
	io_prep_preadv(&iocb, fd, iov, iovcnt, offset);
	io_set_event_fd(&iocb, ev_fd);
	if (io_submit(ioctx, 1, &iocb)) {
		ss << "error while reading " << errno;
		folly::throwSystemError(ss.str());
	}
}

void 
DriveEndPoint::sync_write(int m_sync_fd, const char *data, 
				uint32_t size, uint64_t offset) {
    ssize_t written_size = pwrite(m_sync_fd, data, (ssize_t) size, (off_t) offset);
    if (written_size != size) {
        std::stringstream ss;
        ss << "Error trying to write offset " << offset << " size to write = " 
	   << size << " size written = "
           << written_size << "\n";
        folly::throwSystemError(ss.str());
    }
}

void 
DriveEndPoint::sync_writev(int m_sync_fd, const struct iovec *iov, 
				int iovcnt, uint32_t size, uint64_t offset) {
    ssize_t written_size = pwritev(m_sync_fd, iov, iovcnt, offset);
    if (written_size != size) {
        std::stringstream ss;
        ss << "Error trying to write offset " << offset << " size to write = " 
	   << size << " size written = "
           << written_size << "\n";
        folly::throwSystemError(ss.str());
    }
}

void 
DriveEndPoint::sync_read(int m_sync_fd, char *data, 
				uint32_t size, uint64_t offset) {
    ssize_t read_size = pread(m_sync_fd, data, (ssize_t) size, (off_t) offset);
    if (read_size != size) {
        std::stringstream ss;
        ss << "Error trying to read offset " << offset << " size to read = " 
	   << size << " size read = "
           << read_size << "\n";
        folly::throwSystemError(ss.str());
    }
}

void 
DriveEndPoint::sync_readv(int m_sync_fd, const struct iovec *iov, 
				int iovcnt, uint32_t size, uint64_t offset) {
    ssize_t read_size = preadv(m_sync_fd, iov, iovcnt, (off_t) offset);
    if (read_size != size) {
	    std::stringstream ss;
	    ss << "Error trying to read offset " << offset << " size to read = " 
	       << size << " size read = "
	       << read_size << "\n";
	    folly::throwSystemError(ss.str());
    }
}

}// namespace homeio
