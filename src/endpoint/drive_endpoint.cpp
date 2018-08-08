//
// Created by Kadayam, Hari on 02/04/18.
//
#include <folly/Exception.h>
#include <string>
#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>
#include <sys/uio.h>
#include <folly/Exception.h>
#include <endpoint/drive_endpoint.hpp>
#include <fstream>
#include <sys/epoll.h>
#include <sds_logging/logging.h>

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
using namespace std;
thread_local struct io_event DriveEndPoint::events[MAX_COMPLETIONS] = {{}};
thread_local int DriveEndPoint::ev_fd = 0;
thread_local io_context_t DriveEndPoint::ioctx = 0;
thread_local stack <struct iocb_info *> DriveEndPoint::iocb_list;
uint64_t get_elapsed_time_ns(homeio::Clock::time_point startTime);

uint64_t 
get_elapsed_time_ns(homeio::Clock::time_point startTime) {
	std::chrono::nanoseconds ns = std::chrono::duration_cast
		< std::chrono::nanoseconds >(Clock::now() - startTime);
	return ns.count();
}


DriveEndPoint::DriveEndPoint(std::shared_ptr<iomgr::ioMgr> iomgr, comp_callback cb)
				: EndPoint(iomgr), write_aio_lat(0), total_write_ios(0), spurious_events(0), comp_cb(cb) {
	iomgr->add_ep(this);
}

int 
DriveEndPoint::open_dev(std::string devname, int oflags) {
	/* it doesn't need to keep track of any fds */
	return(open(devname.c_str(), oflags));
}

void
DriveEndPoint::init_local() {
	ev_fd = eventfd(0, EFD_NONBLOCK);
	iomgr->add_local_fd(ev_fd, std::bind(
			    &DriveEndPoint::process_completions, this, 
			    std::placeholders::_1, std::placeholders::_2, std::placeholders::_3), 
			    EPOLLIN, 0, NULL);
	io_setup(MAX_OUTSTANDING_IO, &ioctx);	
	for (int i = 0; i < MAX_OUTSTANDING_IO; i++) {
		struct iocb_info *info = (struct iocb_info *)malloc(sizeof(struct iocb_info));
		iocb_list.push(info);
	}
}

void 
DriveEndPoint::process_completions(int fd, void *cookie, int event) {
	assert(fd == ev_fd);
	/* TODO need to handle the error events */
	uint64_t temp = 0;
	
	/* we should read the event first so that we don't miss 
	 * any completions. We might get spurious events but i
	 * think thats fine.
	 */
	iomgr->process_done(fd, event);
        [[maybe_unused]] auto rsize = read(ev_fd, &temp, sizeof(uint64_t));
	int ret = io_getevents(ioctx, 0, MAX_COMPLETIONS, events, NULL);
	if (ret == 0) {
		spurious_events++;
	}
	if (ret < 0) {
        /* TODO how to handle it */
		cmp_err++;
	}
	for (int i = 0; i < ret; i++) {
        assert(static_cast<int64_t>(events[i].res) >= 0);
		struct iocb_info *info = static_cast<iocb_info *>(events[i].obj);
		struct iocb *iocb = static_cast<struct iocb *>(info);
		if (info->is_read) {
			read_aio_lat.fetch_add(
				get_elapsed_time_ns(info->start_time), 
				memory_order_relaxed);
		} else {
			write_aio_lat.fetch_add(
				get_elapsed_time_ns(info->start_time),
				memory_order_relaxed);
		}
		iocb_list.push(info);
		comp_cb(events[i].res, (uint8_t *) events[i].data);
	}
}

void
DriveEndPoint::print_perf() {
	printf("latency for write in aio %lu us\n", write_aio_lat.load()/(total_write_ios.load() * 1000));
	if (total_read_ios.load() != 0) {
		printf("latency for read in aio %lu us\n", read_aio_lat.load()/(total_read_ios.load() * 1000));
	}
	printf("spurious events %lu \n", spurious_events.load());
	printf("completion errors %lu \n", cmp_err.load());
}

void 
DriveEndPoint::async_write(int m_sync_fd, const char *data, 
			uint32_t size, uint64_t offset, 
			uint8_t *cookie) {
    
    assert(!iocb_list.empty());
	struct iocb_info *info = iocb_list.top();
	struct iocb *iocb = static_cast<struct iocb *>(info);
	iocb_list.pop();
	io_prep_pwrite(iocb, m_sync_fd, (void *)data, size, offset);
	io_set_eventfd(iocb, ev_fd);
	iocb->data = cookie;
	info->start_time = Clock::now();
	info->is_read = false;
	if (io_submit(ioctx, 1, &iocb) != 1) {
		std::stringstream ss;
		ss << "error while writing " << errno;
		folly::throwSystemError(ss.str());
	}
	total_write_ios++;
}

void 
DriveEndPoint::async_read(int m_sync_fd, char *data, 
				uint32_t size, uint64_t offset, 
				uint8_t *cookie) {
    
    assert(!iocb_list.empty());
	struct iocb_info *info = iocb_list.top();
	struct iocb *iocb = static_cast<struct iocb *>(info);
	iocb_list.pop();
	io_prep_pread(iocb, m_sync_fd, data, size, offset);
	io_set_eventfd(iocb, ev_fd);
	iocb->data = cookie;
	info->is_read = true;
	info->start_time = Clock::now();
  LOGTRACE("Reading: {}", size);
	if (io_submit(ioctx, 1, &iocb) != 1) {
		std::stringstream ss;
		ss << "error while read " << errno;
		folly::throwSystemError(ss.str());
		
	}
	total_read_ios++;
}

void 
DriveEndPoint::async_writev(int m_sync_fd, const struct iovec *iov, 
				int iovcnt, uint32_t size, 
				uint64_t offset, uint8_t *cookie) {
    
    assert(!iocb_list.empty());
	struct iocb_info *info = iocb_list.top();
	struct iocb *iocb = static_cast<struct iocb *>(info);
	iocb_list.pop();
	io_prep_pwritev(iocb, m_sync_fd, iov, iovcnt, offset);
	io_set_eventfd(iocb, ev_fd);
	iocb->data = cookie;
	info->start_time = Clock::now();
	info->is_read = false;
	if (io_submit(ioctx, 1, &iocb) != 1) {
		std::stringstream ss;
		ss << "error while writing " << errno;
		folly::throwSystemError(ss.str());
	}
	total_write_ios++;
}

void 
DriveEndPoint::async_readv(int m_sync_fd, const struct iovec *iov, 
				int iovcnt, uint32_t size, 
				uint64_t offset, uint8_t *cookie) {
    
    assert(!iocb_list.empty());
	struct iocb_info *info = iocb_list.top();
	struct iocb *iocb = static_cast<struct iocb *>(info);
	iocb_list.pop();
	io_prep_preadv(iocb, m_sync_fd, iov, iovcnt, offset);
	io_set_eventfd(iocb, ev_fd);
	iocb->data = cookie;
	info->is_read = true;
	info->start_time = Clock::now();
  LOGTRACE("Reading: {} vectors", iovcnt);
	if (io_submit(ioctx, 1, &iocb) != 1) {
		std::stringstream ss;
		ss << "error while reading " << errno;
		folly::throwSystemError(ss.str());
	}
	total_read_ios++;
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
        int i = errno;
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
