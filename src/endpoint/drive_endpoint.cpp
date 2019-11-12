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
#include <metrics/metrics.hpp>
#include "homeds/utility/useful_defs.hpp"
#include "main/homestore_config.hpp"
#include "error/error.h"

namespace homeio {
#ifdef __APPLE__

ssize_t preadv(int fd, const struct iovec* iov, int iovcnt, off_t offset) {
    lseek(fd, offset, SEEK_SET);
    return ::readv(fd, iov, iovcnt);
}

ssize_t pwritev(int fd, const struct iovec* iov, int iovcnt, off_t offset) {
    lseek(fd, offset, SEEK_SET);
    return ::writev(fd, iov, iovcnt);
}

#endif
using namespace std;

thread_local struct io_event            DriveEndPoint::events[MAX_COMPLETIONS] = {{}};
thread_local int                        DriveEndPoint::ev_fd = 0;
thread_local io_context_t               DriveEndPoint::ioctx = 0;
thread_local stack< struct iocb_info* > DriveEndPoint::iocb_list;
thread_local DriveEndPointMetrics       DriveEndPoint::m_metrics = DriveEndPointMetrics();
int                                     DriveEndPointMetrics::thread_num = 0;

DriveEndPoint::DriveEndPoint(std::shared_ptr< iomgr::ioMgr > iomgr, comp_callback cb) :
        EndPoint(iomgr),
        spurious_events(0),
        comp_cb(cb) {
    iomgr->add_ep(this);
}

DriveEndPoint::~DriveEndPoint() {}

int DriveEndPoint::open_dev(std::string devname, int oflags) {
    /* it doesn't need to keep track of any fds */
    return (open(devname.c_str(), oflags));
}

void DriveEndPoint::shutdown_local() {
    // TODO: io_close
    while(!iocb_list.empty()) {
        auto t = iocb_list.top();
        free(t);
        iocb_list.pop();
    }
}

void DriveEndPoint::init_local() {
    ev_fd = eventfd(0, EFD_NONBLOCK);
    iomgr->add_local_fd(ev_fd,
                        std::bind(&DriveEndPoint::process_completions, this, std::placeholders::_1,
                                  std::placeholders::_2, std::placeholders::_3),
                        EPOLLIN, 0, NULL);
    int err = io_setup(MAX_OUTSTANDING_IO, &ioctx);
    if (err) {
        LOGCRITICAL("io_setup failed with ret status {} errno {}", err, errno);
        std::stringstream ss;
        ss << "io_setup failed with ret status " << err << " errno = " << errno;
        folly::throwSystemError(ss.str());
    }
    
    assert(ioctx);
    for (int i = 0; i < MAX_OUTSTANDING_IO; i++) {
        struct iocb_info* info = (struct iocb_info*)malloc(sizeof(struct iocb_info));
        iocb_list.push(info);
    }
}

void DriveEndPoint::process_completions(int fd, void* cookie, int event) {
    assert(fd == ev_fd);

    /* TODO need to handle the error events */
    uint64_t temp = 0;

    /* we should read the event first so that we don't miss
     * any completions. We might get spurious events but i
     * think thats fine.
     */
    iomgr->process_done(fd, event);
    [[maybe_unused]] auto rsize = read(ev_fd, &temp, sizeof(uint64_t));
    int                   ret = io_getevents(ioctx, 0, MAX_COMPLETIONS, events, NULL);
    if (ret == 0) {
        COUNTER_INCREMENT(m_metrics, spurious_events, 1);
    }
    if (ret < 0) {
        /* TODO how to handle it */
        LOGERROR("process_completions ret is less then zero {}", ret);
        COUNTER_INCREMENT(m_metrics, io_get_event_err, 1);
        return;
    }
    
    for (int i = 0; i < ret; i++) {
        assert(static_cast< int64_t >(events[i].res) >= 0);
        struct iocb_info* info = static_cast< iocb_info* >(events[i].obj);
        struct iocb*      iocb = static_cast< struct iocb* >(info);
        iocb_list.push(info);
        if (info->size != events[i].res || events[i].res2) {
            LOGERROR("io is not completed properly. size read/written {} info {} error {}", events[i].res, 
                        info->to_string(), events[i].res2);
            if (events[i].res2 == 0) {
                comp_cb(EIO, (uint8_t*)events[i].data);
                continue;
            }
        }
        comp_cb(events[i].res2, (uint8_t*)events[i].data);
    }
}

void DriveEndPoint::async_write(int m_sync_fd, const char* data, uint32_t size, uint64_t offset, uint8_t* cookie) {
    m_metrics.init();
    if (iocb_list.empty()) {
        COUNTER_INCREMENT(m_metrics, no_iocb, 1);
        sync_write(m_sync_fd, data, size, offset);
        comp_cb(0, cookie);
        return;
    }

    struct iocb_info* info = iocb_list.top();
    struct iocb*      iocb = static_cast< struct iocb* >(info);
    iocb_list.pop();

    io_prep_pwrite(iocb, m_sync_fd, (void*)data, size, offset);
    io_set_eventfd(iocb, ev_fd);
    iocb->data = cookie;
    info->is_read = false;
    info->size = size;
    info->offset = offset;
    info->fd = m_sync_fd;

    LOGTRACE("Writing: {}", size);
    
    auto ret = 0;
    ret = io_submit(ioctx, 1, &iocb);

    if (ret != 1 && errno == EAGAIN) {
        COUNTER_INCREMENT(m_metrics, eagain_error, 1);
        sync_write(m_sync_fd, data, size, offset);
        comp_cb(0, cookie);
        return;
    }
    
    if (ret != 1) {
        LOGERROR("io submit fail fd {}, size {}, offset {}, errno {}", m_sync_fd, size, offset, errno);
        comp_cb(errno, cookie);
    }
    
    if (size % homestore::HomeStoreConfig::align_size) {
        COUNTER_INCREMENT(m_metrics, unalign_write, 1);
    }
    COUNTER_INCREMENT(m_metrics, write_cnt, 1);
    COUNTER_INCREMENT(m_metrics, write_size, size);
}

void DriveEndPoint::async_read(int m_sync_fd, char* data, uint32_t size, uint64_t offset, uint8_t* cookie) {

    m_metrics.init();
    if (iocb_list.empty()) {
        COUNTER_INCREMENT(m_metrics, no_iocb, 1);
        sync_read(m_sync_fd, data, size, offset);
        comp_cb(0, cookie);
        return;
    }
    struct iocb_info* info = iocb_list.top();
    struct iocb*      iocb = static_cast< struct iocb* >(info);
    iocb_list.pop();

    io_prep_pread(iocb, m_sync_fd, data, size, offset);
    io_set_eventfd(iocb, ev_fd);
    iocb->data = cookie;
    info->is_read = true;
    info->size = size;
    info->offset = offset;
    info->fd = m_sync_fd;

    LOGTRACE("Reading: {}", size);
    auto ret = 0;
    ret = io_submit(ioctx, 1, &iocb);
 
    if (ret != 1 && errno == EAGAIN) {
        COUNTER_INCREMENT(m_metrics, eagain_error, 1);
        sync_read(m_sync_fd, data, size, offset);
        comp_cb(0, cookie);
        return;
    }
    
    if (ret != 1) {
        LOGERROR("io submit fail fd {}, size {}, offset {}, errno {}", m_sync_fd, size, offset, errno);
        comp_cb(errno, cookie);
    }
    COUNTER_INCREMENT(m_metrics, read_cnt, 1);
    COUNTER_INCREMENT(m_metrics, read_size, size);
}

void DriveEndPoint::async_writev(int m_sync_fd, const struct iovec* iov, int iovcnt, uint32_t size, uint64_t offset,
                                 uint8_t* cookie) {

    m_metrics.init();
    if (iocb_list.empty() 
#ifdef _PRERELEASE
    || homestore_flip->test_flip("io_write_iocb_empty_flip")
#endif
    ) {
        COUNTER_INCREMENT(m_metrics, no_iocb, 1);
        sync_writev(m_sync_fd, iov, iovcnt, size, offset);
        comp_cb(0, cookie);
        return;
    }
    struct iocb_info* info = iocb_list.top();
    struct iocb*      iocb = static_cast< struct iocb* >(info);
    iocb_list.pop();
    io_prep_pwritev(iocb, m_sync_fd, iov, iovcnt, offset);
    io_set_eventfd(iocb, ev_fd);
    iocb->data = cookie;
    info->is_read = false;
    info->size = size;
    info->offset = offset;
    info->fd = m_sync_fd;

#ifdef _PRERELEASE
    if (homestore_flip->test_flip("io_write_error_flip")) {
        comp_cb(homestore::homestore_error::write_failed, cookie);
        return;
    }
#endif
    auto ret = 0;
    ret = io_submit(ioctx, 1, &iocb);
 
    if (ret != 1 && errno == EAGAIN) {
        COUNTER_INCREMENT(m_metrics, eagain_error, 1);
        sync_writev(m_sync_fd, iov, iovcnt, size, offset);
        comp_cb(0, cookie);
        return;
    }

    if (ret != 1) {
        LOGERROR("io submit fail fd {}, iovcnt {}, size {}, offset {}, errno {}, ioctx {}", m_sync_fd, 
                    iovcnt, size, offset, errno, (uint64_t)ioctx);
        comp_cb(errno, cookie);
    }
    
    if (size % homestore::HomeStoreConfig::align_size) {
        COUNTER_INCREMENT(m_metrics, unalign_write, 1);
    }
    COUNTER_INCREMENT(m_metrics, write_cnt, 1);
    COUNTER_INCREMENT(m_metrics, write_size, size);
}

void DriveEndPoint::async_readv(int m_sync_fd, const struct iovec* iov, int iovcnt, uint32_t size, uint64_t offset,
                                uint8_t* cookie) {

    m_metrics.init();
    if (iocb_list.empty()
#ifdef _PRERELEASE
    || homestore_flip->test_flip("io_read_iocb_empty_flip")
#endif
    ) {
        COUNTER_INCREMENT(m_metrics, no_iocb, 1);
        sync_readv(m_sync_fd, iov, iovcnt, size, offset);
        comp_cb(0, cookie);
        return;
    }
    struct iocb_info* info = iocb_list.top();
    struct iocb*      iocb = static_cast< struct iocb* >(info);
    iocb_list.pop();

    io_prep_preadv(iocb, m_sync_fd, iov, iovcnt, offset);
    io_set_eventfd(iocb, ev_fd);
    iocb->data = cookie;
    info->is_read = true;
    info->size = size;
    info->offset = offset;
    info->fd = m_sync_fd;

#ifdef _PRERELEASE
    if (homestore_flip->test_flip("io_read_error_flip", iovcnt, size)) {
        comp_cb(homestore::homestore_error::read_failed, cookie);
        return;
    }
#endif
    LOGTRACE("Reading: {} vectors", iovcnt);
    auto ret = 0;
    ret = io_submit(ioctx, 1, &iocb);
    
    if (ret != 1 && errno == EAGAIN) {
        COUNTER_INCREMENT(m_metrics, eagain_error, 1);
        sync_readv(m_sync_fd, iov, iovcnt, size, offset);
        comp_cb(0, cookie);
        return;
    }
    
    if (ret != 1) {
        LOGERROR("io submit fail fd {}, iovcnt {}, size {}, offset {}, errno {}", m_sync_fd, iovcnt, size, offset, errno);
        comp_cb(errno, cookie);
    }
    COUNTER_INCREMENT(m_metrics, read_cnt, 1);
    COUNTER_INCREMENT(m_metrics, read_size, size);
}

void DriveEndPoint::sync_write(int m_sync_fd, const char* data, uint32_t size, uint64_t offset) {
    m_metrics.init();

#ifdef _PRERELEASE
    if (homestore_flip->test_flip("io_sync_write_error_flip", size)) {
        folly::throwSystemError("flip error");
    }
#endif
    if (size % homestore::HomeStoreConfig::align_size) {
        COUNTER_INCREMENT(m_metrics, unalign_write, 1);
    }
    
    ssize_t written_size = pwrite(m_sync_fd, data, (ssize_t)size, (off_t)offset);
    
    if (written_size != size) {
        std::stringstream ss;
        ss << "Error trying to write offset " << offset << " size to write = " << size
           << " size written = " << written_size << " err no" << errno << " m_sync_fd" << m_sync_fd << "\n";
        folly::throwSystemError(ss.str());
    }
    COUNTER_INCREMENT(m_metrics, write_cnt, 1);
    COUNTER_INCREMENT(m_metrics, write_size, size);
}

void DriveEndPoint::sync_writev(int m_sync_fd, const struct iovec* iov, int iovcnt, uint32_t size, uint64_t offset) {
#ifdef _PRERELEASE
    if (homestore_flip->test_flip("io_sync_write_error_flip", iovcnt, size)) {
        folly::throwSystemError("flip error");
    }
#endif
    
    if (size % homestore::HomeStoreConfig::align_size) {
        COUNTER_INCREMENT(m_metrics, unalign_write, 1);
    }
    
    ssize_t written_size = pwritev(m_sync_fd, iov, iovcnt, offset);
    if (written_size != size) {
        std::stringstream ss;
        ss << "Error trying to write offset " << offset << " size to write = " << size
           << " size written = " << written_size << " err no: " << errno << " err msg: " << strerror(errno) << " m_sync_fd" << m_sync_fd << "\n";
        folly::throwSystemError(ss.str());
    }
    COUNTER_INCREMENT(m_metrics, write_cnt, 1);
    COUNTER_INCREMENT(m_metrics, write_size, size);
}

ssize_t DriveEndPoint::sync_read(int m_sync_fd, char* data, uint32_t size, uint64_t offset) {
    m_metrics.init();
#ifdef _PRERELEASE
    if (homestore_flip->test_flip("io_sync_read_error_flip", size)) {
        folly::throwSystemError("flip error");
    }
#endif
    ssize_t read_size = pread(m_sync_fd, data, (ssize_t)size, (off_t)offset);
#if 0
    if (read_size != size) {
        std::stringstream ss;
        int               i = errno;
        ss << "Error trying to read offset " << offset << " size to read = " << size << " size read = " << read_size
           << "err no" << errno << " m_sync_fd" << m_sync_fd << "\n";
        folly::throwSystemError(ss.str());
    }
#endif
    COUNTER_INCREMENT(m_metrics, read_cnt, 1);
    COUNTER_INCREMENT(m_metrics, read_size, size);

    return read_size;
}

ssize_t DriveEndPoint::sync_readv(int m_sync_fd, const struct iovec* iov, int iovcnt, uint32_t size, uint64_t offset) {
    m_metrics.init();
#ifdef _PRERELEASE
    if (homestore_flip->test_flip("io_sync_read_error_flip", iovcnt, size)) {
        folly::throwSystemError("flip error");
    }
#endif
    ssize_t read_size = preadv(m_sync_fd, iov, iovcnt, (off_t)offset);
#if 0
    if (read_size != size) {
        std::stringstream ss;
        ss << "Error trying to read offset " << offset << " size to read = " << size << " size read = " << read_size
           << "err no" << errno << " m_sync_fd" << m_sync_fd << "\n";
        folly::throwSystemError(ss.str());
    }
#endif
    COUNTER_INCREMENT(m_metrics, read_cnt, 1);
    COUNTER_INCREMENT(m_metrics, read_size, size);
    return read_size;
}

} // namespace homeio
