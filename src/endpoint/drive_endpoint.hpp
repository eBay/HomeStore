//
// Created by Rishabh Mittal 04/20/2018
//
#pragma once

#include <unistd.h>
#include <string>
#include <iostream> 
#include <sstream> 
#include <iomgr/iomgr.hpp>
#include <stack>
#include <atomic>
#include <mutex>
#include "homeds/utility/useful_defs.hpp"
#include <metrics/metrics.hpp>

#ifdef linux
#include <fcntl.h>
#include <libaio.h>
#include <sys/eventfd.h>
#include <stdio.h>
#endif

using namespace std;
namespace homeio {
#define MAX_OUTSTANDING_IO 200 // if max outstanding IO is more then
			                   //  200 then io_submit will fail.
#define MAX_COMPLETIONS (MAX_OUTSTANDING_IO)  // how many completions to process in one shot

typedef std::function< void (int64_t res, uint8_t* cookie) > comp_callback;
#ifdef linux
struct iocb_info : public iocb {
	bool is_read;
    uint32_t size;
    uint64_t offset;
	Clock::time_point start_time;
    int fd;
        
    std::string to_string() const {
        std::stringstream ss;
        ss << "is_read = " << is_read << ", size = " << size << ", offset = " << offset << ", fd = " << fd;
        return ss.str();
    }
};

class DriveEndPointMetrics : public sisl::MetricsGroupWrapper {
    static std::atomic<int> thread_num;
public:
    DriveEndPointMetrics() : sisl::MetricsGroupWrapper("DriveEndPoint", std::to_string(thread_num.fetch_add(1))) {
        LOGINFO("metrics is inited");
        REGISTER_COUNTER(spurious_events, "spurious events");
        REGISTER_COUNTER(io_get_event_err, "io get event error");
        REGISTER_COUNTER(write_cnt, "Drive async write count");
        REGISTER_COUNTER(read_cnt, "Drive async read count");
        REGISTER_COUNTER(write_size, "Total Count of buffer provided for write");
        REGISTER_COUNTER(read_size, "Total Count of buffer provided for read");
        REGISTER_COUNTER(no_iocb, "no iocb left for read/write");
        REGISTER_COUNTER(eagain_error, "eagain_error for read/write");
        REGISTER_COUNTER(unalign_write, "number of unaligned writes");

        register_me_to_farm();
    }

    void init() {};
};

class DriveEndPoint : public iomgr::EndPoint {
public:
	DriveEndPoint(std::shared_ptr<iomgr::ioMgr> iomgr, comp_callback cb);
    ~DriveEndPoint();
   
	int open_dev(std::string devname, int oflags); 
	void sync_write(int m_sync_fd, const char *data, uint32_t size, uint64_t offset);
	void sync_writev(int m_sync_fd, const iovec *iov, int iovcnt, uint32_t size, uint64_t offset);
	void sync_read(int m_sync_fd, char *data, uint32_t size, uint64_t offset);
	void sync_readv(int m_sync_fd, const iovec *iov, int iovcnt, uint32_t size, uint64_t offset);
	void async_write(int m_sync_fd, const char *data,  uint32_t size, uint64_t offset, uint8_t *cookie);
	void async_writev(int m_sync_fd, const iovec *iov, int iovcnt, uint32_t size, uint64_t offset, uint8_t *cookie);
	void async_read(int m_sync_fd, char *data, uint32_t size, uint64_t offset, uint8_t *cookie);
	void async_readv(int m_sync_fd, const iovec *iov, int iovcnt, uint32_t size, uint64_t offset, uint8_t *cookie);
	void process_completions(int fd, void *cookie, int event);
	void init_local() override;
	void shutdown_local() override;
	void print_perf() override {}

private:
	static thread_local int ev_fd;
	static thread_local io_context_t ioctx;
	static thread_local stack <struct iocb_info *> iocb_list;
	static thread_local struct io_event events[MAX_COMPLETIONS];

	atomic<uint64_t> spurious_events;
	atomic<uint64_t> cmp_err;
	comp_callback comp_cb;
    static thread_local DriveEndPointMetrics m_metrics;
};
#else 
class DriveEndPoint : public iomgr::EndPoint {
public:
	DriveEndPoint(iomgr::ioMgr *iomgr, comp_callback cb) {};
}
#endif
}
