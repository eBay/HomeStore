//
// Created by Rishabh Mittal 04/20/2018
//
#pragma once

#include <unistd.h>
#include <string>
#include <iomgr/iomgr.hpp>
#include <stack>
#include <atomic>
#include <mutex>

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

using Clock = std::chrono::steady_clock;
#define CURRENT_CLOCK(name) Clock::time_point (name) = Clock::now();

typedef std::function< void (int64_t res, uint8_t* cookie) > comp_callback;
#ifdef linux
struct iocb_info : public iocb {
	bool is_read;
	Clock::time_point start_time;
};
class DriveEndPoint : public iomgr::EndPoint {
public:
	DriveEndPoint(std::shared_ptr<iomgr::ioMgr> iomgr, comp_callback cb);
   
	int open_dev(std::string devname, int oflags); 
	void sync_write(int m_sync_fd, const char *data, uint32_t size, uint64_t offset);
	void sync_writev(int m_sync_fd, const struct iovec *iov, 
					int iovcnt, uint32_t size, uint64_t offset);
	void sync_read(int m_sync_fd, char *data, 
					uint32_t size, uint64_t offset);
	void sync_readv(int m_sync_fd, const struct iovec *iov, 
					int iovcnt, uint32_t size, uint64_t offset);
	void async_write(int m_sync_fd, const char *data, 
					uint32_t size, uint64_t offset, 
					uint8_t *cookie);
	void async_writev(int m_sync_fd, const struct iovec *iov, 
					int iovcnt, uint32_t size, uint64_t offset, 
					uint8_t *cookie);
	void async_read(int m_sync_fd, char *data, 
					uint32_t size, uint64_t offset, 
					uint8_t *cookie);
	void async_readv(int m_sync_fd, const struct iovec *iov, 
					int iovcnt, uint32_t size, uint64_t offset, 
					uint8_t *cookie);
	void process_completions(int fd, void *cookie, int event);
	void init_local() override; 
	void print_perf() override;

private:
	static thread_local int ev_fd;
	static thread_local io_context_t ioctx;
	static thread_local stack <struct iocb_info *> iocb_list;
	static thread_local struct io_event events[MAX_COMPLETIONS];

	atomic<uint64_t> write_aio_lat;
	atomic<uint64_t> total_write_ios;
	atomic<uint64_t> read_aio_lat;
	atomic<uint64_t> total_read_ios;
	atomic<uint64_t> spurious_events;
	atomic<uint64_t> cmp_err;
	comp_callback comp_cb;
};
#else 
class DriveEndPoint : public iomgr::EndPoint {
public:
	DriveEndPoint(iomgr::ioMgr *iomgr, comp_callback cb) {};
}
#endif
}
