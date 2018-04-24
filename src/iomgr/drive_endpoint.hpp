//
// Created by Rishabh Mittal 04/20/2018
//

#ifndef _DRIVE_ENDPOINT_HPP_
#define _DRIVE_ENDPOINT_HPP_
#include <unistd.h>
#include <string>
#include <iomgr.hpp>

#ifdef __LINUX__
#include <fcntl.h>
#include <libaio.h>
#include <sys/eventfd.h>
#include <stdio.h>
#endif

namespace homeio {
#define MAX_OUTSTANDING_IO 100 // if max outstanding IO is
			       //  100 then io_submit will fail.
#define MAX_COMPLETIONS MAX_OUTSTANDING_IO/4  // how many completions to process in one shot

typedef std::function< void (int status, uint8_t* cookie) > comp_callback;
#ifdef __LINUX__
class DriveEndPoint : public EndPoint {
public:
	DriveEndPoint(ioMgr *iomgr, comp_callback cb);
   
	int open(std::string devname, int oflags); 
	void sync_write(int m_sync_fd, const char *data, uint32_t size, uint64_t offset);
	void sync_writev(int m_sync_fd, const struct iovec *iov, 
					int iovcnt, uint32_t size, uint64_t offset);
	void sync_read(int m_sync_fd, char *data, 
					uint32_t size, uint64_t offset);
	void sync_readv(int m_sync_fd, const struct iovec *iov, 
					int iovcnt, uint32_t size, uint64_t offset);
	void async_write(int m_sync_fd, const char *data, 
					uint32_t size, uint64_t offset);
	void async_writev(int m_sync_fd, const struct iovec *iov, 
					int iovcnt, uint32_t size, uint64_t offset);
	void async_read(int m_sync_fd, char *data, 
					uint32_t size, uint64_t offset);
	void async_readv(int m_sync_fd, const struct iovec *iov, 
					int iovcnt, uint32_t size, uint64_t offset);
	void process_completions(int fd, int event);
	void init_local() override; 

private:
	thread_local int ev_fd;
	thread_local io_context_t ioctx;
	thread_local struct io_event events[MAX_COMPLETIONS];
	comp_callback comp_cb;
};
#else 
class DriveEndPoint : public EndPoint {
public:
	DriveEndPoint(ioMgr *iomgr, comp_callback cb){};
}
#endif
}
#endif //HOMESTORE_FD_HPP
