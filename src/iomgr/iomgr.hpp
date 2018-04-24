//
// Created by Rishabh Mittal on 04/20/2018
//
#ifndef _IOMGR_H_
#define _IOMGR_H_

#include <atomic>
#include <endpoint.hpp>

#ifdef __LINUX__
#include <sys/eventfd.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <vector.h>
#endif
namespace homeio {

class IoMgr;
typedef std::function< void (int fd, uint32_t events) > ev_callback;
typedef std::function< void (int status, uint8_t* cookie) > comp_callback;

#ifdef __LINUX__
class EndPoint {
    	ioMgr *iomgr;
public:
	EndPoint(class ioMgr *iomgr):iomgr(iomgr) {
		iomgr->add_ep(this);
    	}
    	virtual void init_local() = 0;
};

struct thread_info {
        pthread_t tid;
        uint64_t count;
        uint64_t time_spent_ns;
}

class ioMgr {
	private:
        typedef max_events 10;
        struct fd_info {
                ev_callback cb;
                std::atomic<bool> is_runing;
        };

        int num_ep;
        int num_threads;
        vector<EndPoint *> ep_list;
        vector<thread_info> threads;
        int global_epollfd;
        thread_local int local_epollfd;
        std::map<int, fd_info> fdcb_map;
public: 
        ioMgr(int num_ep, int num_threads);
	void local_init();
	void add_ep(class EndPoint *ep, ev_callback cb);
	void add_fd(int fd, comp_callback cb);
	void add_local_fd(int fd, comp_callback cb);
	void callback(int fd, uint32_t event);
	bool can_process(int fd);
	void process_done(int fd);
	struct thread_info *get_tid_info(pthread_t &tid);
	void print_perf_cntrs();
}
#else 
class EndPoint {
	EndPoint(class ioMgr *iomgr):iomgr(iomgr) {
	}
}

class ioMgr {
	ioMgr(int num_ep, int num_threads) {};
}
#endif
}
#endif
