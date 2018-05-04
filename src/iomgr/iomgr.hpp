//
// Created by Rishabh Mittal on 04/20/2018
//
#ifndef _IOMGR_H_
#define _IOMGR_H_

#include <atomic>
#ifdef linux
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <errno.h>
#include <thread>
#endif

#include <iostream>
#include <cassert>
#include <atomic>
#include <vector>
#include <functional>
#include <stdio.h>
#include <pthread.h>
#include <map>

using std::vector;
namespace homeio {

typedef std::chrono::steady_clock Clock;
typedef std::function< void (int fd, void *cookie, uint32_t events) > ev_callback;

#ifdef linux
class ioMgr;
void *iothread(void *iomgr);
class EndPoint {
public:
    	ioMgr *iomgr;
	EndPoint(class ioMgr *iomgr);
    	virtual void init_local() = 0;
	virtual void print_perf() = 0;
};

struct thread_info {
        pthread_t tid;
        uint64_t count;
        uint64_t time_spent_ns;
	int id;
	int ev_fd;
	int inited;
	int *epollfd_pri;
};

#define READ 0
#define WRITE 1
struct fd_info {
	ev_callback cb;
	int fd;
	std::atomic<int> is_running[2];
	int ev;
	bool is_global;
	int pri;
	vector<int> ev_fd;
	vector<int> event;
	void *cookie;
};

#define MAX_PRI 10

class ioMgr {
	private:

        int num_ep;
        int num_threads;
        vector<class EndPoint *> ep_list;
	std::map<int, fd_info *> fd_info_map;
public: 
        vector<thread_info> threads;
	vector <struct fd_info *>global_fd; /* fds shared between the threads */
        static thread_local int epollfd_pri[MAX_PRI];
        static thread_local int epollfd;
	
        ioMgr(int num_ep, int num_threads);
	void local_init();
	void add_ep(class EndPoint *ep);
	void add_fd(int fd, ev_callback cb, int ev, int pri, void *cookie);
	void add_local_fd(int fd, ev_callback cb, int ev, int pri, void *cookie);
	void add_fd_to_thread(int id, int fd, ev_callback cb, int ev, 
				    int pri, void *cookie);
	void callback(void *data, uint32_t ev);
	void process_done(void *data,int ev);
	struct thread_info *get_thread_info(pthread_t &tid);
	void print_perf_cntrs();
	bool can_process(void *data, uint32_t event);
	void fd_reschedule(int fd, uint32_t event);
	void process_evfd(int fd, void *data, uint32_t event);
	struct thread_info *get_tid_info(pthread_t &tid);
};
#else 
class EndPoint {
	EndPoint(class ioMgr *iomgr):iomgr(iomgr) {
	}
};

class ioMgr {
	ioMgr(int num_ep, int num_threads) {};
};
#endif
}
#endif
