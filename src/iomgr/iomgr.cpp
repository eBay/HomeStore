//
// Created by Rishabh Mittal on 04/20/2018
//
#ifdef linux
#include "iomgr.hpp"
#include <ctime>
#include <chrono>
#include <functional>
#include <sys/types.h>
#include <homeds/utility/logging.hpp>

using namespace homeio;

using namespace std; 


thread_local int ioMgr::epollfd = 0;
thread_local int ioMgr::epollfd_pri[MAX_PRI] = {};

EndPoint::EndPoint(class ioMgr *iomgr):iomgr(iomgr) {
}

ioMgr::ioMgr(size_t num_ep, size_t num_threads):num_ep(num_ep), 
	num_threads(num_threads), threads(num_threads) {
	ready = false;
	global_fd.reserve(num_ep * 10);	
	threads.resize(num_threads);
	for (auto i = 0u; i < num_threads; i++) {
		int rc = pthread_create(&(threads[i].tid), NULL, 
				iothread, (void *)this);
		threads[i].id = i;
		threads[i].inited = false;
		assert(!rc);
	}
}

void 
ioMgr::local_init() {
	struct epoll_event ev;
	pthread_t t = pthread_self();
	thread_info *info = get_tid_info(t);
	
	epollfd = epoll_create1(0);
	
	if (epollfd < 1) {
		assert(0);
		LOG(ERROR) << "epoll_ctl failed " << errno << "line number" << __LINE__; 
	}
	
	for (auto i = 0; i < MAX_PRI; i++) {
		epollfd_pri[i] = epoll_create1(0);
		ev.events = EPOLLET | EPOLLIN | EPOLLOUT;
		ev.data.fd = epollfd_pri[i];
		if (epoll_ctl(epollfd, EPOLL_CTL_ADD,
			epollfd_pri[i], &ev) == -1) {
			assert(0);
			LOG(ERROR) << "epoll_ctl failed " << errno << "line number" << __LINE__; 
		}
	}
	
	// add event fd to each thread
	info->inited = true;
	info->epollfd_pri = epollfd_pri;

	for(auto i = 0u; i < global_fd.size(); i++) {
		/* We cannot use EPOLLEXCLUSIVE flag here. otherwise
                 * some events can be missed.
		 */
		ev.events = EPOLLET | global_fd[i]->ev;
		ev.data.ptr = global_fd[i];
		if (epoll_ctl(epollfd_pri[global_fd[i]->pri], EPOLL_CTL_ADD,
			global_fd[i]->fd, &ev) == -1) {
			assert(0);
			LOG(ERROR) << "epoll_ctl failed " << errno << "line number" << __LINE__; 
		}

		add_local_fd(global_fd[i]->ev_fd[info->id], 
				std::bind(&ioMgr::process_evfd, this, std::placeholders::_1, 
					  std::placeholders::_2, std::placeholders::_3),
				EPOLLIN, 1, global_fd[i]);
		
		LOG(ERROR) << "registered global fds";
	}
	
	assert(num_ep == ep_list.size());
	/* initialize all the thread local variables in end point */
	for (auto i = 0u; i < num_ep; i++) {
		ep_list[i]->init_local();
	}
}

void
ioMgr::wait_for_ready() {
	std::unique_lock<std::mutex> lck(cv_mtx);
	while(!ready) cv.wait(lck);
}

void 
ioMgr::add_ep(class EndPoint *ep) {
	ep_list.push_back(ep);
	if (ep_list.size() == num_ep) {
		/* allow threads to run */
		std::unique_lock<std::mutex> lck(cv_mtx);
		ready = true;
		cv.notify_all();
	}
}

void
ioMgr::add_fd(int fd, ev_callback cb, int iomgr_ev, int pri, void *cookie) {
	struct fd_info* info = new struct fd_info;

	fd_info_map.insert(std::pair<int, fd_info*>(fd, info));	
	info->cb = cb;
	info->is_running[0] = 0;
	info->is_running[1] = 0;
	info->fd = fd;
	info->ev = iomgr_ev;
	info->is_global = true;
	info->pri = pri;
	info->cookie = cookie;
	info->ev_fd.resize(num_threads);
	info->event.resize(num_threads);
	for (auto i = 0u; i < num_threads; i++) {
		info->ev_fd[i] = eventfd(0, EFD_NONBLOCK);
		info->event[i] = 0;
	}
	
	global_fd.push_back(info);
	
	struct epoll_event ev;
	/* add it to all the threads */
	for (auto i = 0u; i < num_threads; i++) {
		ev.events = EPOLLET | info->ev;
		ev.data.ptr = info;
		if (!threads[i].inited) {
			continue;
		}	
		if (epoll_ctl(threads[i].epollfd_pri[pri], EPOLL_CTL_ADD,
				fd, &ev) == -1) {
			assert(0);
		}
		add_fd_to_thread(i, info->ev_fd[i], 
				       std::bind(&ioMgr::process_evfd, this, 
						 std::placeholders::_1, std::placeholders::_2, std::placeholders::_3),
					EPOLLIN, 1, info);
	}
}

void
ioMgr::add_local_fd(int fd, ev_callback cb, int iomgr_ev, int pri, void *cookie) {
	/* get local id */
	pthread_t t = pthread_self();
	thread_info *info = get_tid_info(t);
	
	add_fd_to_thread(info->id, fd, cb, iomgr_ev, pri, cookie);
}

void 
ioMgr::add_fd_to_thread(int i, int fd, ev_callback cb, 
			      int iomgr_ev, int pri, void *cookie) {
	struct epoll_event ev;
	struct fd_info* info = new struct fd_info;
	std::unique_lock<std::mutex> lck(map_mtx);
	fd_info_map.insert(std::pair<int, fd_info*>(fd, info));	

	info->cb = cb;
	info->is_running[0] = 0;
	info->is_running[1] = 0;
	info->fd = fd;
	info->ev = iomgr_ev;
	info->is_global = false;
	info->pri = pri;
	info->cookie = cookie;

	ev.events = EPOLLET | iomgr_ev;
	ev.data.ptr = info;
	if (epoll_ctl(threads[i].epollfd_pri[pri], EPOLL_CTL_ADD, 
				fd, &ev) == -1) {
		assert(0);
	}
	return;
}

void 
ioMgr::callback(void *data, uint32_t event) {
	struct fd_info *info = (struct fd_info *)data;
	info->cb(info->fd, info->cookie, event);
}

bool
ioMgr::can_process(void *data, uint32_t ev) {
	struct fd_info *info = (struct fd_info *)data;
	int expected = 0;
	int desired = 1;
	bool ret = false;
	if (ev == EPOLLIN) { 
		ret = info->is_running[READ].compare_exchange_strong(expected, desired, 
				std::memory_order_acquire, 
				std::memory_order_acquire);
	} else if (ev == EPOLLOUT) {
		ret = info->is_running[WRITE].compare_exchange_strong(expected, desired, 
				std::memory_order_acquire, 
				std::memory_order_acquire);
	} else {
		assert(0);
	}
	if (ret) {
//		LOG(INFO) << "running for fd" << info->fd;
	}else {
//		LOG(INFO) << "not allowed running for fd" << info->fd;
	}
	return ret;
}

void
ioMgr::fd_reschedule(int fd, uint32_t event) {
	/* XXX: we might need to take a lock, if we 
	 * support dynamic add/remove of FDs. To make  it lockless
	 * we should consider fd_info in fd_reschedule.
	 */
	std::map<int, fd_info*>::iterator it;
	it = fd_info_map.find(fd);
	assert(it->first == fd);

	struct fd_info *info = it->second;
	uint64_t min_cnt = UINTMAX_MAX;
	int min_id = 0;
	
	for(auto i = 0u; i < num_threads; i++) {
		if (threads[i].count < min_cnt) {
			min_id = i;
			min_cnt = threads[i].count;
		}
	}
	info->event[min_id] |= event;
	uint64_t temp = 1;
	while (0 > write(info->ev_fd[min_id], &temp, sizeof(uint64_t)) && errno == EAGAIN);
}

void
ioMgr::process_evfd(int fd, void *data, uint32_t event) {
	struct fd_info *info = (struct fd_info *)data;
	uint64_t temp;
	pthread_t t = pthread_self();
	thread_info *tinfo = get_tid_info(t);

	if (info->event[tinfo->id] & EPOLLIN && can_process(info, event)) {
		info->cb(info->fd, info->cookie, EPOLLIN);
	}
	
	if (info->event[tinfo->id] & EPOLLOUT && can_process(info, event)) {
		info->cb(info->fd, info->cookie, EPOLLOUT);
	}
	info->event[tinfo->id] = 0;
	process_done(fd, event);
	while (0 > read(fd, &temp, sizeof(uint64_t)) && errno == EAGAIN);
}

void
ioMgr::process_done(int fd, int ev) {
	std::map<int, fd_info*>::iterator it;
	it = fd_info_map.find(fd);
	assert(it->first == fd);

	struct fd_info *info = it->second;
	
	process_done_impl(info, ev);
}

void 
ioMgr::process_done_impl(void *data, int ev) {
	struct fd_info *info = (struct fd_info *)data;
	if (ev == EPOLLIN) {
		int count = info->is_running[READ].fetch_sub(1, 
			std::memory_order_release);
	} else if (ev == EPOLLOUT) {
		int count = info->is_running[WRITE].fetch_sub(1, 
			std::memory_order_release);
	} else {
		assert(0);
	}
}

struct thread_info * 
ioMgr::get_tid_info(pthread_t &tid) {
	for (auto i = 0u; i < num_threads; i++) {
		if (threads[i].tid == tid) {
			return &threads[i];
		}
	}
	assert(0);
	return NULL;
}

uint64_t 
get_elapsed_time_ns(homeio::Clock::time_point startTime) {
	std::chrono::nanoseconds ns = std::chrono::duration_cast
		< std::chrono::nanoseconds >(Clock::now() - startTime);
	return ns.count();
}

#define MAX_EVENTS 20
void* homeio::iothread(void *obj) {
	pthread_t t = pthread_self();
	ioMgr* iomgr = static_cast<ioMgr *>(obj);
	thread_info *info = iomgr->get_tid_info(t);
	struct epoll_event fd_events[MAX_PRI];
	struct epoll_event events[MAX_EVENTS];
	int num_fds;

	iomgr->wait_for_ready();
	/* initialize the variables local to a thread */
	iomgr->local_init();

	info->count = 0;
	info->time_spent_ns = 0;
	while (1) {
	//	LOG(INFO) << "waiting " << info->id;
		num_fds = epoll_wait(iomgr->epollfd, fd_events, MAX_PRI, -1);
		for (auto i = 0; i < MAX_PRI; i++) {
			/* XXX: should it be  go through only
			 * those fds which has the events.
			 */
			num_fds = epoll_wait(iomgr->epollfd_pri[i], events, 
				MAX_EVENTS, 0);
			if (num_fds < 1) {
				LOG(ERROR) << "epoll wait failed " << errno;
				continue;
			}
//			LOG(INFO) << "waking" << info->id;
			for (auto i = 0; i < num_fds; i++) {
				if (iomgr->can_process(events[i].data.ptr, events[i].events)) {
					Clock::time_point write_startTime = Clock::now();
					info->count++;
					iomgr->callback(events[i].data.ptr, 
							events[i].events);
					info->time_spent_ns += get_elapsed_time_ns(write_startTime);
				} else {
			//		LOG(INFO) << "can not process in thread" << info->id;
				}
			}
		}
	}
}

void
ioMgr::print_perf_cntrs() {
	for(auto i = 0u; i < num_threads; i++) {
		printf("thread %d counters \n", i);
		printf("\tnumber of times %lu it run\n", threads[i].count);
		printf("\t total time spent %lu ms\n", 
				(threads[i].time_spent_ns/(1000 * 1000)));
	}
	for (auto i = 0u; i < num_ep; i++) {
		ep_list[i]->print_perf();
	}
}
#endif
