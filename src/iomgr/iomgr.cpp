//
// Created by Rishabh Mittal on 04/20/2018
//
#include "iomgr.hpp"
uinsg namespace homeio;

thread_local int ioMgr::local_epollfd = 0;
ioMgr::ioMgr(int num_ep, int num_threads):num_ep(num_ep), 
	num_threads(num_threads), threads(num_threads) {
	
	global_epollfd = epoll_create1(0);
	if (global_epollfd < 1) {
		assert(0);
		printf("epoll_ctl failed %d\n", errno):
	}
}

void 
ioMgr::local_init() {
	local_epollfd = epoll_create1(0);

	if (local_epollfd < 1) {
		assert(0);
		printf("epoll_ctl failed %d\n", errno):
	}
	ev.events = EPOLLIN | EPOLLET | EPOLLOUT;
	ev.data.fd = global_epollfd;
	if (epoll_ctl(local_epollfd, EPOLL_CTL_ADD, 
				global_epollfd, &ev) == -1) {
		assert(0);
		printf("epoll_ctl failed %d\n", errno):
	}
	assert(num_ep == ep_list.size());
	/* initialize all the thread local variables in end point */
	for (int i = 0; i < num_ep; i++) {
		ep_list[i].init_local();
	}
}

void 
ioMgr::add_ep(class EndPoint *ep) {
	ep_list.add(ep);
	if (ep_list.size() == num_ep) {
		/* create threads */
		for (int i = 0; i < num_threads; i++) {
			rc = pthread_create(&(threads[i].tid), NULL, 
					iothread, this);
		}
	}
}

void 
ioMgr::add_fd(int fd, ev_callback cb) {
	struct epoll_event ev;
	ev.events = EPOLLIN | EPOLLET | EPOLLOUT;
	ev.data.fd = fd;
	if (epoll_ctl(global_epollfd, EPOLL_CTL_ADD, 
				fd, &ev) == -1) {
		assert(0);
		printf("epoll_ctl failed %d\n", errno):
	}
	fd_info info = {cb, 0};
	fdcb_map.insert(std::pair<int, fd_callback>(fd, cb));
}

void 
ioMgr::add_local_fd(int fd, fd_callback cb) {
	struct epoll_event ev;
	ev.events = EPOLLIN | EPOLLET | EPOLLOUT;
	ev.data.fd = fd;
	if (epoll_ctl(local_epollfd, EPOLL_CTL_ADD, 
				fd, &ev) == -1) {
		assert(0);
		printf("epoll_ctl failed %d\n", errno):
	}
	fdcb_map.insert(std::pair<int, fd_callback>(fd, cb));
}

void 
ioMgr::callback(int fd, uint32_t event) {
	std::map<int, fd_callback>::iterator it;
	id = fdcb_map.find(fd);
	if (it.find == fdcb_map.end()) {
		assert(0);
		return;
	} 
	assert(it->first == fd);

	it->second.fd_cb(fd, event);
}

bool 
ioMgr::can_process(int fd) {
	std::map<int, fd_callback>::iterator it;
	id = fdcb_map.find(fd);
	if (it.find == fdcb_map.end()) {
		assert(0);
		return;
	} 
	assert(it->first == fd);
	return(it->second.is_running.atomic_compare_exchange_strong(0, 1, 
				std::memory_order_acquire, 
				std::memory_order_relaxed));	
}

void 
ioMgr::process_done(int fd) {
	std::map<int, fd_callback>::iterator it;
	id = fdcb_map.find(fd);
	if (it.find == fdcb_map.end()) {
		assert(0);
		return;
	} 
	assert(it->first == fd);

	int count = it->second.is_running.fetch_sub(1, 
			std::memory_order_release);
	assert(count == 0);
}

struct thread_info * 
ioMgr::get_tid_info(pthread_t &tid) {
	for (i = 0; i < num_threads; i++) {
		if (threads[i].tid == tid) {
			return &threads[i];
		}
	}
	assert(0);
	return NULL;
}

uint64_t 
get_elapsed_time_ns(Clock::time_point startTime) {
	std::chrono::nanoseconds ns = std::chrono::duration_cast
		< std::chrono::nanoseconds >(Clock::now() - startTime);
	return ns.count();
}

void 
*iothread(ioMgr *iomgr) {
	thread_info *info = iomgr->get_tid_info
		(std::this_thread::get_id());
	struct epoll_event events[iomgr->max_events];
	int num_fds;

	/* initialize the variables local to a thread */
	iomgr->local_init();

	/* wait on the fds */
	info->count = 0;
	info->time_spent_ns = 0;
	while (1) {
		num_fds = epoll_wait(local_epollfd, events, 
				iomgr->max_events, -1);
		if (num_fds < 1) {
			assert(0);
		}
		info->count++;
		Clock::time_point write_startTime = Clock::now();

		if (num_events < 0) {
			assert(0);
			printf("epoll wait failed %d\n", errno);
		}
		for (int i = 0; i < num_fds; i++) {
			int fd = events[i].data.fd;
			if (iomgr->can_process(fd)) {
				iomgr->callback(fd, events[i].events);
				iomgr->process_done(fd);
			}
		}
		info->time_spent_ns += get_elapsed_time_ns(write_startTime);
	}
}

void
ioMgr::print_perf_cntrs() {
	for(int i = 0; i < num_threadso i++) {
		printf("thread %d counters \n", i);
		printf("\tnumber of times %lu it run\n", threads[i].count);
		printf("\t total time spent %lu ms\n", 
				(threads[i].time_spent_ns/(1000 * 1000)));
	}
}
