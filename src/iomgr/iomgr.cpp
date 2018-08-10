//
// Created by Rishabh Mittal on 04/20/2018
//

#include "iomgr_impl.hpp"

extern "C" {
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <sys/types.h>
}

#include <cerrno>
#include <ctime>
#include <chrono>
#include <functional>
#include <vector>

#include <sds_logging/logging.h>

#include "io_thread.hpp"

namespace iomgr
{

thread_local int ioMgrImpl::epollfd = 0;
thread_local int ioMgrImpl::epollfd_pri[iomgr::MAX_PRI] = {};

struct fd_info {
   enum {READ = 0, WRITE};

   ev_callback cb;
   int fd;
   std::atomic<int> is_running[2];
   int ev;
   bool is_global;
   int pri;
   std::vector<int> ev_fd;
   std::vector<int> event;
   void *cookie;
};

ioMgrImpl::ioMgrImpl(size_t const num_ep, size_t const num_threads) :
    threads(num_threads),
    num_ep(num_ep),
    running(false)
{
   ready = num_ep == 0;
   global_fd.reserve(num_ep * 10);
   LOGDEBUG("Starting ready: {}", ready);
}

ioMgrImpl::~ioMgrImpl() = default;

void
ioMgrImpl::start() {
   running.store(true, std::memory_order_relaxed);
   for (auto i = 0u; threads.size() > i; ++i) {
      auto& t_info = threads[i];
      auto iomgr_copy = new std::shared_ptr<ioMgrImpl>(shared_from_this());
      int rc = pthread_create(&(t_info.tid), nullptr, iothread, iomgr_copy);
      assert(!rc);
      if (rc) {
         LOGCRITICAL("Failed to create thread: {}", rc);
         continue;
      }
      LOGTRACE("Created thread...", i);
      t_info.id = i;
      t_info.inited = false;
      pthread_detach(t_info.tid);
   }
}

void
ioMgrImpl::local_init() {
   {
      std::unique_lock<std::mutex> lck(cv_mtx);
      cv.wait(lck, [this] { return ready; });
   }
   if (!is_running()) return;
   LOGTRACE("Initializing locals.");

   struct epoll_event ev;
   pthread_t t = pthread_self();
   thread_info *info = get_tid_info(t);

   epollfd = epoll_create1(0);
   LOGTRACE("EPoll created: {}", epollfd);

   if (epollfd < 1) {
      assert(0);
      LOGERROR("epoll_ctl failed: {}", strerror(errno));
   }

   for (auto i = 0ul; i < MAX_PRI; ++i) {
      epollfd_pri[i] = epoll_create1(0);
      ev.events = EPOLLET | EPOLLIN | EPOLLOUT;
      ev.data.fd = epollfd_pri[i];
      if (epoll_ctl(epollfd, EPOLL_CTL_ADD,
                    epollfd_pri[i], &ev) == -1) {
         assert(0);
         LOGERROR("epoll_ctl failed: {}", strerror(errno));
      }
   }

   // add event fd to each thread
   info->inited = true;
   info->epollfd_pri = epollfd_pri;

   for(auto i = 0u; i < global_fd.size(); ++i) {
      /* We cannot use EPOLLEXCLUSIVE flag here. otherwise
       * some events can be missed.
       */
      ev.events = EPOLLET | global_fd[i]->ev;
      ev.data.ptr = global_fd[i];
      if (epoll_ctl(epollfd_pri[global_fd[i]->pri], EPOLL_CTL_ADD,
                    global_fd[i]->fd, &ev) == -1) {
         assert(0);
         LOGERROR("epoll_ctl failed: {}", strerror(errno));
      }

      add_local_fd(global_fd[i]->ev_fd[info->id],
                   [this] (int fd, void* cookie, uint32_t events)
                   { process_evfd(fd, cookie, events); },
                   EPOLLIN, 1, global_fd[i]);

      LOGDEBUG("registered global fds");
   }

   assert(num_ep == ep_list.size());
   /* initialize all the thread local variables in end point */
   for (auto i = 0u; i < num_ep; ++i) {
      ep_list[i]->init_local();
   }
}

bool
ioMgrImpl::is_running() const {
    return running.load(std::memory_order_relaxed);
}

void
ioMgrImpl::add_ep(class EndPoint *ep) {
   ep_list.push_back(ep);
   if (ep_list.size() == num_ep) {
      /* allow threads to run */
      std::unique_lock<std::mutex> lck(cv_mtx);
      ready = true;
   }
   cv.notify_all();
   LOGTRACE("Added Endpoint.");
}

void
ioMgrImpl::add_fd(int fd, ev_callback cb, int iomgr_ev, int pri, void *cookie) {
   struct fd_info* info = new struct fd_info;

   fd_info_map.insert(std::pair<int, fd_info*>(fd, info));
   info->cb = cb;
   info->is_running[fd_info::READ] = 0;
   info->is_running[fd_info::WRITE] = 0;
   info->fd = fd;
   info->ev = iomgr_ev;
   info->is_global = true;
   info->pri = pri;
   info->cookie = cookie;
   info->ev_fd.resize(threads.size());
   info->event.resize(threads.size());
   for (auto i = 0u; i < threads.size(); ++i) {
      info->ev_fd[i] = eventfd(0, EFD_NONBLOCK);
      info->event[i] = 0;
   }

   global_fd.push_back(info);

   struct epoll_event ev;
   /* add it to all the threads */
   for (auto i = 0u; threads.size() > i; ++i) {
      auto& t_info = threads[i];
      ev.events = EPOLLET | info->ev;
      ev.data.ptr = info;
      if (!t_info.inited) {
         continue;
      }	
      if (epoll_ctl(t_info.epollfd_pri[pri], EPOLL_CTL_ADD,
                    fd, &ev) == -1) {
         assert(0);
      }
      add_fd_to_thread(t_info, info->ev_fd[i],
                       [this] (int fd, void* cookie, uint32_t events)
                       { process_evfd(fd, cookie, events); },
                       EPOLLIN, 1, info);
   }
}

void
ioMgrImpl::add_local_fd(int fd, ev_callback cb, int iomgr_ev, int pri, void *cookie) {
   /* get local id */
   pthread_t t = pthread_self();
   thread_info *info = get_tid_info(t);

   add_fd_to_thread(*info, fd, cb, iomgr_ev, pri, cookie);
}

void 
ioMgrImpl::add_fd_to_thread(thread_info& t_info, int fd, ev_callback cb,
                        int iomgr_ev, int pri, void *cookie) {
   struct epoll_event ev;
   struct fd_info* info = new struct fd_info;
   std::unique_lock<std::mutex> lck(map_mtx);
   fd_info_map.insert(std::pair<int, fd_info*>(fd, info));

   info->cb = cb;
   info->is_running[fd_info::READ] = 0;
   info->is_running[fd_info::WRITE] = 0;
   info->fd = fd;
   info->ev = iomgr_ev;
   info->is_global = false;
   info->pri = pri;
   info->cookie = cookie;

   ev.events = EPOLLET | iomgr_ev;
   ev.data.ptr = info;
   if (epoll_ctl(t_info.epollfd_pri[pri], EPOLL_CTL_ADD,
                 fd, &ev) == -1) {
      assert(0);
   }
   LOGDEBUG("Added FD: {}", fd);
   return;
}

void 
ioMgrImpl::callback(void *data, uint32_t event) {
   struct fd_info *info = (struct fd_info *)data;
   info->cb(info->fd, info->cookie, event);
}

bool
ioMgrImpl::can_process(void *data, uint32_t ev) {
   struct fd_info *info = (struct fd_info *)data;
   int expected = 0;
   int desired = 1;
   bool ret = false;
   if (ev & EPOLLIN) {
      ret = info->is_running[fd_info::READ].compare_exchange_strong(expected, desired, 
                                                           std::memory_order_acquire, 
                                                           std::memory_order_acquire);
   } else if (ev & EPOLLOUT) {
      ret = info->is_running[fd_info::WRITE].compare_exchange_strong(expected, desired, 
                                                            std::memory_order_acquire, 
                                                            std::memory_order_acquire);
   } else if (ev & EPOLLERR || ev & EPOLLHUP) {
      LOGCRITICAL("Received EPOLLERR or EPOLLHUP without other event: {}!", ev);
      assert(0);
   } else {
      LOGCRITICAL("Unknown event: {}", ev);
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
ioMgrImpl::fd_reschedule(int fd, uint32_t event) {
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

   for(auto i = 0u; threads.size() > i; ++i) {
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
ioMgrImpl::process_evfd(int fd, void *data, uint32_t event) {
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
ioMgrImpl::process_done(int fd, int ev) {
   std::map<int, fd_info*>::iterator it;
   it = fd_info_map.find(fd);
   assert(it->first == fd);

   struct fd_info *info = it->second;

   process_done_impl(info, ev);
}

void 
ioMgrImpl::process_done_impl(void *data, int ev) {
   struct fd_info *info = (struct fd_info *)data;
   if (ev & EPOLLIN) {
      info->is_running[fd_info::READ].fetch_sub(1, std::memory_order_release);
   } else if (ev & EPOLLOUT) {
      info->is_running[fd_info::WRITE].fetch_sub(1, std::memory_order_release);
   } else {
      assert(0);
   }
}

struct thread_info * 
ioMgrImpl::get_tid_info(pthread_t &tid) {
   for (auto& t_info: threads) {
      if (t_info.tid == tid) {
         return &t_info;
      }
   }
   assert(0);
   return nullptr;
}

void
ioMgrImpl::print_perf_cntrs() {
   for(auto i = 0u; threads.size() > i; ++i) {
      LOGINFO("\n\tthread {} counters.\n\tnumber of times {} it run\n\ttotal time spent {}ms",
              i,
              threads[i].count,
              (threads[i].time_spent_ns/(1000 * 1000)));
   }
   for(auto const& ep : ep_list) {
      ep->print_perf();
   }
}

} /* iomgr */ 
