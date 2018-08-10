//
// Created by Rishabh Mittal on 04/20/2018
//
#pragma once

#include <memory>
#include <functional>

namespace iomgr {

struct ioMgr;
struct ioMgrImpl;
using ev_callback = std::function<void(int fd, void *cookie, uint32_t events)>;

class EndPoint {
 protected:
   ioMgr *iomgr;

 public:
   explicit EndPoint(ioMgr* iomgr) : iomgr(iomgr) {}
   virtual ~EndPoint() = default;

   virtual void init_local() = 0;
   virtual void print_perf() = 0;
};

struct ioMgr {
   ioMgr(size_t const num_ep, size_t const num_threads);
   ~ioMgr();

   void start();
   void add_ep(EndPoint *ep);
   void add_fd(int const fd, ev_callback cb, int const ev, int const pri, void *cookie);
   void add_local_fd(int const fd, ev_callback cb, int const ev, int const pri, void *cookie);
   void print_perf_cntrs();
   void fd_reschedule(int const fd, uint32_t const event);
   void process_done(int const fd, int const ev);

 private:
   std::shared_ptr<ioMgrImpl> _impl;
};

} /* iomgr */
