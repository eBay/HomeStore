#include "iomgr_impl.hpp"

namespace iomgr
{

ioMgr::ioMgr(size_t const num_ep, size_t const num_threads)
{ _impl = std::make_shared<ioMgrImpl>(num_ep, num_threads); }

ioMgr::~ioMgr() = default;

void ioMgr::start()
{_impl->start();}

void ioMgr::add_ep(EndPoint *ep)
{_impl->add_ep(ep);}

void ioMgr::add_fd(int const fd, ev_callback cb, int const ev, int const pri, void *cookie)
{_impl->add_fd(fd, cb, ev, pri, cookie);}

void ioMgr::add_local_fd(int const fd, ev_callback cb, int const ev, int const pri, void *cookie)
{_impl->add_local_fd(fd, cb, ev, pri, cookie);}

void ioMgr::print_perf_cntrs()
{_impl->print_perf_cntrs();}

void ioMgr::fd_reschedule(int const fd, uint32_t const event)
{_impl->fd_reschedule(fd, event);}

void ioMgr::process_done(int const fd, int const ev)
{_impl->process_done(fd, ev);}

} /* iomgr */ 
