#include "iomgr_executor.hpp"
#include <sys/epoll.h>
#include <sys/eventfd.h>

namespace homeds {
namespace loadgen {
#define likely(x)     __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

// TODO: move callback into loadgen endpoint
IOMgrExecutor::IOMgrExecutor(int num_threads, int num_priorities, uint32_t max_queue_size) : m_cq(max_queue_size) {
    m_running.store(false, std::memory_order_relaxed);
    // 1. initiate loadgen_ep
    m_ev_fd = eventfd(0, EFD_NONBLOCK);
    m_iomgr = std::make_shared<iomgr::ioMgr>(num_ep, num_threads);
    m_iomgr->add_fd(m_ev_fd, [this](auto fd, auto cookie, auto event) { process_ev_callback(fd, cookie, event); },
           EPOLLIN, 9, nullptr);
    m_ep = new LoadGenEP(m_iomgr);
    m_iomgr->add_ep(m_ep);
    m_iomgr->start();
    uint64_t temp = 1;
    [[maybe_unused]] auto wsize = write(m_ev_fd, &temp, sizeof(uint64_t));
}

IOMgrExecutor::~IOMgrExecutor() {
    delete m_ep;
    m_ep = nullptr;
}

bool 
IOMgrExecutor::is_running() const {
    return m_running.load(std::memory_order_relaxed);
}

void 
IOMgrExecutor::process_ev_callback(const int fd, const void* cookie, const int event) {
    if (unlikely(!is_running())) {
        return;
    }
    
    // trigger another event
    m_iomgr->fd_reschedule(fd, event);
    
    callback cb;
    m_cq.blockingRead(cb);
    cb();
}

void 
IOMgrExecutor::stop() {
    m_running.store(false, std::memory_order_relaxed);
}

void 
IOMgrExecutor::start() {
    m_running.store(true, std::memory_order_relaxed);
}

void 
IOMgrExecutor::add(callback done_cb) {
    m_cq.blockingWrite(std::move(done_cb));
}

}
}
