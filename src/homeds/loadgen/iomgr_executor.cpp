#include "iomgr_executor.hpp"
#include <iomgr/aio_drive_interface.hpp>
#include <sds_logging/logging.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <thread>
#include <chrono>

namespace homeds {
namespace loadgen {
#define likely(x) __builtin_expect((x), 1)
#define unlikely(x) __builtin_expect((x), 0)

IOMgrExecutor::IOMgrExecutor(int num_threads, int num_priorities, uint32_t max_queue_size) : m_cq(max_queue_size) {
    m_running.store(false, std::memory_order_relaxed);
    m_read_cnt = 0;
    m_write_cnt = 0;
    m_ev_fd = eventfd(0, EFD_NONBLOCK);

    iomanager.add_drive_interface(
        std::dynamic_pointer_cast< iomgr::DriveInterface >(std::make_shared< iomgr::AioDriveInterface >()),
        true /* is_default */);

    m_ev_fd = eventfd(0, EFD_NONBLOCK);
    m_ev_fdinfo = iomanager.add_fd(iomanager.default_drive_interface(), m_ev_fd,
                                   std::bind(&IOMgrExecutor::process_ev_callback, this, std::placeholders::_1,
                                             std::placeholders::_2, std::placeholders::_3),
                                   EPOLLIN, 9, nullptr);

#if 0
    m_iomgr = std::make_shared< iomgr::ioMgr >(num_ep, num_threads);
    m_iomgr->add_fd(
        m_ev_fd, [this](auto fd, auto cookie, auto event) { process_ev_callback(fd, cookie, event); }, EPOLLIN, 9,
        nullptr);
#endif

    // exec start should be called before iomgr->start
    start();
    iomanager.start(1 /* total interfaces */, num_threads);

    uint64_t temp = 1;
    std::this_thread::sleep_for(std::chrono::seconds(2));

    [[maybe_unused]] auto wsize = write(m_ev_fd, &temp, sizeof(uint64_t));
}

// It is called everytime a loadgen test case finishes;
IOMgrExecutor::~IOMgrExecutor() {
    //
    // m_ep will be deleted by iomgr
    //
    // put iomgr's stop here (instead of IOMgrExecutor::stop) so that
    // executor could be restarted after a IOMgrExecutor::stop();
    if (m_running.load()) { stop(true); }
    if (m_ev_fdinfo) iomanager.remove_fd(iomanager.default_drive_interface(), m_ev_fdinfo);
    iomanager.stop();
}

bool IOMgrExecutor::is_empty() { return m_cq.isEmpty(); }

bool IOMgrExecutor::is_running() const { return m_running.load(std::memory_order_relaxed); }

void IOMgrExecutor::process_ev_callback(const int fd, const void* cookie, const int event) {
    m_read_cnt.fetch_add(1, std::memory_order_relaxed);
    if (unlikely(!is_running())) {
        m_read_cnt.fetch_sub(1, std::memory_order_relaxed);
        LOGINFO("{}, not running, exit...", __FUNCTION__);
        return;
    }

    assert(fd == m_ev_fd);

    uint64_t temp;
    [[maybe_unused]] auto rsize = read(fd, &temp, sizeof(uint64_t));

    [[maybe_unused]] auto wsize = write(m_ev_fd, &temp, sizeof(uint64_t));

    callback_t cb;
    m_cq.blockingRead(cb);
    cb();
}

//
// 1. Set running to false;
// 2. Wake up any I/O threads blocking on read
//
void IOMgrExecutor::stop(bool wait_io_complete) {
    while (wait_io_complete && m_write_cnt > m_read_cnt && !m_cq.isEmpty()) {
        // wait for I/O threads to finish consuming all the elements in queue;
        LOGDEBUG("wait... read:{} , write: {}", m_read_cnt, m_write_cnt);
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    std::this_thread::sleep_for(std::chrono::seconds(2));
    m_running.store(false, std::memory_order_relaxed);

    if (m_write_cnt >= m_read_cnt) {
        // no I/O threads are blocking on read;
        return;
    }

    auto t = m_read_cnt - m_write_cnt;
    // if t > 0, means we have t blocking read threads that needs to be wake up,
    // so that these threads can exit callback and do epoll_wait again;
    // We need to do this so that iomgr can be triggered for shutdown;
    while (t > 0) {
        assert(m_cq.isEmpty());
        // reschedule event so that I/O threads can exit block reading;
        m_cq.blockingWrite([=] {});
        t--;
    }
}

void IOMgrExecutor::start() { m_running.store(true, std::memory_order_relaxed); }

void IOMgrExecutor::add(callback_t done_cb) {
    // we do not handle add request after stop() has been called;
    assert(is_running());
    m_cq.blockingWrite(std::move(done_cb));
    m_write_cnt.fetch_add(1, std::memory_order_relaxed);
}
} // namespace loadgen
} // namespace homeds
