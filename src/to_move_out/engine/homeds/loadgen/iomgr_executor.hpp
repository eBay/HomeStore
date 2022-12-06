#pragma once

#include <atomic>
#include <cstdint>
#include <functional>

#include <folly/MPMCQueue.h>
#include <iomgr/io_environment.hpp>

namespace homeds {
namespace loadgen {

class IOMgrExecutor {
    typedef std::function< void() > callback_t;

public:
    // Create a bounded lock protected queue.
    IOMgrExecutor(const size_t num_threads, const size_t num_priorities, const uint32_t max_queue_size);
    IOMgrExecutor(const IOMgrExecutor&) = delete;
    IOMgrExecutor& operator=(const IOMgrExecutor&) = delete;
    IOMgrExecutor(IOMgrExecutor&&) noexcept = delete;
    IOMgrExecutor& operator=(IOMgrExecutor&&) noexcept = delete;
    ~IOMgrExecutor();

    // Queues this function to execute in other thread and return back.
    // If the num_entries in queue > size given in max_queue_size, block and wait until queue becomes less.
    // IOMgr thread should dequeue the requests and start executing.
    void add(callback_t done_cb);
    bool is_empty() const;
    void stop(const bool wait_io_complete = true);

private:
    // void process_ev_callback(const int fd, const void* cookie, const int event);
    void handle_iothread_msg(const iomgr::iomgr_msg& msg);
    void process_new_request();
    bool is_running() const;
    void start();

private:
    folly::MPMCQueue< callback_t, std::atomic, true > m_cq;
    // int m_ev_fd;
    // std::shared_ptr< iomgr::fd_info > m_ev_fdinfo = nullptr;
    std::atomic< bool > m_running;
    std::atomic< uint64_t > m_read_cnt;
    std::atomic< uint64_t > m_write_cnt;
};

} // namespace loadgen
} // namespace homeds
