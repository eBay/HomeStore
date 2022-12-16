/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 * Author/Developer(s): Yaming Kuang
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 *********************************************************************************/
#include <chrono>
#include <thread>

#ifdef __linux__
#include <sys/epoll.h>
#include <sys/eventfd.h>
#endif

#include <iomgr/aio_drive_interface.hpp>
#include <sisl/logging/logging.h>

#include "iomgr_executor.hpp"

namespace homeds {
namespace loadgen {

IOMgrExecutor::IOMgrExecutor(const size_t num_threads, const size_t num_priorities, const uint32_t max_queue_size) :
        m_cq{max_queue_size}, m_running{false}, m_read_cnt{0}, m_write_cnt{0} {
    // m_ev_fd = eventfd(0, EFD_NONBLOCK);

    // exec start should be called before iomgr->start
    start();
    ioenvironment.with_iomgr(num_threads);
}

// It is called everytime a loadgen test case finishes;
IOMgrExecutor::~IOMgrExecutor() {
    //
    // m_ep will be deleted by iomgr
    //
    // put iomgr's stop here (instead of IOMgrExecutor::stop) so that
    // executor could be restarted after a IOMgrExecutor::stop();
    if (m_running.load()) { stop(true); }
    // if (m_ev_fdinfo) iomanager.remove_fd(iomanager.default_drive_interface(), m_ev_fdinfo);
    iomanager.stop();
}

bool IOMgrExecutor::is_empty() const { return m_cq.isEmpty(); }

bool IOMgrExecutor::is_running() const { return m_running.load(std::memory_order_relaxed); }

void IOMgrExecutor::process_new_request() {
    m_read_cnt.fetch_add(1, std::memory_order_relaxed);
    if (!m_running.load(std::memory_order_relaxed)) {
        m_read_cnt.fetch_sub(1, std::memory_order_relaxed);
        LOGINFO("{}, not running, exit...", __FUNCTION__);
        return;
    }

    callback_t cb;
    if (m_cq.read(cb)) { cb(); }
}

//
// 1. Set running to false;
// 2. Wake up any I/O threads blocking on read
//
void IOMgrExecutor::stop(bool wait_io_complete) {
    while (wait_io_complete && (m_write_cnt > m_read_cnt) && !m_cq.isEmpty()) {
        // wait for I/O threads to finish consuming all the elements in queue;
        LOGDEBUG("wait... read:{} , write: {}", m_read_cnt, m_write_cnt);
        std::this_thread::sleep_for(std::chrono::seconds{2});
    }

    std::this_thread::sleep_for(std::chrono::seconds{2});
    m_running.store(false, std::memory_order_relaxed);

#if 0
    if (m_write_cnt >= m_read_cnt) {
        // no I/O threads are blocking on read;
        return;
    }

    auto t = m_read_cnt - m_write_cnt;
    // if t > 0, means we have t blocking read threads that needs to be wake up,
    // so that these threads can exit callback and do epoll_wait again;
    // We need to do this so that iomgr can be triggered for shutdown;
    while (t > 0) {
        // assert(m_cq.isEmpty());
        // reschedule event so that I/O threads can exit block reading;
        // m_cq.blockingWrite([=] {});
        // t--;
        iomanager.run_on(iomgr::thread_regex::least_busy_io, [this]() { process_new_request(); });
    }
#endif
}

void IOMgrExecutor::start() { m_running.store(true, std::memory_order_relaxed); }

void IOMgrExecutor::add(callback_t done_cb) {
    // we do not handle add request after stop() has been called;
    assert(is_running());
    m_cq.blockingWrite(std::move(done_cb));
    m_write_cnt.fetch_add(1, std::memory_order_relaxed);

    iomanager.run_on(iomgr::thread_regex::least_busy_worker,
                     [this](iomgr::io_thread_addr_t addr) { process_new_request(); });
}
} // namespace loadgen
} // namespace homeds
