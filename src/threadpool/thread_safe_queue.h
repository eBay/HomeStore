#pragma once

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <utility>

namespace homestore {
template <typename T>
class ThreadSafeQueue {
  public:
    ~ThreadSafeQueue(void) {
        invalidate();
    }

    //
    // Attempt to get the first value in the queue.
    // Returns true if a value was successfully written to the out parameter, false otherwise.
    //
    bool try_pop(T& out) {
        std::lock_guard<std::mutex> lock{m_mtx};
        if(m_queue.empty() || !m_valid) {
            return false;
        }
        out = std::move(m_queue.front());
        m_queue.pop();
        return true;
    }


    //
    // Get the first value in the queue.
    // Will block until a value is available unless clear is called or the instance is destructed.
    // Returns true if a value was successfully written to the out parameter, false otherwise.
    //
    bool wait_pop(T& out) {
        std::unique_lock<std::mutex> lock{m_mtx};
        m_cv.wait(lock, [this]() {
            return !m_queue.empty() || !m_valid;
        });
        if(!m_valid) {
            return false;
        }
        out = std::move(m_queue.front());
        m_queue.pop();
        return true;
    }


    // Push a new value onto the queue.
    void push(T value) {
        std::lock_guard<std::mutex> lock{m_mtx};
        m_queue.push(std::move(value));
        m_cv.notify_one();
    }

    // Check whether or not the queue is empty.
    bool empty(void) const {
        std::lock_guard<std::mutex> lock{m_mtx};
        return m_queue.empty();
    }

    uint64_t size() const {
        std::lock_guard<std::mutex> lock{m_mtx};
        return m_queue.size();
    }

    // Clear all items from the queue.
    void clear(void) {
        std::lock_guard<std::mutex> lock{m_mtx};
        while(!m_queue.empty()) {
            m_queue.pop();
        }
        m_cv.notify_all();
    }

    //
    // Invalidate the queue.
    // Used to ensure no conditions are being waited on in wait_pop when
    // a thread or the application is trying to exit.
    // The queue is invalid after calling this method and it is an error
    // to continue using a queue after this method has been called.
    //
    void invalidate(void) {
        std::lock_guard<std::mutex> lock{m_mtx};
        m_valid = false;
        m_cv.notify_all();
    }

    bool is_valid(void) const {
        std::lock_guard<std::mutex> lock{m_mtx};
        return m_valid;
    }

  private:
    std::atomic_bool            m_valid{true};
    // TODO: replace std::mutex with folly::shared_mutex
    mutable std::mutex          m_mtx;
    std::queue<T>               m_queue;
    std::condition_variable     m_cv;
};
}

