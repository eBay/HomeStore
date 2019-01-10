#pragma once

#include "thread_safe_queue.h"

#include <algorithm>
#include <atomic>
#include <functional>
#include <future>
#include <memory>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace homestore {
class ThreadPool {
#define MAX_NUM_CONCURRENT_THREADS                     8    // TODO: Make this value configurable
#define HIGH_WATERMARK_FACTOR                          4 
  private:
    class ThrdTaskBase {
      public:
        ThrdTaskBase(void) = default;
        virtual ~ThrdTaskBase(void) = default;
        ThrdTaskBase(const ThrdTaskBase& rhs) = delete;
        ThrdTaskBase& operator=(const ThrdTaskBase& rhs) = delete;
        ThrdTaskBase(ThrdTaskBase&& other) = default;
        ThrdTaskBase& operator=(ThrdTaskBase&& other) = default;

        // Execute the task.
        virtual void execute() = 0;
    };

    template <typename TaskFunc>
    class ThrdTask: public ThrdTaskBase {
      public:
        ThrdTask(TaskFunc&& func)
            :m_func{std::move(func)} {
        }

        ~ThrdTask(void) override = default;
        ThrdTask(const ThrdTask& rhs) = delete;
        ThrdTask& operator=(const ThrdTask& rhs) = delete;
        ThrdTask(ThrdTask&& other) = default;
        ThrdTask& operator=(ThrdTask&& other) = default;

        // Execute the task
        void execute() override {
            m_func();
        }

      private:
        TaskFunc m_func;
    };

  public:
    //
    // A wrapper around a std::future that adds the behavior of futures returned from std::async.
    // Specifically, this object will block and wait for execution to finish before going out of scope.
    //
    template <typename T>
    class TaskFuture {
      public:
        TaskFuture(std::future<T>&& future)
            :m_future{std::move(future)} {
        }

        TaskFuture(const TaskFuture& rhs) = delete;
        TaskFuture& operator=(const TaskFuture& rhs) = delete;
        TaskFuture(TaskFuture&& other) = default;
        TaskFuture& operator=(TaskFuture&& other) = default;
        ~TaskFuture(void) {
            if(m_future.valid()) {
                m_future.get();
            }
        }

        auto get(void) {
            return m_future.get();
        }

      private:
        std::future<T> m_future;
    };

  public:
    explicit ThreadPool(const std::uint32_t num_threads)
        :m_done{false},
         m_work_queue{},
         m_threads{} {
        for(std::uint32_t i = 0u; i < num_threads; ++i) {
            m_threads.emplace_back(&ThreadPool::worker, this);
        }
    }

    // Non-copyable.
    ThreadPool(const ThreadPool& rhs) = delete;

    // Non-assignable.
    ThreadPool& operator=(const ThreadPool& rhs) = delete;

    ~ThreadPool(void) {
        m_done = true;
        m_work_queue.invalidate();
        for(auto& thread : m_threads) {
            if(thread.joinable()) {
                thread.join();
            }
        }
    }

    // Submit a job to be run by the thread pool.
    template <typename TaskFunc, typename... Args>
    auto submit(TaskFunc&& func, Args&&... args) {
        auto task = std::bind(std::forward<TaskFunc>(func), std::forward<Args>(args)...);
        using ResultT = std::result_of_t<decltype(task)()>;
        using PTask = std::packaged_task<ResultT()>;

        PTask ptask{std::move(task)};
        TaskFuture<ResultT> result{ptask.get_future()};
        m_work_queue.push(std::make_unique<ThrdTask<PTask>>(std::move(ptask)));
        return result;
    }
    
    bool high_watermark() {
        if (m_work_queue.size() >= HIGH_WATERMARK_FACTOR * MAX_NUM_CONCURRENT_THREADS)   
            return true;
        else
            return false;
    }

  private:
    // Constantly running function each thread uses to acquire work items from the queue.
    void worker(void) {
        while(!m_done) {
            std::unique_ptr<ThrdTaskBase> pTask{nullptr};
            if(m_work_queue.wait_pop(pTask)) {
                pTask->execute();
            }
        }
    }

  private:
    std::atomic<bool>                               m_done;
    ThreadSafeQueue<std::unique_ptr<ThrdTaskBase>>  m_work_queue;
    std::vector<std::thread>                        m_threads;
};

//
// TODO: Make thread pool per-homestore or per-homestore-sub-component?
// e.g.
//      Volume deletion could have one thread pool and
//      BlkAllocator could also have another thread pool
// Or
// Have one thread pool hs wide to serve different needs across hs sub-components.
//
inline ThreadPool& get_thread_pool(std::uint32_t num_threads = MAX_NUM_CONCURRENT_THREADS) {
    static ThreadPool default_pool(num_threads);
    return default_pool;
}

// Submit a job to the default thread pool.
template <typename TaskFunc, typename... Args>
inline auto submit_job(TaskFunc&& func, Args&&... args) {
    // TODO: Make thread number configurable during bootup
    return get_thread_pool(MAX_NUM_CONCURRENT_THREADS).submit(std::forward<TaskFunc>(func), std::forward<Args>(args)...);
}
}
