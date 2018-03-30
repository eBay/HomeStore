//
// Created by Kadayam, Hari on 30/09/17.
//

#ifndef LIBUTILS_ATOMIC_COUNTER_HPP
#define LIBUTILS_ATOMIC_COUNTER_HPP

#include <assert.h>
namespace homeds {

template <typename T>
class atomic_counter
{
    static_assert(std::is_integral<T>::value, "atomic_counter needs integer");

public:
    atomic_counter() {
        m_count = {};
    }

    atomic_counter(T count) :
            m_count(count) {}

    T increment(int32_t n=1) {
        m_count.fetch_add(n, std::memory_order_relaxed);
        return m_count + 1;
    }

    T decrement(int32_t n=1) {
        T count = m_count.fetch_sub(n, std::memory_order_release);
        assert(count > 0);
        return count - 1;
    }

    bool decrement_testz(int32_t n=1) {
        T count = m_count.fetch_sub(n, std::memory_order_release);
        if (count == 1) {
            // Fence the memory to prevent from any release (decrement) getting reordered
            // before returning
            std::atomic_thread_fence(std::memory_order_acquire);
            return true;
        } else {
            assert(count > 0);
        }
        return false;
    }

    bool decrement_test_le(int32_t check, int32_t n=1) {
        T count = m_count.fetch_sub(n, std::memory_order_release);
        if (count <= (check+1)) {
            // Fence the memory to prevent from any release (decrement) getting reordered
            // before returning
            std::atomic_thread_fence(std::memory_order_acquire);
            return true;
        } else {
            assert(count > 0);
        }
        return false;
    }

    // This is not the most optimized version of testing, since it has to
    bool testz() {
        if (get() == 0) {
            std::atomic_thread_fence(std::memory_order_acquire);
            return true;
        }
        return false;
    }

    // This is not guaranteed to be 100% thread safe if we are using it
    // to check for 0. Use dec_testz for decrement and check or testz for
    // just checking for 0
    T get() const {
        return m_count.load(std::memory_order_relaxed);
    }

    void set(int32_t n) {
        m_count.store(n, std::memory_order_release);
    }
private:
    std::atomic<T> m_count;
};

}
#endif //LIBUTILS_ATOMIC_COUNTER_HPP
