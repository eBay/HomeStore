//
// Created by Kadayam, Hari on 07/10/17.
//
#ifndef OMSTORAGE_USEFUL_DEFS_HPP
#define OMSTORAGE_USEFUL_DEFS_HPP

#include <chrono>

#if defined __GNUC__ || defined __llvm__
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#else
#define likely(x) (x)
#define unlikely(x) (x)
#endif

typedef std::chrono::high_resolution_clock Clock;
namespace omds {

inline uint64_t get_elapsed_time_ns(Clock::time_point t) {
    std::chrono::nanoseconds ns = std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() - t);
    return ns.count();
}

inline uint64_t get_elapsed_time_us(Clock::time_point t) { return get_elapsed_time_ns(t) / 1000; }

inline uint64_t get_elapsed_time_ns(Clock::time_point t1, Clock::time_point t2) {
    std::chrono::nanoseconds ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1);
    return ns.count();
}

inline uint64_t get_elapsed_time_us(Clock::time_point t1, Clock::time_point t2) {
    return get_elapsed_time_ns(t1, t2) / 1000;
}

inline uint64_t get_time_since_epoch_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();
}

inline uint64_t get_elapsed_time_ms(uint64_t t) { return get_time_since_epoch_ms() - t; }

template< class P, class M >
inline size_t offset_of(const M P::*member) {
    return (size_t) &(reinterpret_cast<P*>(0)->*member);
}

template< class P, class M >
inline P *container_of(M *ptr, const M P::*member) {
    return (P *) ((char *) ptr - offset_of(member));
}

struct blob {
    uint8_t *bytes;
    uint32_t size;
};

} // namespace omds
#endif //OMSTORAGE_USEFUL_DEFS_HPP
