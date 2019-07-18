//
// Created by Kadayam, Hari on 07/10/17.
//
#ifndef OMSTORAGE_USEFUL_DEFS_HPP
#define OMSTORAGE_USEFUL_DEFS_HPP

#include <chrono>
#include <atomic>
#include <iostream>
#include <array>

#if defined __GNUC__ || defined __llvm__
#define hs_likely(x) __builtin_expect(!!(x), 1)
#define hs_unlikely(x) __builtin_expect(!!(x), 0)
#else
#define hs_likely(x) (x)
#define hs_unlikely(x) (x)
#endif

#define HOMESTORE_LOG_MODS                                                                                             \
    btree_structures, btree_nodes, btree_generics, cache, cache_vmod_evict, cache_vmod_write, device, httpserver_lmod, \
        iomgr, varsize_blk_alloc, VMOD_VOL_MAPPING, volume, blk_read_tracker

using Clock = std::chrono::steady_clock;
#define CURRENT_CLOCK(name) Clock::time_point name = Clock::now()

inline uint64_t get_elapsed_time_ns(Clock::time_point t) {
    std::chrono::nanoseconds ns = std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() - t);
    return ns.count();
}

inline uint64_t get_elapsed_time_ms(Clock::time_point t) { return get_elapsed_time_ns(t) / (1000 * 1000); }
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

template <typename T>
void atomic_update_max(std::atomic<T>& max_value, T const& value,
                       std::memory_order order = std::memory_order_acq_rel) noexcept {
    T prev_value = max_value.load(order);
    while (prev_value < value && !max_value.compare_exchange_weak(prev_value, value, order))
        ;
}

template <typename T>
void atomic_update_min(std::atomic<T>& min_value, T const& value,
                       std::memory_order order = std::memory_order_acq_rel) noexcept {
    T prev_value = min_value.load(order);
    while (prev_value > value && !min_value.compare_exchange_weak(prev_value, value, order))
        ;
}

namespace homeds {

template<unsigned... Is> struct seq{};
template<unsigned N, unsigned... Is>
struct gen_seq : gen_seq<N-1, N-1, Is...>{};
template<unsigned... Is>
struct gen_seq<0, Is...> : seq<Is...>{};

template<unsigned N1, unsigned... I1, unsigned N2, unsigned... I2>
constexpr std::array<char const, N1+N2-1> const_concat(char const (&a1)[N1], char const (&a2)[N2], seq<I1...>, seq<I2...>){
    return {{ a1[I1]..., a2[I2]... }};
}

template<unsigned N1, unsigned N2>
constexpr std::array<char const, N1+N2-1> const_concat(char const (&a1)[N1], char const (&a2)[N2]){
    return const_concat(a1, a2, gen_seq<N1-1>{}, gen_seq<N2>{});
}

#define const_concat_string(s1, s2) (&(const_concat(s1, s2)[0]))

template< class P, class M >
inline size_t offset_of(const M P::*member) {
    return (size_t) &(reinterpret_cast<P*>(0)->*member);
}

template< class P, class M >
inline P *container_of(const M *ptr, const M P::*member) {
    return (P *) ((char *) ptr - offset_of(member));
}

template<uint32_t bits, uint32_t lshifts=0>
static uint64_t constexpr get_mask() {
    return uint64_t(~((uint64_t)(-1)<<bits)<<lshifts);
}

template <int S>
struct LeftShifts {
    constexpr LeftShifts() : values() {
        for (auto i = 0; i != 256; ++i) {
            values[i] = i<<S;
        }
    }

    int values[256];
};

static constexpr int64_t pow(int base, uint32_t exp) {
    int64_t val = 1;
    for (auto i = 0u; i < exp; i++) {
        val *= base;
    }
    return val;
}

template <typename T>
static int spaceship_oper(const T &left, const T& right) {
    if (left == right) {
        return 0;
    } else if (left > right) {
        return -1;
    } else {
        return 1;
    }
}

} // namespace homeds
#endif //OMSTORAGE_USEFUL_DEFS_HPP
