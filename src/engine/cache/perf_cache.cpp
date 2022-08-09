//
// Created by Kadayam, Hari on 28/10/17.
//

//
// Created by Kadayam, Hari on 24/10/17.
//

#include <cstdint>
#include <cstdio>
#include <functional>
#include <iostream>
#include <limits>
#include <string>
#include <sstream>

#include <benchmark/benchmark.h>
#include <boost/intrusive_ptr.hpp>
#include <boost/range/irange.hpp>
#include <sisl/logging/logging.h>
#include <sisl/options/options.h>

#include "cache.h"

SISL_LOGGING_INIT(HOMESTORE_LOG_MODS)
RCU_REGISTER_INIT

static constexpr size_t TEST_COUNT{100000};
static constexpr size_t ITERATIONS{10}; // doing more than one iteration will free memory that was freed before
static constexpr size_t THREADS{4};
static constexpr uint64_t MAX_CACHE_SIZE{static_cast< uint64_t >(2) * 1024 * 1024};

struct blk_id {
    [[nodiscard]] static int compare(const blk_id& one, const blk_id& two) {
        if (one.m_id == two.m_id) {
            return 0;
        } else if (one.m_id > two.m_id) {
            return -1;
        } else {
            return 1;
        }
    }

    blk_id(const uint64_t id) : m_id{id} {}
    blk_id() : blk_id{std::numeric_limits< uint64_t >::max()} {}
    blk_id(const blk_id& other) { m_id = other.m_id; }

    blk_id& operator=(const blk_id& other) {
        m_id = other.m_id;
        return *this;
    }

    [[nodiscard]] std::string to_string() const {
        std::ostringstream ss;
        ss << m_id;
        return ss.str();
    }
    uint64_t m_id;
};

namespace std {
template <>
struct hash< blk_id > {
    typedef blk_id argument_type;
    typedef size_t result_type;
    [[nodiscard]] result_type operator()(const argument_type& bid) const noexcept {
        return std::hash< uint64_t >()(bid.m_id);
    }
};
} // namespace std

typedef homestore::Cache< blk_id, homestore::CacheBuffer< blk_id > > CacheType;
static CacheType* glob_cache;
static char **glob_bufs1, **glob_bufs2;
static blk_id** glob_ids;

void setup(const uint64_t count) {
    glob_cache = new CacheType{MAX_CACHE_SIZE, 8192};
    glob_ids = new blk_id*[count];
    glob_bufs1 = new char*[count];
    glob_bufs2 = new char*[count];

    for (const auto i : boost::irange< uint64_t >(0, count)) {
        glob_ids[i] = new blk_id{i};
        // this must be a std::malloc since the pointer is managed by the cache and later erased with std::free
        glob_bufs1[i] = static_cast< char* >(std::malloc(8192));
        glob_bufs2[i] = static_cast< char* >(std::malloc(8192));
        std::snprintf(glob_bufs1[i], 8192, "Content for blk id = %" PRIu64 "\n", i);
        std::snprintf(glob_bufs2[i], 8192, "Update Content for blk id = %" PRIu64 "\n", i);
    }
}

void teardown(const uint64_t count) {
    for (const auto i : boost::irange< uint64_t >(0, count)) {
        // glob_bufs are cleaned up during erase of cache entry
        // delete[] glob_bufs[i];
        delete glob_ids[i];
    }

    delete[] glob_bufs1;
    delete[] glob_bufs2;
    delete[] glob_ids;
    delete glob_cache;
}

// template <class ...Args>
// void benchmarked_insert(benchmark::State& state, Args&&... args) {
void test_insert(benchmark::State& state) {
    // Actual test
    size_t iteration{0};
    for (auto cs : state) { // Loops upto iteration count
        const size_t index{static_cast< size_t >(state.thread_index)};
        // LOG(INFO) << "Will insert " << index << " - " << state.range(0) << " entries in this thread";
        for (auto i{index + iteration * state.range(0)}; i < (iteration + 1) * state.range(0);
             i += state.threads) { // Loops for provided ranges
            boost::intrusive_ptr< homestore::CacheBuffer< blk_id > > cbuf;
            glob_cache->insert(*glob_ids[i], {reinterpret_cast< uint8_t* >(glob_bufs1[i]), 8192}, 0, &cbuf);
            // LOG(INFO) << "Completed insert of index i = " << i;
        }
        ++iteration;
    }
}

void test_reads(benchmark::State& state) {
    // Actual test
    size_t iteration{0};
    for (auto cs : state) { // Loops upto iteration count
        const size_t index{static_cast< size_t >(state.thread_index)};
        for (auto i{index + iteration * state.range(0)}; i < (iteration + 1) * state.range(0);
             i += state.threads) { // Loops for provided ranges
            boost::intrusive_ptr< homestore::CacheBuffer< blk_id > > cbuf;
            [[maybe_unused]] const bool found{glob_cache->get(*glob_ids[i], &cbuf)};
#if 0
#ifndef NDEBUG
            assert(found);
            int id;
            sisl::blob b;
            cbuf->get(&b);
            sscanf((const char *)b.bytes, "Content for blk id = %d\n", &id);
            assert(id == glob_ids[i]->m_internal_id);
#endif
#endif
        }
        ++iteration;
    }
}

// replace all glob_bufs1 with glob_bufs2 through update
void test_updates(benchmark::State& state) {
    // Actual test
    size_t iteration{0};
    for (auto cs : state) { // Loops upto iteration count
        const size_t index{static_cast< size_t >(state.thread_index)};
        for (auto i{index + iteration * state.range(0)}; i < (iteration + 1) * state.range(0);
             i += state.threads) { // Loops for provided ranges
            boost::intrusive_ptr< homestore::CacheBuffer< blk_id > > cbuf;
            glob_cache->update(*glob_ids[i], {reinterpret_cast< uint8_t* >(glob_bufs2[i]), 8192}, 16384, &cbuf);
        }
        ++iteration;
    }
}

void test_erase(benchmark::State& state) {
    // Actual test
    size_t iteration{0};
    for (auto cs : state) { // Loops upto iteration count
        const size_t index{static_cast< size_t >(state.thread_index)};
        for (auto i{index + iteration * state.range(0)}; i < (iteration + 1) * state.range(0);
             i += state.threads) { // Loops for provided ranges
            boost::intrusive_ptr< homestore::CacheBuffer< blk_id > > cbuf;
            glob_cache->erase(*glob_ids[i], &cbuf);
        }
        ++iteration;
    }
}

BENCHMARK(test_insert)->Range(TEST_COUNT, TEST_COUNT)->Iterations(ITERATIONS)->Threads(THREADS);
BENCHMARK(test_reads)->Range(TEST_COUNT, TEST_COUNT)->Iterations(ITERATIONS)->Threads(THREADS);
BENCHMARK(test_updates)->Range(TEST_COUNT, TEST_COUNT)->Iterations(ITERATIONS)->Threads(THREADS);
BENCHMARK(test_erase)->Range(TEST_COUNT, TEST_COUNT)->Iterations(ITERATIONS)->Threads(THREADS);

SISL_OPTIONS_ENABLE(logging)

int main(int argc, char** argv) {
    SISL_OPTIONS_LOAD(argc, argv, logging)
    sisl::logging::SetLogger("perf_cache");
    sisl::logging::install_crash_handler();
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");
    setup(TEST_COUNT * ITERATIONS);
    ::benchmark::Initialize(&argc, argv);
    ::benchmark::RunSpecifiedBenchmarks();
    teardown(TEST_COUNT * ITERATIONS);
    return 0;
}
