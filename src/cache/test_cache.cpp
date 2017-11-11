//
// Created by Kadayam, Hari on 28/10/17.
//

//
// Created by Kadayam, Hari on 24/10/17.
//

#include <iostream>
#include <glog/logging.h>
#include <benchmark/benchmark.h>
#include <boost/range/irange.hpp>
#include <boost/intrusive_ptr.hpp>
#include "cache.cpp"

using namespace std;

#define TEST_COUNT         100000U
#define ITERATIONS         100U
#define THREADS            8U
//#define THREADS            4U

#define MAX_CACHE_SIZE     2 * 1024 * 1024 * 1024

struct blk_id {
    static omds::blob get_blob(const blk_id &id) {
        omds::blob b;
        b.bytes = (uint8_t *)&id.m_id;
        b.size = sizeof(uint64_t);

        return b;
    }

    static int compare(const blk_id &one, const blk_id &two) {
        if (one.m_id == two.m_id) {
            return 0;
        } else if (one.m_id > two.m_id) {
            return -1;
        } else {
            return 1;
        }
    }

    blk_id(uint64_t id) : m_id(id) {}
    blk_id() : blk_id(-1) {}
    blk_id(const blk_id &other) {
        m_id = other.m_id;
    }

    blk_id &operator=(const blk_id &other) {
        m_id = other.m_id;
        return *this;
    }
    uint64_t m_id;
};

omstore::Cache< blk_id > *glob_cache;
char **glob_bufs;
blk_id **glob_ids;

#if 0
void temp() {
    omstore::CacheBuffer< blk_id > *buf;
    omstore::intrusive_ptr_release(buf);
}
#endif

void setup(int count) {
    glob_cache = new omstore::Cache< blk_id >(MAX_CACHE_SIZE, 8192);
    glob_ids =  new blk_id*[count];
    glob_bufs = new char*[count];

    for (auto i : boost::irange(0, count)) {
        glob_ids[i] = new blk_id(i);
        glob_bufs[i] = new char[64];
        sprintf(glob_bufs[i], "Content for blk id = %d\n", i);
    }
}

//template <class ...Args>
//void benchmarked_insert(benchmark::State& state, Args&&... args) {
void test_insert(benchmark::State& state) {
    // Actual test
    for (auto _ : state) { // Loops upto iteration count
        auto index = state.thread_index;
        for (auto i = index; i < state.range(0); i+=state.threads) { // Loops for provided ranges
            boost::intrusive_ptr< omstore::CacheBuffer< blk_id> > cbuf;
            glob_cache->insert(*glob_ids[i], {(uint8_t *)glob_bufs[i], 64}, &cbuf);
        }
    }
}

void test_reads(benchmark::State& state) {
    // Actual test
    for (auto _ : state) { // Loops upto iteration count
        auto index = state.thread_index;
        for (auto i = index; i < state.range(0); i+=state.threads) { // Loops for provided ranges
            boost::intrusive_ptr< omstore::CacheBuffer< blk_id > > cbuf;
            bool found = glob_cache->get(*glob_ids[i], &cbuf);
#ifndef NDEBUG
            assert(found);
            int id;
            omds::blob b;
            cbuf->get(&b);
            sscanf((const char *)b.bytes, "Content for blk id = %d\n", &id);
            assert(id == glob_ids[i]->m_internal_id);
#endif
        }
    }
}

BENCHMARK(test_insert)->Range(TEST_COUNT, TEST_COUNT)->Iterations(ITERATIONS)->Threads(THREADS);
BENCHMARK(test_reads)->Range(TEST_COUNT, TEST_COUNT)->Iterations(ITERATIONS)->Threads(THREADS);

int main(int argc, char** argv)
{
    setup(TEST_COUNT * THREADS);
    ::benchmark::Initialize(&argc, argv);
    ::benchmark::RunSpecifiedBenchmarks();
}