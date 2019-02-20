/*
 * test_composite_allocator.cpp
 *
 *  Created on: 01-Sep-2017
 *      Author: hkadayam
 */

#include "homeds/memory/generic_freelist_allocator.hpp"
#include "homeds/memory/composite_allocator.hpp"
#include "homeds/memory/chunk_allocator.hpp"
#include "homeds/memory/sys_allocator.hpp"
#include "homeds/memory/freelist_allocator.hpp"
#include "homeds/utility/useful_defs.hpp"
#include <benchmark/benchmark.h>
#include <sds_logging/logging.h>
#include <sds_options/options.h>

#define TOTAL_ALLOCS 10000
#define ITERATIONS   100
#define THREADS      4

SDS_LOGGING_INIT(iomgr)
THREAD_BUFFER_INIT;

uint32_t glob_sizes[TOTAL_ALLOCS * THREADS];
uint8_t *glob_ptr[TOTAL_ALLOCS * THREADS];

#if 0
homeds::CompositeMemAllocator<
        //homeds::GenericFreelistAllocator< 1000, 15, 40, 128, 256 >,
        //homeds::ChunkMemAllocator< 512,  102400 >,
        //homeds::ChunkMemAllocator< 1024, 102400 >
        //homeds::ChunkMemAllocator< 2048, 102400 >,
        homeds::SysMemAllocator
> glob_sys_only_allocator;

homeds::CompositeMemAllocator<
        //homeds::GenericFreelistAllocator< 1000, 15, 40, 128, 256 >,
        homeds::ChunkMemAllocator< 512,  102400 >,
        homeds::ChunkMemAllocator< 1024, 102400 >,
        homeds::ChunkMemAllocator< 2048, 102400 >,
        homeds::SysMemAllocator
> glob_chunk_allocator;

homeds::CompositeMemAllocator<
        homeds::GenericFreelistAllocator< 1000, 15, 40, 128, 256 >,
        homeds::ChunkMemAllocator< 512,  102400 >,
        homeds::ChunkMemAllocator< 1024, 102400 >,
        homeds::ChunkMemAllocator< 2048, 102400 >,
        homeds::SysMemAllocator
> glob_free_and_chunk_allocator;
#endif

/*
homeds::CompositeMemAllocator<
        homeds::GenericFreelistAllocator< TOTAL_ALLOCS * THREADS, 2048 >,
        homeds::SysMemAllocator
> glob_generic_free_and_sys_allocator;
*/
homeds::ChunkMemAllocator< 2048, 2200 * TOTAL_ALLOCS * THREADS> glob_chunk_allocator;
homeds::GenericFreelistAllocator< TOTAL_ALLOCS * THREADS, 256 > glob_generic_free_and_sys_allocator;
homeds::FreeListAllocator< TOTAL_ALLOCS, 256 > glob_freelist_allocator;

void setup(uint32_t count) {
    for (auto i = 0u; i < count; i++) {
        if ((i % 16) == 0) {
            glob_sizes[i] = 15;
        } else if ((i % 12) == 0) {
            glob_sizes[i] = 128;
        } else if ((i % 8) == 0) {
            glob_sizes[i] = 40;
        } else if ((i % 4) == 0) {
            glob_sizes[i] = 256;
        } else {
            glob_sizes[i] = rand() % 32768;
        }
    }
}

extern void g() {}

void test_malloc(benchmark::State& state) {
    // Actual test
    for (auto _ : state) { // Loops upto iteration count
        auto index = state.thread_index;
        for (auto i = index; i < state.range(0); i+=THREADS) { // Loops for provided ranges
            benchmark::DoNotOptimize(glob_ptr[i] = (uint8_t *)malloc(glob_sizes[i]));
            glob_ptr[i][0] = 'a';
            g();
            //printf("glob_ptr[%d] = %p\n", i, glob_ptr[i]);
        }

        for (auto i = index; i < state.range(0); i+=THREADS) { // Loops for provided ranges
            free(glob_ptr[i]);
        }
    }
}

void test_chunk_allocator(benchmark::State& state) {
    // Actual test
    for (auto _ : state) { // Loops upto iteration count
        auto index = state.thread_index;
        for (auto i = index; i < state.range(0); i+=THREADS) { // Loops for provided ranges
            benchmark::DoNotOptimize(glob_ptr[i] = glob_chunk_allocator.allocate(glob_sizes[i], nullptr, nullptr));
            glob_ptr[i][0] = 'a';
            g();
        }

        for (auto i = index; i < state.range(0); i+=THREADS) { // Loops for provided ranges
            glob_chunk_allocator.deallocate(glob_ptr[i], glob_sizes[i]);
        }
    }
}

void test_generic_freelist_allocator(benchmark::State &state) {
    // Actual test
    for (auto _ : state) { // Loops upto iteration count
        auto index = state.thread_index;
        for (auto i = index; i < state.range(0); i+=THREADS) { // Loops for provided ranges
            benchmark::DoNotOptimize(glob_ptr[i] = glob_generic_free_and_sys_allocator.allocate(256, nullptr, nullptr));
            glob_ptr[i][0] = 'a';
            g();
        }

        for (auto i = index; i < state.range(0); i+=THREADS) { // Loops for provided ranges
            glob_generic_free_and_sys_allocator.deallocate(glob_ptr[i], 256);
        }
    }
}

void test_freelist_allocator(benchmark::State &state) {
    // Actual test
    for (auto _ : state) { // Loops upto iteration count
        auto index = state.thread_index;
        for (auto i = index; i < state.range(0); i+=THREADS) { // Loops for provided ranges
            benchmark::DoNotOptimize(glob_ptr[i] = glob_freelist_allocator.allocate(256));
            glob_ptr[i][0] = 'a';
            g();
        }

        for (auto i = index; i < state.range(0); i+=THREADS) { // Loops for provided ranges
            glob_freelist_allocator.deallocate(glob_ptr[i], 256);
        }
    }
}

void test_combo_allocator(benchmark::State& state) {
    // Actual test
    for (auto _ : state) { // Loops upto iteration count
        auto index = state.thread_index;
        for (auto i = index; i < state.range(0); i+=THREADS) { // Loops for provided ranges
            if (glob_sizes[i] == 256) {
                benchmark::DoNotOptimize(glob_ptr[i] = glob_freelist_allocator.allocate(256));
            } else {
                benchmark::DoNotOptimize(glob_ptr[i] = (uint8_t *)malloc(glob_sizes[i]));
            }
            glob_ptr[i][0] = 'a';
            g();
        }

        for (auto i = index; i < state.range(0); i+=THREADS) { // Loops for provided ranges
            if (glob_sizes[i] == 256) {
                glob_freelist_allocator.deallocate(glob_ptr[i], 256);
            } else {
                free(glob_ptr[i]);
            }
        }
    }
}
#if 0
void test_free(benchmark::State& state) {
    // Actual test
    for (auto _ : state) { // Loops upto iteration count
        auto index = state.thread_index;
        for (auto i = index; i < state.range(0); i+=THREADS) { // Loops for provided ranges
            //benchmark::DoNotOptimize(free(glob_ptr[i]));
            free(glob_ptr[i]);
        }
    }
}
#endif

void test_sys_only_allocator(benchmark::State& state) {
    // Actual test
    for (auto _ : state) { // Loops upto iteration count
        auto index = state.thread_index;
        for (auto i = 0U; i < state.range(0); i+=THREADS) { // Loops for provided ranges
            benchmark::DoNotOptimize(glob_ptr[i] = (uint8_t *) malloc(glob_sizes[i]));
        }
    }
}

#if 0
int main(int argc, char *argv[]) {

#if 0
    homeds::CompositeMemAllocator<
        //homeds::GenericFreelistAllocator< 1000, 15, 40, 128, 256 >,
        //homeds::ChunkMemAllocator< 512,  102400 >,
        //homeds::ChunkMemAllocator< 1024, 102400 >
        //homeds::ChunkMemAllocator< 2048, 102400 >,
        homeds::SysMemAllocator
    > allocator1;
#endif

    //homeds::ChunkMemAllocator< 2048, 102400 > allocator1;
    homeds::SysMemAllocator allocator1;
    uint8_t *meta_blk;

    uint32_t sizes[TOTAL_ALLOCS];

    for (auto i = 0; i < TOTAL_ALLOCS; i++) {
        if ((i % 16) == 0) {
            sizes[i] = 256;
        } else if ((i % 12) == 0) {
            sizes[i] = 128;
        } else if ((i % 8) == 0) {
            sizes[i] = 40;
        } else if ((i % 4) == 0) {
            sizes[i] = 15;
        } else {
            sizes[i] = rand() % 2000;
        }
    }

    uint64_t alloc_time_ns, dealloc_time_ns;

    alloc_time_ns = 0; dealloc_time_ns = 0;
    for (auto i = 0; i < TOTAL_ALLOCS; i++) {
        Clock::time_point t1 = Clock::now();
        uint8_t *ptr = (uint8_t *)malloc(sizes[i]);
        alloc_time_ns += homeds::get_elapsed_time_ns(t1);

        //printf("Allocated ptr = %p, meta_blk = %p\n", ptr, meta_blk);
        Clock::time_point t2 = Clock::now();
        free(ptr);
        dealloc_time_ns += homeds::get_elapsed_time_ns(t2);
    }
    std::cout << "Malloc/free    : For " << TOTAL_ALLOCS << " allocs, alloc_time = " << alloc_time_ns << " ns, avg = "
              << alloc_time_ns/TOTAL_ALLOCS << " dealloc_time = " << dealloc_time_ns << " ns avg = "
              << dealloc_time_ns/TOTAL_ALLOCS << "\n";

    alloc_time_ns = 0; dealloc_time_ns = 0;
    for (auto i = 0; i < TOTAL_ALLOCS; i++) {
        Clock::time_point t1 = Clock::now();
        uint8_t *ptr = allocator1.allocate(sizes[i], &meta_blk);
        alloc_time_ns += homeds::get_elapsed_time_ns(t1);

        //printf("Allocated ptr = %p, meta_blk = %p\n", ptr, meta_blk);
        Clock::time_point t2 = Clock::now();
        allocator1.deallocate(ptr, sizes[i]);
        dealloc_time_ns += homeds::get_elapsed_time_ns(t2);
    }
    std::cout << "CustomAllocator: For " << TOTAL_ALLOCS << " allocs, alloc_time = " << alloc_time_ns << " ns, avg = "
              << alloc_time_ns/TOTAL_ALLOCS << " dealloc_time = " << dealloc_time_ns << " ns avg = "
              << dealloc_time_ns/TOTAL_ALLOCS << "\n";
}
#endif

//BENCHMARK(test_chunk_allocator)->Range(TOTAL_ALLOCS, TOTAL_ALLOCS)->Iterations(ITERATIONS)->Threads(THREADS);
BENCHMARK(test_malloc)->Range(TOTAL_ALLOCS, TOTAL_ALLOCS)->Iterations(ITERATIONS)->Threads(THREADS);
BENCHMARK(test_combo_allocator)->Range(TOTAL_ALLOCS, TOTAL_ALLOCS)->Iterations(ITERATIONS)->Threads(THREADS);
BENCHMARK(test_freelist_allocator)->Range(TOTAL_ALLOCS, TOTAL_ALLOCS)->Iterations(ITERATIONS)->Threads(THREADS);
//BENCHMARK(test_generic_freelist_allocator)->Range(TOTAL_ALLOCS, TOTAL_ALLOCS)->Iterations(ITERATIONS)->Threads(THREADS);

int main(int argc, char** argv)
{
    setup(TOTAL_ALLOCS * THREADS);
    ::benchmark::Initialize(&argc, argv);
    ::benchmark::RunSpecifiedBenchmarks();
}
