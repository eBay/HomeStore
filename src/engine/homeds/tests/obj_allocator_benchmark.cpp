//
// Created by Kadayam, Hari on 2/1/19.
//
#include <benchmark/benchmark.h>
#include <sds_logging/logging.h>
#include <sds_options/options.h>
#include "homeds/memory/obj_allocator.hpp"
#include <string>
#include <iostream>

SDS_LOGGING_INIT(HOMESTORE_LOG_MODS)
THREAD_BUFFER_INIT;
RCU_REGISTER_INIT;

#define ITERATIONS 100000
#define THREADS 64

struct my_request {
    int m_a;
    int m_b[10];
    std::string m_c;
    uint64_t m_d;
};

void setup() {}
void test_malloc(benchmark::State& state) {
    uint64_t counter = 0U;
    for (auto _ : state) { // Loops upto iteration count
        my_request* req;
        benchmark::DoNotOptimize(req = new my_request());
        req->m_a = 10;
        req->m_b[0] = 100;
        req->m_d = req->m_a * rand();
        counter += req->m_d;
        delete (req);
    }
    std::cout << "Counter = " << counter << "\n";
}

void test_obj_alloc(benchmark::State& state) {
    uint64_t counter = 0U;
    for (auto _ : state) { // Loops upto iteration count
        my_request* req;
        benchmark::DoNotOptimize(req = homeds::ObjectAllocator< my_request >::make_object());
        req->m_a = 10;
        req->m_b[0] = 100;
        req->m_d = req->m_a * rand();
        counter += req->m_d;
        homeds::ObjectAllocator< my_request >::deallocate(req);
    }
    std::cout << "Counter = " << counter << "\n";
}

BENCHMARK(test_malloc)->Iterations(ITERATIONS)->Threads(THREADS);
BENCHMARK(test_obj_alloc)->Iterations(ITERATIONS)->Threads(THREADS);

SDS_OPTIONS_ENABLE(logging)
int main(int argc, char** argv) {
    SDS_OPTIONS_LOAD(argc, argv, logging)
    setup();
    ::benchmark::Initialize(&argc, argv);
    ::benchmark::RunSpecifiedBenchmarks();
}
