/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
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

#include <benchmark/benchmark.h>
#include <boost/uuid/random_generator.hpp>
#include <stdint.h>

#include <iomgr/io_environment.hpp>
#include <sisl/options/options.h>
#include <homestore/btree/detail/btree_internal.hpp>
#include "test_common/homestore_test_common.hpp"
#include "btree_helpers/btree_test_kvs.hpp"
#include "test_common/range_scheduler.hpp"
#include "btree_helpers/btree_test_helper.hpp"
#include "btree_helpers/btree_decls.h"

using namespace homestore;

#define INDEX_BETREE_BENCHMARK(BTREE_TYPE)                                                                             \
    BENCHMARK(run_benchmark< BTREE_TYPE >)                                                                             \
        ->Setup(BM_Setup< BTREE_TYPE >)                                                                                \
        ->Teardown(BM_Teardown< BTREE_TYPE >)                                                                          \
        ->UseRealTime()                                                                                                \
        ->Iterations(1)                                                                                                \
        ->Name(#BTREE_TYPE);

// this is used to splite the setup and teardown from the benchmark to get a more accurate result
void* globle_helper{nullptr};

#define GET_BENCHMARK_HELPER(BTREE_TYPE) static_cast< IndexBtreeBenchmark< BTREE_TYPE >* >(globle_helper)

SISL_LOGGING_INIT(HOMESTORE_LOG_MODS)
std::vector< std::string > test_common::HSTestHelper::s_dev_names;
SISL_OPTIONS_ENABLE(logging, index_btree_benchmark, iomgr, test_common_setup)

SISL_OPTION_GROUP(index_btree_benchmark,
                  (num_iters, "", "num_iters", "number of iterations for rand ops",
                   ::cxxopts::value< uint32_t >()->default_value("500"), "number"),
                  (num_entries, "", "num_entries", "number of entries to test with",
                   ::cxxopts::value< uint32_t >()->default_value("5000"), "number"),
                  (run_time, "", "run_time", "run time for io", ::cxxopts::value< uint32_t >()->default_value("30"),
                   "seconds"),
                  (operation_list, "", "operation_list",
                   "operation list instead of default created following by percentage",
                   ::cxxopts::value< std::vector< std::string > >()->default_value({"put:100"}), "operations [...]"),
                  (preload_size, "", "preload_size", "number of entries to preload tree with",
                   ::cxxopts::value< uint32_t >()->default_value("1000"), "number"))

template < typename TestType >
struct IndexBtreeBenchmark : public BtreeTestHelper< TestType > {
    using T = TestType;
    using K = typename TestType::KeyType;
    using V = typename TestType::ValueType;
    IndexBtreeBenchmark() { SetUp(); }

    ~IndexBtreeBenchmark() { TearDown(); }

    void SetUp() {
        test_common::HSTestHelper::start_homestore(
            "index_btree_benchmark", {{HS_SERVICE::META, {.size_pct = 10.0}}, {HS_SERVICE::INDEX, {.size_pct = 70.0}}});

        this->m_cfg = BtreeConfig(hs()->index_service().node_size());
        this->m_is_multi_threaded = true;

        auto uuid = boost::uuids::random_generator()();
        auto parent_uuid = boost::uuids::random_generator()();

        BtreeTestHelper< TestType >::SetUp();
        this->m_bt = std::make_shared< typename T::BtreeType >(uuid, parent_uuid, 0, this->m_cfg);
        hs()->index_service().add_index_table(this->m_bt);
        auto input_ops = SISL_OPTIONS["operation_list"].as< std::vector< std::string > >();
        m_op_list = this->build_op_list(input_ops);
    }

    void TearDown() {
        BtreeTestHelper< TestType >::TearDown();
        test_common::HSTestHelper::shutdown_homestore();
    }

    void run_benchmark() { this->run_in_parallel(m_op_list); }

private:
    std::vector< std::pair< std::string, int > > m_op_list;
};

template < class BenchmarkType >
void BM_Setup(const benchmark::State& state) {
    globle_helper = new IndexBtreeBenchmark< BenchmarkType >();
    auto helper = GET_BENCHMARK_HELPER(BenchmarkType);
    helper->preload(SISL_OPTIONS["preload_size"].as< uint32_t >());
}

template < class BenchmarkType >
void BM_Teardown(const benchmark::State& state) {
    delete GET_BENCHMARK_HELPER(BenchmarkType);
}

template < class BenchmarkType >
void add_custom_counter(benchmark::State& state) {
    auto helper = GET_BENCHMARK_HELPER(BenchmarkType);
    auto totol_ops = helper->get_op_num();
    state.counters["thread_num"] = SISL_OPTIONS["num_threads"].as< uint32_t >();
    state.counters["fiber_num"] = SISL_OPTIONS["num_fibers"].as< uint32_t >();
    state.counters["total_ops"] = totol_ops;
    state.counters["rate"] = benchmark::Counter(totol_ops, benchmark::Counter::kIsRate);
    state.counters["InvRate"] =
        benchmark::Counter(totol_ops, benchmark::Counter::kIsRate | benchmark::Counter::kInvert);
}

template < class BenchmarkType >
void run_benchmark(benchmark::State& state) {
    auto helper = GET_BENCHMARK_HELPER(BenchmarkType);
    for (auto _ : state) {
        helper->run_benchmark();
    }
    add_custom_counter< BenchmarkType >(state);
}

INDEX_BETREE_BENCHMARK(FixedLenBtree)
INDEX_BETREE_BENCHMARK(VarKeySizeBtree)
INDEX_BETREE_BENCHMARK(VarValueSizeBtree)
INDEX_BETREE_BENCHMARK(VarObjSizeBtree)
//INDEX_BETREE_BENCHMARK(PrefixIntervalBtree)

int main(int argc, char** argv) {
    SISL_OPTIONS_LOAD(argc, argv, logging, index_btree_benchmark, iomgr, test_common_setup);
    ::benchmark::Initialize(&argc, argv);
    ::benchmark::RunSpecifiedBenchmarks();
}
