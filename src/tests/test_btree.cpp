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
#include <gtest/gtest.h>
#include <boost/uuid/random_generator.hpp>

#include <sisl/utility/enum.hpp>
#include "common/homestore_config.hpp"
#include "common/resource_mgr.hpp"
#include "test_common/homestore_test_common.hpp"
#include "test_common/range_scheduler.hpp"
#include "btree_helpers/btree_test_helper.hpp"
#include "btree_helpers/btree_test_kvs.hpp"
#include "btree_helpers/btree_decls.h"

using namespace homestore;

SISL_OPTIONS_ENABLE(logging, test_btree, iomgr, test_common_setup)

// TODO Add tests to do write,remove after recovery.
// TODO Test with var len key with io mgr page size is 512.

SISL_OPTION_GROUP(
    test_btree,
    (test_type, "", "test_type", "What type of test, [unit | functional | stress ]",
     ::cxxopts::value< std::string >()->default_value("unit"), "string"),
    (num_ios, "", "num_ios", "[override] number of io operations to test", ::cxxopts::value< uint32_t >(), "number"),
    (num_entries, "", "num_entries", "[override] number of entries per btree", ::cxxopts::value< uint32_t >(),
     "number"),
    (run_time, "", "run_time", "[override] run time for io", ::cxxopts::value< uint32_t >(), "seconds"),
    (disable_merge, "", "disable_merge", "disable_merge", ::cxxopts::value< bool >()->default_value("0"), ""),
    (preload_size, "", "preload_size", "[ovveride] number of entries to preload tree with",
     ::cxxopts::value< uint32_t >(), "number"),
    (operation_list, "", "operation_list", "operation list instead of default created following by percentage",
     ::cxxopts::value< std::vector< std::string > >(), "operations [...]"),
    (seed, "", "seed", "random engine seed, use random if not defined",
     ::cxxopts::value< uint64_t >()->default_value("0"), "number"))

void log_obj_life_counter() {
    std::string str;
    sisl::ObjCounterRegistry::foreach ([&str](const std::string& name, int64_t created, int64_t alive) {
        fmt::format_to(std::back_inserter(str), "{}: created={} alive={}\n", name, created, alive);
    });
    LOGINFO("Object Life Counter\n:{}", str);
}

BtreeTestOptions g_opts;

static void set_options() {
    if (SISL_OPTIONS["test_type"].as< std::string >() == "unit") {
        g_opts.num_entries = 5000;
        g_opts.preload_size = 2500;
        g_opts.num_ios = 500;
        g_opts.run_time_secs = 36000; // Limit is on ios than time
    } else if (SISL_OPTIONS["test_type"].as< std::string >() == "functional") {
        g_opts.num_entries = 50000;
        g_opts.preload_size = 25000;
        g_opts.num_ios = 50000;
        g_opts.run_time_secs = 36000; // Limit is on ios than time
    }

    if (SISL_OPTIONS.count("num_entries")) { g_opts.num_entries = SISL_OPTIONS["num_entries"].as< uint32_t >(); }
    if (SISL_OPTIONS.count("preload_size")) { g_opts.preload_size = SISL_OPTIONS["preload_size"].as< uint32_t >(); }
    if (SISL_OPTIONS.count("num_ios")) { g_opts.num_ios = SISL_OPTIONS["num_ios"].as< uint32_t >(); }
    if (SISL_OPTIONS.count("run_time")) { g_opts.run_time_secs = SISL_OPTIONS["run_time"].as< uint32_t >(); }
    if (SISL_OPTIONS.count("disable_merge")) { g_opts.disable_merge = SISL_OPTIONS["disable_merge"].as< bool >(); }

    if (SISL_OPTIONS.count("seed")) {
        LOGINFO("Using seed {} to sow the random generation", SISL_OPTIONS["seed"].as< uint64_t >());
        g_re.seed(SISL_OPTIONS["seed"].as< uint64_t >());
    }
}

template < typename TestType >
struct BtreeTest : public BtreeTestHelper< TestType >, public ::testing::Test {
    using T = TestType;
    using K = typename TestType::KeyType;
    using V = typename TestType::ValueType;

    class TestIndexServiceCallbacks : public IndexServiceCallbacks {
    public:
        TestIndexServiceCallbacks(BtreeTest* test) : m_test(test) {}
        std::shared_ptr< Index > on_index_table_found(superblk< IndexSuperBlock >&& sb) override {
            LOGINFO("Index table recovered");
            m_test->SetUp(std::make_shared< Btree< K, V > >(m_test->m_cfg, std::move(sb)), true /* load */,
                          m_test->m_multi_threaded);
            return m_test->m_bt;
        }

    private:
        BtreeTest* m_test;
    };

    BtreeTest() : BtreeTestHelper< TestType >::BtreeTestHelper(g_opts), testing::Test() {}

    using BtreeTestHelper< TestType >::SetUp;

    void SetUp() override {
        if (TestType::store_type == IndexStore::Type::MEM_BTREE) {
            m_helper.start_homestore(
                "test_btree",
                {{ServiceType::META, {.size_pct = 100.0}},
                 {ServiceType::INDEX, {.size_pct = 0.0, .index_svc_cbs = new TestIndexServiceCallbacks(this)}}},
                nullptr,
                {homestore::dev_info{"", homestore::HSDevType::Data, 64 * 1024 * 1024},
                 homestore::dev_info{"", homestore::HSDevType::Data, 64 * 1024 * 1024}});
            // For mem btree use create only 1 small device
        } else {
            m_helper.start_homestore(
                "test_btree",
                {{ServiceType::META, {.size_pct = 10.0}},
                 {ServiceType::INDEX, {.size_pct = 70.0, .index_svc_cbs = new TestIndexServiceCallbacks(this)}}},
                nullptr, {homestore::dev_info{"", homestore::HSDevType::Fast, 0}});
            // For persistent btree, we try to create a default size, but with only 1 device explictly, since this tests
            // start restart homestore several times and its better to use 1 disk always.
        }

        auto uuid = boost::uuids::random_generator()();
        auto parent_uuid = boost::uuids::random_generator()();

        // Test cp flush of write back.
        HS_SETTINGS_FACTORY().modifiable_settings([](auto& s) {
            s.generic.cache_max_throttle_cnt = 10000;
            HS_SETTINGS_FACTORY().save();
        });
        homestore::hs()->resource_mgr().reset_dirty_buf_qd();

        // Create index table and attach to index service.
        m_multi_threaded =
            (testing::UnitTest::GetInstance()->current_test_info()->name() == std::string("ConcurrentMultiOps"));
        BtreeTestHelper< TestType >::SetUp(std::make_shared< Btree< K, V > >(this->m_cfg, uuid, parent_uuid, 0),
                                           false /* load */, m_multi_threaded);
        hs()->index_service().add_index_table(this->m_bt);
        LOGINFO("Added index table to index service");
    }

    void TearDown() override {
        destroy_btree();
        BtreeTestHelper< TestType >::TearDown();
        m_helper.shutdown_homestore(false);
        log_obj_life_counter();
    }

    void restart_homestore() {
        m_helper.params(HS_SERVICE::INDEX).index_svc_cbs = new TestIndexServiceCallbacks(this);
        this->m_bt.reset();
        m_helper.restart_homestore();
    }

    void destroy_btree() {
        hs()->index_service().destroy_index_table(this->m_bt);
        this->m_bt.reset();
    }

    test_common::HSTestHelper m_helper;
    bool m_multi_threaded{false};
};

using BtreeTypes =
    testing::Types< FixedLenBtree< IndexStore::Type::MEM_BTREE >,     // In memory fixed key/value sized btree
                    VarKeySizeBtree< IndexStore::Type::MEM_BTREE >,   // In memory var key, but fixed value sized btree
                    VarValueSizeBtree< IndexStore::Type::MEM_BTREE >, // In memory fixed key, var value sizeds btree
                    VarObjSizeBtree< IndexStore::Type::MEM_BTREE >,   // In memory var sized key/value btree
                    PrefixIntervalBtree< IndexStore::Type::MEM_BTREE >,         // In memory interval key/value btree
                    FixedLenBtree< IndexStore::Type::COPY_ON_WRITE_BTREE >,     // COW fixed key/value sized btree
                    VarKeySizeBtree< IndexStore::Type::COPY_ON_WRITE_BTREE >,   // COW var key, fixed value sized btree
                    VarValueSizeBtree< IndexStore::Type::COPY_ON_WRITE_BTREE >, // COW fixed key, var value sizeds btree
                    VarObjSizeBtree< IndexStore::Type::COPY_ON_WRITE_BTREE >,   // COW var sized key/value btree
                    PrefixIntervalBtree< IndexStore::Type::COPY_ON_WRITE_BTREE > // COW interval key/value btree
                    >;

TYPED_TEST_SUITE(BtreeTest, BtreeTypes);

TYPED_TEST(BtreeTest, SequentialInsert) {
    LOGINFO("SequentialInsert test start");
    // Forward sequential insert
    const auto entries_iter1 = g_opts.num_entries / 2;
    LOGINFO("Step 1: Do Forward sequential insert for {} entries", entries_iter1);
    for (uint32_t i{0}; i < entries_iter1; ++i) {
        this->put(i, btree_put_type::INSERT);
        // this->print();
    }
    LOGINFO("Step 2: Query {} entries and validate with pagination of 75 entries", entries_iter1);
    this->do_query(0, entries_iter1 - 1, 75);

    // Reverse sequential insert
    const auto entries_iter2 = g_opts.num_entries - entries_iter1;
    LOGINFO("Step 3: Do Reverse sequential insert of remaining {} entries", entries_iter2);
    for (uint32_t i{g_opts.num_entries - 1}; i >= entries_iter1; --i) {
        this->put(i, btree_put_type::INSERT);
    }
    LOGINFO("Step 4: Query {} entries and validate with pagination of 90 entries", entries_iter2);
    this->do_query(entries_iter1, g_opts.num_entries - 1, 90);

    // Do validate all of them
    LOGINFO("Step 5: Query all entries and validate with no pagination");
    this->query_all();

    LOGINFO("Step 6: Query all entries and validate with pagination of 80 entries");
    this->query_all_paginate(80);

    LOGINFO("Step 7: Get all entries 1-by-1 and validate them");
    this->get_all();
    this->get_any(g_opts.num_entries - 3, g_opts.num_entries + 1);

    // Negative cases
    LOGINFO("Step 8: Do incorrect input and validate errors");
    this->do_query(g_opts.num_entries + 100, g_opts.num_entries + 500, 5);
    this->get_any(g_opts.num_entries + 1, g_opts.num_entries + 2);

    LOGINFO("SequentialInsert test end");
}

TYPED_TEST(BtreeTest, RandomInsert) {
    // Forward sequential insert
    std::vector< uint32_t > vec(g_opts.num_entries);
    // make keys [0, num_entries)
    iota(vec.begin(), vec.end(), 0);
    // shuffle keys
    std::random_shuffle(vec.begin(), vec.end());
    LOGINFO("Step 1: Do forward random insert for {} entries", g_opts.num_entries);
    for (uint32_t i{0}; i < g_opts.num_entries; ++i) {
        this->put(vec[i], btree_put_type::INSERT);
    }
    this->get_all();
}

TYPED_TEST(BtreeTest, SequentialRemove) {
    LOGINFO("SequentialRemove test start");
    // Forward sequential insert
    LOGINFO("Step 1: Do Forward sequential insert for {} entries", g_opts.num_entries);
    for (uint32_t i{0}; i < g_opts.num_entries; ++i) {
        this->put(i, btree_put_type::INSERT);
    }
    LOGINFO("Step 2: Query {} entries and validate with pagination of 75 entries", g_opts.num_entries);
    this->do_query(0, g_opts.num_entries - 1, 75);

    const auto entries_iter1 = g_opts.num_entries / 2;
    try {
        LOGINFO("Step 3: Do Forward sequential remove for {} entries", entries_iter1);
        for (uint32_t i{0}; i < entries_iter1; ++i) {
            this->remove_one(i);
        }
    } catch (std::exception& e) { assert(false); }
    LOGINFO("Step 4: Query {} entries and validate with pagination of 75 entries", entries_iter1);
    this->do_query(0, entries_iter1 - 1, 75);
    this->do_query(entries_iter1, g_opts.num_entries - 1, 75);

    const auto entries_iter2 = g_opts.num_entries - entries_iter1;
    LOGINFO("Step 5: Do Reverse sequential remove of remaining {} entries", entries_iter2);
    for (uint32_t i{g_opts.num_entries - 1}; i >= entries_iter1; --i) {
        this->remove_one(i);
    }

    LOGINFO("Step 6: Query the empty tree");
    this->do_query(0, g_opts.num_entries - 1, 75);
    this->get_any(0, 1);
    this->get_specific(0);
    LOGINFO("SequentialRemove test end");
}

TYPED_TEST(BtreeTest, SimpleRemoveRange) {
    // Forward sequential insert
    const auto num_entries = 20;
    LOGINFO("Step 1: Do forward sequential insert for {} entries", num_entries);
    for (uint32_t i{0}; i < num_entries; ++i) {
        this->put(i, btree_put_type::INSERT);
    }
    LOGINFO("Step 2: Do range remove for {} entries", num_entries);
    //    this->print_keys(); // EXPECT size = 20 : 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19
    this->range_remove_any(5, 10);
    //    this->print_keys(); // EXPECT size = 14 : 0 1 2 3 4 [5 6 7 8 9 10] 11 12 13 14 15 16 17 18 19
    this->range_remove_any(0, 2);
    //    this->print_keys(); // EXPECT size = 11 : [0 1 2] 3 4 11 12 13 14 15 16 17 18 19
    this->range_remove_any(18, 19);
    //    this->print_keys(); // EXPECT size = 9 : 3 4 11 12 13 14 15 16 17 [18 19]
    this->range_remove_any(17, 17);
    //    this->print_keys(); // EXPECT size = 8 : 3 4 11 12 13 14 15 16 [17]
    this->range_remove_any(1, 5);
    //    this->print_keys(); // EXPECT size = 6 : [3 4] 11 12 13 14 15 16
    this->range_remove_any(1, 20);
    //    this->print_keys(); // EXPECT size = 0 : [11 12 13 14 15 16]

    this->query_all();
    //    this->query_validate(0, num_entries , 75);
}

TYPED_TEST(BtreeTest, RandomRemove) {
    // Forward sequential insert
    LOGINFO("Step 1: Do forward sequential insert for {} entries", g_opts.num_entries);
    for (uint32_t i{0}; i < g_opts.num_entries; ++i) {
        this->put(i, btree_put_type::INSERT);
    }

    std::vector< uint32_t > vec(g_opts.num_entries);
    iota(vec.begin(), vec.end(), 0);

    // shuffle keys in [0, num_entries)
    std::random_shuffle(vec.begin(), vec.end());
    LOGINFO("Step 2: Do remove one by one for {} entries", g_opts.num_entries);
    for (uint32_t i{0}; i < g_opts.num_entries; ++i) {
        this->remove_one(vec[i]);
    }
    this->get_all();
}

TYPED_TEST(BtreeTest, RandomRemoveRange) {
    // Forward sequential insert
    LOGINFO("Step 1: Do forward sequential insert for {} entries", g_opts.num_entries);
    for (uint32_t i{0}; i < g_opts.num_entries; ++i) {
        this->put(i, btree_put_type::INSERT);
    }
    // generate keys including out of bound
    static thread_local std::uniform_int_distribution< uint32_t > s_rand_key_generator{0, g_opts.num_entries};
    //    this->print_keys();
    LOGINFO("Step 2: Do range remove for maximum of {} iterations", g_opts.num_ios);
    for (uint32_t i{0}; i < g_opts.num_ios; ++i) {
        uint32_t key1 = s_rand_key_generator(g_re);
        uint32_t key2 = s_rand_key_generator(g_re);

        //        LOGINFO("Step 2 - {}: Do Range Remove of maximum [{},{}] keys ", i, start_key, end_key);
        this->range_remove_any(std::min(key1, key2), std::max(key1, key2));
        //        this->print_keys();
    }

    this->query_all();
}

TYPED_TEST(BtreeTest, RangeUpdate) {
    LOGINFO("RangeUpdate test start");
    // Forward sequential insert
    LOGINFO("Step 1: Do Forward sequential insert for {} entries", g_opts.num_entries);
    for (uint32_t i{0}; i < g_opts.num_entries; ++i) {
        this->put(i, btree_put_type::INSERT);
    }

    LOGINFO("Step 2: Do Range Update of random intervals between [1-50] for 100 times with random key ranges");
    for (uint32_t i{0}; i < 100; ++i) {
        this->range_put_random();
    }

    LOGINFO("Step 2: Query {} entries and validate with pagination of 75 entries", g_opts.num_entries);
    this->do_query(0, g_opts.num_entries - 1, 75);
    LOGINFO("RangeUpdate test end");
}

TYPED_TEST(BtreeTest, CpFlush) {
    using TestT = typename TestFixture::T;
    if (TestT::store_type == IndexStore::Type::MEM_BTREE) { GTEST_SKIP(); }

    LOGINFO("CpFlush test start");
    LOGINFO("Do Forward sequential insert for {} entries", g_opts.num_entries / 2);
    for (uint32_t i = 0; i < g_opts.num_entries; ++i) {
        this->put(i, btree_put_type::INSERT);
    }

    // Remove some of the entries.
    for (uint32_t i = 0; i < g_opts.num_entries; i += 10) {
        this->remove_one(i);
    }

    LOGINFO("Query {} entries and validate with pagination of 75 entries", g_opts.num_entries / 2);
    this->do_query(0, g_opts.num_entries / 2 - 1, 75);

    LOGINFO("Trigger checkpoint flush.");
    test_common::HSTestHelper::trigger_cp(true /* wait */);

    LOGINFO("Query {} entries and validate with pagination of 75 entries", g_opts.num_entries);
    this->do_query(0, g_opts.num_entries - 1, 75);

    this->dump_to_file(std::string("before.txt"));

    // Restart homestore. m_bt is updated by the TestIndexServiceCallback.
    this->restart_homestore();

    std::this_thread::sleep_for(std::chrono::seconds{1});
    LOGINFO("Restarted homestore with index recovered");

    this->dump_to_file(std::string("after.txt"));

    LOGINFO("Query {} entries", g_opts.num_entries);
    this->do_query(0, g_opts.num_entries - 1, 1000);

    this->compare_files("before.txt", "after.txt");
    LOGINFO("CpFlush test end");
}

TYPED_TEST(BtreeTest, MultipleCpFlush) {
    using TestT = typename TestFixture::T;
    if (TestT::store_type == IndexStore::Type::MEM_BTREE) { GTEST_SKIP(); }

    LOGINFO("MultipleCpFlush test start");

    LOGINFO("Do Forward sequential insert for {} entries", g_opts.num_entries / 2);
    for (uint32_t i = 0; i < g_opts.num_entries / 2; ++i) {
        this->put(i, btree_put_type::INSERT);
        if (i % 500 == 0) {
            LOGINFO("Trigger checkpoint flush wait=false.");
            test_common::HSTestHelper::trigger_cp(false /* wait */);
        }
    }

    LOGINFO("Trigger checkpoint flush wait=false.");
    test_common::HSTestHelper::trigger_cp(false /* wait */);

    for (uint32_t i = g_opts.num_entries / 2; i < g_opts.num_entries; ++i) {
        this->put(i, btree_put_type::INSERT);
    }

    LOGINFO("Trigger checkpoint flush wait=false.");
    test_common::HSTestHelper::trigger_cp(false /* wait */);

    LOGINFO("Trigger checkpoint flush wait=true.");
    test_common::HSTestHelper::trigger_cp(true /* wait */);

    LOGINFO("Query {} entries and validate with pagination of 75 entries", g_opts.num_entries);
    this->do_query(0, g_opts.num_entries - 1, 75);

    this->dump_to_file(std::string("before.txt"));

    // Restart homestore. m_bt is updated by the TestIndexServiceCallback.
    this->restart_homestore();

    std::this_thread::sleep_for(std::chrono::seconds{1});
    LOGINFO(" Restarted homestore with index recovered");
    this->dump_to_file(std::string("after.txt"));

    this->compare_files("before.txt", "after.txt");

    LOGINFO("Query {} entries and validate with pagination of 1000 entries", g_opts.num_entries);
    this->do_query(0, g_opts.num_entries - 1, 1000);
    LOGINFO("MultipleCpFlush test end");
}

TYPED_TEST(BtreeTest, ThreadedCpFlush) {
    using TestT = typename TestFixture::T;
    if (TestT::store_type == IndexStore::Type::MEM_BTREE) { GTEST_SKIP(); }

    LOGINFO("ThreadedCpFlush test start");

    bool stop = false;
    std::atomic< uint32_t > last_index{0};
    auto insert_io_thread = std::thread([this, &last_index] {
        LOGINFO("Do Forward sequential insert for {} entries", g_opts.num_entries);
        uint32_t j = 0;
        for (uint32_t i = 0; i < g_opts.num_entries; ++i) {
            this->put(i, btree_put_type::INSERT);
            last_index = i;
        }
    });

    auto remove_io_thread = std::thread([this, &stop, &last_index] {
        LOGINFO("Do random removes for {} entries", g_opts.num_entries);
        while (!stop) {
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
            // Remove a random entry.
            std::uniform_int_distribution< uint32_t > rand{0, last_index.load()};
            auto rm_idx = rand(g_re);
            this->remove_one(rm_idx);
        }
    });

    auto cp_flush_thread = std::thread([this, &stop] {
        while (!stop) {
            std::this_thread::sleep_for(std::chrono::seconds{1});
            LOGINFO("Trigger checkpoint flush wait=true.");
            test_common::HSTestHelper::trigger_cp(false /* wait */);
            LOGINFO("Trigger checkpoint flush wait=true done.");
        }
    });

    insert_io_thread.join();
    stop = true;
    remove_io_thread.join();
    cp_flush_thread.join();

    LOGINFO("Trigger checkpoint flush wait=true.");
    test_common::HSTestHelper::trigger_cp(true /* wait */);

    LOGINFO("Query {} entries and validate with pagination of 75 entries", g_opts.num_entries);
    this->do_query(0, g_opts.num_entries - 1, 75);

    this->dump_to_file(std::string("before.txt"));

    // Restart homestore. m_bt is updated by the TestIndexServiceCallback.
    this->restart_homestore();

    std::this_thread::sleep_for(std::chrono::seconds{1});
    LOGINFO(" Restarted homestore with index recovered");
    this->dump_to_file(std::string("after.txt"));

    this->compare_files("before.txt", "after.txt");

    LOGINFO("Query {} entries and validate with pagination of 1000 entries", g_opts.num_entries);
    this->do_query(0, g_opts.num_entries - 1, 1000);
    LOGINFO("ThreadedCpFlush test end");
}

TYPED_TEST(BtreeTest, ConcurrentMultiOps) {
    // range put is not supported for non-extent keys
    std::vector< std::string > input_ops = {"put:18", "remove:14", "range_put:20", "range_remove:2", "query:10"};
    if (SISL_OPTIONS.count("operation_list")) {
        input_ops = SISL_OPTIONS["operation_list"].as< std::vector< std::string > >();
    }
    auto ops = this->build_op_list(input_ops);

    this->multi_op_execute(ops);
}

int main(int argc, char* argv[]) {
    int parsed_argc{argc};
    ::testing::InitGoogleTest(&parsed_argc, argv);
    SISL_OPTIONS_LOAD(parsed_argc, argv, logging, test_btree, iomgr, test_common_setup);
    sisl::logging::SetLogger("test_btree");
    spdlog::set_pattern("[%D %T%z] [%^%L%$] [%t] %v");

    set_options();
    auto ret = RUN_ALL_TESTS();
    return ret;
}
