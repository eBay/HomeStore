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

SISL_LOGGING_INIT(HOMESTORE_LOG_MODS)
SISL_OPTIONS_ENABLE(logging, test_index_crash_recovery, iomgr, test_common_setup)
SISL_LOGGING_DECL(test_index_crash_recovery)

// TODO Add tests to do write,remove after recovery.
// TODO Test with var len key with io mgr page size is 512.

SISL_OPTION_GROUP(test_index_crash_recovery,
                  (num_iters, "", "num_iters", "number of iterations for rand ops",
                      ::cxxopts::value< uint32_t >()->default_value("500"), "number"),
                  (num_entries, "", "num_entries", "number of entries to test with",
                      ::cxxopts::value< uint32_t >()->default_value("5000"), "number"),
                  (run_time, "", "run_time", "run time for io", ::cxxopts::value< uint32_t >()->default_value("360000"),
                      "seconds"),
                  (max_keys_in_node, "", "max_keys_in_node", "max_keys_in_node",
                      ::cxxopts::value< uint32_t >()->default_value("20"), ""),
                  (min_keys_in_node, "", "min_keys_in_node", "min_keys_in_node",
                      ::cxxopts::value< uint32_t >()->default_value("6"), ""),
                  (operation_list, "", "operation_list",
                      "operation list instead of default created following by percentage",
                      ::cxxopts::value< std::vector< std::string > >(), "operations [...]"),
                  (preload_size, "", "preload_size", "number of entries to preload tree with",
                      ::cxxopts::value< uint32_t >()->default_value("1000"), "number"),
                  (init_device, "", "init_device", "init device", ::cxxopts::value< bool >()->default_value("1"), ""),
                  (cleanup_after_shutdown, "", "cleanup_after_shutdown", "cleanup after shutdown",
                      ::cxxopts::value< bool >()->default_value("1"), ""),
                  (seed, "", "seed", "random engine seed, use random if not defined",
                      ::cxxopts::value< uint64_t >()->default_value("0"), "number"))

void log_obj_life_counter() {
    std::string str;
    sisl::ObjCounterRegistry::foreach ([&str](const std::string& name, int64_t created, int64_t alive) {
        fmt::format_to(std::back_inserter(str), "{}: created={} alive={}\n", name, created, alive);
    });
    LOGINFO("Object Life Counter\n:{}", str);
}

enum class OperationType {
    Put,
    Remove,
};

using Operation = std::pair< uint64_t, OperationType >;
using OperationList = std::vector< Operation >;

class SequenceGenerator {
public:
    SequenceGenerator(int putFreq, int removeFreq, uint64_t start_range, uint64_t end_range) :
            putFreq_(putFreq), removeFreq_(removeFreq), start_range_(start_range), end_range_(end_range) {
        std::random_device rd;
        gen_ = std::mt19937(rd());
        keyDist_ = std::uniform_int_distribution<>(start_range_, end_range_);
        updateOperationTypeDistribution();
    }

    void setPutFrequency(int putFreq) {
        putFreq_ = putFreq;
        updateOperationTypeDistribution();
    }

    void setRemoveFrequency(int removeFreq) {
        removeFreq_ = removeFreq;
        updateOperationTypeDistribution();
    }

    void setRange(uint64_t start_range, uint64_t end_range) {
        start_range_ = start_range;
        end_range_ = end_range;
        keyDist_ = std::uniform_int_distribution<>(start_range_, end_range_);
    }

    void fillRange(uint64_t start, uint64_t end) {
        for (uint64_t i = start; i <= end; ++i) {
            keyStates[i] = true;
        }
    }

    OperationList generateOperations(size_t numOperations, bool reset = false) {
        std::vector< Operation > operations;
        if (reset) { this->reset(); }
        while (operations.size() < numOperations) {
            uint32_t key = keyDist_(gen_);
            auto [it, inserted] = keyStates.try_emplace(key, false);
            auto& inUse = it->second;

            OperationType operation = static_cast< OperationType >(opTypeDist_(gen_));

            if (operation == OperationType::Put && !inUse) {
                operations.emplace_back(key, OperationType::Put);
                inUse = true;
            } else if (operation == OperationType::Remove && inUse) {
                operations.emplace_back(key, OperationType::Remove);
                inUse = false;
            }
        }

        return operations;
    }

    __attribute__((noinline)) std::string showKeyState(uint64_t key) const {
        auto it = keyStates.find(key);
        if (it != keyStates.end()) { return it->second ? "Put" : "Remove"; }
        return "Not in keyStates";
    }

    __attribute__((noinline)) static OperationList inspect(const OperationList& operations, uint64_t key) {
        OperationList occurrences;
        for (size_t i = 0; i < operations.size(); ++i) {
            const auto& [opKey, opType] = operations[i];
            if (opKey == key) { occurrences.emplace_back(i, opType); }
        }
        return occurrences;
    }

    __attribute__((noinline)) std::string printOperations(const OperationList& operations) const {
        std::ostringstream oss;
        for (const auto& [key, opType] : operations) {
            std::string opTypeStr = (opType == OperationType::Put) ? "Put" : "Remove";
            oss << "{" << key << ", " << opTypeStr << "}\n";
        }
        return oss.str();
    }

    __attribute__((noinline)) std::string printKeysOccurrences(const OperationList& operations) const {
        std::set< uint64_t > keys = collectUniqueKeys(operations);
        std::ostringstream oss;
        for (auto key : keys) {
            auto keyOccurrences = inspect(operations, key);
            oss << "Occurrences of key " << key << ":\n";
            for (const auto& [index, operation] : keyOccurrences) {
                std::string opTypeStr = (operation == OperationType::Put) ? "Put" : "Remove";
                oss << "Index: " << index << ", Operation: " << opTypeStr << "\n";
            }
        }
        return oss.str();
    }

    __attribute__((noinline)) std::string printKeyOccurrences(const OperationList& operations, uint64_t key ) const {
        std::ostringstream oss;
        auto keyOccurrences = inspect(operations, key);
        oss << "Occurrences of key " << key << ":\n";
        for (const auto& [index, operation] : keyOccurrences) {
            std::string opTypeStr = (operation == OperationType::Put) ? "Put" : "Remove";
                oss << "Index: " << index << ", Operation: " << opTypeStr << "\n";
        }
        return oss.str();
    }

    void reset() { keyStates.clear(); }

private:
    int putFreq_;
    int removeFreq_;
    uint64_t start_range_;
    uint64_t end_range_;
    std::mt19937 gen_;
    std::uniform_int_distribution<> keyDist_;
    std::discrete_distribution<> opTypeDist_;
    std::map< uint64_t, bool > keyStates;

    void updateOperationTypeDistribution() {
        opTypeDist_ =
            std::discrete_distribution<>({static_cast< double >(putFreq_), static_cast< double >(removeFreq_)});
    }

    std::set< uint64_t > collectUniqueKeys(const OperationList& operations) const {
        std::set< uint64_t > keys;
        for (const auto& [key, _] : operations) {
            keys.insert(key);
        }
        return keys;
    }
};
#ifdef _PRERELEASE
template < typename TestType >
struct IndexCrashTest : public test_common::HSTestHelper, BtreeTestHelper< TestType >, public ::testing::Test {
    using T = TestType;
    using K = typename TestType::KeyType;
    using V = typename TestType::ValueType;
    class TestIndexServiceCallbacks : public IndexServiceCallbacks {
    public:
        TestIndexServiceCallbacks(IndexCrashTest* test) : m_test(test) {}

        std::shared_ptr< IndexTableBase > on_index_table_found(superblk< index_table_sb >&& sb) override {
            LOGINFO("Index table recovered, root bnode_id {} version {}", sb->root_node, sb->root_link_version);

            m_test->m_cfg = BtreeConfig(hs()->index_service().node_size());
            m_test->m_cfg.m_leaf_node_type = T::leaf_node_type;
            m_test->m_cfg.m_int_node_type = T::interior_node_type;
            m_test->m_cfg.m_max_keys_in_node = SISL_OPTIONS["max_keys_in_node"].as< uint32_t >();
            m_test->m_cfg.m_min_keys_in_node = SISL_OPTIONS["min_keys_in_node"].as<uint32_t>();
            m_test->m_bt = std::make_shared< typename T::BtreeType >(std::move(sb), m_test->m_cfg);
            return m_test->m_bt;
        }

    private:
        IndexCrashTest* m_test;
    };

    IndexCrashTest() : testing::Test() { this->m_is_multi_threaded = true; }

    void SetUp() override {
        // Set the cp_timer_us to very high value to avoid any automatic checkpointing.
        HS_SETTINGS_FACTORY().modifiable_settings([](auto& s) {
            s.generic.cache_max_throttle_cnt = 10000;
            s.generic.cp_timer_us = 0x8000000000000000;
            s.resource_limits.dirty_buf_percent = 100;
            HS_SETTINGS_FACTORY().save();
        });

        this->start_homestore(
            "test_index_crash_recovery",
            {{HS_SERVICE::META, {.size_pct = 10.0}},
             {HS_SERVICE::INDEX, {.size_pct = 70.0, .index_svc_cbs = new TestIndexServiceCallbacks(this)}}},
            nullptr, {}, SISL_OPTIONS["init_device"].as< bool >());

        LOGINFO("Node size {} ", hs()->index_service().node_size());
        this->m_cfg = BtreeConfig(hs()->index_service().node_size());
        this->m_cfg.m_max_keys_in_node = SISL_OPTIONS["max_keys_in_node"].as< uint32_t >();
        this->m_cfg.m_min_keys_in_node = SISL_OPTIONS["min_keys_in_node"].as<uint32_t>();
        auto uuid = boost::uuids::random_generator()();
        auto parent_uuid = boost::uuids::random_generator()();

        homestore::hs()->resource_mgr().reset_dirty_buf_qd();

        // Create index table and attach to index service.
        BtreeTestHelper< TestType >::SetUp();
        if (this->m_bt == nullptr || SISL_OPTIONS["init_device"].as< bool >()) {
            this->m_bt = std::make_shared< typename T::BtreeType >(uuid, parent_uuid, 0, this->m_cfg);
        } else {
            populate_shadow_map();
        }

        hs()->index_service().add_index_table(this->m_bt);
        LOGINFO("Added index table to index service");
    }

    void populate_shadow_map() {
        this->m_shadow_map.load(m_shadow_filename);
        ASSERT_EQ(this->m_shadow_map.size(), this->m_bt->count_keys(this->m_bt->root_node_id()))
            << "shadow map size and tree size mismatch";
        this->get_all();
    }

    void reset_btree() {
        hs()->index_service().remove_index_table(this->m_bt);
        this->m_bt->destroy();
        this->trigger_cp(true);

        auto uuid = boost::uuids::random_generator()();
        auto parent_uuid = boost::uuids::random_generator()();
        this->m_bt = std::make_shared< typename T::BtreeType >(uuid, parent_uuid, 0, this->m_cfg);
        hs()->index_service().add_index_table(this->m_bt);
        this->m_shadow_map.range_erase(0, SISL_OPTIONS["num_entries"].as< uint32_t >() - 1);
    }

    void restart_homestore(uint32_t shutdown_delay_sec = 3) override {
        this->params(HS_SERVICE::INDEX).index_svc_cbs = new TestIndexServiceCallbacks(this);
        LOGINFO("\n\n\n\n\n\n shutdown homestore for index service Test\n\n\n\n\n");
        test_common::HSTestHelper::restart_homestore(shutdown_delay_sec);
    }

    void reapply_after_crash() {
        ShadowMap< K, V > snapshot_map{this->m_shadow_map.max_keys()};
        snapshot_map.load(m_shadow_filename);
        // LOGDEBUG("\tSnapshot before crash\n{}", snapshot_map.to_string());
        auto diff = this->m_shadow_map.diff(snapshot_map);

        // visualize tree after crash
        // std::string recovered_tree_filename = "tree_after_crash_" + to_string(rand() % 100) + ".dot";
        // this->visualize_keys(recovered_tree_filename);
        // LOGINFO(" tree after recovered stored in {}", recovered_tree_filename);

        std::string dif_str = "KEY \tADDITION\n";
        for (const auto& [k, addition] : diff) {
            dif_str += fmt::format(" {} \t{}\n", k.key(), addition);
        }
        // LOGDEBUG("Diff between shadow map and snapshot map\n{}\n", dif_str);

        for (const auto &[k, addition]: diff) {
            // this->print_keys(fmt::format("reapply: before inserting key {}", k.key()));
            //  this->visualize_keys(recovered_tree_filename);
            if (addition) {
                LOGDEBUG("Reapply: Inserting key {}", k.key());
                this->force_upsert(k.key());
            } else {
                LOGDEBUG("Reapply: Removing key {}", k.key());
                this->remove_one(k.key(), false);
            }
        }
        trigger_cp(true);
        this->m_shadow_map.save(m_shadow_filename);
    }

    void reapply_after_crash(OperationList& operations) {
        for (const auto& [key, opType] : operations) {
            switch (opType) {
            case OperationType::Put:
                LOGDEBUG("Reapply: Inserting key {}", key);
                this->force_upsert(key);
                break;
            case OperationType::Remove:
                LOGDEBUG("Reapply: Removing key {}", key);
                this->remove_one(key, false);
                break;
            }
        }
        trigger_cp(true);
    }

    void TearDown() override {
        bool cleanup = SISL_OPTIONS["cleanup_after_shutdown"].as< bool >();
        LOGINFO("cleanup the dump map and index data? {}", cleanup);
        if (!cleanup) {
            this->m_shadow_map.save(m_shadow_filename);
        } else {
            if (std::filesystem::remove(m_shadow_filename)) {
                LOGINFO("File {} removed successfully", m_shadow_filename);
            } else {
                LOGINFO("Error: failed to remove {}", m_shadow_filename);
            }
        }
        LOGINFO("Teardown with Root bnode_id {} tree size: {}", this->m_bt->root_node_id(),
                this->m_bt->count_keys(this->m_bt->root_node_id()));
        BtreeTestHelper< TestType >::TearDown();
        this->shutdown_homestore(false);
    }

    void crash_and_recover(uint32_t s_key, uint32_t e_key) {
        // this->print_keys("Btree prior to CP and susbsequent simulated crash: ");
        trigger_cp(false);
        this->wait_for_crash_recovery();
        // this->visualize_keys("tree_after_crash_" + std::to_string(s_key) + "_" + std::to_string(e_key) + ".dot");

        // this->print_keys("Post crash and recovery, btree structure: ");
        this->reapply_after_crash();

        // Verification
        this->get_all();
        LOGINFO("Expect to have [{},{}) in tree and it is actually{} ", s_key, e_key, tree_key_count());
        ASSERT_EQ(this->m_shadow_map.size(), this->m_bt->count_keys(this->m_bt->root_node_id()))
            << "shadow map size and tree size mismatch";
    }

    void crash_and_recover(OperationList& operations, std::string filename = "") {
        // this->print_keys("Btree prior to CP and susbsequent simulated crash: ");
        trigger_cp(false);
        this->wait_for_crash_recovery();
        // this->print_keys("Post crash and recovery, btree structure:");

        if (!filename.empty()) {
            LOGINFO("Visualize the tree file {}", filename);
            this->visualize_keys(filename);
        }

        this->reapply_after_crash(operations);

        //        this->print_keys("\n\nafter reapply keys");
        if (!filename.empty()) {
            LOGINFO("Visualize the tree file after_reapply__{}", filename);
            this->visualize_keys("after_reapply__" + filename);
        }

        // Verification
        this->get_all();
    }

    uint32_t tree_key_count() { return this->m_bt->count_keys(this->m_bt->root_node_id()); }

protected:
    const std::string m_shadow_filename = "/tmp/shadow_map_index_recovery.txt";
};

// Crash recovery can test one simple btree, since focus is not on btree test itself, but index recovery
using BtreeTypes = testing::Types< FixedLenBtree >;
TYPED_TEST_SUITE(IndexCrashTest, BtreeTypes);

TYPED_TEST(IndexCrashTest, CrashBeforeFirstCp) {
    // Simulate the crash even before first cp
    this->set_basic_flip("crash_flush_on_root");

    auto ops = this->build_op_list({"put:100"});
    this->multi_op_execute(ops, true /* skip_preload */);

    // Trigger a cp, which should induce the crash and wait for hs to recover
    test_common::HSTestHelper::trigger_cp(false);
    this->wait_for_crash_recovery();

    // Post crash, load the shadow_map into a new instance and compute the diff. Redo the operation
    this->reapply_after_crash();
}

TYPED_TEST(IndexCrashTest, SplitOnLeftEdge) {
    // Insert into 4 phases, first fill up the last part, since we need to test split on left edge
    LOGINFO("Step 1: Fill up the last quarter of the tree");
    auto const num_entries = SISL_OPTIONS["num_entries"].as< uint32_t >();
    for (auto k = num_entries * 3 / 4; k < num_entries; ++k) {
        this->put(k, btree_put_type::INSERT, true /* expect_success */);
    }

    // Trigger the cp to make sure middle part is successful
    LOGINFO("Step 2: Flush all the entries so far");
    test_common::HSTestHelper::trigger_cp(true);
    this->get_all();
    this->m_shadow_map.save(this->m_shadow_filename);

    // Now fill the entries from first and the leftmost child will always split, with crash flip set during flush phase
    LOGINFO("Step 3: Fill the 3rd quarter of the tree, to make sure left child is split and we crash on flush of the "
            "new child");
    this->set_basic_flip("crash_flush_on_split_at_right_child");
    for (auto k = num_entries / 2; k < num_entries * 3 / 4; ++k) {
        this->put(k, btree_put_type::INSERT, true /* expect_success */);
    }
    LOGINFO("Step 4: Crash and reapply the missing entries to tree");
    this->crash_and_recover(num_entries / 2, num_entries);

    LOGINFO("Step 5: Fill the 2nd quarter of the tree, to make sure left child is split and we crash on flush of the "
            "left child");
    this->set_basic_flip("crash_flush_on_split_at_left_child");
    this->visualize_keys("tree_before_insert.dot");
    for (auto k = num_entries / 4; k < num_entries / 2; ++k) {
        // LOGINFO("inserting key {}", k);
        // this->visualize_keys("tree_before_" + to_string(k) + ".dot");
        this->put(k, btree_put_type::INSERT, true /* expect_success */);
    }
    this->visualize_keys("tree_before_crash.dot");
    this->dump_to_file("tree_before_crash.dot");
    LOGINFO("Step 6: Simulate crash and then recover, reapply keys to tree");
    this->crash_and_recover(num_entries / 4, num_entries);

    LOGINFO("Step 7: Fill the 1st quarter of the tree, to make sure left child is split and we crash on flush of the "
            "parent node");
    this->set_basic_flip("crash_flush_on_split_at_parent");
    for (auto k = 0u; k < num_entries / 4; ++k) {
        this->put(k, btree_put_type::INSERT, true /* expect_success */);
    }
    LOGINFO("Step 8: Post crash we reapply the missing entries to tree");
    this->crash_and_recover(0, num_entries);
    LOGINFO("Step 9: Query all entries and validate with pagination of 80 entries");
    this->query_all_paginate(80);
}

TYPED_TEST(IndexCrashTest, SplitCrash1) {
    // Define the lambda function
    auto const num_entries = SISL_OPTIONS["num_entries"].as< uint32_t >();
    SequenceGenerator generator(100 /*putFreq*/, 0 /* removeFreq*/, 0 /*start_range*/, num_entries - 1 /*end_range*/);
    vector< std::string > flips = {"crash_flush_on_split_at_parent", "crash_flush_on_split_at_left_child",
                                   "crash_flush_on_split_at_right_child"};
    OperationList operations;
    for (size_t i = 0; i < flips.size(); ++i) {
        this->reset_btree();
        LOGINFO("Step 1-{}: Set flag {}", i + 1, flips[i]);
        this->set_basic_flip(flips[i]);
        operations = generator.generateOperations(num_entries -1 , true /* reset */);
        //        LOGINFO("Batch {} Operations:\n {} \n ", i + 1, generator.printOperations(operations));
        //        LOGINFO("Detailed Key Occurrences for Batch {}:\n {} \n ", i + 1,
        //        generator.printKeyOccurrences(operations));
        for (auto [k, _] : operations) {
            //          LOGINFO("\t\t\t\t\t\t\t\t\t\t\t\t\tupserting entry {}", k);
            this->put(k, btree_put_type::INSERT, true /* expect_success */);
        }
        this->crash_and_recover(operations, fmt::format("recover_tree_crash_{}.dot", i + 1));
    }
}

TYPED_TEST(IndexCrashTest, long_running_put_crash) {
    // Define the lambda function
    auto const num_entries = SISL_OPTIONS["num_entries"].as< uint32_t >();
    SequenceGenerator generator(100 /*putFreq*/, 0 /* removeFreq*/, 0 /*start_range*/, num_entries - 1 /*end_range*/);
    vector< std::string > flips = {"crash_flush_on_split_at_parent", "crash_flush_on_split_at_left_child",
                                   "crash_flush_on_split_at_right_child"};
    OperationList operations;
    auto m_start_time = Clock::now();
    auto time_to_stop = [this, m_start_time]() { return (get_elapsed_time_sec(m_start_time) > this->m_run_time); };
    double elapsed_time, progress_percent, last_progress_time = 0;
    for (size_t i = 0; !time_to_stop(); ++i) {
        bool print_time = false;
        elapsed_time = get_elapsed_time_sec(m_start_time);

        this->reset_btree();
        auto flip = flips[i % flips.size()];
        LOGINFO("Step 1-{}: Set flag {}", i + 1, flip);

        this->set_basic_flip(flip, 1, 10);
        operations = generator.generateOperations(num_entries -1, true /* reset */);
        //        operations = generator.generateOperations(num_entries/10, false /* reset */);
        //        LOGINFO("Batch {} Operations:\n {} \n ", i + 1, generator.printOperations(operations));
        //        LOGINFO("Detailed Key Occurrences for Batch {}:\n {} \n ", i + 1,
        //        generator.printKeyOccurrences(operations));
        for (auto [k, _] : operations) {
            //          LOGINFO("\t\t\t\t\t\t\t\t\t\t\t\t\tupserting entry {}", k);
            this->put(k, btree_put_type::INSERT, true /* expect_success */);
        }
        this->crash_and_recover(operations/*,  fmt::format("recover_tree_crash_{}.dot", i + 1)*/);
        if (elapsed_time - last_progress_time > 30) {
            last_progress_time = elapsed_time;
            print_time = true;
        }
        if (print_time) {
            LOGINFO("\n\n\n\t\t\tProgress: {} iterations completed - Elapsed time: {:.0f} seconds of total "
                    "{} ({:.2f}%)\n\n\n",
                    i, elapsed_time, this->m_run_time, elapsed_time * 100.0 / this->m_run_time);
        }
        this->print_keys(fmt::format("reapply: after iteration {}", i));

    }
}

// Basic reverse and forward order remove with different flip points
TYPED_TEST(IndexCrashTest, MergeRemoveBasic) {
    vector<std::string> flip_points = {
        "crash_flush_on_merge_at_parent",
        "crash_flush_on_merge_at_left_child",
        "crash_flush_on_freed_child",
    };

    for (size_t i = 0; i < flip_points.size(); ++i) {
        this->reset_btree();

        auto &flip_point = flip_points[i];
        LOGINFO("=== Testing flip point: {} - {} ===", i + 1, flip_point);

        // Populate some keys [1,num_entries) and trigger cp to persist
        LOGINFO("Step {}-1: Populate some keys and flush", i+1);
        auto const num_entries = SISL_OPTIONS["num_entries"].as< uint32_t >();
        for (auto k = 0u; k < num_entries; ++k) {
            this->put(k, btree_put_type::INSERT, true /* expect_success */);
        }
        test_common::HSTestHelper::trigger_cp(true);
        this->m_shadow_map.save(this->m_shadow_filename);

        this->visualize_keys("tree_merge_full.dot");

        // Split keys into batches and remove the last one in reverse order
        LOGINFO("Step {}-2: Set crash flag, remove some keys in reverse order", i + 1);
        int batch_num = 4;
        {
            int n = batch_num;
            auto r = num_entries * n / batch_num - 1;
            auto l = num_entries * (n - 1) / batch_num;
            OperationList ops;
            for (auto k = r; k >= l; --k) {
                ops.emplace_back(k, OperationType::Remove);
            }
            LOGINFO("Step {}-2-1: Remove keys in batch {}/{} ({} to {})", i + 1, n, batch_num, r, l);

            this->set_basic_flip(flip_point);
            for (auto [k, _]: ops) {
                LOGINFO("Removing key {}", k);
                this->remove_one(k, true);
            }
            this->visualize_keys("tree_merge_before_first_crash.dot");

            LOGINFO("Step {}-2-2: Trigger cp to crash", i + 1);
            this->crash_and_recover(ops);
        }

        // Remove the next batch of keys in forward order
        LOGINFO("Step {}-3: Remove another batch in ascending order", i + 1) {
            int n = batch_num - 1;
            auto r = num_entries * n / batch_num - 1;
            auto l = num_entries * (n - 1) / batch_num;
            OperationList ops;
            for (auto k = l; k <= r; ++k) {
                ops.emplace_back(k, OperationType::Remove);
            }
            LOGINFO("Step {}-3-1: Remove keys in batch {}/{} ({} to {})", i + 1, n, batch_num, l, r);

            this->set_basic_flip(flip_point);
            for (auto [k, _]: ops) {
                LOGINFO("Removing key {}", k);
                this->remove_one(k, true);
            }
            this->visualize_keys("tree_merge_before_second_crash.dot");

            LOGINFO("Step {}-3-2: Trigger cp to crash", i + 1);
            this->crash_and_recover(ops);
        }

        // Remove the next batch of keys in random order
        LOGINFO("Step {}-4: Remove another batch in random order", i + 1) {
            int n = batch_num - 2;
            auto r = num_entries * n / batch_num - 1;
            auto l = num_entries * (n - 1) / batch_num;
            SequenceGenerator generator(0, 100, l, r);
            generator.fillRange(l, r);
            OperationList ops = generator.generateOperations(r - l + 1, false);

            LOGINFO("Step {}-4-1: Remove keys in batch {}/{} ({} to {})", i + 1, n, batch_num, l, r);

            this->set_basic_flip(flip_point);
            for (auto [k, _]: ops) {
                LOGINFO("Removing key {}", k);
                this->remove_one(k, true);
            }
            this->visualize_keys("tree_merge_before_third_crash.dot");

            LOGINFO("Step {}-4-2: Trigger cp to crash", i + 1);
            this->crash_and_recover(ops);
        }

        LOGINFO("Step {}-5: Cleanup the tree", i + 1);
        for (auto k = 0u; k < num_entries; ++k) {
            this->remove_one(k, false);
        }
        test_common::HSTestHelper::trigger_cp(true);
        this->get_all();
    }
}
//
// TYPED_TEST(IndexCrashTest, MergeCrash1) {
//     auto const num_entries = SISL_OPTIONS["num_entries"].as<uint32_t>();
//     vector<std::string> flips = {
//         "crash_flush_on_merge_at_parent", "crash_flush_on_merge_at_left_child", "crash_flush_on_freed_child"
//     };
//     SequenceGenerator generator(0 /*putFreq*/, 100 /* removeFreq*/, 0 /*start_range*/, num_entries - 1 /*end_range*/);
//     OperationList operations;
//     for (size_t i = 0; i < flips.size(); ++i) {
//         this->reset_btree();
//         LOGINFO("Step {}-1: Init btree", i + 1);
//         for (auto k = 0u; k < num_entries; ++k) {
//             this->put(k, btree_put_type::INSERT, true /* expect_success */);
//         }
//         test_common::HSTestHelper::trigger_cp(true);
//         this->print_keys("Inited tree");
//
//         LOGINFO("Step {}-2: Set flag {}", i + 1, flips[i]);
//         this->set_basic_flip(flips[i], 1, 10);
//         generator.reset();
//         generator.fillRange(0, num_entries - 1);
//
//         // Randomly remove some keys
//         std::random_device rd;
//         std::mt19937 gen(rd());
//         std::uniform_int_distribution<> dis(num_entries / 4, num_entries / 2);
//         auto num_keys_to_remove = dis(gen);
//         LOGINFO("Removing {} keys before crash", num_keys_to_remove);
//         operations = generator.generateOperations(num_keys_to_remove, false /* reset */);
//         for (auto [k, _]: operations) {
//             LOGINFO("Removing key {}", k);
//             this->remove_one(k, true);
//         }
//
//         LOGINFO("Step {}-3: Simulate crash and recover", i + 1);
//         this->crash_and_recover(operations, fmt::format("recover_tree_crash_{}.dot", i + 1));
//     }
// }
//
// TYPED_TEST(IndexCrashTest, MergeManualCrash) {
//     std::vector<std::string> flip_points = {
//         "crash_flush_on_merge_at_parent",
//         "crash_flush_on_merge_at_left_child",
//         "crash_flush_on_freed_child",
//     };
//
//     constexpr uint32_t num_entries = 28; // with max=5 & min=3
//
//     auto initTree = [this, num_entries]() {
//         for (auto k = 0u; k < num_entries; ++k) {
//             this->put(k, btree_put_type::INSERT, true /* expect_success */);
//         }
//         test_common::HSTestHelper::trigger_cp(true);
//         this->m_shadow_map.save(this->m_shadow_filename);
//     };
//
//     std::vector<OperationList> removing_scenarios = {
//         {
//             {27, OperationType::Remove},
//             {26, OperationType::Remove},
//             {25, OperationType::Remove},
//             {24, OperationType::Remove},
//             {23, OperationType::Remove},
//             {22, OperationType::Remove},
//         }, // Merge 2 rightmost leaf nodes in 1 action
//         {
//             {27, OperationType::Remove},
//             {26, OperationType::Remove},
//             {25, OperationType::Remove},
//             {24, OperationType::Remove},
//             {23, OperationType::Remove},
//             {20, OperationType::Remove},
//             {19, OperationType::Remove},
//         }, // Merge 3 rightmost leaf nodes in 1 action
//         {
//             {27, OperationType::Remove},
//             {26, OperationType::Remove},
//             {25, OperationType::Remove},
//             {24, OperationType::Remove},
//             {23, OperationType::Remove},
//             {22, OperationType::Remove},
//             {21, OperationType::Remove},
//             {20, OperationType::Remove},
//             {19, OperationType::Remove},
//         }, // Merge 3 rightmost leaf nodes in 2 actions
//         {
//             {23, OperationType::Remove},
//             {22, OperationType::Remove},
//             {11, OperationType::Remove},
//             {10, OperationType::Remove},
//             {13, OperationType::Remove},
//         }, // Merge from level=0 then level=1
//         // {
//         //     {16, OperationType::Remove},
//         // }, // Merge from level=1 then level=0 - need to set min=4
//     };
//
//     for (int i = 0; i < static_cast<int>(removing_scenarios.size()); i++) {
//         auto scenario = removing_scenarios[i];
//         auto s_idx = i + 1;
//         LOGINFO("\n\tTesting scenario {}", s_idx);
//         for (int j = 0; j < static_cast<int>(flip_points.size()); j++) {
//             const auto &flip_point = flip_points[j];
//             auto f_idx = j + 1;
//             LOGINFO("\n\t\t\t\tTesting flip point: {}", flip_point);
//
//             LOGINFO("Step {}-{}-1: Populate keys and flush", s_idx, f_idx);
//             initTree();
//             this->visualize_keys(fmt::format("tree_init.{}_{}.dot", s_idx, f_idx));
//
//             LOGINFO("Step {}-{}-2: Set crash flag, remove keys in reverse order", s_idx, f_idx);
//             this->set_basic_flip(flip_point);
//             for (auto k: scenario) {
//                 LOGINFO("Removing entry {}", k.first);
//                 this->remove_one(k.first);
//             }
//             this->visualize_keys(fmt::format("tree_before_first_crash.{}_{}.dot", s_idx, f_idx));
//             this->remove_flip(flip_point);
//
//             LOGINFO("Step {}-{}-3: Trigger cp to crash", s_idx, f_idx);
//             this->crash_and_recover(scenario);
//             test_common::HSTestHelper::trigger_cp(true);
//             this->get_all();
//
//             this->reset_btree();
//             test_common::HSTestHelper::trigger_cp(true);
//         }
//     }
// }
#endif

int main(int argc, char* argv[]) {
    int parsed_argc{argc};
    ::testing::GTEST_FLAG(filter) = "-*long_running*";
    ::testing::InitGoogleTest(&parsed_argc, argv);
    SISL_OPTIONS_LOAD(parsed_argc, argv, logging, test_index_crash_recovery, iomgr, test_common_setup);
    sisl::logging::SetLogger("test_index_crash_recovery");
    spdlog::set_pattern("[%D %T%z] [%^%L%$] [%t] %v");

    if (SISL_OPTIONS.count("seed")) {
        auto seed = SISL_OPTIONS["seed"].as< uint64_t >();
        LOGINFO("Using seed {} to sow the random generation", seed);
        g_re.seed(seed);
    }

#ifdef _PRERELEASE
    return RUN_ALL_TESTS();
#else
    return 0;
#endif
}
