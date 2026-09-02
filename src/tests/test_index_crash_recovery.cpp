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

#include <set>
#include <vector>
#include <sisl/utility/enum.hpp>
#include "common/homestore_config.hpp"
#include "common/resource_mgr.hpp"
#include "device/chunk.h"
#include "device/virtual_dev.hpp"
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

SISL_OPTION_GROUP(
    test_index_crash_recovery,
    (num_iters, "", "num_iters", "number of iterations for rand ops",
     ::cxxopts::value< uint32_t >()->default_value("500"), "number"),
    (num_entries, "", "num_entries", "number of entries to test with",
     ::cxxopts::value< uint32_t >()->default_value("5000"), "number"),
    (run_time, "", "run_time", "run time for io", ::cxxopts::value< uint32_t >()->default_value("360000"), "seconds"),
    (num_rounds, "", "num_rounds", "number of rounds to test with",
     ::cxxopts::value< uint32_t >()->default_value("100"), "number"),
    (num_entries_per_rounds, "", "num_entries_per_rounds", "number of entries per rounds",
     ::cxxopts::value< uint32_t >()->default_value("40"), "number"),
    (max_keys_in_node, "", "max_keys_in_node", "max_keys_in_node", ::cxxopts::value< uint32_t >()->default_value("20"),
     ""),
    (min_keys_in_node, "", "min_keys_in_node", "min_keys_in_node", ::cxxopts::value< uint32_t >()->default_value("6"),
     ""),
    (max_merge_level, "", "max_merge_level", "max merge level", ::cxxopts::value< uint8_t >()->default_value("1"), ""),
    (disable_merge, "", "disable_merge", "disable_merge", ::cxxopts::value< bool >()->default_value("0"), ""),
    (operation_list, "", "operation_list", "operation list instead of default created following by percentage",
     ::cxxopts::value< std::vector< std::string > >(), "operations [...]"),
    (preload_size, "", "preload_size", "number of entries to preload tree with",
     ::cxxopts::value< uint32_t >()->default_value("1000"), "number"),
    (init_device, "", "init_device", "init device", ::cxxopts::value< bool >()->default_value("1"), ""),
    (load_from_file, "", "load_from_file", "load from file", ::cxxopts::value< bool >()->default_value("0"), ""),
    (save_to_file, "", "save_to_file", "save to file", ::cxxopts::value< bool >()->default_value("0"), ""),
    (cleanup_after_shutdown, "", "cleanup_after_shutdown", "cleanup after shutdown",
     ::cxxopts::value< bool >()->default_value("1"), ""),
    (print_keys_verbose_logging, "", "print_keys_verbose_logging", "print_keys_verbose_logging",
     ::cxxopts::value< bool >()->default_value("0"), ""),
    (seed, "", "seed", "random engine seed, use random if not defined",
     ::cxxopts::value< uint64_t >()->default_value("0"), "number"))

void log_obj_life_counter() {
    std::string str;
    sisl::ObjCounterRegistry::foreach ([&str](const std::string& name, int64_t created, int64_t alive) {
        fmt::format_to(std::back_inserter(str), "{}: created={} alive={}\n", name, created, alive);
    });
    LOGINFO("Object Life Counter\n:{}", str);
}

#define print_keys_logging(msg)                                                                                        \
    if (SISL_OPTIONS.count("print_keys_verbose_logging")) { this->print_keys(msg); }

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
        if (putFreq_ == 100 && end_range_ - start_range_ + 1 - in_use_key_cnt_.load() < numOperations) {
            LOGDEBUG("All keys are in use, skipping operation generation. end_range_ {} start_range_ {} "
                     "in_use_key_cnt_ {}, numOperations {}",
                     end_range_, start_range_, in_use_key_cnt_.load(), numOperations);
            return operations;
        }
        if (removeFreq_ == 100 && in_use_key_cnt_.load() < numOperations) {
            LOGDEBUG("Not enough keys are in use, skipping operation generation. in_use_key_cnt_ {} numOperations {}",
                     in_use_key_cnt_.load(), numOperations);
            return operations;
        }

        while (operations.size() < numOperations) {
            uint32_t key = keyDist_(g_re);
            auto [it, inserted] = keyStates.try_emplace(key, false);
            auto& inUse = it->second;

            OperationType operation = static_cast< OperationType >(opTypeDist_(g_re));

            if (operation == OperationType::Put && !inUse) {
                operations.emplace_back(key, OperationType::Put);
                inUse = true;
                in_use_key_cnt_.fetch_add(1);
            } else if (operation == OperationType::Remove && inUse) {
                operations.emplace_back(key, OperationType::Remove);
                inUse = false;
                in_use_key_cnt_.fetch_sub(1);
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

    __attribute__((noinline)) static std::string printOperations(const OperationList& operations) {
        std::ostringstream oss;
        auto count = 1;
        for (const auto& [key, opType] : operations) {
            std::string opTypeStr = (opType == OperationType::Put) ? "Put" : "Remove";
            oss << count++ << "- {" << key << ", " << opTypeStr << "}\n";
        }
        return oss.str();
    }

    __attribute__((noinline)) static std::string printKeysOccurrences(const OperationList& operations) {
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

    __attribute__((noinline)) static std::string printKeyOccurrences(const OperationList& operations, uint64_t key) {
        std::ostringstream oss;
        auto keyOccurrences = inspect(operations, key);
        oss << "Occurrences of key " << key << ":\n";
        for (const auto& [index, operation] : keyOccurrences) {
            std::string opTypeStr = (operation == OperationType::Put) ? "Put" : "Remove";
            oss << "Index: " << index << ", Operation: " << opTypeStr << "\n";
        }
        return oss.str();
    }

    static std::set< uint64_t > collectUniqueKeys(const OperationList& operations) {
        std::set< uint64_t > keys;
        for (const auto& [key, _] : operations) {
            keys.insert(key);
        }
        return keys;
    }
    static void save_to_file(std::string filename, const OperationList& operations) {
        std::ofstream file(filename);
        if (file.is_open()) {
            for (const auto& [key, opType] : operations) {
                file << key << " " << static_cast< int >(opType) << "\n";
            }
            file.close();
        }
    }

    static OperationList load_from_file(std::string filename) {
        std::ifstream file(filename);
        OperationList operations;
        if (file.is_open()) {
            std::string line;
            while (std::getline(file, line)) {
                std::istringstream iss(line);
                uint64_t key;
                int opType;
                iss >> key >> opType;
                operations.emplace_back(key, static_cast< OperationType >(opType));
            }
            file.close();
        }
        return operations;
    }

    void reset() { keyStates.clear(); }

private:
    int putFreq_;
    int removeFreq_;
    uint64_t start_range_;
    uint64_t end_range_;
    std::uniform_int_distribution<> keyDist_;
    std::discrete_distribution<> opTypeDist_;
    std::map< uint64_t, bool > keyStates;
    std::atomic< uint64_t > in_use_key_cnt_{0};

    void updateOperationTypeDistribution() {
        opTypeDist_ =
            std::discrete_distribution<>({static_cast< double >(putFreq_), static_cast< double >(removeFreq_)});
    }
};

#ifdef _PRERELEASE

struct long_running_crash_options {
    uint32_t put_freq;
    std::vector< std::string > put_flips{};
    std::vector< std::string > remove_flips{};
    uint32_t num_entries{SISL_OPTIONS["num_entries"].as< uint32_t >()};
    uint32_t preload_size{SISL_OPTIONS["preload_size"].as< uint32_t >()};
    uint32_t rounds{SISL_OPTIONS["num_rounds"].as< uint32_t >()};
    uint32_t num_entries_per_rounds{SISL_OPTIONS["num_entries_per_rounds"].as< uint32_t >()};
    bool load_mode{SISL_OPTIONS.count("load_from_file") > 0};
    bool save_mode{SISL_OPTIONS.count("save_to_file") > 0};
};

template < typename TestType >
struct IndexCrashTest : public test_common::HSTestHelper, BtreeTestHelper< TestType >, public ::testing::Test {
    using T = TestType;
    using K = typename TestType::KeyType;
    using V = typename TestType::ValueType;
    class TestIndexServiceCallbacks : public IndexServiceCallbacks {
    public:
        TestIndexServiceCallbacks(IndexCrashTest* test) : m_test(test) {}

        std::shared_ptr< IndexTableBase > on_index_table_found(superblk< index_table_sb >&& sb) override {
            LOGINFO("Index table recovered, root bnode_id {} uuid {} ordinal {} version {}",
                    static_cast< uint64_t >(sb->root_node), boost::uuids::to_string(sb->uuid), sb->ordinal,
                    sb->root_link_version);

            m_test->m_cfg = BtreeConfig(hs()->index_service().node_size());
            m_test->m_cfg.m_leaf_node_type = T::leaf_node_type;
            m_test->m_cfg.m_int_node_type = T::interior_node_type;
            m_test->m_cfg.m_max_keys_in_node = SISL_OPTIONS["max_keys_in_node"].as< uint32_t >();
            m_test->m_cfg.m_min_keys_in_node = SISL_OPTIONS["min_keys_in_node"].as< uint32_t >();
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

        this->m_cfg = BtreeConfig(hs()->index_service().node_size());
        this->m_cfg.m_max_keys_in_node = SISL_OPTIONS["max_keys_in_node"].as< uint32_t >();
        this->m_cfg.m_min_keys_in_node = SISL_OPTIONS["min_keys_in_node"].as< uint32_t >();
        LOGINFO("Node size {}, max_keys_in_node {}, min_keys_in_node {}", this->m_cfg.node_size(),
                this->m_cfg.m_max_keys_in_node, this->m_cfg.m_min_keys_in_node);
        auto uuid = boost::uuids::random_generator()();
        auto parent_uuid = boost::uuids::random_generator()();

        homestore::hs()->resource_mgr().reset_dirty_buf_qd();

        // Create index table and attach to index service.
        BtreeTestHelper< TestType >::SetUp();
        if (this->m_bt == nullptr || SISL_OPTIONS["init_device"].as< bool >()) {
            this->m_bt = std::make_shared< typename T::BtreeType >(uuid, parent_uuid, 0, this->m_cfg);
            auto num_keys = this->m_bt->count_keys(this->m_bt->root_node_id());
            //            LOGINFO("Creating new index table with uuid {} - init_device:{:s} bt: {} root id {}, num of
            //            keys {}",  boost::uuids::to_string(uuid), SISL_OPTIONS["init_device"].as< bool >(),
            //            this->m_bt, this->m_bt->root_node_id(), num_keys);
            LOGINFO("Creating new index table with uuid {} - root id {}, num of keys {}", boost::uuids::to_string(uuid),
                    this->m_bt->root_node_id(), num_keys);

        } else {
            populate_shadow_map();
        }

        hs()->index_service().add_index_table(this->m_bt);
        LOGINFO("Added index table to index service with uuid {} - total tables in the system is currently {}",
                boost::uuids::to_string(uuid), hs()->index_service().num_tables());
    }

    void populate_shadow_map() {
        LOGINFO("Populating shadow map");
        this->m_shadow_map.load(m_shadow_filename);
        auto num_keys = this->m_bt->count_keys(this->m_bt->root_node_id());
        LOGINFO("Shadow map size {} - btree keys {} - root id {}", this->m_shadow_map.size(), num_keys,
                this->m_bt->root_node_id());
        ASSERT_EQ(this->m_shadow_map.size(), num_keys) << "shadow map size and tree size mismatch";
        this->get_all();
    }

    void reset_btree() {
        LOGINFO("Destroying index btree with uuid {} root id {}", boost::uuids::to_string(this->m_bt->uuid()),
                this->m_bt->root_node_id());
        hs()->index_service().remove_index_table(this->m_bt);
        this->m_bt->destroy();
        this->trigger_cp(true);
        ASSERT_EQ(hs()->index_service().num_tables(), 0) << "After destroying the index table, some table still exists";

        auto uuid = boost::uuids::random_generator()();
        auto parent_uuid = boost::uuids::random_generator()();
        this->m_bt = std::make_shared< typename T::BtreeType >(uuid, parent_uuid, 0, this->m_cfg);
        hs()->index_service().add_index_table(this->m_bt);
        auto num_keys = this->m_bt->count_keys(this->m_bt->root_node_id());
        this->m_shadow_map.range_erase(0, SISL_OPTIONS["num_entries"].as< uint32_t >() - 1);
        this->m_shadow_map.save(m_shadow_filename);
        LOGINFO("Reset btree with uuid {} - erase shadow map {}", boost::uuids::to_string(uuid), m_shadow_filename);
    }

    void destroy_btree() {
        hs()->index_service().remove_index_table(this->m_bt);
        this->m_bt->destroy();
        this->trigger_cp(true);
        this->m_shadow_map.range_erase(0, SISL_OPTIONS["num_entries"].as< uint32_t >() - 1);
        this->m_shadow_map.save(m_shadow_filename);
        LOGINFO("destroy btree - erase shadow map {}", m_shadow_filename);
    }

    // Install a brand-new empty btree (without destroying the old one first).
    // Used after recovery to replace a stale/destroyed m_bt so TearDown() is safe.
    void install_fresh_btree(uint32_t erase_up_to_key = 0) {
        auto uuid = boost::uuids::random_generator()();
        auto parent_uuid = boost::uuids::random_generator()();
        this->m_bt = std::make_shared< typename T::BtreeType >(uuid, parent_uuid, 0, this->m_cfg);
        hs()->index_service().add_index_table(this->m_bt);
        if (erase_up_to_key > 0) { this->m_shadow_map.range_erase(0, erase_up_to_key - 1); }
        this->m_shadow_map.save(m_shadow_filename);
        LOGINFO("Installed fresh btree with uuid {}", boost::uuids::to_string(uuid));
    }

    void restart_homestore(uint32_t shutdown_delay_sec = 3) override {
        this->params(HS_SERVICE::INDEX).index_svc_cbs = new TestIndexServiceCallbacks(this);
        LOGINFO("\n\n\n\n\n\n shutdown homestore for index service Test\n\n\n\n\n");
        test_common::HSTestHelper::restart_homestore(shutdown_delay_sec);
    }

    void reapply_after_crash() {
        ShadowMap< K, V > snapshot_map{this->m_shadow_map.max_keys()};
        snapshot_map.load(m_shadow_filename);
        // LOGINFO("\tSnapshot before crash\n{}", snapshot_map.to_string());
        auto diff = this->m_shadow_map.diff(snapshot_map);

        // visualize tree after crash
        // std::string recovered_tree_filename = "tree_after_crash_" + to_string(rand() % 100) + ".dot";
        // this->visualize_keys(recovered_tree_filename);
        // LOGINFO(" tree after recovered stored in {}", recovered_tree_filename);

        std::string dif_str = "Keys[";
        for (const auto& [k, _] : diff) {
            dif_str += fmt::format("{} ", k.key());
        }
        dif_str += "]";
        LOGINFO("Diff between shadow map and snapshot map\n{}\n", dif_str);

        for (const auto& [k, addition] : diff) {
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
        LOGINFO("Teardown with Root bnode_id {} tree size: {}", this->m_bt->root_node_id(), this->tree_key_count());
        BtreeTestHelper< TestType >::TearDown();
        this->shutdown_homestore(false);
    }

    void crash_and_recover(uint32_t s_key, uint32_t e_key) {
        // this->print_keys("Btree prior to CP and susbsequent simulated crash: ");
        trigger_cp(false);
        this->wait_for_crash_recovery(true);
        // this->visualize_keys("tree_after_crash_" + std::to_string(s_key) + "_" + std::to_string(e_key) + ".dot");

        // this->print_keys("Post crash and recovery, btree structure: ");
        this->reapply_after_crash();

        // this->print_keys("Post reapply, btree structure: ");

        this->get_all();
        LOGINFO("Expect to have [{},{}) in tree and it is actually{} ", s_key, e_key, tree_key_count());
        ASSERT_EQ(this->m_shadow_map.size(), this->tree_key_count()) << "shadow map size and tree size mismatch";
    }

    void sanity_check(OperationList& operations) const {
        std::set< uint64_t > new_keys;
        std::transform(operations.begin(), operations.end(), std::inserter(new_keys, new_keys.end()),
                       [](const Operation& operation) { return operation.first; });
        uint32_t count = 0;
        this->m_shadow_map.foreach ([this, new_keys, &count](K key, V value) {
            // discard the new keys to check
            if (new_keys.find(key.key()) != new_keys.end()) { return; }
            count++;
            auto copy_key = std::make_unique< K >();
            *copy_key = key;
            auto out_v = std::make_unique< V >();
            auto req = BtreeSingleGetRequest{copy_key.get(), out_v.get()};
            req.enable_route_tracing();
            const auto ret = this->m_bt->get(req);
            if (ret != btree_status_t::success) {
                this->print_keys(fmt::format("Sanity check: key {}", key.key()));
                this->dump_to_file("sanity_fail.txt");
            }
            ASSERT_EQ(ret, btree_status_t::success) << "Missing key " << key << " in btree but present in shadow map";
        });
        LOGINFO("Sanity check passed for {} keys!", count);
    }

    void crash_and_recover_common(OperationList& operations, std::string filename = "") {
        print_keys_logging("Btree prior to CP and susbsequent simulated crash: ");
        LOGINFO("Before Crash: {} keys in shadow map and it is actually {} keys in tree - operations size {}",
                this->m_shadow_map.size(), tree_key_count(), operations.size());

        if (!filename.empty()) {
            std::string b_filename = filename + "_before_crash.dot";
            LOGINFO("Visualize the tree before crash file {}", b_filename);
            this->visualize_keys(b_filename);
        }

        print_keys_logging("Before crash");
        trigger_cp(false);
        LOGINFO("waiting for crash to recover");
        this->wait_for_crash_recovery(true);

        if (!filename.empty()) {
            std::string rec_filename = filename + "_after_recovery.dot";
            LOGINFO("Visualize the tree file after recovery : {}", rec_filename);
            this->visualize_keys(rec_filename);
        }
        print_keys_logging("Post crash and recovery, btree structure: ");
        sanity_check(operations);
        //        Added to the index service right after recovery. Not needed here
        //        test_common::HSTestHelper::trigger_cp(true);
        LOGINFO("Before Reapply: {} keys in shadow map and actually {} in trees operation size {}",
                this->m_shadow_map.size(), tree_key_count(), operations.size());
        this->reapply_after_crash(operations);
        if (!filename.empty()) {
            std::string re_filename = filename + "_after_reapply.dot";
            LOGINFO("Visualize the tree after reapply {}", re_filename);
            this->visualize_keys(re_filename);
        }
        print_keys_logging("Post reapply, btree structure: ");

        this->get_all();
        LOGINFO("After reapply: {} keys in shadow map and actually {} in tress", this->m_shadow_map.size(),
                tree_key_count());
        ASSERT_EQ(this->m_shadow_map.size(), this->m_bt->count_keys(this->m_bt->root_node_id()))
            << "shadow map size and tree size mismatch";
    }

    void crash_and_recover(std::string& flip, OperationList& operations, std::string filename = "") {
        this->remove_flip(flip);
        this->crash_and_recover_common(operations, filename);
    }

    void crash_and_recover(std::vector< std::string >& flips, OperationList& operations, std::string filename = "") {
        for (auto const& flip : flips) {
            this->remove_flip(flip);
        }
        this->crash_and_recover_common(operations, filename);
    }

    uint32_t tree_key_count() { return this->m_bt->count_keys(this->m_bt->root_node_id()); }

    void long_running_crash(long_running_crash_options const& crash_test_options) {
        // set putFreq 100 for the initial load
        SequenceGenerator generator(100 /*putFreq*/, 0 /* removeFreq*/, 0 /*start_range*/,
                                    crash_test_options.num_entries - 1 /*end_range*/);

        std::vector< std::string > flips;
        OperationList operations;
        auto m_start_time = Clock::now();
        auto time_to_stop = [this, m_start_time]() { return (get_elapsed_time_sec(m_start_time) > this->m_run_time); };
        double elapsed_time, progress_percent, last_progress_time = 0;
        bool renew_btree_after_crash = false;
        auto cur_put_flip_idx = 0;
        auto cur_remove_flip_idx = 0;
        std::uniform_int_distribution<> dis(1, 100);
        int flip_percentage = 90; // Set the desired percentage here
        bool normal_execution = true;
        bool clean_shutdown = true;
        // if it is safe then delete all previous save files
        if (crash_test_options.save_mode) {
            std::filesystem::remove_all("/tmp/operations_*.txt");
            std::filesystem::remove_all("/tmp/flips_history.txt");
        }
        // init tree
        LOGINFO("Step 0: Fill up the tree with {} entries", crash_test_options.preload_size);
        if (crash_test_options.load_mode) {
            operations = SequenceGenerator::load_from_file(fmt::format("/tmp/operations_0.txt"));
        } else {
            operations = generator.generateOperations(crash_test_options.preload_size, true /* reset */);
            if (crash_test_options.save_mode) {
                SequenceGenerator::save_to_file(fmt::format("/tmp/operations_0.txt"), operations);
            }
        }

        LOGDEBUG("Lets before crash print operations\n{}", SequenceGenerator::printOperations(operations));
        uint32_t num_keys{0};

        for (auto [k, _] : operations) {
            this->put(k, btree_put_type::INSERT, true /* expect_success */);
            num_keys++;
        }

        generator.setPutFrequency(crash_test_options.put_freq);
        generator.setRemoveFrequency(100 - crash_test_options.put_freq);

        // Trigger the cp to make sure middle part is successful
        LOGINFO("Step 0-1: Flush all the entries so far");
        test_common::HSTestHelper::trigger_cp(true);
        this->get_all();
        this->m_shadow_map.save(this->m_shadow_filename);
        print_keys_logging("reapply: after preload");
        this->visualize_keys("tree_after_preload.dot");

        for (uint32_t round = 1; round <= crash_test_options.rounds && !time_to_stop(); round++) {
            LOGINFO("\n\n\n\n\n\nRound {} of {}\n\n\n\n\n\n", round, crash_test_options.rounds);
            bool print_time = false;
            elapsed_time = get_elapsed_time_sec(m_start_time);
            print_keys_logging(fmt::format("Round {}: before crash", round));

            if (crash_test_options.load_mode) {
                operations = SequenceGenerator::load_from_file(fmt::format("/tmp/operations_{}.txt", round));
            } else {
                operations = generator.generateOperations(crash_test_options.num_entries_per_rounds,
                                                          renew_btree_after_crash /* reset */);
                if (crash_test_options.save_mode) {
                    SequenceGenerator::save_to_file(fmt::format("/tmp/operations_{}.txt", round), operations);
                }
            }
            if (operations.empty()) {
                LOGDEBUG("No operations generated, skipping round {}", round);
                continue;
            }

            flips.clear();
            if (crash_test_options.load_mode) {
                std::ifstream file("/tmp/flips_history.txt");
                std::string line;
                bool found = false;
                for (uint32_t i = 0; i < round && std::getline(file, line); i++) {
                    if (i == round - 1) {
                        found = true;
                        break;
                    }
                }
                if (found && !line.empty()) {
                    if (line == "normal") {
                        normal_execution = true;
                    } else {
                        normal_execution = false;
                        std::istringstream iss(line);
                        std::string flip;
                        while (iss >> flip) {
                            flips.emplace_back(flip);
                        }
                        auto log_str = fmt::format("Step 1-{}: Set flag", round);
                        for (auto const& f : flips) {
                            log_str += fmt::format(" {}", f);
                            this->set_basic_flip(f, 1, 100);
                        }
                        LOGINFO("{}", log_str);
                    }
                }
                file.close();
            } else {
                if (dis(g_re) <= flip_percentage) {
                    if (!crash_test_options.put_flips.empty()) {
                        flips.emplace_back(
                            crash_test_options.put_flips[cur_put_flip_idx++ % crash_test_options.put_flips.size()]);
                    }
                    if (!crash_test_options.remove_flips.empty()) {
                        flips.emplace_back(crash_test_options.remove_flips[cur_remove_flip_idx++ %
                                                                           crash_test_options.remove_flips.size()]);
                    }
                    auto log_str = fmt::format("Step 1-{}: Set flag", round);
                    for (auto const& f : flips) {
                        log_str += fmt::format(" {}", f);
                        this->set_basic_flip(f, 1, 100);
                    }
                    LOGINFO("{}", log_str);
                    normal_execution = false;
                } else {
                    normal_execution = true;
                    LOGINFO("Step 1-{}: No flip set", round);
                }
                if (crash_test_options.save_mode) {
                    // save the filp name to a file for later use
                    std::ofstream file("/tmp/flips_history.txt", std::ios::app);
                    if (file.is_open()) {
                        std::string out_line{"normal"};
                        if (!normal_execution) {
                            out_line = flips[0];
                            for (size_t i = 1; i < flips.size(); i++) {
                                out_line += " " + flips[i];
                            }
                        }
                        file << out_line << "\n";
                    }
                    file.close();
                }
            }

            LOGDEBUG("Lets before crash print operations\n{}", SequenceGenerator::printOperations(operations));

            for (auto [k, op] : operations) {
                if (op == OperationType::Remove) {
                    if (num_keys < 1) {
                        // remove flips and continue
                        for (auto const& flip : flips) {
                            this->remove_flip(flip);
                        }
                        continue;
                    }
                    LOGDEBUG("Removing key {}", k);
                    this->remove_one(k, true /* expect_success */);
                    num_keys--;
                } else {
                    if (num_keys >= crash_test_options.num_entries) {
                        // remove flips and continue
                        for (auto const& flip : flips) {
                            this->remove_flip(flip);
                        }
                        continue;
                    }
                    LOGDEBUG("Inserting key {}", k);
                    this->put(k, btree_put_type::INSERT, true /* expect_success */);
                    num_keys++;
                }
                if (!time_to_stop()) {
                    static bool print_alert = false;
                    if (print_alert) {
                        LOGINFO("It is time to stop but let's finish this round and then stop!");
                        print_alert = false;
                    }
                }
            }
            if (normal_execution) {
                if (clean_shutdown) {
                    this->m_shadow_map.save(this->m_shadow_filename);
                    this->restart_homestore();
                } else {
                    test_common::HSTestHelper::trigger_cp(true);
                    this->get_all();
                }
            } else {
                // remove the flips so that they do not get triggered erroneously
                this->crash_and_recover(flips, operations, fmt::format("long_tree_{}", round));
            }
            if (elapsed_time - last_progress_time > 30) {
                last_progress_time = elapsed_time;
                print_time = true;
            }
            if (print_time) {
                LOGINFO(
                    "\n\n\n\t\t\tProgress: {} rounds of total {} ({:.2f}%) completed - Elapsed time: {:.0f} seconds of "
                    "total {} ({:.2f}%) - {} keys of maximum {} keys ({:.2f}%) inserted\n\n\n",
                    round, crash_test_options.rounds, round * 100.0 / crash_test_options.rounds, elapsed_time,
                    this->m_run_time, elapsed_time * 100.0 / this->m_run_time, this->tree_key_count(),
                    crash_test_options.num_entries, this->tree_key_count() * 100.0 / crash_test_options.num_entries);
            }
            print_keys_logging(fmt::format("reapply: after round {}", round));
            if (renew_btree_after_crash) { this->reset_btree(); };
        }
        this->destroy_btree();
        log_obj_life_counter();
    }

protected:
    const std::string m_shadow_filename = "/tmp/shadow_map_index_recovery.txt";
};

// Crash recovery can test one simple btree, since focus is not on btree test itself, but index recovery
using BtreeTypes = testing::Types< FixedLenBtree, PrefixIntervalBtree >;
TYPED_TEST_SUITE(IndexCrashTest, BtreeTypes);

TYPED_TEST(IndexCrashTest, CrashBeforeFirstCp) {
    this->m_shadow_map.range_erase(0, SISL_OPTIONS["num_entries"].as< uint32_t >() - 1);
    this->m_shadow_map.save(this->m_shadow_filename);
    // Simulate the crash even before first cp
    this->set_basic_flip("crash_flush_on_root");

    auto ops = this->build_op_list({"put:100"});
    this->multi_op_execute(ops, true /* skip_preload */);

    // Trigger a cp, which should induce the crash and wait for hs to recover
    test_common::HSTestHelper::trigger_cp(false);
    this->wait_for_crash_recovery(true);

    // Post crash, load the shadow_map into a new instance and compute the diff. Redo the operation
    this->reapply_after_crash();
}

TYPED_TEST(IndexCrashTest, SplitOnLeftEdge) {
    this->m_shadow_map.range_erase(0, SISL_OPTIONS["num_entries"].as< uint32_t >() - 1);
    this->m_shadow_map.save(this->m_shadow_filename);
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
    bool renew_btree_after_crash = true;
    for (size_t i = 0; i < flips.size(); ++i) {
        LOGINFO("Step 1-{}: Set flag {}", i + 1, flips[i]);
        this->set_basic_flip(flips[i]);
        operations = generator.generateOperations(num_entries - 1, renew_btree_after_crash /* reset */);
        //        LOGINFO("Batch {} Operations:\n {} \n ", i + 1, generator.printOperations(operations));
        //        LOGINFO("Detailed Key Occurrences for Batch {}:\n {} \n ", i + 1,
        //        generator.printKeyOccurrences(operations));
        for (auto [k, _] : operations) {
            //          LOGINFO("\t\t\t\t\t\t\t\t\t\t\t\t\tupserting entry {}", k);
            this->put(k, btree_put_type::INSERT, true /* expect_success */);
        }
        this->crash_and_recover(flips[i], operations, fmt::format("recover_tree_crash_{}.dot", i + 1));
        if (renew_btree_after_crash) { this->reset_btree(); };
    }
}

// Scenario: first root split (depth 0 → 1), crash while writing the SB (meta_buf).
//
// Setup: insert max_keys/2 keys and checkpoint to establish a durable leaf root (depth=0).
// Then insert more keys until the first root split fires (depth becomes 1), with
// "crash_flush_on_meta" armed so that the crash fires the moment the SB write begins.
//
// Disk state at crash:
//   - new_root_buf is durable (Fix 2 pre-flush wrote it before the normal DAG flush).
//   - old_root (the modified leaf) is durable in split state.
//   - SB still names the old_root as root.
//
// Expected recovery (Fix 2): the journal identifies new_root_buf as the intended root,
// persisted_root_was_committed() confirms old_root was written, so new_root_buf is
// promoted.  After recovery depth == 1 and all keys are intact.
TYPED_TEST(IndexCrashTest, CrashAtMetaBufOnFirstRootSplit) {
    const uint32_t max_keys = SISL_OPTIONS["max_keys_in_node"].as< uint32_t >();
    const uint32_t durable_key_count = max_keys / 2;

    for (uint32_t k = 0; k < durable_key_count; ++k) {
        this->put(k, btree_put_type::INSERT, true /* expect_success */);
    }
    test_common::HSTestHelper::trigger_cp(true);
    this->m_shadow_map.save(this->m_shadow_filename);
    auto const durable_root = this->m_bt->root_node_id();
    ASSERT_EQ(this->m_bt->get_btree_depth(), 0);

    this->set_basic_flip("crash_flush_on_meta");
    uint32_t next_key = durable_key_count;
    while (this->m_bt->get_btree_depth() == 0) {
        this->put(next_key++, btree_put_type::INSERT, true /* expect_success */);
    }
    ASSERT_NE(this->m_bt->root_node_id(), durable_root);
    ASSERT_EQ(this->m_bt->get_btree_depth(), 1);
    ASSERT_TRUE(hs()->crash_simulator().will_crash());

    test_common::HSTestHelper::trigger_cp(false);
    this->wait_for_crash_recovery(true);

    ASSERT_EQ(this->m_bt->get_btree_depth(), 1);
    this->reapply_after_crash();
    this->get_all();
}

// Scenario: first root split (depth 0 → 1), crash after old_root is flushed but before
// new_root_buf is written.
//
// Setup: same as CrashAtMetaBufOnFirstRootSplit, but "crash_flush_on_root" fires when
// the new_root_buf write begins, so old_root reaches disk in its split state while
// new_root_buf has not yet been written.
//
// Disk state at crash:
//   - old_root is durable with edge_info=EMPTY and next_bnode=child_node2 (split state).
//   - new_root_buf has NOT been written (Fix 2 pre-flush was interrupted).
//   - SB still names old_root.
//
// Expected recovery: Fix 2 pre-flush guarantees new_root_buf is written before old_root
// reaches disk (Fix 2 barrier), so new_root_buf must be durable.  Recovery identifies
// it via the journal and promotes it.  After recovery depth == 1 and all keys are intact.
TYPED_TEST(IndexCrashTest, CrashAfterOldRootFlushOnFirstRootSplit) {
    const uint32_t max_keys = SISL_OPTIONS["max_keys_in_node"].as< uint32_t >();
    const uint32_t durable_key_count = max_keys / 2;

    for (uint32_t k = 0; k < durable_key_count; ++k) {
        this->put(k, btree_put_type::INSERT, true /* expect_success */);
    }
    test_common::HSTestHelper::trigger_cp(true);
    this->m_shadow_map.save(this->m_shadow_filename);
    auto const durable_root = this->m_bt->root_node_id();
    ASSERT_EQ(this->m_bt->get_btree_depth(), 0);

    this->set_basic_flip("crash_flush_on_root");
    uint32_t next_key = durable_key_count;
    while (this->m_bt->get_btree_depth() == 0) {
        this->put(next_key++, btree_put_type::INSERT, true /* expect_success */);
    }
    ASSERT_NE(this->m_bt->root_node_id(), durable_root);
    ASSERT_EQ(this->m_bt->get_btree_depth(), 1);
    ASSERT_TRUE(hs()->crash_simulator().will_crash());

    test_common::HSTestHelper::trigger_cp(false);
    this->wait_for_crash_recovery(true);

    ASSERT_EQ(this->m_bt->get_btree_depth(), 1);
    this->reapply_after_crash();
    this->get_all();
}

// Scenario: first root split (depth 0 → 1), crash during Fix 2's pre-flush barrier
// before any node of the split reaches disk.
//
// Setup: same initial state (durable leaf root at depth=0), but "crash_during_root_preflush"
// fires inside the async pre-flush writes, before the normal DAG flush starts.
// crash_simulator.set_will_crash(true) is called explicitly because this flip fires
// before the CP engine's own crash point.
//
// Disk state at crash:
//   - Neither new_root_buf nor old_root has been written in the crashed CP.
//   - The tree on disk is still in the pre-split consistent state (depth=0, old leaf root intact).
//   - SB still names the original durable leaf root.
//
// Expected recovery: because old_root was never written in split state,
// persisted_root_was_committed() returns false, new_root_buf is discarded, and the tree
// reverts to its last fully consistent checkpoint.  After recovery root_node_id equals
// durable_root and depth == 0.  reapply_after_crash re-inserts all post-CP keys.
TYPED_TEST(IndexCrashTest, CrashDuringRootPreflushOnFirstRootSplit) {
    const uint32_t max_keys = SISL_OPTIONS["max_keys_in_node"].as< uint32_t >();
    const uint32_t durable_key_count = max_keys / 2;

    for (uint32_t k = 0; k < durable_key_count; ++k) {
        this->put(k, btree_put_type::INSERT, true /* expect_success */);
    }
    test_common::HSTestHelper::trigger_cp(true);
    this->m_shadow_map.save(this->m_shadow_filename);
    auto const durable_root = this->m_bt->root_node_id();
    ASSERT_EQ(this->m_bt->get_btree_depth(), 0);

    this->set_basic_flip("crash_during_root_preflush");
    hs()->crash_simulator().set_will_crash(true);
    uint32_t next_key = durable_key_count;
    while (this->m_bt->get_btree_depth() == 0) {
        this->put(next_key++, btree_put_type::INSERT, true /* expect_success */);
    }
    ASSERT_NE(this->m_bt->root_node_id(), durable_root);
    ASSERT_EQ(this->m_bt->get_btree_depth(), 1);
    ASSERT_TRUE(hs()->crash_simulator().will_crash());

    test_common::HSTestHelper::trigger_cp(false);
    this->wait_for_crash_recovery(true);

    ASSERT_EQ(this->m_bt->root_node_id(), durable_root);
    ASSERT_EQ(this->m_bt->get_btree_depth(), 0);
    this->reapply_after_crash();
    this->get_all();
}

// Scenario: second (or higher) root split (depth N → N+1), crash while writing the SB.
//
// Setup: insert max_keys+1 keys and checkpoint to establish a durable level-1 root.
// Then insert max_keys*max_keys more keys to trigger one or more additional root splits,
// with "crash_flush_on_meta" armed so the crash fires when the SB write begins.
//
// Disk state at crash:
//   - new_root_buf (and any intermediate new roots) are durable via Fix 2 pre-flush.
//   - old_root (level-1 internal node) is durable in split state.
//   - SB still names the level-1 old_root.
//
// Expected recovery: same Fix 2 path as the first-split cases, but exercised on a
// multi-level tree to confirm that the journal-based root promotion works regardless of
// tree height.  After recovery depth > persisted_depth and all keys are intact.
TYPED_TEST(IndexCrashTest, CrashAtMetaBufOnSecondRootSplit) {
    const uint32_t max_keys = SISL_OPTIONS["max_keys_in_node"].as< uint32_t >();

    // Establish a durable level-1 root before triggering the crash-sensitive level-1 -> level-2 split.
    for (uint32_t k = 0; k <= max_keys; ++k) {
        this->put(k, btree_put_type::INSERT, true /* expect_success */);
    }
    test_common::HSTestHelper::trigger_cp(true);
    this->m_shadow_map.save(this->m_shadow_filename);
    auto const persisted_root = this->m_bt->root_node_id();
    auto const persisted_depth = this->m_bt->get_btree_depth();

    this->set_basic_flip("crash_flush_on_meta");
    const uint32_t phase2_count = max_keys * max_keys;
    for (uint32_t k = max_keys + 1; k <= max_keys + phase2_count; ++k) {
        this->put(k, btree_put_type::INSERT, true /* expect_success */);
    }
    ASSERT_NE(this->m_bt->root_node_id(), persisted_root);
    ASSERT_GT(this->m_bt->get_btree_depth(), persisted_depth);
    ASSERT_TRUE(hs()->crash_simulator().will_crash());

    test_common::HSTestHelper::trigger_cp(false);
    this->wait_for_crash_recovery(true);

    ASSERT_GT(this->m_bt->get_btree_depth(), persisted_depth);
    this->reapply_after_crash();
    this->get_all();
}

// Scenario: second (or higher) root split, crash after old_root is flushed but before
// new_root_buf is written; then crash a second time without a recovery CP to prove
// that replaying the same journal and re-promoting the same root is idempotent.
//
// Setup: establish a durable level-1 root, then arm both "crash_flush_on_root" and
// "skip_cp_after_index_root_recovery".  The first flip causes the crash after old_root
// hits disk; the second flip suppresses the forced recovery CP so the original journal
// remains on disk unchanged after the first recovery.
//
// Disk state at first crash:
//   - old_root is durable in split state; new_root_buf is durable (Fix 2 pre-flush).
//   - SB still names old_root.
//
// First recovery: Fix 2 promotes new_root_buf; depth > persisted_depth.
//
// Second crash (immediate, no recovery CP written):
//   - The journal on disk still records the same root-change.
//   - new_root_buf is already the in-memory root, and its blkid is already in the SB
//     (written by set_root_from_committed_buf during the first recovery).
//
// Second recovery: the journal candidate is re-evaluated; set_root_from_committed_buf
// detects the SB already names new_root_buf and is a no-op.  This verifies that
// promoting an already-promoted root does not corrupt the tree.
// After both recoveries depth > persisted_depth and all keys are intact.
TYPED_TEST(IndexCrashTest, CrashAfterOldRootFlushOnSecondRootSplit) {
    const uint32_t max_keys = SISL_OPTIONS["max_keys_in_node"].as< uint32_t >();

    for (uint32_t k = 0; k <= max_keys; ++k) {
        this->put(k, btree_put_type::INSERT, true /* expect_success */);
    }
    test_common::HSTestHelper::trigger_cp(true);
    this->m_shadow_map.save(this->m_shadow_filename);
    auto const persisted_root = this->m_bt->root_node_id();
    auto const persisted_depth = this->m_bt->get_btree_depth();

    this->set_basic_flip("crash_flush_on_root");
    this->set_basic_flip("skip_cp_after_index_root_recovery");
    const uint32_t phase2_count = max_keys * max_keys;
    for (uint32_t k = max_keys + 1; k <= max_keys + phase2_count; ++k) {
        this->put(k, btree_put_type::INSERT, true /* expect_success */);
    }
    ASSERT_NE(this->m_bt->root_node_id(), persisted_root);
    ASSERT_GT(this->m_bt->get_btree_depth(), persisted_depth);
    ASSERT_TRUE(hs()->crash_simulator().will_crash());

    test_common::HSTestHelper::trigger_cp(false);
    this->wait_for_crash_recovery(true);
    ASSERT_GT(this->m_bt->get_btree_depth(), persisted_depth);

    // The recovery CP was deliberately skipped, so the original journal is still current. Crash and wait sequentially
    // to prove replaying the already-published candidate is idempotent.
    hs()->crash_simulator().set_will_crash(true);
    hs()->crash_simulator().crash();
    this->wait_for_crash_recovery(true);
    ASSERT_GT(this->m_bt->get_btree_depth(), persisted_depth);
    this->reapply_after_crash();
    this->get_all();
}

TYPED_TEST(IndexCrashTest, long_running_put_crash) {
    long_running_crash_options crash_test_options{
        .put_freq = 100,
        .put_flips = {"crash_flush_on_split_at_parent", "crash_flush_on_split_at_left_child",
                      "crash_flush_on_split_at_right_child"},
    };
    this->long_running_crash(crash_test_options);
}

TYPED_TEST(IndexCrashTest, long_running_remove_crash) {
    long_running_crash_options crash_test_options{
        .put_freq = 0,
        .remove_flips = {"crash_flush_on_merge_at_parent", "crash_flush_on_merge_at_left_child"
                         /*, "crash_flush_on_freed_child"*/},
        .preload_size = SISL_OPTIONS["num_entries"].as< uint32_t >(),
    };
    this->long_running_crash(crash_test_options);
}

TYPED_TEST(IndexCrashTest, long_running_put_remove_crash) {
    long_running_crash_options crash_test_options{
        .put_freq = 50,
        .put_flips = {"crash_flush_on_split_at_parent", "crash_flush_on_split_at_left_child",
                      "crash_flush_on_split_at_right_child"},
        .remove_flips = {"crash_flush_on_merge_at_parent", "crash_flush_on_merge_at_left_child"
                         /*, "crash_flush_on_freed_child"*/},
    };
    this->long_running_crash(crash_test_options);
}

// Basic reverse and forward order remove with different flip points
TYPED_TEST(IndexCrashTest, MergeRemoveBasic) {
    vector< std::string > flip_points = {
        "crash_flush_on_merge_at_parent",
        "crash_flush_on_merge_at_left_child",
        "crash_flush_on_freed_child",
    };

    for (size_t i = 0; i < flip_points.size(); ++i) {
        this->reset_btree();

        auto& flip_point = flip_points[i];
        LOGINFO("=== Testing flip point: {} - {} ===", i + 1, flip_point);

        // Populate some keys [1,num_entries) and trigger cp to persist
        LOGINFO("Step {}-0: Populate some keys and flush", i + 1);
        auto const num_entries = SISL_OPTIONS["num_entries"].as< uint32_t >();
        for (auto k = 0u; k < num_entries; ++k) {
            this->put(k, btree_put_type::INSERT, true /* expect_success */);
        }
        test_common::HSTestHelper::trigger_cp(true);
        this->m_shadow_map.save(this->m_shadow_filename);

        // Split keys into batches and remove the last one in reverse order
        LOGINFO("\n\n\n\n\n\n\n\n\n\n\n\n\n\nStep {}-1: Set crash flag {}", i + 1, flip_point);
        int batch_num = 4;
        {
            int n = batch_num;
            auto r = num_entries * n / batch_num - 1;
            auto l = num_entries * (n - 1) / batch_num;
            OperationList ops;
            for (auto k = r; k >= l; --k) {
                ops.emplace_back(k, OperationType::Remove);
            }
            LOGINFO("Step {}-1-1: Remove keys in batch {}/{} ({} to {})", i + 1, n, batch_num, r, l);
            this->print_keys(fmt::format("Print before Step {}-1-1: Remove keys in batch {}/{} ({} to {})", i + 1, n,
                                         batch_num, r, l));
            this->set_basic_flip(flip_point);
            for (auto [k, _] : ops) {
                this->remove_one(k, true);
            }
            LOGINFO("Step {}-1-2: Trigger cp to crash", i + 1);
            this->crash_and_recover(flip_point, ops);
        }
        this->print_keys(fmt::format("Print after recover Step {}1--3: flip {}", i + 1, flip_point));

        // Remove the next batch of keys in forward order
        LOGINFO("\n\n\n\n\n\n\n\n\n\n\n\n\n\nStep {}-2: Set crash flag {}", i + 1, flip_point);
        {
            int n = batch_num - 1;
            auto r = num_entries * n / batch_num - 1;
            auto l = num_entries * (n - 1) / batch_num;
            OperationList ops;
            for (auto k = l; k <= r; ++k) {
                ops.emplace_back(k, OperationType::Remove);
            }
            LOGINFO("Step {}-2-1: Remove keys in batch {}/{} ({} to {})", i + 1, n, batch_num, l, r);
            this->print_keys(fmt::format("Print before Step {}-2-1: Remove keys in batch {}/{} ({} to {})", i + 1, n,
                                         batch_num, l, r));
            this->set_basic_flip(flip_point);
            for (auto [k, _] : ops) {
                this->remove_one(k, true);
            }
            LOGINFO("Step {}-2-2: Trigger cp to crash", i + 1);
            this->crash_and_recover(flip_point, ops);
        }
        this->print_keys(fmt::format("Print after recover Step {}-2-3: flip {}", i + 1, flip_point));

        // Remove the next batch of keys in random order
        LOGINFO("\n\n\n\n\n\n\n\n\n\n\n\n\n\nStep {}-3: Set crash flag {}", i + 1, flip_point);
        {
            int n = batch_num - 2;
            auto r = num_entries * n / batch_num - 1;
            auto l = num_entries * (n - 1) / batch_num;
            SequenceGenerator generator(0, 100, l, r);
            generator.fillRange(l, r);
            OperationList ops = generator.generateOperations(r - l + 1, false);

            LOGINFO("Step {}-3-1: Remove keys in batch {}/{} ({} to {})", i + 1, n, batch_num, l, r);

            this->set_basic_flip(flip_point);
            for (auto [k, _] : ops) {
                this->remove_one(k, true);
            }
            this->print_keys(fmt::format("Print before Step {}-3: Remove keys in batch {}/{} ({} to {})", i + 1, n,
                                         batch_num, l, r));

            LOGINFO("Step {}-3-2: Trigger cp to crash", i + 1);
            this->crash_and_recover(flip_point, ops);
        }
        this->print_keys(fmt::format("Print after recover Step {}-3-3: flip {}", i + 1, flip_point));

        // Remove the next batch of keys in random order
        LOGINFO("\n\n\n\n\n\n\n\n\n\n\n\n\n\nStep {}-4: Set crash flag {} Remove another batch in ascending order",
                i + 1, flip_point);
        {
            int n = batch_num - 3;
            auto r = num_entries * n / batch_num - 1;
            auto l = num_entries * (n - 1) / batch_num;
            SequenceGenerator generator(0, 100, l, r);
            generator.fillRange(l, r);
            OperationList ops = generator.generateOperations(r - l + 1, false);

            LOGINFO("Step {}-4-1: Remove keys in batch {}/{} ({} to {})", i + 1, n, batch_num, l, r);
            this->print_keys(fmt::format("Print before Step {}-4-1: Remove keys in batch {}/{} ({} to {})", i + 1, n,
                                         batch_num, l, r));
            this->set_basic_flip(flip_point);
            for (auto [k, _] : ops) {
                this->remove_one(k, true);
            }
            LOGINFO("Step {}-4-2: Trigger cp to crash", i + 1);
            this->crash_and_recover(flip_point, ops);
        }
        this->print_keys(fmt::format("Print after recover Step {}-4-3: flip {}", i + 1, flip_point));

        test_common::HSTestHelper::trigger_cp(true);
        this->get_all();
    }
}

// Regression test for the bug: when an index table is destroyed concurrently with a CP flush,
// the txn_journal (written at the START of the flush) can contain entries for the destroyed
// table's ordinal while the table's meta superblock is already gone.  On recovery the journal
// is replayed but the table cannot be found in m_ordinal_index_map, causing
// repair_index_node / sanity_check to assert.
//
// Sequence that triggers the bug:
//  1. Build a multi-level tree and flush a baseline CP.
//  2. Set a crash flip so the next CP crashes mid-flush (after writing the journal).
//  3. Insert more keys → splits happen → transact_bufs is called → txn_journal entry added
//     for this table's ordinal AND m_crash_flag_on is set on the split parent buf.
//  4. Destroy the table: meta superblock removed from disk, but the dirty split bufs
//     (with m_crash_flag_on) remain in the CP dirty list.
//  5. Trigger CP → journal written to disk → do_flush_one_buf hits the flagged buf → crash.
//  6. Recovery: journal has entries for the destroyed table → without fix: assert/abort.
//              With fix: skip gracefully.
TYPED_TEST(IndexCrashTest, DestroyTableWithPendingCpCrash) {
    // Use a small fixed preload to avoid triggering unrelated block-allocator issues
    // that surface when inserting hundreds of consecutive right-edge keys into a
    // fully-flushed large tree.  With max_keys_in_node=20 and 100 preloaded keys
    // we get 5 full leaf nodes; inserting 20 more triggers 1-2 leaf splits which is
    // enough to (a) populate a txn_journal entry and (b) mark a parent buffer for crash.
    static constexpr uint32_t preload_size = 100;
    static constexpr uint32_t extra_keys = 20;

    // Step 1: Build a small tree and flush a clean baseline CP.
    LOGINFO("Step 1: Preload {} keys and flush baseline CP", preload_size);
    for (auto k = 0u; k < preload_size; ++k) {
        this->put(k, btree_put_type::INSERT, true /* expect_success */);
    }
    test_common::HSTestHelper::trigger_cp(true);
    this->m_shadow_map.save(this->m_shadow_filename);

    // Step 2: Set the crash flip BEFORE the operations that will cause splits.
    // When a split occurs, transact_bufs checks this flip and sets m_crash_flag_on on
    // the parent buf.  The actual crash fires later when the CP flushes that buf.
    LOGINFO("Step 2: Set crash flip on split-at-parent");
    this->set_basic_flip("crash_flush_on_split_at_parent");

    // Step 3: Insert extra keys to cause splits and populate the txn_journal.
    // The rightmost leaf is full after the preload, so the first new key triggers a
    // split → transact_bufs is called → crash flip fires once → m_crash_flag_on set
    // on the parent buf; subsequent splits (if any) accumulate more journal entries
    // but no additional crash flags (flip fires only once, count=1).
    LOGINFO("Step 3: Insert {} extra keys to cause splits (txn_journal populated)", extra_keys);
    for (auto k = preload_size; k < preload_size + extra_keys; ++k) {
        this->put(k, btree_put_type::INSERT, true /* expect_success */);
    }

    // Step 4: Destroy the table.  m_sb.destroy() removes the meta superblock from disk.
    // The dirty split bufs (including the one with m_crash_flag_on) remain in the CP
    // dirty list because free_buf only marks m_node_freed — it does not touch the list.
    LOGINFO("Step 4: Destroy index table — meta superblock removed from disk");
    hs()->index_service().remove_index_table(this->m_bt);
    this->m_bt->destroy();

    // Step 5: Trigger the CP (do not wait).  async_cp_flush will:
    //   (a) write the txn_journal to disk (entries include the destroyed table's ordinal),
    //   (b) start flushing nodes, hit the buf with m_crash_flag_on → simulated crash.
    LOGINFO("Step 5: Trigger CP (crash expected after journal is written)");
    test_common::HSTestHelper::trigger_cp(false /* no wait */);

    // Step 6: Wait for the simulated crash and homestore recovery.
    //   Without fix : repair_index_node / sanity_check asserts → process aborts (SIGABRT).
    //   With fix    : missing table is skipped gracefully and recovery completes normally.
    LOGINFO("Step 6: Waiting for crash-recovery");
    this->wait_for_crash_recovery(true /* check_will_crash */);
    LOGINFO("Step 6: Recovery succeeded without aborting — destroyed table was handled gracefully");

    // Step 7: Install a fresh empty btree so that the shared TearDown() can safely call
    // root_node_id() and tree_key_count() without hitting the stale destroyed btree.
    LOGINFO("Step 7: Installing a fresh empty btree for teardown");
    this->install_fresh_btree(preload_size + extra_keys);
    test_common::HSTestHelper::trigger_cp(true);
}

TYPED_TEST(IndexCrashTest, MetricsTest) {
    const auto num_entries = SISL_OPTIONS["num_entries"].as< uint32_t >();
    std::vector< uint32_t > vec(num_entries);
    iota(vec.begin(), vec.end(), 0);
    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(vec.begin(), vec.end(), g);
    for (auto key : vec) {
        this->put(key, btree_put_type::INSERT, true /* expect_success */);
    }
    print_keys_logging("After populating");

    auto log_btree_metrics = [this](std::string prompt) {
        auto metrics = this->m_bt->get_metrics_in_json().dump(1, '\t');
        LOGDEBUG("metrics: \n{}", metrics);
        auto metrics_json = this->m_bt->get_metrics_in_json();
        auto bt_cnts = this->m_bt->get_num_nodes();
        auto bt_d = this->m_bt->get_btree_depth();
        auto com_cnts = this->m_bt->compute_node_count();
        auto com_d = this->m_bt->compute_btree_depth();
        auto [int_cnt, leaf_cnt, depth] = this->get_btree_metrics(metrics_json);

        LOGDEBUG("\n{}:\nmetrics  (interior, leaf, height):\ncompute ({}, {}, {})\nbtree   ({}, {}, {})\nmetrics ({}, "
                 "{}, {})",
                 prompt, com_cnts.first, com_cnts.second, com_d, bt_cnts.first, bt_cnts.second, bt_d, int_cnt, leaf_cnt,
                 depth);
        ASSERT_EQ(bt_cnts.first, com_cnts.first) << "btree interior count doesn't match the actual node counts";
        ASSERT_EQ(bt_cnts.first, int_cnt) << "btree interior count doesn't match the metrics node counts";
        ASSERT_EQ(bt_cnts.second, com_cnts.second) << "btree leaf count doesn't match the actual node counts";
        ASSERT_EQ(bt_cnts.second, leaf_cnt) << "btree leaf count doesn't match the metrics node counts";
        ASSERT_EQ(bt_d, com_d) << "btree depth doesn't match the actual btee depth";
        ASSERT_EQ(bt_d, depth) << "btree depth doesn't match the metrics depth report";
    };
    log_btree_metrics("node count before CP");

    test_common::HSTestHelper::trigger_cp(true);
    log_btree_metrics("node count after CP");

    this->m_shadow_map.save(this->m_shadow_filename);
    this->restart_homestore();
    print_keys_logging("After restart");
    log_btree_metrics("node count after restart");
    std::string flip = "crash_flush_on_merge_at_parent";
    for (auto key : vec) {
        this->remove_one(key, true);
    }
    this->trigger_cp(false);
    this->wait_for_crash_recovery(true);
    log_btree_metrics("node count after crash recovery");
    print_keys_logging("after removing all keys");
}

//
// TYPED_TEST(IndexCrashTest, MergeCrash1) {
//     auto const num_entries = SISL_OPTIONS["num_entries"].as<uint32_t>();
//     vector<std::string> flips = {
//         "crash_flush_on_merge_at_parent", "crash_flush_on_merge_at_left_child",
//     };
//     SequenceGenerator generator(0 /*putFreq*/, 100 /* removeFreq*/, 0 /*start_range*/, num_entries - 1
//     /*end_range*/); OperationList operations; for (size_t i = 0; i < flips.size(); ++i) {
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

// ============================================================================
// Regression test for SDSTOR-21880:
//   MetaIndexBuffer blkid ({0,0,0,0}) collision in buf_map during recovery
//   when two BTree tables both have a root split in the same CP.
//
// Root cause: all MetaIndexBuffer objects use BlkId{} (zero) as their blkid.
// buf_map is keyed by BlkId, so the MetaBuf for ordinal=1 hits the already-
// inserted MetaBuf for ordinal=0.  The child node for ordinal=1 gets linked to
// the wrong MetaBuf (ordinal=0), and the sanity check in
// IndexCPContext::recover() fires: up_buffer->m_index_ordinal(0) !=
// bufferPtr->m_index_ordinal(1) → HS_REL_ASSERT → crash.
// ============================================================================
struct IndexCrashTestTwoTables : public test_common::HSTestHelper,
                                 BtreeTestHelper< FixedLenBtree >,
                                 public ::testing::Test {
    using T = FixedLenBtree;
    using K = T::KeyType;
    using V = T::ValueType;
    using BtType = T::BtreeType;

    std::shared_ptr< BtType > m_bt2;

    // During recovery each table's superblk triggers on_index_table_found.
    // We route by ordinal: 0 → m_bt, 1 → m_bt2.
    class TestIndexServiceCallbacks : public IndexServiceCallbacks {
    public:
        TestIndexServiceCallbacks(IndexCrashTestTwoTables* test) : m_test(test) {}

        std::shared_ptr< IndexTableBase > on_index_table_found(superblk< index_table_sb >&& sb) override {
            LOGINFO("Index table recovered ordinal={} uuid={}", sb->ordinal, boost::uuids::to_string(sb->uuid));
            m_test->m_cfg = BtreeConfig(hs()->index_service().node_size());
            m_test->m_cfg.m_leaf_node_type = T::leaf_node_type;
            m_test->m_cfg.m_int_node_type = T::interior_node_type;
            m_test->m_cfg.m_max_keys_in_node = 5;
            m_test->m_cfg.m_min_keys_in_node = 2;
            if (sb->ordinal == 0) {
                m_test->m_bt = std::make_shared< BtType >(std::move(sb), m_test->m_cfg);
                return m_test->m_bt;
            } else {
                m_test->m_bt2 = std::make_shared< BtType >(std::move(sb), m_test->m_cfg);
                return m_test->m_bt2;
            }
        }

    private:
        IndexCrashTestTwoTables* m_test;
    };

    IndexCrashTestTwoTables() : testing::Test() { this->m_is_multi_threaded = false; }

    void SetUp() override {
        HS_SETTINGS_FACTORY().modifiable_settings([](auto& s) {
            s.generic.cache_max_throttle_cnt = 10000;
            s.generic.cp_timer_us = 0x8000000000000000; // disable auto CP
            s.resource_limits.dirty_buf_percent = 100;
            HS_SETTINGS_FACTORY().save();
        });

        this->start_homestore(
            "test_index_crash_recovery",
            {{HS_SERVICE::META, {.size_pct = 10.0}},
             {HS_SERVICE::INDEX, {.size_pct = 70.0, .index_svc_cbs = new TestIndexServiceCallbacks(this)}}},
            nullptr, {}, true /* init_device */);

        this->m_cfg = BtreeConfig(hs()->index_service().node_size());
        this->m_cfg.m_leaf_node_type = T::leaf_node_type;
        this->m_cfg.m_int_node_type = T::interior_node_type;
        this->m_cfg.m_max_keys_in_node = 5;
        this->m_cfg.m_min_keys_in_node = 2;

        BtreeTestHelper< FixedLenBtree >::SetUp();

        // Create table 0 (ordinal=0)
        auto uuid1 = boost::uuids::random_generator()();
        auto parent_uuid1 = boost::uuids::random_generator()();
        this->m_bt = std::make_shared< BtType >(uuid1, parent_uuid1, 0, this->m_cfg);
        hs()->index_service().add_index_table(this->m_bt);

        // Create table 1 (ordinal=1)
        auto uuid2 = boost::uuids::random_generator()();
        auto parent_uuid2 = boost::uuids::random_generator()();
        this->m_bt2 = std::make_shared< BtType >(uuid2, parent_uuid2, 0, this->m_cfg);
        hs()->index_service().add_index_table(this->m_bt2);

        LOGINFO("SetUp: created {} index tables", hs()->index_service().num_tables());
    }

    void restart_homestore(uint32_t shutdown_delay_sec = 3) override {
        this->params(HS_SERVICE::INDEX).index_svc_cbs = new TestIndexServiceCallbacks(this);
        test_common::HSTestHelper::restart_homestore(shutdown_delay_sec);
    }

    void TearDown() override {
        BtreeTestHelper< FixedLenBtree >::TearDown();
        this->shutdown_homestore(false);
    }

    // Insert sequential keys directly into a given BTree (no shadow map tracking)
    void insert_into(std::shared_ptr< BtType >& bt, uint32_t start, uint32_t end) {
        for (uint32_t k = start; k < end; ++k) {
            K key{k};
            V value{V::generate_rand()};
            auto sreq = BtreeSinglePutRequest{&key, &value, btree_put_type::INSERT};
            auto ret = bt->put(sreq);
            ASSERT_EQ(ret, btree_status_t::success) << "insert key=" << k << " failed";
        }
    }
};

TEST_F(IndexCrashTestTwoTables, MultiTableMetaBufOrdinalCollisionOnRecovery) {
    // With max_keys_in_node=5, inserting 6+ entries into a single-node BTree
    // forces a root split where MetaIndexBuffer becomes the DAG parent.
    // Both tables must split in the SAME CP so the txn_journal contains:
    //   rec0: ordinal=0, parent=meta@{0,0,0,0}, ...
    //   rec1: ordinal=1, parent=meta@{0,0,0,0}, ...
    // On recovery, buf_map[{0,0,0,0}] is shared → ordinal mismatch → crash.
    const uint32_t n = 10; // well above max_keys_in_node=5; forces root split

    // crash_flush_on_root fires inside transact_bufs() when parent_buf->is_meta_buf()
    // (i.e., during a root split).  It marks child_buf with a crash flag and calls
    // set_will_crash(true); the actual crash fires when that buffer is later flushed
    // by the CP.  The flip is one-shot so it fires on table 0's root split; table 1's
    // root split records still land in the txn_journal in the same CP epoch.
    LOGINFO("Step 1: Set crash_flush_on_root flip (must precede inserts)");
    this->set_basic_flip("crash_flush_on_root");

    LOGINFO("Step 2: Insert {} entries into table 0 (root split fires the flip)", n);
    insert_into(this->m_bt, 0, n);

    LOGINFO("Step 3: Insert {} entries into table 1 (root split, flip already consumed)", n);
    insert_into(this->m_bt2, 1000, 1000 + n);

    // Both tables' root-split records are now in the txn_journal (same CP epoch).
    // Trigger CP: journal is persisted first, then buffer flush crashes on child_buf.
    LOGINFO("Step 4: Trigger CP (will crash during buffer flush)");
    test_common::HSTestHelper::trigger_cp(false);

    // Wait for crash + HS restart.  If the bug is present, recovery will
    // HS_REL_ASSERT inside IndexCPContext::sanityCheck() and abort the process.
    // If the bug is fixed, recovery succeeds and we reach the assertion below.
    LOGINFO("Step 5: Waiting for crash recovery");
    this->wait_for_crash_recovery(true);

    LOGINFO("Step 6: Recovery succeeded - bug is fixed (SDSTOR-21880)");
    ASSERT_EQ(hs()->index_service().num_tables(), 2) << "Both tables should be recovered";
}

// Regression reproducer for the recovery ordering bug where a node that is
// created and freed in the crashed CP is put into deleted_bufs even though its
// blkid was never persisted in the allocator bitmap.
//
// This test does not add or depend on any new test flip. It uses the existing
// crash_flush_on_split_at_parent flip only to stop the CP after the index journal
// is persisted. The first current-CP split is immediately merged away so that
// its newly allocated blkid is also freed in the same CP; because that allocation
// is the first one after the clean baseline CP, the blkid is small and appears
// near the head of fixed_blk_allocator::m_free_blk_q after restart. The later
// split storm creates enough child links for recovery repair to allocate parent
// repair nodes normally; when repair reuses that small created+freed blkid,
// deleted_bufs later frees the live repair node. Subsequent normal inserts then
// either crash in IndexWBCache::alloc_buf() at the duplicate cache insert assert,
// or corrupt a shared-blkid btree node and crash during validation/use.
struct IndexCrashCreatedFreedReuseTest : public test_common::HSTestHelper,
                                         BtreeTestHelper< FixedLenBtree >,
                                         public ::testing::Test {
    using T = FixedLenBtree;
    using K = T::KeyType;
    using V = T::ValueType;

    struct InspectableIndexTable : public T::BtreeType {
        InspectableIndexTable(uuid_t uuid, uuid_t parent_uuid, uint32_t user_sb_size, BtreeConfig const& cfg,
                              bool* flush_recovery_free_list, std::set< bnodeid_t >* recovery_freed_node_ids) :
                T::BtreeType{uuid, parent_uuid, user_sb_size, cfg},
                m_flush_recovery_free_list{flush_recovery_free_list},
                m_recovery_freed_node_ids{recovery_freed_node_ids} {}

        InspectableIndexTable(superblk< index_table_sb >&& sb, BtreeConfig const& cfg, bool* flush_recovery_free_list,
                              std::set< bnodeid_t >* recovery_freed_node_ids) :
                T::BtreeType{std::move(sb), cfg},
                m_flush_recovery_free_list{flush_recovery_free_list},
                m_recovery_freed_node_ids{recovery_freed_node_ids} {}

        void recovery_completed() override {
            T::BtreeType::recovery_completed();
            if (m_flush_recovery_free_list && *m_flush_recovery_free_list) {
                auto cpg = hs()->cp_mgr().cp_guard();
                auto* cp_ctx = s_cast< VDevCPContext* >(cpg.context(cp_consumer_t::INDEX_SVC));
                if (m_recovery_freed_node_ids) {
                    cp_ctx->m_free_blkid_list.foreach_entry(
                        [this](BlkId bid) { m_recovery_freed_node_ids->insert(bid.to_integer()); });
                }
                auto const root_blk = BlkId{this->root_node_id()};
                auto* chunk = hs()->device_mgr()->get_chunk_mutable(root_blk.chunk_num());
                RELEASE_ASSERT(chunk != nullptr, "Index chunk not found for root blkid {}", root_blk.to_string());
                auto* vdev = hs()->device_mgr()->get_vdev_mutable(chunk->vdev_id());
                RELEASE_ASSERT(vdev != nullptr, "Index vdev not found for root blkid {}", root_blk.to_string());
                vdev->cp_flush(cp_ctx);
                *m_flush_recovery_free_list = false;
            }
        }

        std::set< bnodeid_t > collect_node_ids() const {
            std::set< bnodeid_t > ids;
            collect_node_ids_recurse(this->root_node_id(), ids);
            return ids;
        }

    private:
        void collect_node_ids_recurse(bnodeid_t node_id, std::set< bnodeid_t >& ids) const {
            if ((node_id == empty_bnodeid) || ids.contains(node_id)) { return; }

            BtreeNodePtr node;
            if ((this->read_node_impl(node_id, node) != btree_status_t::success) || node->is_node_deleted()) { return; }
            ids.insert(node_id);

            if (node->is_leaf()) { return; }

            for (uint32_t i = 0; i < node->total_entries(); ++i) {
                BtreeLinkInfo child_info;
                node->get_nth_value(i, &child_info, false /* copy */);
                collect_node_ids_recurse(child_info.bnode_id(), ids);
            }

            if (node->has_valid_edge()) { collect_node_ids_recurse(node->get_edge_value().bnode_id(), ids); }
        }

        bool* m_flush_recovery_free_list{nullptr};
        std::set< bnodeid_t >* m_recovery_freed_node_ids{nullptr};
    };

    using BtType = InspectableIndexTable;

    class TestIndexServiceCallbacks : public IndexServiceCallbacks {
    public:
        TestIndexServiceCallbacks(IndexCrashCreatedFreedReuseTest* test) : m_test{test} {}

        std::shared_ptr< IndexTableBase > on_index_table_found(superblk< index_table_sb >&& sb) override {
            LOGINFO("Index table recovered, root bnode_id {} uuid {} ordinal {} version {}",
                    static_cast< uint64_t >(sb->root_node), boost::uuids::to_string(sb->uuid), sb->ordinal,
                    sb->root_link_version);
            m_test->init_cfg();
            m_test->m_bt = std::make_shared< BtType >(std::move(sb), m_test->m_cfg, &m_test->m_flush_recovery_free_list,
                                                      &m_test->m_recovery_freed_node_ids);
            return m_test->m_bt;
        }

    private:
        IndexCrashCreatedFreedReuseTest* m_test;
    };

    IndexCrashCreatedFreedReuseTest() : testing::Test() { this->m_is_multi_threaded = false; }

    bool m_flush_recovery_free_list{false};
    std::set< bnodeid_t > m_recovery_freed_node_ids;

    void init_cfg() {
        this->m_cfg = BtreeConfig(hs()->index_service().node_size());
        this->m_cfg.m_leaf_node_type = T::leaf_node_type;
        this->m_cfg.m_int_node_type = T::interior_node_type;
        this->m_cfg.m_max_keys_in_node = 20;
        this->m_cfg.m_min_keys_in_node = 6;
        this->m_cfg.m_max_merge_level = 1;
    }

    void SetUp() override {
        HS_SETTINGS_FACTORY().modifiable_settings([](auto& s) {
            s.generic.cache_max_throttle_cnt = 10000;
            s.generic.cp_timer_us = 0x8000000000000000;
            s.resource_limits.dirty_buf_percent = 100;
            HS_SETTINGS_FACTORY().save();
        });

        this->start_homestore(
            "test_index_crash_recovery",
            {{HS_SERVICE::META, {.size_pct = 10.0}},
             {HS_SERVICE::INDEX, {.size_pct = 10.0, .index_svc_cbs = new TestIndexServiceCallbacks(this)}}},
            nullptr, {}, true /* init_device */);

        BtreeTestHelper< FixedLenBtree >::SetUp();
        init_cfg();

        auto uuid = boost::uuids::random_generator()();
        auto parent_uuid = boost::uuids::random_generator()();
        this->m_bt = std::make_shared< BtType >(uuid, parent_uuid, 0, this->m_cfg, &m_flush_recovery_free_list,
                                                &m_recovery_freed_node_ids);
        hs()->index_service().add_index_table(this->m_bt);
    }

    void restart_homestore(uint32_t shutdown_delay_sec = 3) override {
        this->params(HS_SERVICE::INDEX).index_svc_cbs = new TestIndexServiceCallbacks(this);
        test_common::HSTestHelper::restart_homestore(shutdown_delay_sec);
    }

    void TearDown() override {
        BtreeTestHelper< FixedLenBtree >::TearDown();
        this->shutdown_homestore(false);
    }

    void insert_key(uint32_t key_num) {
        K key{key_num};
        V value{V::generate_rand()};
        auto req = BtreeSinglePutRequest{&key, &value, btree_put_type::INSERT};
        req.enable_route_tracing();
        auto const ret = this->m_bt->put(req);
        ASSERT_EQ(ret, btree_status_t::success) << "insert key=" << key_num << " failed with " << enum_name(ret);
    }

    void update_key(uint32_t key_num) {
        K key{key_num};
        V value{V::generate_rand()};
        auto req = BtreeSinglePutRequest{&key, &value, btree_put_type::UPDATE};
        req.enable_route_tracing();
        auto const ret = this->m_bt->put(req);
        ASSERT_EQ(ret, btree_status_t::success) << "update key=" << key_num << " failed with " << enum_name(ret);
    }

    bool remove_key(uint32_t key_num) {
        auto existing_v = std::make_unique< V >();
        K key{key_num};
        auto req = BtreeSingleRemoveRequest{&key, existing_v.get()};
        req.enable_route_tracing();
        auto const ret = this->m_bt->remove(req);
        if ((ret != btree_status_t::success) && (ret != btree_status_t::not_found)) {
            ADD_FAILURE() << "remove key=" << key_num << " failed with " << enum_name(ret);
        }
        return ret == btree_status_t::success;
    }

    void insert_sparse_multiples(uint32_t begin, uint32_t end, uint32_t step) {
        for (auto k = begin; k <= end; k += step) {
            insert_key(k);
        }
    }

    void insert_range_skip_multiples(uint32_t begin, uint32_t end, uint32_t step) {
        for (auto k = begin; k < end; ++k) {
            if ((k % step) == 0) { continue; }
            insert_key(k);
        }
    }

    void remove_range_skip_multiples(uint32_t begin, uint32_t end, uint32_t step) {
        uint32_t removed{0};
        for (auto k = begin; k < end; ++k) {
            if ((k % step) == 0) { continue; }
            if (remove_key(k)) { ++removed; }
        }
        ASSERT_GT(removed, 0u) << "expected at least one key to be removed in [" << begin << ", " << end << ")";
    }

    void verify_existing_range(uint32_t begin, uint32_t end) {
        for (auto k = begin; k < end; ++k) {
            auto out_v = std::make_unique< V >();
            K key{k};
            auto req = BtreeSingleGetRequest{&key, out_v.get()};
            req.enable_route_tracing();
            auto const ret = this->m_bt->get(req);
            ASSERT_EQ(ret, btree_status_t::success) << "get key=" << k << " failed with " << enum_name(ret);
        }
    }

    std::shared_ptr< BtType > inspectable_bt() const { return std::static_pointer_cast< BtType >(this->m_bt); }

    bnodeid_t first_added_node_id(std::set< bnodeid_t > const& before, std::set< bnodeid_t > const& after) const {
        for (auto const id : after) {
            if (!before.contains(id)) { return id; }
        }
        return empty_bnodeid;
    }

    std::vector< bnodeid_t > added_then_freed_node_ids(std::set< bnodeid_t > const& before,
                                                       std::set< bnodeid_t > const& after_add,
                                                       std::set< bnodeid_t > const& after_free) const {
        std::vector< bnodeid_t > ids;
        for (auto const id : after_add) {
            if (!before.contains(id) && !after_free.contains(id)) { ids.push_back(id); }
        }
        return ids;
    }

    void commit_index_free_queue_until(uint64_t remaining_blks) {
        auto const root_blk = BlkId{this->m_bt->root_node_id()};
        auto* chunk = hs()->device_mgr()->get_chunk_mutable(root_blk.chunk_num());
        RELEASE_ASSERT(chunk != nullptr, "Index chunk not found for root blkid {}", root_blk.to_string());
        auto* vdev = hs()->device_mgr()->get_vdev_mutable(chunk->vdev_id());
        RELEASE_ASSERT(vdev != nullptr, "Index vdev not found for root blkid {}", root_blk.to_string());

        blk_alloc_hints hints;
        hints.application_hint = this->m_bt->ordinal();

        uint64_t consumed{0};
        while (vdev->available_blks() > remaining_blks) {
            BlkId blkid;
            auto status = vdev->alloc_contiguous_blks(1, hints, blkid);
            ASSERT_EQ(status, BlkAllocStatus::SUCCESS)
                << "failed to consume index free queue after " << consumed << " allocations";
            status = vdev->commit_blk(blkid);
            ASSERT_EQ(status, BlkAllocStatus::SUCCESS) << "failed to commit consumed blk " << blkid.to_string();
            ++consumed;
        }
        LOGINFO("Persistently consumed {} index free blks; remaining free blks={}", consumed, vdev->available_blks());
    }
};

TEST_F(IndexCrashCreatedFreedReuseTest, CreatedAndFreedBlkReusedByRecoveryRepair) {
    constexpr uint32_t sparse_step = 100;
    constexpr uint32_t preload_last_key = 2000;
    constexpr uint64_t crash_cp_free_queue_blks = 512;

    LOGINFO("Step 1: preload sparse keys [0, {}] step {} and flush the baseline CP", preload_last_key, sparse_step);
    insert_sparse_multiples(0, preload_last_key, sparse_step);
    test_common::HSTestHelper::trigger_cp(true);

    LOGINFO("Step 1b: persistently consume index free queue so crash-CP created nodes are near recovery queue head");

    // simulate a case that a lot of blk is consumed by other btree node allocation. for example, we have 2 btrees. one
    // is used for reproduce this issue(the current one) , the other is used for consuming blks(receives lots of put
    // request and lead to a lot of  blk allocation). commit_index_free_queue_until is used to consume free blks , just
    // like what the second btree does.
    commit_index_free_queue_until(crash_cp_free_queue_blks);
    update_key(0);
    test_common::HSTestHelper::trigger_cp(true);

    LOGINFO("Step 2: set existing crash flip to crash after journal persistence but before parent flush");
    this->set_basic_flip("crash_flush_on_split_at_parent");

    LOGINFO("Step 3: observe the first current-CP split node, then make that exact blkid created+freed");
    auto const before_first_split = inspectable_bt()->collect_node_ids();
    insert_range_skip_multiples(1, 160, sparse_step);
    auto const after_first_split = inspectable_bt()->collect_node_ids();
    ASSERT_NE(first_added_node_id(before_first_split, after_first_split), empty_bnodeid)
        << "expected first current-CP split to add a node";

    remove_range_skip_multiples(1, 160, sparse_step);
    auto const after_target_merge = inspectable_bt()->collect_node_ids();
    auto const created_freed_node_ids =
        added_then_freed_node_ids(before_first_split, after_first_split, after_target_merge);
    ASSERT_FALSE(created_freed_node_ids.empty()) << "expected a current-CP split node to be freed in the same CP";
    LOGINFO("Found {} created+freed node candidates in the crash CP", created_freed_node_ids.size());

    LOGINFO("Step 4: create many more split records in the same unflushed CP to force recovery repair allocations");
    insert_range_skip_multiples(1, preload_last_key, sparse_step);

    LOGINFO("Step 5: crash and recover through the normal recovery/repair path");
    m_flush_recovery_free_list = true;
    m_recovery_freed_node_ids.clear();
    test_common::HSTestHelper::trigger_cp(false);
    this->wait_for_crash_recovery(true);

    LOGINFO("Step 6: do sanity check");
    // 1 all the recovered nodes should not exist in m_recovery_freed_node_ids either ( should not be freed during
    // recovery)
    auto const recovered_nodes = inspectable_bt()->collect_node_ids();
    for (const auto id : m_recovery_freed_node_ids) {
        ASSERT_FALSE(recovered_nodes.contains(id))
            << "created_freed_node " << id << " was freed and also recovered as a live node";
    }

    // 2 all the created+freed blkids should not be freed during recovery ( should not appear in
    // m_recovery_freed_node_ids)
    for (auto const id : created_freed_node_ids) {
        ASSERT_FALSE(m_recovery_freed_node_ids.contains(id))
            << "created_freed_node " << id << " was freed during recovery";
    }

    LOGINFO("Step 7: fixed recovery detected; no same-CP created+freed blkid was freed, verify writes and reads");
    for (auto k = 100000u; k < 100300u; ++k) {
        insert_key(k);
    }

    for (auto k = 0u; k <= preload_last_key; k += sparse_step) {
        verify_existing_range(k, k + 1);
    }
}

class SameChunkSelector : public ChunkSelector {
public:
    void add_chunk(cshared<Chunk>& chunk) override {
        if (!m_fixed_chunk) {
            m_fixed_chunk = chunk;
        }
        m_chunks.push_back(chunk);
    }

    void foreach_chunks(std::function<void(cshared<Chunk>&)>&& cb) override {
        for (auto& c : m_chunks) {
            cb(c);
        }
    }

    cshared<Chunk> select_chunk(blk_count_t, const blk_alloc_hints&) override {
        HS_REL_ASSERT(m_fixed_chunk != nullptr, "SameChunkSelector: no chunk was added before select_chunk");
        return m_fixed_chunk;
    }

private:
    shared<Chunk> m_fixed_chunk;
    std::vector<shared<Chunk>> m_chunks;
};

struct DeterministicChunkSelectorWbcReuseTest : public test_common::HSTestHelper,
                                                BtreeTestHelper< FixedLenBtree >,
                                                public ::testing::Test {
    using T = FixedLenBtree;
    using K = typename T::KeyType;
    using V = typename T::ValueType;
    using BaseBt = typename T::BtreeType;

    std::shared_ptr< SameChunkSelector > m_same_chunk_selector;

    class InspectableBtree : public BaseBt {
    public:
        using BaseBt::BaseBt;

        std::set< bnodeid_t > collect_node_ids() const {
            std::set< bnodeid_t > ids;
            collect_node_ids_recurse(this->root_node_id(), ids);
            return ids;
        }

        void warm_all_nodes_into_wbc() {
            auto ids = collect_node_ids();
            for (auto const node_id : ids) {
                BtreeNodePtr node;
                auto ret = this->read_node_impl(node_id, node);
                ASSERT_EQ(ret, btree_status_t::success)
                    << "failed to read node " << BlkId{node_id}.to_string();
            }
        }

        BtreeNodePtr read_node_for_test(bnodeid_t node_id) {
            BtreeNodePtr node;
            auto ret = this->read_node_impl(node_id, node);
            EXPECT_EQ(ret, btree_status_t::success);
            return node;
        }

    private:
        void collect_node_ids_recurse(bnodeid_t node_id, std::set< bnodeid_t >& ids) const {
            if ((node_id == empty_bnodeid) || ids.contains(node_id)) { return; }

            BtreeNodePtr node;
            if ((this->read_node_impl(node_id, node) != btree_status_t::success) || node->is_node_deleted()) { return; }

            ids.insert(node_id);

            if (node->is_leaf()) { return; }

            for (uint32_t i = 0; i < node->total_entries(); ++i) {
                BtreeLinkInfo child_info;
                node->get_nth_value(i, &child_info, false /* copy */);
                collect_node_ids_recurse(child_info.bnode_id(), ids);
            }

            if (node->has_valid_edge()) { collect_node_ids_recurse(node->get_edge_value().bnode_id(), ids); }
        }
    };

    class TestIndexServiceCallbacks : public IndexServiceCallbacks {
    public:
        explicit TestIndexServiceCallbacks(DeterministicChunkSelectorWbcReuseTest* test) : m_test(test) {}

        std::shared_ptr< IndexTableBase > on_index_table_found(superblk< index_table_sb >&& sb) override {
            m_test->init_cfg();
            auto bt = std::make_shared< InspectableBtree >(std::move(sb), m_test->m_cfg);
            m_test->m_last_recovered_bt = bt;
            return bt;
        }

    private:
        DeterministicChunkSelectorWbcReuseTest* m_test;
    };

    DeterministicChunkSelectorWbcReuseTest() : ::testing::Test() { this->m_is_multi_threaded = false; }

    void init_cfg() {
        this->m_cfg = BtreeConfig(hs()->index_service().node_size());
        this->m_cfg.m_leaf_node_type = T::leaf_node_type;
        this->m_cfg.m_int_node_type = T::interior_node_type;
        this->m_cfg.m_max_keys_in_node = 5;
        this->m_cfg.m_min_keys_in_node = 2;
    }

    void SetUp() override {
        HS_SETTINGS_FACTORY().modifiable_settings([](auto& s) {
            s.generic.cache_max_throttle_cnt = 10000;
            s.generic.cp_timer_us = 0x8000000000000000;
            s.resource_limits.dirty_buf_percent = 100;
            HS_SETTINGS_FACTORY().save();
        });

        m_same_chunk_selector = std::make_shared< SameChunkSelector >();

        this->start_homestore(
            "test_index_crash_recovery",
            {{HS_SERVICE::META, {.size_pct = 10.0}},
             {HS_SERVICE::INDEX,
              {.size_pct = 10.0,
               .index_chunk_selector = m_same_chunk_selector,
               .index_svc_cbs = new TestIndexServiceCallbacks(this)}}},
            nullptr, {}, true /* init_device */);

        BtreeTestHelper< FixedLenBtree >::SetUp();
        init_cfg();

        ASSERT_NE(hs()->index_service().get_chunk_selector(), nullptr)
            << "IndexService chunk selector was not installed";
    }

    void restart_homestore(uint32_t shutdown_delay_sec = 3) override {
        this->params(HS_SERVICE::INDEX).index_svc_cbs = new TestIndexServiceCallbacks(this);
        this->params(HS_SERVICE::INDEX).index_chunk_selector = m_same_chunk_selector;
        test_common::HSTestHelper::restart_homestore(shutdown_delay_sec);
    }

    void TearDown() override {
        BtreeTestHelper< FixedLenBtree >::TearDown();
        this->shutdown_homestore(false);
    }

    std::shared_ptr< InspectableBtree > create_btree() {
        auto uuid = boost::uuids::random_generator()();
        auto parent_uuid = boost::uuids::random_generator()();
        auto bt = std::make_shared< InspectableBtree >(uuid, parent_uuid, 0, this->m_cfg);
        hs()->index_service().add_index_table(bt);
        return bt;
    }

    void destroy_btree(std::shared_ptr< InspectableBtree >& bt) {
        hs()->index_service().remove_index_table(bt);
        bt->destroy();
        bt.reset();
    }

    btree_status_t insert_key(std::shared_ptr< InspectableBtree >& bt, uint32_t key_num) {
        K key{key_num};
        V value{V::generate_rand()};
        auto req = BtreeSinglePutRequest{&key, &value, btree_put_type::INSERT};
        req.enable_route_tracing();
        return bt->put(req);
    }

    btree_status_t insert_range(std::shared_ptr< InspectableBtree >& bt, uint32_t begin, uint32_t end) {
        for (uint32_t k = begin; k < end; ++k) {
            auto ret = insert_key(bt, k);
            if (ret != btree_status_t::success) {
                LOGINFO("insert_range failed at key={} ret={}", k, enum_name(ret));
                return ret;
            }
        }
        return btree_status_t::success;
    }

    uint64_t chunk_epoch(chunk_num_t chunk_num) {
        auto* chunk = hs()->device_mgr()->get_chunk_mutable(chunk_num);
        EXPECT_NE(chunk, nullptr);
        return chunk->wbc_epoch();
    }

    uint64_t node_epoch(const BtreeNodePtr& node) {
        auto* idx_node = static_cast<IndexBtreeNode*>(node.get());
        EXPECT_NE(idx_node, nullptr);
        EXPECT_NE(idx_node->m_idx_buf, nullptr);
        return idx_node->m_idx_buf->m_chunk_epoch;
    }

    uint32_t assert_all_nodes_on_same_chunk(std::shared_ptr< InspectableBtree >& bt) {
        auto ids = bt->collect_node_ids();
        HS_DBG_ASSERT_GT(ids.size(), 1u, "expected more than one node");

        auto it = ids.begin();
        auto expected_chunk = BlkId{*it}.chunk_num();

        for (auto const id : ids) {
            auto const chunk_num = BlkId{id}.chunk_num();
            DEBUG_ASSERT_EQ(chunk_num, expected_chunk,
                "node {} landed on chunk {} but expected chunk {}", BlkId{id}.to_string(), chunk_num, expected_chunk);
        }

        return expected_chunk;
    }

    void clear_chunk_bitmap(chunk_num_t chunk_num) {
        Chunk* chunk = hs()->device_mgr()->get_chunk_mutable(chunk_num);
        ASSERT_NE(chunk, nullptr) << "chunk " << chunk_num << " not found";

        // Zero the alloc bitmap so the next btree reuses bt1 blkids
        chunk->reset_block_allocator();
    }

    std::shared_ptr< InspectableBtree > m_last_recovered_bt;
};

TEST_F(DeterministicChunkSelectorWbcReuseTest, DestroyedBtreeStaleWbcEntriesCorruptNextBtreeOnSameChunk) {
    // Create and populate bt1
    auto bt1 = create_btree();
    insert_range(bt1, 0, 256);
    test_common::HSTestHelper::trigger_cp(true);

    auto const bt1_node_ids = bt1->collect_node_ids();
    ASSERT_FALSE(bt1_node_ids.empty());

    auto const bt1_chunk = assert_all_nodes_on_same_chunk(bt1);

    // Force bt1 nodes into wbc
    bt1->warm_all_nodes_into_wbc();

    // Destroy bt1 and leave stale entries in wbc
    destroy_btree(bt1);

    // Clear the chunk
    clear_chunk_bitmap(bt1_chunk);

    // Create bt2 on the same chunk with stale WBC entries still present;
    // Duplicate insert should happen here on root creation if wbc epochs don't work
    auto bt2 = create_btree();

    ASSERT_EQ(BlkId{bt2->root_node_id()}.chunk_num(), bt1_chunk)
        << "bt2 root did not land on the expected reused chunk";

    ASSERT_TRUE(bt1_node_ids.contains(bt2->root_node_id()))
        << "bt2 root did not immediately reuse a bt1 blkid; setup is not deterministic";

    // This is where the wbc duplicate-insert/corruption shows up
    // if wbc epochs function incorrectly and create_btree() didn't trigger it
    auto ret = insert_range(bt2, 100000, 100128);
    ASSERT_EQ(ret, btree_status_t::success);
}

TEST_F(DeterministicChunkSelectorWbcReuseTest, ChunkEpochInvalidatesStaleWbcEntriesOnChunkReuse) {
    auto bt1 = create_btree();
    insert_range(bt1, 0, 256);
    test_common::HSTestHelper::trigger_cp(true);

    auto const bt1_root = bt1->root_node_id();
    auto const bt1_chunk = assert_all_nodes_on_same_chunk(bt1);

    // Keep one old cached node alive so we can inspect its epoch after chunk reset
    auto stale_root = bt1->read_node_for_test(bt1_root);
    auto const old_node_epoch = node_epoch(stale_root);
    auto const old_chunk_epoch = chunk_epoch(bt1_chunk);
    ASSERT_EQ(old_node_epoch, old_chunk_epoch);

    // Populate WBC with bt1 nodes
    bt1->warm_all_nodes_into_wbc();

    // Destroy bt1 and leave stale entries in wbc
    destroy_btree(bt1);

    // Clear the chunk
    clear_chunk_bitmap(bt1_chunk);

    auto const new_chunk_epoch = chunk_epoch(bt1_chunk);
    ASSERT_GT(new_chunk_epoch, old_chunk_epoch);

    // Old cached node should now be stale by epoch
    ASSERT_EQ(node_epoch(stale_root), old_node_epoch);
    ASSERT_NE(node_epoch(stale_root), new_chunk_epoch);

    // Recreate btree on the same chunk. With epoch invalidation, this should not collide with stale WBC
    auto bt2 = create_btree();
    ASSERT_EQ(BlkId{bt2->root_node_id()}.chunk_num(), bt1_chunk);

    auto new_root = bt2->read_node_for_test(bt2->root_node_id());
    ASSERT_EQ(node_epoch(new_root), new_chunk_epoch);
    ASSERT_NE(node_epoch(new_root), node_epoch(stale_root));

    // And the tree should be usable
    insert_range(bt2, 100000, 100128);
    bt2->warm_all_nodes_into_wbc();
}

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
    } else {
        auto seed = std::chrono::system_clock::now().time_since_epoch().count();
        LOGINFO("No seed provided. Using randomly generated seed: {}", seed);
        g_re.seed(seed);
    }

#ifdef _PRERELEASE
    return RUN_ALL_TESTS();
#else
    return 0;
#endif
}
