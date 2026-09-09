#include <gtest/gtest.h>
#include <boost/uuid/random_generator.hpp>

#include "device/device.h"
#include "device/chunk.h"
#include "common/homestore_config.hpp"
#include "common/resource_mgr.hpp"
#include "test_common/homestore_test_common.hpp"
#include "btree_helpers/btree_test_helper.hpp"
#include "btree_helpers/btree_test_kvs.hpp"
#include "btree_helpers/btree_decls.h"
#include "homestore/chunk_selector.hpp"

using namespace homestore;

SISL_OPTIONS_ENABLE(logging, test_index_chunk_selector, iomgr, test_common_setup)

SISL_OPTION_GROUP(
    test_index_chunk_selector,
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
                    << "failed to read node " << blk_id{node_id}.to_string();
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

    DeterministicChunkSelectorWbcReuseTest() : ::testing::Test() {
        this->m_is_multi_threaded = false;
    }

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
        (void)bt->destroy();
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

    uint32_t assert_all_nodes_on_same_chunk(std::shared_ptr< InspectableBtree >& bt) {
        auto ids = bt->collect_node_ids();
        HS_DBG_ASSERT_GT(ids.size(), 1u, "expected more than one node");

        auto it = ids.begin();
        auto expected_chunk = blk_id{*it}.chunk_num();

        for (auto const id : ids) {
            auto const chunk_num = blk_id{id}.chunk_num();
            DEBUG_ASSERT_EQ(chunk_num, expected_chunk,
                "node {} landed on chunk {} but expected chunk {}", blk_id{id}.to_string(), chunk_num, expected_chunk);
        }

        return expected_chunk;
    }

    void clear_chunk_bitmap(chunk_num_t chunk_num) {
        Chunk* chunk = hs()->device_mgr()->get_chunk_mutable(chunk_num);
        ASSERT_NE(chunk, nullptr) << "chunk " << chunk_num << " not found";

        // Zero the alloc bitmap so the next btree reuses bt1 blkids
        chunk->reset_block_allocator();
    }

    void evict_wbc_and_clear_chunk_async(chunk_num_t chunk_num) {
        Chunk* chunk = hs()->device_mgr()->get_chunk_mutable(chunk_num);
        ASSERT_NE(chunk, nullptr) << "chunk " << chunk_num << " not found";

        auto done = std::make_shared<std::promise<void>>();
        auto fut = done->get_future();

        iomanager.run_on_forget(iomgr::reactor_regex::random_worker,
                                [chunk, done]() {
                                    hs()->index_service().wb_cache().evict_chunk_blkids(*chunk);
                                    chunk->reset_block_allocator();
                                    done->set_value();
                                });

        fut.wait();
    }

    std::shared_ptr< InspectableBtree > m_last_recovered_bt;
};

#ifdef _PRERELEASE

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

    // Evict stale WBC entries for that chunk, then clear allocator state
    evict_wbc_and_clear_chunk_async(bt1_chunk);

    // Clear the chunk
    //clear_chunk_bitmap(bt1_chunk);

    // Create bt2 on the same chunk with stale WBC entries still present;
    // Duplicate insert should happen here on root creation
    auto bt2 = create_btree();

    ASSERT_EQ(blk_id{bt2->root_node_id()}.chunk_num(), bt1_chunk)
        << "bt2 root did not land on the expected reused chunk";

    ASSERT_TRUE(bt1_node_ids.contains(bt2->root_node_id()))
        << "bt2 root did not immediately reuse a bt1 blkid; setup is not deterministic";

    // The tree must remain usable
    auto ret = insert_range(bt2, 100000, 100128);
    ASSERT_EQ(ret, btree_status_t::success);
}

#endif

int main(int argc, char* argv[]) {
    int parsed_argc{argc};
    ::testing::InitGoogleTest(&parsed_argc, argv);
    SISL_OPTIONS_LOAD(parsed_argc, argv, logging, test_index_chunk_selector, iomgr, test_common_setup);
    spdlog::set_pattern("[%D %T%z] [%^%L%$] [%t] %v");
    g_re.seed(std::chrono::system_clock::now().time_since_epoch().count());

#ifdef _PRERELEASE
    return RUN_ALL_TESTS();
#else
    return 0;
#endif
}