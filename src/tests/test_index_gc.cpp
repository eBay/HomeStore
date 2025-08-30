#include <gtest/gtest.h>
#include <latch>
#include <boost/uuid/random_generator.hpp>

#include <sisl/utility/enum.hpp>
#include "common/homestore_config.hpp"
#include "common/resource_mgr.hpp"
#include "test_common/homestore_test_common.hpp"
#include "test_common/range_scheduler.hpp"
#include "btree_helpers/btree_test_helper.hpp"
#include "btree_helpers/btree_test_kvs.hpp"
#include "btree_helpers/btree_decls.h"
#include "btree_helpers/blob_route.h"


using namespace homestore;

SISL_LOGGING_INIT(HOMESTORE_LOG_MODS)
SISL_OPTIONS_ENABLE(logging, test_index_gc, iomgr, test_common_setup)
SISL_LOGGING_DECL(test_index_gc)

SISL_OPTION_GROUP(
    test_index_gc,
    (num_iters, "", "num_iters", "number of iterations for rand ops",
    ::cxxopts::value< uint32_t >()->default_value("500000"), "number"),
    (num_entries, "", "num_entries", "number of entries to test with",
     ::cxxopts::value< uint32_t >()->default_value("7000"), "number"),
    (num_put, "", "num_put", "number of entries to test with",
     ::cxxopts::value< uint32_t >()->default_value("20000"), "number"),
    (run_time, "", "run_time", "run time for io", ::cxxopts::value< uint64_t >()->default_value("36000"), "seconds"),
    (disable_merge, "", "disable_merge", "disable_merge", ::cxxopts::value< bool >()->default_value("0"), ""),
    (operation_list, "", "operation_list", "operation list instead of default created following by percentage",
     ::cxxopts::value< std::vector< std::string > >(), "operations [...]"),
    (preload_size, "", "preload_size", "number of entries to preload tree with",
     ::cxxopts::value< uint32_t >()->default_value("1000"), "number"),
    (init_device, "", "init_device", "init device", ::cxxopts::value< bool >()->default_value("1"), ""),
    (ignore_node_lock_refresh, "", "ignore_node_lock_refresh", "ignore node lock refresh", ::cxxopts::value< bool >(), ""),
    (cleanup_after_shutdown, "", "cleanup_after_shutdown", "cleanup after shutdown",
     ::cxxopts::value< bool >()->default_value("1"), ""),
    (max_merge_level, "", "max_merge_level", "max merge level", ::cxxopts::value< uint8_t >()->default_value("127"),
     ""),
    (seed, "", "seed", "random engine seed, use random if not defined",
     ::cxxopts::value< uint64_t >()->default_value("0"), "number"))


using BtreeType = IndexTable< BlobRouteByChunkKey, TestFixedValue >;
using op_func_t = std::function< void(void) >;
static constexpr uint32_t g_num_fibers{4};

class TestIndexGC : public ::testing::Test {
public:
    class TestIndexServiceCallbacks : public IndexServiceCallbacks {
    public:
        TestIndexServiceCallbacks(TestIndexGC* test) : m_test(test) {}
        std::shared_ptr< IndexTableBase > on_index_table_found(superblk< index_table_sb >&& sb) override {
            LOGINFO("Index table recovered");
            LOGINFO("Root bnode_id {} version {}", sb->root_node, sb->root_link_version);
            m_test->m_bt = std::make_shared< BtreeType >(std::move(sb), m_test->m_cfg);
            return m_test->m_bt;
        }

    private:
        TestIndexGC* m_test;
    };

    void SetUp() override {
        m_helper.start_homestore(
            "test_index_gc",
            {{HS_SERVICE::META, {.size_pct = 10.0}},
             {HS_SERVICE::INDEX, {.size_pct = 70.0, .index_svc_cbs = new TestIndexServiceCallbacks(this)}}});

        LOGINFO("Node size {} ", hs()->index_service().node_size());
        m_cfg = BtreeConfig(hs()->index_service().node_size());

        auto uuid = boost::uuids::random_generator()();
        auto parent_uuid = boost::uuids::random_generator()();

        // Test cp flush of write back.
        HS_SETTINGS_FACTORY().modifiable_settings([](auto& s) {
            s.generic.cache_max_throttle_cnt = 10000;
            HS_SETTINGS_FACTORY().save();
        });
        homestore::hs()->resource_mgr().reset_dirty_buf_qd();

        // Create index table and attach to index service.
        m_cfg.m_leaf_node_type = btree_node_type::FIXED;
        m_cfg.m_int_node_type = btree_node_type::FIXED;
        m_cfg.m_max_merge_level = SISL_OPTIONS["max_merge_level"].as< uint8_t >();
        if (SISL_OPTIONS.count("disable_merge")) { m_cfg.m_merge_turned_on = false; }

        m_max_range_input = SISL_OPTIONS["num_entries"].as< uint32_t >();

        create_io_reactors(g_num_fibers);
        m_run_time = SISL_OPTIONS["run_time"].as< uint64_t >();

        //m_operations["put"] = std::bind(&BtreeTestHelper::put_random, this);
        //m_operations["range_remove"] = std::bind(&BtreeTestHelper::range_remove_existing_random, this);
        //m_operations["range_query"] = std::bind(&BtreeTestHelper::query_random, this);
        //m_operations["get"] = std::bind(&BtreeTestHelper::get_random, this);
        m_bt = std::make_shared< BtreeType >(uuid, parent_uuid, 0, m_cfg);
        hs()->index_service().add_index_table(m_bt);
        LOGINFO("Added index table to index service");
    }

    void TearDown() override {
        auto [interior, leaf] = m_bt->compute_node_count();
        LOGINFO("Teardown with Root bnode_id {} tree size: {} btree node count (interior = {} leaf= {})",
                m_bt->root_node_id(), m_bt->count_keys(m_bt->root_node_id()), interior, leaf);
        m_helper.shutdown_homestore(false);
        m_bt.reset();
    }

    void restart_homestore() {
        m_helper.params(HS_SERVICE::INDEX).index_svc_cbs = new TestIndexServiceCallbacks(this);
        m_helper.restart_homestore();
    }

    void destroy_btree() {
        auto cpg = hs()->cp_mgr().cp_guard();
        auto op_context = (void*)cpg.context(cp_consumer_t::INDEX_SVC);
        const auto [ret, free_node_cnt] = m_bt->destroy_btree(op_context);
        ASSERT_EQ(ret, btree_status_t::success) << "btree destroy failed";
        m_bt.reset();
    }

    void create_io_reactors(uint32_t num_io_reactors) {
        struct Context {
            std::condition_variable cv;
            std::mutex mtx;
            uint32_t thread_cnt{0};
        };
        auto ctx = std::make_shared< Context >();
        for (uint32_t i{0}; i < num_io_reactors; ++i) {
        iomanager.create_reactor("homeblks_long_running_io" + std::to_string(i), iomgr::INTERRUPT_LOOP, 1u,
                                 [this, ctx](bool is_started) {
                                     if (is_started) {
                                         {
                                             std::unique_lock< std::mutex > lk{ctx->mtx};
                                             m_fibers.push_back(iomanager.iofiber_self());
                                             ++(ctx->thread_cnt);
                                         }
                                         ctx->cv.notify_one();
                                     }
                                 });
        }
        {
            std::unique_lock< std::mutex > lk{ctx->mtx};
            ctx->cv.wait(lk, [&ctx, num_io_reactors]() { return ctx->thread_cnt == num_io_reactors; });
        }
        LOGINFO("Created {} IO reactors", m_fibers.size());
    }

    void put_many_random(uint16_t chunk_id, uint32_t num_put) {
        for (uint16_t i = 0; i < num_put; ++i) {
            auto key = BlobRouteByChunkKey{BlobRouteByChunk(chunk_id, g_randval_generator(g_re), g_randval_generator(g_re))};
            auto value = TestFixedValue::generate_rand();
            auto sreq = BtreeSinglePutRequest{&key, &value, btree_put_type::UPSERT};
            sreq.enable_route_tracing();
            const auto ret = m_bt->put(sreq);
            ASSERT_EQ(ret, btree_status_t::success);
        }
    }

    bool do_gc(uint16_t chunk_id) {
        LOGDEBUG("Starting GC for chunk {}", chunk_id);
        auto start_key = BlobRouteByChunkKey{BlobRouteByChunk(chunk_id, 0, 0)};
        auto end_key = BlobRouteByChunkKey{
            BlobRouteByChunk{chunk_id, std::numeric_limits< uint64_t >::max(), std::numeric_limits< uint64_t >::max()}};

        homestore::BtreeRangeRemoveRequest< BlobRouteByChunkKey > range_remove_req{
            homestore::BtreeKeyRange< BlobRouteByChunkKey >{
                start_key, true /* inclusive */, end_key, true /* inclusive */
            }};

        auto status = m_bt->remove(range_remove_req);
        if (status != homestore::btree_status_t::success &&
            status != homestore::btree_status_t::not_found /*already empty*/) {
            LOGWARN("fail to purge gc index for chunk={}", chunk_id);
            return false;
        }

        // after range_remove, we check again to make sure there is not any entry in the gc index table for this chunk
        homestore::BtreeQueryRequest< BlobRouteByChunkKey > query_req{homestore::BtreeKeyRange< BlobRouteByChunkKey >{
            std::move(start_key), true /* inclusive */, std::move(end_key), true /* inclusive */
        }};

        std::vector< std::pair< BlobRouteByChunkKey, TestFixedValue > > valid_blob_indexes;

        status = m_bt->query(query_req, valid_blob_indexes);
        if (status != homestore::btree_status_t::success) {
            LOGERROR("Failed to query blobs after purging reserved chunk={} in gc index table, index ret={}", chunk_id,
                    status);
            return false;
        }

        if (!valid_blob_indexes.empty()) {
            LOGERROR("gc index table is not empty for chunk={} after purging, valid_blob_indexes.size={}", chunk_id,
                    valid_blob_indexes.size());
            return SISL_OPTIONS["ignore_node_lock_refresh"].as< bool >();
        }

        return true;
    }

    void gc_task(uint32_t idx) {
        LOGINFO("GC task {} started", idx);
        auto num_puts = SISL_OPTIONS["num_put"].as< uint32_t >();
        while(!time_to_stop()) {
            // Step 1: preload chunks with some data
            for (uint16_t i = 0; i < 20; ++i) {
                uint16_t chunk_id = 20*idx + i;
                put_many_random(chunk_id, num_puts);
            }
            LOGDEBUG("Preload done for index {}", idx);

            // Step 2: start chunk gc
            for (uint16_t i = 0; i < 20; ++i) {
                uint16_t chunk_id = 20*idx + i;
            ASSERT_TRUE(do_gc(chunk_id));
            }
            LOGDEBUG("GC done for index {}", idx);
            auto elapsed_time = get_elapsed_time_sec(m_start_time);
            static uint64_t log_pct = 0;
            if (auto done_pct = (m_run_time > 0) ? (elapsed_time * 100) / m_run_time : 100; done_pct > log_pct) {
                LOGINFO("done pct={}, elapsed={}, fiber idx={}", done_pct, elapsed_time, idx);
                log_pct += 5;
            }
        }
        LOGINFO("GC task {} completed", idx);
        m_test_done_latch.count_down();
    }

    void put_task(uint32_t idx) {
        LOGINFO("Put task {} started", idx);
        while (!time_to_stop()) {
            for (uint16_t i = 0; i < 1000; ++i) {
                uint16_t chunk_id = 20*idx + i;
                put_many_random(chunk_id, 10);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }
        LOGINFO("Put task {} completed", idx);
        m_test_done_latch.count_down();
    }

    void get_task(uint32_t idx) {
        LOGINFO("Get task {} started", idx);
        while (!time_to_stop()) {
            for (uint16_t i = 0; i < 1000; ++i) {
                uint16_t chunk_id = 20*idx + i;
                auto key = BlobRouteByChunkKey{BlobRouteByChunk(chunk_id, g_randval_generator(g_re), g_randval_generator(g_re))};
                TestFixedValue value;
                homestore::BtreeSingleGetRequest get_req{&key, &value};
                m_bt->get(get_req);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }
        LOGINFO("Get task {} completed", idx);
        m_test_done_latch.count_down();
    }

    bool time_to_stop() const {
        return (get_elapsed_time_sec(m_start_time) > m_run_time);
    }

    BtreeConfig m_cfg{g_node_size};
    std::shared_ptr< BtreeType > m_bt;
    uint32_t m_max_range_input{1000};
    bool m_is_multi_threaded{false};
    uint64_t m_run_time{0};
    test_common::HSTestHelper m_helper;
    std::vector< iomgr::io_fiber_t > m_fibers;
    std::map< std::string, op_func_t > m_operations;
    std::latch m_test_done_latch{g_num_fibers};
    Clock::time_point m_start_time;
};

TEST_F(TestIndexGC, chunk_gc_test) {
    LOGINFO("Chunk GC test start");
    m_start_time = Clock::now();
    iomanager.run_on_forget(m_fibers[0], [this]() {
        gc_task(0);
    });
    iomanager.run_on_forget(m_fibers[1], [this]() {
        gc_task(1);
    });
    iomanager.run_on_forget(m_fibers[2], [this]() {
        put_task(2);
    });
    iomanager.run_on_forget(m_fibers[3], [this]() {
        get_task(3);
    });
    m_test_done_latch.wait();
    LOGINFO("Chunk GC test passed");
}

int main(int argc, char* argv[]) {
    int parsed_argc{argc};
    ::testing::InitGoogleTest(&parsed_argc, argv);
    SISL_OPTIONS_LOAD(parsed_argc, argv, logging, test_index_gc, iomgr, test_common_setup);
    sisl::logging::SetLogger("test_index_gc");
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%f %z] [%^%L%$] [%t] %v");

    if (SISL_OPTIONS.count("seed")) {
        auto seed = SISL_OPTIONS["seed"].as< uint64_t >();
        LOGINFO("Using seed {} to sow the random generation", seed);
        g_re.seed(seed);
    } else {
        auto seed = std::chrono::system_clock::now().time_since_epoch().count();
        LOGINFO("No seed provided. Using randomly generated seed: {}", seed);
        g_re.seed(seed);
    }
    auto ret = RUN_ALL_TESTS();
    return ret;
}