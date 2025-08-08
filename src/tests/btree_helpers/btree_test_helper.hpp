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
#pragma once

#include <random>
#include <map>
#include <atomic>
#include <memory>
#include <iomgr/io_environment.hpp>
#include <sisl/options/options.h>
#include <sisl/logging/logging.h>
#include <sisl/utility/enum.hpp>
#include <iomgr/iomgr_flip.hpp>
#include <boost/algorithm/string.hpp>
#include <homestore/btree/btree.ipp>

#include "test_common/range_scheduler.hpp"
#include "shadow_map.hpp"

static constexpr uint32_t g_node_size{4096};

struct BtreeTestOptions {
    uint32_t num_entries;
    uint32_t preload_size;
    uint32_t num_ios;
    uint32_t run_time_secs;
    bool disable_merge{false};
};

template < typename TestType >
struct BtreeTestHelper {
    using T = TestType;
    using K = typename TestType::KeyType;
    using V = typename TestType::ValueType;
    using mutex = iomgr::FiberManagerLib::shared_mutex;
    using op_func_t = std::function< void(void) >;

    BtreeTestHelper(BtreeTestOptions options) : m_options{std::move(options)}, m_shadow_map{options.num_entries} {
        m_cfg.m_leaf_node_type = T::leaf_node_type;
        m_cfg.m_int_node_type = T::interior_node_type;
        m_cfg.m_store_type = T::store_type;
    }

    virtual void SetUp(std::shared_ptr< Btree< K, V > > bt, bool load, bool is_multi_threaded = false) {
        m_bt = std::move(bt);
        m_shadow_filename = fmt::format("/tmp/btree_{}_shadow_map", m_bt->ordinal());

        if (!load) { std::filesystem::remove(m_shadow_filename); }
        m_max_range_input = m_options.num_entries;
        m_is_multi_threaded = is_multi_threaded;
        if (m_options.disable_merge) { m_cfg.m_merge_turned_on = false; }

        if (m_is_multi_threaded) {
            std::mutex mtx;
            m_fibers.clear();
            iomanager.run_on_wait(iomgr::reactor_regex::all_worker, [this, &mtx]() {
                auto fv = iomanager.sync_io_capable_fibers();
                std::unique_lock lg(mtx);
                m_fibers.insert(m_fibers.end(), fv.begin(), fv.end());
            });
        }

        m_operations["put"] = std::bind(&BtreeTestHelper::put_random, this);
        m_operations["remove"] = std::bind(&BtreeTestHelper::remove_random, this);
        m_operations["range_put"] = std::bind(&BtreeTestHelper::range_put_random, this);
        m_operations["range_remove"] = std::bind(&BtreeTestHelper::range_remove_existing_random, this);
        m_operations["query"] = std::bind(&BtreeTestHelper::query_random, this);
    }

    void TearDown() {}

public:
    std::shared_ptr< Btree< K, V > > m_bt;
    BtreeConfig m_cfg;

protected:
    BtreeTestOptions const m_options;
    ShadowMap< K, V > m_shadow_map;
    uint32_t m_max_range_input{1000};
    bool m_is_multi_threaded{false};

    std::map< std::string, op_func_t > m_operations;
    std::vector< iomgr::io_fiber_t > m_fibers;
    std::mutex m_test_done_mtx;
    std::condition_variable m_test_done_cv;
    std::random_device m_re;
    std::atomic< uint32_t > m_num_ops{0};
    Clock::time_point m_start_time;
    std::string m_shadow_filename;

#ifdef _PRERELEASE
    flip::FlipClient m_fc{iomgr_flip::instance()};
#endif
public:
#ifdef _PRERELEASE
    void set_flip_point(const std::string flip_name) {
        flip::FlipCondition null_cond;
        flip::FlipFrequency freq;
        freq.set_count(10000);
        freq.set_percent(100);
        m_fc.inject_noreturn_flip(flip_name, {null_cond}, freq);
        m_bt->set_flip_point(flip_name);
        LOGINFO("Flip {} set", flip_name);
    }
    void reset_flip_point(const std::string flip_name) {
        m_fc.remove_flip(flip_name);
        LOGINFO("Flip {} reset", flip_name);
    }
#endif

    void preload(uint32_t preload_size) {
        if (preload_size == 0) {
            LOGINFO("Preload Skipped");
            return;
        }

        const auto n_fibers = std::min(preload_size, (uint32_t)m_fibers.size());
        const auto chunk_size = preload_size / n_fibers;
        const auto last_chunk_size = preload_size % chunk_size ?: chunk_size;
        auto test_count = n_fibers;

        LOGINFO("Btree{}: {} entries will be preloaded in {} fibers in parallel", m_bt->ordinal(), preload_size,
                m_fibers.size());
        for (std::size_t i = 0; i < n_fibers; ++i) {
            const auto start_range = i * chunk_size;
            const auto end_range = start_range + ((i == n_fibers - 1) ? last_chunk_size : chunk_size) - 1;
            auto fiber_id = i;
            iomanager.run_on_forget(m_fibers[i], [this, start_range, end_range, &test_count, fiber_id, preload_size]() {
                m_start_time = Clock::now();
                for (uint32_t i = start_range; i < end_range; i++) {
                    put(i, btree_put_type::INSERT);
                    track_progress(preload_size, "Preload");
                }
                {
                    std::unique_lock lg(m_test_done_mtx);
                    if (--test_count == 0) { m_test_done_cv.notify_one(); }
                }
            });
        }

        {
            std::unique_lock< std::mutex > lk(m_test_done_mtx);
            m_test_done_cv.wait(lk, [&]() { return test_count == 0; });
        }

        LOGINFO("Btree{}: Preload Done", m_bt->ordinal());
    }

    uint32_t get_op_num() const { return m_num_ops.load(); }

    void track_progress(uint32_t max_ops, std::string_view work_type) {
        static Clock::time_point last_print_time{Clock::now()};

        bool print{false};
        auto completed = m_num_ops.fetch_add(1) + 1;

        auto elapsed_time = get_elapsed_time_sec(last_print_time);
        if (elapsed_time > 30) {
            // Print percent every 30 seconds no matter what
            print = true;
        } else if ((completed % (max_ops / 10) == 0) && (elapsed_time > 1)) {
            // 10% completed and at least 1 second after last print time, we can print again
            print = true;
        }

        if (print) {
            auto map_size = m_shadow_map.size();
            LOGINFO("Progress=({:.2f}%) IOsCompleted={} ElapsedTime={} seconds {} EntriesFilled={} ({:.2f}%)",
                    completed * 100.0 / max_ops, completed, get_elapsed_time_sec(m_start_time), work_type, map_size,
                    map_size * 100.0 / m_max_range_input);
            last_print_time = Clock::now();
        }
    }

    ////////////////////// All put operation variants ///////////////////////////////
    void put(uint64_t k, btree_put_type put_type, bool expect = true) {
        do_put(k, put_type, V::generate_rand(), expect);
    }

    void put_random() {
        auto [start_k, end_k] = m_shadow_map.pick_random_non_existing_keys(1);
        RELEASE_ASSERT_EQ(start_k, end_k, "Range scheduler pick_random_non_existing_keys issue");

        do_put(start_k, btree_put_type::INSERT, V::generate_rand());
    }

    void force_upsert(uint64_t k) {
        auto existing_v = std::make_unique< V >();
        K key = K{k};
        V value = V::generate_rand();

        auto const ret = m_bt->put_one(key, value, btree_put_type::UPSERT, existing_v.get());
        ASSERT_EQ(ret, btree_status_t::success) << "Upsert key=" << k << " failed with error=" << enum_name(ret);
        m_shadow_map.force_put(k, value);
    }

    void put_delta(uint64_t k) {
        K key{k};
        auto it = m_shadow_map.map_const().find(key);
        ASSERT_TRUE(it != m_shadow_map.map_const().cend())
            << "Asked to put_delta for key=" << k << " but its not in the map";

        auto existing_v = std::make_unique< V >();
        auto const ret = m_bt->put_one(key, it->second, btree_put_type::UPSERT, existing_v.get());
        ASSERT_EQ(ret, btree_status_t::success) << "Upsert key=" << k << " failed with error=" << enum_name(ret);
    }

    void range_put(uint32_t start_k, uint32_t end_k, V const& value, bool update) {
        K start_key = K{start_k};
        K end_key = K{end_k};
        auto const nkeys = end_k - start_k + 1;

        auto const [ret, cookie] = m_bt->put_range(BtreeKeyRange< K >{start_key, true, end_key, true},
                                                   update ? btree_put_type::UPDATE : btree_put_type::UPSERT, value);
        ASSERT_EQ(ret, btree_status_t::success) << "range_put failed for " << start_k << "-" << end_k;

        if (update) {
            m_shadow_map.range_update(start_key, nkeys, value);
        } else {
            m_shadow_map.range_upsert(start_k, nkeys, value);
        }
    }

    void range_put_random() {
        bool is_update{true};
        if constexpr (std::is_same_v< V, TestIntervalValue >) { is_update = false; }

        static thread_local std::uniform_int_distribution< uint32_t > s_rand_range_generator{1, 50};

        auto const [start_k, end_k] = is_update
            ? m_shadow_map.pick_random_existing_keys(s_rand_range_generator(m_re))
            : m_shadow_map.pick_random_non_working_keys(s_rand_range_generator(m_re));

        range_put(start_k, end_k, V::generate_rand(), is_update);
    }

    ////////////////////// All remove operation variants ///////////////////////////////
    void remove_one(uint32_t k, bool care_success = true) {
        auto existing_v = std::make_unique< V >();
        auto pk = std::make_unique< K >(k);

        bool removed = (m_bt->remove_one(*pk, existing_v.get()) == btree_status_t::success);
        if (care_success) {
            ASSERT_EQ(removed, m_shadow_map.exists(*pk))
                << "Removal of key " << pk->key() << " status doesn't match with shadow";
            if (removed) { m_shadow_map.remove_and_check(*pk, *existing_v); }
        } else {
            // Do not care if the key is not present in the btree, just cleanup the shadow map
            m_shadow_map.erase(*pk);
        }
    }

    void remove_random() {
        auto const [start_k, end_k] = m_shadow_map.pick_random_existing_keys(1);
        RELEASE_ASSERT_EQ(start_k, end_k, "Range scheduler pick_random_existing_keys issue");

        remove_one(start_k);
    }

    void range_remove_existing(uint32_t start_k, uint32_t count) {
        auto [start_key, end_key] = m_shadow_map.pick_existing_range(K{start_k}, count);
        do_range_remove(start_k, end_key.key(), true /* removing_all_existing */);
    }

    void range_remove_existing_random() {
        static std::uniform_int_distribution< uint32_t > s_rand_range_generator{2, 50};

        auto const [start_k, end_k] = m_shadow_map.pick_random_existing_keys(s_rand_range_generator(m_re));
        do_range_remove(start_k, end_k, true /* only_existing */);
    }

    void range_remove_any(uint32_t start_k, uint32_t end_k) {
        do_range_remove(start_k, end_k, false /* removing_all_existing */);
    }

    ////////////////////// All query operation variants ///////////////////////////////
    void query_all() { do_query(0u, m_options.num_entries - 1, UINT32_MAX); }

    void query_all_paginate(uint32_t batch_size) { do_query(0u, m_options.num_entries - 1, batch_size); }

    void do_query(uint32_t start_k, uint32_t end_k, uint32_t batch_size) {
        std::vector< std::pair< K, V > > out_vector;
        m_shadow_map.guard().lock();
        uint32_t remaining = m_shadow_map.num_elems_in_range(start_k, end_k);
        auto it = m_shadow_map.map_const().lower_bound(K{start_k});

        btree_status_t ret;
        QueryPaginateCookie< K > cookie;

        while (remaining > 0) {
            out_vector.clear();

            auto const expected_count = std::min(remaining, batch_size);
            if (!cookie) {
                std::tie(ret, cookie) = m_bt->query(BtreeKeyRange< K >{K{start_k}, true, K{end_k}, true}, out_vector,
                                                    batch_size, BtreeQueryType::SWEEP_NON_INTRUSIVE_PAGINATION_QUERY);
            } else {
                ret = m_bt->query_next(cookie, out_vector);
            }

            // this->print_keys();
            ASSERT_EQ(out_vector.size(), expected_count) << "Received incorrect value on query pagination";

            if (remaining < batch_size) {
                ASSERT_EQ(ret, btree_status_t::success) << "Expected success on query";
            } else if (remaining > batch_size) {
                ASSERT_EQ(ret, btree_status_t::has_more) << "Expected query to return has_more";
            } else if (remaining == batch_size) {
                // we don't know, go to the next round
            }

            remaining -= expected_count;

            for (size_t idx{0}; idx < out_vector.size(); ++idx) {
                ASSERT_EQ(out_vector[idx].second, it->second)
                    << "Range get doesn't return correct data for key=" << it->first << " idx=" << idx;
                ++it;
            }
        }
        out_vector.clear();
        ret = m_bt->query_next(cookie, out_vector);
        ASSERT_EQ(ret, btree_status_t::success) << "Expected success on query";
        ASSERT_EQ(out_vector.size(), 0) << "Received incorrect value on empty query pagination";

        m_shadow_map.guard().unlock();

        if (start_k < m_max_range_input) {
            m_shadow_map.remove_keys_from_working(start_k, std::min(end_k, m_max_range_input - 1));
        }
    }

    void query_random() {
        static thread_local std::uniform_int_distribution< uint32_t > s_rand_range_generator{1, 100};

        auto const [start_k, end_k] = m_shadow_map.pick_random_non_working_keys(s_rand_range_generator(m_re));
        do_query(start_k, end_k, 79);
    }

    ////////////////////// All get operation variants ///////////////////////////////
    void get_all() const {
        m_shadow_map.foreach ([this](K key, V value) {
            auto out_v = std::make_unique< V >();
            const auto ret = m_bt->get_one(key, out_v.get());

            ASSERT_EQ(ret, btree_status_t::success) << "Missing key " << key << " in btree but present in shadow map";
            ASSERT_EQ((const V&)*out_v, value) << "Found value in btree doesn't return correct data for key=" << key;
        });
    }

    void get_specific(uint32_t k) const {
        K key = K{k};
        auto out_v = std::make_unique< V >();
        const auto status = m_bt->get_one(key, out_v.get());

        if (status == btree_status_t::success) {
            m_shadow_map.validate_data(key, (const V&)*out_v);
        } else {
            ASSERT_EQ(m_shadow_map.exists(key), false) << "Node key " << k << " is missing in the btree";
        }
    }

    void get_any(uint32_t start_k, uint32_t end_k) const {
        auto out_k = std::make_unique< K >();
        auto out_v = std::make_unique< V >();
        auto const status =
            m_bt->get_any(BtreeKeyRange< K >{K{start_k}, true, K{end_k}, true}, out_k.get(), out_v.get());

        if (status == btree_status_t::success) {
            ASSERT_EQ(m_shadow_map.exists_in_range(*out_k, start_k, end_k), true)
                << "Get Any returned key=" << *out_k << " which is not in range " << start_k << "-" << end_k
                << "according to shadow map";
            m_shadow_map.validate_data(*out_k, *out_v);
        } else {
            ASSERT_EQ(m_shadow_map.exists_in_range(*out_k, start_k, end_k), false)
                << "Get Any couldn't find key in the range " << start_k << "-" << end_k
                << " but it present in shadow map";
        }
    }

    void multi_op_execute(const std::vector< std::pair< std::string, int > >& op_list) {
        if (m_shadow_map.size() == 0) {
            auto preload_size = m_options.preload_size;
            if (preload_size > m_options.num_entries / 2) {
                LOGWARN("Preload size={} is more than half of num_entries, setting preload_size to {}", preload_size,
                        m_options.num_entries / 2);
                preload_size = m_options.num_entries / 2;
            }
            preload(preload_size);
        }
        LOGINFO("Btree{}: {} IOs will be executed in {} fibers in parallel", m_bt->ordinal(), m_options.num_ios,
                m_fibers.size());
        run_in_parallel(op_list);
        LOGINFO("Btree{}: {} IOs completed", m_bt->ordinal(), m_options.num_ios);
    }

    void dump_to_file(const std::string& file = "") const { m_bt->dump(file); }
    void print_keys(const std::string& preamble = "") const {
        auto print_key_range = [](std::vector< std::pair< K, V > > const& kvs) -> std::string {
            uint32_t start = 0;
            std::string str;
            for (uint32_t i{1}; i <= kvs.size(); ++i) {
                if ((i == kvs.size()) || (kvs[i].first.key() != kvs[i - 1].first.key() + 1)) {
                    if ((i - start) > 1) {
                        fmt::format_to(std::back_inserter(str), "{}-{}{}", kvs[start].first.key(),
                                       kvs[i - 1].first.key(), (i == kvs.size()) ? "" : ", ");
                    } else {
                        fmt::format_to(std::back_inserter(str), "{}{}", kvs[start].first.key(),
                                       (i == kvs.size()) ? "" : ", ");
                    }
                    start = i;
                }
            }
            return str;
        };

        LOGINFO("{}{}", preamble.empty() ? "" : preamble + ":\n", m_bt->to_custom_string(print_key_range));
    }
    void visualize_keys(const std::string& file) const { m_bt->visualize_tree_keys(file); }

    void compare_files(const std::string& before, const std::string& after) {
        std::ifstream b(before, std::ifstream::ate);
        std::ifstream a(after, std::ifstream::ate);
        if (a.fail() || b.fail()) {
            LOGINFO("Failed to open file");
            assert(false);
        }
        if (a.tellg() != b.tellg()) {
            LOGINFO("Mismatch in btree files");
            assert(false);
        }

        int64_t pending = a.tellg();
        const int64_t batch_size = 4096;
        a.seekg(0, ifstream::beg);
        b.seekg(0, ifstream::beg);
        char a_buffer[batch_size], b_buffer[batch_size];
        while (pending > 0) {
            auto count = std::min(pending, batch_size);
            a.read(a_buffer, count);
            b.read(b_buffer, count);
            if (std::memcmp(a_buffer, b_buffer, count) != 0) {
                LOGINFO("Mismatch in btree files");
                assert(false);
            }
            pending -= count;
        }
    }

    ///////////////////////// All crash recovery methods ///////////////////////////////////
    void save_snapshot() { this->m_shadow_map.save(m_shadow_filename); }

    void reapply_after_crash() {
        ShadowMap< K, V > snapshot_map{m_shadow_map.max_keys()};
        snapshot_map.load(m_shadow_filename);
        LOGDEBUG("Btree:{} Snapshot before crash\n{}", m_bt->ordinal(), snapshot_map.to_string());

        auto diff = m_shadow_map.diff(snapshot_map);
        std::string dif_str;
        for (const auto& [k, delta] : diff) {
            dif_str += fmt::format("[{}-{}] ", k.key(), enum_name(delta));
        }
        LOGDEBUG("Btree:{} Diff between shadow map and snapshot map\n{}\n", m_bt->ordinal(), dif_str);

        for (const auto& [k, delta] : diff) {
            if ((delta == ShadowMapDelta::Added) || (delta == ShadowMapDelta::Updated)) {
                this->put_delta(k.key());
            } else if (delta == ShadowMapDelta::Removed) {
                this->remove_one(k.key(), false);
            }
        }
    }

private:
    void do_put(uint64_t k, btree_put_type put_type, V const& value, bool expect_success = true) {
        auto existing_v = std::make_unique< V >();
        K key = K{k};
        auto ret = m_bt->put_one(key, value, put_type, existing_v.get());
        bool done = expect_success ? (ret == btree_status_t::success) : (ret == btree_status_t::put_failed);

        if (put_type == btree_put_type::INSERT) {
            ASSERT_EQ(done, !m_shadow_map.exists(key));
        } else if (put_type == btree_put_type::UPDATE) {
            ASSERT_EQ(done, m_shadow_map.exists(key));
        }
        if (expect_success) { m_shadow_map.put_and_check(key, value, *existing_v, done); }
    }

    void do_range_remove(uint64_t start_k, uint64_t end_k, bool all_existing) {
        K start_key = K{start_k};
        K end_key = K{end_k};

        auto [ret, cookie] = m_bt->remove_range(BtreeKeyRange< K >{start_key, true, end_key, true});
        if (all_existing) {
            m_shadow_map.range_erase(start_key, end_key);
            ASSERT_EQ((ret == btree_status_t::success), true)
                << "not a successful remove op for range " << start_k << "-" << end_k;
        } else if (start_k < m_max_range_input) {
            K end_range{std::min(end_k, uint64_cast(m_max_range_input - 1))};
            m_shadow_map.range_erase(start_key, end_range);
        }
    }

public:
    void run_in_parallel(const std::vector< std::pair< std::string, int > >& op_list) {
        auto test_count = m_fibers.size();
        const auto num_ios_per_thread = m_options.num_ios / m_fibers.size();
        const auto extra_ios = m_options.num_ios % num_ios_per_thread;

        m_num_ops = 0; // Reset the ops counter
        for (uint32_t fiber_id = 0; fiber_id < m_fibers.size(); ++fiber_id) {
            auto num_ios_this_fiber = num_ios_per_thread + (fiber_id < extra_ios ? 1 : 0);
            iomanager.run_on_forget(m_fibers[fiber_id], [this, fiber_id, &test_count, op_list, num_ios_this_fiber]() {
                std::random_device g_rd{};
                std::default_random_engine re{g_rd()};
                std::vector< uint32_t > weights;
                std::transform(op_list.begin(), op_list.end(), std::back_inserter(weights),
                               [](const auto& pair) { return pair.second; });

                // Construct a weighted distribution based on the input frequencies
                std::discrete_distribution< uint32_t > s_rand_op_generator(weights.begin(), weights.end());
                m_start_time = Clock::now();
                auto time_to_stop = [this]() { return (get_elapsed_time_sec(m_start_time) > m_options.run_time_secs); };

                for (uint32_t i = 0; i < num_ios_this_fiber && !time_to_stop(); i++) {
                    uint32_t op_idx = s_rand_op_generator(re);
                    (this->m_operations[op_list[op_idx].first])();
                    track_progress(m_options.num_ios, "Workload");
                }
                {
                    std::unique_lock lg(m_test_done_mtx);
                    if (--test_count == 0) { m_test_done_cv.notify_one(); }
                }
            });
        }

        {
            std::unique_lock< std::mutex > lk(m_test_done_mtx);
            m_test_done_cv.wait(lk, [&]() { return test_count == 0; });
        }
    }

    std::vector< std::pair< std::string, int > > build_op_list(std::vector< std::string > const& input_ops) {
        std::vector< std::pair< std::string, int > > ops;
        int total = std::accumulate(input_ops.begin(), input_ops.end(), 0, [](int sum, const auto& str) {
            std::vector< std::string > tokens;
            boost::split(tokens, str, boost::is_any_of(":"));
            if (tokens.size() == 2) {
                try {
                    return sum + std::stoi(tokens[1]);
                } catch (const std::exception&) {
                    // Invalid frequency, ignore this element
                }
            }
            return sum; // Ignore malformed strings
        });

        std::transform(input_ops.begin(), input_ops.end(), std::back_inserter(ops), [total](const auto& str) {
            std::vector< std::string > tokens;
            boost::split(tokens, str, boost::is_any_of(":"));
            if (tokens.size() == 2) {
                try {
                    return std::make_pair(tokens[0], (int)(100.0 * std::stoi(tokens[1]) / total));
                } catch (const std::exception&) {
                    // Invalid frequency, ignore this element
                }
            }
            return std::make_pair(std::string(), 0);
        });

        return ops;
    }
};
