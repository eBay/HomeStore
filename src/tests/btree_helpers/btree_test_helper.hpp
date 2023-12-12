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
#include <boost/algorithm/string.hpp>

#include <homestore/btree/mem_btree.hpp>
#include "test_common/range_scheduler.hpp"
#include "shadow_map.hpp"

static constexpr uint32_t g_node_size{4096};

template < typename TestType >
struct BtreeTestHelper {
    using T = TestType;
    using K = typename TestType::KeyType;
    using V = typename TestType::ValueType;
    using mutex = iomgr::FiberManagerLib::shared_mutex;
    using op_func_t = std::function< void(void) >;

    BtreeTestHelper() : m_shadow_map{SISL_OPTIONS["num_entries"].as< uint32_t >()} {}

    void SetUp() {
        m_cfg.m_leaf_node_type = T::leaf_node_type;
        m_cfg.m_int_node_type = T::interior_node_type;
        m_max_range_input = SISL_OPTIONS["num_entries"].as< uint32_t >();
        if (SISL_OPTIONS.count("disable_merge")) { m_cfg.m_merge_turned_on = false; }

        if (m_is_multi_threaded) {
            std::mutex mtx;
            m_run_time = SISL_OPTIONS["run_time"].as< uint32_t >();
            iomanager.run_on_wait(iomgr::reactor_regex::all_io, [this, &mtx]() {
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

protected:
    std::shared_ptr< typename T::BtreeType > m_bt;
    ShadowMap< K, V > m_shadow_map;
    BtreeConfig m_cfg{g_node_size};
    uint32_t m_max_range_input{1000};
    bool m_is_multi_threaded{false};
    uint32_t m_run_time{0};

    std::map< std::string, op_func_t > m_operations;
    std::vector< iomgr::io_fiber_t > m_fibers;
    std::mutex m_test_done_mtx;
    std::condition_variable m_test_done_cv;

    std::random_device m_re;
    std::atomic< uint32_t > m_num_ops{0};

public:
    void preload(uint32_t preload_size) {
        const auto chunk_size = preload_size / m_fibers.size();
        const auto last_chunk_size = preload_size % chunk_size ?: chunk_size;
        auto test_count = m_fibers.size();

        for (std::size_t i = 0; i < m_fibers.size(); ++i) {
            const auto start_range = i * chunk_size;
            const auto end_range = start_range + ((i == m_fibers.size() - 1) ? last_chunk_size : chunk_size);
            iomanager.run_on_forget(m_fibers[i], [this, start_range, end_range, &test_count]() {
                for (uint32_t i = start_range; i < end_range; i++) {
                    put(i, btree_put_type::INSERT);
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
        LOGINFO("Preload Done");
    }

    uint32_t get_op_num() const { return m_num_ops.load(); }

    ////////////////////// All put operation variants ///////////////////////////////
    void put(uint64_t k, btree_put_type put_type) { do_put(k, put_type, V::generate_rand()); }

    void put_random() {
        auto [start_k, end_k] = m_shadow_map.pick_random_non_existing_keys(1);
        RELEASE_ASSERT_EQ(start_k, end_k, "Range scheduler pick_random_non_existing_keys issue");

        do_put(start_k, btree_put_type::INSERT, V::generate_rand());
    }

    void range_put(uint32_t start_k, uint32_t end_k, V const& value, bool update) {
        K start_key = K{start_k};
        K end_key = K{end_k};
        auto const nkeys = end_k - start_k + 1;

        auto preq = BtreeRangePutRequest< K >{BtreeKeyRange< K >{start_key, true, end_key, true},
                                              update ? btree_put_type::UPDATE : btree_put_type::UPSERT, &value};
        preq.enable_route_tracing();
        ASSERT_EQ(m_bt->put(preq), btree_status_t::success) << "range_put failed for " << start_k << "-" << end_k;

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
    void remove_one(uint32_t k) {
        auto existing_v = std::make_unique< V >();
        auto pk = std::make_unique< K >(k);

        auto rreq = BtreeSingleRemoveRequest{pk.get(), existing_v.get()};
        bool removed = (m_bt->remove(rreq) == btree_status_t::success);

        ASSERT_EQ(removed, m_shadow_map.exists(*pk))
            << "Removal of key " << pk->key() << " status doesn't match with shadow";

        if (removed) {
            m_shadow_map.validate_data(rreq.key(), (const V&)rreq.value());
            m_shadow_map.erase(rreq.key());
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
        static std::uniform_int_distribution< uint32_t > s_rand_range_generator{2, 5};

        auto const [start_k, end_k] = m_shadow_map.pick_random_existing_keys(s_rand_range_generator(m_re));
        do_range_remove(start_k, end_k, true /* only_existing */);
    }

    void range_remove_any(uint32_t start_k, uint32_t end_k) {
        do_range_remove(start_k, end_k, false /* removing_all_existing */);
    }

    ////////////////////// All query operation variants ///////////////////////////////
    void query_all() { do_query(0u, SISL_OPTIONS["num_entries"].as< uint32_t >() - 1, UINT32_MAX); }

    void query_all_paginate(uint32_t batch_size) {
        do_query(0u, SISL_OPTIONS["num_entries"].as< uint32_t >() - 1, batch_size);
    }

    void do_query(uint32_t start_k, uint32_t end_k, uint32_t batch_size) {
        std::vector< std::pair< K, V > > out_vector;
        m_shadow_map.guard().lock();
        uint32_t remaining = m_shadow_map.num_elems_in_range(start_k, end_k);
        auto it = m_shadow_map.map_const().lower_bound(K{start_k});

        BtreeQueryRequest< K > qreq{BtreeKeyRange< K >{K{start_k}, true, K{end_k}, true},
                                    BtreeQueryType::SWEEP_NON_INTRUSIVE_PAGINATION_QUERY, batch_size};
        while (remaining > 0) {
            out_vector.clear();
            qreq.enable_route_tracing();
            auto const ret = m_bt->query(qreq, out_vector);
            auto const expected_count = std::min(remaining, batch_size);

            ASSERT_EQ(out_vector.size(), expected_count) << "Received incorrect value on query pagination";
            remaining -= expected_count;

            if (remaining == 0) {
                ASSERT_EQ(ret, btree_status_t::success) << "Expected success on query";
            } else {
                ASSERT_EQ(ret, btree_status_t::has_more) << "Expected query to return has_more";
            }

            for (size_t idx{0}; idx < out_vector.size(); ++idx) {
                ASSERT_EQ(out_vector[idx].second, it->second)
                    << "Range get doesn't return correct data for key=" << it->first << " idx=" << idx;
                ++it;
            }
        }
        out_vector.clear();
        auto ret = m_bt->query(qreq, out_vector);
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
            auto copy_key = std::make_unique< K >();
            *copy_key = key;
            auto out_v = std::make_unique< V >();
            auto req = BtreeSingleGetRequest{copy_key.get(), out_v.get()};

            const auto ret = m_bt->get(req);
            ASSERT_EQ(ret, btree_status_t::success) << "Missing key " << key << " in btree but present in shadow map";
            ASSERT_EQ((const V&)req.value(), value)
                << "Found value in btree doesn't return correct data for key=" << key;
        });
    }

    void get_specific(uint32_t k) const {
        auto pk = std::make_unique< K >(k);
        auto out_v = std::make_unique< V >();
        auto req = BtreeSingleGetRequest{pk.get(), out_v.get()};

        const auto status = m_bt->get(req);
        if (status == btree_status_t::success) {
            m_shadow_map.validate_data(req.key(), (const V&)req.value());
        } else {
            ASSERT_EQ(m_shadow_map.exists(req.key()), false) << "Node key " << k << " is missing in the btree";
        }
    }

    void get_any(uint32_t start_k, uint32_t end_k) const {
        auto out_k = std::make_unique< K >();
        auto out_v = std::make_unique< V >();
        auto req =
            BtreeGetAnyRequest< K >{BtreeKeyRange< K >{K{start_k}, true, K{end_k}, true}, out_k.get(), out_v.get()};
        const auto status = m_bt->get(req);

        if (status == btree_status_t::success) {
            ASSERT_EQ(m_shadow_map.exists_in_range(*(K*)req.m_outkey, start_k, end_k), true)
                << "Get Any returned key=" << *(K*)req.m_outkey << " which is not in range " << start_k << "-" << end_k
                << "according to shadow map";
            m_shadow_map.validate_data(*(K*)req.m_outkey, *(V*)req.m_outval);
        } else {
            ASSERT_EQ(m_shadow_map.exists_in_range(*(K*)req.m_outkey, start_k, end_k), false)
                << "Get Any couldn't find key in the range " << start_k << "-" << end_k
                << " but it present in shadow map";
        }
    }

    void multi_op_execute(const std::vector< std::pair< std::string, int > >& op_list) {
        preload(SISL_OPTIONS["preload_size"].as< uint32_t >());
        run_in_parallel(op_list);
    }

    void print(const std::string& file = "") const { m_bt->print_tree(file); }
    void print_keys() const { m_bt->print_tree_keys(); }

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

private:
    void do_put(uint64_t k, btree_put_type put_type, V const& value) {
        auto existing_v = std::make_unique< V >();
        K key = K{k};
        auto sreq = BtreeSinglePutRequest{&key, &value, put_type, existing_v.get()};
        bool done = (m_bt->put(sreq) == btree_status_t::success);

        if (put_type == btree_put_type::INSERT) {
            ASSERT_EQ(done, !m_shadow_map.exists(key));
        } else {
            ASSERT_EQ(done, m_shadow_map.exists(key));
        }

        m_shadow_map.put_and_check(key, value, *existing_v, done);
    }

    void do_range_remove(uint64_t start_k, uint64_t end_k, bool all_existing) {
        K start_key = K{start_k};
        K end_key = K{end_k};

        auto rreq = BtreeRangeRemoveRequest< K >{BtreeKeyRange< K >{start_key, true, end_key, true}};
        auto const ret = m_bt->remove(rreq);

        m_shadow_map.range_erase(start_key, end_key);

        if (all_existing) {
            ASSERT_EQ((ret == btree_status_t::success), true)
                << "not a successful remove op for range " << start_k << "-" << end_k;
        }

        if (start_k < m_max_range_input) {
            m_shadow_map.remove_keys(start_k, std::min(end_k, uint64_cast(m_max_range_input - 1)));
        }
    }

protected:
    void run_in_parallel(const std::vector< std::pair< std::string, int > >& op_list) {
        auto test_count = m_fibers.size();
        for (auto it = m_fibers.begin(); it < m_fibers.end(); ++it) {
            iomanager.run_on_forget(*it, [this, &test_count, op_list]() {
                std::random_device g_rd{};
                std::default_random_engine re{g_rd()};
                const auto num_iters_per_thread =
                    sisl::round_up(SISL_OPTIONS["num_iters"].as< uint32_t >() / m_fibers.size(), m_fibers.size());
                std::vector< uint32_t > weights;
                std::transform(op_list.begin(), op_list.end(), std::back_inserter(weights),
                               [](const auto& pair) { return pair.second; });

                // Construct a weighted distribution based on the input frequencies
                std::discrete_distribution< uint32_t > s_rand_op_generator(weights.begin(), weights.end());
                auto m_start_time = Clock::now();
                auto time_to_stop = [this, m_start_time]() {
                    return (get_elapsed_time_sec(m_start_time) > m_run_time);
                };
                for (uint32_t i = 0; i < num_iters_per_thread && !time_to_stop(); i++) {
                    uint32_t op_idx = s_rand_op_generator(re);
                    (this->m_operations[op_list[op_idx].first])();
                    m_num_ops.fetch_add(1);
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
        LOGINFO("ALL parallel jobs joined");
    }

    std::vector< std::pair< std::string, int > > build_op_list(std::vector< std::string >& input_ops) {
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
        // this->run_in_parallel(ops);
    }
};
