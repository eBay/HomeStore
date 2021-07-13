#pragma once

#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <random>
#include <thread>

#ifdef _PRERELEASE
#include <flip/flip.hpp>
#endif

#include "homeds/loadgen/loadgen_common.hpp"

namespace homeds::loadgen {
enum class SPECIFIC_TEST : uint8_t {
    MAP = 0,
};

template < typename K, typename V, typename Store, typename Executor >
struct BtreeLoadGen {
    std::unique_ptr< KVGenerator< K, V, Store, Executor > > kvg;
    std::atomic< uint64_t > stored_keys{0}, outstanding_create{0}, outstanding_others{0};
    uint32_t CHECKPOINT_RANGE_BATCH_SIZE{50};
    uint32_t UPDATE_RANGE_BATCH_SIZE{64};
    uint32_t QUERY_RANGE_BATCH_SIZE{32};
    mutable std::mutex m_mtx;
    std::condition_variable m_cv;
    Param p;
    bool m_loadgen_verify_mode{false};
    std::atomic< uint64_t > C_NC{0}, C_NR{0}, C_NU{0}, C_ND{0}, C_NRU{0}, C_NRQ{0},
        C_NV{0}; // current op issued counter

    explicit BtreeLoadGen(const size_t n_threads, const bool verification = true) {
        kvg = std::make_unique< KVGenerator< K, V, Store, Executor > >(n_threads, verification);
    }
    BtreeLoadGen(const BtreeLoadGen&) = delete;
    BtreeLoadGen& operator=(const BtreeLoadGen&) = delete;
    BtreeLoadGen(BtreeLoadGen&&) noexcept = delete;
    BtreeLoadGen& operator=(BtreeLoadGen&&) noexcept = delete;
    ~BtreeLoadGen() = default;

    uint64_t get_warmup_key_count(const uint8_t percent) const { return static_cast<uint64_t>(percent) * p.WARM_UP_KEYS / 100; }

    uint64_t get_existing_key_count(const uint8_t percent) const {
        return static_cast< uint64_t >(percent) * kvg->get_keys_count() / 100;
    }

    Executor& get_executor() { return kvg->get_executor(); }

    void do_checkpoint() {
        kvg->run_parallel([&]() {
            for (uint64_t i{0}; i < get_existing_key_count(100); i += CHECKPOINT_RANGE_BATCH_SIZE) {
                kvg->range_query(KeyPattern::SEQUENTIAL, CHECKPOINT_RANGE_BATCH_SIZE, true /* exclusive_access */, true,
                                 true);
            }
        });
    }

    void do_inserts() {
        // preload sequentail 50%
        kvg->preload(KeyPattern::SEQUENTIAL, ValuePattern::RANDOM_BYTES, get_warmup_key_count(50));

        // insert random 50%
        kvg->run_parallel([&]() {
            for (uint64_t i{0}; i < get_warmup_key_count(50); ++i) {
                kvg->insert_new(KeyPattern::UNI_RANDOM, ValuePattern::RANDOM_BYTES);
            }
        });
    }

    void do_updates() {
        const auto tenPer{get_existing_key_count(10)};
        const auto thirtyPer{get_existing_key_count(30)};

        // update sequential 10%, from start
        kvg->reset_pattern(KeyPattern::SEQUENTIAL, 0);
        kvg->run_parallel([&]() {
            for (uint64_t i{0}; i < tenPer; ++i) {
                kvg->update(KeyPattern::SEQUENTIAL, ValuePattern::RANDOM_BYTES, true, true);
            }
        });

        // update sequential 10%, trailing
        kvg->reset_pattern(KeyPattern::SEQUENTIAL, get_existing_key_count(90));
        kvg->run_parallel([&]() {
            for (uint64_t i{0}; i < tenPer; ++i) {
                kvg->update(KeyPattern::SEQUENTIAL, ValuePattern::RANDOM_BYTES, true, true);
            }
        });

        // update random 30%
        kvg->run_parallel([&]() {
            for (uint64_t i{0}; i < thirtyPer; ++i) {
                kvg->update(KeyPattern::UNI_RANDOM, ValuePattern::RANDOM_BYTES, true, true);
            }
        });
    }

    void do_removes() {
        const auto tenPer{get_existing_key_count(10)};
        const auto thirtyPer{get_existing_key_count(30)};

        // remove sequential 10% from start
        kvg->reset_pattern(KeyPattern::SEQUENTIAL, 0);
        kvg->run_parallel([&]() {
            for (uint64_t i{0}; i < tenPer; ++i) {
                kvg->remove(KeyPattern::SEQUENTIAL, true, true);
            }
        });

        // remove trailing 10%
        kvg->reset_pattern(KeyPattern::SEQUENTIAL, get_existing_key_count(90));
        kvg->run_parallel([&]() {
            for (uint64_t i{0}; i < tenPer; ++i) {
                kvg->remove(KeyPattern::SEQUENTIAL, true, true);
            }
        });

        // remove random 30%
        kvg->run_parallel([&]() {
            for (uint64_t i{0}; i < thirtyPer; ++i) {
                kvg->remove(KeyPattern::UNI_RANDOM, true, true);
            }
        });

        kvg->remove_all_keys();
    }

    void initParam(homeds::loadgen::Param& parameters) {
        // reset times so as runtime is based on start of each test.
        // workload shift is also based on each test instead of global
        parameters.startTime = Clock::now();
        parameters.print_startTime = Clock::now();
        parameters.workload_shiftTime = Clock::now();

        this->p = parameters;
        kvg->set_max_keys(p.NK);
        kvg->init_generator(parameters);
    }

    void do_sub_range_test() {
        // We do inserts then issue large range update to test inner node fanout
        // also add flips to simulate split while in fanout
        const uint64_t kc{get_warmup_key_count(100)};
        kvg->preload(KeyPattern::SEQUENTIAL, ValuePattern::SEQUENTIAL_VAL, kc);
        stored_keys += kc;
        assert(kvg->get_keys_count() == kc);
        kvg->reset_pattern(KeyPattern::SEQUENTIAL, 0);
#ifdef _PRERELEASE
        flip::FlipClient fc(HomeStoreFlip::instance());
        flip::FlipFrequency freq;
        freq.set_count(1);
        freq.set_percent(100);
        fc.inject_noreturn_flip("btree_leaf_node_split", {}, freq);
#endif
        kvg->run_parallel([&]() {
            // single range update over entire tree
            for (uint32_t i{0}; i < kc; i += UPDATE_RANGE_BATCH_SIZE) {
                kvg->range_update(KeyPattern::SEQUENTIAL, ValuePattern::SEQUENTIAL_VAL, UPDATE_RANGE_BATCH_SIZE, true,
                                  true, true);
            }
        });
    }
    void specific_tests(SPECIFIC_TEST st) {
        if (st == SPECIFIC_TEST::MAP) { do_sub_range_test(); }
    }
    void warmup(const bool update_allowed, const bool remove_allowed, const bool range_update_allowed, const bool range_query_allowed) {
        // basic serialized tests
        do_inserts();
        if (update_allowed) { do_updates(); }
        if (remove_allowed) { do_removes(); }
    }

    void join() {
        std::unique_lock< std::mutex > lk{m_mtx};
        m_cv.wait(lk, [this] { return (outstanding_create + outstanding_others == 0); });
    }

    void insert_success_cb(const int op = 1) {
        {
            std::unique_lock< std::mutex > lk{m_mtx};
            stored_keys += op;
            const auto prev_outstanding{outstanding_create.fetch_sub(static_cast< uint64_t >(op))};
            assert(prev_outstanding >= static_cast< uint64_t >(op));
        }
        m_cv.notify_one();
    }

    void remove_success_cb(const int op = 1) {
        {
            std::unique_lock< std::mutex > lk{m_mtx};
            const auto prev_stored{stored_keys.fetch_sub(static_cast< uint64_t >(op))};
            assert(prev_stored >= static_cast< uint64_t >(op));
            const auto prev_outstanding{outstanding_others.fetch_sub(static_cast< uint64_t >(op))};
            assert(prev_outstanding >= static_cast< uint64_t >(op));
        }
        m_cv.notify_one();
    }

    void read_update_success_cb(const int op = 1) {
        {
            std::unique_lock< std::mutex > lk{m_mtx};
            if (op == 0) {
                // range update succes cb
                const auto prev{outstanding_others.fetch_sub(UPDATE_RANGE_BATCH_SIZE)};
                assert(prev >= UPDATE_RANGE_BATCH_SIZE);
            }
            if (op == -1) {
                // range query succes cb
                const auto prev{outstanding_others.fetch_sub(QUERY_RANGE_BATCH_SIZE)};
                assert(prev >= QUERY_RANGE_BATCH_SIZE);
            } else {
                const auto prev{outstanding_others.fetch_sub(static_cast< uint64_t >(op))};
                assert(prev >= static_cast< uint64_t >(op));
            }
        }
        m_cv.notify_one();
    }

    uint64_t get_elapsed_time(const Clock::time_point& stTime) const {
        const std::chrono::seconds sec{std::chrono::duration_cast< std::chrono::seconds >(Clock::now() - stTime)};
        return sec.count();
    }

    bool increment_create() {
        std::unique_lock< std::mutex > lk{m_mtx};
        if ((stored_keys + outstanding_create) >= p.NK) return false; // cant accomodate more
        ++outstanding_create;
        return true;
    }

    bool increment_other(const int op = 1) {
        std::unique_lock< std::mutex > lk{m_mtx};
        if ((outstanding_others > stored_keys) || (stored_keys - outstanding_others < static_cast<uint64_t>(op))) return false; // cannot accomodate more
        outstanding_others += op;
        return true;
    }

    bool is_storedkey_watermark_reached(const uint64_t watermark) const {
        std::unique_lock< std::mutex > lk{m_mtx};
        return (stored_keys + outstanding_create > watermark);
    }

    uint64_t get_issued_ios() const {
        return C_NC + C_NR + C_NU + C_ND + C_NRU / UPDATE_RANGE_BATCH_SIZE + C_NRQ / QUERY_RANGE_BATCH_SIZE;
    }

    void handle_generic_error(const generator_op_error err, const key_info< K, V >* const ki, void* const store_error,
                              const std::string& err_text = "") {
        m_loadgen_verify_mode = true;
        LOGERROR("Store reported error {}, error_text = {}", err, err_text);
    }

    void try_create() {
        if (!increment_create()) return;

        kvg->insert_new(KeyPattern::UNI_RANDOM, ValuePattern::RANDOM_BYTES,
                        std::bind(&BtreeLoadGen::insert_success_cb, this, std::placeholders::_1), true,
                        std::bind(&BtreeLoadGen::handle_generic_error, this, std::placeholders::_1,
                                  std::placeholders::_2, std::placeholders::_3, std::placeholders::_4));
        ++C_NC;
        try_print();
    }

    void try_read() {
        if (!increment_other()) return;

        kvg->get(KeyPattern::UNI_RANDOM, true, true, true,
                 std::bind(&BtreeLoadGen::read_update_success_cb, this, std::placeholders::_1),
                 std::bind(&BtreeLoadGen::handle_generic_error, this, std::placeholders::_1, std::placeholders::_2,
                           std::placeholders::_3, std::placeholders::_4));
        ++C_NR;
        try_print();
    }

    void try_update() {
        if (!increment_other()) return;

        kvg->update(KeyPattern::UNI_RANDOM, ValuePattern::RANDOM_BYTES, true, true, true,
                    std::bind(&BtreeLoadGen::read_update_success_cb, this, std::placeholders::_1),
                    std::bind(&BtreeLoadGen::handle_generic_error, this, std::placeholders::_1, std::placeholders::_2,
                              std::placeholders::_3, std::placeholders::_4));
        ++C_NU;
        try_print();
    }

    void try_range_update() {
        if (!is_storedkey_watermark_reached(UPDATE_RANGE_BATCH_SIZE * 2)) return;

        while (!increment_other(UPDATE_RANGE_BATCH_SIZE)) {
            std::this_thread::sleep_for(std::chrono::seconds{1});
            // if cannot accomodate, halt issue of any new ios and wait for pending ios to finish
        }
        kvg->range_update(KeyPattern::UNI_RANDOM, ValuePattern::RANDOM_BYTES, UPDATE_RANGE_BATCH_SIZE, true, true, true,
                          std::bind(&BtreeLoadGen::read_update_success_cb, this, std::placeholders::_1),
                          std::bind(&BtreeLoadGen::handle_generic_error, this, std::placeholders::_1,
                                    std::placeholders::_2, std::placeholders::_3, std::placeholders::_4));
        C_NRU += UPDATE_RANGE_BATCH_SIZE;
        try_print();
    }

    void try_range_query() {
        if (!is_storedkey_watermark_reached(QUERY_RANGE_BATCH_SIZE * 2)) return;

        while (!increment_other(QUERY_RANGE_BATCH_SIZE)) {
            std::this_thread::sleep_for(std::chrono::seconds{1});
            // if cannot accomodate, halt issue of any new ios and wait for pending ios to finish
        }
        kvg->range_query(KeyPattern::UNI_RANDOM, QUERY_RANGE_BATCH_SIZE, true, true, true,
                         std::bind(&BtreeLoadGen::read_update_success_cb, this, std::placeholders::_1),
                         std::bind(&BtreeLoadGen::handle_generic_error, this, std::placeholders::_1,
                                   std::placeholders::_2, std::placeholders::_3, std::placeholders::_4));

        C_NRQ += QUERY_RANGE_BATCH_SIZE;
        try_print();
    }

    bool try_verify_all() {
        if (C_NV > p.NK) { return true; }
        kvg->verify_all(QUERY_RANGE_BATCH_SIZE);
        C_NV += QUERY_RANGE_BATCH_SIZE;
        try_print();
        return false;
    }

    void try_delete() {
        if (!increment_other()) return;
        kvg->remove(KeyPattern::UNI_RANDOM, true, true,
                    std::bind(&BtreeLoadGen::remove_success_cb, this, std::placeholders::_1), true,
                    std::bind(&BtreeLoadGen::handle_generic_error, this, std::placeholders::_1, std::placeholders::_2,
                              std::placeholders::_3, std::placeholders::_4));
        ++C_ND;
        try_print();
    }

    void try_print() {
        if (get_elapsed_time(p.print_startTime) > p.PRINT_INTERVAL) {
            p.print_startTime = Clock::now();

            LOGINFO("stored_keys:{}, outstanding_create:{},"
                    " outstanding_others:{}, creates:{}, reads:{}, updates:{}, deletes:{}, "
                    "rangeupdate:{}, rangequery:{}, total_io:{}, verify_io:{}",
                    stored_keys, outstanding_create, outstanding_others, C_NC, C_NR, C_NU, C_ND,
                    C_NRU / UPDATE_RANGE_BATCH_SIZE, C_NRQ / QUERY_RANGE_BATCH_SIZE, get_issued_ios(), C_NV);
        }
    }

    void regression(const bool update_allowed, const bool remove_allowed, const bool range_update_allowed, const bool range_query_allowed) {
        kvg->run_parallel([&]() {
            while (true) {
                const auto op{select_io()};

                if (m_loadgen_verify_mode) {

                    if (!range_query_allowed || try_verify_all()) { break; }
                    continue;
                }
                if (op == 1)
                    try_create();
                else if (op == 2)
                    try_read();
                else if (op == 3) {
                    if (!update_allowed) continue;
                    try_update();
                } else if (op == 4) {
                    if (!remove_allowed) continue;
                    try_delete();
                } else if (op == 5) {
                    if (!range_update_allowed) continue;
                    try_range_update();
                } else if (op == 6) {
                    if (!range_query_allowed) continue;
                    try_range_query();
                } else
                    assert(false);

                if ((get_issued_ios() > p.NIO) || (get_elapsed_time(p.startTime) > p.NRT)) break;
            }
        });

        if (remove_allowed) kvg->remove_all_keys();
        join();
        LOGINFO("stored_keys:{}, outstanding_create:{},"
                " outstanding_others:{}, creates:{}, reads:{}, updates:{}, deletes:{}, "
                "rangeupdate:{}, rangequery:{}, total_io:{}, verify_io:{}",
                stored_keys, outstanding_create, outstanding_others, C_NC, C_NR, C_NU, C_ND,
                C_NRU / UPDATE_RANGE_BATCH_SIZE, C_NRQ / QUERY_RANGE_BATCH_SIZE, get_issued_ios(), C_NV);
    }

    int select_io() {
        static thread_local std::random_device rd{};
        static thread_local std::default_random_engine re{rd()};
        std::uniform_int_distribution<int> rand_op{0, 99};
        try_shift_workload();
        const int ran{rand_op(re)};
        if (ran < p.PC)
            return 1;
        else if (ran < p.PR)
            return 2;
        else if (ran < p.PU)
            return 3;
        else if (ran < p.PD)
            return 4;
        else if (ran < p.PRU)
            return 5;
        else if (ran < p.PRQ)
            return 6;
        else
            assert(false);
        return -1;
    }

    void try_shift_workload() {
        static constexpr int half{50}, full{100};
        static thread_local std::random_device rd{};
        static thread_local std::default_random_engine re{rd()};

        if (get_elapsed_time(p.workload_shiftTime) > p.WST) {

            p.workload_shiftTime = Clock::now();
            std::uniform_int_distribution< int > pc_rand{0, half - 1};
            p.PC = pc_rand(re);
            std::uniform_int_distribution< int > pr_rand{0, half - p.PC - 1};
            p.PR = p.PC + pr_rand(re);
            std::uniform_int_distribution< int > pu_rand{0, half - p.PR - 1};
            p.PU = p.PR + pu_rand(re);
            std::uniform_int_distribution< int > pd_rand{0, full - p.PU - 1};
            p.PD = p.PU + pd_rand(re);
            std::uniform_int_distribution< int > pru_rand{0, full - p.PD - 1};
            p.PRU = p.PD + pru_rand(re);
            p.PRQ = full;

            LOGINFO("Shifting workload to PC:{},PR:{},PU:{},PD{},PRU:{},PRQ{}:", p.PC, p.PR - p.PC, p.PU - p.PR,
                    p.PD - p.PU, p.PRU - p.PD, p.PRQ - p.PRU);
        }
    }
};
} // namespace homeds::loadgen
