#include "homeds/loadgen/loadgen_common.hpp"
using namespace flip;
namespace homeds::loadgen {
enum SPECIFIC_TEST {
    MAP = 0,
};

template < typename K, typename V, typename Store, typename Executor >
struct BtreeLoadGen {
    std::unique_ptr< KVGenerator< K, V, Store, Executor > > kvg;
    std::atomic< int64_t > stored_keys = 0, outstanding_create = 0, outstanding_others = 0;
    int CHECKPOINT_RANGE_BATCH_SIZE = 50;
    int UPDATE_RANGE_BATCH_SIZE = 64;
    int QUERY_RANGE_BATCH_SIZE = 32;
    std::mutex m_mtx;
    std::condition_variable m_cv;
    Param p;
    bool m_loadgen_verify_mode = false;

    explicit BtreeLoadGen(uint8_t n_threads, bool verification = true) {
        kvg = std::make_unique< KVGenerator< K, V, Store, Executor > >(n_threads, verification);
    }
    std::atomic< int64_t > C_NC = 0, C_NR = 0, C_NU = 0, C_ND = 0, C_NRU = 0, C_NRQ = 0,
                           C_NV = 0; // current op issued counter

    int64_t get_warmup_key_count(int percent) { return percent * p.WARM_UP_KEYS / 100; }

    int64_t get_existing_key_count(int percent) { return percent * kvg->get_keys_count() / 100; }

    Executor& get_executor() { return kvg->get_executor(); }

    void do_checkpoint() {
        kvg->run_parallel([&]() {
            for (auto i = 0u; i < get_existing_key_count(100); i += CHECKPOINT_RANGE_BATCH_SIZE) {
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
            for (auto i = 0u; i < get_warmup_key_count(50); i++) {
                kvg->insert_new(KeyPattern::UNI_RANDOM, ValuePattern::RANDOM_BYTES);
            }
        });
    }

    void do_updates() {
        auto tenPer = get_existing_key_count(10);
        auto thirtyPer = get_existing_key_count(30);

        // update sequential 10%, from start
        kvg->reset_pattern(KeyPattern::SEQUENTIAL, 0);
        kvg->run_parallel([&]() {
            for (auto i = 0u; i < tenPer; i++) {
                kvg->update(KeyPattern::SEQUENTIAL, ValuePattern::RANDOM_BYTES, true, true);
            }
        });

        // update sequential 10%, trailing
        kvg->reset_pattern(KeyPattern::SEQUENTIAL, get_existing_key_count(90));
        kvg->run_parallel([&]() {
            for (auto i = 0u; i < tenPer; i++) {
                kvg->update(KeyPattern::SEQUENTIAL, ValuePattern::RANDOM_BYTES, true, true);
            }
        });

        // update random 30%
        kvg->run_parallel([&]() {
            for (auto i = 0u; i < thirtyPer; i++) {
                kvg->update(KeyPattern::UNI_RANDOM, ValuePattern::RANDOM_BYTES, true, true);
            }
        });
    }

    void do_removes() {
        auto tenPer = get_existing_key_count(10);
        auto thirtyPer = get_existing_key_count(30);

        // remove sequential 10% from start
        kvg->reset_pattern(KeyPattern::SEQUENTIAL, 0);
        kvg->run_parallel([&]() {
            for (auto i = 0u; i < tenPer; i++) {
                kvg->remove(KeyPattern::SEQUENTIAL, true, true);
            }
        });

        // remove trailing 10%
        kvg->reset_pattern(KeyPattern::SEQUENTIAL, get_existing_key_count(90));
        kvg->run_parallel([&]() {
            for (auto i = 0u; i < tenPer; i++) {
                kvg->remove(KeyPattern::SEQUENTIAL, true, true);
            }
        });

        // remove random 30%
        kvg->run_parallel([&]() {
            for (auto i = 0u; i < thirtyPer; i++) {
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
        int64_t kc = get_warmup_key_count(100);
        kvg->preload(KeyPattern::SEQUENTIAL, ValuePattern::SEQUENTIAL_VAL, kc);
        stored_keys += kc;
        assert(kvg->get_keys_count() == (uint64_t)kc);
        kvg->reset_pattern(KeyPattern::SEQUENTIAL, 0);

        FlipClient fc(HomeStoreFlip::instance());
        FlipFrequency freq;
        freq.set_count(1);
        freq.set_percent(100);
        fc.inject_noreturn_flip("btree_leaf_node_split", {}, freq);

        kvg->run_parallel([&]() {
            // single range update over entire tree
            for (int i = 0; i < kc; i += UPDATE_RANGE_BATCH_SIZE) {
                kvg->range_update(KeyPattern::SEQUENTIAL, ValuePattern::SEQUENTIAL_VAL, UPDATE_RANGE_BATCH_SIZE, true,
                                  true, true);
            }
        });
    }
    void specific_tests(SPECIFIC_TEST st) {
        if (st == SPECIFIC_TEST::MAP) {
            do_sub_range_test();
        }
    }
    void warmup(bool update_allowed, bool remove_allowed, bool range_update_allowed, bool range_query_allowed) {
        // basic serialized tests
        do_inserts();
        if (update_allowed) {
            do_updates();
        }
        if (remove_allowed) {
            do_removes();
        }
    }

    void join() {
        std::unique_lock< std::mutex > lk(m_mtx);
        m_cv.wait(lk, [this] { return outstanding_create + outstanding_others == 0; });
    }

    void insert_success_cb(int op = 1) {
        std::unique_lock< std::mutex > lk(m_mtx);
        stored_keys += op;
        outstanding_create -= op;
        m_cv.notify_one();
    }

    void remove_success_cb(int op = 1) {
        std::unique_lock< std::mutex > lk(m_mtx);
        stored_keys -= op;
        outstanding_others -= op;
        m_cv.notify_one();
    }

    void read_update_success_cb(int op = 1) {
        std::unique_lock< std::mutex > lk(m_mtx);
        if (op == 0) {
            // range update succes cb
            outstanding_others -= UPDATE_RANGE_BATCH_SIZE;
        }
        if (op == -1) {
            // range query succes cb
            outstanding_others -= QUERY_RANGE_BATCH_SIZE;
        } else {
            outstanding_others -= op;
        }
        m_cv.notify_one();
    }

    uint64_t get_elapsed_time(Clock::time_point stTime) {
        std::chrono::seconds sec = std::chrono::duration_cast< std::chrono::seconds >(Clock::now() - stTime);
        return sec.count();
    }

    bool increment_create() {
        std::unique_lock< std::mutex > lk(m_mtx);
        if ((uint64_t)(stored_keys + outstanding_create) >= p.NK)
            return false; // cant accomodate more
        outstanding_create++;
        return true;
    }

    bool increment_other(int op = 1) {
        std::unique_lock< std::mutex > lk(m_mtx);
        if (stored_keys - outstanding_others < op)
            return false; // cannot accomodate more
        outstanding_others += op;
        return true;
    }

    bool is_storedkey_watermark_reached(int watermark) {
        std::unique_lock< std::mutex > lk(m_mtx);
        return stored_keys + outstanding_create > watermark;
    }

    int64_t get_issued_ios() {
        return C_NC + C_NR + C_NU + C_ND + C_NRU / UPDATE_RANGE_BATCH_SIZE + C_NRQ / QUERY_RANGE_BATCH_SIZE;
    }

    void handle_generic_error(generator_op_error err, const key_info< K, V >* ki, void* store_error,
                              const std::string& err_text = "") {
        m_loadgen_verify_mode = true;
        LOGERROR("Store reported error {}, error_text = {}", err, err_text);
    }

    void try_create() {
        if (!increment_create())
            return;

        kvg->insert_new(KeyPattern::UNI_RANDOM, ValuePattern::RANDOM_BYTES,
                        std::bind(&BtreeLoadGen::insert_success_cb, this, std::placeholders::_1), true,
                        std::bind(&BtreeLoadGen::handle_generic_error, this, std::placeholders::_1,
                                  std::placeholders::_2, std::placeholders::_3, std::placeholders::_4));
        C_NC++;
        try_print();
    }

    void try_read() {
        if (!increment_other())
            return;

        kvg->get(KeyPattern::UNI_RANDOM, true, true, true,
                 std::bind(&BtreeLoadGen::read_update_success_cb, this, std::placeholders::_1),
                 std::bind(&BtreeLoadGen::handle_generic_error, this, std::placeholders::_1, std::placeholders::_2,
                           std::placeholders::_3, std::placeholders::_4));
        C_NR++;
        try_print();
    }

    void try_update() {
        if (!increment_other())
            return;

        kvg->update(KeyPattern::UNI_RANDOM, ValuePattern::RANDOM_BYTES, true, true, true,
                    std::bind(&BtreeLoadGen::read_update_success_cb, this, std::placeholders::_1),
                    std::bind(&BtreeLoadGen::handle_generic_error, this, std::placeholders::_1, std::placeholders::_2,
                              std::placeholders::_3, std::placeholders::_4));
        C_NU++;
        try_print();
    }

    void try_range_update() {
        if (!is_storedkey_watermark_reached(UPDATE_RANGE_BATCH_SIZE * 2))
            return;

        while (!increment_other(UPDATE_RANGE_BATCH_SIZE)) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
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
        if (!is_storedkey_watermark_reached(QUERY_RANGE_BATCH_SIZE * 2))
            return;

        while (!increment_other(QUERY_RANGE_BATCH_SIZE)) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
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
        if (C_NV > (int64_t)p.NK) {
            return true;
        }
        kvg->verify_all(QUERY_RANGE_BATCH_SIZE);
        C_NV += QUERY_RANGE_BATCH_SIZE;
        try_print();
        return false;
    }

    void try_delete() {
        if (!increment_other())
            return;
        kvg->remove(KeyPattern::UNI_RANDOM, true, true,
                    std::bind(&BtreeLoadGen::remove_success_cb, this, std::placeholders::_1), true,
                    std::bind(&BtreeLoadGen::handle_generic_error, this, std::placeholders::_1, std::placeholders::_2,
                              std::placeholders::_3, std::placeholders::_4));
        C_ND++;
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

    void regression(bool update_allowed, bool remove_allowed, bool range_update_allowed, bool range_query_allowed) {
        kvg->run_parallel([&]() {
            while (true) {
                auto op = select_io();

                if (m_loadgen_verify_mode) {

                    if (!range_query_allowed || try_verify_all()) {
                        break;
                    }
                    continue;
                }
                if (op == 1)
                    try_create();
                else if (op == 2)
                    try_read();
                else if (op == 3) {
                    if (!update_allowed)
                        continue;
                    try_update();
                } else if (op == 4) {
                    if (!remove_allowed)
                        continue;
                    try_delete();
                } else if (op == 5) {
                    if (!range_update_allowed)
                        continue;
                    try_range_update();
                } else if (op == 6) {
                    if (!range_query_allowed)
                        continue;
                    try_range_query();
                } else
                    assert(0);

                if ((uint64_t)get_issued_ios() > p.NIO || get_elapsed_time(p.startTime) > p.NRT)
                    break;
            }
        });

        if (remove_allowed)
            kvg->remove_all_keys();
        join();
        LOGINFO("stored_keys:{}, outstanding_create:{},"
                " outstanding_others:{}, creates:{}, reads:{}, updates:{}, deletes:{}, "
                "rangeupdate:{}, rangequery:{}, total_io:{}, verify_io:{}",
                stored_keys, outstanding_create, outstanding_others, C_NC, C_NR, C_NU, C_ND,
                C_NRU / UPDATE_RANGE_BATCH_SIZE, C_NRQ / QUERY_RANGE_BATCH_SIZE, get_issued_ios(), C_NV);
    }

    int8_t select_io() {
        try_shift_workload();
        int ran = rand() % 100;
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
            assert(0);
        return -1;
    }

    int half = 50, full = 100;
    void try_shift_workload() {
        if (get_elapsed_time(p.workload_shiftTime) > p.WST) {

            p.workload_shiftTime = Clock::now();
            p.PC = (rand() % half);
            p.PR = p.PC + (rand() % (half - p.PC));
            p.PU = p.PR + (rand() % (half - p.PR));
            p.PD = p.PU + (rand() % (full - p.PU));
            p.PRU = p.PD + (rand() % (full - p.PD));
            p.PRQ = full;

            LOGINFO("Shifting workload to PC:{},PR:{},PU:{},PD{},PRU:{},PRQ{}:", p.PC, p.PR - p.PC, p.PU - p.PR,
                    p.PD - p.PU, p.PRU - p.PD, p.PRQ - p.PRU);
        }
    }
};
} // namespace homeds::loadgen
