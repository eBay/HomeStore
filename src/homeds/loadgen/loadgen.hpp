//
// Created by Kadayam, Hari on 2/22/19.
//

#ifndef HOMESTORE_LOADGEN_HPP
#define HOMESTORE_LOADGEN_HPP

#include "loadgen_common.hpp"
#include "keyset.hpp"
#include "homeds/utility/enum.hpp"
#include <set>
#include <folly/executors/CPUThreadPoolExecutor.h>
#include <folly/synchronization/Baton.h>
#include <folly/Synchronized.h>
#include <utility/atomic_counter.hpp>
#include <spdlog/fmt/fmt.h>
#include <main/homestore_header.hpp>
//#include "iomgr_executor.hpp"

namespace homeds {
namespace loadgen {

ENUM(generator_op_error, uint32_t, no_error, store_failed, store_timeout, data_validation_failed, data_missing,
     custom_validation_failed, order_validation_failed);

template < typename K, typename V, typename Store, typename Exector >
class KVGenerator {
public:
    KVGenerator(uint8_t n_threads, bool verification) :
            m_executor(n_threads /* threads */, 1 /* priorities */, 20000 /* maxQueueSize */) {
        srand(time(0));
        m_store = std::make_shared< Store >();
        m_verify = verification;
    }
    void set_max_keys(uint64_t max_keys) { m_key_registry.set_max_keys(max_keys); }

    Exector& get_executor() { return m_executor; }

    void init_generator(homeds::loadgen::Param& parameters) { m_store->init_store(parameters); }

    typedef std::function< void(generator_op_error, const key_info< K, V >*, void*, const std::string&) >
        store_error_cb_t;
    typedef std::function< void(int op) > loadgen_success_cb_t;

    static void handle_generic_error(generator_op_error err, const key_info< K, V >* ki, void* store_error,
                                     const std::string& err_text = "") {
        LOGDFATAL("Store reported error {}, error_text = {}", err, err_text);
    }

    void preload(KeyPattern key_pattern, ValuePattern value_pattern, uint32_t count,
                 loadgen_success_cb_t success_cb = nullptr, store_error_cb_t error_cb = handle_generic_error) {
        run_parallel([&]() {
            for (auto i = 0u; i < count; i++) {
                insert_new(key_pattern, value_pattern, success_cb, true, error_cb);
            }
        });
    }

    void reset_pattern(KeyPattern key_pattern, int index = 0) { _reset_pattern(key_pattern, index); }
    void insert_new(KeyPattern key_pattern, ValuePattern value_pattern, loadgen_success_cb_t success_cb = nullptr,
                    bool expected_success = true, store_error_cb_t error_cb = handle_generic_error) {
        insert(key_pattern, value_pattern, error_cb, expected_success, true, success_cb);
    }

    void insert_existing(KeyPattern key_pattern, ValuePattern value_pattern, bool expected_success,
                         loadgen_success_cb_t success_cb = nullptr) {
        insert(key_pattern, value_pattern, handle_generic_error, expected_success, false /* new_key */, success_cb);
    }

    void insert_existing(KeyPattern key_pattern, ValuePattern value_pattern,
                         store_error_cb_t error_cb = handle_generic_error, bool expected_success = false,
                         loadgen_success_cb_t success_cb = nullptr) {
        insert(key_pattern, value_pattern, error_cb, expected_success, false /* new_key */, success_cb);
    }

    void insert(KeyPattern key_pattern, ValuePattern value_pattern, store_error_cb_t error_cb, bool expected_success,
                bool new_key, loadgen_success_cb_t success_cb = nullptr) {
        this->op_start();
        m_executor.add([=] {
            this->_insert(key_pattern, value_pattern, error_cb, expected_success, new_key);
            this->op_done(success_cb);
        });
    }

    void update(KeyPattern key_pattern, ValuePattern value_pattern, bool exclusive_access = true,
                bool expected_success = true, bool valid_key = true, loadgen_success_cb_t success_cb = nullptr,
                store_error_cb_t error_cb = handle_generic_error) {
        this->op_start();
        m_executor.add([=] {
            this->_update(key_pattern, exclusive_access, value_pattern, error_cb, expected_success, valid_key);
            this->op_done(success_cb);
        });
    }

    void range_update(KeyPattern pattern, ValuePattern value_pattern, uint32_t num_keys_in_range, bool exclusive_access,
                      bool start_incl, bool end_incl, loadgen_success_cb_t success_cb = nullptr,
                      store_error_cb_t error_cb = handle_generic_error) {
        this->op_start();
        m_executor.add([=] {
            this->_range_update(pattern, value_pattern, num_keys_in_range, true, exclusive_access, start_incl, end_incl,
                                error_cb);
            this->op_done(success_cb, 0);
        });
    }

    void range_query(KeyPattern pattern, uint32_t num_keys_in_range, bool exclusive_access, bool start_incl,
                     bool end_incl, loadgen_success_cb_t success_cb = nullptr,
                     store_error_cb_t error_cb = handle_generic_error) {
        this->op_start();
        m_executor.add([=] {
            this->_range_query(pattern, num_keys_in_range, true, exclusive_access, start_incl, end_incl, error_cb);
            this->op_done(success_cb, -1);
        });
    }

    void verify_all(uint32_t num_keys_in_range) {
        this->op_start();
        m_executor.add([=] {
            this->_verify_all(num_keys_in_range);
            this->op_done(nullptr);
        });
    }

    void get_non_existing(bool expected_success) { get_non_existing(handle_generic_error, expected_success); }

    void get_non_existing(store_error_cb_t error_cb = handle_generic_error, bool expected_success = false) {
        get(KeyPattern::SEQUENTIAL, true, error_cb, expected_success, false /* valid_key */);
    }

    void get(KeyPattern pattern, bool exclusive_access = true, bool expected_success = true, bool valid_key = true,
             loadgen_success_cb_t success_cb = nullptr, store_error_cb_t error_cb = handle_generic_error) {
        this->op_start();
        m_executor.add([=] {
            this->_get(pattern, exclusive_access, error_cb, expected_success, valid_key);
            this->op_done(success_cb);
        });
    }

    void remove(KeyPattern pattern, bool exclusive_access = true, bool expected_success = true,
                loadgen_success_cb_t success_cb = nullptr, bool valid_key = true,
                store_error_cb_t error_cb = handle_generic_error) {
        this->op_start();
        m_executor.add([=] {
            this->_remove(pattern, exclusive_access, error_cb, expected_success, valid_key);
            this->op_done(success_cb);
        });
    }

    uint64_t get_keys_count() { return this->_get_keys_count(); }

    void remove_all_keys(KeyPattern pattern = KeyPattern::SEQUENTIAL,
                         store_error_cb_t error_cb = handle_generic_error) {
        reset_pattern(pattern);
        auto kc = get_keys_count();
        for (auto i = 0u; i < kc; i++) {
            this->_remove(pattern, true, error_cb, true, true);
        }
        assert(get_keys_count() == 0);
    }

    void remove_non_existing(store_error_cb_t error_cb = handle_generic_error) {
        remove(KeyPattern::SEQUENTIAL, true, error_cb, false, false);
    }

    void range_query_nonexisting(store_error_cb_t error_cb = handle_generic_error) {
        this->op_start();
        m_executor.add([=] {
            this->_range_query(KeyPattern::SEQUENTIAL, 1, false, true, error_cb);
            this->op_done();
        });
    }

    void run_parallel(std::function< void() > test_fn) {
        m_outstanding.set(1);
        test_fn();
        op_done();
        m_test_baton.wait();
        m_test_baton.reset();
    }

private:
    void op_start() { m_outstanding.increment(1); }

    bool _verify() { return m_verify; }

    void op_done(loadgen_success_cb_t success_cb = nullptr, int op = 1) {
        if (m_outstanding.decrement_testz()) {
            m_test_baton.post();
        }
        if (success_cb)
            success_cb(op);
    }

    uint64_t _get_keys_count() { return m_key_registry.get_keys_count(); }

    void _insert(KeyPattern key_pattern, ValuePattern value_pattern, store_error_cb_t error_cb, bool expected_success,
                 bool new_key, bool new_value = true) {
        // Generate or read existing a new key from keyset.
        auto kip = (new_key) ? m_key_registry.generate_and_put_key(key_pattern)
                             : m_key_registry.get_key(key_pattern, true, false);

        // Generate a new value.
        // TODO: Instead of passing nullptr, save the value in lock protected entity and pass them as ref for gen_value
        auto value = m_key_registry.generate_value(value_pattern);

        bool success = m_store->insert(kip->m_key, value);

        if (success != expected_success) {
            error_cb(generator_op_error::store_failed, kip.m_ki, nullptr,
                     fmt::format("Insert status expected {} got {}", expected_success, success));
        }

        if (!success) {
            if (new_key) {
                m_key_registry.remove_key(kip);
                return;
            }
            kip->set_error();
            /* error happen. We move to only verify mode */
        }

        kip->add_hash_code(value->get_hash_code());
        LOGTRACE("Insert {}", *kip);
    }

    void _get(KeyPattern pattern, bool exclusive_access, store_error_cb_t error_cb, bool expected_success,
              bool valid_key) {
        // Generate a new key from keyset.
        const auto kip = valid_key ? m_key_registry.get_key(pattern, false /* for_mutate */, exclusive_access)
                                   : m_key_registry.generate_invalid_key();

        V value;
        bool success = m_store->get(kip->m_key, &value);
        if (success != expected_success) {
            error_cb(generator_op_error::store_failed, kip.m_ki, nullptr,
                     fmt::format("Get status expected {} got {}", expected_success, success));
            return;
        }
        if (!success) {
            return;
        }

        // If mutating key is not ok, which means strongly consistent and hence we should check only for last
        // hash_code in find_hash_code. Else we can check all previous values.

        if (_verify() && !kip->validate_hash_code(value.get_hash_code(), exclusive_access)) {
            // TODO -below log message would not be correct for non-exclusive access as we use last_hash_code

            error_cb(generator_op_error::data_validation_failed, kip.m_ki, nullptr,
                     fmt::format("HashCode mistmatch between loadgen and store {}:{}", kip->get_last_hash_code(),
                                 value.get_hash_code()));
            assert(0);
            return;
        }
        LOGTRACE("Get {}", *kip);
    }

    void print_blob(homeds::blob blob) {
        std::stringstream ss;
        ss << "Blob: Size-" << blob.size << ", Data -[";
        char* p = (char*)blob.bytes;
        for (auto i = 0u; i < blob.size; i++) {
            ss << *p;
            p++;
        }
        ss << "]";
        LOGERROR("{}", ss.str());
    }

    void _remove(KeyPattern pattern, bool exclusive_access, store_error_cb_t error_cb, bool expected_success,
                 bool valid_key) {
        // Generate a new key from keyset.
        auto kip = valid_key ? m_key_registry.get_key(pattern, true /* for_mutate */, exclusive_access)
                             : m_key_registry.generate_invalid_key();
        assert(kip.m_ki->m_free_pending == false);
        V value; // preassigning so as can be successful by default

        //  remove from store
        bool success = m_store->remove(kip->m_key, &value);

        // remvoe from loadgen, no other threads can pick up this if has exclusive access
        m_key_registry.remove_key(kip);

        if (success != expected_success) {
            error_cb(generator_op_error::store_failed, kip.m_ki, nullptr,
                     fmt::format("Remove status expected {} got {}", expected_success, success));
            return;
        }
        if (!success) {
            return;
        }

        if (_verify() && !kip->validate_hash_code(value.get_hash_code(), exclusive_access)) {
            error_cb(generator_op_error::data_validation_failed, kip.m_ki, nullptr,
                     fmt::format("Remove op has incorrect value hash_code={}", value.get_hash_code()));
            assert(0);
            return;
        }
        // LOGDEBUG("Remove {}", kip->m_key);
        LOGTRACE("Remove {}", *kip);
    }

    void _update(KeyPattern key_pattern, bool exclusive_access, ValuePattern value_pattern, store_error_cb_t error_cb,
                 bool expected_success, bool valid_key, bool new_value = true) {
        // Generate a new key from keyset.
        auto kip = valid_key ? m_key_registry.get_key(key_pattern, true /* is_mutate */, exclusive_access)
                             : m_key_registry.generate_invalid_key();

        auto value = m_key_registry.generate_value(value_pattern);

        bool success = m_store->update(kip->m_key, value);

        if (success != expected_success) {
            error_cb(generator_op_error::store_failed, kip.m_ki, nullptr,
                     fmt::format("update status expected {} got {}", expected_success, success));
        }

        if (!success) {
            kip->set_error();
        }
        kip->add_hash_code(value->get_hash_code());
        LOGTRACE("Update {}", *kip);
    }

    void _verify_all(uint32_t num_keys_in_range) {
        static bool reset = false;
        std::vector< key_info_ptr< K, V > > kis;
        std::vector< std::pair< K, V > > kvs;

        if (!reset) {
            m_key_registry.reset_pattern(KeyPattern::SEQUENTIAL, 0);
            reset = true;
        }
        kis =
            m_key_registry.get_consecutive_keys(KeyPattern::SEQUENTIAL, true, false /* is_mutate */, num_keys_in_range);

    retry:
        auto count = m_store->query(kis[0]->m_key, true, kis.back()->m_key, true, kvs);
        if (count == 0) {
            std::this_thread::sleep_for(std::chrono::seconds(10));
            goto retry;
        }
        uint32_t store_indx = 0;
        assert(store_indx <= kvs.size());
        for (uint32_t i = 0; i < kvs.size(); ++i) {
            if (kis[store_indx]->m_key != kvs[i].first) {
                continue;
            }
            if (!kis[store_indx]->validate_hash_code(kvs[i].second.get_hash_code(), true)) {
                // TODO -below log message would not be correct for non-exclusive access as we use last_hash_code

                assert(!"hashcode mismatch");
                return;
            }
            store_indx++;
        }
    }

    void _range_query(KeyPattern pattern, uint32_t num_keys_in_range, bool valid_query, bool exclusive_access,
                      bool start_incl, bool end_incl, store_error_cb_t error_cb) {
        std::vector< key_info_ptr< K, V > > kis;
        std::vector< std::pair< K, V > > kvs;

        if (valid_query) {
            kis =
                m_key_registry.get_contiguous_keys(pattern, exclusive_access, false /* is_mutate */, num_keys_in_range);
        } else {
            kis.emplace_back(m_key_registry.generate_invalid_key());
        }

        // const auto it = m_data_set.rlock()->find(start_incl ? kis[0] : kis[1]);
        // auto it = m_key_registry.find_key(start_incl ? kis[0] : kis[1]);
        auto count = m_store->query(kis[0]->m_key, start_incl, kis.back()->m_key, end_incl, kvs);

        if (!valid_query) {
            if (count > 0) {
                error_cb(generator_op_error::data_missing, kis[0].m_ki, nullptr,
                         fmt::format("Was expecting no result"));
            }
            return;
        }

        if (!_verify()) {
            return;
        }

        uint32_t store_indx = 0;
        assert(store_indx <= kvs.size());
        for (uint32_t i = 0; i < kvs.size(); ++i) {
            if (kis[store_indx]->m_key != kvs[i].first) {
                continue;
            }
            if (!kis[store_indx]->validate_hash_code(kvs[i].second.get_hash_code(), exclusive_access)) {
                // TODO -below log message would not be correct for non-exclusive access as we use last_hash_code

                assert(!"hashcode mismatch");
                return;
            }
            store_indx++;
        }
    }

    void _range_update(KeyPattern pattern, ValuePattern valuePattern, uint32_t num_keys_in_range, bool valid_query,
                       bool exclusive_access, bool start_incl, bool end_incl, store_error_cb_t error_cb) {
        assert(valid_query); // TODO support invalid queries in future
        assert(start_incl);  // TODO
        assert(end_incl);    // TODO
        assert(exclusive_access);

        std::vector< key_info_ptr< K, V > > kips;
        std::vector< std::shared_ptr< V > > values;

        // get existing keys
        kips = m_key_registry.get_consecutive_keys(pattern, exclusive_access, true /* is_mutate */, num_keys_in_range);

        std::vector< std::shared_ptr< V > > val_vec_p;
        int updated = m_key_registry.update_contigious_kv(kips, val_vec_p);
        if (updated != (int)kips.size()) {
            kips.erase(kips.begin() + updated, kips.end());
        }

        if (kips.size() == 0) {
            return;
        }

        bool success = m_store->range_update(kips[0]->m_key, start_incl, kips.back()->m_key, end_incl, val_vec_p);
        if (!success) {
            for (uint32_t i = 0; i < kips.size(); ++i) {
                kips[i]->set_error();
            }
            error_cb(generator_op_error::store_failed, kips[0].m_ki, nullptr,
                     fmt::format("range update status failed"));
        }
    }

    void _reset_pattern(KeyPattern key_pattern, int index = 0) { m_key_registry.reset_pattern(key_pattern, index); }

private:
    KeyRegistry< K, V > m_key_registry;
    folly::Synchronized< std::set< key_info< K, V >*, compare_key_info< K, V > > > m_data_set;

    std::shared_ptr< Store > m_store;
    Exector m_executor;
    sisl::atomic_counter< int64_t > m_outstanding = 0;
    folly::Baton<> m_test_baton;
    bool m_verify;
};
} // namespace loadgen
} // namespace homeds

#endif // HOMESTORE_LOADGEN_HPP
