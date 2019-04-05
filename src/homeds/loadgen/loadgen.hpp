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

namespace homeds {
namespace loadgen {

ENUM(generator_op_error, uint32_t, no_error, store_failed, store_timeout, data_validation_failed, data_missing,
     custom_validation_failed, order_validation_failed);

template < typename K, typename V, typename Store >
class KVGenerator {
public:
    KVGenerator() : m_executor(4 /* threads */, 1 /* priorities */, 20000 /* maxQueueSize */) {}

    typedef std::function< void(generator_op_error, const key_info< K >*, void*, const std::string&) > store_error_cb_t;

    void register_store(const std::shared_ptr< Store >& store) { m_store = store; }

    static void handle_generic_error(generator_op_error err, const key_info< K >* ki, void* store_error,
                                     const std::string& err_text = "") {
        LOGDFATAL_IF(true, "Store reported error {}, failed key = {} error_text = {}", err, ki->m_key, err_text);
    }

    void preload(KeyPattern key_pattern, ValuePattern value_pattern, uint32_t count,
            store_error_cb_t error_cb = handle_generic_error) {
        run_parallel([&](){
            for (auto i = 0u; i < count; i++) {
                insert_new(key_pattern, value_pattern, error_cb);
            }
        });
    }

    void insert_new(KeyPattern key_pattern, ValuePattern value_pattern,
                    store_error_cb_t error_cb = handle_generic_error, bool expected_success = true) {
        insert(key_pattern, value_pattern, error_cb, expected_success, true);
    }

    void insert_existing(KeyPattern key_pattern, ValuePattern value_pattern, bool expected_success) {
        insert(key_pattern, value_pattern, handle_generic_error, expected_success, false /* new_key */);
    }

    void insert_existing(KeyPattern key_pattern, ValuePattern value_pattern,
                         store_error_cb_t error_cb = handle_generic_error, bool expected_success = false) {
        insert(key_pattern, value_pattern, error_cb, expected_success, false /* new_key */);
    }

    void insert(KeyPattern key_pattern, ValuePattern value_pattern, store_error_cb_t error_cb, bool expected_success,
                bool new_key) {
        this->m_outstanding.increment(1);
        m_executor.add([=] {
            this->_insert(key_pattern, value_pattern, error_cb, expected_success, new_key);
            this->op_done();
        });
    }

    void get_non_existing(bool expected_success) {
        get_non_existing(handle_generic_error, expected_success);
    }

    void get_non_existing(store_error_cb_t error_cb = handle_generic_error, bool expected_success = false) {
        get(KeyPattern::SEQUENTIAL, true, error_cb, expected_success, false /* valid_key */);
    }

    void get(KeyPattern pattern, bool exclusive_access = true, store_error_cb_t error_cb = handle_generic_error,
             bool expected_success = true, bool valid_key = true) {
        this->m_outstanding.increment(1);
        m_executor.add([=] {
            this->_get(pattern, exclusive_access, error_cb, expected_success, valid_key);
            this->op_done();
        });
    }

    void remove(KeyPattern pattern, bool exclusive_access = true, store_error_cb_t error_cb = handle_generic_error,
                bool expected_success = true, bool valid_key = true) {
        this->m_outstanding.increment(1);
        m_executor.add([=] {
            this->_remove(pattern, exclusive_access, error_cb, expected_success, valid_key);
            this->op_done();
        });
    }

    void remove_non_existing(store_error_cb_t error_cb = handle_generic_error) {
        remove(KeyPattern::SEQUENTIAL, true, error_cb, false, false);
    }

    void range_query(KeyPattern pattern, uint32_t num_keys_in_range, bool exclusive_access, bool start_incl, bool end_incl,
                     store_error_cb_t error_cb = handle_generic_error) {
        this->m_outstanding.increment(1);
        m_executor.add([=] {
            this->_range_query(pattern, num_keys_in_range, true, exclusive_access, start_incl, end_incl, error_cb);
            this->op_done();
        });
    }

    void range_query_nonexisting(store_error_cb_t error_cb = handle_generic_error) {
        this->m_outstanding.increment(1);
        m_executor.add([=] {
            this->_range_query(KeyPattern::SEQUENTIAL, 1, false, true, error_cb);
            this->op_done();
        });
    }

    void run_parallel(std::function<void()> test_fn) {
        m_outstanding.set(1);
        test_fn();
        op_done();
        m_test_baton.wait();
        m_test_baton.reset();
    }

private:
    void op_done() {
        if (m_outstanding.decrement_testz()) {
            m_test_baton.post();
        }
    }

    void _insert(KeyPattern key_pattern, ValuePattern value_pattern, store_error_cb_t error_cb, bool expected_success,
                 bool new_key) {
        // Generate or read existing a new key from keyset.
        auto kip = (new_key) ? m_key_registry.generate_key(key_pattern) : m_key_registry.get_key(key_pattern, true, false);

        // Generate a new value.
        // TODO: Instead of passing nullptr, save the value in lock protected entity and pass them as ref for gen_value
        auto value = V::gen_value(value_pattern, nullptr);

        bool success = m_store->insert(kip->m_key, value);
        if (success != expected_success) {
            error_cb(generator_op_error::store_failed, kip.m_ki, nullptr,
                     fmt::format("Insert status expected {} got {}", expected_success, success));
            return;
        }

        if (success) {
            kip->add_hash_code(V::hash_code(value));
            m_key_registry.put_key(kip);
            LOGTRACE("Insert {}", *kip);
        }
    }

    void _get(KeyPattern pattern, bool exclusive_access, store_error_cb_t error_cb, bool expected_success,
              bool valid_key) {
        // Generate a new key from keyset.
        const auto kip = valid_key ? m_key_registry.get_key(pattern, false /* for_mutate */, exclusive_access) :
                                     m_key_registry.generate_invalid_key();

        V    value;
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
        if (!kip->validate_hash_code(V::hash_code(value), exclusive_access)) {
            error_cb(generator_op_error::data_validation_failed, kip.m_ki, nullptr,
                     fmt::format("Get op has incorrect value hash_code={}", V::hash_code(value)));
            assert(0);
            return;
        }

        LOGTRACE("Get {}", *kip);
    }

    void _remove(KeyPattern pattern, bool exclusive_access, store_error_cb_t error_cb, bool expected_success,
                 bool valid_key) {
        // Generate a new key from keyset.
        auto kip = valid_key ? m_key_registry.get_key(pattern, true /* for_mutate */, exclusive_access) :
                               m_key_registry.generate_invalid_key();

        V    value;
        bool success = m_store->remove(kip->m_key, &value);
        if (success != expected_success) {
            error_cb(generator_op_error::store_failed, kip.m_ki, nullptr,
                     fmt::format("Remove status expected {} got {}", expected_success, success));
            return;
        }
        if (!success) {
            return;
        }

        if (!kip->validate_hash_code(V::hash_code(value), exclusive_access)) {
            error_cb(generator_op_error::data_validation_failed, kip.m_ki, nullptr,
                     fmt::format("Remove op has incorrect value hash_code={}", V::hash_code(value)));
            assert(0);
            return;
        }

        LOGTRACE("Remove {}", *kip);
        m_key_registry.remove_key(kip);
    }

    void _update(KeyPattern key_pattern, bool exclusive_access, ValuePattern value_pattern, store_error_cb_t error_cb,
                 bool expected_success, bool valid_key) {
        // Generate a new key from keyset.
        auto kip = valid_key ? m_key_registry.get_key(key_pattern, true /* is_mutate */, exclusive_access) :
                               m_key_registry.generate_invalid_key();

        auto value = V::gen_value(value_pattern, nullptr);
        bool success = m_store->update(kip->m_key, value);
        if (success != expected_success) {
            error_cb(generator_op_error::store_failed, kip.m_ki, 0, nullptr,
                     fmt::format("Update status expected {} got {}", expected_success, success));
            return;
        }
        if (!success) {
            return;
        }

        kip->add_hash_code(V::hash_code(value));
        LOGTRACE("Update {}", *kip);
    }

    void _range_query(KeyPattern pattern, uint32_t num_keys_in_range, bool valid_query, bool exclusive_access,
                      bool start_incl, bool end_incl, store_error_cb_t error_cb) {
        std::vector< key_info_ptr< K > > kis;
        int32_t                       expected_count;
        int32_t                       actual_count = 0;

        if (valid_query) {
            kis = m_key_registry.get_contiguous_keys(pattern, exclusive_access, false /* is_mutate */, num_keys_in_range);
            expected_count = (int32_t)kis.size() - !start_incl - !end_incl;
        } else {
            kis.emplace_back(m_key_registry.generate_invalid_key());
            expected_count = 0;
        }

        //const auto it = m_data_set.rlock()->find(start_incl ? kis[0] : kis[1]);
        auto it = m_key_registry.find_key(start_incl ? kis[0] : kis[1]);

        auto count = m_store->query(kis[0]->m_key, start_incl, kis.back()->m_key, end_incl, 1000, nullptr,
                                [&](const K& k, const V& v, void* context) {
                                    const key_info< K >* expected_ki = *it;
                                    ++it;

                                    if (actual_count++ > expected_count) {
                                        error_cb(generator_op_error::order_validation_failed, expected_ki, nullptr, "");
                                        return false;
                                    }

                                    if (k != expected_ki->m_key) {
                                        error_cb(generator_op_error::order_validation_failed, expected_ki, nullptr, "");
                                        return false;
                                    }

                                    if (!expected_ki->validate_hash_code(V::hash_code(v), exclusive_access)) {
                                        error_cb(generator_op_error::data_validation_failed, expected_ki, nullptr, "");
                                        return false;
                                    }

                                    LOGTRACE("RangeQuery {}", *expected_ki);
                                    return true;
                                });

        if (actual_count != expected_count) {
            error_cb(generator_op_error::data_missing, kis[0].m_ki, nullptr,
                     fmt::format("Expecting {} keys, got {}", expected_count, actual_count));
        }
    }

private:
    KeyRegistry< K >                                                         m_key_registry;
    folly::Synchronized< std::set< key_info< K >*, compare_key_info< K > > > m_data_set;
    std::shared_ptr< Store >                                                 m_store;
    folly::CPUThreadPoolExecutor                                             m_executor;
    sisl::atomic_counter< int64_t >                                          m_outstanding = 0;
    folly::Baton<>                                                           m_test_baton;
};
} // namespace loadgen
} // namespace homeds

#endif // HOMESTORE_LOADGEN_HPP
