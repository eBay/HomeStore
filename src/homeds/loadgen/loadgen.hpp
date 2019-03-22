//
// Created by Kadayam, Hari on 2/22/19.
//

#ifndef HOMESTORE_LOADGEN_HPP
#define HOMESTORE_LOADGEN_HPP

#include "loadgen_common.hpp"
#include "keyset.hpp"
#include "homeds/utility/enum.hpp"
#include <folly/executors/CPUThreadPoolExecutor.h>
#include <folly/synchronization/Baton.h>
#include <utility/atomic_counter.hpp>

namespace homeds {
namespace loadgen {

ENUM(generator_op_error, uint32_t, no_error, store_failed, store_timeout, validation_failed, custom_validation_failed);

template < typename K, typename V, typename Store >
class KVGenerator {
public:
    KVGenerator() : m_executor(4 /* threads */, 1 /* priorities */, 20000 /* maxQueueSize */) {}

    typedef std::function< void(generator_op_error, K&, size_t, void*) > store_error_cb_t;

    void register_keyset(const std::shared_ptr< KeySet< K > >& ks) {
        std::unique_lock< std::mutex >(m_rwlock);
        m_keysets.push_back(ks);
    }

    void unregister_keyset(const std::shared_ptr< KeySet< K > >& ks) {
        std::unique_lock< std::mutex >(m_rwlock);
        m_keysets.remove(ks);
    }

    void register_store(const std::shared_ptr< Store >& store) { m_store = store; }

    static void handle_generic_error(generator_op_error err, K& err_key, size_t val_hash_code, void* store_error) {
        LOGERROR("Store reported error {}, failed key = {} value hash_code = {}", err, err_key, val_hash_code);
    }

    void preload(const std::shared_ptr< KeySet< K > >& ks, ValuePattern value_pattern, uint32_t count,
                 store_error_cb_t error_cb = handle_generic_error) {
        for (auto i = 0u; i < count; i++) {
            insert_new(ks, value_pattern, error_cb);
        }
        wait_for_test();
        m_test_baton.reset();
        m_outstanding.increment(1); // Increment to indicate new test will follow
    }

    void insert_new(const std::shared_ptr< KeySet< K > >& ks, ValuePattern value_pattern,
            store_error_cb_t error_cb = handle_generic_error, bool expected_success = true) {
        insert(ks, value_pattern, error_cb, expected_success, true);
    }

    void insert_existing(const std::shared_ptr< KeySet< K > >& ks, ValuePattern value_pattern, bool expected_success) {
        insert(ks, value_pattern, handle_generic_error, expected_success, false /* new_key */);
    }

    void insert_existing(const std::shared_ptr< KeySet< K > >& ks, ValuePattern value_pattern,
                         store_error_cb_t error_cb = handle_generic_error, bool expected_success = false) {
        insert(ks, value_pattern, error_cb, expected_success, false /* new_key */);
    }

    void insert(const std::shared_ptr< KeySet< K > >& ks, ValuePattern value_pattern, store_error_cb_t error_cb,
            bool expected_success, bool new_key) {
        this->m_outstanding.increment(1);
        m_executor.add([=] {
            this->_insert(ks, value_pattern, error_cb, expected_success, new_key);
            this->op_done();
        });
    }

    void get_non_existing(const std::shared_ptr< KeySet< K > >& ks, bool expected_success) {
        get_non_existing(ks, handle_generic_error, expected_success);
    }

    void get_non_existing(const std::shared_ptr< KeySet< K > >& ks, store_error_cb_t error_cb = handle_generic_error,
            bool expected_success = false) {
        get(ks, ks->default_pattern(), error_cb, expected_success, false /* valid_key */);
    }

    void get(const std::shared_ptr< KeySet< K > >& ks, KeyPattern get_pattern,
             store_error_cb_t error_cb = handle_generic_error, bool expected_success = true, bool valid_key = true) {
        this->m_outstanding.increment(1);
        m_executor.add([=] {
            this->_get(ks, get_pattern, error_cb, expected_success, valid_key);
            this->op_done();
        });
    }

    void wait_for_test() {
        op_done();
        m_test_baton.wait();
    }

private:
    void op_done() {
        if (m_outstanding.decrement_testz()) {
            m_test_baton.post();
        }
    }

    void _insert(const std::shared_ptr< KeySet< K > >& ks, ValuePattern value_pattern,
            store_error_cb_t error_cb, bool expected_success, bool new_key) {
        // Generate or read existing a new key from keyset.
        auto keys = (new_key) ? ks->generate_keys(1) : ks->get_keys(ks->default_pattern(), 1);

        // Generate a new value as well.
        // TODO: Instead of passing nullptr, save the value in lock protected entity and pass them as ref for gen_value
        auto value = V::gen_value(value_pattern, nullptr);

        bool success = m_store->insert(keys[0], value);
        if (success != expected_success) {
            handle_generic_error(generator_op_error::store_failed, keys[0], 0, nullptr);
            return;
        }

        if (success) {
            std::unique_lock< std::mutex >(m_rwlock);
            m_data_map.insert(std::make_pair<>(keys[0], V::hash_code(value)));
        }
    }

    void _get(const std::shared_ptr< KeySet< K > >& ks, KeyPattern get_pattern, store_error_cb_t error_cb,
            bool expected_success, bool valid_key) {
        // Generate a new key from keyset.
        auto key = valid_key ? ks->get_keys(get_pattern, 1)[0] : ks->generate_invalid_key();

        V    value;
        bool success = m_store->get(key, &value);
        if (success != expected_success) {
            handle_generic_error(generator_op_error::store_failed, key, 0, nullptr);
            return;
        }
        if (!success) { return; }

        uint64_t map_hash_code;
        {
            std::shared_lock lk(m_rwlock);
            auto it = m_data_map.find(key);
            if (it == m_data_map.end()) {
                LOGERROR("key {} not found in just inserted map, kvgenerator error", key);
                assert(0);
                return;
            }
            map_hash_code = it->second;
        }

        if (V::hash_code(value) != map_hash_code) {
            handle_generic_error(generator_op_error::validation_failed, key, map_hash_code, nullptr);
            assert(0);
            return;
        }
    }

private:
    std::shared_mutex                                               m_rwlock;
    std::vector< std::shared_ptr< KeySet< K > > >                   m_keysets;
    std::unordered_map< K, uint64_t, key_hash< K >, compare_keys< K > > m_data_map;
    std::shared_ptr< Store >                                        m_store;
    folly::CPUThreadPoolExecutor                                    m_executor;
    sisl::atomic_counter<int64_t>                                   m_outstanding = 1;
    folly::Baton<>                                                  m_test_baton;
//    folly::Baton<>                                                  m_end_test_baton;
};
} // namespace loadgen
} // namespace homeds

#endif // HOMESTORE_LOADGEN_HPP
