//
// Created by Kadayam, Hari on 2/22/19.
//

#ifndef HOMESTORE_LOADGEN_HPP
#define HOMESTORE_LOADGEN_HPP

#include <cassert>
#include <chrono>
#include <cstdint>
#include <functional>
#include <iterator>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <common/homestore_header.hpp>
#include <folly/executors/CPUThreadPoolExecutor.h>
#include <folly/Synchronized.h>
#include <folly/synchronization/Baton.h>
#include <spdlog/fmt/fmt.h>
#include <sisl/utility/atomic_counter.hpp>
#include <sisl/utility/enum.hpp>

//#include "iomgr_executor.hpp"
#include "keyset.hpp"
#include "loadgen_common.hpp"

namespace homeds {
namespace loadgen {

ENUM(generator_op_error, uint32_t, no_error, store_failed, store_timeout, data_validation_failed, data_missing,
     custom_validation_failed, order_validation_failed);

template < typename K, typename V, typename Store, typename Exector >
class KVGenerator {
public:
    KVGenerator(const size_t n_threads, const bool verification) :
            m_executor(n_threads /* threads */, 1 /* priorities */, 20000 /* maxQueueSize */) {
        m_store = std::make_shared< Store >();
        m_verify = verification;
    }
    void set_max_keys(const uint64_t max_keys) { m_key_registry.set_max_keys(max_keys); }

    Exector& get_executor() { return m_executor; }

    void init_generator(const homeds::loadgen::Param& parameters) { m_store->init_store(parameters); }

    typedef std::function< void(generator_op_error, const key_info< K, V >*, void*, const std::string&) >
        store_error_cb_t;
    typedef std::function< void(int op) > loadgen_success_cb_t;

    static void handle_generic_error(const generator_op_error err, const key_info< K, V >* const ki,
                                     void* const store_error, const std::string& err_text = "") {
        LOGDFATAL("Store reported error {}, error_text = {}", err, err_text);
    }

    void preload(const KeyPattern key_pattern, const ValuePattern value_pattern, const uint32_t count,
                 loadgen_success_cb_t success_cb = nullptr, store_error_cb_t error_cb = handle_generic_error) {
        run_parallel([&]() {
            for (uint32_t i{0}; i < count; ++i) {
                insert_new(key_pattern, value_pattern, std::move(success_cb), true, std::move(error_cb));
            }
        });
    }

    void reset_pattern(const KeyPattern key_pattern, const int32_t index = 0) {
        reset_pattern_impl(key_pattern, index);
    }
    void insert_new(const KeyPattern key_pattern, const ValuePattern value_pattern,
                    loadgen_success_cb_t success_cb = nullptr, const bool expected_success = true,
                    store_error_cb_t error_cb = handle_generic_error) {
        insert(key_pattern, value_pattern, std::move(error_cb), expected_success, true, std::move(success_cb));
    }

    void insert_existing(const KeyPattern key_pattern, const ValuePattern value_pattern, const bool expected_success,
                         loadgen_success_cb_t success_cb = nullptr) {
        insert(key_pattern, value_pattern, handle_generic_error, expected_success, false /* new_key */,
               std::move(success_cb));
    }

    void insert_existing(const KeyPattern key_pattern, const ValuePattern value_pattern,
                         store_error_cb_t error_cb = handle_generic_error, const bool expected_success = false,
                         loadgen_success_cb_t success_cb = nullptr) {
        insert(key_pattern, value_pattern, std::move(error_cb), expected_success, false /* new_key */,
               std::move(success_cb));
    }

    void insert(const KeyPattern key_pattern, const ValuePattern value_pattern, store_error_cb_t error_cb,
                const bool expected_success, const bool new_key, loadgen_success_cb_t success_cb = nullptr) {
        this->op_start();
        m_executor.add([this, key_pattern, value_pattern, error_cb = std::move(error_cb), expected_success, new_key,
                        success_cb = std::move(success_cb)] {
            this->insert_impl(key_pattern, value_pattern, std::move(error_cb), expected_success, new_key);
            this->op_done(std::move(success_cb));
        });
    }

    void update(const KeyPattern key_pattern, const ValuePattern value_pattern, const bool exclusive_access = true,
                const bool expected_success = true, const bool valid_key = true,
                loadgen_success_cb_t success_cb = nullptr, store_error_cb_t error_cb = handle_generic_error) {
        this->op_start();
        m_executor.add([this, key_pattern, value_pattern, exclusive_access, expected_success, valid_key,
                        success_cb = std::move(success_cb), error_cb = std::move(error_cb)] {
            this->update_impl(key_pattern, exclusive_access, value_pattern, std::move(error_cb), expected_success,
                              valid_key);
            this->op_done(std::move(success_cb));
        });
    }

    void range_update(const KeyPattern pattern, const ValuePattern value_pattern, const uint32_t num_keys_in_range,
                      const bool exclusive_access, const bool start_incl, const bool end_incl,
                      loadgen_success_cb_t success_cb = nullptr, store_error_cb_t error_cb = handle_generic_error) {
        this->op_start();
        m_executor.add([this, pattern, value_pattern, num_keys_in_range, exclusive_access, start_incl, end_incl,
                        success_cb = std::move(success_cb), error_cb = std::move(error_cb)] {
            this->range_update_impl(pattern, value_pattern, num_keys_in_range, true, exclusive_access, start_incl,
                                    end_incl, std::move(error_cb));
            this->op_done(std::move(success_cb), 0);
        });
    }

    void range_query(const KeyPattern pattern, const uint32_t num_keys_in_range, const bool exclusive_access,
                     const bool start_incl, const bool end_incl, loadgen_success_cb_t success_cb = nullptr,
                     store_error_cb_t error_cb = handle_generic_error) {
        this->op_start();
        m_executor.add([this, pattern, num_keys_in_range, exclusive_access, start_incl, end_incl,
                        success_cb = std::move(success_cb), error_cb = std::move(error_cb)] {
            this->range_query_impl(pattern, num_keys_in_range, true, exclusive_access, start_incl, end_incl,
                                   std::move(error_cb));
            this->op_done(std::move(success_cb), -1);
        });
    }

    void verify_all(const uint32_t num_keys_in_range) {
        this->op_start();
        m_executor.add([this, num_keys_in_range] {
            this->verify_all_impl(num_keys_in_range);
            this->op_done(nullptr);
        });
    }

    void get_non_existing(const bool expected_success) { get_non_existing(handle_generic_error, expected_success); }

    void get_non_existing(store_error_cb_t error_cb = handle_generic_error, const bool expected_success = false) {
        get(KeyPattern::SEQUENTIAL, true, std::move(error_cb), expected_success, false /* valid_key */);
    }

    void get(const KeyPattern pattern, const bool exclusive_access = true, const bool expected_success = true,
             const bool valid_key = true, loadgen_success_cb_t success_cb = nullptr,
             store_error_cb_t error_cb = handle_generic_error) {
        this->op_start();
        m_executor.add([this, pattern, exclusive_access, expected_success, valid_key,
                        success_cb = std::move(success_cb), error_cb = std::move(error_cb)] {
            this->get_impl(pattern, exclusive_access, std::move(error_cb), expected_success, valid_key);
            this->op_done(std::move(success_cb));
        });
    }

    void remove(const KeyPattern pattern, const bool exclusive_access = true, const bool expected_success = true,
                loadgen_success_cb_t success_cb = nullptr, const bool valid_key = true,
                store_error_cb_t error_cb = handle_generic_error) {
        this->op_start();
        m_executor.add([this, pattern, exclusive_access, expected_success, valid_key,
                        success_cb = std::move(success_cb), error_cb = std::move(error_cb)] {
            this->remove_impl(pattern, exclusive_access, std::move(error_cb), expected_success, valid_key);
            this->op_done(std::move(success_cb));
        });
    }

    uint64_t get_keys_count() const { return this->get_keys_count_impl(); }

    void remove_all_keys(const KeyPattern pattern = KeyPattern::SEQUENTIAL,
                         store_error_cb_t error_cb = handle_generic_error) {
        reset_pattern(pattern);
        const auto kc{get_keys_count()};
        for (uint64_t i{0}; i < kc; ++i) {
            this->remove_impl(pattern, true, std::move(error_cb), true, true);
        }
        assert(get_keys_count() == 0);
    }

    void remove_non_existing(store_error_cb_t error_cb = handle_generic_error) {
        remove(KeyPattern::SEQUENTIAL, true, std::move(error_cb), false, false);
    }

    void range_query_nonexisting(store_error_cb_t error_cb = handle_generic_error) {
        this->op_start();
        m_executor.add([this, error_cb = std::move(error_cb)] {
            this->range_query_impl(KeyPattern::SEQUENTIAL, 1, false, true, std::move(error_cb));
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

    bool verify_impl() const { return m_verify; }

    void op_done(loadgen_success_cb_t success_cb = nullptr, const int op = 1) {
        if (m_outstanding.decrement_testz()) { m_test_baton.post(); }
        if (success_cb) success_cb(op);
    }

    uint64_t get_keys_count_impl() const { return m_key_registry.get_keys_count(); }

    void insert_impl(const KeyPattern key_pattern, const ValuePattern value_pattern, store_error_cb_t error_cb,
                     const bool expected_success, const bool new_key, const bool new_value = true) {
        // Generate or read existing a new key from keyset.
        auto kip{(new_key) ? m_key_registry.generate_and_put_key(key_pattern)
                           : m_key_registry.get_key(key_pattern, true, false)};

        // Generate a new value.
        // TODO: Instead of passing nullptr, save the value in lock protected entity and pass them as ref for gen_value
        const auto value{m_key_registry.generate_value(value_pattern)};

        const bool success{m_store->insert(kip->m_key, value)};

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

    void get_impl(const KeyPattern pattern, const bool exclusive_access, store_error_cb_t error_cb,
                  const bool expected_success, const bool valid_key) {
        // Generate a new key from keyset.
        const auto kip{valid_key ? m_key_registry.get_key(pattern, false /* for_mutate */, exclusive_access)
                                 : m_key_registry.generate_invalid_key()};

        V value;
        const bool success{m_store->get(kip->m_key, &value)};
        if (success != expected_success) {
            error_cb(generator_op_error::store_failed, kip.m_ki, nullptr,
                     fmt::format("Get status expected {} got {}", expected_success, success));
            return;
        }
        if (!success) { return; }

        // If mutating key is not ok, which means strongly consistent and hence we should check only for last
        // hash_code in find_hash_code. Else we can check all previous values.

        if (verify_impl() && !kip->validate_hash_code(value.get_hash_code(), exclusive_access)) {
            // TODO -below log message would not be correct for non-exclusive access as we use last_hash_code

            error_cb(generator_op_error::data_validation_failed, kip.m_ki, nullptr,
                     fmt::format("HashCode mistmatch between loadgen and store {}:{}", kip->get_last_hash_code(),
                                 value.get_hash_code()));
            assert(false);
            return;
        }
        LOGTRACE("Get {}", *kip);
    }

    void print_blob(const sisl::blob& blob) const {
        std::ostringstream ss;
        ss << "Blob: Size-" << blob.size << ", Data -[";
        const char* p{reinterpret_cast< const char* >(blob.bytes)};
        for (uint32_t i{0}; i < blob.size; ++i) {
            ss << *(p++);
        }
        ss << "]";
        LOGERROR("{}", ss.str());
    }

    void remove_impl(const KeyPattern pattern, const bool exclusive_access, store_error_cb_t error_cb,
                     const bool expected_success, const bool valid_key) {
        // Generate a new key from keyset.
        auto kip{valid_key ? m_key_registry.get_key(pattern, true /* for_mutate */, exclusive_access)
                           : m_key_registry.generate_invalid_key()};
        assert(kip.m_ki->m_free_pending == false);
        V value; // preassigning so as can be successful by default

        //  remove from store
        const bool success{m_store->remove(kip->m_key, &value)};

        // remvoe from loadgen, no other threads can pick up this if has exclusive access
        m_key_registry.remove_key(kip);

        if (success != expected_success) {
            error_cb(generator_op_error::store_failed, kip.m_ki, nullptr,
                     fmt::format("Remove status expected {} got {}", expected_success, success));
            return;
        }
        if (!success) { return; }

        if (verify_impl() && !kip->validate_hash_code(value.get_hash_code(), exclusive_access)) {
            error_cb(generator_op_error::data_validation_failed, kip.m_ki, nullptr,
                     fmt::format("Remove op has incorrect value hash_code={}", value.get_hash_code()));
            assert(false);
            return;
        }
        // LOGDEBUG("Remove {}", kip->m_key);
        LOGTRACE("Remove {}", *kip);
    }

    void update_impl(const KeyPattern key_pattern, const bool exclusive_access, const ValuePattern value_pattern,
                     store_error_cb_t error_cb, const bool expected_success, const bool valid_key,
                     const bool new_value = true) {
        // Generate a new key from keyset.
        auto kip{valid_key ? m_key_registry.get_key(key_pattern, true /* is_mutate */, exclusive_access)
                           : m_key_registry.generate_invalid_key()};

        const auto value{m_key_registry.generate_value(value_pattern)};

        const bool success{m_store->update(kip->m_key, value)};

        if (success != expected_success) {
            error_cb(generator_op_error::store_failed, kip.m_ki, nullptr,
                     fmt::format("update status expected {} got {}", expected_success, success));
        }

        if (!success) { kip->set_error(); }
        kip->add_hash_code(value->get_hash_code());
        LOGTRACE("Update {}", *kip);
    }

    void verify_all_impl(const uint32_t num_keys_in_range) {
        static bool reset{false};
        std::vector< key_info_ptr< K, V > > kis;
        std::vector< std::pair< K, V > > kvs;

        if (!reset) {
            m_key_registry.reset_pattern(KeyPattern::SEQUENTIAL, 0);
            reset = true;
        }
        kis =
            m_key_registry.get_consecutive_keys(KeyPattern::SEQUENTIAL, true, false /* is_mutate */, num_keys_in_range);

    retry:
        const auto count{m_store->query(kis[0]->m_key, true, kis.back()->m_key, true, kvs)};
        if (count == 0) {
            std::this_thread::sleep_for(std::chrono::seconds{10});
            goto retry;
        }
        size_t store_indx{0};
        assert(store_indx <= kvs.size());
        for (size_t i{0}; i < kvs.size(); ++i) {
            if (kis[store_indx]->m_key != kvs[i].first) { continue; }
            if (!kis[store_indx]->validate_hash_code(kvs[i].second.get_hash_code(), true)) {
                // TODO -below log message would not be correct for non-exclusive access as we use last_hash_code

                assert(!"hashcode mismatch");
                return;
            }
            ++store_indx;
        }
    }

    void range_query_impl(const KeyPattern pattern, const uint32_t num_keys_in_range, const bool valid_query,
                          const bool exclusive_access, const bool start_incl, const bool end_incl,
                          store_error_cb_t error_cb) {
        std::vector< key_info_ptr< K, V > > kis;
        std::vector< std::pair< K, V > > kvs;

        if (valid_query) {
            kis = m_key_registry.get_consecutive_keys(pattern, exclusive_access, false /* is_mutate */,
                                                      num_keys_in_range);
        } else {
            kis.emplace_back(m_key_registry.generate_invalid_key());
        }

        // const auto it = m_data_set.rlock()->find(start_incl ? kis[0] : kis[1]);
        // auto it = m_key_registry.find_key(start_incl ? kis[0] : kis[1]);
        const auto count{m_store->query(kis[0]->m_key, start_incl, kis.back()->m_key, end_incl, kvs)};

        if (!valid_query) {
            if (count > 0) {
                error_cb(generator_op_error::data_missing, kis[0].m_ki, nullptr,
                         fmt::format("Was expecting no result"));
            }
            return;
        }

        if (!verify_impl()) { return; }

        size_t store_indx{0};
        assert(store_indx <= kvs.size());
        for (size_t i{0}; i < kvs.size(); ++i) {
            if (kis[store_indx]->m_key != kvs[i].first) { continue; }
            if (!kis[store_indx]->validate_hash_code(kvs[i].second.get_hash_code(), exclusive_access)) {
                // TODO -below log message would not be correct for non-exclusive access as we use last_hash_code

                assert(!"hashcode mismatch");
                return;
            }
            ++store_indx;
        }
    }

    void range_update_impl(const KeyPattern pattern, const ValuePattern valuePattern, const uint32_t num_keys_in_range,
                           const bool valid_query, const bool exclusive_access, const bool start_incl,
                           const bool end_incl, store_error_cb_t error_cb) {
        assert(valid_query); // TODO support invalid queries in future
        assert(start_incl);  // TODO
        assert(end_incl);    // TODO
        assert(exclusive_access);

        std::vector< key_info_ptr< K, V > > kips;
        std::vector< std::shared_ptr< V > > values;

        // get existing keys
        kips = m_key_registry.get_consecutive_keys(pattern, exclusive_access, true /* is_mutate */, num_keys_in_range);

        std::vector< std::shared_ptr< V > > val_vec_p;
        const size_t updated{m_key_registry.update_contigious_kv(kips, val_vec_p)};
        if (updated != kips.size()) { kips.erase(std::next(std::begin(kips), updated), std::end(kips)); }

        if (kips.size() == 0) { return; }

        const bool success{m_store->range_update(kips[0]->m_key, start_incl, kips.back()->m_key, end_incl, val_vec_p)};
        if (!success) {
            for (size_t i{0}; i < kips.size(); ++i) {
                kips[i]->set_error();
            }
            error_cb(generator_op_error::store_failed, kips[0].m_ki, nullptr,
                     fmt::format("range update status failed"));
        }
    }

    void reset_pattern_impl(const KeyPattern key_pattern, const int32_t index = 0) {
        m_key_registry.reset_pattern(key_pattern, index);
    }

private:
    KeyRegistry< K, V > m_key_registry;
    folly::Synchronized< std::set< key_info< K, V >*, compare_key_info< K, V > > > m_data_set;

    std::shared_ptr< Store > m_store;
    Exector m_executor;
    sisl::atomic_counter< int64_t > m_outstanding{0};
    folly::Baton<> m_test_baton;
    bool m_verify;
};
} // namespace loadgen
} // namespace homeds

#endif // HOMESTORE_LOADGEN_HPP
