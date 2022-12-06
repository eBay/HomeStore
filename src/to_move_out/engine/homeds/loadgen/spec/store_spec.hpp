//
// Created by Kadayam, Hari on 2/24/19.
//

#ifndef HOMESTORE_STORE_SPEC_HPP
#define HOMESTORE_STORE_SPEC_HPP

#include <cstdint>
#include <functional>
#include <iterator>
#include <memory>
#include <vector>

namespace homeds {
namespace loadgen {
template < typename K, typename V >
class StoreSpec {
public:
    StoreSpec(const StoreSpec&) = delete;
    StoreSpec& operator=(const StoreSpec&) = delete;
    StoreSpec(StoreSpec&&) noexcept = delete;
    StoreSpec& operator=(StoreSpec&&) noexcept = delete;
    virtual ~StoreSpec() = default;

    virtual bool insert(K& k, std::shared_ptr< V > v) = 0;
    virtual bool upsert(K& k, std::shared_ptr< V > v) = 0;
    virtual bool update(K& k, std::shared_ptr< V > v) = 0;
    virtual bool get(const K& k, V* const out_v) const = 0;
    virtual bool remove(const K& k, V* const removed_v = nullptr) = 0;
    virtual bool remove_any(const K& start_key, const bool start_incl, const K& end_key, const bool end_incl,
                            K* const out_key, V* const out_val) = 0;
    virtual uint32_t query(const K& start_key, const bool start_incl, const K& end_key, const bool end_incl,
                           std::vector< std::pair< K, V > >& result) const = 0;
    virtual bool range_update(K& start_key, const bool start_incl, K& end_key, const bool end_incl,
                              std::vector< std::shared_ptr< V > >& result) = 0;
    virtual void init_store(const homeds::loadgen::Param& parameters) = 0;

    typedef std::function< void(generator_op_error, const key_info< K, V >*, void*, const std::string&) >
        store_error_cb_t;

    virtual void verify(const std::vector< key_info_ptr< K, V > >& loadgenkv,
                        const std::vector< std::pair< K, V > >& storekv, store_error_cb_t error_cb,
                        const bool exclusive_access) const {

        auto l_itr{std::cbegin(loadgenkv)};
        auto s_itr{std::cbegin(storekv)};
        while ((l_itr != std::cend(loadgenkv)) && (s_itr != std::cend(storekv))) {
            const auto expected_ki{*l_itr};
            if (!expected_ki->validate_hash_code(s_itr->second.get_hash_code(), exclusive_access)) {
                error_cb(generator_op_error::data_validation_failed, expected_ki.m_ki, nullptr, "");
            }
            ++l_itr;
            ++s_itr;
        }
        if ((l_itr == std::cend(loadgenkv)) && (s_itr != std::cend(storekv))) {
            error_cb(generator_op_error::data_missing, nullptr, nullptr, fmt::format("More data found than expected"));
        } else if ((l_itr != std::cend(loadgenkv)) && (s_itr == std::cend(storekv))) {
            error_cb(generator_op_error::data_missing, (*l_itr).m_ki, nullptr,
                     fmt::format("Less data found than expected"));
        }
    }

private:
    StoreSpec() = default;
};

} // namespace loadgen
} // namespace homeds
#endif // HOMESTORE_STORE_SPEC_HPP
