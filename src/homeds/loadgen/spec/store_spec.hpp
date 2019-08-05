//
// Created by Kadayam, Hari on 2/24/19.
//

#ifndef HOMESTORE_STORE_SPEC_HPP
#define HOMESTORE_STORE_SPEC_HPP

namespace homeds {
namespace loadgen {
template < typename K, typename V >
class StoreSpec {
public:
    virtual bool     insert(K& k, V& v) = 0;
    virtual bool     upsert(K& k, V& v) = 0;
    virtual bool     update(K& k, V& v) = 0;
    virtual bool     get(K& k, V* out_v) = 0;
    virtual bool     remove(K& k, V* removed_v = nullptr) = 0;
    virtual bool     remove_any(K& start_key, bool start_incl, K& end_key, bool end_incl, K* out_key, V* out_val) = 0;
    virtual uint32_t query(K& start_key, bool start_incl, K& end_key, bool end_incl, uint32_t batch_size,
                           std::vector< std::pair< K, V > >& result) = 0;
    virtual bool     range_update(K& start_key, bool start_incl, K& end_key, bool end_incl, V& start_value,
                                  V& end_value) = 0;
    virtual void     init_store() = 0;

    typedef std::function< void(generator_op_error, const key_info< K, V >*, void*, const std::string&) >
        store_error_cb_t;

    virtual void verify(std::vector< key_info_ptr< K, V > > loadgenkv, std::vector< std::pair< K, V > > storekv,
                        store_error_cb_t error_cb, bool exclusive_access) {

        auto l_itr = loadgenkv.begin();
        auto s_itr = storekv.begin();
        while (l_itr != loadgenkv.end() && s_itr != storekv.end()) {
            auto expected_ki = *l_itr;
            if (!expected_ki->validate_hash_code(s_itr->second.get_hash_code(), exclusive_access)) {
                error_cb(generator_op_error::data_validation_failed, expected_ki.m_ki, nullptr, "");
            }
            l_itr++;
            s_itr++;
        }
        if (l_itr == loadgenkv.end() && s_itr != storekv.end()) {
            error_cb(generator_op_error::data_missing, nullptr, nullptr, fmt::format("More data found than expected"));
        } else if (l_itr != loadgenkv.end() && s_itr == storekv.end()) {
            error_cb(generator_op_error::data_missing, (*l_itr).m_ki, nullptr,
                     fmt::format("Less data found than expected"));
        }
    }
};

} // namespace loadgen
} // namespace homeds
#endif // HOMESTORE_STORE_SPEC_HPP
