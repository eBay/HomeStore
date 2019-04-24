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
    virtual bool insert(K& k, V& v) = 0;
    virtual bool upsert(K& k, V& v) = 0;
    virtual bool update(K& k, V& v) = 0;
    virtual bool get(K& k, V* out_v) = 0;
    virtual bool remove(K& k, V* removed_v = nullptr) = 0;
    virtual bool remove_any(K& start_key, bool start_incl, K& end_key, bool end_incl, K *out_key, V* out_val) = 0;
    virtual uint32_t query(K& start_key, bool start_incl, K& end_key, bool end_incl, uint32_t batch_size,
                           void *cb_context, std::function<bool(K&, V&, bool, void *)> foreach_cb) = 0;
    virtual std::vector< V > range_update(K& start_key, bool start_incl, K& end_key, bool end_incl) = 0;
};

} // namespace loadgen
} // namespace homeds
#endif // HOMESTORE_STORE_SPEC_HPP
