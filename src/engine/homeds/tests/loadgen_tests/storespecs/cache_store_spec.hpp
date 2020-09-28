//
// Modified by Amit Desai
//

#ifndef HOMESTORE_CACHE_STORE_SPEC_HPP
#define HOMESTORE_CACHE_STORE_SPEC_HPP

#include "homeds/loadgen/spec/store_spec.hpp"
#include "../valuespecs/cache_value_spec.hpp"

namespace homeds {
namespace loadgen {

#define MAX_CACHE_SIZE 2 * 1024 * 1024 * 1024ul

template < typename K, typename V, size_t NodeSize = 8192 >
class CacheStoreSpec : public StoreSpec< K, V > {
    typedef std::function< void(generator_op_error, const key_info< K, V >*, void*, const std::string&) >
        store_error_cb_t;

public:
    CacheStoreSpec() {}

    virtual bool insert(K& k, std::shared_ptr< V > v) override {

        auto ibuf = v->get_buf();
        ibuf->set_key(k);

        boost::intrusive_ptr< CacheBuffer< CacheKey > > out_bbuf;

        bool inserted = m_cache->insert(k, boost::static_pointer_cast< CacheBuffer< CacheKey > >(ibuf),
                                        (boost::intrusive_ptr< CacheBuffer< CacheKey > >*)&out_bbuf);
        LOGDEBUG("Cache store inserted {}", *k.getBlkId());

        return inserted;
    }

    virtual bool upsert(K& k, std::shared_ptr< V > v) override {
        assert(0);
        return true;
    }

    virtual void init_store(homeds::loadgen::Param& parameters) override {
        m_cache = std::make_unique< homestore::Cache< CacheKey > >(MAX_CACHE_SIZE, CACHE_ENTRY_SIZE);
    }

    virtual bool update(K& k, std::shared_ptr< V > v) override {
        assert(0);
        return true;
    }

    virtual bool get(K& k, V* out_v) override {
        boost::intrusive_ptr< CacheValueBuffer > bbuf;
        auto ret = m_cache->get(k, (boost::intrusive_ptr< CacheBuffer< CacheKey > >*)&bbuf);
        out_v->set_buf(bbuf);
        return ret;
    }

    virtual bool remove(K& k, V* removed_v = nullptr) override {
        m_cache->safe_erase(k, [this, &k, removed_v](boost::intrusive_ptr< CacheBuffer< CacheKey > > erased_buf) {
            LOGDEBUG("Cache store removed {}", *(k.getBlkId()));
        });
        return true;
    }

    virtual bool remove_any(K& start_key, bool start_incl, K& end_key, bool end_incl, K* out_key, V* out_val) override {
        assert(0);
        return true;
    }

    virtual uint32_t query(K& start_key, bool start_incl, K& end_key, bool end_incl,
                           std::vector< std::pair< K, V > >& result) override {
        assert(0);
        return 0;
    }

    virtual bool range_update(K& start_key, bool start_incl, K& end_key, bool end_incl,
                              std::vector< std::shared_ptr< V > >& result) {
        assert(0);
        return true;
    }

private:
    std::unique_ptr< homestore::Cache< CacheKey > > m_cache;
    boost::uuids::uuid uuid;
};

} // namespace loadgen
} // namespace homeds

#endif // HOMESTORE_CACHE_STORE_SPEC_HPP
