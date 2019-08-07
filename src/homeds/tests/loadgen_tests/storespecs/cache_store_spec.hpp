//
// Modified by Amit Desai
//

#ifndef HOMESTORE_CACHE_STORE_SPEC_HPP
#define HOMESTORE_CACHE_STORE_SPEC_HPP

#include "homeds/loadgen/spec/store_spec.hpp"

namespace homeds {
namespace loadgen {

#define MAX_CACHE_SIZE 2 * 1024 * 1024 * 1024ul
#define CACHE_ENTRY_SIZE 8192

template < typename K, typename V, size_t NodeSize = 8192 >
class CacheStoreSpec : public StoreSpec< K, V > {
    typedef std::function< void(generator_op_error, const key_info< K, V >*, void*, const std::string&) >
        store_error_cb_t;

    class CacheValueBuffer : public CacheBuffer< CacheKey > {
    public:
        static CacheValueBuffer* make_object() { return homeds::ObjectAllocator< CacheValueBuffer >::make_object(); }

        void free_yourself() { homeds::ObjectAllocator< CacheValueBuffer >::deallocate(this); }

        friend void intrusive_ptr_add_ref(CacheValueBuffer* buf) {
            intrusive_ptr_add_ref((CacheBuffer< CacheKey >*)buf);
        }

        friend void intrusive_ptr_release(CacheValueBuffer* buf) {
            intrusive_ptr_release((CacheBuffer< CacheKey >*)buf);
        }
    };

public:
    CacheStoreSpec() {}

    virtual bool insert(K& k, V& v) override {
        uint8_t*                                  raw_buf = V::generate_bytes(v.get_id(), CACHE_ENTRY_SIZE);
        boost::intrusive_ptr< homeds::MemVector > mvec(new homeds::MemVector());
        mvec->set(raw_buf, CACHE_ENTRY_SIZE, 0);

        auto buf = CacheValueBuffer::make_object();
        buf->set_key(k);
        buf->set_memvec(mvec, 0, CACHE_ENTRY_SIZE);
        auto ibuf = boost::intrusive_ptr< CacheValueBuffer >(buf);

        boost::intrusive_ptr< CacheBuffer< CacheKey > > out_bbuf;

        bool inserted = m_cache->insert(k, boost::static_pointer_cast< CacheBuffer< CacheKey > >(ibuf),
                                        (boost::intrusive_ptr< CacheBuffer< CacheKey > >*)&out_bbuf);
        LOGDEBUG("Cache store inserted {}:{}",*k.getBlkId(),v.get_id());
        
        return inserted;
    }

    virtual bool upsert(K& k, V& v) override {
        assert(0);
        return true;
    }

    virtual void init_store() override {
        m_cache = std::make_unique< homestore::Cache< CacheKey > >(MAX_CACHE_SIZE, CACHE_ENTRY_SIZE);
    }

    virtual bool update(K& k, V& v) override {
        assert(0);
        return true;
    }

    virtual bool get(K& k, V* out_v) override {
        boost::intrusive_ptr< CacheValueBuffer > bbuf;
        m_cache->get(k, (boost::intrusive_ptr< CacheBuffer< CacheKey > >*)&bbuf);
        return true;
    }

    virtual bool remove(K& k, V* removed_v = nullptr) override {
        m_cache->safe_erase(k, [this, &k ,removed_v](boost::intrusive_ptr< CacheBuffer< CacheKey > > erased_buf) {
            LOGDEBUG("Cache store removed {}:{}",*(k.getBlkId()),removed_v->get_id());
        });
        return true;
    }

    virtual bool remove_any(K& start_key, bool start_incl, K& end_key, bool end_incl, K* out_key, V* out_val) override {
        assert(0);
        return true;
    }

    virtual uint32_t query(K& start_key, bool start_incl, K& end_key, bool end_incl, uint32_t batch_size,
                           std::vector< std::pair< K, V > >& result) override {
        assert(0);
        return 0;
    }

    virtual void verify(std::vector< key_info_ptr< K, V > > loadgenkv, std::vector< std::pair< K, V > > storekv,
                        store_error_cb_t error_cb, bool exclusive_access) override {

        assert(0);
    }

    virtual bool range_update(K& start_key, bool start_incl, K& end_key, bool end_incl, V& start_value, V& end_value) {
        assert(0);
        return true;
    }

private:
    std::unique_ptr< homestore::Cache< CacheKey > > m_cache;
    boost::uuids::uuid                              uuid;
};

} // namespace loadgen
} // namespace homeds

#endif // HOMESTORE_CACHE_STORE_SPEC_HPP
