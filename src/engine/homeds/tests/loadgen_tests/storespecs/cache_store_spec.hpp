/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 *********************************************************************************/
#ifndef HOMESTORE_CACHE_STORE_SPEC_HPP
#define HOMESTORE_CACHE_STORE_SPEC_HPP

#include <cassert>
#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include <boost/uuid/uuid.hpp>

#include "homeds/loadgen/spec/store_spec.hpp"

#include "../valuespecs/cache_value_spec.hpp"

namespace homeds {
namespace loadgen {

template < typename K, typename V, const size_t NodeSize = 8192 >
class CacheStoreSpec : public StoreSpec< K, V > {
    static constexpr uint64_t MAX_CACHE_SIZE{static_cast< uint64_t >(2) * 1024 * 1024 * 1024};

    typedef homestore::Cache< CacheKey, homestore::CacheBuffer< CacheKey > > CacheType;
    typedef std::function< void(generator_op_error, const key_info< K, V >*, void*, const std::string&) >
        store_error_cb_t;

public:
    CacheStoreSpec() = default;
    CacheStoreSpec(const CacheStoreSpec&) = delete;
    CacheStoreSpec& operator=(const CacheStoreSpec&) = delete;
    CacheStoreSpec(CacheStoreSpec&&) noexcept = delete;
    CacheStoreSpec& operator=(CacheStoreSpec&&) noexcept = delete;
    virtual ~CacheStoreSpec() override = default;

    virtual bool insert(K& k, std::shared_ptr< V > v) override {
        auto& bbuf{v->get_buf()};
        bbuf->set_key(k);

        auto ibuf{boost::static_pointer_cast< CacheBuffer< CacheKey > >(bbuf)};
        boost::intrusive_ptr< CacheBuffer< CacheKey > > out_bbuf;
        const bool inserted{m_cache->insert(k, ibuf, &out_bbuf)};
        LOGDEBUG("Cache store inserted {}", *k.getBlkId());

        return inserted;
    }

    virtual bool upsert(K& k, std::shared_ptr< V > v) override {
        assert(false);
        return false;
    }

    virtual void init_store(const homeds::loadgen::Param& parameters) override {
        m_cache = std::make_unique< CacheType >(MAX_CACHE_SIZE, CacheValue::CACHE_ENTRY_SIZE);
    }

    virtual bool update(K& k, std::shared_ptr< V > v) override {
        assert(false);
        return false;
    }

    virtual bool get(const K& k, V* const out_v) const override {
        boost::intrusive_ptr< CacheBuffer< CacheKey > > out_bbuf;
        const auto ret{m_cache->get(k, &out_bbuf)};
        auto& obuf{out_v->get_buf()};
#ifdef NDEBUG
        obuf = boost::intrusive_ptr< CacheValueBuffer >(reinterpret_cast< CacheValueBuffer* >(out_bbuf.get()));
#else
        obuf = boost::dynamic_pointer_cast< CacheValueBuffer >(out_bbuf);
#endif
        return ret;
    }

    virtual bool remove(const K& k, V* const removed_v = nullptr) override {
        m_cache->safe_erase(k,
                            [this, &k, removed_v](const boost::intrusive_ptr< CacheBuffer< CacheKey > >& erased_buf) {
                                LOGDEBUG("Cache store removed {}", *(k.getBlkId()));
                            });
        return true;
    }

    virtual bool remove_any(const K& start_key, const bool start_incl, const K& end_key, const bool end_incl,
                            K* const out_key, V* const out_val) override {
        assert(false);
        return false;
    }

    virtual uint32_t query(const K& start_key, const bool start_incl, const K& end_key, const bool end_incl,
                           std::vector< std::pair< K, V > >& result) const override {
        assert(false);
        return 0;
    }

    virtual bool range_update(K& start_key, const bool start_incl, K& end_key, const bool end_incl,
                              std::vector< std::shared_ptr< V > >& result) override {
        assert(false);
        return false;
    }

private:
    std::unique_ptr< CacheType > m_cache;
    boost::uuids::uuid uuid;
};

} // namespace loadgen
} // namespace homeds

#endif // HOMESTORE_CACHE_STORE_SPEC_HPP
