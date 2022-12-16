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
#ifndef __VOLUME_STORE_SPEC_HPP__
#define __VOLUME_STORE_SPEC_HPP__

#include <atomic>
#include <cassert>
#include <cstdint>
#include <mutex>
#include <vector>

#include "homeds/loadgen/spec/store_spec.hpp"
#include "homeds/tests/loadgen_tests/vol_manager.hpp"
#include "homeds/tests/loadgen_tests/keyspecs/vol_key_spec.hpp"
#include "homeds/tests/loadgen_tests/valuespecs/vol_value_spec.hpp"

using namespace homeds::btree;

namespace homeds {
namespace loadgen {

//
// For volume plugin,
// K is offset in volume and
// V is the data buffer written to volume
//
template < typename K, typename V >
class VolumeStoreSpec : public StoreSpec< K, V > {
public:
    VolumeStoreSpec() = default;
    VolumeStoreSpec(const VolumeStoreSpec&) = delete;
    VolumeStoreSpec& operator=(const VolumeStoreSpec&) = delete;
    VolumeStoreSpec(VolumeStoreSpec&&) noexcept = delete;
    VolumeStoreSpec& operator=(VolumeStoreSpec&&) noexcept = delete;
    virtual ~VolumeStoreSpec() override = default;

    virtual void init_store(const homeds::loadgen::Param& parameters) override {
        m_vol_mgr = VolumeManager< IOMgrExecutor >::instance();
    }

    // read
    virtual bool get(const K& k, V* const out_v) const override {
#ifdef NDEBUG
        const VolumeKey& vk{reinterpret_cast< const VolumeKey& >(k)};
#else
        const VolumeKey& vk{dynamic_cast< const VolumeKey& >(k)};
#endif

        const uint64_t vol_id{vk.vol_id()};
        const uint64_t lba{vk.lba()};
        const uint64_t nblks{vk.nblks()};

        const auto verify{VolumeManager< IOMgrExecutor >::instance()->check_and_set_bm(vol_id, lba, nblks)};

        const auto ret_io{m_vol_mgr->read(vol_id, lba, nblks, verify)};
        if (ret_io != no_error) { return false; }

        return true;
    }

    // new write
    virtual bool insert(K& k, std::shared_ptr< V > v) override { return update_internal(k, v); }

    virtual bool upsert(K& k, std::shared_ptr< V > v) override {
        assert(false);
        return false;
    }

    // over-write
    virtual bool update(K& k, std::shared_ptr< V > v) override {
#ifdef NDEBUG
        const VolumeKey& vk{reinterpret_cast< const VolumeKey& >(k)};
#else
        const VolumeKey& vk{dynamic_cast< const VolumeKey& >(k)};
#endif

        const uint64_t vol_id{vk.vol_id()};
        const uint64_t lba{vk.lba()};
        const uint64_t nblks{vk.nblks()};

        const auto ret{VolumeManager< IOMgrExecutor >::instance()->check_and_set_bm(vol_id, lba, nblks)};
        if (ret == false) {
            // we don't allow writes on same lba that read/write has not acked yet.
            m_write_skip++;
            return true;
        }

        return update_internal(k, v);
    }

    virtual bool remove(const K& k, V* const removed_v = nullptr) override {
        assert(false);
        return false;
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
    bool update_internal(K& k, std::shared_ptr< V > v) {
#ifdef NDEBUG
        const VolumeKey& vk{reinterpret_cast< const VolumeKey& >(k)};
#else
        const VolumeKey& vk{dynamic_cast< const VolumeKey& >(k)};
#endif

        const uint64_t vol_id{vk.vol_id()};
        const uint64_t lba{vk.lba()};
        const uint64_t nblks{vk.nblks()};

        uint8_t* const buf{VolumeManager< IOMgrExecutor >::instance()->gen_value(nblks)};
        assert(buf != nullptr);

        // To Do: write should take a const buf
        const auto ret_io{m_vol_mgr->write(vol_id, lba, buf, nblks)};
        iomanager.iobuf_free(buf);
        if (ret_io != no_error) {
            assert(false);
            return false;
        }

        return true;
    }

    uint64_t get_size(const uint64_t lba) const { return lba * VOL_PAGE_SIZE; }

private:
    std::atomic< uint64_t > m_write_skip{0};
    std::mutex m_mtx;
    VolumeManager< IOMgrExecutor >* m_vol_mgr = nullptr;
};

} // namespace loadgen
} // namespace homeds

#endif
