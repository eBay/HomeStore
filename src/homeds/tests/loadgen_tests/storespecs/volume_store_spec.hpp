//
//  Created by Yaming Kuang
//
#ifndef __VOLUME_STORE_SPEC_HPP__
#define __VOLUME_STORE_SPEC_HPP__

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
template< typename K, typename V >
class VolumeStoreSpec : public StoreSpec< K, V > {
public:

    virtual void init_store(homeds::loadgen::Param& parameters) override {
        m_vol_mgr = VolumeManager<IOMgrExecutor>::instance();
    }

    // read
    virtual bool get(K& k, V* out_v) override { 
        VolumeKey* vk = dynamic_cast<VolumeKey*>(&k);

        uint64_t vol_id = vk->vol_id();
        uint64_t lba = vk->lba();
        uint64_t nblks = vk->nblks();

        auto verify = VolumeManager<IOMgrExecutor>::instance()->check_and_set_bm(vol_id, lba, nblks);

        auto ret_io = m_vol_mgr->read(vol_id, lba, nblks, verify);
        if (ret_io != no_error) {
            return false;
        } 

        return true;
    }
    
    // new write
    virtual bool insert(K& k, std::shared_ptr<V> v) override {
        return update_internal (k, v);
    }

    virtual bool upsert(K& k, std::shared_ptr<V> v) override {
        assert(0);
        return update_internal (k, v);
    }

    // over-write
    virtual bool update(K& k, std::shared_ptr<V> v) override {
        VolumeKey*      vk = dynamic_cast<VolumeKey*>(&k);
        
        uint64_t        nblks = vk->nblks();
        uint64_t        lba = vk->lba();
        uint64_t        vol_id = vk->vol_id();

        auto ret = VolumeManager<IOMgrExecutor>::instance()->check_and_set_bm(vol_id, lba, nblks);
        if (ret == false) {
            // we don't allow writes on same lba that read/write has not acked yet.
            m_write_skip++;
            return true;
        }

        return update_internal(k, v);
    }

    virtual bool remove(K& k, V* removed_v = nullptr) override {
        assert(0);
        return true;
    }
     
    virtual bool remove_any(K& start_key, bool start_incl, K& end_key, bool end_incl, K *out_key, V* out_val) override {
        assert(0);
        return true;
    }

    virtual uint32_t query(K& start_key, bool start_incl, K& end_key, bool end_incl, std::vector<std::pair<K, V>> &result) {
        assert(0);
        return 1;
    }

    virtual bool range_update(K& start_key, bool start_incl, K& end_key, bool end_incl, 
                              std::vector< std::shared_ptr<V> > &result) {
        assert(0);
        return true;
    }

private: 
    bool update_internal(K& k, std::shared_ptr<V> v) {
        VolumeKey*      vk = dynamic_cast<VolumeKey*>(&k);

        uint64_t        nblks = vk->nblks();
        uint8_t*        buf = VolumeManager<IOMgrExecutor>::instance()->gen_value(nblks);

        uint64_t lba = vk->lba();
        uint64_t vol_id = vk->vol_id();

        assert(buf != nullptr);


        auto ret_io = m_vol_mgr->write(vol_id, lba, buf, nblks);
        if (ret_io != no_error) {
            assert(0);
            free(buf);
            return false;
        }

        return true;
    }

    uint64_t get_size(uint64_t lba) {
        return lba * VOL_PAGE_SIZE;
    }   

private:
    std::atomic<uint64_t>           m_write_skip = 0;
    std::mutex                      m_mtx;
    VolumeManager<IOMgrExecutor>*   m_vol_mgr = nullptr;
};

}
}


#endif

