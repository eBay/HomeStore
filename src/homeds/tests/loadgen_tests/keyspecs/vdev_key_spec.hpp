//
// Modified by Yaming Kuang
//

#pragma once

#include "homeds/loadgen/loadgen_common.hpp"
#include "homeds/loadgen/spec/key_spec.hpp"
#include "homeds/loadgen/iomgr_executor.hpp"

#include <random>
#include <sstream>

namespace homeds { 
namespace loadgen {

// 
//
class VDevKey : public KeySpec {
private:

public:
    VDevKey()  {}

    static VDevKey gen_key(KeyPattern spec, VDevKey *ref_key = nullptr) {
        switch(spec) {
            case KeyPattern::UNI_RANDOM:
            {
                auto store = HomeBlks::instance()->get_logdev_blkstore();
                auto off = store->alloc_blk(512);
                return VDevKey(off);
            }

            case KeyPattern::SEQUENTIAL: 
                assert(0);
                return VDevKey((uint64_t)-1);

            case KeyPattern::OUT_OF_BOUND: 
                return VDevKey((uint64_t)-1);

            default:
                assert(0);
                return VDevKey((uint64_t)-1);
        }
    }

    VDevKey(uint64_t k) : m_key_val(k) {}

    VDevKey(const VDevKey& key) { m_key_val = key.get_key_val(); }
    
    virtual bool operator==(const KeySpec& other) const override {
        assert(0);
        return true;
    }
    
    friend ostream& operator<<(ostream& os, const VDevKey& k) {
        return os;
    }

    virtual bool is_consecutive(KeySpec& k) override {
        assert(0);
        return false;
    }
    
    virtual int compare(KeySpec* other) const {
        VDevKey* k = dynamic_cast<VDevKey*> (other);
        return to_string().compare(k->to_string());
    }
    
    std::string to_string() const {
        ostringstream os;
        os << m_key_val;
        return os.str();
    }

    uint64_t get_key_val() const {
        return m_key_val;
    }

private:
    uint64_t m_key_val;  
};

}  // loadgen
}  // homeds

