//
// Modified by Yaming Kuang
//

#ifndef __HOMESTORE_VOLUME_KEY_SPEC_HPP__
#define __HOMESTORE_VOLUME_KEY_SPEC_HPP__

#include "homeds/loadgen/loadgen_common.hpp"
#include "homeds/loadgen/spec/key_spec.hpp"
#include "homeds/loadgen/iomgr_executor.hpp"
#include "homeds/tests/loadgen_tests/vol_manager.hpp"

#include <random>
#include <sstream>

namespace homeds {
namespace loadgen {

class VolumeKey : public KeySpec {
private:
public:
    VolumeKey() : m_vol_id(0), m_lba(0), m_nblks(0) {}

    static VolumeKey gen_key(KeyPattern spec, VolumeKey* ref_key = nullptr) {
        switch (spec) {
        case KeyPattern::SEQUENTIAL: assert(0); return VolumeKey(0, 0, 0);

        case KeyPattern::UNI_RANDOM: {
            uint64_t vol_id = 0, new_lba = 0, nblks = 0;

            VolumeManager< IOMgrExecutor >::instance()->gen_key(vol_id, new_lba, nblks);

            return VolumeKey(vol_id, new_lba, nblks);
        }

        case KeyPattern::OUT_OF_BOUND:
            return VolumeKey(VolumeManager< IOMgrExecutor >::instance()->max_vols() + 1, KeySpec::MAX_KEYS + 100, 0);

        default: assert(0); return VolumeKey(0, 0, 0);
        }
    }

    VolumeKey(uint64_t vol_index, uint64_t n_lba, uint64_t nblks) : m_vol_id(vol_index), m_lba(n_lba), m_nblks(nblks) {}

    VolumeKey(const VolumeKey& key) {
        m_vol_id = key.vol_id();
        m_lba = key.lba();
        m_nblks = key.nblks();
    }

    uint64_t nblks() const { return m_nblks; }
    uint64_t vol_id() const { return m_vol_id; }
    uint64_t lba() const { return m_lba; }

    virtual bool operator==(const KeySpec& other) const override {
        return (((const VolumeKey*)&(VolumeKey&)other)->lba() == m_lba) &&
            (((const VolumeKey*)&(VolumeKey&)other)->vol_id() == m_vol_id);
    }

    friend ostream& operator<<(ostream& os, const VolumeKey& k) {
        os << k.vol_id() << k.lba();
        return os;
    }

    virtual bool is_consecutive(KeySpec& k) override {
        assert(0);
        return false;
    }

    virtual int compare(KeySpec* other) const {
        VolumeKey* k = dynamic_cast< VolumeKey* >(other);
        return to_string().compare(k->to_string());
    }

    std::string to_string() const {
        ostringstream os;
        os << m_vol_id << m_lba;
        return os.str();
    }

private:
    uint64_t m_vol_id;
    uint64_t m_lba;
    uint64_t m_nblks;
};

} // namespace loadgen
} // namespace homeds

#endif //__HOMESTORE_VOLUME_KEY_SPEC_HPP__
