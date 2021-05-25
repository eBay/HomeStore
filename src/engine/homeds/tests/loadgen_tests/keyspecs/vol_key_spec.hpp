//
// Modified by Yaming Kuang
//

#ifndef __HOMESTORE_VOLUME_KEY_SPEC_HPP__
#define __HOMESTORE_VOLUME_KEY_SPEC_HPP__

#include <cassert>
#include <cstdint>
#include <functional>
#include <random>
#include <sstream>
#include <string>

#include "homeds/loadgen/iomgr_executor.hpp"
#include "homeds/loadgen/loadgen_common.hpp"
#include "homeds/loadgen/spec/key_spec.hpp"
#include "homeds/tests/loadgen_tests/vol_manager.hpp"

namespace homeds {
namespace loadgen {

class VolumeKey : public KeySpec {
private:
public:
    static VolumeKey gen_key(const KeyPattern spec, const VolumeKey* const ref_key = nullptr) {
        switch (spec) {
        case KeyPattern::SEQUENTIAL:
            assert(false);
            return VolumeKey{0, 0, 0};

        case KeyPattern::UNI_RANDOM: {
            uint64_t vol_id{0}, new_lba{0}, nblks{0};

            VolumeManager< IOMgrExecutor >::instance()->gen_key(vol_id, new_lba, nblks);

            return VolumeKey{vol_id, new_lba, nblks};
        }

        case KeyPattern::OUT_OF_BOUND:
            return VolumeKey{VolumeManager< IOMgrExecutor >::instance()->max_vols() + 1, KeySpec::MAX_KEYS + 100, 0};

        default:
            assert(false);
            return VolumeKey{0, 0, 0};
        }
    }

    VolumeKey() = default;
    VolumeKey(uint64_t vol_index, uint64_t n_lba, uint64_t nblks) : m_vol_id(vol_index), m_lba(n_lba), m_nblks(nblks) {}

    VolumeKey(const VolumeKey& key) : m_vol_id{key.vol_id()}, m_lba{key.lba()}, m_nblks{key.nblks()} {}
    VolumeKey& operator=(const VolumeKey& rhs) {
        if (this != &rhs) {
            m_vol_id = rhs.vol_id();
            m_lba = rhs.lba();
            m_nblks = rhs.nblks();
        }
        return *this;
    }

    VolumeKey(VolumeKey&& key) noexcept : m_vol_id{key.vol_id()}, m_lba{key.lba()}, m_nblks{key.nblks()} {}
    VolumeKey& operator=(VolumeKey&& rhs) noexcept {
        if (this != &rhs) {
            m_vol_id = rhs.vol_id();
            m_lba = rhs.lba();
            m_nblks = rhs.nblks();
        }
        return *this;
    }

    virtual ~VolumeKey() override = default;

    uint64_t nblks() const { return m_nblks; }
    uint64_t vol_id() const { return m_vol_id; }
    uint64_t lba() const { return m_lba; }

    virtual bool operator==(const KeySpec& rhs) const override { return (compare(&rhs) == 0); }

    virtual bool is_consecutive(const KeySpec& k) const override {
#ifdef NDEBUG
        [[maybe_unused]] const VolumeKey& volume_key{reinterpret_cast< const VolumeKey& >(k)};
#else
        [[maybe_unused]] const VolumeKey& volume_key{dynamic_cast< const VolumeKey& >(k)};
#endif
        assert(false);
        return false;
    }

    virtual int compare(const KeySpec* const other) const {
#ifdef NDEBUG
        const VolumeKey* volume_key{reinterpret_cast< const VolumeKey* >(other)};
#else
        const VolumeKey* volume_key{dynamic_cast< const VolumeKey* >(other)};
#endif

        if (m_vol_id < volume_key->m_vol_id)
            return -1;
        else if (m_vol_id > volume_key->m_vol_id)
            return 1;
        else {
            if (m_lba < volume_key->m_lba)
                return -1;
            else if (m_lba > volume_key->m_lba)
                return 1;
            return 0;
        }
    }

    std::string to_string() const {
        std::ostringstream os;
        os << m_vol_id << m_lba;
        return os.str();
    }

private:
    uint64_t m_vol_id{0};
    uint64_t m_lba{0};
    uint64_t m_nblks{0};
};

template < typename charT, typename traits >
std::basic_ostream< charT, traits >& operator<<(std::basic_ostream< charT, traits >& outStream, const VolumeKey& key) {
    // copy the stream formatting
    std::basic_ostringstream< charT, traits > outStringStream;
    outStringStream.copyfmt(outStream);

    // print the stream
    outStringStream << key.to_string();
    outStream << outStringStream.str();

    return outStream;
}

} // namespace loadgen
} // namespace homeds

// hash function definitions
namespace std {
template <>
struct hash< homeds::loadgen::VolumeKey > {
    typedef homeds::loadgen::VolumeKey argument_type;
    typedef size_t result_type;
    result_type operator()(const argument_type& vol_key) const noexcept {
        return std::hash< uint64_t >()(vol_key.vol_id()) ^ std::hash< uint64_t >()(vol_key.lba()) ^
            std::hash< uint64_t >()(vol_key.nblks());
    }
};
} // namespace std

#endif //__HOMESTORE_VOLUME_KEY_SPEC_HPP__
