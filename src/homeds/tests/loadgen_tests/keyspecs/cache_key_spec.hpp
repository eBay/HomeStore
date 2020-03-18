//
// Modified by Amit Desai
//

#ifndef HOMESTORE_CACHE_KEY_SPEC_HPP
#define HOMESTORE_CACHE_KEY_SPEC_HPP

#include "homeds/loadgen/loadgen_common.hpp"
#include "homeds/loadgen/spec/key_spec.hpp"
#include <fmt/ostream.h>
#include <random>
namespace homeds {
namespace loadgen {
class CacheKey : public BlkId, public KeySpec {

    static CacheKey generate_random_key() {
        /* Seed */
        std::random_device rd;

        /* Random number generator */
        std::default_random_engine generator(rd());

        /* Distribution on which to apply the generator */
        std::uniform_int_distribution< long long unsigned > distribution(0, KeySpec::MAX_KEYS);

        auto sblkid = distribution(generator);
        return CacheKey(sblkid, 1);
    }

public:
    static CacheKey gen_key(KeyPattern spec, CacheKey* ref_key = nullptr) {
        switch (spec) {
        case KeyPattern::SEQUENTIAL: {
            uint64_t newblkId = 0;
            if (ref_key) {
                newblkId = (ref_key->get_id() + 1) % KeySpec::MAX_KEYS;
                return CacheKey(newblkId, 1, 0);
            } else {
                return generate_random_key();
            }
        }
        case KeyPattern::UNI_RANDOM: { // start key is random
            return generate_random_key();
        }
        case KeyPattern::OUT_OF_BOUND: return CacheKey((uint64_t)-1, 1, 0);

        default:
            // We do not support other gen spec yet
            assert(0);
            return CacheKey(0, 0);
        }
    }

    explicit CacheKey() : BlkId(0, 0, 0) {}
    explicit CacheKey(uint64_t id, uint8_t nblks, uint16_t chunk_num = 0) : BlkId(id, nblks, chunk_num) {}
    CacheKey(const CacheKey& key) : BlkId(0, 0, 0) { set(key.m_id, key.m_nblks, key.m_chunk_num); }

    virtual bool operator==(const KeySpec& other) const override {
        CacheKey otherKey = (CacheKey&)other;
        return compare(*this, otherKey);
    }

    BlkId* getBlkId() { return (BlkId*)this; }

    friend ostream& operator<<(ostream& os, const CacheKey& k) {
        os << k.to_string();
        return os;
    }

    virtual bool is_consecutive(KeySpec& k) override {
        CacheKey* nk = (CacheKey*)&k;
        if (get_id() + get_nblks() == nk->get_id())
            return true;
        else
            return false;
    }

    int compare(const CacheKey* other) const { return compare(*this, *other); }

    static int compare(const CacheKey& one, const CacheKey& two) {
        BlkId bid1 = *(BlkId*)&one;
        BlkId bid2 = *(BlkId*)&two;
        int v = BlkId::compare(bid2, bid1);
        return v;
    }

    static void gen_keys_in_range(CacheKey& k1, uint32_t num_of_keys, std::vector< CacheKey >& keys_inrange) {
        uint64_t start = k1.get_id();
        uint64_t end = start + num_of_keys - 1;
        while (start <= end) {
            keys_inrange.push_back(CacheKey(start, 1, 0));
            start++;
        }
    }
};

}; // namespace loadgen

} // namespace homeds
#endif // HOMESTORE_CACHE_KEY_SPEC_HPP
