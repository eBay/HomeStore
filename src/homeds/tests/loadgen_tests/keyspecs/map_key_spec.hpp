//
// Modified by Amit Desai
//

#ifndef HOMESTORE_MAP_KEY_SPEC_HPP
#define HOMESTORE_MAP_KEY_SPEC_HPP

#include "homeds/loadgen/loadgen_common.hpp"
#include "homeds/loadgen/spec/key_spec.hpp"
#include <spdlog/fmt/bundled/ostream.h>
#include <random>
namespace homeds {
namespace loadgen {
class MapKey : public MappingKey, public KeySpec {

    static MapKey generate_random_key() {
        /* Seed */
        std::random_device rd;

        /* Random number generator */
        std::default_random_engine generator(rd());

        /* Distribution on which to apply the generator */
        std::uniform_int_distribution< long long unsigned > distribution(0, KeySpec::MAX_KEYS);

        auto slba = distribution(generator);
        return MapKey(slba, 1);
    }

public:
    static MapKey gen_key(KeyPattern spec, MapKey* ref_key = nullptr) {
        switch (spec) {
        case KeyPattern::SEQUENTIAL: {
            uint64_t newlba = 0;
            if (ref_key) {
                newlba = (ref_key->end() + 1) % KeySpec::MAX_KEYS;
                return MapKey(newlba, 1);
            } else {
                return generate_random_key();
            }
        }
        case KeyPattern::UNI_RANDOM: { // start key and nlba is random
            return generate_random_key();
        }
        case KeyPattern::OUT_OF_BOUND: return MapKey((uint64_t)-1, 1);

        default:
            // We do not support other gen spec yet
            assert(0);
            return MapKey(0, 0);
        }
    }

    explicit MapKey(uint64_t lba_start, uint64_t n_lba) : MappingKey(lba_start, n_lba) {}
    explicit MapKey(const MapKey& key) : MappingKey() { set(key.start(), key.get_n_lba()); }
    explicit MapKey(const MappingKey& key) { set(key.start(), key.get_n_lba()); }

    virtual bool operator==(const KeySpec& other) const override {
        return (compare((const BtreeKey*)&(MapKey&)other) == 0);
    }

    friend ostream& operator<<(ostream& os, const MapKey& k) {
        os << k.to_string();
        return os;
    }

    virtual bool is_consecutive(KeySpec& k) override {
        MapKey* nk = (MapKey*)&k;
        if (end() + 1 == nk->start())
            return true;
        else
            return false;
    }

    static void gen_keys_in_range(MapKey& k1, uint32_t num_of_keys, std::vector< MapKey >& keys_inrange) {
        uint64_t start = k1.start();
        uint64_t end = start + num_of_keys - 1;
        while (start <= end) {
            keys_inrange.push_back(MapKey(start, 1));
            start++;
        }
    }
};

}; // namespace loadgen

} // namespace homeds
#endif // HOMESTORE_MAP_KEY_SPEC_HPP
