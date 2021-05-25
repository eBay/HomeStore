//
// Modified by Amit Desai
//

#ifndef HOMESTORE_MAP_KEY_SPEC_HPP
#define HOMESTORE_MAP_KEY_SPEC_HPP

#include <cassert>
#include <cstdint>
#include <functional>
#include <random>
#include <sstream>
#include <string>

#include "homeds/loadgen/loadgen_common.hpp"
#include "homeds/loadgen/spec/key_spec.hpp"

namespace homeds {
namespace loadgen {
class MapKey : public MappingKey, public KeySpec {

    static MapKey generate_random_key() {
        /* Seed */
        static thread_local std::random_device rd{};

        /* Random number generator */
        static thread_local std::default_random_engine generator{rd()};

        /* Distribution on which to apply the generator */
        std::uniform_int_distribution< lba_t > distribution{0, KeySpec::MAX_KEYS};

        const auto slba{distribution(generator)};
        return MapKey{slba, 1};
    }

public:
    static MapKey gen_key(const KeyPattern spec, const MapKey* const ref_key = nullptr) {
        switch (spec) {
        case KeyPattern::SEQUENTIAL: {
            if (ref_key) {
                const lba_t newlba{(ref_key->end() + 1) % KeySpec::MAX_KEYS};
                return MapKey{newlba, 1};
            } else {
                return generate_random_key();
            }
        }
        case KeyPattern::UNI_RANDOM: { // start key and nlba is random
            return generate_random_key();
        }
        case KeyPattern::OUT_OF_BOUND:
            return MapKey{LbaId::max_lba_possible(), 1};

        default:
            // We do not support other gen spec yet
            assert(false);
            return MapKey{0, 0};
        }
    }

    MapKey() = default;
    explicit MapKey(const lba_t lba_start, const lba_count_t n_lba) : MappingKey{lba_start, n_lba} {}
    explicit MapKey(const MapKey& key) : MappingKey{} { set(key.start(), key.get_n_lba()); }
    explicit MapKey(const MappingKey& key) { set(key.start(), key.get_n_lba()); }
    MapKey(MapKey&& key) noexcept : MappingKey{} { set(key.start(), key.get_n_lba()); }

    MapKey& operator=(const MapKey&) = delete;
    MapKey& operator=(MapKey&&) noexcept = delete;

    virtual ~MapKey() override = default;

    virtual bool operator==(const KeySpec& other) const override {
#ifdef NDEBUG
        const MapKey& map_key{reinterpret_cast< const MapKey& >(other)};
#else
        const MapKey& map_key{dynamic_cast< const MapKey& >(other)};
#endif
        return (compare(static_cast<const BtreeKey*>(&map_key)) == 0);
    }

    virtual bool is_consecutive(const KeySpec& k) const override {
#ifdef NDEBUG
        const MapKey& nk{reinterpret_cast< const MapKey& >(k)};
#else
        const MapKey& nk{dynamic_cast< const MapKey& >(k)};
#endif
        if (end() + 1 == nk.start())
            return true;
        else
            return false;
    }

    static void gen_keys_in_range(const MapKey& k1, const uint32_t num_of_keys, std::vector< MapKey >& keys_inrange) {
        lba_t start{k1.start()};
        const lba_t end{start + num_of_keys - 1};
        while (start <= end) {
            keys_inrange.push_back(MapKey{start, 1});
            ++start;
        }
    }
};

template < typename charT, typename traits >
std::basic_ostream< charT, traits >& operator<<(std::basic_ostream< charT, traits >& outStream,
                                                const MapKey& map_key) {
    // copy the stream formatting
    std::basic_ostringstream< charT, traits > outStringStream;
    outStringStream.copyfmt(outStream);

    // print the stream
    outStringStream << map_key.to_string();
    outStream << outStringStream.str();

    return outStream;
}

}; // namespace loadgen

} // namespace homeds
#endif // HOMESTORE_MAP_KEY_SPEC_HPP
