//
// Modified by Amit Desai
//

#ifndef HOMESTORE_CACHE_VALUE_SPEC_HPP
#define HOMESTORE_CACHE_VALUE_SPEC_HPP

#include "homeds/loadgen/loadgen_common.hpp"
#include "homeds/btree/btree.hpp"
#include "homeds/loadgen/spec/value_spec.hpp"
#include <farmhash.h>

namespace homeds {
namespace loadgen {
class CacheValue : public ValueSpec {
    uint64_t m_id = 0;

#define INVALID_SEQ_ID UINT64_MAX
public:
    void set_id(uint64_t id) { m_id = id; }

    uint64_t get_id() const { return m_id; }

    static CacheValue gen_value(ValuePattern spec, CacheValue* ref_value = nullptr) {
        std::array< uint16_t, CS_ARRAY_STACK_SIZE > carr;
        for (auto i = 0ul; i < CS_ARRAY_STACK_SIZE; i++)
            carr[i] = 1;

        switch (spec) {
        case ValuePattern::SEQUENTIAL_VAL: {
            uint64_t newid = 0;
            if (ref_value) {
                newid = ref_value->get_id() + 1;
                if (newid == MAX_VALUES) {
                    newid = 0;
                }
                return CacheValue(newid);
            } else {
                return CacheValue(0);
            }
        }
        case ValuePattern::RANDOM_BYTES: {

            /* Seed */
            std::random_device rd;

            /* Random number generator */
            std::default_random_engine generator(rd());

            /* Distribution on which to apply the generator */
            std::uniform_int_distribution< long long unsigned > distribution(0, MAX_VALUES);

            auto sid = distribution(generator);

            return CacheValue(sid);
        }
        default:
            // We do not support other gen spec yet
            assert(0);
            return CacheValue();
        }
    }

    CacheValue() {}
    CacheValue(uint64_t id) { set_id(id); }

    CacheValue& operator=(const CacheValue& other) {
        uint64_t id = ((CacheValue*)(&other))->get_id();
        set_id(id);
        return *this;
    }

    virtual uint64_t get_hash_code() override {
        homeds::blob b = get_blob();
        return util::Hash64((const char*)b.bytes, (size_t)b.size);
    }

    virtual int compare(ValueSpec& other) override {
        CacheValue* mv = (CacheValue*)&other;

        int x = get_id() - mv->get_id();
        if (x == 0)
            return 0;
        else
            return x; // which start is lesser
    }

    virtual bool is_consecutive(ValueSpec& v) override {
        CacheValue* nv = (CacheValue*)&v;
        if (get_id() + 1 == nv->get_id())
            return true;
        else
            return false;
    }

    static void* merge_bytes(std::vector< void* > locs) {
        // creates new bytes array and combines all data from locs
        return nullptr;
    }

    static uint8_t* generate_bytes(uint64_t id, uint64_t size) {
        // generates 4k bytes with repeating id at loc
        uint64_t* raw_buf = (uint64_t*)malloc(size);
        for (auto b = 0U; b < size / sizeof(uint64_t); b++)
            raw_buf[b] = id;
        return (uint8_t*)raw_buf;
    }

    static void release_bytes(uint64_t* loc, uint64_t size) {
        // release 4k bytes at loc
        free(loc);
    }

    static bool verify_id(uint64_t* loc, uint64_t id, uint64_t size) {
        // verifies if loc has repeating id
        for (auto b = 0U; b < size / sizeof(uint64_t); b++)
            if (loc[b] != id)
                return false;
        return true;
    }

    virtual std::string to_string() const { return std::to_string(get_id()); }

    homeds::blob get_blob() const {
        homeds::blob b;
        b.bytes = (uint8_t*)&m_id;
        b.size = sizeof(uint64_t);
        return b;
    }
};
} // namespace loadgen
} // namespace homeds

#endif // HOMESTORE_CACHE_VALUE_SPEC_HPP
