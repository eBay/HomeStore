//
// Modified by Amit Desai
//

#ifndef HOMESTORE_MAP_VALUE_SPEC_HPP
#define HOMESTORE_MAP_VALUE_SPEC_HPP

#include "homeds/loadgen/loadgen_common.hpp"
#include "homeds/btree/btree.hpp"
#include "homeds/loadgen/spec/value_spec.hpp"
#include <farmhash.h>

namespace homeds {
namespace loadgen {
class MapValue : public MappingValue, public ValueSpec {

#define INVALID_SEQ_ID UINT64_MAX
public:
    BlkId get_blkId() {
        ValueEntry ve;
        get_array().get(0, ve, false);
        return ve.get_blkId();
    }

    uint64_t start() {
        ValueEntry ve;
        get_array().get(0, ve, false);
        return ve.get_blkId().m_id + ve.get_blk_offset();
    }

    // NOTE assuming data block size is same as lba-volume block size
    uint64_t end() {
        ValueEntry ve;
        get_array().get(0, ve, false);
        return start() + ve.get_nlba() - 1;
    }

    void addToId(uint64_t val) {
        ValueEntry ve;
        get_array().get(0, ve, false);
        ve.get_blkId().m_id += val;
    }

    void reset() {
        ValueEntry ve;
        get_array().get(0, ve, false);
        ve.get_blkId().m_id = 0;
    }

    static MapValue gen_value(ValuePattern spec, MapValue* ref_value = nullptr) {
        std::array< uint16_t, CS_ARRAY_STACK_SIZE > carr;
        for (auto i = 0ul; i < CS_ARRAY_STACK_SIZE; i++)
            carr[i] = 1;

        switch (spec) {
        case ValuePattern::SEQUENTIAL_VAL: {
            if (ref_value) {
                MapValue value(*ref_value);
                value.addToId(1);
                if (value.start() == MAX_VALUES) {
                    value.reset();
                }
                return value;
            } else {
                ValueEntry ve(INVALID_SEQ_ID, BlkId(1, 1, 0), 0, 1, carr);
                return MapValue(ve);
            }
        }
        case ValuePattern::RANDOM_BYTES: {

            auto sid = INVALID_SEQ_ID;

            /* Seed */
            std::random_device rd;

            /* Random number generator */
            std::default_random_engine generator(rd());

            /* Distribution on which to apply the generator */
            std::uniform_int_distribution< long long unsigned > distribution(0, MAX_VALUES);

            auto sblk = distribution(generator);

            ValueEntry ve(sid, BlkId(sblk, 1, 0), 0, 1, carr);

            return MapValue(ve);
        }
        default:
            // We do not support other gen spec yet
            assert(0);
            return MapValue();
        }
    }

    MapValue() : MappingValue() {}
    explicit MapValue(ValueEntry& ve) : MappingValue(ve) {}
    explicit MapValue(MappingValue& value) : MappingValue(value) {}

    MapValue& operator=(const MapValue& other) {
        copy_blob(other.get_blob());
        return *this;
    }

    // This is not mandatory overridden method for BtreeValue, but for testing comparision
    //            bool operator==(const MapValue& other) const {
    //                return (memcpy(m_bytes, other.get_blob().m_bytes, Size) == 0);
    //            }
    //
    virtual uint64_t get_hash_code() override {
        homeds::blob b = get_blob();
        return util::Hash64((const char*)b.bytes, (size_t)b.size);
    }

    virtual int compare(ValueSpec& other) override {
        MapValue* mv = (MapValue*)&other;
        assert(end() - start() == 0);
        assert(mv->end() - mv->start() == 0);

        int x = start() - mv->start();
        if (x == 0)
            return 0;
        else
            return x; // which start is lesser
    }

    virtual bool is_consecutive(ValueSpec& v) override {
        MapValue* nv = (MapValue*)&v;
        if (end() + 1 == nv->start())
            return true;
        else
            return false;
    }
};
} // namespace loadgen
} // namespace homeds

#endif // HOMESTORE_MAP_VALUE_SPEC_HPP
