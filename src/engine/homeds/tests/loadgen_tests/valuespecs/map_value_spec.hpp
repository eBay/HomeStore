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
#ifndef HOMESTORE_MAP_VALUE_SPEC_HPP
#define HOMESTORE_MAP_VALUE_SPEC_HPP

#include <array>
#include <cassert>
#include <cstdint>
#include <memory>
#include <random>

#include <farmhash.h>

#include "homeds/btree/btree.hpp"
#include "homeds/loadgen/loadgen_common.hpp"
#include "homeds/loadgen/spec/value_spec.hpp"

namespace homeds {
namespace loadgen {
class MapValue : public MappingValue, public ValueSpec {
private:
    static auto gen_array() {
        std::array< uint16_t, CS_ARRAY_STACK_SIZE > carr;
        carr.fill(1);
        return carr;
    }

public:
    BlkId get_blkId() const {
        const ValueEntry* const ve{get_nth_entry(0)};
        return ve->get_base_blkid();
    }

    uint64_t start() const {
        const ValueEntry* const ve{get_nth_entry(0)};
        return ve->get_base_blkid().get_blk_num() + ve->get_lba_offset();
    }

    // NOTE assuming data block size is same as lba-volume block size
    uint64_t end() const {
        const ValueEntry* const ve{get_nth_entry(0)};
        return start() + ve->get_num_lbas() - 1;
    }

    void addToId(const uint64_t val) {
        ValueEntry* const ve{get_nth_entry(0)};
        auto bid{ve->get_base_blkid()};
        bid.set_blk_num(ve->get_base_blkid().get_blk_num() + val);
        ve->set_blkid(bid);
    }

    void reset() {
        ValueEntry* const ve{get_nth_entry(0)};
        ve->get_base_blkid().set_blk_num(0);
    }

    static std::shared_ptr< MapValue > gen_value(const ValuePattern spec, const MapValue* const ref_value = nullptr) {
        static const auto carr{gen_array()};
        std::shared_ptr< MapValue > temp;
        switch (spec) {
        case ValuePattern::SEQUENTIAL_VAL: {
            if (ref_value) {
                temp = std::make_shared< MapValue >(*ref_value);
                temp->addToId(1);
                if (temp->start() == MAX_VALUES) {
                    /* return invalid value */
                    temp.reset();
                }

                return temp;
            } else {
                temp =
                    std::make_shared< MapValue >(MappingValue{INVALID_SEQ_ID, BlkId{1u, 1u, 0u}, 0u, 1u, carr.data()});
                return temp;
            }
        }
        case ValuePattern::RANDOM_BYTES: {

            const auto sid{INVALID_SEQ_ID};

            /* Seed */
            static thread_local std::random_device rd{};

            /* Random number generator */
            static thread_local std::default_random_engine generator{rd()};

            /* Distribution on which to apply the generator */
            const blk_num_t max_blk{MAX_VALUES > static_cast< uint64_t >(std::numeric_limits< blk_num_t >::max())
                                        ? std::numeric_limits< blk_num_t >::max()
                                        : static_cast< blk_num_t >(MAX_VALUES)};

            std::uniform_int_distribution< blk_num_t > distribution{0, max_blk};

            const auto sblk{distribution(generator)};

            temp = std::make_shared< MapValue >(MappingValue{sid, BlkId{sblk, 1u, 0u}, 0u, 1u, carr.data()});
            return temp;
        }
        default:
            // We do not support other gen spec yet
            assert(false);
            temp = std::make_shared< MapValue >();
            return temp;
        }
    }

    MapValue() : MappingValue{} {}
    // explicit MapValue(ValueEntry& ve) : MappingValue(ve) {}
    explicit MapValue(const MappingValue& value) : MappingValue{value} {}

    MapValue(const MapValue& other) : MappingValue{other} {}
    MapValue& operator=(const MapValue& rhs) {
        if (this != &rhs) { copy_blob(rhs.get_blob()); }
        return *this;
    }
    MapValue(MapValue&&) noexcept = delete;
    MapValue& operator=(MapValue&&) noexcept = delete;

    virtual ~MapValue() override = default;

    // This is not mandatory overridden method for BtreeValue, but for testing comparision
    //            bool operator==(const MapValue& other) const {
    //                return (memcpy(m_bytes, other.get_blob().m_bytes, Size) == 0);
    //            }
    //
    virtual uint64_t get_hash_code() const override {
        ValueEntry* const ve{get_latest_entry()};
        auto seqid{ve->get_seqid()};
        ve->set_seq_id(INVALID_SEQ_ID);
        const sisl::blob b{ve->get_blob()};
        const auto hash{util::Hash64(reinterpret_cast< const char* >(b.bytes), static_cast< size_t >(b.size))};
        ve->set_seq_id(seqid);
        return hash;
    }
};
} // namespace loadgen
} // namespace homeds

#endif // HOMESTORE_MAP_VALUE_SPEC_HPP
