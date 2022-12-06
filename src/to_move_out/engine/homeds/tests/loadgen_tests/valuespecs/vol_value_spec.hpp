//
// Created by Kuang Yaming
//

#ifndef __HOMESTORE_VOLUME_VALUE_SPEC_HPP__
#define __HOMESTORE_VOLUME_VALUE_SPEC_HPP__

#include <array>
#include <cassert>
#include <cstdint>
#include <limits>
#include <memory>
#include <random>
#include <string>

#include "homeds/btree/btree.hpp"
#include "homeds/loadgen/iomgr_executor.hpp"
#include "homeds/loadgen/loadgen_common.hpp"
#include "homeds/loadgen/spec/value_spec.hpp"
#include "homeds/tests/loadgen_tests/vol_manager.hpp"

namespace homeds {
namespace loadgen {

class VolumeValue : public ValueSpec {

public:
    static std::shared_ptr< VolumeValue > gen_value(const ValuePattern spec, const VolumeValue* const ref_value = nullptr) {
        std::shared_ptr< VolumeValue > temp;
        switch (spec) {
        case ValuePattern::SEQUENTIAL_VAL:
            if (ref_value) {
                temp = std::make_shared< VolumeValue >(*ref_value);
            } else {
                temp = std::make_shared< VolumeValue >();
            }
            break;
        case ValuePattern::RANDOM_BYTES: {
            //
            // Generating dummy-unique value.
            // volume store to will generate the actual value;
            //
            std::array< uint8_t, 4096 > bytes;
            static thread_local std::random_device rd{};
            static thread_local std::default_random_engine generator{rd()};
            std::uniform_int_distribution< uint64_t > dist{std::numeric_limits< uint64_t >::min(),
                                                           std::numeric_limits< uint64_t >::max()};

            for (size_t i{0} ; i < bytes.size(); i += sizeof(uint64_t)) {
                *reinterpret_cast<uint64_t*>(bytes.data() + i) = dist(generator);
            }

            temp = std::make_shared< VolumeValue >(1, util::Hash64(reinterpret_cast<const char*>(bytes.data()), VOL_PAGE_SIZE));
            break;
        }

        default:
            // We do not support other gen spec yet
            assert(false);
            temp = std::make_shared< VolumeValue >();
            break;
        }

        return temp;
    }

    virtual ~VolumeValue() override {
        // m_bytes will be freed by homestore I/O path;
    }

    VolumeValue() = default;
    VolumeValue(const uint64_t nblks, const uint64_t crc) : m_nblks{nblks}, m_crc{crc} {}

    VolumeValue(const VolumeValue& other) : m_nblks{other.nblks()}, m_crc{other.crc()} {}
    VolumeValue& operator=(const VolumeValue& rhs) {
        if (this != &rhs) {
            m_nblks = rhs.nblks();
            m_crc = rhs.crc();
        }
        return *this;
    }
    VolumeValue(VolumeValue&&) noexcept = delete;
    VolumeValue& operator=(VolumeValue&&) noexcept = delete;

    uint64_t crc() const { return m_crc; }

    uint64_t nblks() const { return m_nblks; }

    virtual uint64_t get_hash_code() const override {
        return m_crc;
        // return util::Hash64((const char *)m_bytes, get_size(m_nblks));
    }

    int compare(const ValueSpec& other) const {
#ifdef NDEBUG
        const VolumeValue& other_val{reinterpret_cast< const VolumeValue& >(other)};
#else
        const VolumeValue& other_val{dynamic_cast< const VolumeValue& >(other)};
#endif

        if (m_nblks < other_val.m_nblks)
            return -1;
        else if (m_nblks > other_val.m_nblks)
            return 1;
        else {
            if (m_crc < other_val.m_crc)
                return -1;
            else if (m_crc > other_val.m_crc)
                return 1;
            return 0;
        }
    }

    bool operator==(const VolumeValue& rhs) const { return ((m_nblks == rhs.m_nblks) && (m_crc == rhs.m_crc));
    }

    std::string to_string() const { return std::to_string(m_nblks) + " " + std::to_string(m_crc); }

    sisl::blob get_blob() const {
        sisl::blob b;
        b.size = sizeof(uint64_t);
        b.bytes = reinterpret_cast< uint8_t* >(const_cast < uint64_t *>(& m_crc));
        return b;
    }

private:
    size_t get_size(const uint64_t nblks) const { return nblks * VOL_PAGE_SIZE; }

private:
    uint64_t m_nblks{0};
    uint64_t m_crc{0}; // crc of the buffer
    // uint8_t*    m_bytes;      // memory will be released by homestore
};
} // namespace loadgen
} // namespace homeds

#endif //_HOMESTORE_VOLUME_VALUE_SPEC_HPP__
