//
// Created by Kuang Yaming
//

#ifndef __HOMESTORE_VOLUME_VALUE_SPEC_HPP__
#define __HOMESTORE_VOLUME_VALUE_SPEC_HPP__

#include <climits>
#include "homeds/loadgen/loadgen_common.hpp"
#include "homeds/btree/btree.hpp"
#include "homeds/loadgen/spec/value_spec.hpp"
#include "homeds/loadgen/iomgr_executor.hpp"
#include "homeds/tests/loadgen_tests/vol_manager.hpp"

namespace homeds {
namespace loadgen {

class VolumeValue : public ValueSpec {

public:
    static std::shared_ptr< VolumeValue > gen_value(ValuePattern spec, VolumeValue* ref_value = nullptr) {
        std::shared_ptr< VolumeValue > temp;
        switch (spec) {
        case ValuePattern::SEQUENTIAL_VAL:
            if (ref_value) {
                VolumeValue v = VolumeValue(*ref_value);
                temp = std::make_shared< VolumeValue >(v);
            } else {
                VolumeValue v = VolumeValue();
                temp = std::make_shared< VolumeValue >(v);
            }
            break;
        case ValuePattern::RANDOM_BYTES: {
            //
            // Generating dummy-unique value.
            // volume store to will generate the actual value;
            //
            uint8_t bytes[4096];
            auto size = 4096ull;
#if 0
                std::random_device rd;
                std::default_random_engine generator(rd());

                // TODO: populate uint64_t every time instead of uchar;
                std::uniform_int_distribution<long long unsigned> dist(0, UCHAR_MAX); 
                for (auto i = 0ull; i < size-1; i++) { 
                    bytes[i] = dist(generator);
                }
 
                bytes[size-1] = 0;
#endif
            std::random_device rd;
            std::default_random_engine generator(rd());
            std::uniform_int_distribution< long long unsigned > dist(std::numeric_limits< unsigned long long >::min(),
                                                                     std::numeric_limits< unsigned long long >::max());

            for (auto i = 0ull; i < size; i += sizeof(uint64_t)) {
                *(uint64_t*)(bytes + i) = dist(generator);
            }

            VolumeValue v = VolumeValue(1, util::Hash64((const char*)&bytes[0], VOL_PAGE_SIZE));
            temp = std::make_shared< VolumeValue >(v);
            break;
        }

        default:
            // We do not support other gen spec yet
            assert(0);
            VolumeValue v = VolumeValue();
            temp = std::make_shared< VolumeValue >(v);
            break;
        }

        return temp;
    }

    ~VolumeValue() {
        // m_bytes will be freed by homestore I/O path;
    }

    VolumeValue() {
        m_nblks = 0;
        m_crc = 0;
        // m_bytes = nullptr;
    }

    VolumeValue(const VolumeValue& other) {
        m_nblks = other.nblks();
        m_crc = other.crc();
        // m_bytes = other.get_bytes_ptr();
    }

    VolumeValue& operator=(const VolumeValue& other) {
        assert(0);
        return *this;
    }

    VolumeValue(uint64_t nblks, uint64_t crc) {
        m_nblks = nblks;
        m_crc = crc;
        // m_bytes = bytes;
    }

    uint64_t crc() const { return m_crc; }

    uint64_t nblks() const { return m_nblks; }

    virtual uint64_t get_hash_code() override {
        return m_crc;
        // return util::Hash64((const char *)m_bytes, get_size(m_nblks));
    }

    int compare(ValueSpec& other) {
        return to_string().compare(((const VolumeValue*)&(VolumeValue&)other)->to_string());
#if 0
        VolumeValue* vv = (VolumeValue*)&other;
        int x = m_crc - vv->crc();
        if (x == 0)
            return 0;
        else 
            return x;
#endif
    }

    bool operator==(const VolumeValue& other) const { return to_string().compare(other.to_string()) == 0; }

    std::string to_string() const { return std::to_string(m_nblks) + " " + std::to_string(m_crc); }

    homeds::blob get_blob() const {
        homeds::blob b;
        b.size = sizeof(uint64_t);
        b.bytes = (uint8_t*)&m_crc;
        return b;
    }

private:
    size_t get_size(uint64_t nblks) const { return nblks * VOL_PAGE_SIZE; }

private:
    uint64_t m_nblks;
    uint64_t m_crc; // crc of the buffer
    // uint8_t*    m_bytes;      // memory will be released by homestore
};
} // namespace loadgen
} // namespace homeds

#endif //_HOMESTORE_VOLUME_VALUE_SPEC_HPP__
