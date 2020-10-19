//
// Modified by Yaming Kuang
//

#pragma once

#include <cassert>
#include <cstdint>
#include <functional>
#include <random>
#include <sstream>
#include <string>

#include "homeds/loadgen/loadgen_common.hpp"
#include "homeds/loadgen/spec/key_spec.hpp"
#include "homeds/loadgen/iomgr_executor.hpp"

namespace homeds {
namespace loadgen {

class VDevKey : public KeySpec {
#define MAX_VDEV_ALLOC_SIZE 8192
#define VDEV_BLK_SIZE 512

public:
    VDevKey() {}

    static VDevKey gen_key(KeyPattern spec, VDevKey* ref_key = nullptr) {
        static uint64_t total_allocated_size = 0;
        auto alloc_size = get_rand_alloc_size();
        switch (spec) {
        case KeyPattern::UNI_RANDOM: {
            auto store = HomeBlks::instance()->get_logdev_blkstore();

            if (total_allocated_size + alloc_size > store->get_size()) { return VDevKey((uint64_t)-1, alloc_size); }

            auto off = store->alloc_next_append_blk(alloc_size);
            total_allocated_size += alloc_size;
            return VDevKey(off, alloc_size);
        }

        case KeyPattern::SEQUENTIAL:
            assert(0);
            return VDevKey((uint64_t)-1, (uint64_t)-1);

        case KeyPattern::OUT_OF_BOUND:
            return VDevKey((uint64_t)-1, (uint64_t)-1);

        default:
            assert(0);
            return VDevKey((uint64_t)-1, (uint64_t)-1);
        }
    }

    VDevKey(uint64_t off, uint64_t sz) : m_off(off), m_alloc_size(sz) {}

    VDevKey(const VDevKey& key) {
        m_off = key.get_offset();
        m_alloc_size = key.get_alloc_size();
    }

    virtual bool operator==(const KeySpec& other) const override {
        assert(0);
        return true;
    }

    virtual bool is_consecutive(KeySpec& k) override {
        assert(0);
        return false;
    }

    virtual int compare(KeySpec* other) const {
        // this is hokey down casting
#ifdef NDEBUG
        const VDevKey* vdev_key{reinterpret_cast< const VDevKey* >(other)};
#else
        const VDevKey* vdev_key{dynamic_cast< const VDevKey* >(other)};
#endif
        return to_string().compare(vdev_key->to_string());
    }

    std::string to_string() const {
        std::ostringstream os;
        os << m_off << ", " << m_alloc_size;
        return os.str();
    }

    uint64_t get_offset() const { return m_off; }

    static uint64_t get_rand_alloc_size() {
        auto d = rand() % (MAX_VDEV_ALLOC_SIZE / VDEV_BLK_SIZE);

        // size is between VDEV_BLK_SIZE ~ MAX_VDEV_ALLOC_SIZE, aligned of VDEV_BLK_SIZE;
        return (d + 1) * VDEV_BLK_SIZE;
    }

    uint64_t get_alloc_size() const { return m_alloc_size; }

private:
    uint64_t m_off = 0;
    uint64_t m_alloc_size = 0;
};

template < typename charT, typename traits >
std::basic_ostream< charT, traits >& operator<<(std::basic_ostream< charT, traits >& outStream, const VDevKey& key) {
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
struct hash< homeds::loadgen::VDevKey > {
    typedef homeds::loadgen::VDevKey argument_type;
    typedef size_t result_type;
    result_type operator()(const argument_type& vdev_key) const noexcept {
        return std::hash< uint64_t >()(vdev_key.get_offset()) ^ std::hash< uint64_t >()(vdev_key.get_alloc_size());
    }
};
} // namespace std