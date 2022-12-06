//
// Modified by Yaming Kuang
//

#pragma once

#include <cassert>
#include <cstdint>
#include <functional>
#include <limits>
#include <random>
#include <sstream>
#include <string>

#include "homeds/loadgen/loadgen_common.hpp"
#include "homeds/loadgen/spec/key_spec.hpp"
#include "homeds/loadgen/iomgr_executor.hpp"

namespace homeds {
namespace loadgen {

class VDevKey : public KeySpec {
    static constexpr uint64_t MAX_VDEV_ALLOC_SIZE{8192};
    static constexpr uint64_t VDEV_BLK_SIZE{512};

public:
    static VDevKey gen_key(const KeyPattern spec, const VDevKey* const ref_key = nullptr) {
        static uint64_t total_allocated_size{0};
        switch (spec) {
        case KeyPattern::UNI_RANDOM: {
            const auto alloc_size{get_rand_alloc_size()};
            const auto store{HomeBlks::instance()->get_data_logdev_blkstore()};

            if (total_allocated_size + alloc_size > store->get_size()) {
                return VDevKey{std::numeric_limits< uint64_t >::max(), alloc_size};
            }

            const auto off{store->alloc_next_append_blk(alloc_size)};
            total_allocated_size += alloc_size;
            return VDevKey{static_cast< uint64_t >(off), alloc_size};
        }

        case KeyPattern::SEQUENTIAL:
            assert(false);
            return VDevKey{std::numeric_limits< uint64_t >::max(), std::numeric_limits< uint64_t >::max()};

        case KeyPattern::OUT_OF_BOUND:
            return VDevKey{std::numeric_limits< uint64_t >::max(), std::numeric_limits< uint64_t >::max()};

        default:
            assert(false);
            return VDevKey{std::numeric_limits< uint64_t >::max(), std::numeric_limits< uint64_t >::max()};
        }
    }

    VDevKey() = default;
    VDevKey(const uint64_t off, const uint64_t sz) : m_off{off}, m_alloc_size{sz} {}

    VDevKey(const VDevKey& key) : m_off{key.get_offset()}, m_alloc_size{key.get_alloc_size()} {}

    VDevKey& operator=(const VDevKey& rhs) {
        if (this != &rhs) {
            m_off = rhs.get_offset();
            m_alloc_size = rhs.get_alloc_size();
        }
        return *this;
    }

    VDevKey(VDevKey&& key) noexcept : m_off{key.get_offset()}, m_alloc_size{key.get_alloc_size()} {}

    VDevKey& operator=(VDevKey&& rhs) noexcept {
        if (this != &rhs) {
            m_off = rhs.get_offset();
            m_alloc_size = rhs.get_alloc_size();
        }
        return *this;
    }

    virtual ~VDevKey() override = default;

    virtual bool operator==(const KeySpec& rhs) const override { return (compare(&rhs) == 0); }

    virtual bool is_consecutive(const KeySpec& k) const override {
        assert(false);
        return false;
    }

    virtual int compare(const KeySpec* const other) const {
#ifdef NDEBUG
        const VDevKey* vdev_key{reinterpret_cast< const VDevKey* >(other)};
#else
        const VDevKey* vdev_key{dynamic_cast< const VDevKey* >(other)};
#endif
        if (m_off < vdev_key->m_off)
            return -1;
        else if (m_off > vdev_key->m_off)
            return 1;
        else {
            if (m_alloc_size < vdev_key->m_alloc_size)
                return -1;
            else if (m_alloc_size > vdev_key->m_alloc_size)
                return 1;
            return 0;
        }
    }

    std::string to_string() const {
        std::ostringstream os;
        os << m_off << ", " << m_alloc_size;
        return os.str();
    }

    uint64_t get_offset() const { return m_off; }

    static uint64_t get_rand_alloc_size() {
        static thread_local std::random_device rd{};
        static thread_local std::default_random_engine generator{rd()};
        std::uniform_int_distribution< uint64_t > distribution{0, MAX_VDEV_ALLOC_SIZE / VDEV_BLK_SIZE - 1};

        const auto d{distribution(generator)};

        // size is between VDEV_BLK_SIZE ~ MAX_VDEV_ALLOC_SIZE, aligned of VDEV_BLK_SIZE;
        return (d + 1) * VDEV_BLK_SIZE;
    }

    uint64_t get_alloc_size() const { return m_alloc_size; }

private:
    uint64_t m_off{0};
    uint64_t m_alloc_size{0};
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