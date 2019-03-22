//
// Created by Kadayam, Hari on 2/22/19.
//
#ifndef HOMESTORE_WORKLOAD_GENERATOR_HPP
#define HOMESTORE_WORKLOAD_GENERATOR_HPP

#include "../loadgen_common.hpp"
#include "homeds/btree/btree.hpp"
#include <spdlog/fmt/bundled/ostream.h>

namespace homeds { namespace loadgen {

template< typename K >
struct compare_keys {
public:
    bool operator()(const K &key1, const K &key2) const {
        return key1.compare(&key2) == 0;
    }
};

template< typename K >
struct key_hash {
    size_t operator()(const K &key) const {
        auto b = key.get_blob();
        return util::Hash32((const char *)b.bytes, (size_t)b.size);
    }
};

class SimpleNumberKey : public homeds::btree::BtreeKey {
private:
    uint64_t m_num;

public:
    static SimpleNumberKey gen_key(KeyPattern spec, SimpleNumberKey *ref_key = nullptr) {
        switch (spec) {
        case KeyPattern::SEQUENTIAL:
            return ref_key ? SimpleNumberKey(ref_key->to_integer() + 1) : SimpleNumberKey();

        case KeyPattern::UNI_RANDOM:
            return SimpleNumberKey(rand());

        case KeyPattern::LAST:
            return SimpleNumberKey((uint64_t)-1);

        default:
            // We do not support other gen spec yet
            assert(0);
            return SimpleNumberKey();
        }
    }

    static constexpr bool is_fixed_size() { return true; }
    static constexpr uint32_t get_max_size() { return sizeof(uint64_t); }

    explicit SimpleNumberKey(uint64_t num = 0) : m_num(num) {}
    SimpleNumberKey(const SimpleNumberKey& other) = default;
    SimpleNumberKey& operator=(const SimpleNumberKey& other) = default;

    static constexpr size_t get_fixed_size() { return sizeof(uint64_t); }
    uint64_t to_integer() const { return m_num; }

    int compare(const BtreeKey* o) const override {
        SimpleNumberKey* other = (SimpleNumberKey*)o;
        if (m_num < other->m_num) { return -1; }
        else if (m_num > other->m_num) { return 1; }
        else { return 0; }
    }

    int compare_range(const homeds::btree::BtreeSearchRange& range) const override {
        auto other_start = (SimpleNumberKey*)range.get_start_key();
        auto other_end = (SimpleNumberKey*)range.get_end_key();

        assert(0); // Do not support it yet
        return 0;
    }

    virtual homeds::blob get_blob() const {
        homeds::blob b = {(uint8_t*)&m_num, sizeof(uint64_t)};
        return b;
    };

    virtual void set_blob(const homeds::blob& b) {
        auto n = *((uint64_t *)b.bytes);
        m_num = n;
    }
    virtual void copy_blob(const homeds::blob& b) { set_blob(b); }

    virtual uint32_t get_blob_size() const { return sizeof(uint64_t); }
    virtual void set_blob_size(uint32_t size) {}
    virtual std::string to_string() const { return std::to_string(m_num); }

    friend ostream& operator<<(ostream& os, const SimpleNumberKey& k) {
        os << std::to_string(k.m_num);
        return os;
    }
};

class CompositeNumberKey : public homeds::btree::BtreeKey {
private:
    typedef struct __attribute__((packed)) {
        uint64_t m_count : 16;
        uint64_t m_rank : 10;
        uint64_t m_blk_num : 38;
    } attr_t;

    attr_t* m_attr;
    attr_t m_inplace_attr;

public:
    static CompositeNumberKey gen_key(KeyPattern spec, CompositeNumberKey *ref_key = nullptr) {
        switch (spec) {
        case KeyPattern::SEQUENTIAL:
            assert(ref_key != nullptr);
            return CompositeNumberKey(ref_key->to_integer() + 1);

        case KeyPattern::UNI_RANDOM:
            return CompositeNumberKey(rand());

        case KeyPattern::LAST:
            return CompositeNumberKey((uint64_t)-1);

        default:
            // We do not support other gen spec yet
            assert(0);
            return CompositeNumberKey();
        }
    }

    static constexpr bool is_fixed_size() { return true; }
    static constexpr uint32_t get_max_size() { return sizeof(attr_t); }

    CompositeNumberKey(uint32_t count, uint16_t rank, uint64_t blk_num) {
        m_attr = &m_inplace_attr;
        set_count(count);
        set_rank(rank);
        set_blk_num(blk_num);
    }

    CompositeNumberKey() : CompositeNumberKey(0, 0, 0) {}

    CompositeNumberKey(const CompositeNumberKey& other) :
            CompositeNumberKey(other.get_count(), other.get_rank(), other.get_blk_num()) {}

    CompositeNumberKey& operator=(const CompositeNumberKey& other) {
        copy_blob(other.get_blob());
        return *this;
    }

    explicit CompositeNumberKey(uint64_t num) {
        m_attr = &m_inplace_attr;
        memcpy(&m_inplace_attr, &num, sizeof(uint64_t));
    }

    uint32_t get_count() const { return (m_attr->m_count); }
    uint16_t get_rank() const { return (m_attr->m_rank); }
    uint64_t get_blk_num() const { return (m_attr->m_blk_num); }
    void set_count(uint32_t count) { m_attr->m_count = count; }
    void set_rank(uint32_t rank) { m_attr->m_rank = rank; }
    void set_blk_num(uint32_t blkNum) { m_attr->m_blk_num = blkNum; }
    uint64_t to_integer() const {
        uint64_t n;
        memcpy(&n, m_attr, sizeof(uint64_t));
        return n;
    }

    int compare(const BtreeKey* o) const override {
        CompositeNumberKey* other = (CompositeNumberKey*)o;
        if (get_count() < other->get_count()) {
            return -1;
        } else if (get_count() > other->get_count()) {
            return 1;
        } else if (get_rank() < other->get_rank()) {
            return -1;
        } else if (get_rank() > other->get_rank()) {
            return 1;
        } else if (get_blk_num() < other->get_blk_num()) {
            return -1;
        } else if (get_blk_num() > other->get_blk_num()) {
            return 1;
        } else {
            return 0;
        }
    }

    int compare_range(const homeds::btree::BtreeSearchRange& range) const override {
        auto other_start = (CompositeNumberKey*)range.get_start_key();
        auto other_end = (CompositeNumberKey*)range.get_end_key();

        assert(0); // Do not support it yet
        return 0;
    }

    int is_in_range(uint64_t val, uint64_t start, bool start_incl, uint64_t end, bool end_incl) {
        if (val < start) {
            return 1;
        } else if ((val == start) && (!start_incl)) {
            return 1;
        } else if (val > end) {
            return -1;
        } else if ((val == end) && (!end_incl)) {
            return -1;
        } else {
            return 0;
        }
    }

    int compare_range(BtreeKey* s, bool start_incl, BtreeKey* e, bool end_incl) {
        CompositeNumberKey* start = (CompositeNumberKey*)s;
        CompositeNumberKey* end = (CompositeNumberKey*)e;

        int ret = is_in_range(this->get_count(), start->get_count(), start_incl, end->get_count(), end_incl);
        if (ret != 0) {
            return ret;
        }

        ret = is_in_range(this->get_rank(), start->get_rank(), start_incl, end->get_rank(), end_incl);
        if (ret != 0) {
            return ret;
        }

        ret = is_in_range(this->get_blk_num(), start->get_blk_num(), start_incl, end->get_blk_num(), end_incl);
        if (ret != 0) {
            return ret;
        }

        return 0;
    }

    virtual homeds::blob get_blob() const override {
        homeds::blob b = {(uint8_t*)m_attr, sizeof(attr_t)};
        return b;
    }

    virtual void set_blob(const homeds::blob& b) override { m_attr = (attr_t*)b.bytes; }
    virtual void copy_blob(const homeds::blob& b) override { memcpy(m_attr, b.bytes, b.size); }
    virtual uint32_t get_blob_size() const override { return (sizeof(attr_t)); }

    static uint32_t get_fixed_size() { return (sizeof(attr_t)); }
    virtual void set_blob_size(uint32_t size) override {}

    std::string to_string() const {
        std::stringstream ss;
        ss << "count: " << get_count() << " rank: " << get_rank() << " blknum: " << get_blk_num();
        return ss.str();
    }

    friend ostream& operator<<(ostream& os, const CompositeNumberKey& k) {
        os << "count: " << k.get_count() << " rank: " << k.get_rank() << " blknum: " << k.get_blk_num();
        return os;
    }

    bool operator<(const CompositeNumberKey& o) const { return (compare(&o) < 0); }
    bool operator==(const CompositeNumberKey& other) const { return (compare(&other) == 0); }
};
} } // namespace homeds::loadgen
#endif // HOMESTORE_WORKLOAD_GENERATOR_HPP
