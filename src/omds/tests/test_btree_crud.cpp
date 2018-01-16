//
// Created by Kadayam, Hari on 11/01/18.
//
#include <gtest/gtest.h>
#include <iostream>
#include "omds/btree/mem_btree.hpp"
#include <thread>

class TestSimpleKey : public omds::btree::BtreeKey {
private:
    typedef struct __attribute__((packed)) {
        uint64_t m_count :16;
        uint64_t m_rank :10;
        uint64_t m_blk_num :38;
    } blob_t;

    blob_t *m_blob;
    blob_t m_inplace_blob;

public:
    TestSimpleKey(uint32_t count, uint16_t rank, uint64_t blk_num) {
        m_blob = &m_inplace_blob;
        set_count(count);
        set_rank(rank);
        set_blk_num(blk_num);
    }

    TestSimpleKey() : TestSimpleKey(0, 0, 0) {
    }

    inline uint32_t get_count() const {
        return (m_blob->m_count);
    }

    inline uint16_t get_rank() const {
        return (m_blob->m_rank);
    }

    inline uint64_t get_blk_num() const {
        return (m_blob->m_blk_num);
    }

    inline void set_count(uint32_t count) {
        m_blob->m_count = count;
    }

    inline void set_rank(uint32_t rank) {
        m_blob->m_rank = rank;
    }

    inline void set_blk_num(uint32_t blkNum) {
        m_blob->m_blk_num = blkNum;
    }

    int compare(const BtreeKey *o) const override {
        TestSimpleKey *other = (TestSimpleKey *) o;
        if (get_count() < other->get_count()) {
            return 1;
        } else if (get_count() > other->get_count()) {
            return -1;
        } else if (get_rank() < other->get_rank()) {
            return 1;
        } else if (get_rank() > other->get_rank()) {
            return -1;
        } else if (get_blk_num() < other->get_blk_num()) {
            return 1;
        } else if (get_blk_num() > other->get_blk_num()) {
            return -1;
        } else {
            return 0;
        }
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

    int compare_range(BtreeKey *s, bool start_incl, BtreeKey *e, bool end_incl) {
        TestSimpleKey *start = (TestSimpleKey *) s;
        TestSimpleKey *end = (TestSimpleKey *) e;

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

    virtual omds::blob get_blob() const override {
        omds::blob b = {(uint8_t *) m_blob, sizeof(blob_t)};
        return b;
    }

    virtual void set_blob(const omds::blob &b) override {
        m_blob = (blob_t *) b.bytes;
    }

    virtual void copy_blob(const omds::blob &b) override {
        memcpy(m_blob, b.bytes, b.size);
    }

    virtual uint32_t get_blob_size() const override {
        return (sizeof(blob_t));
    }

    static uint32_t get_fixed_size() {
        return (sizeof(blob_t));
    }

    virtual void set_blob_size(uint32_t size) override {
    }

    void print() {
        cout << "count: " << get_count() << " rank: " << get_rank() << " blknum: " << get_blk_num();
    }

    bool operator<(const TestSimpleKey &o) const {
        return (compare(&o) < 0);
    }
};

class TestSimpleValue : public omds::btree::BtreeValue {
public:
    TestSimpleValue(uint32_t val) : omds::btree::BtreeValue() {
        m_val = val;
    }

    TestSimpleValue() : TestSimpleValue((uint32_t)-1) {}

    omds::blob get_blob() const override {
        omds::blob b;
        b.bytes = (uint8_t *)&m_val; b.size = sizeof(m_val);
        return b;
    }

    void set_blob(const omds::blob &b) override {
        m_val = *((uint32_t *)b.bytes);
    }

    void copy_blob(const omds::blob &b) override {
        m_val = *((uint32_t *)b.bytes);
    }

    void append_blob(const BtreeValue &new_val) override {
        m_val = ((const TestSimpleValue &)new_val).m_val;
    }

    uint32_t get_blob_size() const override {
        return sizeof(m_val);
    }

    void set_blob_size(uint32_t size) override {
        assert(size == sizeof(m_val));
    }

    static uint32_t get_fixed_size() {
        return sizeof(m_val);
    }

    void print() const override {
        std::cout << "val = " << m_val;
    }

    // This is not mandatory overridden method for BtreeValue, but for testing comparision
    bool operator==(const TestSimpleValue &other) const {
        return (m_val == other.m_val);
    }
    uint32_t m_val;
};

struct SimpleKeyComparator {
    bool operator()(const TestSimpleKey* left, const TestSimpleKey* right) const {
        return (left->compare(right) > 0);
    }
};

#define TOTAL_ENTRIES          1000
#define TOTAL_OPERS_PER_TEST   500
#define NTHREADS               1

struct BtreeCrudTest : public testing::Test {
protected:
    omds::btree::MemBtree< TestSimpleKey, TestSimpleValue > *m_bt;
    std::array<TestSimpleKey *, TOTAL_ENTRIES> m_entries;
    std::map<TestSimpleKey *, TestSimpleValue, SimpleKeyComparator> m_create_map;

public:
    BtreeCrudTest() {
        omds::btree::BtreeConfig btree_cfg;
        btree_cfg.set_leaf_node_type(omds::btree::BTREE_NODETYPE_SIMPLE);
        btree_cfg.set_interior_node_type(omds::btree::BTREE_NODETYPE_SIMPLE);
        btree_cfg.set_max_objs(TOTAL_ENTRIES);
        btree_cfg.set_max_key_size(sizeof(TestSimpleKey));
        btree_cfg.set_max_value_size(0);
        m_bt = new omds::btree::MemBtree<TestSimpleKey, TestSimpleValue >(btree_cfg);
        init_entries();
    }

    void init_entries() {
        for (auto i = 0; i < TOTAL_ENTRIES; i++) {
            do {
                m_entries[i] = new TestSimpleKey(rand() % 5000, rand() % 1000, 1);
                auto e = m_create_map.find(m_entries[i]);
                if (e == m_create_map.end()) {
                    m_create_map.insert(std::pair<TestSimpleKey *, TestSimpleValue>(m_entries[i], TestSimpleValue(0U)));
                    break;
                }
                delete(m_entries[i]);
            } while (true);
        }
    }

    virtual ~BtreeCrudTest() {
        delete(m_bt);

        for (auto e : m_entries) {
            delete(e);
        }
    }

    void put_nth_entry(uint32_t i) {
        auto it = m_create_map.find(m_entries[i]);
        assert(it != m_create_map.end());
        m_bt->put(*m_entries[i], it->second, omds::btree::INSERT_ONLY_IF_NOT_EXISTS);
    }

    void get_nth_entry(uint32_t i) {
        TestSimpleValue v;
        bool ret = m_bt->get(*m_entries[i], &v);
        EXPECT_EQ(ret, true);
        EXPECT_EQ(m_create_map.find(m_entries[i])->second, v);
    }

    void delete_nth_entry(uint32_t i) {
        TestSimpleValue v;
        bool ret = m_bt->remove(*m_entries[i], &v);
        EXPECT_EQ(ret, true);
        EXPECT_EQ(m_create_map.find(m_entries[i])->second, v);
    }

    static void insert_and_get_thread(BtreeCrudTest *test, uint32_t start, uint32_t count, int get_pct) {
        // First preload upto the get_pct
        uint32_t readable_count = (count * get_pct)/100;
        for (auto i = start; i < start + readable_count; i++) {
            test->put_nth_entry(i);
            // EXPECT_EQ(ret, true);
        }

        // Next read and insert based on the percentage of reads provided
        uint32_t nopers = 0;
        while (nopers++ < TOTAL_OPERS_PER_TEST) {
            if (((rand() % 100) > get_pct) && (readable_count < count)) {
                // Its an insert, do a put
                test->put_nth_entry(start + readable_count++);
            } else {
                test->get_nth_entry((rand() % readable_count) + start);
            }
        }

        // Cleanup the btree
        for (auto i = start; i < start + readable_count; i++) {
            test->delete_nth_entry(i);
        }
    }
};

TEST_F(BtreeCrudTest, SimpleInsert) {
#if 0
    for (auto i = 0; i < TOTAL_ENTRIES; i++) {
        auto it = m_create_map.find(m_entries[i]);
        assert(it != m_create_map.end());
        m_bt->put(*m_entries[i], it->second, omds::btree::INSERT_ONLY_IF_NOT_EXISTS);
    }

    for (auto i = 0; i < TOTAL_ENTRIES; i++) {
        TestSimpleValue v;
        bool ret = m_bt->get(*m_entries[i], &v);
        EXPECT_EQ(ret, true);
        EXPECT_EQ(m_create_map.find(m_entries[i])->second, v);
    }
#endif

    std::array<std::thread *, NTHREADS> thrs;
    for (auto i = 0; i < NTHREADS; i++) {
        thrs[i] = new std::thread(insert_and_get_thread, this, i * TOTAL_ENTRIES/NTHREADS, TOTAL_ENTRIES/NTHREADS, 50);
    }

    for (auto &t : thrs) {
        t->join();
        delete (t);
    }
}

int main(int argc, char *argv[]) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}