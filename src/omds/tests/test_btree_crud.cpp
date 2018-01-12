//
// Created by Kadayam, Hari on 11/01/18.
//
#include <gtest/gtest.h>
#include <iostream>
#include "omds/btree/mem_btree.hpp"

class BtreeTestEntry : public omds::btree::BtreeKey {
private:
    typedef struct __attribute__((packed)) {
        uint64_t m_count :16;
        uint64_t m_rank :10;
        uint64_t m_blk_num :38;
    } blob_t;

    blob_t *m_blob;
    blob_t m_inplace_blob;

public:
    BtreeTestEntry(uint32_t count, uint16_t rank, uint64_t blk_num) {
        m_blob = &m_inplace_blob;
        set_count(count);
        set_rank(rank);
        set_blk_num(blk_num);
    }

    BtreeTestEntry() : BtreeTestEntry(0, 0, 0) {
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
        BtreeTestEntry *other = (BtreeTestEntry *) o;
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
        BtreeTestEntry *start = (BtreeTestEntry *) s;
        BtreeTestEntry *end = (BtreeTestEntry *) e;

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
};

struct BtreeCrudTest : public testing::Test {
protected:
    omds::btree::MemBtree< BtreeTestEntry, omds::btree::EmptyClass > *m_bt;
public:
    BtreeCrudTest() {
        omds::btree::BtreeConfig btree_cfg;
        btree_cfg.set_leaf_node_type(omds::btree::BTREE_NODETYPE_SIMPLE);
        btree_cfg.set_interior_node_type(omds::btree::BTREE_NODETYPE_SIMPLE);
        btree_cfg.set_max_objs(1000);
        btree_cfg.set_max_key_size(sizeof(BtreeTestEntry));
        btree_cfg.set_max_value_size(0);
        m_bt = new omds::btree::MemBtree<BtreeTestEntry, omds::btree::EmptyClass >(btree_cfg);
    }

    virtual ~BtreeCrudTest() {
        delete(m_bt);
    }
};

TEST_F(BtreeCrudTest, SimpleInsert) {
    BtreeTestEntry te1(rand() % 5000, rand() % 1000, 1);
    omds::btree::EmptyClass v;
    m_bt->put(te1, v, omds::btree::INSERT_ONLY_IF_NOT_EXISTS);
    bool ret = m_bt->get(te1, &v);
    EXPECT_EQ(ret, true);
}

int main(int argc, char *argv[]) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}