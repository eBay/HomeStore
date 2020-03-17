//
// Created by Kadayam, Hari on 11/01/18.
//
#include <gtest/gtest.h>
#include <iostream>
#include "homeds/btree/btree.hpp"
#include <thread>
#include <memory>
#include <sds_logging/logging.h>
#include <sds_options/options.h>
#include <utility/thread_buffer.hpp>
#include <utility/obj_life_counter.hpp>

#include "blkstore/blkstore.hpp"
#include "device/virtual_dev.hpp"
#include "homeds/btree/mem_btree.hpp"
#include <metrics/metrics.hpp>
#include "main/homestore_header.hpp"

SDS_LOGGING_INIT(HOMESTORE_LOG_MODS)
THREAD_BUFFER_INIT;

#define MAX_CACHE_SIZE 2 * 1024 * 1024 * 1024
using namespace std;
using namespace homestore;
using namespace homeds::btree;

#if 0
homestore::DeviceManager *dev_mgr = nullptr;
homestore::Cache< BlkId > *glob_cache = nullptr;
btree_device_info bt_dev_info;
#endif

#define TestBtreeDeclType                                                                                              \
    Btree< btree_store_type::MEM_BTREE, TestSimpleKey, TestSimpleValue, btree_node_type::SIMPLE,                       \
           btree_node_type::SIMPLE >

#if 0
AbstractVirtualDev *new_vdev_found(homestore::DeviceManager *mgr, homestore::vdev_info_block *vb) {
    LOGINFO("New virtual device found id = {} size = {}", vb->vdev_id, vb->size);
    assert(0); // This test at present does not support restoring the btree
    return nullptr;
}

void setup_devices(uint32_t ndevs) {
    std::vector<std::string> dev_names;
    dev_names.reserve(ndevs);

    for (auto i = 0; i < ndevs; i++) {
        std::stringstream ss;
        ss << "/tmp/phys_dev" << i+1;
        dev_names.push_back(ss.str());

        LOGINFO("Creating device: {}", ss.str());

        std::stringstream cmd;
        cmd << "dd if=/dev/zero of=" << ss.str() << " bs=64k count=32768";
        system(cmd.str().c_str());
    }

    // Create a global cache entry
    glob_cache = new homestore::Cache< homestore::BlkId >(MAX_CACHE_SIZE, 8192);
    assert(glob_cache);

    /* Create/Load the devices */
    LOGINFO("Adding devices to DeviceManager");
    dev_mgr = new homestore::DeviceManager(new_vdev_found, 0);
    try {
        dev_mgr->add_devices(dev_names);
    } catch (std::exception &e) {
        LOGCRITICAL("Exception info {}", e.what());
        exit(1);
    }

    // Create device info for btree
    bt_dev_info.size = 512 * 1024 * 1024;
    bt_dev_info.dev_mgr = dev_mgr;
    bt_dev_info.cache = glob_cache;
    bt_dev_info.new_device = true;
    bt_dev_info.vb = nullptr;
}
#endif

class TestSimpleKey : public BtreeKey {
private:
    typedef struct __attribute__((packed)) {
        uint64_t m_count : 16;
        uint64_t m_rank : 10;
        uint64_t m_blk_num : 38;
    } blob_t;

    blob_t* m_blob;
    blob_t m_inplace_blob;

public:
    TestSimpleKey(uint32_t count, uint16_t rank, uint64_t blk_num) {
        m_blob = &m_inplace_blob;
        set_count(count);
        set_rank(rank);
        set_blk_num(blk_num);
    }

    TestSimpleKey() : TestSimpleKey(0, 0, 0) {}

    TestSimpleKey(const TestSimpleKey& other) :
            TestSimpleKey(other.get_count(), other.get_rank(), other.get_blk_num()) {}
    TestSimpleKey& operator=(const TestSimpleKey& other) {
        copy_blob(other.get_blob());
        return *this;
    }

    inline uint32_t get_count() const { return (m_blob->m_count); }

    inline uint16_t get_rank() const { return (m_blob->m_rank); }

    inline uint64_t get_blk_num() const { return (m_blob->m_blk_num); }

    inline void set_count(uint32_t count) { m_blob->m_count = count; }

    inline void set_rank(uint32_t rank) { m_blob->m_rank = rank; }

    inline void set_blk_num(uint32_t blkNum) { m_blob->m_blk_num = blkNum; }

    int compare(const BtreeKey* o) const override {
        TestSimpleKey* other = (TestSimpleKey*)o;
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

    int compare_range(const BtreeSearchRange& range) const override {
        auto other_start = (TestSimpleKey*)range.get_start_key();
        auto other_end = (TestSimpleKey*)range.get_end_key();

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
        TestSimpleKey* start = (TestSimpleKey*)s;
        TestSimpleKey* end = (TestSimpleKey*)e;

        int ret = is_in_range(this->get_count(), start->get_count(), start_incl, end->get_count(), end_incl);
        if (ret != 0) { return ret; }

        ret = is_in_range(this->get_rank(), start->get_rank(), start_incl, end->get_rank(), end_incl);
        if (ret != 0) { return ret; }

        ret = is_in_range(this->get_blk_num(), start->get_blk_num(), start_incl, end->get_blk_num(), end_incl);
        if (ret != 0) { return ret; }

        return 0;
    }

    virtual homeds::blob get_blob() const override {
        homeds::blob b = {(uint8_t*)m_blob, sizeof(blob_t)};
        return b;
    }

    virtual void set_blob(const homeds::blob& b) override { m_blob = (blob_t*)b.bytes; }

    virtual void copy_blob(const homeds::blob& b) override { memcpy(m_blob, b.bytes, b.size); }

    virtual uint32_t get_blob_size() const override { return (sizeof(blob_t)); }

    static uint32_t get_fixed_size() { return (sizeof(blob_t)); }

    virtual void set_blob_size(uint32_t size) override {}

    std::string to_string() const {
        std::stringstream ss;
        ss << "count: " << get_count() << " rank: " << get_rank() << " blknum: " << get_blk_num();
        return ss.str();
    }

    friend ostream& operator<<(ostream& os, const TestSimpleKey& k) {
        os << "count: " << k.get_count() << " rank: " << k.get_rank() << " blknum: " << k.get_blk_num();
        return os;
    }

    bool operator<(const TestSimpleKey& o) const { return (compare(&o) < 0); }

    bool operator==(const TestSimpleKey& other) const { return (compare(&other) == 0); }
};

class TestSimpleValue : public BtreeValue {
public:
    TestSimpleValue(uint32_t val) : BtreeValue() { m_val = val; }

    TestSimpleValue() : TestSimpleValue((uint32_t)-1) {}

    TestSimpleValue(const TestSimpleValue& other) { copy_blob(other.get_blob()); }
    TestSimpleValue& operator=(const TestSimpleValue& other) {
        copy_blob(other.get_blob());
        return *this;
    }

    homeds::blob get_blob() const override {
        homeds::blob b;
        b.bytes = (uint8_t*)&m_val;
        b.size = sizeof(m_val);
        return b;
    }

    void set_blob(const homeds::blob& b) override { m_val = *((uint32_t*)b.bytes); }

    void copy_blob(const homeds::blob& b) override { m_val = *((uint32_t*)b.bytes); }

    void append_blob(const BtreeValue& new_val, BtreeValue& existing_val) override {
        m_val = ((const TestSimpleValue&)new_val).m_val;
    }

    uint32_t get_blob_size() const override { return sizeof(m_val); }

    void set_blob_size(uint32_t size) override { assert(size == sizeof(m_val)); }

    static uint32_t get_fixed_size() { return sizeof(m_val); }

    std::string to_string() const {
        std::stringstream ss;
        ss << "val = " << m_val;
        return ss.str();
    }

    friend ostream& operator<<(ostream& os, const TestSimpleValue& v) {
        os << "val = " << v.m_val;
        return os;
    }

    // This is not mandatory overridden method for BtreeValue, but for testing comparision
    bool operator==(const TestSimpleValue& other) const { return (m_val == other.m_val); }

    uint32_t estimate_size_after_append(const BtreeValue& new_val) override { return sizeof(m_val); }
    uint32_t m_val;
};

struct SimpleKeyComparator {
    bool operator()(const TestSimpleKey* left, const TestSimpleKey* right) const { return (left->compare(right) < 0); }
};

#define TOTAL_ENTRIES 100000
#define TOTAL_OPERS_PER_TEST 500
#define NTHREADS 4
//#define NTHREADS               1

struct BtreeCrudTest : public testing::Test {
protected:
    TestBtreeDeclType* m_bt;
    std::array< TestSimpleKey*, TOTAL_ENTRIES > m_entries;
    std::array< TestSimpleKey*, TOTAL_ENTRIES > m_sorted_entries;
    std::map< TestSimpleKey*, TestSimpleValue, SimpleKeyComparator > m_create_map;

public:
    BtreeCrudTest() {
        BtreeConfig btree_cfg(4096);
        btree_cfg.set_max_objs(TOTAL_ENTRIES);
        btree_cfg.set_max_key_size(sizeof(TestSimpleKey));
        btree_cfg.set_max_value_size(0);
        // m_bt = TestBtreeDeclType::create_btree(btree_cfg, &bt_dev_info);
        m_bt = TestBtreeDeclType::create_btree(btree_cfg, nullptr);
        init_entries();
    }

    void init_entries() {
        for (auto i = 0; i < TOTAL_ENTRIES; i++) {
            do {
                m_entries[i] = new TestSimpleKey(rand() % 5000, rand() % 1000, 1);
                auto e = m_create_map.find(m_entries[i]);
                if (e == m_create_map.end()) {
                    m_create_map.insert(
                        std::pair< TestSimpleKey*, TestSimpleValue >(m_entries[i], TestSimpleValue(0U)));
                    break;
                }
                delete (m_entries[i]);
            } while (true);
        }
    }

    virtual ~BtreeCrudTest() {
#ifdef _PRERELEASE
        LOGINFO("Final test metrics result = {}", m_bt->get_metrics_in_json().dump());
        sisl::ObjCounterRegistry::foreach ([](const std::string& name, int64_t created, int64_t alive) {
            LOGINFO("ObjLife {}: created={} alive={}", name, created, alive);
        });
#endif
        delete (m_bt);

        for (auto e : m_entries) {
            delete (e);
        }
    }

    void put_nth_entry(uint32_t i) {
        auto it = m_create_map.find(m_entries[i]);
        assert(it != m_create_map.end());
        auto ret = m_bt->put(*m_entries[i], it->second, btree_put_type::INSERT_ONLY_IF_NOT_EXISTS);
        assert(ret == btree_status_t::success);
    }

    void get_nth_entry(uint32_t i) {
        TestSimpleValue v;
        auto ret = m_bt->get(*m_entries[i], &v);
        EXPECT_EQ(ret, btree_status_t::success);
        EXPECT_EQ(m_create_map.find(m_entries[i])->second, v);
    }

    void delete_nth_entry(uint32_t i) {
        TestSimpleValue v;
        auto ret = m_bt->remove(*m_entries[i], &v);
        if (ret != btree_status_t::success) {
            m_bt->print_tree();
            assert(0);
        }
        EXPECT_EQ(ret, btree_status_t::success);
        EXPECT_EQ(m_create_map.find(m_entries[i])->second, v);
    }

    template < class Fn, class... Args >
    void run_in_parallel(int nthreads, Fn&& fn, uint32_t start, uint32_t count, Args&&... args) {
        std::vector< std::thread* > thrs;
        for (auto i = 0; i < nthreads; i++) {
            thrs.push_back(new std::thread(fn, this, start + (i * count / nthreads), count / nthreads,
                                           std::forward< Args >(args)...));
        }

        for (auto t : thrs) {
            t->join();
            delete (t);
        }
    }

    static void preload_thread(BtreeCrudTest* test, uint32_t start, uint32_t count) {
        for (auto i = start; i < start + count; i++) {
            test->put_nth_entry(i);
            // EXPECT_EQ(ret, true);
        }
    }

    static void insert_and_get_thread(BtreeCrudTest* test, uint32_t start, uint32_t count, int get_pct) {
        // First preload upto the get_pct
        uint32_t readable_count = (count * get_pct) / 100;

        test->run_in_parallel(1, preload_thread, start, readable_count);

        // Next read and insert based on the percentage of reads provided

        // BELOW code has some bug, hence commenting for now.
        // bug surfaces when we run memory sanitizer only.
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

    static void query_thread(BtreeCrudTest* test, uint32_t start, uint32_t count, BtreeQueryType qtype,
                             uint32_t query_batch_size) {
        auto search_range = BtreeSearchRange(*test->m_entries[start], true, *test->m_entries[start + count - 1], true);
        BtreeQueryRequest< TestSimpleKey, TestSimpleValue > qreq(search_range, qtype, query_batch_size);

        auto result_count = 0U;
        auto cmp_ind = start;

        std::vector< std::pair< TestSimpleKey, TestSimpleValue > > values;
        values.reserve(query_batch_size);

        bool has_more = false;
        do {
            auto status = test->m_bt->query(qreq, values);
            if (status == btree_status_t::has_more) {
                has_more = true;
            } else {
                has_more = false;
            }
            for (auto& val : values) {
                auto kp = test->m_entries[cmp_ind];
                ASSERT_EQ(val.first, *kp);
                ASSERT_EQ(val.second, test->m_create_map.find(kp)->second);
                ++cmp_ind;
                ++result_count;
            }
            values.clear();
        } while (has_more);

        ASSERT_EQ(count, result_count);
    }
};

TEST_F(BtreeCrudTest, SimpleInsert) {
    run_in_parallel(NTHREADS, insert_and_get_thread, 0, TOTAL_ENTRIES, 50 /* get_pct */);

    auto json = m_bt->get_metrics_in_json();
    EXPECT_EQ(json["Counters"]["Btree object count"], 0u);
    EXPECT_EQ(json["Counters"]["Btree Interior node count"], 0u);
}

TEST_F(BtreeCrudTest, SimpleQuery) {
    // Sort the entries before preload.
    std::sort(m_entries.begin(), m_entries.end(),
              [](const auto& left, const auto& right) { return (left->compare(right) < 0); });
    run_in_parallel(NTHREADS, preload_thread, 0, TOTAL_ENTRIES);
    auto json = m_bt->get_metrics_in_json();
    EXPECT_EQ(json["Counters"]["Btree object count"], TOTAL_ENTRIES);

    run_in_parallel(NTHREADS, query_thread, 0, TOTAL_ENTRIES, BtreeQueryType::SWEEP_NON_INTRUSIVE_PAGINATION_QUERY,
                    1000);
    run_in_parallel(NTHREADS, query_thread, 0, TOTAL_ENTRIES, BtreeQueryType::TREE_TRAVERSAL_QUERY, 1000);
}

SDS_OPTIONS_ENABLE(logging)

int main(int argc, char* argv[]) {
    SDS_OPTIONS_LOAD(argc, argv, logging)
    sds_logging::SetLogger("test_btree_crud");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    // setup_devices(2);
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
