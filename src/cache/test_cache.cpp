//
// Created by Kadayam, Hari on 22/04/18.
//

#include <gtest/gtest.h>
#include <glog/logging.h>
#include <boost/range/irange.hpp>
#include <boost/intrusive_ptr.hpp>
#include <cstring>
#include "cache.cpp"

struct blk_id {
    static homeds::blob get_blob(const blk_id &id) {
        homeds::blob b;
        b.bytes = (uint8_t *)&id.m_id;
        b.size = sizeof(uint64_t);

        return b;
    }

    static int compare(const blk_id &one, const blk_id &two) {
        if (one.m_id == two.m_id) {
            return 0;
        } else if (one.m_id > two.m_id) {
            return -1;
        } else {
            return 1;
        }
    }

    blk_id(uint64_t id) : m_id(id) {}
    blk_id() : blk_id(-1) {}
    blk_id(const blk_id &other) {
        m_id = other.m_id;
    }

    blk_id &operator=(const blk_id &other) {
        m_id = other.m_id;
        return *this;
    }

    std::string to_string() const {
        std::stringstream ss; ss << m_id;
        return ss.str();
    }
    uint64_t m_id;
};

#define MAX_CACHE_SIZE  2 * 1024 * 1024
#define NTHREADS 4U

struct CacheTest : public testing::Test {
protected:
    std::unique_ptr< homestore::Cache< blk_id> > m_cache;

public:
    CacheTest() {
        m_cache = std::make_unique< homestore::Cache< blk_id > >(MAX_CACHE_SIZE, 8192);
    }

    void insert_one(uint64_t id, uint32_t size) {
        boost::intrusive_ptr< homestore::CacheBuffer< blk_id > > cbuf;
        auto raw_buf = new uint64_t[size/8];
        for (auto b = 0U; b < size/8; b++) raw_buf[b] = id;
        EXPECT_EQ(m_cache->insert(blk_id(id), {(uint8_t *) raw_buf, 64}, 0, &cbuf), true);
    }

    void read_one(uint64_t id, uint32_t size, bool expected = true) {
        boost::intrusive_ptr< homestore::CacheBuffer< blk_id > > cbuf;
        bool found = m_cache->get(blk_id(id), &cbuf);
        EXPECT_EQ(found, expected);

        if (found) {
            auto blob = cbuf->at_offset(0);
            auto b = 0U;
            for (b = 0U; b < blob.size / 8; b++) if (((uint64_t *)blob.bytes)[b] != id) break;
            EXPECT_EQ(b, blob.size/8);
        }
    }

    void fixed_insert_and_get(uint64_t start, uint32_t count, uint32_t size) {
        for (auto i = start; i < start+count; i++) {
            insert_one(i, size);
            read_one(i, size);
        }
    }

    uint32_t fixed_total_entries(uint32_t size) {
        return (MAX_CACHE_SIZE * 3)/size;
    }
};

static void insert_and_get_thread(CacheTest *ctest, uint32_t tnum) {
    auto total_entries = ctest->fixed_total_entries(8192);
    ctest->fixed_insert_and_get(tnum * total_entries/NTHREADS, total_entries/NTHREADS, 8192);
}

TEST_F(CacheTest, InsertGet) {
    std::array<std::thread *, NTHREADS> thrs;
    for (auto i = 0; i < NTHREADS; i++) {
        thrs[i] = new std::thread(insert_and_get_thread, this, i);
    }

    for (auto i = 0; i < NTHREADS; i++) {
        thrs[i]->join();
    }
    LOG(INFO) << "Cache Stats: \n" << this->m_cache->get_stats().to_string();
}

INIT_VMODULES(CACHE_VMODULES);
int main(int argc, char *argv[]) {
    InithomedsLogging(argv[0], CACHE_VMODULES);

    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}