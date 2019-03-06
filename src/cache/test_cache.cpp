//
// Created by Kadayam, Hari on 22/04/18.
//

#include <gtest/gtest.h>
#include <sds_logging/logging.h>
#include <sds_options/options.h>
#include <boost/range/irange.hpp>
#include <boost/intrusive_ptr.hpp>
#include <cstring>
#include "cache.cpp"

SDS_LOGGING_INIT(cache_vmod_evict, cache_vmod_write);
THREAD_BUFFER_INIT;

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

    ~CacheTest() {
        m_cache.reset();
    }

    void insert_one(uint64_t id, uint32_t size) {
        boost::intrusive_ptr< homestore::CacheBuffer< blk_id > > cbuf;
        uint64_t * raw_buf = (uint64_t *)malloc(sizeof(uint64_t) * size);
        for (auto b = 0U; b < size; b++) raw_buf[b] = id;
        EXPECT_EQ(m_cache->insert(blk_id(id), {(uint8_t *) raw_buf, size}, 0, &cbuf), true);
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

    // Fix Sanitizer reported memory leak.
    void erase_one(uint64_t id, uint32_t size) {
        boost::intrusive_ptr< homestore::CacheBuffer< blk_id > > cbuf;
        m_cache->erase(blk_id(id), &cbuf);
    }

    void fixed_insert_and_get(uint64_t start, uint32_t count, uint32_t size) {
        for (auto i = start; i < start+count; i++) {
            insert_one(i, size);
            read_one(i, size);
        }

        for (auto i = start; i < start+count; i++) {
            erase_one(i, size);
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
    for (auto i = 0u; i < NTHREADS; i++) {
        thrs[i] = new std::thread(insert_and_get_thread, this, i);
    }

    for (auto i = 0u; i < NTHREADS; i++) {
        thrs[i]->join();
    }
    
    for (auto i = 0u; i < NTHREADS; i++) {
        delete (thrs[i]);
    }
}

SDS_OPTIONS_ENABLE(logging)

int main(int argc, char *argv[]) {
    SDS_OPTIONS_LOAD(argc, argv, logging)
    testing::InitGoogleTest(&argc, argv);
    sds_logging::SetLogger("test_cache");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");
    return RUN_ALL_TESTS();
}
