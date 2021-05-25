//
// Created by Kadayam, Hari on 22/04/18.
//

#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <boost/intrusive_ptr.hpp>
#include <sds_logging/logging.h>
#include <sds_options/options.h>

#include <gtest/gtest.h>

#include "cache.h"

SDS_LOGGING_INIT(HOMESTORE_LOG_MODS)
THREAD_BUFFER_INIT
RCU_REGISTER_INIT

struct blk_id {
    [[nodiscard]] static int compare(const blk_id& one, const blk_id& two) {
        if (one.m_id == two.m_id) {
            return 0;
        } else if (one.m_id > two.m_id) {
            return -1;
        } else {
            return 1;
        }
    }

    blk_id(const uint64_t id) : m_id{id} {}
    blk_id() : blk_id{std::numeric_limits< uint64_t >::max()} {}
    blk_id(const blk_id& other) { m_id = other.m_id; }

    blk_id& operator=(const blk_id& other) {
        m_id = other.m_id;
        return *this;
    }

    [[nodiscard]] std::string to_string() const {
        std::ostringstream ss;
        ss << m_id;
        return ss.str();
    }
    uint64_t m_id;
};

namespace std {
template <>
struct hash< blk_id > {
    typedef blk_id argument_type;
    typedef size_t result_type;
    [[nodiscard]] result_type operator()(const argument_type& bid) const noexcept {
        return std::hash< uint64_t >()(bid.m_id);
    }
};
} // namespace std

static constexpr uint64_t MAX_CACHE_SIZE{static_cast< uint64_t >(2) * 1024 * 1024};
static constexpr size_t NTHREADS{1};

struct CacheTest : public ::testing::Test {
protected:
    typedef homestore::Cache< blk_id, homestore::CacheBuffer<blk_id> > CacheType; 
    std::unique_ptr< CacheType > m_cache;

public:
    CacheTest() : m_cache{std::make_unique< CacheType >(MAX_CACHE_SIZE, 8192)} {}
    CacheTest(const CacheTest&) = delete;
    CacheTest(CacheTest&&) noexcept = delete;
    CacheTest& operator=(const CacheTest&) = delete;
    CacheTest& operator=(CacheTest&&) noexcept = delete;

    virtual ~CacheTest() override { m_cache.reset(); }

    virtual void SetUp() override{};

    virtual void TearDown() override{};

    [[nodiscard]] bool insert_one(const uint64_t id, const uint32_t size) {
        boost::intrusive_ptr< homestore::CacheBuffer< blk_id > > cbuf;
        const size_t num_entries{size / sizeof(uint64_t)};
        // this must be a std::malloc since the pointer is managed by the cache and later erased with std::free
        uint64_t* const raw_buf{static_cast<uint64_t*>(std::malloc(sizeof(uint64_t) * num_entries))};
        for (size_t b{0}; b < num_entries; ++b) {
            raw_buf[b] = id;
        }
        const sisl::blob raw_buf_blob{reinterpret_cast< uint8_t* >(raw_buf), size};
        const bool insert{m_cache->insert(blk_id{id}, raw_buf_blob, 0, &cbuf)};
        assert(insert);
        EXPECT_TRUE(insert) << "blk_id: " << id << " failed";
        return insert;
    }

    [[nodiscard]] bool read_one(const uint64_t id, const uint32_t size, const bool expected = true) {
        boost::intrusive_ptr< homestore::CacheBuffer< blk_id > > cbuf;
        const bool found{m_cache->get(blk_id{id}, &cbuf)};
        EXPECT_TRUE(found) << "blk_id: " << id << " not found";
        bool failed{false};

        if (found) {
            const auto blob{cbuf->at_offset(0)};
            const auto* const data{reinterpret_cast< const uint64_t* >(blob.bytes)};
            const size_t num_entries{size / sizeof(uint64_t)};
            for (size_t entry{0}; entry < num_entries; ++entry) {
                if (data[entry] != id) {
                    assert(data[entry] == id);
                    EXPECT_EQ(data[entry], id) << "blk_id: " << id << " failure";
                    failed = true;
                }
            }
        }

        return found && !failed;
    }

    void erase_one(const uint64_t id, const uint32_t size) {
        boost::intrusive_ptr< homestore::CacheBuffer< blk_id > > cbuf;
        m_cache->erase(blk_id{id}, &cbuf);
    }

    void fixed_insert_and_get(const uint64_t start, const uint32_t count, const uint32_t size) {
        for (auto i{start}; i < start + count; ++i) {
            if (insert_one(i, size)) {
                [[maybe_unused]] const bool result{read_one(i, size)};
            }
        }

        for (auto i{start}; i < start + count; ++i) {
            erase_one(i, size);
        }
    }

    [[nodiscard]] static uint32_t fixed_total_entries(const uint32_t size) { return (MAX_CACHE_SIZE * 3) / size; }
};

static void insert_and_get_thread(CacheTest* const ctest, const uint32_t tnum) {
    const auto total_entries{ctest->fixed_total_entries(8192)};
    ctest->fixed_insert_and_get(tnum * total_entries / NTHREADS, total_entries / NTHREADS, 8192);
}

TEST_F(CacheTest, InsertGet) {
    std::vector< std::thread> thrs;
    for (size_t i{0}; i < NTHREADS; ++i) {
        thrs.emplace_back(insert_and_get_thread, this, i);
    }

    for (size_t i{0}; i < NTHREADS; ++i) {
        if (thrs[i].joinable()) thrs[i].join();
    }
}

SDS_OPTIONS_ENABLE(logging)

int main(int argc, char* argv[]) {
    SDS_OPTIONS_LOAD(argc, argv, logging)
    ::testing::InitGoogleTest(&argc, argv);
    sds_logging::SetLogger("test_cache");
    sds_logging::install_crash_handler();
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");
    const int result{RUN_ALL_TESTS()};
    return result;
}
