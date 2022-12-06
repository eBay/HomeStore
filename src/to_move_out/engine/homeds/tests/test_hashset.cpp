//
// Created by Kadayam, Hari on 24/10/17.
//

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <limits>

#include <boost/range/irange.hpp>
#include <sisl/logging/logging.h>
#include <sisl/options/options.h>
#include <sisl/utility/atomic_counter.hpp>
#include <sisl/utility/thread_buffer.hpp>

#include <benchmark/benchmark.h>

#include "homeds/hash/intrusive_hashset.hpp"

SISL_LOGGING_INIT(HOMESTORE_LOG_MODS)
RCU_REGISTER_INIT

static constexpr size_t TEST_COUNT{10000};
static constexpr size_t ITERATIONS{100};
static constexpr size_t THREADS{8};
static constexpr size_t ENTRIES_PER_BUCKET{4};

struct blk_id {
    static sisl::blob get_blob(const blk_id& id) {
        sisl::blob b;
        b.bytes = reinterpret_cast< uint8_t* >(const_cast< uint64_t* >(&id.m_id));
        b.size = sizeof(uint64_t);

        return b;
    }

    static int compare(const blk_id& one, const blk_id& two) {
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

    blk_id(const blk_id&) = delete;
    blk_id& operator=(const blk_id&) = delete;
    blk_id(blk_id&&) noexcept = delete;
    blk_id& operator=(blk_id&&) noexcept = delete;

    ~blk_id() = default;

    uint64_t m_id;
};

class blk_entry : public homeds::HashNode {
public:
    blk_entry() : m_blk_id{} { m_blk_contents.fill('0'); }

    blk_entry(const uint64_t id, const char* const contents) : m_blk_id{id} {
        std::strncpy(m_blk_contents.data(), contents, m_blk_contents.size());
        m_blk_contents[m_blk_contents.size() - 1] = '0';
    }

    blk_entry(const blk_entry&) = delete;
    blk_entry& operator=(const blk_entry&) = delete;
    blk_entry(blk_entry&&) noexcept = delete;
    blk_entry& operator=(blk_entry&&) noexcept = delete;

    ~blk_entry() = default;

    void set(const uint64_t id, const char* contents) {
        m_blk_id.m_id = id;
        std::strncpy(m_blk_contents.data(), contents, m_blk_contents.size());
        m_blk_contents[m_blk_contents.size() - 1] = '0';
    }

    static const blk_id* extract_key(const blk_entry& b) { return &b.m_blk_id; }

    static void ref(blk_entry& pe) { pe.m_ref.increment(); }

    static void deref(blk_entry& pe) {
        if (pe.m_ref.decrement_testz()) {}
    }

    static bool deref_testz(blk_entry& pe) { return pe.m_ref.decrement_testz(); }

    char* get_contents() { return m_blk_contents.data(); }

private:
    blk_id m_blk_id;
    sisl::atomic_counter< uint32_t > m_ref;
    std::array< char, 40 > m_blk_contents{};
};

static homeds::IntrusiveHashSet< blk_id, blk_entry >* glob_set;
static blk_entry** glob_entries;
static const blk_id** glob_ids;

void setup(const size_t count) {
    glob_set = new homeds::IntrusiveHashSet< blk_id, blk_entry >{static_cast< uint32_t >(count / ENTRIES_PER_BUCKET)};
    glob_entries = new blk_entry*[count];
    glob_ids = new const blk_id*[count];

    std::array< char, 40 > contents;
    for (auto i : boost::irange< size_t >(0, count)) {
        std::snprintf(contents.data(), contents.size(), "Contents for Blk %zu", i);
        glob_entries[i] = new blk_entry(static_cast< uint64_t >(i), contents.data());
        glob_ids[i] = blk_entry::extract_key(*glob_entries[i]);
    }
}

void teardown(const size_t count) {
    for (auto i : boost::irange< size_t >(0, count)) {
        delete glob_entries[i];
    }

    delete[] glob_ids;
    delete[] glob_entries;
    delete glob_set;
}

// template <class ...Args>
// void benchmarked_insert(benchmark::State& state, Args&&... args) {
void test_insert(benchmark::State& state) {
    // Actual test
    size_t iteration{0};
    for (auto cs : state) { // Loops upto iteration count
        const size_t index{static_cast< size_t >(state.thread_index())};
        for (auto i{index + iteration * state.range(0)}; i < (iteration + 1) * state.range(0);
             i += state.threads()) { // Loops for provided ranges
            blk_entry* res_entry;
            const bool ret{glob_set->insert(*glob_entries[i], &res_entry)};
        }
        ++iteration;
    }
}

void test_reads(benchmark::State& state) {
    // Actual test
    size_t iteration{0};
    for (auto cs : state) { // Loops upto iteration count
        const size_t index{static_cast< size_t >(state.thread_index())};
        for (auto i{index + iteration * state.range(0)}; i < (iteration + 1) * state.range(0);
             i += state.threads()) { // Loops for provided ranges
            blk_entry* res_entry;
            const bool ret{glob_set->get(*glob_ids[i], &res_entry)};
        }
        ++iteration;
    }
}

void test_removes(benchmark::State& state) {
    // Actual test
    size_t iteration{0};
    for (auto cs : state) { // Loops upto iteration count
        const size_t index{static_cast< size_t >(state.thread_index())};
        for (auto i{index + iteration * state.range(0)}; i < (iteration + 1) * state.range(0);
             i += state.threads()) { // Loops for provided range
            const bool ret{glob_set->remove(*glob_ids[i])};
        }
        ++iteration;
    }
}

BENCHMARK(test_insert)->Range(TEST_COUNT, TEST_COUNT)->Iterations(ITERATIONS)->Threads(THREADS);
BENCHMARK(test_reads)->Range(TEST_COUNT, TEST_COUNT)->Iterations(ITERATIONS)->Threads(THREADS);
BENCHMARK(test_removes)->Range(TEST_COUNT, TEST_COUNT)->Iterations(ITERATIONS)->Threads(THREADS);

SISL_OPTIONS_ENABLE(logging)
int main(int argc, char** argv) {
    SISL_OPTIONS_LOAD(argc, argv, logging)
    sisl::logging::SetLogger("test_hashset");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");
    setup(TEST_COUNT * ITERATIONS);
    ::benchmark::Initialize(&argc, argv);
    ::benchmark::RunSpecifiedBenchmarks();
    teardown(TEST_COUNT * ITERATIONS);

    return 0;
}
