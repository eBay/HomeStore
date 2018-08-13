//
// Created by Kadayam, Hari on 24/10/17.
//

#include <iostream>
#include "homeds/hash/intrusive_hashset.hpp"
#include "homeds/utility/atomic_counter.hpp"
#include <sds_logging/logging.h>
#include <benchmark/benchmark.h>
#include <boost/range/irange.hpp>

SDS_LOGGING_INIT()

using namespace std;

#define TEST_COUNT         10000U
#define ITERATIONS         100U
#define THREADS            8U
#define ENTRIES_PER_BUCKET 4

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
    uint64_t m_id;
};

class blk_entry : public homeds::HashNode
{
public:
    blk_entry() : m_blk_id((uint64_t)-1) {
    }

    blk_entry(uint64_t id, char *contents) : m_blk_id(id) {
        strcpy((char *)m_blk_contents, contents);
    }

    void set(uint64_t id, char *contents) {
        m_blk_id.m_id = id;
        strcpy((char *)m_blk_contents, contents);
    }

    static const blk_id *extract_key(const blk_entry &b) {
        return &b.m_blk_id;
    }

    static void ref(blk_entry &pe) {
        pe.m_ref.increment();
    }

    static bool deref_testz(blk_entry &pe) {
        return pe.m_ref.decrement_testz();
    }

    char *get_contents() {
        return m_blk_contents;
    }

private:
    blk_id m_blk_id;
    homeds::atomic_counter< uint32_t > m_ref;
    char m_blk_contents[32];
};

homeds::IntrusiveHashSet<blk_id, blk_entry> *glob_set;
blk_entry **glob_entries;
const blk_id **glob_ids;

void setup(int count) {
    glob_set = new homeds::IntrusiveHashSet<blk_id, blk_entry>(count/ENTRIES_PER_BUCKET);
    glob_entries = new blk_entry*[count];
    glob_ids =  new const blk_id*[count];

    for (auto i : boost::irange(0, count)) {
        char contents[32];
        sprintf(contents, "Contents for Blk %d", i);
        glob_entries[i] = new blk_entry((uint64_t)i, contents);
        glob_ids[i] = blk_entry::extract_key((const blk_entry &)glob_entries[i]);
    }
}

//template <class ...Args>
//void benchmarked_insert(benchmark::State& state, Args&&... args) {
void test_insert(benchmark::State& state) {
    // Actual test
    for (auto _ : state) { // Loops upto iteration count
        auto index = state.thread_index;
        for (auto i = 0U; i < state.range(0); i++) { // Loops for provided ranges
            blk_entry *res_entry;
            bool ret = glob_set->insert(*glob_entries[index], &res_entry);
            index += state.threads;
        }
    }
}

void test_reads(benchmark::State& state) {
    // Actual test
    for (auto _ : state) { // Loops upto iteration count
        auto index = state.thread_index;
        for (auto i = 0U; i < state.range(0); i++) { // Loops for provided ranges
            blk_entry *res_entry;
            bool ret = glob_set->get(*glob_ids[index], &res_entry);
            index += state.threads;
        }
    }
}

#if 0
void insert_thread(homeds::IntrusiveHashSet<BlkId, blk_entry> *set, uint64_t start, uint64_t count)
{
    for (auto i = start; i < start + count; i++) {
        char contents[32];
        sprintf(contents, "Contents for Blk %llu", i);

        auto *be = new blk_entry(i, contents);
        blk_entry *res_entry;

        bool ret = set->insert(*be, &res_entry);
        assert(ret);

        const BlkId *bid = blk_entry::extract_key(be);
        ret = set->get(*bid, &res_entry);
        LOG(INFO) << "Inserted id=" << i << " Content read = " << res_entry->get_contents() << " \n";
    }
}

int main(int argc, char** argv)
{
    std::thread *thrs[8];

    homeds::IntrusiveHashSet<BlkId, blk_entry> set(8000);

    uint64_t count = 1000;
    int nthrs = 1;
    for (auto i = 0; i < nthrs; i++) {
        thrs[i] = new std::thread(insert_thread, &set, i * count, count);
    }

    for (auto i = 0; i < nthrs; i++) {
        thrs[i]->join();
    }
}
#endif

BENCHMARK(test_insert)->Range(TEST_COUNT, TEST_COUNT)->Iterations(ITERATIONS)->Threads(THREADS);
BENCHMARK(test_reads)->Range(TEST_COUNT, TEST_COUNT)->Iterations(ITERATIONS)->Threads(THREADS);

SDS_OPTIONS_ENABLE(logging)
int main(int argc, char** argv)
{
    SDS_OPTIONS_LOAD(argc, argv, logging)
    sds_logging::SetLogger("test_hashset");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");
    setup(TEST_COUNT * THREADS);
    ::benchmark::Initialize(&argc, argv);
    ::benchmark::RunSpecifiedBenchmarks();
}
