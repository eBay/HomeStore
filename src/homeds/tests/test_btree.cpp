/*
 * test_btree.cpp
 *
 *  Created on: 17-May-2016
 *      Author: Hari Kadayam
 */

#include <iostream>
#include <pthread.h>
#include <cstdlib>
#include <ctime>
#include <chrono>
#include <sys/timeb.h>
#include <cmath>

#include "homeds/btree/mem_btree.hpp"

using namespace std;
using namespace homeds::btree;

typedef std::chrono::high_resolution_clock Clock;

class TestEntry : public homeds::btree::BtreeKey {
private:
    typedef struct __attribute__((packed)) {
        uint64_t m_count :16;
        uint64_t m_rank :10;
        uint64_t m_blk_num :38;
    } blob_t;

    blob_t *m_blob;
    blob_t m_inplace_blob;

public:
    TestEntry(uint32_t count, uint16_t rank, uint64_t blk_num) {
        m_blob = &m_inplace_blob;
        set_count(count);
        set_rank(rank);
        set_blk_num(blk_num);
    }

    TestEntry() : TestEntry(0, 0, 0) {
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
        TestEntry *other = (TestEntry *) o;
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
        TestEntry *start = (TestEntry *) s;
        TestEntry *end = (TestEntry *) e;

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
        homeds::blob b = {(uint8_t *) m_blob, sizeof(blob_t)};
        return b;
    }

    virtual void set_blob(const homeds::blob &b) override {
        m_blob = (blob_t *) b.bytes;
    }

    virtual void copy_blob(const homeds::blob &b) override {
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

uint64_t get_elapsed_time(Clock::time_point startTime) {
    std::chrono::nanoseconds ns = std::chrono::duration_cast< std::chrono::nanoseconds >(Clock::now() - startTime);
    //return ns.count();
    return ns.count() / 1000;
}

int64_t unformat_num(const char *str) {
    int64_t val;
    char unit = ' ';

    sscanf(str, "%lld%c", &val, &unit);

    switch (unit) {

    case ' ':
        break;

    case 'G':
    case 'g':
        val *= 1000; // fallthru

    case 'M':
    case 'm':
        val *= 1000; // fallthru

    case 'K':
    case 'k':
        val *= 1000;
        break;

    case 'H':
    case 'h':
        val *= 60;

    case 'U':
    case 'u':
        val *= 60;

    case 'S':
    case 's':
        break;
    }

    return val;
}

#if 0
typedef struct {
    BtreeKVStore<TestEntry, EmptyClass> *bt;
    uint32_t start;
    uint32_t count;
    pthread_t tid;
    uint32_t myid;
    uint64_t ins_time_us;
    uint64_t read_time_us;
    uint64_t delete_time_us;
}threadarg_t;
#endif

struct WorkloadInfo {
    uint32_t start;
    uint32_t count;
    uint64_t time_us;
};

typedef struct {
    homeds::btree::Btree< TestEntry, homeds::btree::EmptyClass > *bt;
    WorkloadInfo preloadInfo;
    WorkloadInfo insertInfo;
    WorkloadInfo readInfo;

    pthread_t tid;
    uint32_t myid;
    uint32_t riRatio;
} threadarg_t;

struct BtreePerfTest {
    TestEntry **readEntries;
    TestEntry **insertEntries;
};

BtreePerfTest tst;

void init_entries(uint32_t n_read_entries, uint32_t n_insert_entries) {
    tst.readEntries = new TestEntry *[n_read_entries];
    for (auto i = 0; i < n_read_entries; i++) {
        tst.readEntries[i] = new TestEntry(rand() % 5000, i % 1000, i);
    }

    tst.insertEntries = new TestEntry *[n_insert_entries];
    for (auto i = 0; i < n_insert_entries; i++) {
        tst.insertEntries[i] = new TestEntry(rand() % 5000, i % 1000, i + n_read_entries);
    }
}

#if 0
void initDev(char *devName)
{
    DeviceManager::startInstance();
    DeviceManager *devMgr = DeviceManager::getInstance();
    devMgr->addDevice(devName);
}
#endif

void *preloadThread(void *arg) {
    threadarg_t *targ = (threadarg_t *) arg;
    homeds::btree::EmptyClass e;

    for (auto i = targ->preloadInfo.start; i < (targ->preloadInfo.start + targ->preloadInfo.count); i++) {
        TestEntry *te = tst.readEntries[i];

        Clock::time_point startTime = Clock::now();
        targ->bt->put(*te, e, INSERT_ONLY_IF_NOT_EXISTS);
        targ->preloadInfo.time_us += get_elapsed_time(startTime);

        if (((i + 1) % 1000) == 0) {
            printf("Thread %u completed %u preloads\n", targ->myid, i + 1);
            fflush(stdout);
        }
    }

    return nullptr;
}

void *readInsertThread(void *arg) {
    threadarg_t *targ = (threadarg_t *) arg;
    homeds::btree::EmptyClass e;
    uint32_t iter = 0;

    printf("Thread %u does readCount=%u insertCount=%u\n", targ->myid, targ->readInfo.count, targ->insertInfo.count);
    fflush(stdout);
    while ((targ->readInfo.count > 0) && (targ->insertInfo.count > 0)) {
        if ((rand() % 100) > targ->riRatio) {
            // It is an insert
            --(targ->insertInfo.count);
            TestEntry *te = tst.insertEntries[targ->insertInfo.start + targ->insertInfo.count];
            Clock::time_point startTime = Clock::now();
            targ->bt->put(*te, e, INSERT_ONLY_IF_NOT_EXISTS);
            targ->insertInfo.time_us += get_elapsed_time(startTime);
        } else {
            --(targ->readInfo.count);
            TestEntry *te = tst.readEntries[targ->readInfo.start + targ->readInfo.count];
            Clock::time_point startTime = Clock::now();
            bool isFound = targ->bt->get(*te, &e);
            targ->readInfo.time_us += get_elapsed_time(startTime);
            assert(isFound);
        }

        if (((++iter) % 1000) == 0) {
            printf("Thread %u completed %u reads/inserts\n", targ->myid, iter);
            fflush(stdout);
        }
    }

    while (targ->readInfo.count > 0) {
        --(targ->readInfo.count);
        TestEntry *te = tst.readEntries[targ->readInfo.start + targ->readInfo.count];
        Clock::time_point startTime = Clock::now();
        bool isFound = targ->bt->get(*te, &e);
        targ->readInfo.time_us += get_elapsed_time(startTime);
        assert(isFound);
}

    while (targ->insertInfo.count > 0) {
        --(targ->insertInfo.count);
        TestEntry *te = tst.insertEntries[targ->insertInfo.start + targ->insertInfo.count];
        Clock::time_point startTime = Clock::now();
        targ->bt->put(*te, e, INSERT_ONLY_IF_NOT_EXISTS);
        targ->insertInfo.time_us += get_elapsed_time(startTime);
    }

    return nullptr;
}

#if 0
void *trxThread(void *arg)
{
    threadarg_t *targ = (threadarg_t *)arg;
    EmptyClass e;
    TestEntry **entries = new TestEntry* [targ->count];
    uint32_t count = 0;

    for (int i = targ->start; i < (targ->start+targ->count); i++) {
        entries[count++] = new TestEntry(rand()%5000, i%1000, i);
    }

    targ->ins_time_us = 0;
    targ->read_time_us = 0;
    targ->delete_time_us = 0;
    for (int i = 0; i < targ->count; i++) {
        TestEntry *te = entries[i];

        Clock::time_point startTime = Clock::now();
        targ->bt->insert(*te, e);
        targ->ins_time_us += getElapsedTime(startTime);

        if (((i+1) % 1000) == 0) {
            printf("Thread %u completed %u inserts\n", targ->myid, i+1);
            fflush(stdout);
        }
    }

    for (int i = 0; i < targ->count; i++) {
        TestEntry *te = entries[i];
        Clock::time_point startTime = Clock::now();
        bool isFound = targ->bt->get(*te, &e);
        targ->read_time_us += getElapsedTime(startTime);
        assert(isFound);

        if (((i+1) % 1000) == 0) {
            printf("Thread %u completed %u reads\n", targ->myid, i+1);
            fflush(stdout);
        }
    }

#if 0
    for (int i = 0; i < targ->count; i++) {
        TestEntry *te = entries[i];
        Clock::time_point startTime = Clock::now();
        bool success = targ->bt->remove(*te);
        // Update and insert again.
        te->setCount(rand() % 5000);
        targ->bt->insert(*te, e);

        targ->delete_time_us += getElapsedTime(startTime);
        assert(success);

        if (((i+1) % 1000) == 0) {
            printf("Thread %u completed %u deletes\n", targ->myid, i+1);
            fflush(stdout);
        }
    }
#endif
    return NULL;
}
#endif

int main(int argc, const char *argv[]) {
    uint32_t nTotalCount = 10000000;
    int nThreads = 50;
    uint32_t nodeSize = 8192;
    uint32_t readRatio;

    uint32_t i = 0;
    while (++i < argc) {
        if (strcmp(argv[i], "-c") == 0) {
            nTotalCount = (uint32_t) unformat_num(argv[++i]);
        } else if (strcmp(argv[i], "-t") == 0) {
            nThreads = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-n") == 0) {
            nodeSize = (uint32_t) unformat_num(argv[++i]);
        } else if (strcmp(argv[i], "-r") == 0) {
            readRatio = (uint32_t) unformat_num(argv[++i]);
        } else {
            cout << "Invalid option " << argv[i] << endl;
            return 1;
        }
    }

    cout << "Testing with nTotalCount=" << nTotalCount << " nThreads=" << nThreads << " nodeSize=" << nodeSize << endl;

    uint32_t nPreloadCount = (nTotalCount * readRatio) / 100;
    uint32_t nReadCount = nPreloadCount;
    uint32_t nInsertCount = nTotalCount - nReadCount;

    init_entries(nReadCount, nInsertCount);
#if 0
    OmDBConfig cfg;
    cfg.dev.name = "/tmp/ssd_store";
    OmDB *omdb = OmDB::newInstance(cfg);
#endif

    // Initialize btree
    homeds::btree::BtreeConfig btree_cfg;
    btree_cfg.set_leaf_node_type(homeds::btree::BTREE_NODETYPE_SIMPLE);
    btree_cfg.set_interior_node_type(homeds::btree::BTREE_NODETYPE_SIMPLE);
    btree_cfg.set_max_objs(nTotalCount);
    btree_cfg.set_max_key_size(sizeof(TestEntry));
    btree_cfg.set_max_value_size(0);
    homeds::btree::MemBtree< TestEntry, EmptyClass> bt(btree_cfg);

    threadarg_t *targs = new threadarg_t[nThreads];

    cout << "Preloading amount = " << nPreloadCount << " of data first " << endl;
    uint32_t start = 0;
    for (int i = 0; i < nThreads; i++) {
        targs[i].bt = &bt;
        targs[i].preloadInfo.count = nPreloadCount / nThreads;
        targs[i].preloadInfo.start = start;
        targs[i].myid = i + 1;
        targs[i].riRatio = 0;
        targs[i].preloadInfo.time_us = 0;
        pthread_create(&targs[i].tid, NULL, preloadThread, (void *) &targs[i]);

        start += targs[i].preloadInfo.count;
    }

    uint64_t total_preload_time_us = 0;
    for (int i = 0; i < nThreads; i++) {
        pthread_join(targs[i].tid, NULL);
        total_preload_time_us += targs[i].preloadInfo.time_us;
    }

    cout << "Completed " << nPreloadCount << " preloads in " << total_preload_time_us / nThreads << " microseconds"
         << endl;
    cout << "Starting Read/Insert test with insertCount = " << nInsertCount << " readCount = " << nReadCount << endl;
    uint32_t insert_start = 0;
    uint32_t read_start = 0;
    for (int i = 0; i < nThreads; i++) {
        targs[i].bt = &bt;
        targs[i].readInfo.count = nReadCount / nThreads;
        targs[i].readInfo.start = read_start;
        targs[i].readInfo.time_us = 0;

        targs[i].insertInfo.count = nInsertCount / nThreads;
        targs[i].insertInfo.start = insert_start;
        targs[i].insertInfo.time_us = 0;

        targs[i].myid = i + 1;
        targs[i].riRatio = readRatio;

        pthread_create(&targs[i].tid, NULL, readInsertThread, (void *) &targs[i]);
        insert_start += targs[i].insertInfo.count;
        read_start += targs[i].readInfo.count;
    }

    uint64_t total_insert_time_us = 0;
    uint64_t total_read_time_us = 0;
//	uint64_t total_delete_time_us = 0;
    for (int i = 0; i < nThreads; i++) {
        pthread_join(targs[i].tid, NULL);

        total_insert_time_us += targs[i].insertInfo.time_us;
        total_read_time_us += targs[i].readInfo.time_us;
        //	total_delete_time_us += targs[i].delete_time_us;
    }

    cout << "Completed " << nPreloadCount << " preloads in " << total_preload_time_us / nThreads << " microseconds"
         << endl;
    cout << "Completed " << nInsertCount << " inserts during read in " << total_insert_time_us / nThreads
         << " microseconds" << endl;
    cout << "Completed " << nReadCount << " reads during inserts in " << total_read_time_us / nThreads
         << " microseconds" << endl;
//	cout << "Completed " << nTotalCount << " deletes in " << total_delete_time_us/nThreads << " microseconds" << endl;

    double avgSecs = total_preload_time_us / nThreads / 1000000;
    double tps = nPreloadCount / avgSecs;
    cout << "Preload TPS = " << tps << endl;

    avgSecs = total_insert_time_us / nThreads / 1000000;
    tps = nInsertCount / avgSecs;
    cout << "Insert during read TPS = " << tps << endl;

    avgSecs = total_read_time_us / nThreads / 1000000;
    tps = nReadCount / avgSecs;
    cout << "Read during insert TPS = " << tps << endl;

#if 0
    avgSecs = total_delete_time_us/nThreads/1000000;
    tps = nTotalCount/avgSecs;
    cout << "Delete TPS = " << tps << endl;
#endif

    return 0;
}
