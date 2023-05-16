#pragma once

#include <atomic>
#include <map>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "histogram.h"
#include "latency_collector.h"

// Note: accessing a StatElem instance using multiple threads is safe.
class StatElem {
public:
    enum Type {
        COUNTER = 0,
        HISTOGRAM = 1,
        GAUGE = 2,
    };

    StatElem(Type _type, const std::string& _name);
    ~StatElem();

    inline void inc(size_t amount = 1) {
        assert(statType == COUNTER);
        counter.fetch_add(amount);
    }

    inline void addLatency(uint64_t us) {
        assert(statType == HISTOGRAM);
        hist->add(us);
    }
    inline void addVal(uint64_t val) { addLatency(val); }

    inline void set(int64_t value) {
        assert(statType != HISTOGRAM);
        if (statType == COUNTER) {
            counter.store(value);
        } else {
            gauge.store(value);
        }
    }

    StatElem& operator+=(size_t amount) {
        switch (statType) {
        case COUNTER:
            inc(amount);
            break;
        case HISTOGRAM:
            addLatency(amount);
            break;
        case GAUGE:
            assert(0);
            break;
        default:
            break;
        }
        return *this;
    }
    StatElem& operator++() {
        inc();
        return *this;
    }
    StatElem& operator=(size_t val) {
        set(val);
        return *this;
    }

    const std::string& getName() const { return statName; }
    Type getType() const { return statType; }
    uint64_t getCounter() const { return counter; }
    int64_t getGauge() const { return gauge; }
    Histogram* getHistogram() const { return hist; }

private:
    Type statType;
    std::string statName;
    std::atomic< uint64_t > counter;
    std::atomic< int64_t > gauge;
    Histogram* hist;
};

// Singleton class
class StatMgr {
public:
    struct MemoryStat {
        MemoryStat() : virtSize(0), resSize(0), sharedSize(0) {}
        uint64_t virtSize;
        uint64_t resSize;
        uint64_t sharedSize;
    };

    struct CpuStat {
        CpuStat() : userTimeMs(0), kernelTimeMs(0), userMilliCores(0), kernelMilliCores(0) {}
        uint64_t userTimeMs;
        uint64_t kernelTimeMs;

        // CPU usage (num cores) * 1000.
        // i.e., 1000 == 100% CPU usage.
        uint64_t userMilliCores;
        uint64_t kernelMilliCores;
    };

    struct IoStat {
        IoStat() :
                bytesRead(0),
                bytesReadFromDisk(0),
                bytesWritten(0),
                bytesWrittenToDisk(0),
                numReads(0),
                numWrites(0),
                avgRTimeUs(0),
                avgWTimeUs(0),
                partitionUtil(0),
                deviceUtil(0) {}
        uint64_t bytesRead;
        uint64_t bytesReadFromDisk;
        uint64_t bytesWritten;
        uint64_t bytesWrittenToDisk;
        uint64_t numReads;
        uint64_t numWrites;
        uint64_t avgRTimeUs;
        uint64_t avgWTimeUs;

        // Utiliazation of the partition. 1000 == 100%.
        uint64_t partitionUtil;

        // Utiliazation of the entire device. 1000 == 100%.
        uint64_t deviceUtil;
    };

    static StatMgr* init();
    static StatMgr* getInstance();
    static void destroy();

    static MemoryStat getMemoryStat();
    static CpuStat getCpuStat();
    static IoStat getIoStat(const std::string& path);
    static uint64_t getDiskUsage(const std::string& path);

    StatElem* getStat(const std::string& stat_name);
    StatElem* createStat(StatElem::Type type, const std::string& stat_name);
    void getAllStats(std::vector< StatElem* >& stats_out);

private:
    static std::mutex instanceLock;
    static std::atomic< StatMgr* > instance;

    StatMgr();
    ~StatMgr();

    std::mutex statMapLock;
    std::map< std::string, StatElem* > statMap;
};
