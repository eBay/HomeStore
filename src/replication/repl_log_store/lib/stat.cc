
#include <fstream>
#include <iostream>
#include <string>

#ifdef __linux__
#include <sys/sysmacros.h>
#include <unistd.h>
#endif

#include "common.h"
#include "stat.h"

std::atomic<StatMgr*> StatMgr::instance(nullptr);
std::mutex StatMgr::instanceLock;

StatElem::StatElem(Type _type, const std::string& _name)
    : statType(_type)
    , statName(_name)
    , counter(0)
    , gauge(0)
    , hist( (_type == HISTOGRAM)
            ?(new Histogram())
            :(nullptr) ) {}

StatElem::~StatElem() {
    delete hist;
}


StatMgr::StatMgr() {
}

StatMgr::~StatMgr() {
    std::unique_lock<std::mutex> l(statMapLock);
    for (auto& entry: statMap) {
        delete entry.second;
    }
}

StatMgr* StatMgr::init() {
    StatMgr* mgr = instance.load();
    if (!mgr) {
        std::lock_guard<std::mutex> l(instanceLock);
        mgr = instance.load();
        if (!mgr) {
            mgr = new StatMgr();
            instance.store(mgr);
        }
    }
    return mgr;
}

StatMgr* StatMgr::getInstance() {
    StatMgr* mgr = instance.load();
    if (!mgr) return init();
    return mgr;
}

void StatMgr::destroy() {
    std::lock_guard<std::mutex> l(instanceLock);
    StatMgr* mgr = instance.load();
    if (mgr) {
        delete mgr;
        instance.store(nullptr);
    }
}

StatMgr::MemoryStat StatMgr::getMemoryStat() {
    MemoryStat ret;

#ifdef __linux__
    std::ifstream fs;
    std::string path = "/proc/self/statm";

    fs.open(path.c_str());
    if (!fs.good()) return ret;

    fs >> ret.virtSize >> ret.resSize >> ret.sharedSize;
    fs.close();

    uint32_t pgsize = sysconf(_SC_PAGESIZE);
    ret.virtSize *= pgsize;
    ret.resSize *= pgsize;
    ret.sharedSize *= pgsize;

#endif
    // TODO: other platforms

    return ret;
}

StatMgr::CpuStat StatMgr::getCpuStat() {
    static std::mutex last_numbers_lock;
    static GenericTimer timer;
    CpuStat ret;

#ifdef __linux__
    std::ifstream fs;
    std::string path = "/proc/self/stat";

    fs.open(path.c_str());
    if (!fs.good()) return ret;

    std::string dummy_str;
    uint64_t dummy_int;

    // 1) pid
    // 2) executable name (str)
    // 3) state (str)
    // 4) ppid
    // 5) pgrp
    // 6) session
    // 7) tty
    // 8) tpgid
    // 9) flags
    // 10) # minor page faults
    // 11) # minor page faults including children
    // 12) # major page faults
    // 13) # major page faults including children
    // 14) user time
    // 15) kernel time
    // ...

    fs >> dummy_int >> dummy_str >> dummy_str;
    fs >> dummy_int >> dummy_int >> dummy_int >> dummy_int;
    fs >> dummy_int >> dummy_int >> dummy_int >> dummy_int;
    fs >> dummy_int >> dummy_int >> ret.userTimeMs >> ret.kernelTimeMs;

    fs.close();

    // TODO: currently assuming 100Hz (10ms) jiffy.
    //       It should support all kinds of platforms.
    ret.kernelTimeMs *= 10;
    ret.userTimeMs *= 10;

#endif
    // TODO: other platforms

    {
        std::lock_guard<std::mutex> l(last_numbers_lock);
        static uint64_t last_user_time = 0;
        static uint64_t last_kernel_time = 0;
        static uint64_t last_user_millicores = 0;
        static uint64_t last_kernel_millicores = 0;

        if ( last_user_time && last_kernel_time &&
                last_user_time <= ret.userTimeMs &&
                last_kernel_time <= ret.kernelTimeMs ) {
            uint64_t time_gap_us = timer.getElapsedUs();
            // Minimum gap should be bigger than 1 second.
            if (time_gap_us >= 1000000) {
                uint64_t user_time_gap = ret.userTimeMs - last_user_time;
                uint64_t kernel_time_gap = ret.kernelTimeMs - last_kernel_time;
                ret.userMilliCores =
                    1000 * (user_time_gap * 1000) / time_gap_us;
                ret.kernelMilliCores =
                    1000 * (kernel_time_gap * 1000) / time_gap_us;

                timer.reset();
                last_user_time = ret.userTimeMs;
                last_kernel_time = ret.kernelTimeMs;
                last_user_millicores = ret.userMilliCores;
                last_kernel_millicores = ret.kernelMilliCores;

            } else {
                // If not, return the last results.
                ret.userMilliCores = last_user_millicores;
                ret.kernelMilliCores = last_kernel_millicores;
            }
        }

        if (!last_user_time || !last_kernel_time) {
            // Maybe the first call.
            timer.reset();
            last_user_time = ret.userTimeMs;
            last_kernel_time = ret.kernelTimeMs;
        }
    }

    return ret;
}

StatMgr::IoStat StatMgr::getIoStat(const std::string& path) {
    static std::mutex last_numbers_lock;
    static GenericTimer timer;
    IoStat ret;

#ifdef __linux__
    struct stat ss;
    if (stat(path.c_str(), &ss) != 0) return ret;

    std::ifstream fs;
    std::string diskstats_path = "/proc/diskstats";

    fs.open(diskstats_path.c_str());
    if (!fs.good()) return ret;

    std::string partition_name;
    uint64_t dummy_int;

    // /proc/diskstats:
    //
    // 1 - major number
    // 2 - minor mumber
    // 3 - device name
    // 4 - reads completed successfully
    // 5 - reads merged
    // 6 - sectors read
    // 7 - time spent reading (ms)
    // 8 - writes completed
    // 9 - writes merged
    // 10 - sectors written
    // 11 - time spent writing (ms)
    // 12 - I/Os currently in progress
    // 13 - time spent doing I/Os (ms)
    // 14 - weighted time spent doing I/Os (ms)
    //
    // WARNING: From kernel 4.18+, there will be 18 fields.

    uint64_t time_io_p = 0; // partition.
    uint64_t time_io_d = 0; // device.
    uint64_t time_r = 0;
    uint64_t time_w = 0;
    do {
        size_t dev_major = 0, dev_minor = 0;
        fs >> dev_major >> dev_minor;
        if ( dev_major != major(ss.st_dev) ||
                dev_minor != minor(ss.st_dev) ) {
            fs.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            continue;
        }

        fs >> partition_name;
        fs >> ret.numReads >> dummy_int >> dummy_int >> time_r;
        fs >> ret.numWrites >> dummy_int >> dummy_int >> time_w >> dummy_int;
        fs >> time_io_p;
        break;
    } while (!fs.eof());

    // Get device name from partition name.
    std::string dev_name;
    if (!partition_name.empty()) {
        dev_name = partition_name.substr(0, partition_name.size() - 1);
    }

    // Rewind.
    fs.seekg(0, fs.beg);
    do {
        size_t dev_major = 0, dev_minor = 0;
        fs >> dev_major >> dev_minor;

        std::string dummy_str;
        fs >> dummy_str;
        if (dummy_str != dev_name) {
            fs.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            continue;
        }

        fs >> dummy_int >> dummy_int >> dummy_int >> dummy_int;
        fs >> dummy_int >> dummy_int >> dummy_int >> dummy_int >> dummy_int;
        fs >> time_io_d;
        break;
    } while (!fs.eof());
    fs.close();

    FILE *fp = fopen("/proc/self/io", "r");
    while(!feof(fp)) {
        char str[64];
        unsigned long temp;
        int rr = fscanf(fp, "%s %lu", str, &temp);
        (void)rr;
        if (!strcmp(str, "rchar:")) ret.bytesRead = temp;
        if (!strcmp(str, "wchar:")) ret.bytesWritten = temp;
        if (!strcmp(str, "read_bytes:")) ret.bytesReadFromDisk = temp;
        if (!strcmp(str, "write_bytes:")) ret.bytesWrittenToDisk = temp;
    }
    fclose(fp);

    // Calculate time-based metrics.
    {
        std::lock_guard<std::mutex> l(last_numbers_lock);
        static uint64_t last_time_io_p = 0;
        static uint64_t last_time_io_d = 0;
        static uint64_t last_time_r = 0;
        static uint64_t last_time_w = 0;
        static uint64_t last_num_r = 0;
        static uint64_t last_num_w = 0;

        static uint64_t last_avg_r = 0;
        static uint64_t last_avg_w = 0;
        static uint64_t last_util_p = 0;
        static uint64_t last_util_d = 0;

        bool update_prev_stats = false;

        // Minimum gap should be bigger than 0.5 second.
        uint64_t gap_ms = timer.getElapsedMs();
        if (gap_ms >= 500) {
            last_util_p = (time_io_p >= last_time_io_p)
                          ? (time_io_p - last_time_io_p) * 1000 / gap_ms
                          : 0;
            last_util_d = (time_io_d >= last_time_io_d)
                          ? (time_io_d - last_time_io_d) * 1000 / gap_ms
                          : 0;
            last_avg_r = (time_r >= last_time_r && ret.numReads > last_num_r)
                         ? ( (time_r - last_time_r) * 1000 /
                             (ret.numReads - last_num_r) )
                         : 0;
            last_avg_w = (time_w >= last_time_w && ret.numWrites > last_num_w)
                         ? ( (time_w - last_time_w) * 1000 /
                             (ret.numWrites - last_num_w) )
                         : 0;

            update_prev_stats = true;

        } // If not, return last results.
        ret.avgRTimeUs = last_avg_r;
        ret.avgWTimeUs = last_avg_w;
        ret.partitionUtil = last_util_p;
        ret.deviceUtil = last_util_d;

        if (!last_num_r || !last_num_w) {
            // Maybe the first call, initialize.
            update_prev_stats = true;
        }

        if (update_prev_stats) {
            timer.reset();
            last_time_io_p = time_io_p;
            last_time_io_d = time_io_d;
            last_time_r = time_r;
            last_time_w = time_w;
            last_num_r = ret.numReads;
            last_num_w = ret.numWrites;
        }
    }

#endif
    return ret;
}

uint64_t StatMgr::getDiskUsage(const std::string& path) {
    if (!PathMgr::exist(path)) return 0;

    uint64_t ret = 0;

#if defined(__linux__) || defined(__APPLE__)
    ret = PathMgr::dirSize(path, false);

#endif
    // TODO: other platforms?

    return ret;
}

StatElem* StatMgr::getStat(const std::string& stat_name) {
    std::unique_lock<std::mutex> l(statMapLock);
    auto entry = statMap.find(stat_name);
    if (entry == statMap.end()) {
        // Not exist.
        return nullptr;
    }
    return entry->second;
}

StatElem* StatMgr::createStat(StatElem::Type type, const std::string& stat_name) {
    StatElem* elem = new StatElem(type, stat_name);

    std::unique_lock<std::mutex> l(statMapLock);
    auto entry = statMap.find(stat_name);
    if (entry != statMap.end()) {
        // Alraedy exist.
        delete elem;
        return entry->second;
    }
    statMap.insert( std::make_pair(stat_name, elem) );
    return elem;
}

void StatMgr::getAllStats(std::vector<StatElem*>& stats_out) {
    std::unique_lock<std::mutex> l(statMapLock);
    stats_out.resize(statMap.size());
    size_t idx = 0;
    for (auto& entry: statMap) {
        stats_out[idx++] = entry.second;
    }
}




