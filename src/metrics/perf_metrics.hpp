#pragma once

#include <metrics.hpp>

namespace homestore {

/* HomeStore Metrics - Histograms */
enum e_hist {
    VOL_READ_H,
    VOL_WRITE_H,
    VOL_MAP_READ_H,
    VOL_IO_READ_H,
    VOL_IO_WRITE_H,
    VOL_BLK_ALLOC_H,
    BLKSTR_CACHE_READS_H,
    BLKSTR_CACHE_WRITES_H,
    BLKSTR_WRITES_H,
    VDEV_PHYSICAL_H,
    MAX_HIST_CNT
};

/* HomeStore Metrics - Counters */
enum e_cntr {
    BLKSTR_READS_C,
    BLKSTR_WRITES_C,
    BLKSTR_CACHE_HITS_C,
    MAX_CNTR_CNT
};

/* Singleton for Peformance Metrics */
class PerfMetrics {
public:
    static PerfMetrics* getInstance();
    void incrCntr(e_cntr c, int64_t value);
    void decrCntr(e_cntr c, int64_t value);
    void updateHist(e_hist h, int64_t value);
    std::string report();

private:
    PerfMetrics();
    static PerfMetrics *instance;

    std::string metrics_hists[MAX_HIST_CNT][3] = {
        {"Vol-Reads"        , " for HS Volume"  , ""},
        {"Vol-Writes"       , " for HS Volume"  , ""},
        {"Vol-Map-Reads"    , " for HS Volume"  , ""},
        {"Vol-IO-Reads"     , " for HS Volume"  , ""},
        {"Vol-IO-Writes"    , " for HS Volume"  , ""},
        {"Vol-Blk-Allocs"   , " for HS Volume"  , ""},
        {"BlkS-Cache-Reads" , " for HS BlkStore", ""},
        {"BlkS-Cache-Writes", " for HS BlkStore", ""},
        {"BlkS-Writes"      , " for HS BlkStore", ""},
        {"VDev-Physical"    , " for HS Virtual Device", ""}
    };

    std::string metrics_cntrs[MAX_CNTR_CNT][3] = {
        {"BlkS-Blk-Reads"   , " for HS BlkStore", ""},
        {"BlkS-Blk-Writes"  , " for HS BlkStore", ""},
        {"BlkS-Cache-Hits"  , " for HS BlkStore", ""}
    };
};
}
