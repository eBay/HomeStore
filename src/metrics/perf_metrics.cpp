

//
// Created by Gupta,Sounak in Sept 2018
//

#include "perf_metrics.hpp"

using namespace homestore;

CREATE_REPORT;
THREAD_BUFFER_INIT;
RCU_REGISTER_INIT;

PerfMetrics* PerfMetrics::instance = nullptr;
std::once_flag init_flag;
PerfMetrics* PerfMetrics::getInstance() {
    std::call_once(init_flag, [](){ instance = new PerfMetrics(); });
    return instance;
}

PerfMetrics::PerfMetrics() {
    for (auto i = 0U; i < MAX_CNTR_CNT; i++) {
        REPORT.registerCounter( metrics_cntrs[i][0],
                                metrics_cntrs[i][1],
                                metrics_cntrs[i][2] );
    }
    for (auto i = 0U; i < MAX_HIST_CNT; i++) {
        REPORT.registerHistogram(   metrics_hists[i][0],
                                    metrics_hists[i][1],
                                    metrics_hists[i][2] );
    }
}

void PerfMetrics::incrCntr(e_cntr c, int64_t value) {
    REPORT.getCounter(c)->increment(value);
}

void PerfMetrics::decrCntr(e_cntr c, int64_t value) {
    REPORT.getCounter(c)->decrement(value);
}

void PerfMetrics::updateHist(e_hist h, int64_t value) {
    REPORT.getHistogram(h)->update(value);
}

std::string PerfMetrics::report() {
    return REPORT.gather()->getJSON();
}
