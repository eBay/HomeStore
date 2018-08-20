#pragma once

#include <metrics.hpp>
#include <map>

namespace homestore {
/* Singleton for Peformance Metrics */
class PerfMetrics {
public:
    static PerfMetrics *getInstance();

    void registerCounter(   std::string name,
                            std::string desc,
                            std::string sub_type    ) {
        if(m_metrics_map->find(name) != m_metrics_map->end()) return;
        (*m_metrics_map)[name] = m_perf_report->registerCounter(name, desc, "", 0);
    }

    bool incrCounter( std:: string name, int64_t value ) {
        if (m_metrics_map->find(name) == m_metrics_map->end()) return false;
        auto addr = m_perf_report->getCounter( (*m_metrics_map)[name] );
        addr->increment(value);
        return true;
    }

    bool decrCounter( std:: string name, int64_t value ) {
        if (m_metrics_map->find(name) == m_metrics_map->end()) return false;
        auto addr = m_perf_report->getCounter( (*m_metrics_map)[name] );
        addr->decrement(value);
        return true;
    }

    void registerHistogram( std::string name,
                            std::string desc,
                            std::string sub_type    ) {
        if(m_metrics_map->find(name) != m_metrics_map->end()) return;
        (*m_metrics_map)[name] = m_perf_report->registerHistogram(name, desc, "");
    }

    bool updateHistogram( std:: string name, int64_t value ) {
        if(m_metrics_map->find(name) == m_metrics_map->end()) return false;
        auto addr = m_perf_report->getHistogram( (*m_metrics_map)[name] );
        addr->update(value);
        return true;
    }

    std::string report() {
        m_perf_report->gather();
        return m_perf_report->getJSON();
    }

private:
    PerfMetrics() :
            m_perf_report(new metrics::ReportMetrics()),
            m_metrics_map(new std::map<std::string, uint64_t>()) {}

    static PerfMetrics *instance;
    metrics::ReportMetrics *m_perf_report;
    std::map<std::string, uint64_t> *m_metrics_map;
};
}
