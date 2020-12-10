#include <sys/timeb.h>

#include <fds/utils.hpp>
#include <sds_logging/logging.h>
#include <sds_options/options.h>
#include "engine/common/mod_test_iface.hpp"
#include "engine/common/homestore_flip.hpp"
#include <random>

using namespace homestore;
using namespace flip;

struct indx_mgr_test_cfg {
    bool vol_create_first_cp_abort = false;
};

indx_mgr_test_cfg indx_cfg;
const uint64_t run_time_sec = 10;
const uint64_t abort_time_sec = 10;

class indx_test : public module_test {
    indx_test() : m_fc(HomeStoreFlip::instance()) {}
    virtual void run_start() override {
        // set start time
        m_start_time = Clock::now();
    }

    virtual void try_run_one_iteration() override {
        std::unique_lock< std::mutex > lk{m_mutex};
        if (indx_cfg.vol_create_first_cp_abort) { vol_create_first_cp_abort(); }
    }

    /* It simulate the crash before first cp is taken on a volume. It simulate 3 scenarios before crash
     * 1. Few IOs
     * 2. No IOs
     * 3. volume delete
     */
    void vol_create_first_cp_abort() {
        static thread_local std::random_device rd{};
        static thread_local std::default_random_engine engine{rd()};
        static thread_local std::uniform_int_distribution< uint64_t > dist{0, 10};
        if (get_elapsed_time_sec(m_start_time) > run_time_sec && !m_flip_enabled) {
            // set flip point
            FlipCondition null_cond;
            FlipFrequency freq;
            freq.set_count(1);
            freq.set_percent(100);
            m_fc.inject_noreturn_flip("vol_create_suspend_cp", {null_cond}, freq);
            m_flip_enabled = true;
            m_flip_start_time = Clock::now();
        } else if (m_flip_enabled && get_elapsed_time_sec(m_flip_start_time) > dist(engine) * abort_time_sec) {
            raise(SIGKILL);
        }
    }

protected:
    Clock::time_point m_start_time;
    Clock::time_point m_flip_start_time;
    std::mutex m_mutex;
    bool m_flip_enabled = false;
    FlipClient m_fc;
};

indx_test test;
/************************* CLI options ***************************/
SDS_OPTION_GROUP(test_indx_mgr,
                 (vol_create_first_cp_abort, "", "vol_create_first_cp_abort", "vol_create_first_cp_abort",
                  ::cxxopts::value< bool >()->default_value("false"), "true or false"))

void indx_mgr_test_main() {
    indx_cfg.vol_create_first_cp_abort = SDS_OPTIONS["vol_create_first_cp_abort"].as< bool >();
    mod_tests.push_back(&test);
    return;
}
