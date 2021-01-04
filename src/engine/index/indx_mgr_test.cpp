#include <sys/timeb.h>

#include <fds/utils.hpp>
#include <sds_logging/logging.h>
#include <sds_options/options.h>
#include "engine/common/mod_test_iface.hpp"
#include "engine/common/homestore_flip.hpp"
#include <random>
#include "common/homestore_config.hpp"

using namespace homestore;
using namespace flip;

struct indx_mgr_test_cfg {

    bool indx_create_first_cp_abort = false;
    bool indx_del_partial_free_data_blks_after_meta_write = false;
    bool indx_del_partial_free_data_blks_before_meta_write = false;
    bool indx_del_partial_free_indx_blks = false;
    bool indx_del_free_blks_completed = false;
    uint32_t free_blk_cnt = 0;
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
        if (indx_cfg.indx_create_first_cp_abort) { indx_create_first_cp_abort(); }
        if (indx_cfg.indx_del_partial_free_data_blks_after_meta_write) {
            indx_del_partial_free_data_blks_after_meta_write();
        }
        if (indx_cfg.indx_del_partial_free_data_blks_before_meta_write) {
            indx_del_partial_free_data_blks_before_meta_write();
        }
        if (indx_cfg.indx_del_partial_free_indx_blks) { indx_del_partial_free_indx_blks(); }
        if (indx_cfg.indx_del_free_blks_completed) { indx_del_free_blks_completed(); }
        if (indx_cfg.free_blk_cnt) {
            HS_SETTINGS_FACTORY().modifiable_settings(
                [](auto& s) { s.resource_limits.free_blk_cnt = indx_cfg.free_blk_cnt; });
            HS_SETTINGS_FACTORY().save();
        }
    }

    /* It simulate the crash before first cp is taken on a index. It simulate 3 scenarios before crash
     * 1. Few IOs
     * 2. No IOs
     * 3. index delete
     */
    void indx_create_first_cp_abort() {

        static thread_local std::random_device rd{};
        static thread_local std::default_random_engine engine{rd()};
        static thread_local std::uniform_int_distribution< uint64_t > dist{0, 10};
        if (get_elapsed_time_sec(m_start_time) > run_time_sec && !m_flip_enabled) {
            // set flip point
            FlipCondition null_cond;
            FlipFrequency freq;
            freq.set_count(1);
            freq.set_percent(100);
            m_fc.inject_noreturn_flip("indx_create_suspend_cp", {null_cond}, freq);

            m_flip_enabled = true;
            m_flip_start_time = Clock::now();
        } else if (m_flip_enabled && get_elapsed_time_sec(m_flip_start_time) > dist(engine) * abort_time_sec) {
            raise(SIGKILL);
        }
    }

    void indx_del_partial_free_data_blks_after_meta_write() {
        // set flip point
        FlipCondition null_cond;
        FlipFrequency freq;
        freq.set_count(1);
        freq.set_percent(100);
        m_fc.inject_noreturn_flip("indx_del_partial_free_data_blks_after_meta_write", {null_cond}, freq);
    }

    void indx_del_partial_free_data_blks_before_meta_write() {
        // set flip point
        FlipCondition null_cond;
        FlipFrequency freq;
        freq.set_count(1);
        freq.set_percent(100);
        m_fc.inject_noreturn_flip("indx_del_partial_free_data_blks_before_meta_write", {null_cond}, freq);
    }

    void indx_del_partial_free_indx_blks() {
        // set flip point
        FlipCondition null_cond;
        FlipFrequency freq;
        freq.set_count(1);
        freq.set_percent(100);
        m_fc.inject_noreturn_flip("indx_del_partial_free_indx_blks", {null_cond}, freq);
    }

    void indx_del_free_blks_completed() {
        // set flip point
        FlipCondition null_cond;
        FlipFrequency freq;
        freq.set_count(1);
        freq.set_percent(100);
        m_fc.inject_noreturn_flip("indx_del_free_blks_completed", {null_cond}, freq);
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
SDS_OPTION_GROUP(
    test_indx_mgr,
    (indx_create_first_cp_abort, "", "indx_create_first_cp_abort", "indx_create_first_cp_abort",
     ::cxxopts::value< bool >()->default_value("false"), "true or false"),
    (indx_del_free_blks_completed, "", "indx_del_free_blks_completed", "indx_del_free_blks_completed",
     ::cxxopts::value< bool >()->default_value("false"), "true or false"),
    (indx_del_partial_free_indx_blks, "", "indx_del_partial_free_indx_blks", "indx_del_partial_free_indx_blks",
     ::cxxopts::value< bool >()->default_value("false"), "true or false"),
    (indx_del_partial_free_data_blks_after_meta_write, "", "indx_del_partial_free_data_blks_after_meta_write",
     "indx_del_partial_free_data_blks_after_meta_write", ::cxxopts::value< bool >()->default_value("false"),
     "true or false"),
    (indx_del_partial_free_data_blks_before_meta_write, "", "indx_del_partial_free_data_blks_before_meta_write",
     "indx_del_partial_free_data_blks_before_meta_write", ::cxxopts::value< bool >()->default_value("false"),
     "true or false"),
    (free_blk_cnt, "", "free_blk_cnt", "free_blk_cnt", ::cxxopts::value< uint32_t >()->default_value("0"), ""))

void indx_mgr_test_main() {
    indx_cfg.indx_create_first_cp_abort = SDS_OPTIONS["indx_create_first_cp_abort"].as< bool >();
    indx_cfg.indx_del_free_blks_completed = SDS_OPTIONS["indx_del_free_blks_completed"].as< bool >();
    indx_cfg.indx_del_partial_free_indx_blks = SDS_OPTIONS["indx_del_partial_free_indx_blks"].as< bool >();
    indx_cfg.indx_del_partial_free_data_blks_after_meta_write =
        SDS_OPTIONS["indx_del_partial_free_data_blks_after_meta_write"].as< bool >();
    indx_cfg.indx_del_partial_free_data_blks_before_meta_write =
        SDS_OPTIONS["indx_del_partial_free_data_blks_before_meta_write"].as< bool >();
    indx_cfg.free_blk_cnt = SDS_OPTIONS["free_blk_cnt"].as< uint32_t >();

    mod_tests.push_back(&test);
    return;
}
