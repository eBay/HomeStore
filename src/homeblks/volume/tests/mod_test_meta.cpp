#include <random>
#include <cstdint>
#include <mutex>
#include <memory>
#include <sys/timeb.h>
#include <fds/buffer.hpp>
#include <sds_logging/logging.h>
#include <sds_options/options.h>
#include "engine/common/mod_test_iface.hpp"
#include "engine/common/homestore_flip.hpp"
#include "engine/common/homestore_config.hpp"
#include "api/meta_interface.hpp"

using namespace homestore;
using namespace flip;

// TODO: make it under mode_test namespace

struct mod_test_meta_cfg {
    bool write_sb_abort{false};       //
    bool write_with_ovf_abort{false}; //
    bool remove_sb_abort{false};      //
    bool update_sb_abort{false};
    bool abort_before_recover_cb_sent{false}; //
    bool abort_after_recover_cb_sent{false};  //
};

mod_test_meta_cfg meta_cfg;

static constexpr uint64_t run_time_sec = 10;
static constexpr uint64_t abort_time_sec = 10;

// #define GET_VARIABLE_NAME(Variable) (#Variable)

class mod_test_meta : public module_test {
    mod_test_meta() : m_fc(HomeStoreFlip::instance()) {}

    virtual void run_start() override {
        // set start time
        m_start_time = Clock::now();
    }

    virtual void try_run_last_iteration() override { std::unique_lock< std::mutex > lk{m_mutex}; }

    virtual void try_run_one_iteration() override { std::unique_lock< std::mutex > lk{m_mutex}; }

    virtual void try_init_iteration() override {
        std::unique_lock< std::mutex > lk{m_mutex};
        //
        // set percent to 1 to allow volume creation complete and abort later.
        //
        // TODO: assert in vol_gtest about mounted number of vols needs to be changed to be more smart by
        // checking whether volume creation finished successfuly (vs. hit abort), instead of just by checking on
        // disk files, e.g. it creates files before sending create volume to homestore which can hit flip abort;
        //
        if (meta_cfg.write_sb_abort) { set_flip("write_sb_abort", 1, 1); }
        if (meta_cfg.write_with_ovf_abort) { set_flip("write_with_ovf_abort", 1, 1); }
        if (meta_cfg.update_sb_abort) { set_flip("update_sb_abort", 1, 1); }
        if (meta_cfg.remove_sb_abort) { set_flip("remove_sb_abort", 1, 100); }
        if (meta_cfg.abort_before_recover_cb_sent) { set_flip("abort_before_recover_cb_sent", 1, 100); }
        if (meta_cfg.abort_after_recover_cb_sent) { set_flip("abort_after_recover_cb_sent", 1, 100); }
    }

    void set_flip(const std::string& flip_name, const uint32_t count, const uint32_t percent) {
        // set flip point
        FlipCondition null_cond;
        FlipFrequency freq;
        freq.set_count(count);
        freq.set_percent(percent);
        m_fc.inject_noreturn_flip(flip_name, {null_cond}, freq);
    }

protected:
    Clock::time_point m_start_time;
    Clock::time_point m_flip_start_time;
    std::mutex m_mutex;
    bool m_flip_enabled = false;
    FlipClient m_fc;
};

mod_test_meta meta_test;

/************************* CLI options ***************************/
SDS_OPTION_GROUP(test_meta_mod,
                 (write_sb_abort, "", "write_sb_abort", "write_sb_abort",
                  ::cxxopts::value< bool >()->default_value("0"), "true or false"),
                 (write_with_ovf_abort, "", "write_with_ovf_abort", "write_with_ovf_abort",
                  ::cxxopts::value< bool >()->default_value("0"), "true or false"),
                 (update_sb_abort, "", "update_sb_abort", "update_sb_abort",
                  ::cxxopts::value< bool >()->default_value("0"), "true or false"),
                 (remove_sb_abort, "", "remove_sb_abort", "remove_sb_abort",
                  ::cxxopts::value< bool >()->default_value("0"), "true or false"),
                 (abort_before_recover_cb_sent, "", "abort_before_recover_cb_sent", "abort_before_recover_cb_sent",
                  ::cxxopts::value< bool >()->default_value("0"), "true or false"),
                 (abort_after_recover_cb_sent, "", "abort_after_recover_cb_sent", "abort_after_recover_cb_sent",
                  ::cxxopts::value< bool >()->default_value("0"), "true or false"))

void meta_mod_test_main() {
    meta_cfg.write_sb_abort = SDS_OPTIONS["write_sb_abort"].as< bool >();
    meta_cfg.write_with_ovf_abort = SDS_OPTIONS["write_with_ovf_abort"].as< bool >();
    meta_cfg.remove_sb_abort = SDS_OPTIONS["remove_sb_abort"].as< bool >();
    meta_cfg.update_sb_abort = SDS_OPTIONS["update_sb_abort"].as< bool >();
    meta_cfg.abort_before_recover_cb_sent = SDS_OPTIONS["abort_before_recover_cb_sent"].as< bool >();
    meta_cfg.abort_after_recover_cb_sent = SDS_OPTIONS["abort_after_recover_cb_sent"].as< bool >();

    mod_tests.push_back(&meta_test);

    return;
}
