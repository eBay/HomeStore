/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 *********************************************************************************/
#include <random>
#include <mutex>
#include <memory>
#include <cstdint>
#include <sys/timeb.h>
#include <sisl/fds/buffer.hpp>
#include <sisl/logging/logging.h>
#include <sisl/options/options.h>
#include "engine/common/mod_test_iface.hpp"
#include "engine/common/homestore_flip.hpp"
#include "engine/common/homestore_config.hpp"
#include "engine/index/indx_mgr.hpp"

using namespace homestore;
#ifdef _PRERELEASE
using namespace flip;
#endif

// TODO: make it under mode_test namespace

struct indx_mgr_test_cfg {

    bool indx_create_first_cp_abort = false;
    bool indx_del_partial_free_data_blks_after_meta_write = false;
    bool indx_del_partial_free_data_blks_before_meta_write = false;
    bool indx_del_partial_free_indx_blks = false;
    bool indx_del_free_blks_completed = false;
    uint32_t free_blk_cnt = 0;

    bool cp_bitmap_abort = 0;            // crash while bitmap is persisting
    bool cp_wb_flush_abort = 0;          // abort in middle of wb flush
    bool cp_logstore_truncate_abort = 0; // crash after logstore is truncated

    bool unmap_post_sb_write_abort = false;
    bool unmap_pre_sb_remove_abort = false;
    bool unmap_post_free_blks_abort_before_cp = false;
    bool unmap_pre_second_cp_abort = false;
};

indx_mgr_test_cfg indx_cfg;
const uint64_t run_time_sec = 300;
const uint64_t abort_time_sec = 10;

enum flip_state { FLIP_NOT_SET = 0, FLIP_SET = 1, SYSTEM_PANIC = 2 };

#ifdef _PRERELEASE
class indx_test : public module_test {
    indx_test() : m_fc(HomeStoreFlip::instance()) {}
    virtual void run_start() override {}

    bool is_cp_abort_test() {
        if (indx_cfg.cp_bitmap_abort || indx_cfg.cp_wb_flush_abort || indx_cfg.cp_logstore_truncate_abort) {
            return true;
        }
        return false;
    }
    virtual void try_run_last_iteration() override {
        std::unique_lock< std::mutex > lk{m_mutex};
        if (is_cp_abort_test()) { indx_cp_abort_test(); }
    }
    virtual void try_run_one_iteration() override {
        static std::atomic< int > cnt = 0;
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
        if (indx_cfg.unmap_post_sb_write_abort) { unmap_post_sb_write_abort(); }
        if (indx_cfg.unmap_pre_sb_remove_abort) { unmap_pre_sb_remove_abort(); }
        if (indx_cfg.unmap_post_free_blks_abort_before_cp) { unmap_post_free_blks_abort_before_cp(); }
        if (indx_cfg.unmap_pre_second_cp_abort) { unmap_pre_second_cp_abort(); }

        if (is_cp_abort_test()) { suspend_cp(); }
    }

    virtual void try_init_iteration() override {
        // set start time
        m_start_time = Clock::now();
        try_run_one_iteration();
    }

    void suspend_cp() {
        if (get_elapsed_time_sec(m_start_time) > run_time_sec) { IndxMgr::hs_cp_suspend(); }
    }

    void indx_cp_abort_test() {
        if (indx_cfg.cp_bitmap_abort) { set_flip_point("indx_cp_bitmap_abort"); }
        if (indx_cfg.cp_wb_flush_abort) { set_flip_point("indx_cp_wb_flush_abort"); }
        if (indx_cfg.cp_logstore_truncate_abort) { set_flip_point("indx_cp_logstore_truncate_abort"); }
        IndxMgr::hs_cp_resume();
    }

    /* It simulate the crash before first cp is taken on a index. It simulate 3 scenarios before crash
     * 1. Few IOs
     * 2. No IOs
     * 3. index delete just after create
     */
    void indx_create_first_cp_abort() {

        static thread_local std::random_device rd{};
        static thread_local std::default_random_engine engine{rd()};
        static thread_local std::uniform_int_distribution< uint64_t > dist{5, 10};
        switch (m_flip_state) {
        case flip_state::FLIP_NOT_SET:
            if (get_elapsed_time_sec(m_start_time) > run_time_sec) {
                set_flip_point("indx_create_suspend_cp");
                m_flip_state = FLIP_SET;
            }
            break;
        case flip_state::FLIP_SET:
            std::atomic_thread_fence(std::memory_order_acquire);
            if (indx_test_status::indx_create_suspend_cp_test) {
                m_flip_start_time = Clock::now();
                m_flip_state = SYSTEM_PANIC;
            }
            break;
        case flip_state::SYSTEM_PANIC:
            if (get_elapsed_time_sec(m_flip_start_time) > dist(engine)) { raise(SIGKILL); }
        }
    }

    void indx_del_partial_free_data_blks_after_meta_write() {
        set_flip_point("indx_del_partial_free_data_blks_after_meta_write");
    }

    void indx_del_partial_free_data_blks_before_meta_write() {
        set_flip_point("indx_del_partial_free_data_blks_before_meta_write");
    }

    void indx_del_partial_free_indx_blks() { set_flip_point("indx_del_partial_free_indx_blks"); }

    void indx_del_free_blks_completed() { set_flip_point("indx_del_free_blks_completed"); }

    void unmap_post_sb_write_abort() { set_flip_point("unmap_post_sb_write_abort"); }

    void unmap_pre_sb_remove_abort() { set_flip_point("unmap_pre_sb_remove_abort"); }

    void unmap_post_free_blks_abort_before_cp() { set_flip_point("unmap_post_free_blks_abort_before_cp"); }

    void unmap_pre_second_cp_abort() { set_flip_point("unmap_pre_second_cp_abort"); }

private:
    void set_flip_point(const std::string flip_name) {
        FlipCondition null_cond;
        FlipFrequency freq;
        freq.set_count(1);
        freq.set_percent(100);
        m_fc.inject_noreturn_flip(flip_name, {null_cond}, freq);
        LOGDEBUG("Flip " + flip_name + " set");
    }

protected:
    Clock::time_point m_start_time;
    Clock::time_point m_flip_start_time;
    std::mutex m_mutex;
    bool m_flip_enabled = false;
    enum flip_state m_flip_state = flip_state::FLIP_NOT_SET;
    FlipClient m_fc;
};

indx_test test;
#endif

/************************* CLI options ***************************/
SISL_OPTION_GROUP(
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
    (free_blk_cnt, "", "free_blk_cnt", "free_blk_cnt", ::cxxopts::value< uint32_t >()->default_value("0"), ""),
    (cp_bitmap_abort, "", "cp_bitmap_abort", "cp_bitmap_abort", ::cxxopts::value< bool >()->default_value("0"), ""),
    (cp_wb_flush_abort, "", "cp_wb_flush_abort", "cp_wb_flush_abort", ::cxxopts::value< bool >()->default_value("0"),
     ""),
    (cp_logstore_truncate_abort, "", "cp_logstore_truncate_abort", "cp_logstore_truncate_abort",
     ::cxxopts::value< bool >()->default_value("0"), ""),
    (unmap_post_sb_write_abort, "", "unmap_post_sb_write_abort", "abort after unmap sb is written",
     ::cxxopts::value< bool >()->default_value("false"), "true or false"),
    (unmap_pre_sb_remove_abort, "", "unmap_pre_sb_remove_abort", "abort after cp is complete and before sb is removed",
     ::cxxopts::value< bool >()->default_value("false"), "true or false"),
    (unmap_post_free_blks_abort_before_cp, "", "unmap_post_free_blks_abort_before_cp",
     "abort after unmap free blks collected and before cp", ::cxxopts::value< bool >()->default_value("false"),
     "true or false"),
    (unmap_pre_second_cp_abort, "", "unmap_pre_second_cp_abort",
     "abort after the first blk alloc CP with unmap is completed "
     "and before the next blk alloc cp",
     ::cxxopts::value< bool >()->default_value("false"), "true or false"))

void indx_mgr_test_main() {
    indx_cfg.indx_create_first_cp_abort = SISL_OPTIONS["indx_create_first_cp_abort"].as< bool >();
    indx_cfg.indx_del_free_blks_completed = SISL_OPTIONS["indx_del_free_blks_completed"].as< bool >();
    indx_cfg.indx_del_partial_free_indx_blks = SISL_OPTIONS["indx_del_partial_free_indx_blks"].as< bool >();
    indx_cfg.indx_del_partial_free_data_blks_after_meta_write =
        SISL_OPTIONS["indx_del_partial_free_data_blks_after_meta_write"].as< bool >();
    indx_cfg.indx_del_partial_free_data_blks_before_meta_write =
        SISL_OPTIONS["indx_del_partial_free_data_blks_before_meta_write"].as< bool >();
    indx_cfg.free_blk_cnt = SISL_OPTIONS["free_blk_cnt"].as< uint32_t >();
    indx_cfg.cp_bitmap_abort = SISL_OPTIONS["cp_bitmap_abort"].as< bool >();
    indx_cfg.cp_wb_flush_abort = SISL_OPTIONS["cp_wb_flush_abort"].as< bool >();
    indx_cfg.cp_logstore_truncate_abort = SISL_OPTIONS["cp_logstore_truncate_abort"].as< bool >();
    indx_cfg.unmap_post_sb_write_abort = SISL_OPTIONS["unmap_post_sb_write_abort"].as< bool >();
    indx_cfg.unmap_pre_sb_remove_abort = SISL_OPTIONS["unmap_pre_sb_remove_abort"].as< bool >();
    indx_cfg.unmap_post_free_blks_abort_before_cp = SISL_OPTIONS["unmap_post_free_blks_abort_before_cp"].as< bool >();
    indx_cfg.unmap_pre_second_cp_abort = SISL_OPTIONS["unmap_pre_second_cp_abort"].as< bool >();
    if (indx_cfg.free_blk_cnt) {
        HS_SETTINGS_FACTORY().modifiable_settings(
            [](auto& s) { s.resource_limits.free_blk_cnt = indx_cfg.free_blk_cnt; });
        HS_SETTINGS_FACTORY().save();
    }
#ifdef _PRERELEASE
    mod_tests.push_back(&test);
#endif
    return;
}
