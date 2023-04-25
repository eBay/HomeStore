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
#include <sisl/logging/logging.h>
#include <sisl/options/options.h>
#include "engine/common/mod_test_iface.hpp"
#include "engine/common/homestore_flip.hpp"
#include "engine/common/homestore_config.hpp"

using namespace homestore;
#ifdef _PRERELEASE
using namespace flip;
#endif

// TODO: make it under mode_test namespace

struct mod_test_vdev_cfg {
    bool abort_before_update_eof_cur_chunk{false};
    bool abort_after_update_eof_cur_chunk{false};
    bool abort_after_update_eof_next_chunk{false};
};

mod_test_vdev_cfg vdev_cfg;

static constexpr uint64_t run_time_sec = 10;
static constexpr uint64_t abort_time_sec = 10;

#ifdef _PRERELEASE
class mod_test_vdev : public module_test {
public:
    mod_test_vdev() : m_fc(HomeStoreFlip::instance()) {}

    virtual void run_start() override {
        // set start time
        m_start_time = Clock::now();
    }

    virtual void try_run_last_iteration() override { std::unique_lock< std::mutex > lk{m_mutex}; }

    virtual void try_run_one_iteration() override { std::unique_lock< std::mutex > lk{m_mutex}; }

    virtual void try_init_iteration() override {
        std::unique_lock< std::mutex > lk{m_mutex};
        if (vdev_cfg.abort_before_update_eof_cur_chunk) { set_flip("abort_before_update_eof_cur_chunk", 1, 1); }
        if (vdev_cfg.abort_after_update_eof_cur_chunk) { set_flip("abort_after_update_eof_cur_chunk", 1, 1); }
        if (vdev_cfg.abort_after_update_eof_next_chunk) { set_flip("abort_after_update_eof_next_chunk", 1, 1); }
    }

    void set_flip(const std::string& flip_name, uint32_t count, uint32_t percent) {
        // set flip point
        FlipCondition null_cond;
        FlipFrequency freq;
        freq.set_count(count);
        freq.set_percent(percent);
        m_fc.inject_noreturn_flip(flip_name, {null_cond}, freq);
    }

    Clock::time_point m_start_time;
    Clock::time_point m_flip_start_time;
    std::mutex m_mutex;
    bool m_flip_enabled{false};
    FlipClient m_fc;
};

mod_test_vdev vdev_test;
#endif

/************************* CLI options ***************************/
SISL_OPTION_GROUP(test_vdev_mod,
                  (abort_before_update_eof_cur_chunk, "", "abort_before_update_eof_cur_chunk",
                   "abort_before_update_eof_cur_chunk", ::cxxopts::value< bool >()->default_value("0"),
                   "true or false"),
                  (abort_after_update_eof_cur_chunk, "", "abort_after_update_eof_cur_chunk",
                   "abort_after_update_eof_cur_chunk", ::cxxopts::value< bool >()->default_value("0"), "true or false"),
                  (abort_after_update_eof_next_chunk, "", "abort_after_update_eof_next_chunk",
                   "abort_after_update_eof_next_chunk", ::cxxopts::value< bool >()->default_value("0"),
                   "true or false"))

void vdev_mod_test_main() {
    vdev_cfg.abort_before_update_eof_cur_chunk = SISL_OPTIONS["abort_before_update_eof_cur_chunk"].as< bool >();
    vdev_cfg.abort_after_update_eof_cur_chunk = SISL_OPTIONS["abort_after_update_eof_cur_chunk"].as< bool >();
    vdev_cfg.abort_after_update_eof_next_chunk = SISL_OPTIONS["abort_after_update_eof_next_chunk"].as< bool >();
#ifdef _PRERELEASE
    mod_tests.push_back(&vdev_test);
#endif
    return;
}
