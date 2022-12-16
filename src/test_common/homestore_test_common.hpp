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
/*
 * Homestore testing binaries shared common definitions, apis and data structures
 * */

#pragma once
#include <sisl/logging/logging.h>
#include <iomgr/iomgr_config.hpp>

const std::string SPDK_ENV_VAR_STRING{"USER_WANT_SPDK"};
const std::string HTTP_SVC_ENV_VAR_STRING{"USER_WANT_HTTP_OFF"};
const std::string CP_WATCHDOG_TIMER_SEC{"USER_SET_CP_WD_TMR_SEC"};          // used in nightly test;
const std::string FLIP_SLOW_PATH_EVERY_NTH{"USER_SET_SLOW_PATH_EVERY_NTH"}; // used in nightly test;
const std::string BLKSTORE_FORMAT_OFF{"USER_WANT_BLKSTORE_FORMAT_OFF"};     // used for debug purpose;
const std::string USER_WANT_DIRECT_IO{"USER_WANT_DIRECT_IO"};               // used for HDD direct io mode;

namespace test_common {

// generate random port for http server
inline static void set_random_http_port() {
    static std::random_device dev;
    static std::mt19937 rng(dev());
    std::uniform_int_distribution< std::mt19937::result_type > dist(1001u, 99999u);
    const uint32_t http_port = dist(rng);
    LOGINFO("random port generated = {}", http_port);
    IM_SETTINGS_FACTORY().modifiable_settings([http_port](auto& s) { s.io_env->http_port = http_port; });
    IM_SETTINGS_FACTORY().save();
}
} // namespace test_common

// TODO: start_homestore should be moved here and called by each testing binaries
