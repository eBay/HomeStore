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
#pragma once
#include <atomic>
#include <array>
#include <memory>
#include <mutex>

#include <sisl/logging/logging.h>
#include <iomgr/iomgr.hpp>
#include <folly/futures/SharedPromise.h>

namespace homestore {
class CPManager;
class CPWatchdog {
public:
    CPWatchdog(CPManager* cp_mgr);
    void set_cp(CP* cp);
    void reset_cp();
    void cp_watchdog_timer();
    void stop();

private:
    CP* m_cp;
    CPManager* m_cp_mgr;
    std::shared_mutex m_cp_mtx;
    Clock::time_point m_last_state_ch_time;
    uint64_t m_timer_sec{0};
    iomgr::timer_handle_t m_timer_hdl;
    uint32_t m_progress_pct{0};
};
} // namespace homestore
