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
#ifdef _PRERELEASE

#include <csignal>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <map>

#include <boost/date_time/posix_time/posix_time.hpp>
#include <sisl/flip/flip.hpp>
#include <sisl/flip/flip_client.hpp>
#include <iomgr/iomgr.hpp>

namespace homestore {
class FlipTimerIOMgr : public flip::FlipTimerBase {
public:
    void schedule(const std::string& timer_name, const boost::posix_time::time_duration delay_us,
                  const std::function< void() >& closure) override {
        auto thdl = std::make_shared< iomgr::timer_handle_t >();
        auto cb = [closure, timer_name, thdl, this](void*) {
            closure();
            remove_timer(timer_name, thdl);
        };

        std::unique_lock< std::mutex > lk(m_mutex);
        *thdl = iomgr::IOManager::instance().schedule_thread_timer(delay_us.total_nanoseconds(), false /* recurring */,
                                                                   nullptr /* cookie */, cb);
        m_timer_instances.insert(std::make_pair(timer_name, thdl));
    }

    void cancel(const std::string& timer_name) { remove_timer(timer_name, nullptr); }

private:
    void remove_timer(const std::string& timer_name, const std::shared_ptr< iomgr::timer_handle_t >& thdl) {
        std::unique_lock< std::mutex > lk(m_mutex);
        auto range = m_timer_instances.equal_range(timer_name);
        for (auto it = range.first; it != range.second;) {
            if ((thdl == nullptr) || (it->second == thdl)) {
                it = m_timer_instances.erase(it);
            } else {
                ++it;
            }
        }
    }

private:
    std::mutex m_mutex;
    std::multimap< std::string, std::shared_ptr< iomgr::timer_handle_t > > m_timer_instances;
};

namespace HomeStoreFlip {
static flip::Flip* instance() {
    static std::once_flag flag1;
    std::call_once(flag1, []() {
        flip::Flip::instance().override_timer(
            (std::unique_ptr< flip::FlipTimerBase >(std::make_unique< homestore::FlipTimerIOMgr >())));
    });
    return &(flip::Flip::instance());
}

static flip::FlipClient* client_instance() {
    static flip::FlipClient fc{HomeStoreFlip::instance()};
    return &fc;
}

/**
 * @brief : test flip and abort without core dump.
 *
 * @param flip_name :
 */
/* TODO: add this function in flip */
static void test_and_abort(const std::string& flip_name) {
    if (instance()->test_flip(flip_name.c_str())) {
        // abort without generating core dump
        std::raise(SIGKILL);
    }
}
}; // namespace HomeStoreFlip

#define homestore_flip HomeStoreFlip::instance()

} // namespace homestore
#endif
