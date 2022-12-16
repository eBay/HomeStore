/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 * Author/Developer(s): Harihara Kadayam
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

#include <boost/date_time/posix_time/posix_time.hpp>
#include <sisl/flip/flip.hpp>
#include <sisl/flip/flip_client.hpp>
#include <iomgr/iomgr.hpp>

namespace homestore {
class FlipTimerIOMgr : public flip::FlipTimerBase {
public:
    void schedule(const boost::posix_time::time_duration delay_us, const std::function< void() >& closure) override {
        auto cb{[closure]([[maybe_unused]] void* const cookie) { closure(); }};
        iomgr::IOManager::instance().schedule_thread_timer(delay_us.total_nanoseconds(), false /* recurring */,
                                                           nullptr /* cookie */, cb);
    }
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
