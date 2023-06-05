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

#include <memory>
#include <string>

#include <iomgr/io_environment.hpp>
#include <iomgr/http_server.hpp>

namespace homestore {
class HomeBlks;

class HomeBlksHttpServer {
public:
    HomeBlksHttpServer(HomeBlks* hb);
    void register_api_post_start();

    // Use only in safe mode or testing
    // We cannot add routes to pistache after starting the server. In the regular path, we expect the main program to
    // start the server
    void start();

    void get_version(const Pistache::Rest::Request& request, Pistache::Http::ResponseWriter response);
    void get_metrics(const Pistache::Rest::Request& request, Pistache::Http::ResponseWriter response);
    void get_obj_life(const Pistache::Rest::Request& request, Pistache::Http::ResponseWriter response);
    void get_prometheus_metrics(const Pistache::Rest::Request& request, Pistache::Http::ResponseWriter response);
    void get_log_level(const Pistache::Rest::Request& request, Pistache::Http::ResponseWriter response);
    void set_log_level(const Pistache::Rest::Request& request, Pistache::Http::ResponseWriter response);
    void dump_stack_trace(const Pistache::Rest::Request& request, Pistache::Http::ResponseWriter response);
    void verify_hs(const Pistache::Rest::Request& request, Pistache::Http::ResponseWriter response);
    void get_malloc_stats(const Pistache::Rest::Request& request, Pistache::Http::ResponseWriter response);
    void get_config(const Pistache::Rest::Request& request, Pistache::Http::ResponseWriter response);
    void reload_dynamic_config(const Pistache::Rest::Request& request, Pistache::Http::ResponseWriter response);
    void get_status(const Pistache::Rest::Request& request, Pistache::Http::ResponseWriter response);
    void verify_bitmap(const Pistache::Rest::Request& request, Pistache::Http::ResponseWriter response);
    void dump_disk_metablks(const Pistache::Rest::Request& request, Pistache::Http::ResponseWriter response);
    void verify_metablk_store(const Pistache::Rest::Request& request, Pistache::Http::ResponseWriter response);
    void wakeup_init(const Pistache::Rest::Request& request, Pistache::Http::ResponseWriter response);
    void copy_vol(const Pistache::Rest::Request& request, Pistache::Http::ResponseWriter response);
#ifdef _PRERELEASE
    void set_safe_mode(const Pistache::Rest::Request& request, Pistache::Http::ResponseWriter response);
    void unset_safe_mode(const Pistache::Rest::Request& request, Pistache::Http::ResponseWriter response);
    void crash_system(const Pistache::Rest::Request& request, Pistache::Http::ResponseWriter response);
    void move_vol_offline(const Pistache::Rest::Request& request, Pistache::Http::ResponseWriter response);
    void move_vol_online(const Pistache::Rest::Request& request, Pistache::Http::ResponseWriter response);
#endif

private:
    void setup_routes();
    bool verify_and_get_verbosity(const Pistache::Rest::Request& request, std::string& failure_resp,
                                  int& verbosity_level);

private:
    HomeBlks* m_hb;
};

}; // namespace homestore
