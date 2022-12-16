/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 * Author/Developer(s): Harihara Kadayam, Ravi Nagarjuna Akella
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
#include <ifaddrs.h>

namespace homestore {
class HomeBlks;

class HomeBlksHttpServer {
public:
    HomeBlksHttpServer(HomeBlks* hb);
    void start();
    void register_api_post_start();

    static bool is_local_addr(struct sockaddr* addr);
    static bool is_secure_zone();

    static void get_version(iomgr::HttpCallData cd);
    static void get_metrics(iomgr::HttpCallData cd);
    static void get_obj_life(iomgr::HttpCallData cd);
    static void get_prometheus_metrics(iomgr::HttpCallData cd);
    static void get_log_level(iomgr::HttpCallData cd);
    static void set_log_level(iomgr::HttpCallData cd);
    static void dump_stack_trace(iomgr::HttpCallData cd);
    static void verify_hs(iomgr::HttpCallData cd);
    static void get_malloc_stats(iomgr::HttpCallData cd);
    static void get_config(iomgr::HttpCallData cd);
    static void reload_dynamic_config(iomgr::HttpCallData cd);
    static void get_status(iomgr::HttpCallData cd);
    static void verify_bitmap(iomgr::HttpCallData cd);
    static void dump_disk_metablks(iomgr::HttpCallData cd);
    static void verify_metablk_store(iomgr::HttpCallData cd);
    static void wakeup_init(iomgr::HttpCallData cd);
#ifdef _PRERELEASE
    static void set_safe_mode(iomgr::HttpCallData cd);
    static void unset_safe_mode(iomgr::HttpCallData cd);
    static void crash_system(iomgr::HttpCallData cd);
    static void move_vol_offline(iomgr::HttpCallData cd);
    static void move_vol_online(iomgr::HttpCallData cd);
#endif

private:
    static HomeBlks* to_homeblks(iomgr::HttpCallData cd);
    static HomeBlksHttpServer* pThis(iomgr::HttpCallData cd);
    static bool verify_and_get_verbosity(const evhtp_request_t* req, std::string& failure_resp, int& verbosity_level);

private:
    HomeBlks* m_hb;
    static std::vector< std::string > m_iface_list;
};

}; // namespace homestore
