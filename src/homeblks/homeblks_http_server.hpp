#pragma once

#include <memory>
#include <string>

#include <iomgr/io_environment.hpp>
#include <ifaddrs.h>

namespace homestore {
class HomeBlks;

class HomeBlksHttpServer {
public:
    HomeBlksHttpServer(HomeBlks* hb);
    void start();
    void register_api_post_start();

    static bool is_local_addr(struct sockaddr* addr);

    static void get_version(sisl::HttpCallData cd);
    static void get_metrics(sisl::HttpCallData cd);
    static void get_obj_life(sisl::HttpCallData cd);
    static void get_prometheus_metrics(sisl::HttpCallData cd);
    static void get_log_level(sisl::HttpCallData cd);
    static void set_log_level(sisl::HttpCallData cd);
    static void dump_stack_trace(sisl::HttpCallData cd);
    static void verify_hs(sisl::HttpCallData cd);
    static void get_malloc_stats(sisl::HttpCallData cd);
    static void get_config(sisl::HttpCallData cd);
    static void reload_dynamic_config(sisl::HttpCallData cd);
    static void get_status(sisl::HttpCallData cd);
    static void verify_bitmap(sisl::HttpCallData cd);
    static void dump_disk_metablks(sisl::HttpCallData cd);
    static void verify_metablk_store(sisl::HttpCallData cd);
    static void wakeup_init(sisl::HttpCallData cd);
#ifdef _PRERELEASE
    static void set_safe_mode(sisl::HttpCallData cd);
    static void unset_safe_mode(sisl::HttpCallData cd);
    static void crash_system(sisl::HttpCallData cd);
    static void move_vol_offline(sisl::HttpCallData cd);
    static void move_vol_online(sisl::HttpCallData cd);
#endif

private:
    static HomeBlks* to_homeblks(sisl::HttpCallData cd);
    static HomeBlksHttpServer* pThis(sisl::HttpCallData cd);
    static bool verify_and_get_verbosity(const evhtp_request_t* req, std::string& failure_resp, int& verbosity_level);

private:
    HomeBlks* m_hb;
    static std::vector< std::string > m_iface_list;
};

}; // namespace homestore
