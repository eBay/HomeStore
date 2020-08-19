#pragma once

#include <memory>
#include <async_http/http_server.hpp>

namespace homestore {
class HomeBlks;

class HomeBlksHttpServer {
public:
    HomeBlksHttpServer(HomeBlks* hb);
    void start();
    void stop();

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

private:
    static HomeBlks* to_homeblks(sisl::HttpCallData cd);
    static HomeBlksHttpServer* pThis(sisl::HttpCallData cd);

private:
    HomeBlks* m_hb;
    std::unique_ptr< sisl::HttpServer > m_http_server;
};

}; // namespace homestore