#include <chrono>
#include <csignal>
#include <cstdint>
#include <sstream>
#include <thread>

#include <boost/algorithm/string.hpp>
#include <nlohmann/json.hpp>
#include <sisl/version.hpp>

#include "engine/common/homestore_config.hpp"
#include "homeblks_config.hpp"
#include "homeblks_http_server.hpp"
#include "engine/common/homestore_status_mgr.hpp"
#include "home_blks.hpp"

namespace homestore {

std::vector< std::string > HomeBlksHttpServer::m_iface_list;
HomeBlksHttpServer* HomeBlksHttpServer::pThis(sisl::HttpCallData cd) { return (HomeBlksHttpServer*)cd->cookie(); }
HomeBlks* HomeBlksHttpServer::to_homeblks(sisl::HttpCallData cd) { return pThis(cd)->m_hb; }

HomeBlksHttpServer::HomeBlksHttpServer(HomeBlks* hb) : m_hb(hb) {}

void HomeBlksHttpServer::start() {
    sisl::HttpServerConfig cfg;
    cfg.is_tls_enabled = false;
    cfg.bind_address = "0.0.0.0";
    cfg.server_port = SDS_OPTIONS["hb_stats_port"].as< int32_t >();
    cfg.read_write_timeout_secs = 10;

    m_http_server = std::unique_ptr< sisl::HttpServer >(new sisl::HttpServer(
        cfg,
        {{
            handler_info("/api/v1/version", HomeBlksHttpServer::get_version, (void*)this),
            handler_info("/api/v1/getMetrics", HomeBlksHttpServer::get_metrics, (void*)this),
            handler_info("/api/v1/getObjLife", HomeBlksHttpServer::get_obj_life, (void*)this),
            handler_info("/metrics", HomeBlksHttpServer::get_prometheus_metrics, (void*)this),
            handler_info("/api/v1/getLogLevel", HomeBlksHttpServer::get_log_level, (void*)this),
            handler_info("/api/v1/setLogLevel", HomeBlksHttpServer::set_log_level, (void*)this),
            handler_info("/api/v1/dumpStackTrace", HomeBlksHttpServer::dump_stack_trace, (void*)this),
            handler_info("/api/v1/verifyHS", HomeBlksHttpServer::verify_hs, (void*)this),
            handler_info("/api/v1/mallocStats", HomeBlksHttpServer::get_malloc_stats, (void*)this),
            handler_info("/api/v1/getConfig", HomeBlksHttpServer::get_config, (void*)this),
            handler_info("/api/v1/reloadConfig", HomeBlksHttpServer::reload_dynamic_config, (void*)this),
            handler_info("/api/v1/getStatus", HomeBlksHttpServer::get_status, (void*)this),
            handler_info("/api/v1/verifyBitmap", HomeBlksHttpServer::verify_bitmap, (void*)this),
            handler_info("/api/v1/dumpDiskMetaBlks", HomeBlksHttpServer::dump_disk_metablks, (void*)this),
            handler_info("/api/v1/verifyMetaBlkStore", HomeBlksHttpServer::verify_metablk_store, (void*)this),
            handler_info("/api/v1/wakeupInit", HomeBlksHttpServer::wakeup_init, (void*)this),
#ifdef _PRERELEASE
            handler_info("/api/v1/crashSystem", HomeBlksHttpServer::crash_system, (void*)this),
            handler_info("/api/v1/moveVolOffline", HomeBlksHttpServer::move_vol_offline, (void*)this),
            handler_info("/api/v1/moveVolOnline", HomeBlksHttpServer::move_vol_online, (void*)this),
#endif
        }}));
    m_http_server->start();

    // get sock interfaces and store ips
    struct ifaddrs* interfaces = nullptr;
    struct ifaddrs* temp_addr = nullptr;
    auto error = getifaddrs(&interfaces);
    if (error != 0) { LOGWARN("getifaddrs returned non zero code: {}", error); }
    temp_addr = interfaces;
    while (temp_addr != nullptr) {
        if (temp_addr->ifa_addr->sa_family == AF_INET) {
            m_iface_list.emplace_back(inet_ntoa(((struct sockaddr_in*)temp_addr->ifa_addr)->sin_addr));
        }
        temp_addr = temp_addr->ifa_next;
    }
    freeifaddrs(interfaces);
}

void HomeBlksHttpServer::stop() { m_http_server->stop(); }

bool HomeBlksHttpServer::is_local_addr(struct sockaddr* addr) {
    std::string client_ip = inet_ntoa(((struct sockaddr_in*)addr)->sin_addr);
    return (std::find(m_iface_list.begin(), m_iface_list.end(), client_ip) != m_iface_list.end());
}

void HomeBlksHttpServer::get_version(sisl::HttpCallData cd) {
    auto vers{sisl::VersionMgr::getVersions()};
    std::string ver_str{""};
    for (auto v : vers) {
        ver_str += fmt::format("{0}: {1}; ", v.first, v.second);
    }
    pThis(cd)->m_http_server->respond_OK(cd, EVHTP_RES_OK, ver_str);
}

void HomeBlksHttpServer::get_metrics(sisl::HttpCallData cd) {
    std::string msg = sisl::MetricsFarm::getInstance().get_result_in_json_string();
    pThis(cd)->m_http_server->respond_OK(cd, EVHTP_RES_OK, msg);
}

void HomeBlksHttpServer::get_prometheus_metrics(sisl::HttpCallData cd) {
    std::string msg = sisl::MetricsFarm::getInstance().report(sisl::ReportFormat::kTextFormat);
    pThis(cd)->m_http_server->respond_OK(cd, EVHTP_RES_OK, msg);
}

void HomeBlksHttpServer::get_obj_life(sisl::HttpCallData cd) {
    nlohmann::json j;
    sisl::ObjCounterRegistry::foreach ([&j](const std::string& name, int64_t created, int64_t alive) {
        std::stringstream ss;
        ss << "created=" << created << " alive=" << alive;
        j[name] = ss.str();
    });
    pThis(cd)->m_http_server->respond_OK(cd, EVHTP_RES_OK, j.dump());
}

void HomeBlksHttpServer::set_log_level(sisl::HttpCallData cd) {
    auto req = cd->request();

    const evhtp_kv_t* _new_log_level = nullptr;
    const evhtp_kv_t* _new_log_module = nullptr;
    const char* logmodule = nullptr;
    char* endptr = nullptr;

    _new_log_module = evhtp_kvs_find_kv(req->uri->query, "logmodule");
    if (_new_log_module) { logmodule = _new_log_module->val; }

    _new_log_level = evhtp_kvs_find_kv(req->uri->query, "loglevel");
    if (!_new_log_level) {
        pThis(cd)->m_http_server->respond_NOTOK(cd, EVHTP_RES_BADREQ, "Invalid loglevel param!");
        return;
    }
    auto new_log_level = _new_log_level->val;

    std::string resp = "";
    if (logmodule == nullptr) {
        sds_logging::SetAllModuleLogLevel(spdlog::level::from_str(new_log_level));
        resp = sds_logging::GetAllModuleLogLevel().dump(2);
    } else {
        sds_logging::SetModuleLogLevel(logmodule, spdlog::level::from_str(new_log_level));
        resp = std::string("logmodule ") + logmodule + " level set to " +
            spdlog::level::to_string_view(sds_logging::GetModuleLogLevel(logmodule)).data();
    }

    pThis(cd)->m_http_server->respond_OK(cd, EVHTP_RES_OK, resp);
}

void HomeBlksHttpServer::get_log_level(sisl::HttpCallData cd) {
    auto req = cd->request();

    const evhtp_kv_t* _log_module = nullptr;
    const char* logmodule = nullptr;
    _log_module = evhtp_kvs_find_kv(req->uri->query, "logmodule");
    if (_log_module) { logmodule = _log_module->val; }

    std::string resp = "";
    if (logmodule == nullptr) {
        resp = sds_logging::GetAllModuleLogLevel().dump(2);
    } else {
        resp = std::string("logmodule ") + logmodule +
            " level = " + spdlog::level::to_string_view(sds_logging::GetModuleLogLevel(logmodule)).data();
    }
    pThis(cd)->m_http_server->respond_OK(cd, EVHTP_RES_OK, resp);
}

void HomeBlksHttpServer::dump_stack_trace(sisl::HttpCallData cd) {
    if (!is_local_addr(cd->request()->conn->saddr)) {
        pThis(cd)->m_http_server->respond_NOTOK(cd, EVHTP_RES_FORBIDDEN, "Access not allowed from external host");
        return;
    }

    sds_logging::log_stack_trace(true);
    pThis(cd)->m_http_server->respond_OK(cd, EVHTP_RES_OK, "Look for stack trace in the log file");
}

void HomeBlksHttpServer::get_malloc_stats(sisl::HttpCallData cd) {
    pThis(cd)->m_http_server->respond_OK(cd, EVHTP_RES_OK, sisl::get_malloc_stats_detailed().dump(2));
}

void HomeBlksHttpServer::verify_hs(sisl::HttpCallData cd) {
    if (!is_local_addr(cd->request()->conn->saddr)) {
        pThis(cd)->m_http_server->respond_NOTOK(cd, EVHTP_RES_FORBIDDEN, "Access not allowed from external host");
        return;
    }

    auto hb = to_homeblks(cd);
    auto ret = hb->verify_vols();
    std::string resp{"HomeBlks verified "};
    resp += ret ? "successfully" : "failed";
    pThis(cd)->m_http_server->respond_OK(cd, EVHTP_RES_OK, resp);
}

void HomeBlksHttpServer::get_config(sisl::HttpCallData cd) {
    nlohmann::json j;
    j = sisl::SettingsFactoryRegistry::instance().get_json();
    j["static"] = homestore::HomeStoreStaticConfig::instance().to_json();
    pThis(cd)->m_http_server->respond_OK(cd, EVHTP_RES_OK, j.dump(2));
}

void HomeBlksHttpServer::reload_dynamic_config(sisl::HttpCallData cd) {
    if (!is_local_addr(cd->request()->conn->saddr)) {
        pThis(cd)->m_http_server->respond_NOTOK(cd, EVHTP_RES_FORBIDDEN, "Access not allowed from external host");
        return;
    }

    bool restart_needed = sisl::SettingsFactoryRegistry::instance().reload_all();
    pThis(cd)->m_http_server->respond_OK(
        cd, EVHTP_RES_OK,
        fmt::format("All config reloaded, is app restarted {}\n", (restart_needed ? "true" : "false")));
    if (restart_needed) {
        LOGINFO("Restarting HomeBlks because of config change which needed a restart");
        std::this_thread::sleep_for(std::chrono::microseconds{1000});
        std::raise(SIGTERM);
    }
}

bool HomeBlksHttpServer::verify_and_get_verbosity(const evhtp_request_t* req, std::string& failure_resp,
                                                  int& verbosity_level) {
    bool ret{true};
    auto verbosity_kv = evhtp_kvs_find_kv(req->uri->query, "verbosity");
    if (verbosity_kv) {
        try {
            verbosity_level = std::stoi(verbosity_kv->val);
        } catch (...) {
            failure_resp = fmt::format("{} is not a valid verbosity level", verbosity_kv->val);
            ret = false;
        }
    } else {
        verbosity_level = 0; // default verbosity level
    }
    return ret;
}

void HomeBlksHttpServer::verify_metablk_store(sisl::HttpCallData cd) {
    auto req = cd->request();

    const auto hb = to_homeblks(cd);
    if (hb->is_safe_mode()) {
        const auto ret = hb->verify_metablk_store();
        pThis(cd)->m_http_server->respond_OK(
            cd, EVHTP_RES_OK, fmt::format("Disk sanity of MetaBlkStore result: {}", ret ? "Passed" : "Failed"));
    } else {
        pThis(cd)->m_http_server->respond_NOTOK(
            cd, EVHTP_RES_BADREQ, fmt::format("HomeBlks not in safe mode, not allowed to serve this request"));
    }
}

void HomeBlksHttpServer::dump_disk_metablks(sisl::HttpCallData cd) {
    auto req = cd->request();

    std::vector< std::string > clients;
    auto modules_kv = evhtp_kvs_find_kv(req->uri->query, "client");
    if (modules_kv) {
        boost::algorithm::split(clients, modules_kv->val, boost::is_any_of(","), boost::token_compress_on);
    }

    if (clients.size() != 1) {
        pThis(cd)->m_http_server->respond_NOTOK(
            cd, EVHTP_RES_BADREQ,
            fmt::format("Can serve only one client per request. Number clients received: {}\n", clients.size()));
        return;
    }

    const auto hb = to_homeblks(cd);
    if (hb->is_safe_mode()) {
        const auto j = to_homeblks(cd)->dump_disk_metablks(clients[0]);
        pThis(cd)->m_http_server->respond_OK(cd, EVHTP_RES_OK, j.dump(2));
    } else {
        pThis(cd)->m_http_server->respond_NOTOK(
            cd, EVHTP_RES_BADREQ, fmt::format("HomeBlks not in safe mode, not allowed to serve this request"));
    }
}

void HomeBlksHttpServer::get_status(sisl::HttpCallData cd) {
    auto req = cd->request();

    std::vector< std::string > modules;
    auto modules_kv = evhtp_kvs_find_kv(req->uri->query, "module");
    if (modules_kv) {
        boost::algorithm::split(modules, modules_kv->val, boost::is_any_of(","), boost::token_compress_on);
    }

    std::string failure_resp{""};
    int verbosity_level{-1};
    if (!verify_and_get_verbosity(req, failure_resp, verbosity_level)) {
        pThis(cd)->m_http_server->respond_NOTOK(cd, EVHTP_RES_BADREQ, failure_resp);
        return;
    }

    const auto status_mgr = to_homeblks(cd)->status_mgr();
    auto status_json = status_mgr->get_status(modules, verbosity_level);
    pThis(cd)->m_http_server->respond_OK(cd, EVHTP_RES_OK, status_json.dump(2));
}

void HomeBlksHttpServer::verify_bitmap(sisl::HttpCallData cd) {
    if (!is_local_addr(cd->request()->conn->saddr)) {
        pThis(cd)->m_http_server->respond_NOTOK(cd, EVHTP_RES_FORBIDDEN, "Access not allowed from external host");
        return;
    }

    auto hb = to_homeblks(cd);
    auto ret = hb->verify_bitmap();
    std::string resp{"HomeBlks bitmap verified "};
    resp += ret ? "successfully" : "failed";
    pThis(cd)->m_http_server->respond_OK(cd, EVHTP_RES_OK, resp);
}

void HomeBlksHttpServer::wakeup_init(sisl::HttpCallData cd) {
    auto hb = to_homeblks(cd);
    hb->wakeup_init();
    std::string resp{"completed"};
    pThis(cd)->m_http_server->respond_OK(cd, EVHTP_RES_OK, resp);
}

#ifdef _PRERELEASE
void HomeBlksHttpServer::crash_system(sisl::HttpCallData cd) {
    auto req{cd->request()};

    const evhtp_kv_t* _crash_type{nullptr};
    std::string crash_type;
    _crash_type = evhtp_kvs_find_kv(req->uri->query, "type");
    if (_crash_type) { crash_type = _crash_type->val; }

    std::string resp = "";
    if (crash_type.empty() || boost::iequals(crash_type, "assert")) {
        HS_RELEASE_ASSERT(0, "Fake Assert in response to an http request");
    } else if (boost::iequals(crash_type, "segv")) {
        int* x{nullptr};
        LOGINFO("Simulating a segv with dereferencing nullptr={}", *x);
    } else {
        resp = "crash type " + crash_type + " not supported yet";
    }
    pThis(cd)->m_http_server->respond_OK(cd, EVHTP_RES_OK, resp);
}

void HomeBlksHttpServer::move_vol_online(sisl::HttpCallData cd) {
    auto req = cd->request();

    std::string vol_uuid;
    const evhtp_kv_t* _vol_uuid = evhtp_kvs_find_kv(req->uri->query, "uuid");
    if (_vol_uuid) { vol_uuid = _vol_uuid->val; }

    if (vol_uuid.length() == 0) {
        pThis(cd)->m_http_server->respond_NOTOK(cd, EVHTP_RES_BADREQ, std::string("empty vol_uuid!"));
        return;
    }

    boost::uuids::string_generator gen;
    boost::uuids::uuid uuid = gen(vol_uuid);
    auto hb = to_homeblks(cd);
    auto res = hb->mark_vol_online(uuid);
    std::string resp{"Vol: " + vol_uuid + " moved to online state "};

    resp += (res == no_error ? "successfully" : "failed");
    if (res != no_error) { resp += ("error: " + res.message()); }
    pThis(cd)->m_http_server->respond_OK(cd, EVHTP_RES_OK, resp);
}

void HomeBlksHttpServer::move_vol_offline(sisl::HttpCallData cd) {
    auto req = cd->request();

    std::string vol_uuid;
    const evhtp_kv_t* _vol_uuid = evhtp_kvs_find_kv(req->uri->query, "uuid");
    if (_vol_uuid) { vol_uuid = _vol_uuid->val; }

    if (vol_uuid.length() == 0) {
        pThis(cd)->m_http_server->respond_NOTOK(cd, EVHTP_RES_BADREQ, std::string("empty vol_uuid!"));
        return;
    }

    boost::uuids::string_generator gen;
    boost::uuids::uuid uuid = gen(vol_uuid);
    auto hb = to_homeblks(cd);
    auto res = hb->mark_vol_offline(uuid);
    std::string resp{"Vol: " + vol_uuid + " moved to offline state "};

    resp += (res == no_error ? "successfully" : "failed");
    if (res != no_error) { resp += ("error: " + res.message()); }
    pThis(cd)->m_http_server->respond_OK(cd, EVHTP_RES_OK, resp);
}
#endif

} // namespace homestore
