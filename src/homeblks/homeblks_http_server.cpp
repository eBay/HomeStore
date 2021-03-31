#include <chrono>
#include <csignal>
#include <cstdint>
#include <sstream>
#include <thread>

#include <boost/algorithm/string.hpp>
#include <nlohmann/json.hpp>

#include "engine/common/homestore_config.hpp"
#include "homeblks_config.hpp"
#include "homeblks_http_server.hpp"
#include "home_blks.hpp"

namespace homestore {
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
#ifdef _PRERELEASE
            handler_info("/api/v1/crashSystem", HomeBlksHttpServer::crash_system, (void*)this),
#endif
        }}));
    m_http_server->start();
}

void HomeBlksHttpServer::stop() { m_http_server->stop(); }

void HomeBlksHttpServer::get_version(sisl::HttpCallData cd) {
    pThis(cd)->m_http_server->respond_OK(cd, EVHTP_RES_OK, std::string("HomeBlks: ") + HomeBlks::version);
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
    sds_logging::log_stack_trace(true);
    pThis(cd)->m_http_server->respond_OK(cd, EVHTP_RES_OK, "Look for stack trace in the log file");
}

void HomeBlksHttpServer::get_malloc_stats(sisl::HttpCallData cd) {
    pThis(cd)->m_http_server->respond_OK(cd, EVHTP_RES_OK, sisl::get_malloc_stats_detailed().dump(2));
}

void HomeBlksHttpServer::verify_hs(sisl::HttpCallData cd) {
    auto hb = to_homeblks(cd);
    hb->verify_vols();
    pThis(cd)->m_http_server->respond_OK(cd, EVHTP_RES_OK, std::string("HomeBlks verified"));
}

void HomeBlksHttpServer::get_config(sisl::HttpCallData cd) {
    nlohmann::json j;
    j = sisl::SettingsFactoryRegistry::instance().get_json();
    j["static"] = homestore::HomeStoreStaticConfig::instance().to_json();
    pThis(cd)->m_http_server->respond_OK(cd, EVHTP_RES_OK, j.dump(2));
}

void HomeBlksHttpServer::reload_dynamic_config(sisl::HttpCallData cd) {
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

    const auto status_mgr = to_homeblks(cd)->get_status_mgr();
    const auto status_json = status_mgr->get_status(modules, verbosity_level);
    pThis(cd)->m_http_server->respond_OK(cd, EVHTP_RES_OK, status_json.dump(2));
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
        int y = *x; // Deliberately dereference a nullptr (simulate rather than sending segv signal)
    } else {
        resp = "crash type " + crash_type + " not supported yet";
    }
    pThis(cd)->m_http_server->respond_OK(cd, EVHTP_RES_OK, resp);
}
#endif

} // namespace homestore