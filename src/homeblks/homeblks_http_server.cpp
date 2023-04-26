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

HomeBlksHttpServer::HomeBlksHttpServer(HomeBlks* hb) : m_hb(hb) { setup_routes(); }

void HomeBlksHttpServer::register_api_post_start() {
    // apis that rely on start of homestore to be completed should be added here;
    auto http_server_ptr = ioenvironment.get_http_server();
    try {
        http_server_ptr->setup_route(Pistache::Http::Method::Get, "/api/v1/getMetrics",
                                     Pistache::Rest::Routes::bind(&HomeBlksHttpServer::get_metrics, this));
        http_server_ptr->setup_route(Pistache::Http::Method::Get, "/metrics",
                                     Pistache::Rest::Routes::bind(&HomeBlksHttpServer::get_prometheus_metrics, this),
                                     iomgr::url_t::safe);
    } catch (const std::runtime_error& e) { LOGWARN("{}", e.what()) }
}

void HomeBlksHttpServer::start() { ioenvironment.get_http_server()->start(); }

void HomeBlksHttpServer::setup_routes() {
    using namespace Pistache;
    using namespace Pistache::Rest;
    auto http_server_ptr = ioenvironment.with_http_server().get_http_server();
    try {
        http_server_ptr->setup_route(Http::Method::Get, "/api/v1/version",
                                     Routes::bind(&HomeBlksHttpServer::get_version, this));
        http_server_ptr->setup_route(Http::Method::Get, "/api/v1/getObjLife",
                                     Routes::bind(&HomeBlksHttpServer::get_obj_life, this));
        http_server_ptr->setup_route(Http::Method::Get, "/api/v1/getLogLevel",
                                     Routes::bind(&HomeBlksHttpServer::get_log_level, this));
        http_server_ptr->setup_route(Http::Method::Post, "/api/v1/setLogLevel",
                                     Routes::bind(&HomeBlksHttpServer::set_log_level, this));
        http_server_ptr->setup_route(Http::Method::Get, "/api/v1/dumpStackTrace",
                                     Routes::bind(&HomeBlksHttpServer::dump_stack_trace, this),
                                     iomgr::url_t::localhost);
        http_server_ptr->setup_route(Http::Method::Get, "/api/v1/verifyHS",
                                     Routes::bind(&HomeBlksHttpServer::verify_hs, this), iomgr::url_t::localhost);
        http_server_ptr->setup_route(Http::Method::Get, "/api/v1/mallocStats",
                                     Routes::bind(&HomeBlksHttpServer::get_malloc_stats, this));
        http_server_ptr->setup_route(Http::Method::Get, "/api/v1/getConfig",
                                     Routes::bind(&HomeBlksHttpServer::get_config, this));
        http_server_ptr->setup_route(Http::Method::Post, "/api/v1/reloadConfig",
                                     Routes::bind(&HomeBlksHttpServer::reload_dynamic_config, this),
                                     iomgr::url_t::localhost);
        http_server_ptr->setup_route(Http::Method::Get, "/api/v1/getStatus",
                                     Routes::bind(&HomeBlksHttpServer::get_status, this));
        http_server_ptr->setup_route(Http::Method::Get, "/api/v1/verifyBitmap",
                                     Routes::bind(&HomeBlksHttpServer::verify_bitmap, this), iomgr::url_t::localhost);
        http_server_ptr->setup_route(Http::Method::Get, "/api/v1/dumpDiskMetaBlks",
                                     Routes::bind(&HomeBlksHttpServer::dump_disk_metablks, this));
        http_server_ptr->setup_route(Http::Method::Get, "/api/v1/verifyMetaBlkStore",
                                     Routes::bind(&HomeBlksHttpServer::verify_metablk_store, this));
        http_server_ptr->setup_route(Http::Method::Post, "/api/v1/wakeupInit",
                                     Routes::bind(&HomeBlksHttpServer::wakeup_init, this));
        http_server_ptr->setup_route(Http::Method::Post, "/api/v1/copy_vol",
                                     Routes::bind(&HomeBlksHttpServer::copy_vol, this));
#ifdef _PRERELEASE
        http_server_ptr->setup_route(Http::Method::Post, "/api/v1/crashSystem",
                                     Routes::bind(&HomeBlksHttpServer::crash_system, this));
        http_server_ptr->setup_route(Http::Method::Post, "/api/v1/moveVolOffline",
                                     Routes::bind(&HomeBlksHttpServer::move_vol_offline, this));
        http_server_ptr->setup_route(Http::Method::Post, "/api/v1/moveVolOnline",
                                     Routes::bind(&HomeBlksHttpServer::move_vol_online, this));
#endif
    } catch (const std::runtime_error& e) { LOGWARN("{}", e.what()) }
}

void HomeBlksHttpServer::get_version(const Pistache::Rest::Request& request, Pistache::Http::ResponseWriter response) {
    auto vers{sisl::VersionMgr::getVersions()};
    std::string ver_str{""};
    for (auto v : vers) {
        ver_str += fmt::format("{0}: {1}; ", v.first, v.second);
    }
    response.send(Pistache::Http::Code::Ok, ver_str);
}

void HomeBlksHttpServer::get_metrics(const Pistache::Rest::Request& request, Pistache::Http::ResponseWriter response) {
    std::string msg = sisl::MetricsFarm::getInstance().get_result_in_json_string();
    response.send(Pistache::Http::Code::Ok, msg);
}

void HomeBlksHttpServer::get_prometheus_metrics(const Pistache::Rest::Request& request,
                                                Pistache::Http::ResponseWriter response) {
    std::string msg = sisl::MetricsFarm::getInstance().report(sisl::ReportFormat::kTextFormat);
    response.send(Pistache::Http::Code::Ok, msg);
}

void HomeBlksHttpServer::get_obj_life(const Pistache::Rest::Request& request, Pistache::Http::ResponseWriter response) {
    nlohmann::json j;
    sisl::ObjCounterRegistry::foreach ([&j](const std::string& name, int64_t created, int64_t alive) {
        std::stringstream ss;
        ss << "created=" << created << " alive=" << alive;
        j[name] = ss.str();
    });
    response.send(Pistache::Http::Code::Ok, j.dump());
}

void HomeBlksHttpServer::set_log_level(const Pistache::Rest::Request& request,
                                       Pistache::Http::ResponseWriter response) {
    std::string logmodule;
    const auto _new_log_module{request.query().get("logmodule")};
    if (_new_log_module) { logmodule = _new_log_module.value(); }

    const auto _new_log_level{request.query().get("loglevel")};
    if (!_new_log_level) {
        response.send(Pistache::Http::Code::Bad_Request, "Invalid loglevel param!");
        return;
    }
    auto new_log_level = _new_log_level.value();

    std::string resp;
    if (logmodule.empty()) {
        sisl::logging::SetAllModuleLogLevel(spdlog::level::from_str(new_log_level));
        resp = sisl::logging::GetAllModuleLogLevel().dump(2);
    } else {
        sisl::logging::SetModuleLogLevel(logmodule, spdlog::level::from_str(new_log_level));
        resp = std::string("logmodule ") + logmodule + " level set to " +
            spdlog::level::to_string_view(sisl::logging::GetModuleLogLevel(logmodule)).data();
    }

    response.send(Pistache::Http::Code::Ok, resp);
}

void HomeBlksHttpServer::get_log_level(const Pistache::Rest::Request& request,
                                       Pistache::Http::ResponseWriter response) {
    std::string logmodule;
    const auto _new_log_module{request.query().get("logmodule")};
    if (_new_log_module) { logmodule = _new_log_module.value(); }

    std::string resp;
    if (logmodule.empty()) {
        resp = sisl::logging::GetAllModuleLogLevel().dump(2);
    } else {
        resp = std::string("logmodule ") + logmodule +
            " level = " + spdlog::level::to_string_view(sisl::logging::GetModuleLogLevel(logmodule)).data();
    }
    response.send(Pistache::Http::Code::Ok, resp);
}

void HomeBlksHttpServer::dump_stack_trace(const Pistache::Rest::Request& request,
                                          Pistache::Http::ResponseWriter response) {
    sisl::logging::log_stack_trace(true);
    response.send(Pistache::Http::Code::Ok, "Look for stack trace in the log file");
}

void HomeBlksHttpServer::get_malloc_stats(const Pistache::Rest::Request& request,
                                          Pistache::Http::ResponseWriter response) {
    response.send(Pistache::Http::Code::Ok, sisl::get_malloc_stats_detailed().dump(2));
}

void HomeBlksHttpServer::verify_hs(const Pistache::Rest::Request& request, Pistache::Http::ResponseWriter response) {
    auto ret = m_hb->verify_vols();
    std::string resp{"HomeBlks verified "};
    resp += ret ? "successfully" : "failed";
    response.send(Pistache::Http::Code::Ok, resp);
}

void HomeBlksHttpServer::get_config(const Pistache::Rest::Request& request, Pistache::Http::ResponseWriter response) {
    nlohmann::json j;
    j = sisl::SettingsFactoryRegistry::instance().get_json();
    j["static"] = homestore::HomeStoreStaticConfig::instance().to_json();
    response.send(Pistache::Http::Code::Ok, j.dump(2));
}

void HomeBlksHttpServer::reload_dynamic_config(const Pistache::Rest::Request& request,
                                               Pistache::Http::ResponseWriter response) {
    bool restart_needed = sisl::SettingsFactoryRegistry::instance().reload_all();
    response.send(Pistache::Http::Code::Ok,
                  fmt::format("All config reloaded, is app restarted {}\n", (restart_needed ? "true" : "false")));
    if (restart_needed) {
        LOGINFO("Restarting HomeBlks because of config change which needed a restart");
        std::this_thread::sleep_for(std::chrono::microseconds{1000});
        std::raise(SIGTERM);
    }
}

bool HomeBlksHttpServer::verify_and_get_verbosity(const Pistache::Rest::Request& request, std::string& failure_resp,
                                                  int& verbosity_level) {
    bool ret{true};
    const auto verbosity_kv{request.query().get("verbosity")};
    if (verbosity_kv) {
        try {
            verbosity_level = std::stoi(verbosity_kv.value());
        } catch (...) {
            failure_resp = fmt::format("{} is not a valid verbosity level", verbosity_kv.value());
            ret = false;
        }
    } else {
        verbosity_level = 0; // default verbosity level
    }
    return ret;
}

void HomeBlksHttpServer::verify_metablk_store(const Pistache::Rest::Request& request,
                                              Pistache::Http::ResponseWriter response) {
    if (m_hb->is_safe_mode()) {
        const auto ret = m_hb->verify_metablk_store();
        response.send(Pistache::Http::Code::Ok,
                      fmt::format("Disk sanity of MetaBlkStore result: {}", ret ? "Passed" : "Failed"));
    } else {
        response.send(Pistache::Http::Code::Bad_Request,
                      "HomeBlks not in safe mode, not allowed to serve this request");
    }
}

void HomeBlksHttpServer::dump_disk_metablks(const Pistache::Rest::Request& request,
                                            Pistache::Http::ResponseWriter response) {
    std::vector< std::string > clients;
    const auto modules_kv{request.query().get("client")};
    if (modules_kv) {
        boost::algorithm::split(clients, modules_kv.value(), boost::is_any_of(","), boost::token_compress_on);
    }

    if (clients.size() != 1) {
        response.send(
            Pistache::Http::Code::Bad_Request,
            fmt::format("Can serve only one client per request. Number clients received: {}\n", clients.size()));
        return;
    }

    if (m_hb->is_safe_mode()) {
        const auto j = m_hb->dump_disk_metablks(clients[0]);
        response.send(Pistache::Http::Code::Ok, j.dump(2));
    } else {
        response.send(Pistache::Http::Code::Bad_Request,
                      "HomeBlks not in safe mode, not allowed to serve this request");
    }
}

void HomeBlksHttpServer::get_status(const Pistache::Rest::Request& request, Pistache::Http::ResponseWriter response) {
    std::vector< std::string > modules;
    const auto modules_kv{request.query().get("module")};
    if (modules_kv) {
        boost::algorithm::split(modules, modules_kv.value(), boost::is_any_of(","), boost::token_compress_on);
    }

    std::string failure_resp{""};
    int verbosity_level{-1};
    if (!verify_and_get_verbosity(request, failure_resp, verbosity_level)) {
        response.send(Pistache::Http::Code::Bad_Request, failure_resp);
        return;
    }

    const auto status_mgr = m_hb->status_mgr();
    auto status_json = status_mgr->get_status(modules, verbosity_level);
    response.send(Pistache::Http::Code::Ok, status_json.dump(2));
}

void HomeBlksHttpServer::verify_bitmap(const Pistache::Rest::Request& request,
                                       Pistache::Http::ResponseWriter response) {
    auto ret = m_hb->verify_bitmap();
    response.send(Pistache::Http::Code::Ok,
                  fmt::format("HomeBlks bitmap verified {}", ret ? "successfully" : "failed"));
}

void HomeBlksHttpServer::wakeup_init(const Pistache::Rest::Request& request, Pistache::Http::ResponseWriter response) {
    m_hb->wakeup_init();
    response.send(Pistache::Http::Code::Ok, "completed");
}

void HomeBlksHttpServer::copy_vol(iomgr::HttpCallData cd) {
    if (is_secure_zone() && !is_local_addr(cd->request()->conn->saddr)) {
        ioenvironment.get_http_server()->respond_NOTOK(cd, EVHTP_RES_FORBIDDEN,
                                                       "Access not allowed from external host");
        return;
    }
    auto req = cd->request();

    std::vector< std::string > vol_uuids;
    auto vol_uuids_kv = evhtp_kvs_find_kv(req->uri->query, "uuid");
    if (vol_uuids_kv) {
        boost::algorithm::split(vol_uuids, vol_uuids_kv->val, boost::is_any_of(","), boost::token_compress_on);
    }

    std::vector< std::string > write_path;
    auto write_path_kv = evhtp_kvs_find_kv(req->uri->query, "path");
    if (write_path_kv) {
        boost::algorithm::split(write_path, write_path_kv->val, boost::is_any_of(","), boost::token_compress_on);
    }

    std::string resp{"volume write to path: " + write_path[0] + " , file name: " + vol_uuids[0]};
    auto hb = to_homeblks(cd);

    //
    // TODO: error condition:
    // 0. only take one vol uuid and one write path;
    // 1. return error if uuid file already exists;
    // 2. vol uuid not recognized;
    // 3. check disk free space before copying;
    //
    boost::uuids::string_generator gen;
    boost::uuids::uuid uuid = gen(vol_uuids[0]);

    // TODO: remove tailing / of write_path[0] if there is any;
    const auto file_path = write_path[0] + "/" + vol_uuids[0];
    const auto err = hb->copy_vol(uuid, file_path);

    resp += (err == no_error ? " Successfully" : " Failed");
    ioenvironment.get_http_server()->respond_OK(cd, EVHTP_RES_OK, resp);
}

#ifdef _PRERELEASE
void HomeBlksHttpServer::crash_system(const Pistache::Rest::Request& request, Pistache::Http::ResponseWriter response) {
    std::string crash_type;
    const auto _crash_type{request.query().get("type")};
    if (_crash_type) { crash_type = _crash_type.value(); }

    std::string resp = "";
    if (crash_type.empty() || boost::iequals(crash_type, "assert")) {
        HS_REL_ASSERT(0, "Fake Assert in response to an http request");
    } else if (boost::iequals(crash_type, "segv")) {
        int* x{nullptr};
        LOGINFO("Simulating a segv with dereferencing nullptr={}", *x);
    } else {
        resp = "crash type " + crash_type + " not supported yet";
    }
    response.send(Pistache::Http::Code::Ok, resp);
}

void HomeBlksHttpServer::move_vol_online(const Pistache::Rest::Request& request,
                                         Pistache::Http::ResponseWriter response) {
    std::string vol_uuid;
    const auto _vol_uuid{request.query().get("uuid")};
    if (_vol_uuid) { vol_uuid = _vol_uuid.value(); }

    if (vol_uuid.length() == 0) {
        response.send(Pistache::Http::Code::Bad_Request, "empty vol_uuid!");
        return;
    }

    boost::uuids::string_generator gen;
    boost::uuids::uuid uuid = gen(vol_uuid);
    auto res = m_hb->mark_vol_online(uuid);
    std::string resp{"Vol: " + vol_uuid + " moved to online state "};

    resp += (res == no_error ? "successfully" : "failed");
    if (res != no_error) { resp += ("error: " + res.message()); }
    response.send(Pistache::Http::Code::Ok, resp);
}

void HomeBlksHttpServer::move_vol_offline(const Pistache::Rest::Request& request,
                                          Pistache::Http::ResponseWriter response) {
    std::string vol_uuid;
    const auto _vol_uuid{request.query().get("uuid")};
    if (_vol_uuid) { vol_uuid = _vol_uuid.value(); }

    if (vol_uuid.length() == 0) {
        response.send(Pistache::Http::Code::Bad_Request, "empty vol_uuid!");
        return;
    }

    boost::uuids::string_generator gen;
    boost::uuids::uuid uuid = gen(vol_uuid);
    auto res = m_hb->mark_vol_offline(uuid);
    std::string resp{"Vol: " + vol_uuid + " moved to offline state "};

    resp += (res == no_error ? "successfully" : "failed");
    if (res != no_error) { resp += ("error: " + res.message()); }
    response.send(Pistache::Http::Code::Ok, resp);
}
#endif

} // namespace homestore
