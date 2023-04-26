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

std::vector< std::string > HomeBlksHttpServer::m_iface_list;

HomeBlksHttpServer* HomeBlksHttpServer::pThis(iomgr::HttpCallData cd) { return (HomeBlksHttpServer*)cd->cookie(); }
HomeBlks* HomeBlksHttpServer::to_homeblks(iomgr::HttpCallData cd) { return pThis(cd)->m_hb; }

HomeBlksHttpServer::HomeBlksHttpServer(HomeBlks* hb) : m_hb(hb) {
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

void HomeBlksHttpServer::register_api_post_start() {
    // apis that rely on start of homestore to be completed should be added here;
    auto http_server_ptr = ioenvironment.with_http_server().get_http_server();
    http_server_ptr->register_handler_info(
        handler_info("/api/v1/getMetrics", HomeBlksHttpServer::get_metrics, (void*)this));
    http_server_ptr->register_handler_info(
        handler_info("/metrics", HomeBlksHttpServer::get_prometheus_metrics, (void*)this));
}

void HomeBlksHttpServer::start() {
    auto http_server_ptr = ioenvironment.with_http_server().get_http_server();

    http_server_ptr->register_handler_info(
        handler_info("/api/v1/version", HomeBlksHttpServer::get_version, (void*)this));
    http_server_ptr->register_handler_info(
        handler_info("/api/v1/getObjLife", HomeBlksHttpServer::get_obj_life, (void*)this));
    http_server_ptr->register_handler_info(
        handler_info("/api/v1/getLogLevel", HomeBlksHttpServer::get_log_level, (void*)this));
    http_server_ptr->register_handler_info(
        handler_info("/api/v1/setLogLevel", HomeBlksHttpServer::set_log_level, (void*)this));
    http_server_ptr->register_handler_info(
        handler_info("/api/v1/dumpStackTrace", HomeBlksHttpServer::dump_stack_trace, (void*)this));
    http_server_ptr->register_handler_info(
        handler_info("/api/v1/verifyHS", HomeBlksHttpServer::verify_hs, (void*)this));
    http_server_ptr->register_handler_info(
        handler_info("/api/v1/mallocStats", HomeBlksHttpServer::get_malloc_stats, (void*)this));
    http_server_ptr->register_handler_info(
        handler_info("/api/v1/getConfig", HomeBlksHttpServer::get_config, (void*)this));
    http_server_ptr->register_handler_info(
        handler_info("/api/v1/reloadConfig", HomeBlksHttpServer::reload_dynamic_config, (void*)this));
    http_server_ptr->register_handler_info(
        handler_info("/api/v1/getStatus", HomeBlksHttpServer::get_status, (void*)this));
    http_server_ptr->register_handler_info(
        handler_info("/api/v1/verifyBitmap", HomeBlksHttpServer::verify_bitmap, (void*)this));
    http_server_ptr->register_handler_info(
        handler_info("/api/v1/dumpDiskMetaBlks", HomeBlksHttpServer::dump_disk_metablks, (void*)this));
    http_server_ptr->register_handler_info(
        handler_info("/api/v1/verifyMetaBlkStore", HomeBlksHttpServer::verify_metablk_store, (void*)this));
    http_server_ptr->register_handler_info(
        handler_info("/api/v1/wakeupInit", HomeBlksHttpServer::wakeup_init, (void*)this));
    http_server_ptr->register_handler_info(handler_info("/api/v1/copy_vol", HomeBlksHttpServer::copy_vol, (void*)this));
#ifdef _PRERELEASE
    http_server_ptr->register_handler_info(
        handler_info("/api/v1/crashSystem", HomeBlksHttpServer::crash_system, (void*)this));
    http_server_ptr->register_handler_info(
        handler_info("/api/v1/moveVolOffline", HomeBlksHttpServer::move_vol_offline, (void*)this));
    http_server_ptr->register_handler_info(
        handler_info("/api/v1/moveVolOnline", HomeBlksHttpServer::move_vol_online, (void*)this));
#endif
}
bool HomeBlksHttpServer::is_secure_zone() {
    return IM_DYNAMIC_CONFIG(io_env->encryption) || IM_DYNAMIC_CONFIG(io_env->authorization);
}

bool HomeBlksHttpServer::is_local_addr(struct sockaddr* addr) {
    std::string client_ip = inet_ntoa(((struct sockaddr_in*)addr)->sin_addr);
    return (std::find(m_iface_list.begin(), m_iface_list.end(), client_ip) != m_iface_list.end());
}

void HomeBlksHttpServer::get_version(iomgr::HttpCallData cd) {
    if (is_secure_zone() && !is_local_addr(cd->request()->conn->saddr)) {
        ioenvironment.get_http_server()->respond_NOTOK(cd, EVHTP_RES_FORBIDDEN,
                                                       "Access not allowed from external host");
        return;
    }
    auto vers{sisl::VersionMgr::getVersions()};
    std::string ver_str{""};
    for (auto v : vers) {
        ver_str += fmt::format("{0}: {1}; ", v.first, v.second);
    }
    ioenvironment.get_http_server()->respond_OK(cd, EVHTP_RES_OK, ver_str);
}

void HomeBlksHttpServer::get_metrics(iomgr::HttpCallData cd) {
    std::string msg = sisl::MetricsFarm::getInstance().get_result_in_json_string();
    ioenvironment.get_http_server()->respond_OK(cd, EVHTP_RES_OK, msg);
}

void HomeBlksHttpServer::get_prometheus_metrics(iomgr::HttpCallData cd) {
    if (is_secure_zone() && !is_local_addr(cd->request()->conn->saddr)) {
        ioenvironment.get_http_server()->respond_NOTOK(cd, EVHTP_RES_FORBIDDEN,
                                                       "Access not allowed from external host");
        return;
    }
    std::string msg = sisl::MetricsFarm::getInstance().report(sisl::ReportFormat::kTextFormat);
    ioenvironment.get_http_server()->respond_OK(cd, EVHTP_RES_OK, msg);
}

void HomeBlksHttpServer::get_obj_life(iomgr::HttpCallData cd) {
    if (is_secure_zone() && !is_local_addr(cd->request()->conn->saddr)) {
        ioenvironment.get_http_server()->respond_NOTOK(cd, EVHTP_RES_FORBIDDEN,
                                                       "Access not allowed from external host");
        return;
    }
    nlohmann::json j;
    sisl::ObjCounterRegistry::foreach ([&j](const std::string& name, int64_t created, int64_t alive) {
        std::stringstream ss;
        ss << "created=" << created << " alive=" << alive;
        j[name] = ss.str();
    });
    ioenvironment.get_http_server()->respond_OK(cd, EVHTP_RES_OK, j.dump());
}

void HomeBlksHttpServer::set_log_level(iomgr::HttpCallData cd) {
    if (is_secure_zone() && !is_local_addr(cd->request()->conn->saddr)) {
        ioenvironment.get_http_server()->respond_NOTOK(cd, EVHTP_RES_FORBIDDEN,
                                                       "Access not allowed from external host");
        return;
    }
    auto req = cd->request();

    const evhtp_kv_t* _new_log_level = nullptr;
    const evhtp_kv_t* _new_log_module = nullptr;
    const char* logmodule = nullptr;
    char* endptr = nullptr;

    _new_log_module = evhtp_kvs_find_kv(req->uri->query, "logmodule");
    if (_new_log_module) { logmodule = _new_log_module->val; }

    _new_log_level = evhtp_kvs_find_kv(req->uri->query, "loglevel");
    if (!_new_log_level) {
        ioenvironment.get_http_server()->respond_NOTOK(cd, EVHTP_RES_BADREQ, "Invalid loglevel param!");
        return;
    }
    auto new_log_level = _new_log_level->val;

    std::string resp = "";
    if (logmodule == nullptr) {
        sisl::logging::SetAllModuleLogLevel(spdlog::level::from_str(new_log_level));
        resp = sisl::logging::GetAllModuleLogLevel().dump(2);
    } else {
        sisl::logging::SetModuleLogLevel(logmodule, spdlog::level::from_str(new_log_level));
        resp = std::string("logmodule ") + logmodule + " level set to " +
            spdlog::level::to_string_view(sisl::logging::GetModuleLogLevel(logmodule)).data();
    }

    ioenvironment.get_http_server()->respond_OK(cd, EVHTP_RES_OK, resp);
}

void HomeBlksHttpServer::get_log_level(iomgr::HttpCallData cd) {
    if (is_secure_zone() && !is_local_addr(cd->request()->conn->saddr)) {
        ioenvironment.get_http_server()->respond_NOTOK(cd, EVHTP_RES_FORBIDDEN,
                                                       "Access not allowed from external host");
        return;
    }
    auto req = cd->request();

    const evhtp_kv_t* _log_module = nullptr;
    const char* logmodule = nullptr;
    _log_module = evhtp_kvs_find_kv(req->uri->query, "logmodule");
    if (_log_module) { logmodule = _log_module->val; }

    std::string resp = "";
    if (logmodule == nullptr) {
        resp = sisl::logging::GetAllModuleLogLevel().dump(2);
    } else {
        resp = std::string("logmodule ") + logmodule +
            " level = " + spdlog::level::to_string_view(sisl::logging::GetModuleLogLevel(logmodule)).data();
    }
    ioenvironment.get_http_server()->respond_OK(cd, EVHTP_RES_OK, resp);
}

void HomeBlksHttpServer::dump_stack_trace(iomgr::HttpCallData cd) {
    if (!is_local_addr(cd->request()->conn->saddr)) {
        ioenvironment.get_http_server()->respond_NOTOK(cd, EVHTP_RES_FORBIDDEN,
                                                       "Access not allowed from external host");
        return;
    }

    sisl::logging::log_stack_trace(true);
    ioenvironment.get_http_server()->respond_OK(cd, EVHTP_RES_OK, "Look for stack trace in the log file");
}

void HomeBlksHttpServer::get_malloc_stats(iomgr::HttpCallData cd) {
    if (is_secure_zone() && !is_local_addr(cd->request()->conn->saddr)) {
        ioenvironment.get_http_server()->respond_NOTOK(cd, EVHTP_RES_FORBIDDEN,
                                                       "Access not allowed from external host");
        return;
    }
    ioenvironment.get_http_server()->respond_OK(cd, EVHTP_RES_OK, sisl::get_malloc_stats_detailed().dump(2));
}

void HomeBlksHttpServer::verify_hs(iomgr::HttpCallData cd) {
    if (!is_local_addr(cd->request()->conn->saddr)) {
        ioenvironment.get_http_server()->respond_NOTOK(cd, EVHTP_RES_FORBIDDEN,
                                                       "Access not allowed from external host");
        return;
    }

    auto hb = to_homeblks(cd);
    auto ret = hb->verify_vols();
    std::string resp{"HomeBlks verified "};
    resp += ret ? "successfully" : "failed";
    ioenvironment.get_http_server()->respond_OK(cd, EVHTP_RES_OK, resp);
}

void HomeBlksHttpServer::get_config(iomgr::HttpCallData cd) {
    if (is_secure_zone() && !is_local_addr(cd->request()->conn->saddr)) {
        ioenvironment.get_http_server()->respond_NOTOK(cd, EVHTP_RES_FORBIDDEN,
                                                       "Access not allowed from external host");
        return;
    }
    nlohmann::json j;
    j = sisl::SettingsFactoryRegistry::instance().get_json();
    j["static"] = homestore::HomeStoreStaticConfig::instance().to_json();
    ioenvironment.get_http_server()->respond_OK(cd, EVHTP_RES_OK, j.dump(2));
}

void HomeBlksHttpServer::reload_dynamic_config(iomgr::HttpCallData cd) {
    if (!is_local_addr(cd->request()->conn->saddr)) {
        ioenvironment.get_http_server()->respond_NOTOK(cd, EVHTP_RES_FORBIDDEN,
                                                       "Access not allowed from external host");
        return;
    }

    bool restart_needed = sisl::SettingsFactoryRegistry::instance().reload_all();
    ioenvironment.get_http_server()->respond_OK(
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

void HomeBlksHttpServer::verify_metablk_store(iomgr::HttpCallData cd) {
    if (is_secure_zone() && !is_local_addr(cd->request()->conn->saddr)) {
        ioenvironment.get_http_server()->respond_NOTOK(cd, EVHTP_RES_FORBIDDEN,
                                                       "Access not allowed from external host");
        return;
    }
    auto req = cd->request();

    const auto hb = to_homeblks(cd);
    if (hb->is_safe_mode()) {
        const auto ret = hb->verify_metablk_store();
        ioenvironment.get_http_server()->respond_OK(
            cd, EVHTP_RES_OK, fmt::format("Disk sanity of MetaBlkStore result: {}", ret ? "Passed" : "Failed"));
    } else {
        ioenvironment.get_http_server()->respond_NOTOK(
            cd, EVHTP_RES_BADREQ, fmt::format("HomeBlks not in safe mode, not allowed to serve this request"));
    }
}

void HomeBlksHttpServer::dump_disk_metablks(iomgr::HttpCallData cd) {
    if (is_secure_zone() && !is_local_addr(cd->request()->conn->saddr)) {
        ioenvironment.get_http_server()->respond_NOTOK(cd, EVHTP_RES_FORBIDDEN,
                                                       "Access not allowed from external host");
        return;
    }
    auto req = cd->request();

    std::vector< std::string > clients;
    auto modules_kv = evhtp_kvs_find_kv(req->uri->query, "client");
    if (modules_kv) {
        boost::algorithm::split(clients, modules_kv->val, boost::is_any_of(","), boost::token_compress_on);
    }

    if (clients.size() != 1) {
        ioenvironment.get_http_server()->respond_NOTOK(
            cd, EVHTP_RES_BADREQ,
            fmt::format("Can serve only one client per request. Number clients received: {}\n", clients.size()));
        return;
    }

    const auto hb = to_homeblks(cd);
    if (hb->is_safe_mode()) {
        const auto j = to_homeblks(cd)->dump_disk_metablks(clients[0]);
        ioenvironment.get_http_server()->respond_OK(cd, EVHTP_RES_OK, j.dump(2));
    } else {
        ioenvironment.get_http_server()->respond_NOTOK(
            cd, EVHTP_RES_BADREQ, fmt::format("HomeBlks not in safe mode, not allowed to serve this request"));
    }
}

void HomeBlksHttpServer::get_status(iomgr::HttpCallData cd) {
    if (is_secure_zone() && !is_local_addr(cd->request()->conn->saddr)) {
        ioenvironment.get_http_server()->respond_NOTOK(cd, EVHTP_RES_FORBIDDEN,
                                                       "Access not allowed from external host");
        return;
    }
    auto req = cd->request();

    std::vector< std::string > modules;
    auto modules_kv = evhtp_kvs_find_kv(req->uri->query, "module");
    if (modules_kv) {
        boost::algorithm::split(modules, modules_kv->val, boost::is_any_of(","), boost::token_compress_on);
    }

    std::string failure_resp{""};
    int verbosity_level{-1};
    if (!verify_and_get_verbosity(req, failure_resp, verbosity_level)) {
        ioenvironment.get_http_server()->respond_NOTOK(cd, EVHTP_RES_BADREQ, failure_resp);
        return;
    }

    const auto status_mgr = to_homeblks(cd)->status_mgr();
    auto status_json = status_mgr->get_status(modules, verbosity_level);
    ioenvironment.get_http_server()->respond_OK(cd, EVHTP_RES_OK, status_json.dump(2));
}

void HomeBlksHttpServer::verify_bitmap(iomgr::HttpCallData cd) {
    if (!is_local_addr(cd->request()->conn->saddr)) {
        ioenvironment.get_http_server()->respond_NOTOK(cd, EVHTP_RES_FORBIDDEN,
                                                       "Access not allowed from external host");
        return;
    }

    auto hb = to_homeblks(cd);
    auto ret = hb->verify_bitmap();
    std::string resp{"HomeBlks bitmap verified "};
    resp += ret ? "successfully" : "failed";
    ioenvironment.get_http_server()->respond_OK(cd, EVHTP_RES_OK, resp);
}

void HomeBlksHttpServer::wakeup_init(iomgr::HttpCallData cd) {
    if (is_secure_zone() && !is_local_addr(cd->request()->conn->saddr)) {
        ioenvironment.get_http_server()->respond_NOTOK(cd, EVHTP_RES_FORBIDDEN,
                                                       "Access not allowed from external host");
        return;
    }
    auto hb = to_homeblks(cd);
    hb->wakeup_init();
    std::string resp{"completed"};
    ioenvironment.get_http_server()->respond_OK(cd, EVHTP_RES_OK, resp);
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
void HomeBlksHttpServer::crash_system(iomgr::HttpCallData cd) {
    if (is_secure_zone() && !is_local_addr(cd->request()->conn->saddr)) {
        ioenvironment.get_http_server()->respond_NOTOK(cd, EVHTP_RES_FORBIDDEN,
                                                       "Access not allowed from external host");
        return;
    }
    auto req{cd->request()};

    const evhtp_kv_t* _crash_type{nullptr};
    std::string crash_type;
    _crash_type = evhtp_kvs_find_kv(req->uri->query, "type");
    if (_crash_type) { crash_type = _crash_type->val; }

    std::string resp = "";
    if (crash_type.empty() || boost::iequals(crash_type, "assert")) {
        HS_REL_ASSERT(0, "Fake Assert in response to an http request");
    } else if (boost::iequals(crash_type, "segv")) {
        int* x{nullptr};
        LOGINFO("Simulating a segv with dereferencing nullptr={}", *x);
    } else {
        resp = "crash type " + crash_type + " not supported yet";
    }
    ioenvironment.get_http_server()->respond_OK(cd, EVHTP_RES_OK, resp);
}

void HomeBlksHttpServer::move_vol_online(iomgr::HttpCallData cd) {
    if (is_secure_zone() && !is_local_addr(cd->request()->conn->saddr)) {
        ioenvironment.get_http_server()->respond_NOTOK(cd, EVHTP_RES_FORBIDDEN,
                                                       "Access not allowed from external host");
        return;
    }
    auto req = cd->request();

    std::string vol_uuid;
    const evhtp_kv_t* _vol_uuid = evhtp_kvs_find_kv(req->uri->query, "uuid");
    if (_vol_uuid) { vol_uuid = _vol_uuid->val; }

    if (vol_uuid.length() == 0) {
        ioenvironment.get_http_server()->respond_NOTOK(cd, EVHTP_RES_BADREQ, std::string("empty vol_uuid!"));
        return;
    }

    boost::uuids::string_generator gen;
    boost::uuids::uuid uuid = gen(vol_uuid);
    auto hb = to_homeblks(cd);
    auto res = hb->mark_vol_online(uuid);
    std::string resp{"Vol: " + vol_uuid + " moved to online state "};

    resp += (res == no_error ? "successfully" : "failed");
    if (res != no_error) { resp += ("error: " + res.message()); }
    ioenvironment.get_http_server()->respond_OK(cd, EVHTP_RES_OK, resp);
}

void HomeBlksHttpServer::move_vol_offline(iomgr::HttpCallData cd) {
    if (is_secure_zone() && !is_local_addr(cd->request()->conn->saddr)) {
        ioenvironment.get_http_server()->respond_NOTOK(cd, EVHTP_RES_FORBIDDEN,
                                                       "Access not allowed from external host");
        return;
    }
    auto req = cd->request();

    std::string vol_uuid;
    const evhtp_kv_t* _vol_uuid = evhtp_kvs_find_kv(req->uri->query, "uuid");
    if (_vol_uuid) { vol_uuid = _vol_uuid->val; }

    if (vol_uuid.length() == 0) {
        ioenvironment.get_http_server()->respond_NOTOK(cd, EVHTP_RES_BADREQ, std::string("empty vol_uuid!"));
        return;
    }

    boost::uuids::string_generator gen;
    boost::uuids::uuid uuid = gen(vol_uuid);
    auto hb = to_homeblks(cd);
    auto res = hb->mark_vol_offline(uuid);
    std::string resp{"Vol: " + vol_uuid + " moved to offline state "};

    resp += (res == no_error ? "successfully" : "failed");
    if (res != no_error) { resp += ("error: " + res.message()); }
    ioenvironment.get_http_server()->respond_OK(cd, EVHTP_RES_OK, resp);
}
#endif

} // namespace homestore
