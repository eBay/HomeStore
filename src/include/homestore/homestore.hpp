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

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <map>
#include <vector>

#include <sisl/logging/logging.h>
#include <iomgr/iomgr.hpp>

#include <homestore/homestore_decl.hpp>
#include <homestore/blk.h>

namespace spdlog {
class logger;
} // namespace spdlog

namespace sisl {
class Evictor;
}

namespace homestore {
class DeviceManager;
class ResourceMgr;
class HomeStoreStatusMgr;
class MetaBlkService;
class LogStoreService;
class BlkDataService;
class IndexService;
class ReplicationService;
class IndexServiceCallbacks;
struct vdev_info;
class HomeStore;
class CPManager;
class VirtualDev;
class ChunkSelector;
class ReplDevListener;
class ReplApplication;

using HomeStoreSafePtr = std::shared_ptr< HomeStore >;

VENUM(hs_vdev_type_t, uint32_t, DATA_VDEV = 1, INDEX_VDEV = 2, META_VDEV = 3, DATA_LOGDEV_VDEV = 4,
      CTRL_LOGDEV_VDEV = 5);

#pragma pack(1)
struct hs_vdev_context {
    enum hs_vdev_type_t type;

    sisl::blob to_blob() { return sisl::blob{uintptr_cast(this), sizeof(*this)}; }
};
#pragma pack()

using hs_before_services_starting_cb_t = std::function< void(void) >;

struct hs_stats {
    uint64_t total_capacity{0ul};
    uint64_t used_capacity{0ul};
};

struct HS_SERVICE {
    static constexpr uint32_t META = 1 << 0;
    static constexpr uint32_t LOG_REPLICATED = 1 << 1;
    static constexpr uint32_t LOG_LOCAL = 1 << 2;
    static constexpr uint32_t DATA = 1 << 3;
    static constexpr uint32_t INDEX = 1 << 4;
    static constexpr uint32_t REPLICATION = 1 << 5;

    uint32_t svcs;

    HS_SERVICE() : svcs{META} {}

    std::string list() const {
        std::string str;
        if (svcs & META) { str += "meta,"; }
        if (svcs & DATA) { str += "data,"; }
        if (svcs & INDEX) { str += "index,"; }
        if (svcs & LOG_REPLICATED) { str += "log_replicated,"; }
        if (svcs & LOG_LOCAL) { str += "log_local,"; }
        if (svcs & REPLICATION) { str += "replication,"; }
        return str;
    }
};

/*
 * IO errors handling by homestore.
 * Write error :- Reason :- Disk error, space full,btree node read fail
 *                Handling :- Writeback cache,logdev and meta blk mgr doesn't handle any write errors.
 *                            It panics the system for write errors.
 * Read error :- Reason :- Disk error
 *               Handling :- logdev doesn't support any read error. It panic for read errors.
 * If HS see write error/read error during recovery then it panic the system.
 */

class HomeStore {
private:
    std::unique_ptr< BlkDataService > m_data_service;
    std::unique_ptr< MetaBlkService > m_meta_service;
    std::unique_ptr< LogStoreService > m_log_service;
    std::unique_ptr< IndexService > m_index_service;
    std::shared_ptr< ReplicationService > m_repl_service;

    std::unique_ptr< DeviceManager > m_dev_mgr;
    shared< sisl::logging::logger_t > m_periodic_logger;
    std::unique_ptr< HomeStoreStatusMgr > m_status_mgr;
    std::unique_ptr< ResourceMgr > m_resource_mgr;
    std::unique_ptr< CPManager > m_cp_mgr;
    shared< sisl::Evictor > m_evictor;

    HS_SERVICE m_services; // Services homestore is starting with
    hs_before_services_starting_cb_t m_before_services_starting_cb{nullptr};
    std::atomic< bool > m_init_done{false};

public:
    HomeStore() = default;
    virtual ~HomeStore() = default;

    /////////////////////////////////////////// static HomeStore member functions /////////////////////////////////
    static HomeStoreSafePtr s_instance;

    static void set_instance(const HomeStoreSafePtr& instance) { s_instance = instance; }
    static void reset_instance() { s_instance.reset(); }
    static HomeStore* instance();
    static shared< HomeStore > safe_instance() { return s_instance; }

    static shared< spdlog::logger >& periodic_logger() { return instance()->m_periodic_logger; }

    ///////////////////////////// Member functions /////////////////////////////////////////////
    HomeStore& with_data_service(cshared< ChunkSelector >& custom_chunk_selector = nullptr);
    HomeStore& with_log_service();
    HomeStore& with_index_service(std::unique_ptr< IndexServiceCallbacks > cbs);
    HomeStore& with_repl_data_service(cshared< ReplApplication >& repl_app,
                                      cshared< ChunkSelector >& custom_chunk_selector = nullptr);

    bool start(const hs_input_params& input, hs_before_services_starting_cb_t svcs_starting_cb = nullptr);
    void format_and_start(std::map< uint32_t, hs_format_params >&& format_opts);
    void shutdown();

    // cap_attrs get_system_capacity() const; // Need to move this to homeblks/homeobj
    bool is_first_time_boot() const;
    bool is_initializing() const { return !m_init_done; }

    // Getters
    bool has_index_service() const;
    bool has_data_service() const;
    bool has_meta_service() const;
    bool has_log_service() const;
    bool has_repl_data_service() const;

    BlkDataService& data_service() { return *m_data_service; }
    MetaBlkService& meta_service() { return *m_meta_service; }
    LogStoreService& logstore_service() { return *m_log_service; }
    IndexService& index_service() { return *m_index_service; }
    ReplicationService& repl_service() { return *m_repl_service; }
    DeviceManager* device_mgr() { return m_dev_mgr.get(); }
    ResourceMgr& resource_mgr() { return *m_resource_mgr.get(); }
    CPManager& cp_mgr() { return *m_cp_mgr.get(); }
    shared< sisl::Evictor > evictor() { return m_evictor; }

private:
    void init_cache();
    shared< VirtualDev > create_vdev_cb(const vdev_info& vinfo, bool load_existing);
    uint64_t pct_to_size(float pct, HSDevType dev_type) const;
    void do_start();
};

static HomeStore* hs() { return HomeStore::instance(); }
} // namespace homestore
