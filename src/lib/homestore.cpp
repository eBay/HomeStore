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
#include <cstdint>
#include <mutex>
#include <stdexcept>
#include <boost/intrusive_ptr.hpp>

#include <sisl/fds/malloc_helper.hpp>
#include <sisl/fds/buffer.hpp>
#include <sisl/logging/logging.h>
#include <sisl/cache/lru_evictor.hpp>

#include <homestore/blkdata_service.hpp>
#include <homestore/meta_service.hpp>
#include <homestore/logstore_service.hpp>
#include <homestore/index_service.hpp>
#include <homestore/homestore.hpp>
#include <homestore/checkpoint/cp_mgr.hpp>

#include "index/wb_cache.hpp"
#include "common/homestore_utils.hpp"
#include "common/homestore_config.hpp"
#include "common/homestore_assert.hpp"
#include "common/homestore_status_mgr.hpp"
#include "device/physical_dev.hpp"
#include "device/device.h"
#include "device/virtual_dev.hpp"
#include "common/resource_mgr.hpp"
#include "meta/meta_sb.hpp"
#include "replication/service/generic_repl_svc.h"
#include "common/crash_simulator.hpp"

/*
 * IO errors handling by homestore.
 * Write error :- Reason :- Disk error, space full,btree node read fail
 *                Handling :- Writeback cache,logdev and meta blk mgr doesn't handle any write errors.
 *                            It panics the system for write errors.
 * Read error :- Reason :- Disk error
 *               Handling :- logdev doesn't support any read error. It panic for read errors.
 * If HS see write error/read error during recovery then it panic the system.
 */
namespace homestore {
HomeStoreSafePtr HomeStore::s_instance{nullptr};

static std::unique_ptr< IndexServiceCallbacks > s_index_cbs;
static shared< ChunkSelector > s_custom_chunk_selector{nullptr};
static shared< ReplApplication > s_repl_app{nullptr};

HomeStore* HomeStore::instance() {
    if (s_instance == nullptr) { s_instance = std::make_shared< HomeStore >(); }
    return s_instance.get();
}

HomeStore& HomeStore::with_data_service(cshared< ChunkSelector >& custom_chunk_selector) {
    m_services.svcs |= HS_SERVICE::DATA;
    m_services.svcs &= ~HS_SERVICE::REPLICATION; // ReplicationDataSvc or DataSvc are mutually exclusive
    s_custom_chunk_selector = std::move(custom_chunk_selector);
    return *this;
}

HomeStore& HomeStore::with_index_service(std::unique_ptr< IndexServiceCallbacks > cbs) {
    m_services.svcs |= HS_SERVICE::INDEX;
    s_index_cbs = std::move(cbs);
    return *this;
}

HomeStore& HomeStore::with_log_service() {
    m_services.svcs |= HS_SERVICE::LOG;
    return *this;
}

HomeStore& HomeStore::with_repl_data_service(cshared< ReplApplication >& repl_app,
                                             cshared< ChunkSelector >& custom_chunk_selector) {
    m_services.svcs |= HS_SERVICE::REPLICATION | HS_SERVICE::LOG;
    m_services.svcs &= ~HS_SERVICE::DATA; // ReplicationDataSvc or DataSvc are mutually exclusive
    s_repl_app = repl_app;
    s_custom_chunk_selector = std::move(custom_chunk_selector);
    return *this;
}

#ifdef _PRERELEASE
HomeStore& HomeStore::with_crash_simulator(std::function< void(void) > cb) {
    m_crash_simulator = std::make_unique< CrashSimulator >(std::move(cb));
    return *this;
}
#endif

bool HomeStore::start(const hs_input_params& input, hs_before_services_starting_cb_t svcs_starting_cb) {
    auto& hs_config = HomeStoreStaticConfig::instance();
    hs_config.input = input;

    if (input.devices.empty()) {
        LOGERROR("No devices provided to start homestore");
        throw std::invalid_argument("null device list");
    }

    m_before_services_starting_cb = std::move(svcs_starting_cb);

    ///////////// Startup resource status and other manager outside core services /////////////////////////
    sisl::ObjCounterRegistry::enable_metrics_reporting();
    sisl::MallocMetrics::enable();
    m_status_mgr = std::make_unique< HomeStoreStatusMgr >();
    m_resource_mgr = std::make_unique< ResourceMgr >();

#ifdef _PRERELEASE
    flip::Flip::instance().start_rpc_server();
#endif

    static std::once_flag flag1;
    std::call_once(flag1, [this]() {
        m_periodic_logger =
            sisl::logging::CreateCustomLogger("homestore", "_periodic", false, true /* tee_to_stdout_stderr */);
        sisl::logging::SetLogPattern("[%D %T.%f] [%^%L%$] [%t] %v", m_periodic_logger);
    });

    HomeStoreDynamicConfig::init_settings_default();

#ifdef _PRERELEASE
    // Start a default crash simulator which raises SIGKILL, in case user has not provided with_crash_simulator()
    // callback
    if (m_crash_simulator == nullptr) { m_crash_simulator = std::make_unique< CrashSimulator >(nullptr); }
#endif

    LOGINFO("Homestore is loading with following services: {}", m_services.list());
    if (has_meta_service()) { m_meta_service = std::make_unique< MetaBlkService >(); }
    if (has_index_service()) { m_index_service = std::make_unique< IndexService >(std::move(s_index_cbs)); }
    if (has_repl_data_service()) {
        m_log_service = std::make_unique< LogStoreService >();
        m_data_service = std::make_unique< BlkDataService >(std::move(s_custom_chunk_selector));
        m_repl_service = GenericReplService::create(std::move(s_repl_app));
    } else {
        if (has_log_service()) { m_log_service = std::make_unique< LogStoreService >(); }
        if (has_data_service()) {
            m_data_service = std::make_unique< BlkDataService >(std::move(s_custom_chunk_selector));
        }
    }
    m_cp_mgr = std::make_unique< CPManager >();
    m_dev_mgr = std::make_unique< DeviceManager >(input.devices, bind_this(HomeStore::create_vdev_cb, 2));

    if (!m_dev_mgr->is_first_time_boot()) {
        m_dev_mgr->load_devices();
        if (input.has_fast_dev()) {
            hs_utils::set_btree_mempool_size(m_dev_mgr->atomic_page_size({HSDevType::Fast}));
        } else {
            hs_utils::set_btree_mempool_size(m_dev_mgr->atomic_page_size({HSDevType::Data}));
        }
        do_start();
        return false;
    } else {
        return true;
    }
}

void HomeStore::format_and_start(std::map< uint32_t, hs_format_params >&& format_opts) {
    std::map< HSDevType, float > total_pct_by_type = {{HSDevType::Fast, 0.0f}, {HSDevType::Data, 0.0f}};
    // Accumulate total percentage of services on each device type
    for (const auto& [svc_type, fparams] : format_opts) {
        total_pct_by_type[fparams.dev_type] += fparams.size_pct;
    }

    // Sanity check, each type accumulated pct <=100%
    auto all_pct = 0;
    for (const auto& [DevType, total_pct] : total_pct_by_type) {
        all_pct += total_pct;
        if (total_pct > 100.0f) {
            LOGERROR("Total percentage of services on Device type {} is greater than 100.0f, total_pct_sum={}", DevType,
                     total_pct);
            throw std::invalid_argument("total percentage of on Device type {} services is greater than 100.0f");
        }
    }
    // Sanity check , at least one service should be placed on some device type
    if (all_pct == 0) {
        LOGERROR("No services are configured to be placed on any device type");
        throw std::invalid_argument("No services are configured to be placed on any device type");
    }

    // Sanity check, should have fast if fast pct >0
    if (total_pct_by_type[HSDevType::Fast] > 0 && !HomeStoreStaticConfig::instance().input.has_fast_dev()) {
        LOGERROR("Fast device is not configured but services are configured to be placed on fast device");
        throw std::invalid_argument(
            "Fast device is not configured but services are configured to be placed on fast device");
    }

    m_dev_mgr->format_devices();
    if (HomeStoreStaticConfig::instance().input.has_fast_dev()) {
        hs_utils::set_btree_mempool_size(m_dev_mgr->atomic_page_size({HSDevType::Fast}));
    } else {
        hs_utils::set_btree_mempool_size(m_dev_mgr->atomic_page_size({HSDevType::Data}));
    }

    std::vector< folly::Future< std::error_code > > futs;
    for (const auto& [svc_type, fparams] : format_opts) {
        if (fparams.size_pct == 0) { continue; }

        if ((svc_type & HS_SERVICE::META) && has_meta_service()) {
            m_meta_service->create_vdev(pct_to_size(fparams.size_pct, fparams.dev_type), fparams.dev_type,
                                        fparams.num_chunks);

        } else if ((svc_type & HS_SERVICE::LOG) && has_log_service()) {
            futs.emplace_back(m_log_service->create_vdev(pct_to_size(fparams.size_pct, fparams.dev_type),
                                                         fparams.dev_type, fparams.chunk_size));
        } else if ((svc_type & HS_SERVICE::INDEX) && has_index_service()) {
            m_index_service->create_vdev(pct_to_size(fparams.size_pct, fparams.dev_type), fparams.dev_type,
                                         fparams.num_chunks);
        } else if ((svc_type & HS_SERVICE::DATA) && has_data_service()) {
            m_data_service->create_vdev(pct_to_size(fparams.size_pct, fparams.dev_type), fparams.dev_type,
                                        fparams.block_size, fparams.alloc_type, fparams.chunk_sel_type,
                                        fparams.num_chunks);
        } else if ((svc_type & HS_SERVICE::REPLICATION) && has_repl_data_service()) {
            m_data_service->create_vdev(pct_to_size(fparams.size_pct, fparams.dev_type), fparams.dev_type,
                                        fparams.block_size, fparams.alloc_type, fparams.chunk_sel_type,
                                        fparams.num_chunks);
        }
    }

    if (!futs.empty()) {
        auto tlist = folly::collectAllUnsafe(futs).get();
        for (auto const& t : tlist) {
            auto const err = t.value();
            HS_REL_ASSERT(!err, "IO error during format of vdev, error={}", err.message());
        }
    }
    do_start();
}

void HomeStore::do_start() {
    const auto& inp_params = HomeStoreStaticConfig::instance().input;

    uint64_t cache_size = resource_mgr().get_cache_size();
    m_evictor = std::make_shared< sisl::LRUEvictor >(cache_size, 1000);

    if (m_before_services_starting_cb) { m_before_services_starting_cb(); }

    LOGINFO("HomeStore starting first_time_boot?={} dynamic_config_version={}, cache_size={}, static_config: {}",
            m_dev_mgr->is_first_time_boot(), HS_DYNAMIC_CONFIG(version), cache_size,
            HomeStoreStaticConfig::instance().to_json().dump(4));

    m_meta_service->start(m_dev_mgr->is_first_time_boot());
    m_cp_mgr->start(is_first_time_boot());

    if (has_index_service()) { m_index_service->start(); }

    if (has_repl_data_service()) {
        s_cast< GenericReplService* >(m_repl_service.get())->start(); // Replservice starts logstore & data service
    } else {
        if (has_data_service()) { m_data_service->start(); }
        if (has_log_service() && inp_params.auto_recovery) {
            // In case of custom recovery, let consumer starts the recovery and it is consumer module's responsibilities
            // to start log store
            m_log_service->start(is_first_time_boot() /* format */);
        }
    }

    m_cp_mgr->start_timer();

    m_resource_mgr->start(m_dev_mgr->total_capacity());
    m_init_done = true;
}

void HomeStore::shutdown() {
    if (!m_init_done) {
        LOGWARN("Homestore shutdown is called before init is completed");
        return;
    }

    LOGINFO("Homestore shutdown is started");

    m_cp_mgr->shutdown();
    m_cp_mgr.reset();

    m_resource_mgr->stop();

    if (has_repl_data_service()) {
        // Log and Data services are stopped by repl service
        s_cast< GenericReplService* >(m_repl_service.get())->stop();
        m_log_service.reset();
        m_data_service.reset();
        m_repl_service.reset();
    } else {
        if (has_log_service()) {
            m_log_service->stop();
            m_log_service.reset();
        }
        if (has_data_service()) { m_data_service.reset(); }
    }

    if (has_index_service()) {
        m_index_service->stop();
        // m_index_service.reset();
    }

    if (has_meta_service()) {
        m_meta_service->stop();
        m_meta_service.reset();
    }

    m_dev_mgr->close_devices();
    m_dev_mgr.reset();

#ifdef _PRERELEASE
    flip::Flip::instance().stop_rpc_server();
#endif

    HomeStore::reset_instance();
    LOGINFO("Homestore is completed its shutdown");
}

#if 0
cap_attrs HomeStore::get_system_capacity() const {
    cap_attrs cap;
    // if (has_data_service()) {
    //     cap.used_data_size = get_data_blkstore()->used_size();
    //     cap.data_capacity = get_data_blkstore()->get_size();
    // }
    if (has_index_service()) {
        cap.used_index_size = m_index_service->used_size();
        cap.meta_capacity += m_index_service->total_size();
    }
    if (has_log_service()) {
        cap.used_log_size = m_log_service->used_size();
        cap.meta_capacity += m_log_service->total_size();
    }
    if (has_meta_service()) {
        cap.used_metablk_size = m_meta_service->used_size();
        cap.meta_capacity += m_meta_service->total_size();
    }
    cap.used_total_size = cap.used_data_size + cap.used_index_size + cap.used_log_size + cap.used_metablk_size;
    return cap;
}
#endif

bool HomeStore::is_first_time_boot() const { return m_dev_mgr->is_first_time_boot(); }

bool HomeStore::has_index_service() const { return m_services.svcs & HS_SERVICE::INDEX; }
bool HomeStore::has_data_service() const { return m_services.svcs & HS_SERVICE::DATA; }
bool HomeStore::has_repl_data_service() const { return m_services.svcs & HS_SERVICE::REPLICATION; }
bool HomeStore::has_meta_service() const { return m_services.svcs & HS_SERVICE::META; }
bool HomeStore::has_log_service() const {
    auto const s = m_services.svcs;
    return (s & HS_SERVICE::LOG);
}

#if 0
void HomeStore::init_cache() {
    auto& hs_config = HomeStoreStaticConfig::instance();
    const auto& input = hs_config.input;

    /* Btree leaf node in index btree should accamodate minimum 2 entries to do the split. And on a average
     * a value consume 2 bytes (for checksum) per blk and few bytes for each IO and node header.
     * max_blk_cnt represents max number of blks blk allocator should give in a blk. We are taking
     * conservatively 4 entries in a node with avg size of 2 for each blk.
     * Note :- This restriction will go away once btree start supporinting higher size value.
     */
    hs_config.engine.max_blks_in_blkentry =
        std::min(static_cast< uint32_t >(BlkId::max_blks_in_op()), get_indx_mgr_page_size() / (4 * 2));
    hs_config.engine.min_io_size = std::min(input.min_virtual_page_size, get_indx_mgr_page_size());
    hs_config.engine.memvec_max_io_size = {static_cast< uint64_t >(
        HS_STATIC_CONFIG(engine.min_io_size) * ((static_cast< uint64_t >(1) << MEMPIECE_ENCODE_MAX_BITS) - 1))};
    hs_config.engine.max_vol_io_size = hs_config.engine.memvec_max_io_size;

    m_data_pagesz = input.min_virtual_page_size;

    LOGINFO("HomeStore starting with dynamic config version: {} static config: {}", HS_DYNAMIC_CONFIG(version),
            hs_config.to_json().dump(4));

    /* create cache */
    uint64_t cache_size = ResourceMgrSI().get_cache_size();
    m_cache = std::make_unique< CacheType >(cache_size, get_indx_mgr_page_size());
}
#endif

shared< VirtualDev > HomeStore::create_vdev_cb(const vdev_info& vinfo, bool load_existing) {
    shared< VirtualDev > ret_vdev;
    auto& hs_config = HomeStoreStaticConfig::instance();
    auto vdev_context = r_cast< const hs_vdev_context* >(vinfo.get_user_private());

    switch (vdev_context->type) {
    case hs_vdev_type_t::LOGDEV_VDEV:
        if (has_log_service()) { ret_vdev = m_log_service->open_vdev(vinfo, load_existing); }
        break;
    case hs_vdev_type_t::META_VDEV:
        if (has_meta_service()) { ret_vdev = m_meta_service->open_vdev(vinfo, load_existing); }
        break;

    case hs_vdev_type_t::INDEX_VDEV:
        if (has_index_service()) { ret_vdev = m_index_service->open_vdev(vinfo, load_existing); }
        break;

    case hs_vdev_type_t::DATA_VDEV:
        if (has_data_service() || has_repl_data_service()) {
            ret_vdev = m_data_service->open_vdev(vinfo, load_existing);
        }
        break;

    default:
        HS_LOG_ASSERT(0, "Unknown vdev_type {}", vdev_context->type);
    }

    return ret_vdev;
}

uint64_t HomeStore::pct_to_size(float pct, HSDevType dev_type) const {
    uint64_t sz = uint64_cast((pct * static_cast< double >(m_dev_mgr->total_capacity(dev_type))) / 100);
    return sisl::round_up(sz, m_dev_mgr->optimal_page_size(dev_type));
}

/////////////////////////////////////////// static HomeStore member functions /////////////////////////////////
// void HomeStore::fake_reboot() {}

#if 0
std::string cap_attrs::to_string() const {
    return fmt::format("used_data_size={}, used_index_size={}, used_log_size={}, used_metablk_size={}, "
                       "used_total_size={}, initial_total_size={}, initial_total_data_meta_size={}",
                       in_bytes(used_data_size), in_bytes(used_index_size), in_bytes(used_log_size),
                       in_bytes(used_metablk_size), in_bytes(used_total_size), in_bytes(initial_total_size),
                       in_bytes(initial_total_data_meta_size));
}
#endif

nlohmann::json hs_input_params::to_json() const {
    nlohmann::json json;
    json["devices"] = nlohmann::json::array();
    for (const auto& d : devices) {
        json["devices"].push_back(d.to_string());
    }
    json["data_open_flags"] = data_open_flags;
    json["fast_open_flags"] = fast_open_flags;
    json["is_read_only"] = is_read_only;

    json["app_mem_size"] = in_bytes(app_mem_size);
    json["hugepage_size"] = in_bytes(hugepage_size);
    json["auto_recovery?"] = auto_recovery;
    return json;
}

nlohmann::json hs_engine_config::to_json() const {
    nlohmann::json json;
    json["max_chunks"] = max_chunks;
    json["max_vdevs"] = max_vdevs;
    json["max_pdevs"] = max_pdevs;
    json["max_blks_in_blkentry"] = max_blks_in_blkentry;
    return json;
}
} // namespace homestore
