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
#include "logstore/log_store_family.hpp"
#include "device/journal_vdev.hpp"

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

HomeStore* HomeStore::instance() {
    if (s_instance == nullptr) { s_instance = std::make_shared< HomeStore >(); }
    return s_instance.get();
}

HomeStore& HomeStore::with_params(const hs_input_params& input) {
    auto& hs_config = HomeStoreStaticConfig::instance();
    hs_config.input = input;
    return *this;
}

HomeStore& HomeStore::with_index_service(float size_pct, std::unique_ptr< IndexServiceCallbacks > cbs) {
    m_index_svc_cbs = std::move(cbs);
    m_index_store_size_pct = size_pct;
    return *this;
}

#if 0
HomeStore& HomeStore::with_data_service(float size_pct, std::unique_ptr< DataServiceCallbacks > cbs) {
    m_data_svc_cbs = (cbs) ? std::move(cbs) : std::make_unique< DataServiceCallbacks >();
    m_data_store_size_pct = size_pct;
    return *this;
}
#endif

HomeStore& HomeStore::with_log_service(float data_size_pct, float ctrl_size_pct) {
    m_data_log_store_size_pct = data_size_pct;
    m_ctrl_log_store_size_pct = ctrl_size_pct;
    return *this;
}

HomeStore& HomeStore::with_meta_service(float size_pct) {
    m_meta_store_size_pct = size_pct;
    return *this;
}

HomeStore& HomeStore::with_data_service(float size_pct) {
    m_data_store_size_pct = size_pct;
    return *this;
}

HomeStore& HomeStore::after_init_done(hs_init_done_cb_t init_done_cb) {
    m_init_done_cb = std::move(init_done_cb);
    return *this;
}

HomeStore& HomeStore::before_init_devices(hs_init_starting_cb_t init_starting_cb) {
    m_before_init_starting_cb = std::move(init_starting_cb);
    return *this;
}

void HomeStore::init(bool wait_for_init, float meta_size_pct, float log_data_size_pct, float log_ctrl_size_pct,
                     float data_svc_size_pct) {
    with_meta_service(meta_size_pct);
    with_log_service(log_data_size_pct, log_ctrl_size_pct);
    with_data_service(data_svc_size_pct);
    init_internal(wait_for_init);
}

void HomeStore::init_internal(bool wait_for_init) {
    auto& hs_config = HomeStoreStaticConfig::instance();
    if (hs_config.input.data_devices.empty()) {
        LOGERROR("no data devices given");
        throw std::invalid_argument("null device list");
    }

    // Validate all pre-requisite services started
    if (!has_meta_service()) {
        LOGERROR("Meta services is mandatory to be started");
        throw std::invalid_argument("Meta services has to be started");
    }

    static std::mutex start_mutex;
    static std::condition_variable cv;
    static bool inited;
    inited = false;
    if (wait_for_init) {
        if (m_init_done_cb) {
            LOGWARN("Homestore init is called with wait till init, but it has valid after_init_done callback set in "
                    "its init params, ignoring the after_init_done callback; it will not be called");
        }
        m_init_done_cb = [& tl_cv = cv, &tl_start_mutex = start_mutex, &tl_inited = inited]() {
            LOGINFO("HomeStore Init completed");
            {
                std::unique_lock< std::mutex > lk{tl_start_mutex};
                tl_inited = true;
            }
            tl_cv.notify_one();
        };
    }

    ///////////// Startup resource status and other manager outside core services /////////////////////////
    sisl::ObjCounterRegistry::enable_metrics_reporting();
    sisl::MallocMetrics::enable();
    m_status_mgr = std::make_unique< HomeStoreStatusMgr >();
    m_resource_mgr = std::make_unique< ResourceMgr >();

#ifndef NDEBUG
    flip::Flip::instance().start_rpc_server();
#endif

    static std::once_flag flag1;
    std::call_once(flag1, [this]() {
        m_periodic_logger =
            sisl::logging::CreateCustomLogger("homestore", "_periodic", false, true /* tee_to_stdout_stderr */);
    });
    sisl::logging::SetLogPattern("[%D %T.%f] [%^%L%$] [%t] %v", m_periodic_logger);

    ///////////// Config related setup /////////////////////////
    HomeStoreDynamicConfig::init_settings_default();

    // Restrict iomanager to throttle upto the app mem size allocated for us
    iomanager.set_io_memory_limit(HS_STATIC_CONFIG(input.io_mem_size()));

    ///////////// Startup of services  /////////////////////////
    // Order of the initialization
    // 1. Meta Service instance is created
    // 2. All other optional services instances are created. At this point, none of the services are started
    // 3. Create DeviceManager instance and init it
    // 4. Start the Evictor which bounds the cache
    // 5. Initialize all the Physical/Virtual devices in separate init thread
    // 6. Upon device instances are created and read, depending on first_time_boot or not, create or load the superblock
    // of all devices
    // 7. Start the MetaService instance. This will walk and possibly call all registered service static method which
    // should have enough information about their services
    // 8. Start all the optional services
    LOGINFO("Homestore is initializing with following services: ", list_services());
    if (has_meta_service()) { m_meta_service = std::make_unique< MetaBlkService >(); }
    if (has_log_service()) { m_log_service = std::make_unique< LogStoreService >(); }
    if (has_data_service()) { m_data_service = std::make_unique< BlkDataService >(); }
    if (has_index_service()) { m_index_service = std::make_unique< IndexService >(std::move(m_index_svc_cbs)); }

    m_dev_mgr = std::make_unique< DeviceManager >(hs_config.input.data_devices, bind_this(HomeStore::new_vdev_found, 2),
                                                  sizeof(sb_blkstore_blob), VirtualDev::static_process_completions,
                                                  bind_this(HomeStore::process_vdev_error, 1));
    m_dev_mgr->init();

    uint64_t cache_size = resource_mgr().get_cache_size();
    m_evictor = std::make_shared< sisl::LRUEvictor >(cache_size, 1000);

    LOGINFO("HomeStore starting first_time_boot?={} dynamic_config_version={}, cache_size={}, static_config: {}",
            is_first_time_boot(), HS_DYNAMIC_CONFIG(version), cache_size, hs_config.to_json().dump(4));

    iomanager.create_reactor("hs_init", INTERRUPT_LOOP, [this](bool thread_started) {
        if (thread_started) {
            if (m_before_init_starting_cb) { m_before_init_starting_cb(); }
            if (is_first_time_boot()) { create_vdevs(); }
            init_done();
        }
    });

    if (wait_for_init) {
        std::unique_lock< std::mutex > lk{start_mutex};
        cv.wait(lk, [] { return inited; });
    }
}

void HomeStore::shutdown(bool wait, const hs_comp_callback& done_cb) {
    static std::mutex stop_mutex;
    static std::condition_variable cv;
    static bool done;

    done = false;
    auto _stop = [this](bool wait, const hs_comp_callback& done_cb) {
        LOGINFO("Homestore shutdown is started");
        if (has_log_service()) {
            m_log_service->stop();
            m_log_service.reset();
        }

        if (has_meta_service()) {
            m_meta_service->stop();
            m_meta_service.reset();
        }

        if (has_data_service()) { m_data_service.reset(); }

        m_dev_mgr->close_devices();
        m_dev_mgr.reset();
        m_cp_mgr->shutdown();
        LOGINFO("Homestore is completed its shutdown");

        if (wait) {
            {
                std::unique_lock< std::mutex > lk{stop_mutex};
                done = true;
            }
            cv.notify_one();
        }

        if (done_cb) { done_cb(true); }
    };

    // Doing shutdown on non-user io reactor threads will be a problem, so in those cases start a new reactor thread for
    // shutdown. For HomeBlks shutdown is issued from its own reactor thread, so this will not create additional thread
    // in that context.
    if (!iomanager.am_i_io_reactor() || iomanager.am_i_worker_reactor()) {
        iomanager.create_reactor("hs_shutdown", INTERRUPT_LOOP, [this, wait, done_cb, _stop](bool thread_started) {
            if (thread_started) {
                _stop(wait, done_cb);
                iomanager.stop_io_loop();
            }
        });
    } else {
        _stop(wait, done_cb);
    }

    if (wait) {
        std::unique_lock< std::mutex > lk{stop_mutex};
        cv.wait(lk, [] { return done; });
    }
    HomeStore::reset_instance();
}

void HomeStore::create_vdevs() {
    if (has_meta_service()) { m_meta_service->create_vdev(pct_to_size(m_meta_store_size_pct, PhysicalDevGroup::META)); }

    if (has_data_service()) { m_data_service->create_vdev(pct_to_size(m_data_store_size_pct, PhysicalDevGroup::DATA)); }

    if (has_log_service() && m_data_log_store_size_pct) {
        ++m_format_cnt;
        m_log_service->create_vdev(pct_to_size(m_data_log_store_size_pct, PhysicalDevGroup::FAST),
                                   LogStoreService::DATA_LOG_FAMILY_IDX,
                                   [this](std::error_condition err, void* cookie) {
                                       HS_REL_ASSERT((err == no_error), "IO error during format of vdev");
                                       init_done();
                                   });
    }
    if (has_log_service() && m_ctrl_log_store_size_pct) {
        ++m_format_cnt;
        m_log_service->create_vdev(pct_to_size(m_ctrl_log_store_size_pct, PhysicalDevGroup::FAST),
                                   LogStoreService::CTRL_LOG_FAMILY_IDX,
                                   [this](std::error_condition err, void* cookie) {
                                       HS_REL_ASSERT((err == no_error), "IO error during format of vdev");
                                       init_done();
                                   });
    }

    if (has_index_service()) {
        m_index_service->create_vdev(pct_to_size(m_index_store_size_pct, PhysicalDevGroup::FAST));
    }
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

void HomeStore::init_done() {
    const auto& inp_params = HomeStoreStaticConfig::instance().input;
    auto cnt = m_format_cnt.fetch_sub(1);
    if (cnt != 1) { return; }
    m_dev_mgr->init_done();

    m_cp_mgr = std::make_unique< CPManager >(is_first_time_boot()); // Initialize CPManager
    m_meta_service->start(is_first_time_boot());
    m_resource_mgr->set_total_cap(m_dev_mgr->total_cap());

    // In case of custom recovery, let consumer starts the recovery and it is consumer module's responsibilities to
    // start log store
    if (has_log_service() && inp_params.auto_recovery) { m_log_service->start(is_first_time_boot()); }

    if (has_index_service()) { m_index_service->start(); }

    if (m_init_done_cb) { m_init_done_cb(); }
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

void HomeStore::new_vdev_found(DeviceManager* dev_mgr, vdev_info_block* vb) {
    auto& hs_config = HomeStoreStaticConfig::instance();

    /* create blkstore */
    blkstore_blob* blob = r_cast< blkstore_blob* >(vb->context_data);

    switch (blob->type) {
    case blkstore_type::DATA_LOGDEV_STORE:
        if (has_log_service() && m_data_log_store_size_pct) {
            m_log_service->open_vdev(vb, LogStoreService::DATA_LOG_FAMILY_IDX);
        }
        break;
    case blkstore_type::CTRL_LOGDEV_STORE:
        if (has_log_service() && m_ctrl_log_store_size_pct) {
            m_log_service->open_vdev(vb, LogStoreService::CTRL_LOG_FAMILY_IDX);
        }
        break;
    case blkstore_type::META_STORE:
        if (has_meta_service()) { m_meta_service->open_vdev(vb); }
        break;

    case blkstore_type::INDEX_STORE:
        if (has_index_service()) { m_index_service->open_vdev(vb); }
        break;

    default:
        HS_LOG_ASSERT(0, "Unknown blkstore_type {}", blob->type);
    }
}

uint64_t HomeStore::pct_to_size(const float pct, const PhysicalDevGroup pdev_group) const {
    uint64_t sz = uint64_cast((pct * static_cast< double >(m_dev_mgr->total_cap(pdev_group))) / 100);
    return sisl::round_up(sz, m_dev_mgr->phys_page_size(pdev_group));
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
    json["system_uuid"] = boost::uuids::to_string(system_uuid);
    json["devices"] = nlohmann::json::array();
    for (const auto& d : data_devices) {
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
