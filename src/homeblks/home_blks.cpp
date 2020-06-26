#include "home_blks.hpp"
#include "volume/volume.hpp"
#include <engine/device/device.h>
#include <engine/device/virtual_dev.hpp>
#include <cassert>
#include <engine/device/blkbuffer.hpp>
#include <iostream>
#include <fstream>
#include <stdexcept>
#include <nlohmann/json.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <homelogstore/log_store.hpp>
#include <map>
#include <engine/meta/meta_blks_mgr.hpp>

SDS_OPTION_GROUP(home_blks,
                 (hb_stats_port, "", "hb_stats_port", "Stats port for HTTP service",
                  cxxopts::value< int32_t >()->default_value("5000"), "port"))
using namespace homestore;

REGISTER_METABLK_SUBSYSTEM(homeblks, "HOMEBLK", HomeBlks::meta_blk_found_cb, HomeBlks::meta_blk_recovery_comp_cb)

#ifndef DEBUG
bool same_value_gen = false;
#endif

std::string HomeBlks::version = PACKAGE_VERSION;
thread_local std::vector< std::shared_ptr< Volume > >* HomeBlks::s_io_completed_volumes = nullptr;

VolInterface* VolInterfaceImpl::init(const init_params& cfg, bool force_reinit) {
    return (HomeBlks::init(cfg, force_reinit));
}
#if 0
boost::intrusive_ptr< VolInterface > VolInterfaceImpl::safe_instance() {
    return boost::dynamic_pointer_cast< VolInterface >(HomeBlks::safe_instance());
}
#endif
VolInterface* VolInterfaceImpl::raw_instance() { return HomeBlks::instance(); }

VolInterface* HomeBlks::init(const init_params& cfg, bool force_reinit) {
    fLI::FLAGS_minloglevel = 3;

    static std::once_flag flag1;
    try {
        std::call_once(flag1, [&cfg]() {
#ifndef NDEBUG
            LOGINFO("HomeBlks DEBUG version: {}", HomeBlks::version);
#else
                LOGINFO("HomeBlks RELEASE version: {}", HomeBlks::version);
#endif
            auto instance = boost::static_pointer_cast< homestore::HomeStoreBase >(HomeBlksSafePtr(new HomeBlks(cfg)));
            set_instance(boost::static_pointer_cast< homestore::HomeStoreBase >(instance));
        });
        return (VolInterface*)(HomeStoreBase::instance());
    } catch (const std::exception& e) {
        LOGERROR("{}", e.what());
        assert(0);
        return nullptr;
    }
}

vol_interface_req::vol_interface_req(void* wbuf, uint64_t lba, uint32_t nlbas, bool is_sync) :
        write_buf(wbuf),
        request_id(counter_generator.next_request_id()),
        refcount(0),
        lba(lba),
        nlbas(nlbas),
        sync(is_sync) {}

vol_interface_req::~vol_interface_req() = default;

HomeBlks::HomeBlks(const init_params& cfg) : m_cfg(cfg), m_metrics("HomeBlks") {
    LOGINFO("Initializing HomeBlks with Config {}", m_cfg.to_string());
    HomeStore< BLKSTORE_BUFFER_TYPE >::init((const hs_input_params&)cfg);

    m_out_params.max_io_size = VOL_MAX_IO_SIZE;
    uint32_t align = 0;
    uint32_t size = HOMEBLKS_SB_SIZE;
    if (meta_blk_mgr->is_aligned_buf_needed(size)) {
        align = HS_STATIC_CONFIG(disk_attr.align_size);
        size = sisl::round_up(size, align);
    }
    sisl::byte_view b(size, align);
    m_homeblks_sb_buf = b;

    superblock_init();
    sisl::MallocMetrics::enable();

    /* start thread */
#if 0
    auto run_method = sisl::ObjectAllocator< run_method_t >::make_object();
    *run_method = ([this]() {
        try {
            this->init_devices();
        } catch (const std::exception& e) {
            LOGERROR("{}", e.what());
            init_done(std::make_error_condition(std::errc::io_error));
        }
    });
    iomgr_msg io_msg;
    io_msg.m_type = RUN_METHOD;
    io_msg.m_data_buf = (void*)run_method;
    /* We are distributing work based on btree. Other approach is to use both threads working
     * on same btree.
     */
    iomanager.send_to_least_busy_thread(-1, io_msg);
#endif
    auto sthread = sisl::named_thread("hb_init", [this]() {
        this->init_devices();
        iomanager.run_io_loop(false, nullptr);
        LOGINFO("REMOVE_ME: Exiting hb_init thread");
    });
    sthread.detach();
    m_start_shutdown = false;
}

void HomeBlks::attach_prepare_indx_cp_id(std::map< boost::uuids::uuid, indx_cp_id_ptr >* cur_id_map,
                                         std::map< boost::uuids::uuid, indx_cp_id_ptr >* new_id_map, hs_cp_id* hs_id,
                                         hs_cp_id* new_hs_id) {

    std::lock_guard< std::recursive_mutex > lg(m_vol_lock);

#ifndef NDEBUG
    /* If a volume is participated in a cp then it can not be deleted without participating
     * in a cp flush.
     */
    if (cur_id_map) {
        for (auto it = cur_id_map->cbegin(); it != cur_id_map->cend(); ++it) {
            assert(m_volume_map.find(it->first) != m_volume_map.cend());
        }
    }
#endif

    for (auto it = m_volume_map.cbegin(); it != m_volume_map.cend(); ++it) {
        auto vol = it->second;
        if (vol == nullptr) { continue; }

        /* get the cur cp id ptr */
        indx_cp_id_ptr cur_cp_id_ptr = nullptr;
        if (cur_id_map) {
            auto id_it = cur_id_map->find(it->first);
            if (id_it != cur_id_map->end()) {
                /* It is a new volume which is created after this cp */
                cur_cp_id_ptr = id_it->second;
            }
        }

        /* get the cur cp id ptr */
        auto new_cp_id_ptr = vol->attach_prepare_volume_cp(cur_cp_id_ptr, hs_id, new_hs_id);

        if (new_cp_id_ptr) {
            bool happened{false};
            std::map< boost::uuids::uuid, indx_cp_id_ptr >::iterator temp_it;
            std::tie(temp_it, happened) = new_id_map->emplace(std::make_pair(it->first, new_cp_id_ptr));
            if (!happened) { throw std::runtime_error("Unknown bug"); }
        } else {
            /* this volume doesn't want to participate now */
            assert(vol->get_state() == vol_state::DESTROYED || is_shutdown());
        }
    }
}

vol_interface_req_ptr HomeBlks::create_vol_interface_req(void* buf, uint64_t lba, uint32_t nlbas, bool is_sync) {
    return vol_interface_req_ptr(new vol_interface_req(buf, lba, nlbas, is_sync));
}

std::error_condition HomeBlks::write(const VolumePtr& vol, const vol_interface_req_ptr& req, bool part_of_batch) {
    assert(m_rdy);
    if (!vol) {
        assert(0);
        throw std::invalid_argument("null vol ptr");
    }
    if (!m_rdy || is_shutdown()) { return std::make_error_condition(std::errc::device_or_resource_busy); }
    req->vol_instance = vol;
    req->part_of_batch = part_of_batch;
    req->is_read = false;
    return (vol->write(req));
}

std::error_condition HomeBlks::read(const VolumePtr& vol, const vol_interface_req_ptr& req, bool part_of_batch) {
    assert(m_rdy);
    if (!vol) {
        assert(0);
        throw std::invalid_argument("null vol ptr");
    }
    if (!m_rdy || is_shutdown()) { return std::make_error_condition(std::errc::device_or_resource_busy); }
    req->vol_instance = vol;
    req->part_of_batch = part_of_batch;
    req->is_read = true;
    return (vol->read(req));
}

std::error_condition HomeBlks::sync_read(const VolumePtr& vol, const vol_interface_req_ptr& req) {
    assert(m_rdy);
    if (!vol) {
        assert(0);
        throw std::invalid_argument("null vol ptr");
    }
    if (!m_rdy || is_shutdown()) { return std::make_error_condition(std::errc::device_or_resource_busy); }
    req->vol_instance = vol;
    return (vol->read(req));
}

const char* HomeBlks::get_name(const VolumePtr& vol) { return vol->get_name(); }
uint64_t HomeBlks::get_page_size(const VolumePtr& vol) { return vol->get_page_size(); }
uint64_t HomeBlks::get_size(const VolumePtr& vol) { return vol->get_size(); }
boost::uuids::uuid HomeBlks::get_uuid(VolumePtr vol) { return vol->get_uuid(); }
homeds::blob HomeBlks::at_offset(const blk_buf_t& buf, uint32_t offset) { return (buf->at_offset(offset)); }

/* this function can be called during recovery also */
void HomeBlks::create_volume(VolumePtr vol) {
    /* add it to map */
    decltype(m_volume_map)::iterator it;
    // Try to add an entry for this volume
    std::lock_guard< std::recursive_mutex > lg(m_vol_lock);
    bool happened{false};
    std::tie(it, happened) = m_volume_map.emplace(std::make_pair(vol->get_uuid(), nullptr));
    HS_ASSERT(RELEASE, happened, "volume already exists");

    // Okay, this is a new volume so let's create it
    it->second = vol;

    /* set available size and return */
    set_available_size(available_size() - vol->get_size());

    VOL_INFO_LOG(vol->get_uuid(), "Created volume: {}", vol->get_name());
}

VolumePtr HomeBlks::create_volume(const vol_params& params) {
    if (HS_STATIC_CONFIG(input.is_read_only)) {
        assert(0);
        LOGERROR("can not create vol on read only boot");
        return nullptr;
    }
    if (!m_rdy || is_shutdown()) { return nullptr; }

    if (params.page_size != get_data_pagesz()) {
        LOGERROR("{} page size is not supported", params.page_size);
        return nullptr;
    }

    if ((int64_t)params.size >= available_size()) {
        LOGINFO("there is a possibility of running out of space as total size of the volumes"
                "created are more then maximum capacity");
    }
    /* create new volume */
    auto new_vol = Volume::make_volume(params);
    create_volume(new_vol);

    auto system_cap = get_system_capacity();
    LOGINFO("System capacity after vol create: {}", system_cap.to_string());
    VOL_INFO_LOG(new_vol->get_uuid(), "Create volume with params: {}", params.to_string());
    return new_vol;
}

VolumePtr HomeBlks::lookup_volume(const boost::uuids::uuid& uuid) {
    std::lock_guard< std::recursive_mutex > lg(m_vol_lock);
    auto it = m_volume_map.find(uuid);
    if (m_volume_map.end() != it) { return it->second; }
    return nullptr;
}
#if 0
SnapshotPtr HomeBlks::snap_volume(VolumePtr volptr) {
    if (!m_rdy || is_shutdown()) {
        LOGINFO("Snapshot: volume not online");
        return nullptr;
    }

    auto sp = volptr->make_snapshot();
    LOGINFO("Snapshot created volume {}, Snapshot {}", volptr->to_string(), sp->to_string());
    return sp;
}
#endif
void HomeBlks::submit_io_batch() {
    iomanager.default_drive_interface()->submit_batch();
    call_multi_vol_completions();
}

HomeBlks* HomeBlks::instance() { return static_cast< HomeBlks* >(HomeStoreBase::instance()); }
HomeBlksSafePtr HomeBlks::safe_instance() {
    return boost::static_pointer_cast< HomeBlks >(HomeStoreBase::safe_instance());
}

void HomeBlks::superblock_init() {
    /* build the homeblks super block */
    auto sb = (homeblks_sb*)m_homeblks_sb_buf.bytes();
    sb->version = HOMEBLKS_SB_VERSION;
    sb->boot_cnt = 0;
    sb->init_flag(0);
    sb->uuid = HS_STATIC_CONFIG(input.system_uuid);
}

void HomeBlks::homeblks_sb_write() {
    if (m_sb_cookie == nullptr) {
        // add to MetaBlkMgr
        meta_blk_mgr->add_sub_sb("HOMEBLK", (void*)m_homeblks_sb_buf.bytes(), sizeof(homeblks_sb), m_sb_cookie);
    } else {
        // update existing homeblks sb
        meta_blk_mgr->update_sub_sb("HOMEBLK", (void*)m_homeblks_sb_buf.bytes(), sizeof(homeblks_sb), m_sb_cookie);
    }
}

void HomeBlks::process_vdev_error(vdev_info_block* vb) {
    /* For now we need to move all volumes in a failed state. Later on when we move to multiple virtual devices for
     * data blkstore we need to move only those volumes to failed state which  belong to this virtual device.
     */
    std::lock_guard< std::recursive_mutex > lg(m_vol_lock);
    auto it = m_volume_map.begin();
    while (it != m_volume_map.end()) {
        auto old_state = it->second->get_state();
        if (old_state == vol_state::ONLINE) {
            /* We don't persist this state. Reason that we come over here is that
             * disks are not working. It doesn't make sense to write to faulty
             * disks.
             */
            it->second->set_state(vol_state::FAILED, false);
            m_cfg.vol_state_change_cb(it->second, old_state, vol_state::FAILED);
        }
        ++it;
    }
}

void HomeBlks::attach_vol_completion_cb(const VolumePtr& vol, const io_comp_callback& cb) {
    vol->attach_completion_cb(cb);
}
void HomeBlks::attach_end_of_batch_cb(const end_of_batch_callback& cb) { m_cfg.end_of_batch_cb = cb; }

void HomeBlks::vol_mounted(const VolumePtr& vol, vol_state state) {
    m_cfg.vol_mounted_cb(vol, state);
    VOL_INFO_LOG(vol->get_uuid(), " Mounted the volume in state {}", state);
}

bool HomeBlks::vol_state_change(const VolumePtr& vol, vol_state new_state) {
    assert(new_state == vol_state::OFFLINE || new_state == vol_state::ONLINE);
    try {
        vol->set_state(new_state);
    } catch (std::exception& e) {
        LOGERROR("{}", e.what());
        return false;
    }
    return true;
}

void HomeBlks::init_done(std::error_condition err) {
    /* check for error */
    bool expected = false;
    bool desired = true;
    if (err != no_error && m_init_finished.compare_exchange_strong(expected, desired)) {
        m_cfg.init_done_cb(err, m_out_params);
        m_cv.notify_all();
        return;
    }

    if (err == no_error) { m_rdy = true; }

    data_recovery_done();
    uint64_t used_data_size = 0;
    for (auto it = m_volume_map.cbegin(); it != m_volume_map.cend(); ++it) {
        vol_mounted(it->second, it->second->get_state());
        used_data_size += it->second->get_used_size();
    }
    auto system_cap = get_system_capacity();
    LOGINFO("{}", system_cap.to_string());
    assert(system_cap.used_total_size == used_data_size);

    LOGINFO("init done");
    m_cfg.init_done_cb(err, m_out_params);
    m_init_finished = true;
    m_cv.notify_all();
#ifndef NDEBUG
    /* It will trigger race conditions without generating any IO error */
    set_io_flip();
#endif
}

data_blkstore_t::comp_callback HomeBlks::data_completion_cb() { return Volume::process_vol_data_completions; };

#ifdef _PRERELEASE
void HomeBlks::set_io_flip() {
    Volume::set_io_flip();
    MappingBtreeDeclType::set_io_flip();
}

void HomeBlks::set_error_flip() {
    Volume::set_error_flip();
    MappingBtreeDeclType::set_error_flip();
}
#endif

void HomeBlks::print_tree(const VolumePtr& vol, bool chksum) {
    m_print_checksum = chksum;
    vol->print_tree();
}

bool HomeBlks::verify_tree(const VolumePtr& vol) {
    VOL_INFO_LOG(vol->get_uuid(), "Verifying the integrity of the index tree");
    return vol->verify_tree();
}

void HomeBlks::verify_vols() {
    std::unique_lock< std::recursive_mutex > lg(m_vol_lock);
    auto it = m_volume_map.begin();
    while (it != m_volume_map.end()) {
        verify_tree(it->second);
        ++it;
    }
}

void HomeBlks::verify_hs(sisl::HttpCallData cd) {
    HomeBlks* hb = (HomeBlks*)(cd->cookie());
    hb->verify_vols();
    hb->m_http_server->respond_OK(cd, EVHTP_RES_OK, std::string("HomeBlks verified"));
}

void HomeBlks::print_node(const VolumePtr& vol, uint64_t blkid, bool chksum) {
    m_print_checksum = chksum;
    vol->print_node(blkid);
}

void HomeBlks::get_version(sisl::HttpCallData cd) {
    HomeBlks* hb = (HomeBlks*)(cd->cookie());
    hb->m_http_server->respond_OK(cd, EVHTP_RES_OK, std::string("HomeBlks: ") + HomeBlks::version);
}

void HomeBlks::get_metrics(sisl::HttpCallData cd) {
    HomeBlks* hb = (HomeBlks*)(cd->cookie());
    std::string msg = sisl::MetricsFarm::getInstance().get_result_in_json_string();
    hb->m_http_server->respond_OK(cd, EVHTP_RES_OK, msg);
}

void HomeBlks::get_prometheus_metrics(sisl::HttpCallData cd) {
    HomeBlks* hb = (HomeBlks*)(cd->cookie());
    std::string msg = sisl::MetricsFarm::getInstance().report(sisl::ReportFormat::kTextFormat);
    hb->m_http_server->respond_OK(cd, EVHTP_RES_OK, msg);
}

void HomeBlks::get_obj_life(sisl::HttpCallData cd) {
    HomeBlks* hb = (HomeBlks*)(cd->cookie());
    nlohmann::json j;
    sisl::ObjCounterRegistry::foreach ([&j](const std::string& name, int64_t created, int64_t alive) {
        std::stringstream ss;
        ss << "created=" << created << " alive=" << alive;
        j[name] = ss.str();
    });
    hb->m_http_server->respond_OK(cd, EVHTP_RES_OK, j.dump());
}

void HomeBlks::set_log_level(sisl::HttpCallData cd) {
    HomeBlks* hb = (HomeBlks*)(cd->cookie());
    auto req = cd->request();

    const evhtp_kv_t* _new_log_level = nullptr;
    const evhtp_kv_t* _new_log_module = nullptr;
    const char* logmodule = nullptr;
    char* endptr = nullptr;

    _new_log_module = evhtp_kvs_find_kv(req->uri->query, "logmodule");
    if (_new_log_module) { logmodule = _new_log_module->val; }

    _new_log_level = evhtp_kvs_find_kv(req->uri->query, "loglevel");
    if (!_new_log_level) {
        hb->m_http_server->respond_NOTOK(cd, EVHTP_RES_BADREQ, "Invalid loglevel param!");
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

    hb->m_http_server->respond_OK(cd, EVHTP_RES_OK, resp);
}

void HomeBlks::get_log_level(sisl::HttpCallData cd) {
    HomeBlks* hb = (HomeBlks*)(cd->cookie());
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
    hb->m_http_server->respond_OK(cd, EVHTP_RES_OK, resp);
}

void HomeBlks::dump_stack_trace(sisl::HttpCallData cd) {
    HomeBlks* hb = (HomeBlks*)(cd->cookie());
    sds_logging::log_stack_trace(true);
    hb->m_http_server->respond_OK(cd, EVHTP_RES_OK, "Look for stack trace in the log file");
}

void HomeBlks::get_malloc_stats(sisl::HttpCallData cd) {
    HomeBlks* hb = (HomeBlks*)(cd->cookie());
    hb->m_http_server->respond_OK(cd, EVHTP_RES_OK, sisl::get_malloc_stats_detailed().dump(2));
}

bool HomeBlks::shutdown(bool force) {
    std::mutex stop_mutex;
    std::condition_variable cv;
    bool status = false;
    bool done = false;

    done = !trigger_shutdown(
        [&](bool is_success) {
            LOGINFO("Completed the shutdown of HomeBlks with success ? {}", is_success);
            {
                std::unique_lock< std::mutex > lk(stop_mutex);
                status = is_success;
                done = true;
            }
            cv.notify_all();
        },
        force);

    // Wait for the shutdown completion.
    std::unique_lock< std::mutex > lk(stop_mutex);
    if (!done) {
        cv.wait(lk, [&] { return done; });
    }
    return status;
}

//
// Shutdown:
// 1. Set persistent state of shutdown
// 2. Start a thread to do shutdown routines;
//
bool HomeBlks::trigger_shutdown(const shutdown_comp_callback& shutdown_done_cb, bool force) {
    uint64_t expected = 0;
    if (!m_shutdown_start_time.compare_exchange_strong(expected, get_time_since_epoch_ms())) {
        // shutdown thread should be only started once;
        LOGINFO("shutdown thread already started {} milliseconds earlier",
                get_time_since_epoch_ms() - m_shutdown_start_time.load());
        return false;
    }
    LOGINFO("HomeBlks shutdown sequence triggered");

    // No more objects are depending on this other than base _instance. Go ahead and do shutdown processing
    if (m_init_failed) {
        LOGINFO("Init is failed. Nothing to shutdown");
        return false;
    }

    // Execute the shutdown on the io thread, because clean shutdown will do IO (albeit sync io)
    auto sthread = sisl::named_thread("hb_shutdown", [this, shutdown_done_cb, force]() {
        iomanager.run_io_loop(false, nullptr, [&](bool thread_started) {
            if (thread_started) { schedule_shutdown(shutdown_done_cb, force); }
        });
    });
    sthread.detach();
    return true;
}

void HomeBlks::schedule_shutdown(const shutdown_comp_callback& shutdown_done_cb, bool force) {
    do_shutdown(shutdown_done_cb, force);
}

void HomeBlks::do_shutdown(const shutdown_comp_callback& shutdown_done_cb, bool force) {
    //
    // Need to wait m_init_finished to be true before we create shutdown thread because:
    // 1. if init thread is running slower than shutdown thread,
    // 2. it is possible that shutdown thread completed but init thread
    //    is still creating resources, which would be resource leak
    //    after shutdown thread exits;
    //
    {
        std::unique_lock< std::mutex > lk(m_cv_mtx);
        if (!m_init_finished.load()) { m_cv.wait(lk); }
    }

    auto elapsed_time_ms = get_time_since_epoch_ms() - m_shutdown_start_time.load();
    if (elapsed_time_ms > (HB_SETTINGS_VALUE(general_config->shutdown_timeout_secs) * 1000)) {
        LOGERROR("Graceful shutdown of volumes took {} ms exceeds time limit {} seconds, attempting forceful shutdown",
                 elapsed_time_ms, HB_SETTINGS_VALUE(general_config->shutdown_timeout_secs));
        force = true;
    }

    m_shutdown_done_cb = shutdown_done_cb;
    m_force_shutdown = force;
    do_volume_shutdown(force);

    if (!m_vol_shutdown_cmpltd) {
        LOGINFO("Not all volumes are completely shutdown yet, will check again in {} milliseconds",
                HB_SETTINGS_VALUE(general_config->shutdown_status_check_freq_ms));
        m_shutdown_timer_hdl = iomanager.schedule_thread_timer(
            HB_SETTINGS_VALUE(general_config->shutdown_status_check_freq_ms) * 1000 * 1000, false /* recurring */,
            nullptr, [this, shutdown_done_cb, force](void* cookie) { schedule_shutdown(shutdown_done_cb, force); });
        return;
    }

    /* We set the clean shutdown flag only when it is not forcefully shutdown. In clean shutdown
     * we don't replay journal on boot and assume that everything is correct.
     */
    if (!m_force_shutdown) {
        ((homeblks_sb*)m_homeblks_sb_buf.bytes())->set_flag(HOMEBLKS_SB_FLAGS_CLEAN_SHUTDOWN);
        if (!m_cfg.is_read_only) { homeblks_sb_write(); }
    }

    // Waiting for http server thread to join
    m_http_server->stop();
    m_http_server.reset();
    LOGINFO("http server stopped");

    /* XXX: can we move it to indx mgr */
    home_log_store_mgr.stop();
    meta_blk_mgr->stop();
    iomanager.default_drive_interface()->detach_end_of_batch_cb();
    iomanager.stop_io_loop();

    auto cb = m_shutdown_done_cb;

    /*
     * Decrement a counter which is incremented for indicating that homeblks is up and running. Once homeblks
     * usage count is 1, which means only remaining instance is the global _instance variable, we can do the
     * _instance cleanup
     */
    intrusive_ptr_release(this);

    if (cb) cb(true);
    return;
}

void HomeBlks::do_volume_shutdown(bool force) {
    if (!force && !Volume::can_all_vols_shutdown()) {
        Volume::trigger_homeblks_cp();
        return;
    }

    bool expected = false;
    bool desired = true;
    if (!m_start_shutdown.compare_exchange_strong(expected, desired)) { return; }

    /* XXX:- Do we need a force time here. It might get stuck in cp */
    Volume::shutdown(([this](bool success) {
        std::unique_lock< std::recursive_mutex > lg(m_vol_lock);

        auto system_cap = get_system_capacity();
        LOGINFO("{}", system_cap.to_string());
        m_volume_map.clear();
        LOGINFO("All volumes are shutdown successfully, proceed to bring down other subsystems");
        m_vol_shutdown_cmpltd = true;
    }));
}

//
// Each volume will have use_count set to 2 here in this function:
// 1. HomeBlks::m_volume_map;
// 2. This function's it->second hold another use_count
// 3. IOTest::vol will hold another use_count but we will release use_count
// in IOTest before this function so it will be same use_count both with production or test.
//

std::error_condition HomeBlks::remove_volume(const boost::uuids::uuid& uuid) {
    if (HS_STATIC_CONFIG(input.is_read_only)) {
        assert(0);
        return std::make_error_condition(std::errc::device_or_resource_busy);
    }

    if (!m_rdy || is_shutdown()) { return std::make_error_condition(std::errc::device_or_resource_busy); }

    try {
        VolumePtr cur_vol = nullptr;
        {
            std::lock_guard< std::recursive_mutex > lg(m_vol_lock);
            auto it = m_volume_map.find(uuid);
            if (it == m_volume_map.end()) { return std::make_error_condition(std::errc::no_such_device_or_address); }
            cur_vol = it->second;
        }

        /* Taking a reference on volume only to make sure that it won't get dereference while destroy is going on. One
         * possible scenario if shutdown is called while remove is happening.
         */
        cur_vol->destroy(([this, uuid, cur_vol](bool success) {
            if (success) {
                std::lock_guard< std::recursive_mutex > lg(m_vol_lock);
                m_volume_map.erase(uuid);
            }
        }));

        // volume destructor will be called since the user_count of share_ptr
        // will drop to zero while going out of this scope;

        VOL_INFO_LOG(uuid, " Deleting the volume name: {}", cur_vol->get_name());
        return no_error;
    } catch (std::exception& e) {
        LOGERROR("{}", e.what());
        auto error = std::make_error_condition(std::errc::io_error);
        return error;
    }
}

vol_state HomeBlks::get_state(VolumePtr vol) { return vol->get_state(); }

bool HomeBlks::fix_tree(VolumePtr vol, bool verify) { return vol->fix_mapping_btree(verify); }

void HomeBlks::call_multi_vol_completions() {
    auto v_comp_events = 0;

    if (s_io_completed_volumes) {
        auto comp_vols = s_io_completed_volumes;
        s_io_completed_volumes = nullptr;

        for (auto& v : *comp_vols) {
            v_comp_events += v->call_batch_completion_cbs();
        }
        sisl::VectorPool< std::shared_ptr< Volume > >::free(comp_vols);
        if (m_cfg.end_of_batch_cb && v_comp_events) {
            LOGTRACE("Total completions across all volumes in the batch = {}. Calling end of batch callback",
                     v_comp_events);
            m_cfg.end_of_batch_cb(v_comp_events);
        }
    }
}

void HomeBlks::migrate_sb() {
    migrate_homeblk_sb();
    migrate_volume_sb();
    migrate_logstore_sb();
    migrate_cp_sb();

    meta_blk_mgr->set_migrated();
}

void HomeBlks::migrate_logstore_sb() {}
void HomeBlks::migrate_cp_sb() {}

void HomeBlks::migrate_homeblk_sb() {
    std::lock_guard< std::recursive_mutex > lg(m_vol_lock);
    void* cookie = nullptr;
    meta_blk_mgr->add_sub_sb("HOMEBLK", (void*)m_homeblks_sb_buf.bytes(), sizeof(homeblks_sb), cookie);
}

void HomeBlks::migrate_volume_sb() {
    std::lock_guard< std::recursive_mutex > lg(m_vol_lock);
    void* cookie = nullptr;
    for (auto it = m_volume_map.cbegin(); it != m_volume_map.end(); it++) {
        auto vol = it->second;
        vol->migrate_sb();
    }
}

/* Recovery has these steps
 * - Meta blk recovery start :- It is started when its blkstore is loaded
 *      - Blk alloc bit map recovery start :- It is started when its superblock is read.
 * - Meta blk recovery done :- It is done when all meta blks are read and subystems are notified
 *          - Log store recovery start
 *              - Btree recovery start
 *              - Btree recovery done
 *          - Log store recovery done
 *               - Vol recovery start
 *               - Vol recovery done
 *      - Blk alloc bit map recovery done :- It is done when all the entries in journal are replayed.
 */

void HomeBlks::meta_blk_found_cb(meta_blk* mblk, sisl::byte_view buf, size_t size) {
    instance()->meta_blk_found(mblk, buf, size);
}
void HomeBlks::meta_blk_recovery_comp_cb(bool success) { instance()->meta_blk_recovery_comp(success); }

void HomeBlks::meta_blk_recovery_comp(bool success) {
    HS_ASSERT(RELEASE, success, "failed to recover HomeBlks SB.");
    auto sb = (homeblks_sb*)m_homeblks_sb_buf.bytes();
    /* check the status of last boot */
    if (sb->test_flag(HOMEBLKS_SB_FLAGS_CLEAN_SHUTDOWN)) {
        LOGDEBUG("System was shutdown cleanly.");
    } else if (!HS_STATIC_CONFIG(input.disk_init)) {
        LOGCRITICAL("System experienced sudden panic since last boot!");
    } else {
        HS_ASSERT(RELEASE, m_cfg.disk_init, "not the first boot");
        LOGINFO("first time boot");
    }
    // clear the flag and persist to disk, if we received a new shutdown and completed successfully,
    // the flag should be set again;
    sb->clear_flag(HOMEBLKS_SB_FLAGS_CLEAN_SHUTDOWN);
    ++sb->boot_cnt;

    sisl::HttpServerConfig cfg;
    cfg.is_tls_enabled = false;
    cfg.bind_address = "0.0.0.0";
    cfg.server_port = SDS_OPTIONS["hb_stats_port"].as< int32_t >();
    cfg.read_write_timeout_secs = 10;

    m_http_server = std::unique_ptr< sisl::HttpServer >(
        new sisl::HttpServer(cfg,
                             {{
                                 handler_info("/api/v1/version", HomeBlks::get_version, (void*)this),
                                 handler_info("/api/v1/getMetrics", HomeBlks::get_metrics, (void*)this),
                                 handler_info("/api/v1/getObjLife", HomeBlks::get_obj_life, (void*)this),
                                 handler_info("/metrics", HomeBlks::get_prometheus_metrics, (void*)this),
                                 handler_info("/api/v1/getLogLevel", HomeBlks::get_log_level, (void*)this),
                                 handler_info("/api/v1/setLogLevel", HomeBlks::set_log_level, (void*)this),
                                 handler_info("/api/v1/dumpStackTrace", HomeBlks::dump_stack_trace, (void*)this),
                                 handler_info("/api/v1/verifyHS", HomeBlks::verify_hs, (void*)this),
                             }}));
    m_http_server->start();

    // Attach all completions
    iomanager.default_drive_interface()->attach_end_of_batch_cb([this](int nevents) { call_multi_vol_completions(); });

    /* phase 1 updates a btree superblock required for btree recovery during journal replay */
    vol_recovery_start_phase1();

    // start log store recovery
    LOGINFO("home log store recovery is started");
    home_log_store_mgr.start(m_cfg.disk_init);

    /* indx would have recovered by now */
    indx_recovery_done();

    // start volume data recovery
    LOGINFO("volume recovery is started");
    vol_recovery_start_phase2();

    LOGINFO("writing homeblks superblk in init");
    homeblks_sb_write();

    /* scan all the volumes and check if it needs to be mounted */
    for (auto it = m_volume_map.cbegin(); it != m_volume_map.cend(); ++it) {
        if (!m_cfg.vol_found_cb(it->second->get_uuid())) { remove_volume(it->second->get_uuid()); }
    }

    // trigger CP
    LOGINFO("triggering system CP in init");
    Volume::trigger_homeblks_cp(([this](bool success) {
        if (success) {
            LOGINFO("system CP is taken in init");
            init_done(no_error);
        } else {
            LOGERROR("{}", "system cp failed");
            init_done(std::make_error_condition(std::errc::io_error));
        }
    }));
}

void HomeBlks::meta_blk_found(meta_blk* mblk, sisl::byte_view buf, size_t size) {
    static bool meta_blk_found = false;

    // HomeBlk layer expects to see one valid meta_blk record during reboot;
    HS_ASSERT(RELEASE, !meta_blk_found, "More than one HomeBlk SB is received, only expecting one!");

    meta_blk_found = true;

    HS_ASSERT(RELEASE, mblk != nullptr, "null meta blk received in meta_blk_found_callback.");

    m_sb_cookie = (void*)mblk;

    // recover from meta_blk;
    m_homeblks_sb_buf = buf;
}

void HomeBlks::vol_recovery_start_phase1() {
    for (auto it = m_volume_map.cbegin(); it != m_volume_map.cend(); ++it) {
        it->second->recovery_start_phase1();
    }
}

void HomeBlks::vol_recovery_start_phase2() {
    for (auto it = m_volume_map.cbegin(); it != m_volume_map.cend(); ++it) {
        it->second->recovery_start_phase2();
    }
}

/* * Snapshot APIs  * */
SnapshotPtr HomeBlks::create_snapshot(const VolumePtr& vol) { return nullptr; }

std::error_condition HomeBlks::remove_snapshot(const SnapshotPtr& snap) {
    std::error_condition ok;
    return ok;
}

SnapshotPtr HomeBlks::clone_snapshot(const SnapshotPtr& snap) { return nullptr; }

std::error_condition HomeBlks::restore_snapshot(const SnapshotPtr& snap) {
    std::error_condition ok;
    return ok;
}

void HomeBlks::list_snapshot(const VolumePtr&, std::vector< SnapshotPtr > snap_list) {}

void HomeBlks::read(const SnapshotPtr& snap, const snap_interface_req_ptr& req) {}
