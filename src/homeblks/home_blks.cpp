#include <algorithm>
#include <fstream>
#include <iterator>
#include <iostream>
#include <stdexcept>

#include <boost/lexical_cast.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <nlohmann/json.hpp>
#include <sds_logging/logging.h>
#include <sisl/version.hpp>

#include "engine/common/homestore_status_mgr.hpp"
#include "engine/blkstore/blkbuffer.hpp"
#include "engine/device/device.h"
#include "engine/device/virtual_dev.hpp"
#include "homelogstore/log_store.hpp"
#include "homeblks_http_server.hpp"
#include "volume/volume.hpp"

#include "home_blks.hpp"

SDS_OPTION_GROUP(home_blks,
                 (hb_stats_port, "", "hb_stats_port", "Stats port for HTTP service",
                  cxxopts::value< int32_t >()->default_value("5000"), "port"))
using namespace homestore;

#ifndef DEBUG
bool same_value_gen = false;
#endif

std::string HomeBlks::version = PACKAGE_VERSION;
thread_local std::vector< std::shared_ptr< Volume > >* HomeBlks::s_io_completed_volumes = nullptr;

void VolInterfaceImpl::zero_boot_sbs(const std::vector< dev_info >& devices) {
    return (HomeBlks::zero_boot_sbs(devices));
}

VolInterface* VolInterfaceImpl::init(const init_params& cfg, bool fake_reboot) {
#ifdef _PRERELEASE
    if (cfg.force_reinit) { zero_boot_sbs(cfg.data_devices); }
#endif

    return (HomeBlks::init(cfg, fake_reboot));
}

bool VolInterfaceImpl::shutdown(const bool force) { return HomeBlks::shutdown(force); }

#if 0
boost::intrusive_ptr< VolInterface > VolInterfaceImpl::safe_instance() {
    return boost::dynamic_pointer_cast< VolInterface >(HomeBlks::safe_instance());
}
#endif
VolInterface* VolInterfaceImpl::raw_instance() { return HomeBlks::instance(); }

VolInterface* HomeBlks::init(const init_params& cfg, bool fake_reboot) {
    fLI::FLAGS_minloglevel = 3;
    HomeBlksSafePtr instance;
    VolInterface* ret{nullptr};

    static std::once_flag flag1;
    try {

        /* Note :- it is not thread safe. We only support it for testing */
        if (fake_reboot) {
            HomeStore::fake_reboot();
            MetaBlkMgrSI()->register_handler("HOMEBLK", HomeBlks::meta_blk_found_cb,
                                             HomeBlks::meta_blk_recovery_comp_cb);
            Volume::fake_reboot();
            m_meta_blk_found = false;
            instance = HomeBlksSafePtr(new HomeBlks(cfg));
        }
        std::call_once(flag1, [&cfg, &instance]() {
#ifndef NDEBUG
            LOGINFO("HomeBlks DEBUG version: {}", HomeBlks::version);
#else
            LOGINFO("HomeBlks RELEASE version: {}", HomeBlks::version);
#endif
            sisl::VersionMgr::addVersion(PACKAGE_NAME, version::Semver200_version(PACKAGE_VERSION));
            MetaBlkMgrSI()->register_handler("HOMEBLK", HomeBlks::meta_blk_found_cb,
                                             HomeBlks::meta_blk_recovery_comp_cb);
            MetaBlkMgrSI()->register_handler("VOLUME", Volume::meta_blk_found_cb, nullptr);
            instance = HomeBlksSafePtr(new HomeBlks(cfg));
            LOGINFO("HomeBlks Dynamic config version: {}", HB_DYNAMIC_CONFIG(version));
        });
        set_instance(boost::static_pointer_cast< homestore::HomeStoreBase >(instance));
        ret = static_cast< VolInterface* >(instance.get());
    } catch (const std::exception& e) {
        LOGERROR("{}", e.what());
        HS_DEBUG_ASSERT(false, "Exception during homeblks start");
        return ret;
    }

    /* start thread */
    auto sthread = sisl::named_thread("hb_init", [instance]() {
        iomanager.run_io_loop(false, nullptr, [instance](bool thread_started) {
            if (thread_started) {
                instance->m_init_thread_id = iomanager.iothread_self();
                if (instance->is_safe_mode()) {
                    std::unique_lock< std::mutex > lk(instance->m_cv_mtx);
                    /* we wait for gdb to attach in safe mode */
                    LOGINFO("Going to sleep. Waiting for user to send http command to wake up");
                    instance->m_cv_wakeup_init.wait(lk);
                }
                instance->init_devices();
            }
        });
    });
    sthread.detach();

    /* start custom io threads for hdd */
    if (is_data_drive_hdd()) {
        const uint32_t hdd_thread_count{HS_DYNAMIC_CONFIG(generic.hdd_io_threads)};
        instance->m_custom_hdd_threads.reserve(hdd_thread_count);

        for (auto i = 0u; i < hdd_thread_count; ++i) {
            auto sthread1 = sisl::named_thread("custom_hdd", [&instance, hdd_thread_count]() {
                iomanager.run_io_loop(false, nullptr, [&](bool is_started) {
                    if (is_started) {
                        std::lock_guard< std::mutex > lock(instance->m_hdd_threads_mtx);
                        instance->m_custom_hdd_threads.emplace_back(iomanager.iothread_self());
                        if (instance->m_custom_hdd_threads.size() == hdd_thread_count) {
                            instance->m_hdd_threads_cv.notify_one();
                        }
                    }
                });
            });
            sthread1.detach();
        }

        {
            auto lg = std::unique_lock< std::mutex >(instance->m_hdd_threads_mtx);
            instance->m_hdd_threads_cv.wait(lg, [&instance, hdd_thread_count]() {
                return (instance->m_custom_hdd_threads.size() == hdd_thread_count);
            });
        }
    }
    return ret;
}

HomeBlks::~HomeBlks() = default;

void HomeBlks::zero_boot_sbs(const std::vector< dev_info >& devices) {
    if (devices.empty()) return;
    auto& hs_config = HomeStoreStaticConfig::instance();

    // ensure devices are all the same type
    const auto dev_type{devices.front().dev_type};
    for (size_t device_num{1}; device_num < devices.size(); ++device_num) {
        if (devices[device_num].dev_type != dev_type) {
            HS_LOG(ERROR, device, "dev={} type={} does not match type dev={} type={}", devices[device_num].dev_names,
                   devices[device_num].dev_type, devices.front().dev_names, dev_type);
            HS_DEBUG_ASSERT(false, "Mixed zero_boot_sbs device types");
        }
    }
    return DeviceManager::zero_boot_sbs(devices);
}

vol_interface_req::vol_interface_req(void* const buf, const uint64_t lba, const uint32_t nlbas, const bool is_sync,
                                     const bool cache) :
        buffer{buf},
        request_id{counter_generator.next_request_id()},
        refcount{0},
        lba{lba},
        nlbas{nlbas},
        sync{is_sync},
        cache{cache} {}

vol_interface_req::vol_interface_req(std::vector< iovec > iovecs, const uint64_t lba, const uint32_t nlbas,
                                     const bool is_sync, const bool cache) :
        iovecs{std::move(iovecs)},
        request_id{counter_generator.next_request_id()},
        refcount{0},
        lba{lba},
        nlbas{nlbas},
        sync{is_sync},
        cache{cache} {}

vol_interface_req::~vol_interface_req() = default;

HomeBlks::HomeBlks(const init_params& cfg) :
        m_cfg(cfg), m_metrics(new HomeBlksMetrics("HomeBlks")), m_start_shutdown{false} {
    LOGINFO("Initializing HomeBlks with Config {}", m_cfg.to_string());

    if (m_cfg.start_http) {
        m_hb_http_server = std::make_unique< HomeBlksHttpServer >(this);
        m_hb_http_server->start();
    } else {
        LOGINFO("Http server is not started by user! start_http = {}", m_cfg.start_http);
    }

    HomeStore< BLKSTORE_BUFFER_TYPE >::init((const hs_input_params&)cfg);

    sisl::MallocMetrics::enable();

    m_recovery_stats = std::make_unique< HomeBlksRecoveryStats >();
    m_recovery_stats->start();

    if (HB_DYNAMIC_CONFIG(general_config->boot_safe_mode)) { LOGINFO("HomeBlks booting into safe_mode"); }
}

void HomeBlks::wakeup_init() { m_cv_wakeup_init.notify_one(); }

void HomeBlks::attach_prepare_indx_cp(std::map< boost::uuids::uuid, indx_cp_ptr >* cur_icp_map,
                                      std::map< boost::uuids::uuid, indx_cp_ptr >* new_icp_map, hs_cp* cur_hcp,
                                      hs_cp* new_hcp) {

    std::lock_guard< std::recursive_mutex > lg(m_vol_lock);

#ifndef NDEBUG
    /* If a volume is participated in a cp then it can not be deleted without participating
     * in a cp flush.
     */
    if (cur_icp_map) {
        for (auto it = cur_icp_map->cbegin(); it != cur_icp_map->cend(); ++it) {
            assert(m_volume_map.find(it->first) != m_volume_map.cend());
        }
    }
#endif

    for (auto it = m_volume_map.cbegin(); it != m_volume_map.cend(); ++it) {
        auto vol = it->second;
        if (vol == nullptr) { continue; }

        /* get the cur cp id ptr */
        indx_cp_ptr cur_icp = nullptr;
        auto id_it = cur_icp_map->find(it->first);
        if (id_it != cur_icp_map->end()) {
            cur_icp = id_it->second;
        } else {
            /* It is a new volume which is created after this cp */
            cur_icp = nullptr;
        }

        /* get the cur cp id ptr */
        auto new_icp = vol->attach_prepare_volume_cp(cur_icp, cur_hcp, new_hcp);

        if (new_icp) {
            bool happened{false};
            std::map< boost::uuids::uuid, indx_cp_ptr >::iterator temp_it;
            std::tie(temp_it, happened) = new_icp_map->emplace(std::make_pair(it->first, new_icp));
            if (!happened) { throw std::runtime_error("Unknown bug"); }
        } else {
            /* this volume doesn't want to participate now */
            assert(vol->get_state() == vol_state::DESTROYING);
        }
    }
}

vol_interface_req_ptr HomeBlks::create_vol_interface_req(void* const buf, const uint64_t lba, const uint32_t nlbas,
                                                         const bool is_sync, const bool cache) {
    return vol_interface_req_ptr(new vol_interface_req(buf, lba, nlbas, is_sync, cache));
}

vol_interface_req_ptr HomeBlks::create_vol_interface_req(std::vector< iovec > iovecs, const uint64_t lba,
                                                         const uint32_t nlbas, const bool is_sync, const bool cache) {
    return vol_interface_req_ptr(new vol_interface_req(iovecs, lba, nlbas, is_sync, cache));
}

std::error_condition HomeBlks::write(const VolumePtr& vol, const vol_interface_req_ptr& req, bool part_of_batch) {
    assert(m_rdy);
    if (!vol) {
        assert(false);
        throw std::invalid_argument("null vol ptr");
    }
    if (!m_rdy || is_shutdown()) { return std::make_error_condition(std::errc::device_or_resource_busy); }
    req->vol_instance = vol;
    req->part_of_batch = part_of_batch;
    req->op_type = Op_type::WRITE;
    if (is_data_drive_hdd()) {
        iomanager.run_on(m_custom_hdd_threads[next_available_hdd_thread_idx()],
                         [vol, req](io_thread_addr_t addr) { vol->write(req); });
        return std::error_condition();
    }
    return (vol->write(req));
}

std::error_condition HomeBlks::read(const VolumePtr& vol, const vol_interface_req_ptr& req, bool part_of_batch) {
    assert(m_rdy);
    if (!vol) {
        assert(false);
        throw std::invalid_argument("null vol ptr");
    }
    if (!m_rdy || is_shutdown()) { return std::make_error_condition(std::errc::device_or_resource_busy); }
    req->vol_instance = vol;
    req->part_of_batch = part_of_batch;
    req->op_type = Op_type::READ;
    if (is_data_drive_hdd()) {
        iomanager.run_on(m_custom_hdd_threads[next_available_hdd_thread_idx()],
                         [vol, req](io_thread_addr_t addr) { vol->read(req); });
        return std::error_condition();
    }
    return (vol->read(req));
}

std::error_condition HomeBlks::sync_read(const VolumePtr& vol, const vol_interface_req_ptr& req) {
    assert(m_rdy);
    if (!vol) {
        assert(false);
        throw std::invalid_argument("null vol ptr");
    }
    if (!m_rdy || is_shutdown()) { return std::make_error_condition(std::errc::device_or_resource_busy); }
    req->vol_instance = vol;
    return (vol->read(req));
}

std::error_condition HomeBlks::unmap(const VolumePtr& vol, const vol_interface_req_ptr& req) {
    assert(m_rdy);
    if (!vol) {
        assert(false);
        throw std::invalid_argument("null vol ptr");
    }
    if (!m_rdy || is_shutdown()) { return std::make_error_condition(std::errc::device_or_resource_busy); }
    req->vol_instance = vol;
    req->op_type = Op_type::UNMAP;
    if (is_data_drive_hdd()) {
        iomanager.run_on(m_custom_hdd_threads[next_available_hdd_thread_idx()],
                         [vol, req](io_thread_addr_t addr) { vol->unmap(req); });
        return std::error_condition();
    }
    return (vol->unmap(req));
}

const char* HomeBlks::get_name(const VolumePtr& vol) { return vol->get_name(); }
uint64_t HomeBlks::get_page_size(const VolumePtr& vol) { return vol->get_page_size(); }
uint64_t HomeBlks::get_size(const VolumePtr& vol) { return vol->get_size(); }
boost::uuids::uuid HomeBlks::get_uuid(VolumePtr vol) { return vol->get_uuid(); }
sisl::blob HomeBlks::at_offset(const blk_buf_t& buf, uint32_t offset) { return (buf->at_offset(offset)); }

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
        assert(false);
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
    std::shared_ptr< Volume > new_vol;
    try {
        new_vol = Volume::make_volume(params);
    } catch (const std::exception& e) {
        LOGERROR("volume creation failed exception: {}", e.what());
        return nullptr;
    }

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

bool HomeBlks::inc_hs_ref_cnt(const boost::uuids::uuid& uuid) {
    auto vol = lookup_volume(uuid);
    if (!vol) return false;
    vol->inc_ref_cnt();
    return true;
}

bool HomeBlks::dec_hs_ref_cnt(const boost::uuids::uuid& uuid) {
    auto vol = lookup_volume(uuid);
    if (!vol) return false;
    vol->shutdown_if_needed();
    return true;
}

bool HomeBlks::fault_containment(const boost::uuids::uuid& uuid) {
    auto vol = lookup_volume(uuid);
    if (!vol) return false;
    vol->fault_containment();
    return true;
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
    // iomanager.default_drive_interface()->submit_batch();
    call_multi_completions();
}

HomeBlks* HomeBlks::instance() { return static_cast< HomeBlks* >(HomeStoreBase::instance()); }
HomeBlksSafePtr HomeBlks::safe_instance() {
    return boost::static_pointer_cast< HomeBlks >(HomeStoreBase::safe_instance());
}

homeblks_sb* HomeBlks::superblock_init() {
    HS_RELEASE_ASSERT_EQ(m_homeblks_sb_buf, nullptr, "Reinit already initialized super block");

    /* build the homeblks super block */
    // TO DO: Might need to address alignment based on data or fast type
    const uint64_t hb_sb_size =
        get_meta_blkstore()->get_vdev()->get_atomic_page_size(); // it is not really required. Kept it for compatibility
    m_homeblks_sb_buf = hs_utils::make_byte_array(hb_sb_size, MetaBlkMgrSI()->is_aligned_buf_needed(hb_sb_size),
                                                  sisl::buftag::metablk, MetaBlkMgrSI()->get_align_size());

    auto* sb = new (m_homeblks_sb_buf->bytes) homeblks_sb();
    sb->version = hb_sb_version;
    sb->magic = hb_sb_magic;
    sb->boot_cnt = 0;
    sb->init_flag(0);
    return sb;
}

void HomeBlks::homeblks_sb_write() {
    if (m_sb_cookie == nullptr) {
        // add to MetaBlkMgr
        MetaBlkMgrSI()->add_sub_sb("HOMEBLK", (void*)m_homeblks_sb_buf->bytes, sizeof(homeblks_sb), m_sb_cookie);
    } else {
        // update existing homeblks sb
        MetaBlkMgrSI()->update_sub_sb((void*)m_homeblks_sb_buf->bytes, sizeof(homeblks_sb), m_sb_cookie);
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

void HomeBlks::move_to_restricted_state() {
    ((homeblks_sb*)m_homeblks_sb_buf->bytes)->set_flag(HOMEBLKS_SB_FLAGS_RESTRICTED);
    homeblks_sb_write();
}

void HomeBlks::attach_vol_completion_cb(const VolumePtr& vol, const io_comp_callback& cb) {
    vol->attach_completion_cb(cb);
}

void HomeBlks::attach_end_of_batch_cb(const end_of_batch_callback& cb) {
    m_cfg.end_of_batch_cb = cb;
    iomanager.generic_interface()->attach_listen_sentinel_cb([this]() { call_multi_completions(); });
}

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

void HomeBlks::init_done() {
    cap_attrs used_size;
    for (auto it = m_volume_map.cbegin(); it != m_volume_map.cend(); ++it) {
        if (it->second->get_state() == vol_state::ONLINE) { vol_mounted(it->second, it->second->get_state()); }
        used_size.add(it->second->get_used_size());
    }
    auto system_cap = get_system_capacity();
    LOGINFO("system_cap from blkstore: {}, system cap from volume: {}", system_cap.to_string(), used_size.to_string());
    LOGINFO("number of streams {}, stream size {}", get_num_streams(), get_stream_size());

#ifdef _PRERELEASE
    HB_SETTINGS_FACTORY().modifiable_settings([](auto& s) { s.general_config.boot_consistency_check = true; });
    HB_SETTINGS_FACTORY().save();
#endif

    if (is_safe_mode() || HB_DYNAMIC_CONFIG(general_config->boot_consistency_check)) {
        HS_RELEASE_ASSERT((verify_bitmap()), "bitmap verify failed");
    } else {
        LOGINFO("Skip running verification (vols/bitmap).");
    }
    HS_RELEASE_ASSERT_EQ(system_cap.used_data_size, used_size.used_data_size,
                         "vol data used size mismatch. used size {}", used_size.to_string());
    HS_RELEASE_ASSERT_EQ(system_cap.used_index_size, used_size.used_index_size,
                         "index used size mismatch. used size {}", used_size.to_string());

    LOGINFO("init done");
    m_out_params.first_time_boot = m_dev_mgr->is_first_time_boot();
    m_out_params.max_io_size = HS_STATIC_CONFIG(engine.max_vol_io_size);
    if (m_cfg.end_of_batch_cb) { attach_end_of_batch_cb(m_cfg.end_of_batch_cb); }

    status_mgr()->register_status_cb("MetaBlkMgr",
                                     std::bind(&MetaBlkMgr::get_status, MetaBlkMgrSI(), std::placeholders::_1));
    status_mgr()->register_status_cb("Volumes", std::bind(&HomeBlks::get_status, this, std::placeholders::_1));

    m_recovery_stats->end();

    /* start custom io threads for hdd */
    if (is_data_drive_hdd()) {
        m_custom_hdd_threads.reserve(HS_DYNAMIC_CONFIG(generic.hdd_io_threads));
        std::atomic< uint32_t > thread_cnt{0};
        uint32_t expected_thread_cnt{HS_DYNAMIC_CONFIG(generic.hdd_io_threads)};
        for (auto i = 0u; i < expected_thread_cnt; ++i) {
            auto sthread1 = sisl::named_thread("custom_hdd_thrd", [this, &thread_cnt]() mutable {
                iomanager.run_io_loop(false, nullptr, [this, &thread_cnt](bool is_started) {
                    if (is_started) {
                        ++thread_cnt;
                        const std::lock_guard< std::mutex > lock(m_hdd_threads_mtx);
                        m_custom_hdd_threads.push_back(iomanager.iothread_self());
                    } else {
                        // it is called during shutdown
                    }
                });
            });
            sthread1.detach();
        }
        while (thread_cnt.load(std::memory_order_acquire) != expected_thread_cnt) {}
    }

    if (!is_safe_mode()) { m_cfg.init_done_cb(no_error, m_out_params); }
    // Don't do any callback if it is running in safe mode
}

BlkStore< BlkBuffer >::comp_callback HomeBlks::data_completion_cb() { return Volume::process_vol_data_completions; };

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

bool HomeBlks::verify_vols() {
    LOGINFO("Start verification for all volumes. ");
    std::unique_lock< std::recursive_mutex > lg(m_vol_lock);
    auto it = m_volume_map.begin();
    bool ret = true;
    while (it != m_volume_map.end()) {
        ret = verify_tree(it->second);
        if (!ret) { return ret; }
        ++it;
    }
    return ret;
}

bool HomeBlks::verify_data_bm() {
    /* Create the data bitmap */
    auto hb{HomeBlks::safe_instance()};
    auto* const data_blkstore_ptr{hb->get_data_blkstore()};
    BlkAllocStatus status{data_blkstore_ptr->create_debug_bm()};
    if (status != BlkAllocStatus::SUCCESS) {
        LOGERROR("failing to create data debug bitmap as it is out of disk space");
        return false;
    }

    /* Update the data bitmap */
    std::unique_lock< std::recursive_mutex > lg(m_vol_lock);
    auto it{m_volume_map.begin()};
    LOGINFO("Verifying the integrity of the data bitmap : START");
    while (it != m_volume_map.end()) {
        const VolumePtr& vol{it->second};
        vol->populate_debug_bm();
        ++it;
    }

    /* Verify data bitmap */
    BlkAllocStatus ver_status{hb->get_data_blkstore()->verify_debug_bm()};
    if (ver_status != BlkAllocStatus::SUCCESS) {
        LOGERROR("failing to match data debug bitmap with persisted bitmap");
        return false;
    }
    LOGINFO("Verifying the integrity of the data bitmap : DONE");
    return true;
}

bool HomeBlks::verify_index_bm() {
    /* Create the index bitmap */
    auto hb{HomeBlks::safe_instance()};
    auto* const index_blockstore_ptr{hb->get_index_blkstore()};
    BlkAllocStatus status{index_blockstore_ptr->create_debug_bm()};
    if (status != BlkAllocStatus::SUCCESS) {
        LOGERROR("failing to create index debug bitmap as it is out of disk space");
        return false;
    }

    /* Update the index bitmap */
    std::unique_lock< std::recursive_mutex > lg(m_vol_lock);
    auto it{m_volume_map.begin()};
    LOGINFO("Verifying the integrity of the index bitmap : START");
    while (it != m_volume_map.end()) {
        const VolumePtr& vol{it->second};
        vol->verify_tree(true);
        ++it;
    }

    /* Verify index bitmap */
    BlkAllocStatus ver_status{hb->get_index_blkstore()->verify_debug_bm()};
    if (ver_status != BlkAllocStatus::SUCCESS) {
        LOGERROR("failing to match index debug bitmap with persisted bitmap");
        return false;
    }
    LOGINFO("Verifying the integrity of the Index bitmap : DONE");
    return true;
}

nlohmann::json HomeBlks::get_status(const int log_level) {
    nlohmann::json j;
    /* Update per volume status */
    std::unique_lock< std::recursive_mutex > lg(m_vol_lock);
    auto it{m_volume_map.begin()};
    LOGINFO("Print status of all volumes");
    while (it != m_volume_map.end()) {
        const VolumePtr& vol{it->second};
        auto vol_json = vol->get_status(log_level);
        if (!vol_json.empty()) { j.update(vol_json); }
        ++it;
    }
    /* Get status from index blkstore */
    auto hb{HomeBlks::safe_instance()};
    auto index_blkstore_json = hb->get_index_blkstore()->get_status(log_level);
    if (!index_blkstore_json.empty()) { j.update(index_blkstore_json); }

    return j;
}

bool HomeBlks::verify_bitmap() {
    StaticIndxMgr::hs_cp_suspend();
    HS_RELEASE_ASSERT(verify_data_bm(), "data debug bitmap verify failed");
    HS_RELEASE_ASSERT(verify_index_bm(), "index debug bitmap verify failed");
    StaticIndxMgr::hs_cp_resume();
    return true;
}

void HomeBlks::print_node(const VolumePtr& vol, uint64_t blkid, bool chksum) {
    m_print_checksum = chksum;
    vol->print_node(blkid);
}

bool HomeBlks::shutdown(bool force) {
    // this should be static so that it stays in scope in the lambda in case function ends before lambda completes
    static std::mutex stop_mutex;
    static std::condition_variable cv;
    static bool status;
    static bool done;

    status = false;
    done = false;
    auto hb{HomeBlks::safe_instance()};
    const bool wait{hb->trigger_shutdown(
        [](bool is_success) {
            LOGINFO("Completed the shutdown of HomeBlks with success ? {}", is_success);
            {
                std::unique_lock< std::mutex > lk{stop_mutex};
                status = is_success;
                done = true;
            }
            cv.notify_one();
        },
        force)};

    // Wait for the shutdown completion.
    if (wait) {
        std::unique_lock< std::mutex > lk{stop_mutex};
        cv.wait(lk, [] { return done; });
    }
    HomeStoreBase::reset_instance();
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
            if (thread_started) { do_shutdown(shutdown_done_cb, force); }
        });
    });
    sthread.detach();
    return true;
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
        if (!m_init_finished.load()) { m_cv_init_cmplt.wait(lk); }
    }

    auto elapsed_time_ms = get_time_since_epoch_ms() - m_shutdown_start_time.load();
    if (elapsed_time_ms > (HB_DYNAMIC_CONFIG(general_config->shutdown_timeout_secs) * 1000)) {
        HS_RELEASE_ASSERT(
            false, "Graceful shutdown of volumes took {} ms exceeds time limit {} seconds, forcefully shutting down",
            elapsed_time_ms, HB_DYNAMIC_CONFIG(general_config->shutdown_timeout_secs));
    }

    m_shutdown_done_cb = shutdown_done_cb;
    m_force_shutdown = force;
    do_volume_shutdown(force);

    if (!m_vol_shutdown_cmpltd) {
        LOGINFO("Not all volumes are completely shutdown yet, will check again in {} milliseconds",
                HB_DYNAMIC_CONFIG(general_config->shutdown_status_check_freq_ms));
        m_shutdown_timer_hdl = iomanager.schedule_thread_timer(
            HB_DYNAMIC_CONFIG(general_config->shutdown_status_check_freq_ms) * 1000 * 1000, false /* recurring */,
            nullptr, [this, shutdown_done_cb, force](void* cookie) { do_shutdown(shutdown_done_cb, force); });
        return;
    }

    /* We set the clean shutdown flag only when it is not forcefully shutdown. In clean shutdown
     * we don't replay journal on boot and assume that everything is correct.
     */
    if (!m_force_shutdown) {
        ((homeblks_sb*)m_homeblks_sb_buf->bytes)->set_flag(HOMEBLKS_SB_FLAGS_CLEAN_SHUTDOWN);
        if (!m_cfg.is_read_only) { homeblks_sb_write(); }
    }

    // Waiting for http server thread to join
    if (m_cfg.start_http) {
        m_hb_http_server->stop();
        m_hb_http_server.reset();
        LOGINFO("http server stopped");
    } else {
        LOGINFO("Skip stopping http server since it was not started before.");
    }

    /* XXX: can we move it to indx mgr */
    HomeLogStoreMgrSI().stop();
    MetaBlkMgrSI()->stop();
    this->close_devices();

    // stop io
    iomanager.generic_interface()->detach_listen_sentinel_cb(iomgr::wait_type_t::spin);
    iomanager.stop_io_loop();
    m_metrics.reset();
    if (m_shutdown_done_cb) { m_shutdown_done_cb(true); }
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
    return (remove_volume_internal(uuid, false));
}
std::error_condition HomeBlks::remove_volume_internal(const boost::uuids::uuid& uuid, bool force) {
    if (HS_STATIC_CONFIG(input.is_read_only)) {
        assert(false);
        return std::make_error_condition(std::errc::device_or_resource_busy);
    }

    if ((!force && !m_rdy) || is_shutdown()) { return std::make_error_condition(std::errc::device_or_resource_busy); }

    try {
        VolumePtr cur_vol = nullptr;
        {
            std::lock_guard< std::recursive_mutex > lg(m_vol_lock);
            auto it = m_volume_map.find(uuid);
            if (it == m_volume_map.end()) { return std::make_error_condition(std::errc::no_such_device_or_address); }
            cur_vol = it->second;
        }

        /* Taking a reference on volume only to make sure that it won't get dereference while destroy is going on.
         * One possible scenario if shutdown is called while remove is happening.
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

void HomeBlks::register_status_cb(const std::string& module,
                                  const std::function< nlohmann::json(const int verbosity_level) > get_status_cb) {
    status_mgr()->register_status_cb(module, get_status_cb);
}

bool HomeBlks::fix_tree(VolumePtr vol, bool verify) { return vol->fix_mapping_btree(verify); }

void HomeBlks::call_multi_completions() {
    auto v_comp_events = 0;

    while (s_io_completed_volumes) {
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

    MetaBlkMgrSI()->set_migrated();
}

void HomeBlks::migrate_logstore_sb() {}
void HomeBlks::migrate_cp_sb() {}

void HomeBlks::migrate_homeblk_sb() {
    std::lock_guard< std::recursive_mutex > lg(m_vol_lock);
    void* cookie = nullptr;
    MetaBlkMgrSI()->add_sub_sb("HOMEBLK", (void*)m_homeblks_sb_buf->bytes, sizeof(homeblks_sb), cookie);
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

    m_recovery_stats->phase0_done();
    if (m_dev_mgr->is_first_time_boot()) { superblock_init(); }

    auto sb = (homeblks_sb*)m_homeblks_sb_buf->bytes;
    if (sb->test_flag(HOMEBLKS_SB_FLAGS_RESTRICTED)) {
        HS_RELEASE_ASSERT(is_safe_mode(), "should be boot in safe mode");
        sb->clear_flag(HOMEBLKS_SB_FLAGS_RESTRICTED);
    }
    /* check the status of last boot */
    if (sb->test_flag(HOMEBLKS_SB_FLAGS_CLEAN_SHUTDOWN)) {
        LOGDEBUG("System was shutdown cleanly.");
        HS_ASSERT_CMP(DEBUG, MetaBlkMgr::is_self_recovered(), ==, false);
    } else if (!m_dev_mgr->is_first_time_boot()) {
        m_unclean_shutdown = true;
        LOGCRITICAL("System experienced sudden panic since last boot!");
    } else {
        HS_ASSERT(RELEASE, m_dev_mgr->is_first_time_boot(), "not the first boot");
        LOGINFO("System is booting up first time");
        HS_ASSERT_CMP(DEBUG, MetaBlkMgr::is_self_recovered(), ==, false);
    }

    // clear the flag and persist to disk, if we received a new shutdown and completed successfully,
    // the flag should be set again;
    sb->clear_flag(HOMEBLKS_SB_FLAGS_CLEAN_SHUTDOWN);
    ++sb->boot_cnt;

    /* We don't allow any cp to happen during phase1 */
    StaticIndxMgr::init();

    /* phase 1 updates a btree superblock required for btree recovery during journal replay */
    vol_recovery_start_phase1();

    start_home_log_store();

    StaticIndxMgr::hs_cp_resume(); // cp is suspended by default

    /* indx would have recovered by now */
    indx_recovery_done();

    // start volume data recovery
    LOGINFO("All volumes recovery is started");
    vol_recovery_start_phase2();

    LOGINFO("Writing homeblks super block during init");
    homeblks_sb_write();

    uint32_t vol_mnt_cnt = 0;
    /* scan all the volumes and check if it needs to be mounted */
    {
        std::lock_guard< std::recursive_mutex > lg(m_vol_lock);
        for (auto it = m_volume_map.cbegin(); it != m_volume_map.cend(); ++it) {
            if (!m_cfg.vol_found_cb(it->second->get_uuid())) {
                LOGINFO("volume {} is not valid for AM", it->second->get_name());
                remove_volume_internal(it->second->get_uuid(), true);
            } else if (it->second->get_state() == vol_state::DESTROYING) {
                LOGERROR("volume {} is valid by AM but its state is set to destroying", it->second->get_name());
                remove_volume_internal(it->second->get_uuid(), true);
            } else {
                HS_RELEASE_ASSERT_NE(it->second->get_state(), vol_state::DESTROYING, "volume state is destroyed");
                ++vol_mnt_cnt;
            }
        }
    }

    trigger_cp_init(vol_mnt_cnt);
}

void HomeBlks::trigger_cp_init(uint32_t vol_mnt_cnt) {
    // trigger CP
    LOGINFO("Triggering system CP during initialization");
    Volume::trigger_homeblks_cp(([this, vol_mnt_cnt](bool success) {
        HS_ASSERT(RELEASE, success, "trigger cp during init failed");
        {
            std::lock_guard< std::recursive_mutex > lg(m_vol_lock);
            if (m_volume_map.size() != vol_mnt_cnt) {
                /* trigger another CP until all partial deleted volumes are completed */
                trigger_cp_init(vol_mnt_cnt);
                return;
            }
            /* check if all the volumes have flushed their dirty buffers */
            for (auto it = m_volume_map.cbegin(); it != m_volume_map.cend(); ++it) {
                if (!it->second->is_recovery_done()) {
                    /* trigger another CP */
                    trigger_cp_init(vol_mnt_cnt);
                    return;
                }
            }
        }
        LOGINFO("System CP taken upon init is completed successfully");
        data_recovery_done();
        m_rdy = true;
        iomanager.run_on(m_init_thread_id, ([this](io_thread_addr_t addr) { this->init_done(); }));
        {
            std::unique_lock< std::mutex > lk{m_cv_mtx};
            m_init_finished = true;
            m_cv_init_cmplt.notify_all();
        }
    }));
}

void HomeBlks::meta_blk_found(meta_blk* mblk, sisl::byte_view buf, size_t size) {
    // HomeBlk layer expects to see one valid meta_blk record during reboot;
    HS_ASSERT(RELEASE, !m_meta_blk_found, "More than one HomeBlk SB is received, only expecting one!");

    m_meta_blk_found = true;

    HS_ASSERT(RELEASE, mblk != nullptr, "null meta blk received in meta_blk_found_callback.");

    m_sb_cookie = (void*)mblk;

    // recover from meta_blk;
    // TO DO: Might need to address alignment based on data or fast type
    m_homeblks_sb_buf = hs_utils::extract_byte_array(buf, true, MetaBlkMgrSI()->get_align_size());
    auto* sb = (homeblks_sb*)(m_homeblks_sb_buf->bytes);
    HS_RELEASE_ASSERT_EQ(sb->version, hb_sb_version, "version does not match");
    HS_RELEASE_ASSERT_EQ(sb->magic, hb_sb_magic, "magic does not match");
}

void HomeBlks::start_home_log_store() {
    auto log_store_start = Clock::now();
    // start log store recovery
    LOGINFO("HomeLogStore recovery is started");
    HomeLogStoreMgrSI().start(m_dev_mgr->is_first_time_boot());
    m_recovery_stats->m_log_store_ms = get_elapsed_time_ms(log_store_start);
}

void HomeBlks::vol_recovery_start_phase1() {
    auto phase1_start = Clock::now();
    for (auto it = m_volume_map.cbegin(); it != m_volume_map.cend(); ++it) {
        it->second->recovery_start_phase1();
    }
    m_recovery_stats->m_phase1_ms = get_elapsed_time_ms(phase1_start);
}

void HomeBlks::vol_recovery_start_phase2() {
    auto phase2_start = Clock::now();
    for (auto it = m_volume_map.cbegin(); it != m_volume_map.cend(); ++it) {
        HS_ASSERT(RELEASE, (it->second->verify_tree() == true), "true");
        it->second->recovery_start_phase2();
    }

    m_recovery_stats->m_phase2_ms = get_elapsed_time_ms(phase2_start);
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

std::error_condition HomeBlks::mark_vol_online(const boost::uuids::uuid& uuid) {
    auto vol_ptr = lookup_volume(uuid);
    if (!vol_ptr) { return std::make_error_condition(std::errc::invalid_argument); }

    // move volume back online;
    vol_state_change(vol_ptr, vol_state::ONLINE);
    return no_error;
}

std::error_condition HomeBlks::mark_vol_offline(const boost::uuids::uuid& uuid) {
    auto vol_ptr = lookup_volume(uuid);
    if (!vol_ptr) { return std::make_error_condition(std::errc::invalid_argument); }

    // mark volume offline and trigger FC
    vol_ptr->fault_containment();
    return no_error;
}

nlohmann::json HomeBlks::dump_disk_metablks(const std::string& client) {
    return MetaBlkMgrSI()->dump_disk_metablks(client);
}

bool HomeBlks::verify_metablk_store() { return MetaBlkMgrSI()->verify_metablk_store(); }

bool HomeBlks::is_safe_mode() { return HB_DYNAMIC_CONFIG(general_config->boot_safe_mode); }

void HomeBlks::list_snapshot(const VolumePtr&, std::vector< SnapshotPtr > snap_list) {}

void HomeBlks::read(const SnapshotPtr& snap, const snap_interface_req_ptr& req) {}

bool HomeBlks::is_unclean_shutdown() const {
    auto sb = (homeblks_sb*)m_homeblks_sb_buf->bytes;
    return m_unclean_shutdown;
}

void HomeBlks::reset_unclean_shutdown() { m_unclean_shutdown = false; }

// Note: Metrics scrapping can happen at any point after volume instance is created and registered with metrics
// farm;
void HomeBlksMetrics::on_gather() {
    auto hb = HomeBlks::instance();
    GAUGE_UPDATE(*this, boot_cnt, hb->get_boot_cnt());
    if (hb->is_unclean_shutdown()) {
        GAUGE_UPDATE(*this, unclean_shutdown, 2);
        hb->reset_unclean_shutdown();
    } else {
        GAUGE_UPDATE(*this, unclean_shutdown, 1);
    }
}

uint32_t HomeBlks::next_available_hdd_thread_idx() {
    static thread_local uint32_t current_index{0};
    uint32_t ret = current_index;
    current_index = (current_index + 1) % m_custom_hdd_threads.size();
    return ret;
}

bool HomeBlks::m_meta_blk_found = false;
