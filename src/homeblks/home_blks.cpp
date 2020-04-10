#include "home_blks.hpp"
#include "volume/volume.hpp"
#include <device/device.h>
#include <device/virtual_dev.hpp>
#include <cassert>
#include <device/blkbuffer.hpp>
#include <iostream>
#include <fstream>
#include <stdexcept>
#include <nlohmann/json.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <homelogstore/log_store.hpp>

SDS_OPTION_GROUP(home_blks,
                 (hb_stats_port, "", "hb_stats_port", "Stats port for HTTP service",
                  cxxopts::value< int32_t >()->default_value("5000"), "port"))

using namespace homestore;

#ifndef DEBUG
bool same_value_gen = false;
#endif

HomeBlksSafePtr HomeBlks::_instance = nullptr;
std::string HomeBlks::version = PACKAGE_VERSION;
thread_local std::vector< std::shared_ptr< Volume > > HomeBlks::s_io_completed_volumes = {};

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
        if (force_reinit) {
            _instance = HomeBlksSafePtr(new HomeBlks(cfg));
        } else {
            std::call_once(flag1, [&cfg]() {
#ifndef NDEBUG
                LOGINFO("HomeBlks DEBUG version: {}", HomeBlks::version);
#else
                LOGINFO("HomeBlks RELEASE version: {}", HomeBlks::version);
#endif
                _instance = HomeBlksSafePtr(new HomeBlks(cfg));
            });
        }
        return (VolInterface*)(_instance.get());
    } catch (const std::exception& e) {
        LOGERROR("{}", e.what());
        assert(0);
        return nullptr;
    }
}

vol_interface_req::vol_interface_req(void* wbuf, uint64_t lba, uint32_t nblks, bool is_sync) :
        write_buf(wbuf),
        request_id(counter_generator.next_request_id()),
        refcount(0),
        lba(lba),
        nblks(nblks),
        sync(is_sync) {}

vol_interface_req::~vol_interface_req() = default;

HomeBlks::HomeBlks(const init_params& cfg) : m_cfg(cfg), m_metrics("HomeBlks") {
    LOGINFO("Initializing HomeBlks with Config {}", m_cfg.to_string());
    HomeStore< BLKSTORE_BUFFER_TYPE >::init((const hs_input_params&)cfg);

    assert(VOL_SB_SIZE >= sizeof(vol_ondisk_sb));
    assert(VOL_SB_SIZE >= sizeof(homeblks_sb));

    m_out_params.max_io_size = VOL_MAX_IO_SIZE;
    m_homeblks_sb = sisl::make_aligned_unique< homeblks_sb >(HS_STATIC_CONFIG(disk_attr.align_size), HOMEBLKS_SB_SIZE);

    /* start thread */
    m_thread_id = std::thread(&HomeBlks::init_thread, this);
}

cap_attrs HomeBlks::get_vol_capacity(const VolumePtr& vol) {
    if (!vol) {
        assert(0);
        throw std::invalid_argument("null vol ptr");
    }
    cap_attrs cap;
    cap.used_data_size = vol->get_data_used_size();
    cap.used_index_size = vol->get_index_used_size();
    cap.used_total_size = cap.used_data_size + cap.used_index_size;
    cap.initial_total_size = vol->get_size();
    return cap;
}

vol_interface_req_ptr HomeBlks::create_vol_interface_req(void* buf, uint64_t lba, uint32_t nblks, bool is_sync) {
    return vol_interface_req_ptr(new vol_interface_req(buf, lba, nblks, is_sync));
}

std::error_condition HomeBlks::write(const VolumePtr& vol, const vol_interface_req_ptr& req) {
    assert(m_rdy);
    if (!vol) {
        assert(0);
        throw std::invalid_argument("null vol ptr");
    }
    if (!m_rdy || is_shutdown()) { return std::make_error_condition(std::errc::device_or_resource_busy); }
    req->vol_instance = vol;
    return (vol->write(req));
}

std::error_condition HomeBlks::read(const VolumePtr& vol, const vol_interface_req_ptr& req) {
    assert(m_rdy);
    if (!vol) {
        assert(0);
        throw std::invalid_argument("null vol ptr");
    }
    if (!m_rdy || is_shutdown()) { return std::make_error_condition(std::errc::device_or_resource_busy); }
    req->vol_instance = vol;
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
boost::uuids::uuid HomeBlks::get_uuid(VolumePtr vol) { return vol->get_uuid(); }
homeds::blob HomeBlks::at_offset(const blk_buf_t& buf, uint32_t offset) { return (buf->at_offset(offset)); }

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

    if (params.size >= available_size()) {
        LOGINFO("there is a possibility of running out of space as total size of the volumes"
                "created are more then maximum capacity");
    }
    try {
        decltype(m_volume_map)::iterator it;
        // Try to add an entry for this volume
        std::lock_guard< std::recursive_mutex > lg(m_vol_lock);
        bool happened{false};
        std::tie(it, happened) = m_volume_map.emplace(std::make_pair(params.uuid, nullptr));
        if (!happened) {
            if (m_volume_map.end() != it) { return it->second; }
            throw std::runtime_error("Unknown bug");
        }
        // Okay, this is a new volume so let's create it
        auto new_vol = Volume::make_volume(params);
        it->second = new_vol;
        set_available_size(available_size() < params.size ? 0 : available_size() - params.size);
        VOL_INFO_LOG(params.uuid, "Create volume with params: {}", params.to_string());

        auto system_cap = get_system_capacity();
        LOGINFO("System capacity after vol create: {}", system_cap.to_string());
        return it->second;
    } catch (const std::exception& e) { LOGERROR("{}", e.what()); }
    return nullptr;
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
        std::lock_guard< std::recursive_mutex > lg(m_vol_lock);
        auto it = m_volume_map.find(uuid);
        if (it == m_volume_map.end()) { return std::make_error_condition(std::errc::no_such_device_or_address); }
        auto cur_vol = it->second;
        auto sb = cur_vol->get_sb();
        /* Remove the block from the previous super block. We are going to delete the super block later when
         * ref count on volume drops to zero.
         */

        // updating the previous super block
        vol_mem_sb* prev_sb = nullptr;
        if (sb->ondisk_sb->prev_blkid.to_integer() != BlkId::invalid_internal_id()) {
            prev_sb = vol_sb_read(sb->ondisk_sb->prev_blkid);
            assert(prev_sb);
            // we do have a valid prev_sb, update it.
            auto it = m_volume_map.find(prev_sb->ondisk_sb->uuid);
            delete (prev_sb);
            assert(it != m_volume_map.end());

            auto vol = it->second;
            prev_sb = vol->get_sb();
            // need to update the in-memory copy of sb then persist this copy to disk;
            prev_sb->lock();
            prev_sb->ondisk_sb->next_blkid = sb->ondisk_sb->next_blkid;
            prev_sb->unlock();
            vol_sb_write(prev_sb);
            if (sb == m_last_vol_sb) { m_last_vol_sb = prev_sb; }
        } else {
            // no prev_sb, this is the first sb being removed.
            // we need to update m_homeblks_sb to sb->nextblkid;
            // if there is next sb, sb->next_blkid will be invalid interal blkid, which is good;
            m_homeblks_sb->vol_list_head.set(sb->ondisk_sb->next_blkid);
            if (sb == m_last_vol_sb) { m_last_vol_sb = nullptr; }
        }

        // updating the next super block
        vol_mem_sb* next_sb = nullptr;
        if (sb->ondisk_sb->next_blkid.to_integer() != BlkId::invalid_internal_id()) {
            next_sb = vol_sb_read(sb->ondisk_sb->next_blkid);
            assert(next_sb);
            auto it = m_volume_map.find(next_sb->ondisk_sb->uuid);
            delete (next_sb);
            assert(it != m_volume_map.end());
            auto vol = it->second;

            next_sb = vol->get_sb();
            // need to update the in-memory copy of sb then persist this copy to disk;
            next_sb->lock();
            next_sb->ondisk_sb->prev_blkid = sb->ondisk_sb->prev_blkid;
            next_sb->unlock();
            vol_sb_write(next_sb);
        }

        // persist m_homeblks_sb
        m_homeblks_sb->num_vols--;
        homeblks_sb_write();

        // Destroy the current volume and remove it from the map
        cur_vol->destroy();
        m_volume_map.erase(uuid);

        // volume destructor will be called since the user_count of share_ptr
        // will drop to zero while going out of this scope;
        std::error_condition no_err;
        VOL_INFO_LOG(uuid, " Deleting the volume name: {}", cur_vol->get_name());
        return no_err;
    } catch (std::exception& e) {
        LOGERROR("{}", e.what());
        auto error = std::make_error_condition(std::errc::io_error);
        return error;
    }
}

VolumePtr HomeBlks::lookup_volume(const boost::uuids::uuid& uuid) {
    std::lock_guard< std::recursive_mutex > lg(m_vol_lock);
    auto it = m_volume_map.find(uuid);
    if (m_volume_map.end() != it) { return it->second; }
    return nullptr;
}

SnapshotPtr HomeBlks::snap_volume(VolumePtr volptr) {
    if (!m_rdy || is_shutdown()) {
        LOGINFO("Snapshot: volume not online");
        return nullptr;
    }

    auto sp = volptr->make_snapshot();
    LOGINFO("Snapshot created volume {}, Snapshot {}", volptr->to_string(), sp->to_string());
    return sp;
}

HomeBlks* HomeBlks::instance() { return _instance.get(); }
HomeBlksSafePtr HomeBlks::safe_instance() { return _instance; }

void HomeBlks::vol_sb_init(vol_mem_sb* sb) {
    /* allocate block */
    assert(!HS_STATIC_CONFIG(input.is_read_only));
    BlkId bid = alloc_sb_blk(VOL_SB_SIZE);
    std::lock_guard< std::recursive_mutex > lg(m_vol_lock);
    // No need to hold vol's sb update lock here since it is being initiated and not added to m_volume_map yet;
    sb->ondisk_sb->gen_cnt = 0;
    sb->ondisk_sb->prev_blkid.set(m_last_vol_sb ? m_last_vol_sb->ondisk_sb->blkid.to_integer()
                                                : BlkId::invalid_internal_id());
    sb->ondisk_sb->next_blkid.set(BlkId::invalid_internal_id());
    sb->ondisk_sb->blkid.set(bid);
    sb->ondisk_sb->version = VOL_SB_VERSION;
    sb->ondisk_sb->magic = VOL_SB_MAGIC;

    /* write the sb */
    vol_sb_write(sb);

    /* update the previous pointers */
    if (m_last_vol_sb != nullptr) {
        m_last_vol_sb->lock();
        assert(m_homeblks_sb->vol_list_head.to_integer() != BlkId::invalid_internal_id());
        assert(m_last_vol_sb->ondisk_sb->next_blkid.to_integer() == BlkId::invalid_internal_id());
        m_last_vol_sb->ondisk_sb->next_blkid.set(bid);
        m_last_vol_sb->unlock();
        vol_sb_write(m_last_vol_sb);
    } else {
        assert(m_homeblks_sb->vol_list_head.to_integer() == BlkId::invalid_internal_id());
        m_homeblks_sb->vol_list_head.set(bid);
    }

    m_homeblks_sb->num_vols++;
    homeblks_sb_write();
    /* update the last volume super block. If exception happens in between it won't be updated */
    m_last_vol_sb = sb;
}

bool HomeBlks::vol_sb_sanity(vol_mem_sb* sb) {
    return ((sb->ondisk_sb->magic == VOL_SB_MAGIC) && (sb->ondisk_sb->version == VOL_SB_VERSION));
}

vol_mem_sb* HomeBlks::vol_sb_read(BlkId bid) {
    bool rewrite = false;
    if (bid.to_integer() == BlkId::invalid_internal_id()) return nullptr;
    std::vector< blk_buf_t > bbuf = m_sb_blk_store->read_nmirror(bid, m_cfg.devices.size() - 1);
    blk_buf_t valid_buf = get_valid_buf(bbuf, rewrite);

    vol_mem_sb* sb = new vol_mem_sb(HS_STATIC_CONFIG(disk_attr.align_size), VOL_SB_SIZE);
    memcpy(sb->ondisk_sb.get(), valid_buf->at_offset(0).bytes, sizeof(vol_ondisk_sb));

    // TODO: how do we recover this if it fails in release mode?
    assert(sb->ondisk_sb->blkid.to_integer() == bid.to_integer());

    if (!vol_sb_sanity(sb)) {
        VOL_ERROR_LOG(sb->ondisk_sb->vol_name, "Sanity check failure in volume superblock");
        return nullptr;
    }

    if (rewrite) {
        /* update the super block */
        vol_sb_write(sb);
    }

    return sb;
}

//
// Steps:
// 1. Read the super block based on BlkId.
// 2. Get prev_blkid/next_blkid.
// 3. Read previous super block into memory and point its next_blkid to next_blkid;
// 4. Read next super block into memory and point its prev_blkid to prev_blkid;
// 5. Persiste the previous/nxt super block.
// 6. Free the vol_sb's blk_id
//
void HomeBlks::vol_sb_remove(vol_mem_sb* sb) {
    VOL_INFO_LOG(sb->ondisk_sb->uuid, " Removing superblock of the volume");
    std::lock_guard< std::recursive_mutex > lg(m_vol_lock);
    m_sb_blk_store->free_blk(sb->ondisk_sb->blkid, boost::none, boost::none);
}

void HomeBlks::superblock_init(BlkId bid) {
    /* build the homeblks super block */
    m_homeblks_sb->blkid.set(bid);
    m_homeblks_sb->vol_list_head.set(BlkId::invalid_internal_id());
    m_homeblks_sb->num_vols = 0;
    m_homeblks_sb->gen_cnt = 0;
    m_homeblks_sb->version = HOMEBLKS_SB_VERSION;
    m_homeblks_sb->magic = HOMEBLKS_SB_MAGIC;
    m_homeblks_sb->boot_cnt = 0;
    m_homeblks_sb->init_flag(0);
    m_homeblks_sb->uuid = HS_STATIC_CONFIG(input.system_uuid);
    homeblks_sb_write();
}

void HomeBlks::superblock_load(const std::vector< blk_buf_t >& bbuf, BlkId sb_blk_id) {
    bool rewrite = false;
    blk_buf_t valid_buf = get_valid_buf(bbuf, rewrite);
    memcpy(m_homeblks_sb.get(), valid_buf->at_offset(0).bytes, sizeof(*m_homeblks_sb));
    assert(m_homeblks_sb->gen_cnt > 0);
    assert(m_homeblks_sb->blkid.to_integer() == sb_blk_id.to_integer());
    m_homeblks_sb->boot_cnt++;

    /* update the homeblks super block */
    if (!m_cfg.is_read_only) { homeblks_sb_write(); }
}

void HomeBlks::homeblks_sb_write() {
    homeds::MemVector mvec;
    std::lock_guard< std::recursive_mutex > lg(m_vol_lock);

    m_homeblks_sb->gen_cnt++;
    try {
        mvec.set((uint8_t*)m_homeblks_sb.get(), VOL_SB_SIZE, 0);
        m_sb_blk_store->write(m_homeblks_sb->blkid, mvec);
    } catch (std::exception& e) { throw e; }
}

void HomeBlks::vol_sb_write(vol_mem_sb* sb) {
    homeds::MemVector mvec;
    std::lock_guard< std::recursive_mutex > lg(m_vol_lock);

    /* take a sb lock so that nobody update the in memory copy while
     * we are persisting it to disk.
     */
    sb->lock();
    try {
        sb->ondisk_sb->gen_cnt++;
        mvec.set((uint8_t*)sb->ondisk_sb.get(), VOL_SB_SIZE, 0);
        m_sb_blk_store->write(sb->ondisk_sb->blkid, mvec);
    } catch (std::exception& e) {
        sb->unlock();
        throw e;
    }

    sb->unlock();
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
void HomeBlks::attach_batch_sentinel_cb(const batch_sentinel_callback& cb) { m_cfg.batch_sentinel_cb = cb; }

void HomeBlks::vol_mounted(const VolumePtr& vol, vol_state state) {
    m_cfg.vol_mounted_cb(vol, state);
    VOL_INFO_LOG(vol->get_sb()->ondisk_sb->uuid, " Mounted the volume in state {}", state);
}

bool HomeBlks::vol_state_change(const VolumePtr& vol, vol_state new_state) {
    assert(new_state == vol_state::OFFLINE || new_state == vol_state::ONLINE);
    std::lock_guard< std::recursive_mutex > lg(m_vol_lock);
    try {
        vol->set_state(new_state);
    } catch (std::exception& e) {
        LOGERROR("{}", e.what());
        return false;
    }
    return true;
}

blk_buf_t HomeBlks::get_valid_buf(const std::vector< blk_buf_t >& bbuf, bool& rewrite) {
    blk_buf_t valid_buf = nullptr;
    uint32_t gen_cnt = 0;
    boost::uuids::uuid uuid;
    for (uint32_t i = 0; i < bbuf.size(); i++) {
        vol_ondisk_sb* hdr = (vol_ondisk_sb*)(bbuf[i]->at_offset(0).bytes);

        if (hdr->magic != VOL_SB_MAGIC || hdr->version != VOL_SB_VERSION) {
            LOGINFO("found superblock with invalid magic and version");
            continue;
        }

        if (gen_cnt == 0) {
            /* update only for first valid sb */
            uuid = hdr->uuid;
        }

        /* It is not possible to get two valid super blocks with different uuid. */
        HS_ASSERT_CMP(RELEASE, uuid, ==, hdr->uuid)

        if (hdr->gen_cnt > gen_cnt) {
            if (valid_buf != nullptr) {
                /* superblock is not consistent across the disks */
                rewrite = true;
                LOGINFO("gen_cnt is mismatched of vol superblock");
            }
            gen_cnt = hdr->gen_cnt;
            valid_buf = bbuf[i];
        }
    }
    assert(gen_cnt > 0);
    return valid_buf;
}

//
// TODO: Do we need to handle shutdown request during scan_volumes since it may take a long to
// time to finish scan all the volumes?
//
// Does it make sense to let consumer wait until a shutdown request can be served by HomeStore after scan_volumes?
//
void HomeBlks::scan_volumes() {
    auto blkid = m_homeblks_sb->vol_list_head;
    bool rewrite = false;
    m_scan_cnt++;
    int num_vol = 0;
#ifdef _PRERELEASE
    if (homestore_flip->test_flip("reboot_abort")) { abort(); }
#endif
    try {
        while (blkid.to_integer() != BlkId::invalid_internal_id()) {
            vol_mem_sb* sb = vol_sb_read(blkid);
            if (sb == nullptr) {
                // TODO: Error handling here...
            }

            auto vol_uuid = sb->ondisk_sb->uuid;

            if (!m_cfg.vol_found_cb(vol_uuid)) {
                VOL_INFO_LOG(vol_uuid, "Deleting the volume after recovery: Vol name {}", sb->ondisk_sb->vol_name);
                //                             boost::uuids::to_string(vol_uuid));

                /* don't need to mount this volume. Delete this volume. Its block will be recaimed automatically */
                if (m_last_vol_sb) {
                    m_last_vol_sb->ondisk_sb->next_blkid = sb->ondisk_sb->next_blkid;
                    /* write vdev superblocks */
                    vol_sb_write(m_last_vol_sb);
                } else {
                    m_homeblks_sb->vol_list_head = sb->ondisk_sb->next_blkid;
                }
                m_homeblks_sb->num_vols--;
            } else {
                /* create the volume */
                assert(sb->ondisk_sb->state != vol_state::DESTROYING);
                if (m_last_vol_sb && BlkId::compare(sb->ondisk_sb->prev_blkid, m_last_vol_sb->ondisk_sb->blkid)) {
                    /* prev volume is deleted. update the prev blkid */
                    LOGINFO("updating the previous volume blkid");
                    sb->ondisk_sb->prev_blkid.set(m_last_vol_sb->ondisk_sb->blkid);
                    vol_sb_write(sb);
                }

                if (sb->ondisk_sb->state == vol_state::ONLINE && m_vdev_failed) {
                    /* Move all the volumes to failed state */
                    sb->ondisk_sb->state = vol_state::FAILED;
                    vol_sb_write(sb);
                }
                num_vol++;
                decltype(m_volume_map)::iterator it;

                bool happened{false};
                std::tie(it, happened) = m_volume_map.emplace(std::make_pair(vol_uuid, nullptr));
                assert(happened);

                m_scan_cnt++;
                VolumePtr new_vol;
                try {
                    new_vol = Volume::make_volume(sb);
                    new_vol->recovery_start();
                } catch (const std::exception& e) {
                    m_scan_cnt--;
                    throw e;
                }
                it->second = new_vol;

                /* allocate this blkid in the sb blkstore */
                m_sb_blk_store->alloc_blk(blkid);
                m_last_vol_sb = sb;
            }
            blkid = sb->ondisk_sb->next_blkid;

            VOL_INFO_LOG(sb->ondisk_sb->uuid, "Found the volume name: {}", sb->ondisk_sb->vol_name);
        }
        assert(num_vol <= m_homeblks_sb->num_vols);
        m_homeblks_sb->num_vols = num_vol;
        if (!m_cfg.is_read_only) { homeblks_sb_write(); }
        /* clear the state in virtual devices as appropiate state is set in volume superblocks */
        if (m_vdev_failed) {
            m_data_blk_store->reset_vdev_failed_state();
            m_index_blk_store->reset_vdev_failed_state();
            m_sb_blk_store->reset_vdev_failed_state();
            m_logdev_blk_store->reset_vdev_failed_state();
            m_vdev_failed = false;
        }
    } catch (const std::exception& e) {
        m_init_failed = true;
        int cnt = m_scan_cnt.fetch_sub(1, std::memory_order_relaxed);
        if (cnt == 1) {
            LOGERROR("{}", e.what());
            auto error = std::make_error_condition(std::errc::io_error);
            init_done(error, m_out_params);
        }
        return;
    }

    int cnt = m_scan_cnt.fetch_sub(1, std::memory_order_relaxed);
    if (cnt == 1) {
        m_rdy = true;
        m_dev_mgr->inited();
        init_done(no_error, m_out_params);
    }
}

void HomeBlks::init_done(std::error_condition err, const out_params& params) {
    LOGINFO("init done status {}", err.message());
    if (!err) {
        auto system_cap = get_system_capacity();
        LOGINFO("{}", system_cap.to_string());
#ifndef NDEBUG
        /* It will trigger race conditions without generating any IO error */
        set_io_flip();
#endif
    }
    m_cfg.init_done_cb(err, m_out_params);
}

//
// Handle the race between shutdown therad and init thread;
// 1. HomeStore starts init
// 2. AM send shutdown request immediately
// 3. Init switched out after is_shutdown() return false;
// 4. Shutdown thread set m_shutdown to true;
//    and found nothing needs to be freed since init thread hasn't finished yet so shutdown thread completes;
// 5. Init thread comes back and init things out with all the memory leaked since shutdown thread has already
// finished;
//
void HomeBlks::init_thread() {
    std::error_condition error = no_error;
    try {
        init_devices();

        //
        // Will not resume shutdown if we reboot from an un-finished shutdown procedure.
        //
        {
            std::lock_guard< std::recursive_mutex > lg(m_vol_lock);
            if (m_homeblks_sb->test_flag(HOMEBLKS_SB_FLAGS_CLEAN_SHUTDOWN)) {
                LOGDEBUG("System was shutdown cleanly.");
                // clear the flag and persist to disk, if we received a new shutdown and completed successfully,
                // the flag should be set again;
                m_homeblks_sb->clear_flag(HOMEBLKS_SB_FLAGS_CLEAN_SHUTDOWN);
                if (!m_cfg.is_read_only) { homeblks_sb_write(); }
            } else if (!HS_STATIC_CONFIG(input.disk_init)) {
                LOGCRITICAL("System experienced sudden panic since last boot!");
            } else {
                LOGINFO("Initializing the system");
            }
        }

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
        iomanager.default_drive_interface()->attach_batch_sentinel_cb([this](int nevents) {
            auto v_comp_events = 0;
            for (auto& v : s_io_completed_volumes) {
                v_comp_events += v->call_batch_completion_cbs();
            }
            s_io_completed_volumes.clear();
            if (m_cfg.batch_sentinel_cb && v_comp_events) m_cfg.batch_sentinel_cb(v_comp_events);
        });

        /* scan volumes */
        auto vol_scan_start_time = Clock::now();
        scan_volumes();
        HISTOGRAM_OBSERVE(m_metrics, scan_volumes_latency, get_elapsed_time_ms(vol_scan_start_time));

        m_init_finished = true;
        m_cv.notify_all();
        return;
    } catch (const std::exception& e) {
        m_init_failed = true;
        LOGERROR("{}", e.what());
        error = std::make_error_condition(std::errc::io_error);
    }
    init_done(error, m_out_params);
}

void HomeBlks::vol_scan_cmpltd(const VolumePtr& vol, vol_state state, bool success) {
    if (success) {
        vol_mounted(vol, state);
    } else {
        m_init_failed = true;
    }

    int cnt = m_scan_cnt.fetch_sub(1, std::memory_order_relaxed);
    if (cnt == 1) {
        if (m_init_failed) {
            LOGCRITICAL("init failed");
            auto error = std::make_error_condition(std::errc::io_error);
            init_done(error, m_out_params);
        } else {
            LOGINFO("init completed");
            m_rdy = true;
            m_dev_mgr->inited();
            init_done(no_error, m_out_params);
        }
    }
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

    if (logmodule == nullptr) {
        sds_logging::SetAllModuleLogLevel(spdlog::level::from_str(new_log_level));
    } else {
        sds_logging::SetModuleLogLevel(logmodule, spdlog::level::from_str(new_log_level));
    }

    hb->m_http_server->respond_OK(cd, EVHTP_RES_OK, sds_logging::GetAllModuleLogLevel().dump());
}

void HomeBlks::get_log_level(sisl::HttpCallData cd) {
    HomeBlks* hb = (HomeBlks*)(cd->cookie());
    hb->m_http_server->respond_OK(cd, EVHTP_RES_OK, sds_logging::GetAllModuleLogLevel().dump());
}

void HomeBlks::dump_stack_trace(sisl::HttpCallData cd) {
    HomeBlks* hb = (HomeBlks*)(cd->cookie());
    sds_logging::log_stack_trace(true);
    hb->m_http_server->respond_OK(cd, EVHTP_RES_OK, "Look for stack trace in the log file");
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
    auto sthread = std::thread([this, shutdown_done_cb, force]() {
        iomanager.run_io_loop(false, nullptr, [&](const iomgr_msg& msg) {
            if (msg.m_type == iomgr::iomgr_msg_type::WAKEUP) { schedule_shutdown(shutdown_done_cb, force); }
        });
    });
    sthread.detach();
    return true;
}

void HomeBlks::schedule_shutdown(const shutdown_comp_callback& shutdown_done_cb, bool force) {
    if (do_shutdown(shutdown_done_cb, force)) { iomanager.stop_io_loop(); }
}

bool HomeBlks::do_shutdown(const shutdown_comp_callback& shutdown_done_cb, bool force) {
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

    try {
        if (!do_volume_shutdown(force)) {
            LOGINFO("Not all volumes are completely shutdown yet, will check again in {} milliseconds",
                    HB_SETTINGS_VALUE(general_config->shutdown_status_check_freq_ms));
            m_shutdown_timer_hdl = iomanager.schedule_thread_timer(
                HB_SETTINGS_VALUE(general_config->shutdown_status_check_freq_ms) * 1000 * 1000, false /* recurring */,
                nullptr, [this, shutdown_done_cb, force](void* cookie) { schedule_shutdown(shutdown_done_cb, force); });
            return false;
        }
        iomanager.cancel_thread_timer(m_shutdown_timer_hdl);
        LOGINFO("All volumes are shutdown successfully, proceed to bring down other subsystems");

        // m_homeblks_sb needs to to be freed in the last, because we need to set the clean shutdown flag
        // after shutdown is succesfully completed;
        // clear the shutdown bit on disk;
        {
            std::lock_guard< std::recursive_mutex > lg(m_vol_lock);
            m_homeblks_sb->set_flag(HOMEBLKS_SB_FLAGS_CLEAN_SHUTDOWN);
            if (!m_cfg.is_read_only) { homeblks_sb_write(); }
        }

        // Waiting for http server thread to join
        m_http_server->stop();
        m_http_server.reset();

        home_log_store_mgr.stop();
        if (shutdown_done_cb) shutdown_done_cb(true);

        /*
         * Decrement a counter which is incremented for indicating that homeblks is up and running. Once homeblks
         * usage count is 1, which means only remaining instance is the global _instance variable, we can do the
         * _instance cleanup
         */
        intrusive_ptr_release(this);
    } catch (const std::exception& e) {
        LOGERROR("{}", e.what());
        if (shutdown_done_cb) shutdown_done_cb(false);
    }
    return true;
}

bool HomeBlks::do_volume_shutdown(bool force) {
    std::unique_lock< std::recursive_mutex > lg(m_vol_lock);
    for (auto it = m_volume_map.cbegin(); it != m_volume_map.cend();) {
        auto pending_ref = it->second.use_count();
        if ((pending_ref != 1) && !force) {
            LOGDEBUG("vol: {} still has ref_count {}. Waiting to be unrefed. ", it->second->get_name(), pending_ref);
            ++it;
            continue;
        }

        if (pending_ref == 1) {
            LOGINFO("vol: {} ref_count successfully drops to 1. Normal volume shutdown. ", it->second->get_name());
        } else if (force) {
            LOGINFO("vol: {} still has ref_count {}, but we are forced to shutdown ", it->second->get_name(),
                    pending_ref);
        }
        it->second->shutdown();
        it = m_volume_map.erase(it);
    }

    return (m_volume_map.size() == 0);
}

vol_state HomeBlks::get_state(VolumePtr vol) { return vol->get_state(); }

bool HomeBlks::fix_tree(VolumePtr vol, bool verify) {
    std::unique_lock< std::recursive_mutex > lg(m_vol_lock);
    return vol->fix_mapping_btree(verify);
}
