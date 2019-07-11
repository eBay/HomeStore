#include "home_blks.hpp"
#include "volume.hpp"
#include <device/device.h>
#include <device/virtual_dev.hpp>
#include <cassert>
#include <device/blkbuffer.hpp>
#include <iostream>
#include <stdexcept>

SDS_OPTION_GROUP(home_blks, (hb_stats_port, "", "hb_stats_port", "Stats port for HTTP service", cxxopts::value<int32_t>()->default_value("5000"), "port"))

using namespace homestore;

HomeBlks* HomeBlks::_instance = nullptr;
std::string HomeBlks::version = PACKAGE_VERSION;

VolInterface* homestore::vol_homestore_init(const init_params& cfg) { return (HomeBlks::init(cfg)); }

VolInterface* HomeBlks::init(const init_params& cfg) {
    fLI::FLAGS_minloglevel = 3;

    LOGINFO("HomeBlks version: {}", HomeBlks::version);
    _instance = new HomeBlks(cfg);
    return ((VolInterface*)(_instance));
}

HomeBlks::HomeBlks(const init_params& cfg) :
        m_cfg(cfg),
        m_cache(nullptr),
        m_rdy(false),
        m_last_vol_sb(nullptr),
        m_vdev_failed(false),
        m_size_avail(0),
        m_scan_cnt(0),
        m_init_failed(false),
        m_shutdown(false),
        m_init_finished(false) {

    _instance = this;
    LOGINFO("homeblks initing {}", m_cfg.to_string());
    /* set the homestore config parameters */
    populate_disk_attrs();
    /* If these parameters changes then we need to take care of upgrade/revert in device manager */
    HomeStoreConfig::max_chunks = MAX_CHUNKS;
    HomeStoreConfig::max_vdevs = MAX_VDEVS;
    HomeStoreConfig::max_pdevs = MAX_PDEVS;
    HomeStoreConfig::min_page_size = m_cfg.min_virtual_page_size;
    HomeStoreConfig::open_flag = m_cfg.flag;
    m_data_pagesz = m_cfg.min_virtual_page_size;

    assert(VOL_SB_SIZE >= sizeof(vol_ondisk_sb));
    assert(VOL_SB_SIZE >= sizeof(vol_config_sb));

    assert(HomeStoreConfig::atomic_phys_page_size >= HomeStoreConfig::min_page_size);

    m_out_params.max_io_size = VOL_MAX_IO_SIZE;
    int ret = posix_memalign((void**)&m_cfg_sb, HomeStoreConfig::align_size, VOL_SB_SIZE);
    assert(!ret);

    /* create cache */
    m_cache = new Cache< BlkId >(m_cfg.cache_size, HomeStoreConfig::atomic_phys_page_size);

    /* create device manager */
    m_dev_mgr = new homestore::DeviceManager(new_vdev_found, sizeof(sb_blkstore_blob), m_cfg.iomgr,
                                             virtual_dev_process_completions, m_cfg.is_file, m_cfg.system_uuid, 
                                             std::bind(&HomeBlks::process_vdev_error, this, std::placeholders::_1));

    /* start thread */
    m_thread_id = std::thread(&HomeBlks::init_thread, this);
}

void HomeBlks::populate_disk_attrs() {
    if (m_cfg.disk_attr) {
        HomeStoreConfig::phys_page_size = m_cfg.disk_attr->physical_page_size;
        HomeStoreConfig::align_size = m_cfg.disk_attr->disk_align_size;
        HomeStoreConfig::atomic_phys_page_size = m_cfg.disk_attr->atomic_page_size;
    } else {
        /* We should take these params from the config file or from the disks direectly */
        HomeStoreConfig::phys_page_size = 4096;
        HomeStoreConfig::align_size = 4096;
        HomeStoreConfig::atomic_phys_page_size = 4096;
    }
    LOGINFO("atomic_phys_page size is set to {}", HomeStoreConfig::atomic_phys_page_size);
    LOGINFO("align size is set to {}", HomeStoreConfig::align_size);
    LOGINFO("phys_page size is set to {}", HomeStoreConfig::phys_page_size);
}

cap_attrs HomeBlks::get_system_capacity() {
    cap_attrs cap;
    cap.used_data_size = get_data_blkstore()->get_used_size();
    cap.used_metadata_size = get_metadata_blkstore()->get_used_size();
    cap.used_total_size = cap.used_data_size + cap.used_metadata_size;
    cap.initial_total_size = get_data_blkstore()->get_size() + get_metadata_blkstore()->get_size();
    return cap;
}

cap_attrs HomeBlks::get_vol_capacity(const VolumePtr& vol) {
    if (!vol) {
        assert(0);
        throw std::invalid_argument("null vol ptr");
    }
    cap_attrs cap;
    cap.used_data_size = vol->get_data_used_size();
    cap.used_metadata_size = vol->get_metadata_used_size();
    cap.used_total_size = cap.used_data_size + cap.used_metadata_size;
    cap.initial_total_size = vol->get_size();
    return cap;
}
    
std::error_condition HomeBlks::write(const VolumePtr& vol, uint64_t lba, uint8_t* buf, uint32_t nblks,
                                     const vol_interface_req_ptr& req) {
    assert(m_rdy);
    if (!vol) {
        assert(0);
        throw std::invalid_argument("null vol ptr");
    }
    if (!m_rdy || is_shutdown()) {
        return std::make_error_condition(std::errc::device_or_resource_busy);
    }
    return (vol->write(lba, buf, nblks, req));
}

std::error_condition HomeBlks::read(const VolumePtr& vol, uint64_t lba, int nblks, const vol_interface_req_ptr& req) {
    assert(m_rdy);
    if (!vol) {
        assert(0);
        throw std::invalid_argument("null vol ptr");
    }
    if (!m_rdy || is_shutdown()) {
        return std::make_error_condition(std::errc::device_or_resource_busy);
    }
    return (vol->read(lba, nblks, req, false));
}

std::error_condition HomeBlks::sync_read(const VolumePtr& vol, uint64_t lba, int nblks,
                                         const vol_interface_req_ptr& req) {
    assert(m_rdy);
    if (!vol) {
        assert(0);
        throw std::invalid_argument("null vol ptr");
    }
    if (!m_rdy || is_shutdown()) {
        return std::make_error_condition(std::errc::device_or_resource_busy);
    }
    return (vol->read(lba, nblks, req, true));
}

VolumePtr HomeBlks::create_volume(const vol_params& params) {
    
    if (!m_rdy || is_shutdown()) {
        return nullptr;
    }
    if (params.size >= m_size_avail) {
        LOGINFO("there is a possibility of running out of space as total size of the volumes"
                "created are more then maximum capacity");
    }
    try {
        decltype(m_volume_map)::iterator it;
        // Try to add an entry for this volume
        std::lock_guard< std::recursive_mutex > lg(m_vol_lock);
        bool                          happened{false};
        std::tie(it, happened) = m_volume_map.emplace(std::make_pair(params.uuid, nullptr));
        if (!happened) {
            if (m_volume_map.end() != it) {
                return it->second;
            }
            throw std::runtime_error("Unknown bug");
        }
        // Okay, this is a new volume so let's create it
        auto new_vol = Volume::make_volume(params);
        it->second = new_vol;
        if (m_size_avail < params.size) {
            m_size_avail = 0;
        } else {
            m_size_avail -= params.size;
        }
        LOGINFO("vol created {}", params.to_string());
        auto system_cap = get_system_capacity();
        LOGINFO("{}", system_cap.to_string());
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
    if (!m_rdy || is_shutdown()) {
        return std::make_error_condition(std::errc::device_or_resource_busy);
    }
    try {
        {
            std::lock_guard<std::recursive_mutex> lg(m_vol_lock);
            auto it = m_volume_map.find(uuid);
            if (it == m_volume_map.end()) {
                return std::make_error_condition(std::errc::no_such_device_or_address);
            }

            it->second->set_state(DESTROYING);

            // remove it from the map;
            m_volume_map.erase(it);
        }
       
        // vol sb should be removed after all blks(data blk and btree blk) have been freed.

        // volume destructor will be called since the user_count of share_ptr 
        // will drop to zero while going out of this scope;
        std::error_condition no_err;
        return no_err;
    } catch (std::exception& e) {
        LOGERROR("{}", e.what());
        auto error = std::make_error_condition(std::errc::io_error);
        return error;
    }
}

VolumePtr HomeBlks::lookup_volume(const boost::uuids::uuid& uuid) {

    std::lock_guard< std::recursive_mutex > lg(m_vol_lock);
    auto                          it = m_volume_map.find(uuid);
    if (m_volume_map.end() != it) {
        return it->second;
    }
    return nullptr;
}

HomeBlks* HomeBlks::instance() { return _instance; }

BlkId HomeBlks::alloc_blk() {
    BlkId           bid;
    blk_alloc_hints hints;
    hints.desired_temp = 0;
    hints.dev_id_hint = -1;
    hints.is_contiguous = true;
    auto ret = m_sb_blk_store->alloc_blk(VOL_SB_SIZE, hints, &bid);
    if (ret != BLK_ALLOC_SUCCESS) {
        throw homestore::homestore_exception("space not available", homestore_error::space_not_avail);
    }
    assert(ret == BLK_ALLOC_SUCCESS);
    return bid;
}

void HomeBlks::vol_sb_init(vol_mem_sb* sb) {
    /* allocate block */

    BlkId                         bid = alloc_blk();
    std::lock_guard< std::recursive_mutex > lg(m_vol_lock);
    // No need to hold vol's sb update lock here since it is being initiated and not added to m_volume_map yet;
    sb->ondisk_sb->gen_cnt = 0;
    sb->ondisk_sb->prev_blkid.set(m_last_vol_sb ? m_last_vol_sb->ondisk_sb->blkid.to_integer() : 
                                                  BlkId::invalid_internal_id());
    sb->ondisk_sb->next_blkid.set(BlkId::invalid_internal_id());
    sb->ondisk_sb->blkid.set(bid);
    sb->ondisk_sb->version = VOL_SB_VERSION;
    sb->ondisk_sb->magic = VOL_SB_MAGIC;

    /* write the sb */
    vol_sb_write(sb);

    /* update the previous pointers */
    if (m_last_vol_sb != nullptr) {
        m_last_vol_sb->lock();
        assert(m_cfg_sb->vol_list_head.to_integer() != BlkId::invalid_internal_id());
        assert(m_last_vol_sb->ondisk_sb->next_blkid.to_integer() == BlkId::invalid_internal_id());
        m_last_vol_sb->ondisk_sb->next_blkid.set(bid);
        m_last_vol_sb->unlock();
        vol_sb_write(m_last_vol_sb);
    } else {
        assert(m_cfg_sb->vol_list_head.to_integer() == BlkId::invalid_internal_id());
        m_cfg_sb->vol_list_head.set(bid);
    }

    m_cfg_sb->num_vols++;
    config_super_block_write();
    /* update the last volume super block. If exception happens in between it won't be updated */
    m_last_vol_sb = sb;
}

bool 
HomeBlks::vol_sb_sanity(vol_mem_sb* sb) {
    return ((sb->ondisk_sb->magic == VOL_SB_MAGIC) && 
            (sb->ondisk_sb->version == VOL_SB_VERSION));
}

vol_mem_sb* 
HomeBlks::vol_sb_read(BlkId bid) {
    bool rewrite = false;
    if (bid.to_integer() == BlkId::invalid_internal_id()) return nullptr;
    std::vector<boost::intrusive_ptr<BlkBuffer>> bbuf = m_sb_blk_store->read_nmirror(bid, m_cfg.devices.size() - 1);
    boost::intrusive_ptr<BlkBuffer> valid_buf = get_valid_buf(bbuf, rewrite);

    vol_mem_sb *sb = new vol_mem_sb;
    int ret = posix_memalign((void **) &(sb->ondisk_sb), HomeStoreConfig::align_size, VOL_SB_SIZE); 
    assert(!ret);
    memcpy(sb->ondisk_sb, valid_buf->at_offset(0).bytes, sizeof(vol_ondisk_sb));
    
    // TODO: how do we recover this if it fails in release mode?
    assert(sb->ondisk_sb->blkid.to_integer() == bid.to_integer());

    if (!vol_sb_sanity(sb)) {
        LOGERROR("Sanity check failure for vol sb: name: {}", sb->ondisk_sb->vol_name);
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
void 
HomeBlks::vol_sb_remove(vol_mem_sb *sb) {
    LOGINFO("Removing sb of vol: {}", sb->ondisk_sb->vol_name);
    std::lock_guard< std::recursive_mutex > lg(m_vol_lock);

    vol_mem_sb* prev_sb = nullptr;
    if (sb->ondisk_sb->prev_blkid.to_integer() != BlkId::invalid_internal_id()) {
        prev_sb = vol_sb_read(sb->ondisk_sb->prev_blkid);
        assert (prev_sb);
        // we do have a valid prev_sb, update it. 
        auto it = m_volume_map.find(prev_sb->ondisk_sb->uuid);
        delete(prev_sb);
        assert(it != m_volume_map.end());
        
        auto vol = it->second;
        prev_sb = vol->get_sb();
        // need to update the in-memory copy of sb then persist this copy to disk;
        prev_sb->lock();
        prev_sb->ondisk_sb->next_blkid = sb->ondisk_sb->next_blkid;
        prev_sb->unlock();
        vol_sb_write(prev_sb);
        if (sb == m_last_vol_sb) {
            m_last_vol_sb = prev_sb;
        }
    } else {
        // no prev_sb, this is the first sb being removed. 
        // we need to update m_cfg_sb to sb->nextblkid;
        assert(m_cfg_sb);
        // if there is next sb, sb->next_blkid will be invalid interal blkid, which is good;
        m_cfg_sb->vol_list_head.set(sb->ondisk_sb->next_blkid);
        if (sb == m_last_vol_sb) {
            m_last_vol_sb = nullptr;
        }
        // persist m_cfg_sb 
        config_super_block_write();
    }

    vol_mem_sb* next_sb = nullptr;
    if (sb->ondisk_sb->next_blkid.to_integer() != BlkId::invalid_internal_id()) {
        next_sb = vol_sb_read(sb->ondisk_sb->next_blkid);
        assert(next_sb);
        auto it = m_volume_map.find(next_sb->ondisk_sb->uuid);
        delete(next_sb);
        assert(it != m_volume_map.end());
        auto vol = it->second;
        
        next_sb = vol->get_sb();
        // need to update the in-memory copy of sb then persist this copy to disk;
        next_sb->lock();
        next_sb->ondisk_sb->prev_blkid = sb->ondisk_sb->prev_blkid;
        next_sb->unlock();
        vol_sb_write(next_sb);
    } 
    
    m_sb_blk_store->free_blk(sb->ondisk_sb->blkid, boost::none, boost::none);
}

void HomeBlks::config_super_block_init(BlkId& bid) {
    /* build the config super block */
    m_cfg_sb->blkid.set(bid);
    m_cfg_sb->vol_list_head.set(BlkId::invalid_internal_id());
    m_cfg_sb->num_vols = 0;
    m_cfg_sb->gen_cnt = 0;
    m_cfg_sb->version = VOL_SB_VERSION;
    m_cfg_sb->magic = VOL_SB_MAGIC;
    m_cfg_sb->boot_cnt = 0;
    m_cfg_sb->init_flag(0);
    config_super_block_write();
}

boost::uuids::uuid 
HomeBlks::get_uuid(VolumePtr vol) {
    return vol->get_uuid();
}

void HomeBlks::config_super_block_write() {
    homeds::MemVector mvec;
    std::lock_guard< std::recursive_mutex > lg(m_vol_lock);

    m_cfg_sb->gen_cnt++;
    try {
        mvec.set((uint8_t*)m_cfg_sb, VOL_SB_SIZE, 0);
        m_sb_blk_store->write(m_cfg_sb->blkid, mvec);
    } catch (std::exception& e) {
        throw e;
    }
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
        mvec.set((uint8_t*)sb->ondisk_sb, VOL_SB_SIZE, 0);
        m_sb_blk_store->write(sb->ondisk_sb->blkid, mvec);
    } catch (std::exception& e) {
        sb->unlock();
        throw e;
    }

    sb->unlock();
}

void HomeBlks::process_vdev_error(vdev_info_block* vb) {
    /* For now we need to move all volumes in a failed state. Later on when we move to multiple virtual devices for
     * data blkstoree we need to move only those volumes to failed state which  belong to this virtual device.
     */
    std::lock_guard< std::recursive_mutex > lg(m_vol_lock);
    auto it = m_volume_map.begin();
    while (it != m_volume_map.end()) {
        auto old_state = it->second->get_state();
        if (old_state == ONLINE) {
            /* We don't persist this state. Reason that we come over here is that
             * disks are not working. It doesn't make sense to write to faulty
             * disks.
             */
            it->second->set_state(OFFLINE, false);
            m_cfg.vol_state_change_cb(it->second, old_state, OFFLINE);
        }
        ++it;
    }
}

void HomeBlks::new_vdev_found(DeviceManager* dev_mgr, vdev_info_block* vb) {
    /* create blkstore */
    blkstore_blob* blob = (blkstore_blob*)vb->context_data;
    switch (blob->type) {
    case DATA_STORE: HomeBlks::instance()->create_data_blkstore(vb); break;
    case METADATA_STORE: HomeBlks::instance()->create_metadata_blkstore(vb); break;
    case SB_STORE: HomeBlks::instance()->create_sb_blkstore(vb); break;
    default: assert(0);
    }
}

void HomeBlks::create_blkstores() {
    create_data_blkstore(nullptr);
    create_metadata_blkstore(nullptr);
    create_sb_blkstore(nullptr);
}

void HomeBlks::attach_vol_completion_cb(const VolumePtr& vol, io_comp_callback cb) { vol->attach_completion_cb(cb); }

void HomeBlks::add_devices() { 
    m_dev_mgr->add_devices(m_cfg.devices, m_cfg.disk_init); 
    assert(m_dev_mgr->get_total_cap() / m_cfg.devices.size() > MIN_DISK_CAP_SUPPORTED);
    assert(m_dev_mgr->get_total_cap() < MAX_SUPPORTED_CAP);
}

void HomeBlks::vol_mounted(const VolumePtr& vol, vol_state state) {
    m_cfg.vol_mounted_cb(vol, state);
    LOGINFO("vol mounted name {} state {}", vol->get_sb()->ondisk_sb->vol_name, state);
}

bool HomeBlks::vol_state_change(const VolumePtr& vol, vol_state new_state) {
    assert(new_state == OFFLINE || new_state == ONLINE);
    std::lock_guard< std::recursive_mutex > lg(m_vol_lock);
    try {
        vol->set_state(new_state);
    } catch (std::exception &e) {
        LOGERROR("{}", e.what());
        return false;
    }
    return true;
}

homestore::BlkStore< homestore::VdevVarSizeBlkAllocatorPolicy >* HomeBlks::get_data_blkstore() {
    return m_data_blk_store;
}

homestore::BlkStore< homestore::VdevFixedBlkAllocatorPolicy, BLKSTORE_BUFFER_TYPE >* HomeBlks::get_metadata_blkstore() {
    return m_metadata_blk_store;
}

boost::intrusive_ptr< BlkBuffer > HomeBlks::get_valid_buf(const std::vector< boost::intrusive_ptr< BlkBuffer > >& bbuf,
                                                          bool& rewrite) {
    boost::intrusive_ptr< BlkBuffer > valid_buf = nullptr;
    uint32_t                          gen_cnt = 0;
    for (uint32_t i = 0; i < bbuf.size(); i++) {
        vol_sb_header* hdr = (vol_sb_header*)(bbuf[i]->at_offset(0).bytes);
        assert(hdr->magic == VOL_SB_MAGIC);
        assert(hdr->version == VOL_SB_VERSION);
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
    auto blkid = m_cfg_sb->vol_list_head;
    bool rewrite = false;
    m_scan_cnt++;
    int num_vol = 0;
    try {
        while (blkid.to_integer() != BlkId::invalid_internal_id()) {
            vol_mem_sb *sb = vol_sb_read(blkid);
            if (sb == nullptr) {
                // TODO: Error handling here...
            }

            auto vol_uuid = sb->ondisk_sb->uuid;

            if (!m_cfg.vol_found_cb(vol_uuid)) {
                LOGINFO("vol delete after recovery {}", sb->ondisk_sb->vol_name);
                /* don't need to mount this volume. Delete this volume. Its block will be recaimed automatically */
                LOGINFO("volume is deleted {}", boost::uuids::to_string(vol_uuid));
                if (m_last_vol_sb) {
                    m_last_vol_sb->ondisk_sb->next_blkid = sb->ondisk_sb->next_blkid;
                    /* write vdev superblocks */
                    vol_sb_write(m_last_vol_sb);
                } else {
                    m_cfg_sb->vol_list_head = sb->ondisk_sb->next_blkid;
                    m_cfg_sb->num_vols--;
                    config_super_block_write();
                }
            } else {
                /* create the volume */
                assert(sb->ondisk_sb->state != DESTROYING);
                if (m_last_vol_sb && BlkId::compare(sb->ondisk_sb->prev_blkid, m_last_vol_sb->ondisk_sb->blkid)) {
                    /* prev volume is deleted. update the prev blkid */
                    LOGINFO("updating the previous volume blkid");
                    sb->ondisk_sb->prev_blkid.set(m_last_vol_sb->ondisk_sb->blkid);
                    vol_sb_write(sb);
                }

                if (sb->ondisk_sb->state == ONLINE && m_vdev_failed) {
                    /* Move all the volumes to failed state */
                    sb->ondisk_sb->state = FAILED;
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
            LOGINFO("vol found {}", sb->ondisk_sb->vol_name);
        }

        assert(num_vol == m_cfg_sb->num_vols);
        /* clear the state in virtual devices as appropiate state is set in volume superblocks */
        if (m_vdev_failed) {
            m_data_blk_store->reset_vdev_failed_state();
            m_metadata_blk_store->reset_vdev_failed_state();
            m_sb_blk_store->reset_vdev_failed_state();
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
    }
    m_cfg.init_done_cb(err, m_out_params);
}

void HomeBlks::create_data_blkstore(vdev_info_block* vb) {
    if (vb == nullptr) {
        /* change it to context */
        struct blkstore_blob blob;
        blob.type = blkstore_type::DATA_STORE;
        uint64_t size = (90 * m_dev_mgr->get_total_cap()) / 100;
        size = ALIGN_SIZE(size, HomeStoreConfig::phys_page_size);
        m_size_avail = size;
        LOGINFO("maximum capacity for data blocks is {}", m_size_avail);
        m_data_blk_store = new BlkStore< VdevVarSizeBlkAllocatorPolicy >(
            m_dev_mgr, m_cache, size, WRITEBACK_CACHE, 0, (char*)&blob, sizeof(blkstore_blob), m_data_pagesz,
            "data", Volume::process_vol_data_completions);
    } else {
        m_data_blk_store = new BlkStore< VdevVarSizeBlkAllocatorPolicy >(
            m_dev_mgr, m_cache, vb, WRITEBACK_CACHE, m_data_pagesz, "data", Volume::process_vol_data_completions);
        if (vb->failed) {
            m_vdev_failed = true;
            LOGINFO("data block store is in failed state");
        }
    }
}

void HomeBlks::create_metadata_blkstore(vdev_info_block* vb) {
    if (vb == nullptr) {
        struct blkstore_blob blob;
        blob.type = blkstore_type::METADATA_STORE;
        uint64_t size = (2 * m_dev_mgr->get_total_cap()) / 100;
        size = ALIGN_SIZE(size, HomeStoreConfig::phys_page_size);
        m_metadata_blk_store = new BlkStore< VdevFixedBlkAllocatorPolicy, BLKSTORE_BUFFER_TYPE >(
            m_dev_mgr, m_cache, size, RD_MODIFY_WRITEBACK_CACHE, 0, (char*)&blob, sizeof(blkstore_blob),
            HomeStoreConfig::atomic_phys_page_size, "metadata");
    } else {
        m_metadata_blk_store = new BlkStore< VdevFixedBlkAllocatorPolicy, BLKSTORE_BUFFER_TYPE >(
            m_dev_mgr, m_cache, vb, RD_MODIFY_WRITEBACK_CACHE, HomeStoreConfig::atomic_phys_page_size, "metadata");
        if (vb->failed) {
            m_vdev_failed = true;
            LOGINFO("metadata block store is in failed state");
        }
    }
}

uint32_t HomeBlks::get_data_pagesz() const { return m_data_pagesz; }

void HomeBlks::create_sb_blkstore(vdev_info_block* vb) {
    if (vb == nullptr) {

        /* create a blkstore */
        struct sb_blkstore_blob blob;
        blob.type = blkstore_type::SB_STORE;
        blob.blkid.set(BlkId::invalid_internal_id());
        uint64_t size = (1 * m_dev_mgr->get_total_cap()) / 100;
        size = ALIGN_SIZE(size, HomeStoreConfig::phys_page_size);
        m_sb_blk_store = new BlkStore< VdevVarSizeBlkAllocatorPolicy >(
            m_dev_mgr, m_cache, size, PASS_THRU, m_cfg.devices.size() - 1, (char*)&blob, sizeof(sb_blkstore_blob),
            HomeStoreConfig::atomic_phys_page_size, "superblock");

        /* allocate a new blk id */
        BlkId bid = alloc_blk();
        blob.type = blkstore_type::SB_STORE;
        blob.blkid.set(bid);

        /* build the config super block */
        config_super_block_init(bid);

        /* update the context info */
        m_sb_blk_store->update_vb_context((uint8_t*)&blob);
    } else {
        /* create a blkstore */
        m_sb_blk_store = new BlkStore< VdevVarSizeBlkAllocatorPolicy >(m_dev_mgr, m_cache, vb, PASS_THRU,
                                                                       HomeStoreConfig::atomic_phys_page_size,
                                                                       "superblock");
        if (vb->failed) {
            m_vdev_failed = true;
            LOGINFO("super block store is in failed state");
        }

        /* get the blkid of config super block */
        sb_blkstore_blob* blob = (sb_blkstore_blob*)(&(vb->context_data));
        if (blob->blkid.to_integer() == BlkId::invalid_internal_id()) {
            LOGINFO("init was failed last time. Should retry it with init flag");
            throw homestore::homestore_exception("init was failed last time. Should retry it with init",
                                                 homestore_error::init_failed);
        }

        /* read and build the config super block */
        std::vector< boost::intrusive_ptr< BlkBuffer > > bbuf =
            m_sb_blk_store->read_nmirror(blob->blkid, m_cfg.devices.size() - 1);
        bool                              rewrite = false;
        boost::intrusive_ptr< BlkBuffer > valid_buf = get_valid_buf(bbuf, rewrite);
        memcpy(m_cfg_sb, valid_buf->at_offset(0).bytes, sizeof(*m_cfg_sb));
        assert(m_cfg_sb->gen_cnt > 0);
        assert(m_cfg_sb->blkid.to_integer() == blob->blkid.to_integer());
        m_cfg_sb->boot_cnt++;
        /* update the config super block */
        config_super_block_write();
    }
}

bool HomeBlks::is_ready() { return (m_rdy); }

uint64_t HomeBlks::get_boot_cnt() {
    
    assert(m_cfg_sb->boot_cnt < UINT16_MAX);
    return (uint16_t) m_cfg_sb->boot_cnt; 
}

// 
// Handle the race between shutdown therad and init thread;
// 1. HomeStore starts init
// 2. AM send shutdown request immediately
// 3. Init switched out after is_shutdown() return false;
// 4. Shutdown thread set m_shutdown to true;
//    and found nothing needs to be freed since init thread hasn't finished yet so shutdown thread completes;
// 5. Init thread comes back and init things out with all the memory leaked since shutdown thread has already finished;
//
void HomeBlks::init_thread() {
    std::error_condition error = no_error;
    try {
        bool init = m_cfg.disk_init;
        /* attach physical devices */
        add_devices();
                
        /* create blkstore if it is a first time boot */
        if (init) {
            create_blkstores();
        }

        // 
        // Will not resume shutdown if we reboot from an un-finished shutdown procedure. 
        //
        {
            std::lock_guard<std::recursive_mutex>  lg(m_vol_lock);
            if (m_cfg_sb->test_flag(HOMEBLKS_SB_FLAGS_CLEAN_SHUTDOWN)) {
                LOGDEBUG("System was shutdown cleanly.");
                // clear the flag and persist to disk, if we received a new shutdown and completed successfully, 
                // the flag should be set again; 
                m_cfg_sb->clear_flag(HOMEBLKS_SB_FLAGS_CLEAN_SHUTDOWN);
                config_super_block_write();
            } else if (!init) {
                LOGCRITICAL("System experienced sudden panic since last boot!");
            } else {
                LOGINFO("Initializing the system");
            }
        }

        sisl::HttpServerConfig cfg;
        cfg.is_tls_enabled = false;
        cfg.bind_address = "0.0.0.0";
        cfg.server_port = SDS_OPTIONS["hb_stats_port"].as<int32_t>();
        cfg.read_write_timeout_secs = 10;

        m_http_server = std::unique_ptr< sisl::HttpServer >(new sisl::HttpServer(cfg, {{
                handler_info("/api/v1/version", HomeBlks::get_version, (void *)this),
                handler_info("/api/v1/getMetrics", HomeBlks::get_metrics, (void *)this),
                handler_info("/api/v1/getObjLife", HomeBlks::get_obj_life, (void *)this),
                handler_info("/metrics", HomeBlks::get_prometheus_metrics, (void *)this),
                handler_info("/api/v1/getLogLevel", HomeBlks::get_log_level, (void *)this),
                handler_info("/api/v1/setLogLevel", HomeBlks::set_log_level, (void *)this),
                handler_info("/api/v1/dumpStackTrace", HomeBlks::dump_stack_trace, (void *)this),
        }}));
        m_http_server->start();

        /* scan volumes */
        scan_volumes();
        m_init_finished = true;
        m_cv.notify_all();
        return;
        
    } catch (const std::exception& e) {
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

const char* HomeBlks::get_name(const VolumePtr& vol) { return vol->get_name(); }
uint64_t    HomeBlks::get_page_size(const VolumePtr& vol) { return vol->get_page_size(); }

homeds::blob HomeBlks::at_offset(const boost::intrusive_ptr< BlkBuffer >& buf, uint32_t offset) {
    return (buf->at_offset(offset));
}

#ifndef NDEBUG
void HomeBlks::print_tree(const VolumePtr& vol) { vol->print_tree(); }
#endif

void HomeBlks::get_version(sisl::HttpCallData cd) {
    HomeBlks *hb = (HomeBlks *)(cd->cookie());
    hb->m_http_server->respond_OK(cd, EVHTP_RES_OK, std::string("HomeBlks: ") + HomeBlks::version);
}

void HomeBlks::get_metrics(sisl::HttpCallData cd) {
    HomeBlks *hb = (HomeBlks *)(cd->cookie());
    std::string msg = sisl::MetricsFarm::getInstance().get_result_in_json_string();
    hb->m_http_server->respond_OK(cd, EVHTP_RES_OK, msg);
}

void HomeBlks::get_prometheus_metrics(sisl::HttpCallData cd) {
    HomeBlks *hb = (HomeBlks *)(cd->cookie());
    std::string msg = sisl::MetricsFarm::getInstance().report(sisl::ReportFormat::kTextFormat);
    hb->m_http_server->respond_OK(cd, EVHTP_RES_OK, msg);
}

void HomeBlks::get_obj_life(sisl::HttpCallData cd) {
    HomeBlks *hb = (HomeBlks *)(cd->cookie());
    nlohmann::json j;
    sisl::ObjCounterRegistry::foreach([&j](const std::string& name, int64_t created, int64_t alive) {
        std::stringstream ss; ss << "created=" << created << " alive=" << alive;
        j[name] = ss.str();
    });
    hb->m_http_server->respond_OK(cd, EVHTP_RES_OK, j.dump());
}

void HomeBlks::set_log_level(sisl::HttpCallData cd) {
    HomeBlks *hb = (HomeBlks *)(cd->cookie());
    auto req = cd->request();

    const evhtp_kv_t* _new_log_level = nullptr;
    const evhtp_kv_t* _new_log_module = nullptr;
    const char* logmodule = nullptr;
    char* endptr = nullptr;

    _new_log_module = evhtp_kvs_find_kv(req->uri->query, "logmodule");
    if (_new_log_module) {
        logmodule = _new_log_module->val;
    }

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
    HomeBlks *hb = (HomeBlks *)(cd->cookie());
    hb->m_http_server->respond_OK(cd, EVHTP_RES_OK, sds_logging::GetAllModuleLogLevel().dump());
}

void HomeBlks::dump_stack_trace(sisl::HttpCallData cd) {
    HomeBlks *hb = (HomeBlks *)(cd->cookie());
    sds_logging::log_stack_trace(true);
    hb->m_http_server->respond_OK(cd, EVHTP_RES_OK, "Look for stack trace in the log file");
}

//
// free resources shared accross volumes
//
void HomeBlks::shutdown_process(shutdown_comp_callback shutdown_comp_cb, bool force) {
    try {
        auto start = std::chrono::steady_clock::now();
        std::unique_lock<std::recursive_mutex>  lg(m_vol_lock);
        while (m_volume_map.size()) {
            for (auto & x : m_volume_map) {
                if (x.second.use_count() == 1) {
                    LOGINFO("vol: {} ref_count successfully drops to 1. Trigger normal shutdown. ", x.second->get_name());
                    m_volume_map.erase(x.first);
                }
            }

            if (m_volume_map.size() != 0) {
                auto end = std::chrono::steady_clock::now();
                auto num_seconds = std::chrono::duration_cast<std::chrono::seconds>(end - start).count();

                // triger force shutdown if timeout
                if (force || (num_seconds > SHUTDOWN_TIMEOUT_NUM_SECS)) {
                    if (force) {
                        LOGINFO("FORCE shutdown requested!");
                    } else {
                        LOGERROR("Shutdown timeout for {} seconds, trigger force shutdown. ", SHUTDOWN_TIMEOUT_NUM_SECS);
                    }
                    // trigger dump on debug mode
                    assert(0);

                    // in release mode, just forcely free 
                    // Force trigger every Volume's destructor when there 
                    // is ref_count leak for this volume instance.
                    for (auto& x : m_volume_map) {
                        LOGERROR("Force Shutdown vol: {}, ref_cnt: {}", x.second->get_name(), x.second.use_count());
                        x.second.get()->~Volume();       
                    }

                    m_volume_map.clear();

                    // break the while loop to continue force shutdown
                    break;
                }

                // unlock before we go sleep
                lg.unlock();

                // sleep for a while before we make another check;
                std::this_thread::sleep_for(2s);

                // take look before we make another check;
                lg.lock();
            }
        }


        assert(m_volume_map.size() == 0);

        // m_cfg_sb needs to to be freed in the last, because we need to set the clean shutdown flag
        // after shutdown is succesfully completed;

        // clear the shutdown bit on disk;
        m_cfg_sb->set_flag(HOMEBLKS_SB_FLAGS_CLEAN_SHUTDOWN);
        config_super_block_write();
        // free the in-memory copy 
        free(m_cfg_sb);
        lg.unlock();

        // All of volume's destructors have been called, now release shared resoruces.
        delete m_sb_blk_store;
        delete m_data_blk_store;
        delete m_metadata_blk_store;

        // BlkStore ::m_cache/m_wb_cache points to HomeBlks::m_cache;
        delete m_cache;

        delete m_dev_mgr; 

        // Waiting for http server thread to join
        m_http_server->stop();   
        m_http_server.reset();

        shutdown_comp_cb(true);
    } catch (const std::exception& e) {
        LOGERROR("{}", e.what());
        shutdown_comp_cb(false);
    }
}

// 
// Shutdown:
// 1. Set persistent state of shutdown
// 2. Start a thread to do shutdown routines;
//
std::error_condition HomeBlks::shutdown(shutdown_comp_callback shutdown_comp_cb, bool force) {
    // shutdown thread should be only started once;
    static bool started = false;

    if (started) {
        LOGINFO("shutdown thread already started;");
        return no_error;
    }
    started = true;
    
    m_shutdown = true;

    // 
    // Need to wait m_init_finished to be true before we create shutdown thread because:
    // 1. if init thread is running slower than shutdown thread, 
    // 2. it is possible that shutdown thread completed but init thread 
    //    is still creating resources, which would be resource leak 
    //    after shutdown thread exits;
    //
    {
        std::unique_lock<std::mutex>   lk(m_cv_mtx);
        if (!m_init_finished.load()) {
            m_cv.wait(lk);
        }
    }

    // The volume destructor should be triggered automatcially when ref_cnt drops to zero;

    // Sart a thread to monitor the shutdown progress, if timeout, trigger force shutdown
    std::vector<ThreadPool::TaskFuture<void>>   task_result;
    task_result.push_back(submit_job([this, &shutdown_comp_cb, force](){
                this->shutdown_process(shutdown_comp_cb, force);
                }));

    for (auto& x : task_result) {
        x.get();
    }

    return no_error;
}

// m_shutdown is used for I/O threads to check is_shutdown() without holding m_vol_lock;
bool HomeBlks::is_shutdown() {
    return m_shutdown.load();
}
