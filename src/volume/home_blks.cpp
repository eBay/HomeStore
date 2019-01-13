#include "home_blks.hpp"
#include "volume.hpp"
#include <device/device.h>
#include <device/virtual_dev.hpp>
#include <cassert>
#include <device/blkbuffer.hpp>

using namespace homestore;

HomeBlks* HomeBlks::_instance = nullptr;

VolInterface* homestore::vol_homestore_init(init_params& cfg) { return (HomeBlks::init(cfg)); }

VolInterface* HomeBlks::init(init_params& cfg) {
    fLI::FLAGS_minloglevel = 3;
    _instance = new HomeBlks(cfg);
    return ((VolInterface*)(_instance));
}

HomeBlks::HomeBlks(init_params& cfg) :
        m_cfg(cfg),
        m_cache(nullptr),
        m_rdy(false),
        m_last_vol_sb(nullptr),
        m_vdev_failed(false),
        m_size_avail(0),
        m_scan_cnt(0),
        m_init_failed(false) {

    /* set the homestore config parameters */
    HomeStoreConfig::phys_page_size = m_cfg.physical_page_size;
    HomeStoreConfig::align_size = m_cfg.disk_align_size;
    HomeStoreConfig::atomic_phys_page_size = m_cfg.atomic_page_size;
    /* If these parameters changes then we need to take care upgrade/revert in device manager */
    HomeStoreConfig::max_chunks = MAX_CHUNKS;
    HomeStoreConfig::max_vdevs = MAX_VDEVS;
    HomeStoreConfig::max_pdevs = MAX_PDEVS;
    HomeStoreConfig::min_page_size = m_cfg.min_virtual_page_size;
    m_data_pagesz = m_cfg.min_virtual_page_size;

    assert(VOL_SB_SIZE >= sizeof(vol_sb));
    assert(VOL_SB_SIZE >= sizeof(vol_config_sb));

    assert(m_cfg.atomic_page_size >= m_cfg.min_virtual_page_size);
    assert(cfg.max_cap / cfg.devices.size() > MIN_DISK_CAP_SUPPORTED);
    m_out_params.max_io_size = VOL_MAX_IO_SIZE;
    int ret = posix_memalign((void**)&m_cfg_sb, HomeStoreConfig::align_size, VOL_SB_SIZE);
    assert(!ret);

    /* create cache */
    m_cache = new Cache< BlkId >(m_cfg.cache_size, m_cfg.physical_page_size);

    /* create device manager */
    m_dev_mgr = new homestore::DeviceManager(new_vdev_found, sizeof(sb_blkstore_blob), cfg.iomgr,
                                             virtual_dev_process_completions, m_cfg.is_file);

    /* start thread */
    m_thread_id = std::thread(&HomeBlks::init_thread, this);
}

std::error_condition HomeBlks::write(std::shared_ptr< Volume > vol, uint64_t lba, uint8_t* buf, uint32_t nblks,
                                     boost::intrusive_ptr< vol_interface_req > req) {
    assert(m_rdy);
    return (vol->write(lba, buf, nblks, req));
}

std::error_condition HomeBlks::read(std::shared_ptr< Volume > vol, uint64_t lba, int nblks,
                                    boost::intrusive_ptr< vol_interface_req > req) {
    assert(m_rdy);
    return (vol->read(lba, nblks, req, false));
}

std::error_condition HomeBlks::sync_read(std::shared_ptr< Volume > vol, uint64_t lba, int nblks,
                                         boost::intrusive_ptr< vol_interface_req > req) {
    assert(m_rdy);
    return (vol->read(lba, nblks, req, true));
}

std::shared_ptr< Volume > HomeBlks::createVolume(const vol_params& params) {
    if (params.size >= m_size_avail) {
        LOGINFO("there is a possibility of running out of space as total size of the volumes"
                "created are more then maximum capacity");
    }
    try {
        decltype(m_volume_map)::iterator it;
        // Try to add an entry for this volume
        {
            std::lock_guard< std::mutex > lg(m_vol_lock);
            bool                          happened{false};
            std::tie(it, happened) = m_volume_map.emplace(std::make_pair(params.uuid, nullptr));
            if (!happened) {
                if (m_volume_map.end() != it)
                    return it->second;
                throw std::runtime_error("Unknown bug");
            }
        }
        // Okay, this is a new volume so let's create it
        auto new_vol = Volume::make_volume(params);
        it->second = new_vol;
        if (m_size_avail < params.size) {
            m_size_avail = 0;
        } else {
            m_size_avail -= params.size;
        }
        LOGINFO("vol created {}", params.vol_name);
        return it->second;
    } catch (const std::exception& e) { LOGERROR("{}", e.what()); }
    return nullptr;
}

std::error_condition HomeBlks::removeVolume(boost::uuids::uuid const& uuid) {
    std::shared_ptr< Volume > volume;
    // Locked Map
    {
        std::lock_guard< std::mutex > lg(m_vol_lock);
        if (auto it = m_volume_map.find(uuid); m_volume_map.end() != it) {
            if (2 <= it->second.use_count()) {
                LOGERROR("Refusing to delete volume with outstanding references: {}", to_string(uuid));
                return std::make_error_condition(std::errc::device_or_resource_busy);
            }
            volume = std::move(it->second);
            m_volume_map.erase(it);
        }
    } // Unlock Map
    return (volume ? volume->destroy() : std::make_error_condition(std::errc::no_such_device_or_address));
}

std::shared_ptr< Volume > HomeBlks::lookupVolume(boost::uuids::uuid const& uuid) {

    std::lock_guard< std::mutex > lg(m_vol_lock);
    auto                          it = m_volume_map.find(uuid);
    if (m_volume_map.end() != it)
        return it->second;
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
    assert(ret == BLK_ALLOC_SUCCESS);
    return bid;
}

void HomeBlks::vol_sb_init(vol_sb* sb) {
    /* allocate block */

    BlkId                         bid = alloc_blk();
    std::lock_guard< std::mutex > lg(m_vol_lock);
    sb->gen_cnt = 0;
    sb->prev_blkid.set(m_last_vol_sb ? m_last_vol_sb->blkid.to_integer() : BlkId::invalid_internal_id());
    sb->next_blkid.set(BlkId::invalid_internal_id());
    sb->blkid.set(bid);
    sb->version = VOL_SB_VERSION;
    sb->magic = VOL_SB_MAGIC;

    /* write the sb */
    vol_sb_write(sb, true);

    /* update the previous pointers */
    if (m_last_vol_sb != nullptr) {
        assert(m_cfg_sb->vol_list_head.to_integer() != BlkId::invalid_internal_id());
        assert(m_last_vol_sb->next_blkid.to_integer() == BlkId::invalid_internal_id());
        m_last_vol_sb->next_blkid.set(bid);
        vol_sb_write(m_last_vol_sb, true);
    } else {
        assert(m_cfg_sb->vol_list_head.to_integer() == BlkId::invalid_internal_id());
        m_cfg_sb->vol_list_head.set(bid);
    }

    m_cfg_sb->num_vols++;
    config_super_block_write(true);
    /* update the last volume super block. If exception happens in between it won't be updated */
    m_last_vol_sb = sb;
}

void HomeBlks::vol_sb_remove(vol_sb* sb) { /* TODO need to implement it when vol delete comes in */ }

void HomeBlks::config_super_block_init(BlkId& bid) {
    /* build the config super block */
    m_cfg_sb->blkid.set(bid);
    m_cfg_sb->vol_list_head.set(BlkId::invalid_internal_id());
    m_cfg_sb->num_vols = 0;
    m_cfg_sb->gen_cnt = 0;
    m_cfg_sb->version = VOL_SB_VERSION;
    m_cfg_sb->magic = VOL_SB_MAGIC;
    config_super_block_write(false);
}

void HomeBlks::config_super_block_write(bool lock) {
    homeds::MemVector mvec;

    if (!lock) {
        m_vol_lock.lock();
    }
    m_cfg_sb->gen_cnt++;
    try {
        mvec.set((uint8_t*)m_cfg_sb, VOL_SB_SIZE, 0);
        m_sb_blk_store->write(m_cfg_sb->blkid, mvec);
    } catch (std::exception& e) {
        if (!lock) {
            m_vol_lock.unlock();
        };
        throw e;
    }

    if (!lock) {
        m_vol_lock.unlock();
    };
}

void HomeBlks::vol_sb_write(vol_sb* sb) { vol_sb_write(sb, false); }

void HomeBlks::vol_sb_write(vol_sb* sb, bool lock) {
    homeds::MemVector mvec;

    if (!lock) {
        m_vol_lock.lock();
    }
    try {
        sb->gen_cnt++;
        mvec.set((uint8_t*)sb, VOL_SB_SIZE, 0);
        m_sb_blk_store->write(sb->blkid, mvec);
    } catch (std::exception& e) {
        if (!lock) {
            m_vol_lock.unlock();
        };
        throw e;
    }
    if (!lock) {
        m_vol_lock.unlock();
    };
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

void HomeBlks::attach_vol_completion_cb(std::shared_ptr< Volume > vol, io_comp_callback cb) {
    vol->attach_completion_cb(cb);
}

void HomeBlks::add_devices() { m_dev_mgr->add_devices(m_cfg.devices, m_cfg.disk_init); }

void HomeBlks::vol_mounted(std::shared_ptr< Volume > vol, vol_state state) {
    m_cfg.vol_mounted_cb(vol, state);
    LOGINFO("vol mounted name {} state {}", vol->get_sb()->vol_name, state);
}

void HomeBlks::vol_state_change(std::shared_ptr< Volume > vol, vol_state old_state, vol_state new_state) {
    m_cfg.vol_state_change_cb(vol, old_state, new_state);
}

homestore::BlkStore< homestore::VdevVarSizeBlkAllocatorPolicy >* HomeBlks::get_data_blkstore() {
    return m_data_blk_store;
}

homestore::BlkStore< homestore::VdevFixedBlkAllocatorPolicy, BLKSTORE_BUFFER_TYPE >* HomeBlks::get_metadata_blkstore() {
    return m_metadata_blk_store;
}

boost::intrusive_ptr< BlkBuffer > HomeBlks::get_valid_buf(std::vector< boost::intrusive_ptr< BlkBuffer > > bbuf,
                                                          bool&                                            rewrite) {
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

void HomeBlks::scan_volumes() {
    auto blkid = m_cfg_sb->vol_list_head;
    bool rewrite = false;
    m_scan_cnt++;
    int num_vol = 0;
    try {
        while (blkid.to_integer() != BlkId::invalid_internal_id()) {
            std::vector< boost::intrusive_ptr< BlkBuffer > > bbuf =
                m_sb_blk_store->read_nmirror(blkid, m_cfg.devices.size() - 1);
            boost::intrusive_ptr< BlkBuffer > valid_buf = get_valid_buf(bbuf, rewrite);

            vol_sb* sb = nullptr;
            int     ret = posix_memalign((void**)&sb, HomeStoreConfig::align_size, VOL_SB_SIZE);
            assert(!ret);
            memcpy(sb, valid_buf->at_offset(0).bytes, sizeof(*sb));
            assert(sb->blkid.to_integer() == blkid.to_integer());
            if (rewrite) {
                /* update the super block */
                vol_sb_write(sb, false);
            }

            if (!m_cfg.vol_found_cb(sb->uuid)) {
                LOGINFO("vol delete after recovery {}", sb->vol_name);
                /* don't need to mount this volume. Delete this volume. Its block will be recaimed automatically */
                LOGINFO("volume is deleted {}", to_string(sb->uuid));
                if (m_last_vol_sb) {
                    m_last_vol_sb->next_blkid = sb->next_blkid;
                    /* write vdev superblocks */
                    vol_sb_write(m_last_vol_sb, false);
                } else {
                    m_cfg_sb->vol_list_head = sb->next_blkid;
                    m_cfg_sb->num_vols--;
                    config_super_block_write(false);
                }
            } else {
                /* create the volume */
                if (m_last_vol_sb && BlkId::compare(sb->prev_blkid, m_last_vol_sb->blkid)) {
                    /* prev volume is deleted. update the prev blkid */
                    LOGINFO("updating the previous volume blkid");
                    sb->prev_blkid.set(m_last_vol_sb->blkid);
                    vol_sb_write(sb, false);
                }
                num_vol++;
                decltype(m_volume_map)::iterator it;
                bool                             happened{false};
                std::tie(it, happened) = m_volume_map.emplace(std::make_pair(sb->uuid, nullptr));
                assert(happened);
                m_scan_cnt++;

                std::shared_ptr< Volume > new_vol;
                try {
                    new_vol = Volume::make_volume(sb);
                } catch (const std::exception& e) {
                    m_scan_cnt--;
                    throw e;
                }
                it->second = new_vol;

                /* allocate this blkid in the sb blkstore */
                m_sb_blk_store->alloc_blk(blkid);
                m_last_vol_sb = sb;
            }
            blkid = sb->next_blkid;
            LOGINFO("vol found {}", sb->vol_name);
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
            m_cfg.init_done_cb(error, m_out_params);
        }
        return;
    }

    int cnt = m_scan_cnt.fetch_sub(1, std::memory_order_relaxed);
    if (cnt == 1) {
        m_rdy = true;
        m_dev_mgr->inited();
        m_cfg.init_done_cb(no_error, m_out_params);
    }
}

void HomeBlks::create_data_blkstore(vdev_info_block* vb) {
    if (vb == nullptr) {
        /* change it to context */
        struct blkstore_blob blob;
        blob.type = blkstore_type::DATA_STORE;
        uint64_t size = (90 * m_cfg.max_cap) / 100;
        size = ALIGN_SIZE(size, HomeStoreConfig::phys_page_size);
        m_size_avail = size;
        LOGINFO("maximum capacity for data blocks is {}", m_size_avail);
        m_data_blk_store = new BlkStore< VdevVarSizeBlkAllocatorPolicy >(
            m_dev_mgr, m_cache, size, WRITEBACK_CACHE, 0, Volume::process_vol_data_completions, (char*)&blob,
            sizeof(blkstore_blob), m_data_pagesz);
    } else {
        m_data_blk_store = new BlkStore< VdevVarSizeBlkAllocatorPolicy >(
            m_dev_mgr, m_cache, vb, WRITEBACK_CACHE, Volume::process_vol_data_completions, m_data_pagesz);
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
        uint64_t size = (2 * m_cfg.max_cap) / 100;
        size = ALIGN_SIZE(size, HomeStoreConfig::phys_page_size);
        m_metadata_blk_store = new BlkStore< VdevFixedBlkAllocatorPolicy, BLKSTORE_BUFFER_TYPE >(
            m_dev_mgr, m_cache, size, WRITEBACK_CACHE, 0, (char*)&blob, sizeof(blkstore_blob),
            HomeStoreConfig::atomic_phys_page_size);
    } else {
        m_metadata_blk_store = new BlkStore< VdevFixedBlkAllocatorPolicy, BLKSTORE_BUFFER_TYPE >(
            m_dev_mgr, m_cache, vb, WRITEBACK_CACHE, 0, HomeStoreConfig::atomic_phys_page_size);
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
        uint64_t size = (1 * m_cfg.max_cap) / 100;
        size = ALIGN_SIZE(size, HomeStoreConfig::phys_page_size);
        m_sb_blk_store = new BlkStore< VdevVarSizeBlkAllocatorPolicy >(
            m_dev_mgr, m_cache, size, PASS_THRU, m_cfg.devices.size() - 1, (char*)&blob, sizeof(sb_blkstore_blob),
            HomeStoreConfig::atomic_phys_page_size);

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
                                                                       HomeStoreConfig::atomic_phys_page_size);
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
        if (rewrite) {
            /* update the config super block */
            config_super_block_write(false);
        }
    }
}

bool HomeBlks::is_ready() { return (m_rdy); }

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

        /* scan volumes */
        scan_volumes();
        return;
    } catch (homestore::homestore_exception& e) {
        auto error = e.get_err();
        LOGERROR("get exception {}", error.message());
    } catch (const std::exception& e) {
        LOGERROR("{}", e.what());
        error = std::make_error_condition(std::errc::io_error);
    }
    m_cfg.init_done_cb(error, m_out_params);
}

void HomeBlks::vol_scan_cmpltd(std::shared_ptr< Volume > vol, vol_state state) {

    vol_mounted(vol, state);

    int cnt = m_scan_cnt.fetch_sub(1, std::memory_order_relaxed);
    if (cnt == 1) {
        if (m_init_failed) {
            auto error = std::make_error_condition(std::errc::io_error);
            m_cfg.init_done_cb(error, m_out_params);
        } else {
            m_rdy = true;
            m_dev_mgr->inited();
            m_cfg.init_done_cb(no_error, m_out_params);
        }
    }
}

const char* HomeBlks::get_name(std::shared_ptr< Volume > vol) { return vol->get_name(); }

uint64_t HomeBlks::get_page_size(std::shared_ptr< Volume > vol) { return vol->get_page_size(); }

uint64_t HomeBlks::get_size(std::shared_ptr< Volume > vol) { return vol->get_size(); }

homeds::blob HomeBlks::at_offset(boost::intrusive_ptr< BlkBuffer > buf, uint32_t offset) {
    return (buf->at_offset(offset));
}
