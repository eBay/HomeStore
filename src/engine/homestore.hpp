#pragma once

#include <sds_logging/logging.h>

#include "engine/blkstore/blkstore.hpp"
#include "engine/common/homestore_config.hpp"
#include "engine/device/device.h"
#include "engine/homeds/btree/btree.hpp"
#include "engine/homeds/btree/ssd_btree.hpp"
#include "api/meta_interface.hpp"
#include "fds/malloc_helper.hpp"
#include "fds/utils.hpp"
#include "homelogstore/log_store.hpp"

#include "homestore_base.hpp"
#include "engine/common/homestore_config.hpp"

using namespace homeds::btree;

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
typedef BlkStore< VdevVarSizeBlkAllocatorPolicy > sb_blkstore_t;

template < typename IndexBuffer >
using index_blkstore_t = BlkStore< VdevFixedBlkAllocatorPolicy, IndexBuffer >;

typedef BlkStore< homestore::VdevVarSizeBlkAllocatorPolicy > meta_blkstore_t;

typedef boost::intrusive_ptr< BlkBuffer > blk_buf_t;

VENUM(blkstore_type, uint32_t, DATA_STORE = 1, INDEX_STORE = 2, SB_STORE = 3, LOGDEV_STORE = 4, META_STORE = 5);

struct blkstore_blob {
    enum blkstore_type type;
};

struct sb_blkstore_blob : blkstore_blob {
    BlkId blkid;
};


template < typename IndexBuffer >
class HomeStore : public HomeStoreBase {
public:
    HomeStore() = default;
    virtual ~HomeStore() = default;

    void init(const hs_input_params& input) {
        if (input.devices.size() == 0) {
            LOGERROR("no devices given");
            throw std::invalid_argument("null device list");
        }

        /* set the homestore static config parameters */
        auto& hs_config = HomeStoreStaticConfig::instance();
        hs_config.input = input;
        hs_config.drive_attr =
            (input.drive_attr) ? *input.drive_attr : get_drive_attrs(input.devices, input.device_type);

        HomeStoreDynamicConfig::init_settings_default();

        // Start a custom periodic logger
        static std::once_flag flag1;
        std::call_once(flag1, [this]() {
            m_periodic_logger = sds_logging::CreateCustomLogger("homestore", "_periodic", false /* tee_to_stdout */);
        });
        sds_logging::SetLogPattern("[%D %T.%f] [%^%L%$] [%t] %v", m_periodic_logger);

#ifndef NDEBUG
        flip::Flip::instance().start_rpc_server();
#endif

        /* Btree leaf node in index btree should accamodate minimum 2 entries to do the split. And on a average
         * a value consume 2 bytes (for checksum) per blk and few bytes for each IO and node header.
         * max_blk_cnt represents max number of blks blk allocator should give in a blk. We are taking
         * conservatively 4 entries in a node with avg size of 2 for each blk.
         * Note :- This restriction will go away once btree start supporinting higher size value.
         */
        hs_config.engine.max_blks_in_blkentry = std::min(static_cast< uint32_t >(BlkId::max_blks_in_op()),
                                                         hs_config.drive_attr.atomic_phys_page_size / (4 * 2));
        hs_config.engine.min_io_size =
            std::min(input.min_virtual_page_size, (uint32_t)hs_config.drive_attr.atomic_phys_page_size);
        hs_config.engine.memvec_max_io_size = {static_cast< uint64_t >(
            HS_STATIC_CONFIG(engine.min_io_size) * ((static_cast< uint64_t >(1) << MEMPIECE_ENCODE_MAX_BITS) - 1))};
        hs_config.engine.max_vol_io_size = hs_config.engine.memvec_max_io_size;

        m_data_pagesz = input.min_virtual_page_size;

        LOGINFO("HomeStore starting with dynamic config version: {} static config: {}", HS_DYNAMIC_CONFIG(version),
                hs_config.to_json().dump(4));

#ifndef NDEBUG
        hs_config.validate();
#endif

        /* create cache */
        uint64_t cache_size = ResourceMgr::get_cache_size();
        sisl::set_memory_release_rate(HS_DYNAMIC_CONFIG(generic.mem_release_rate));

        m_cache = std::make_unique< Cache< BlkId > >(cache_size, hs_config.drive_attr.atomic_phys_page_size);

        /* create device manager */
        m_dev_mgr = std::make_unique< DeviceManager >(
            std::bind(&HomeStore::new_vdev_found, this, std::placeholders::_1, std::placeholders::_2),
            sizeof(sb_blkstore_blob), virtual_dev_process_completions, input.device_type,
            std::bind(&HomeStore::process_vdev_error, this, std::placeholders::_1), input.is_restricted_mode);
    }

    cap_attrs get_system_capacity() {
        cap_attrs cap;
        cap.used_data_size = get_data_blkstore()->get_used_size();
        cap.used_index_size = get_index_blkstore()->get_used_size();
        cap.used_log_size = get_logdev_blkstore()->get_used_size();
        cap.used_metablk_size = get_meta_blkstore()->get_used_size();
        cap.used_total_size = cap.used_data_size + cap.used_index_size + cap.used_log_size + cap.used_metablk_size;
        cap.initial_total_size = get_data_blkstore()->get_size();
        cap.initial_total_data_meta_size = get_data_blkstore()->get_size() + get_index_blkstore()->get_size() +
            get_logdev_blkstore()->get_size() + get_meta_blkstore()->get_size();
        return cap;
    }

    virtual data_blkstore_t* get_data_blkstore() const override { return m_data_blk_store.get(); }
    index_blkstore_t< IndexBuffer >* get_index_blkstore() const { return m_index_blk_store.get(); }
    sb_blkstore_t* get_sb_blkstore() const { return m_sb_blk_store.get(); }
    logdev_blkstore_t* get_logdev_blkstore() const { return m_logdev_blk_store.get(); }
    meta_blkstore_t* get_meta_blkstore() const { return m_meta_blk_store.get(); }

    uint32_t get_data_pagesz() const { return m_data_pagesz; }
    bool print_checksum() const { return m_print_checksum; }

    BlkId alloc_sb_blk(size_t sz) {
        BlkId bid;
        blk_alloc_hints hints;
        hints.desired_temp = 0;
        hints.dev_id_hint = -1;
        hints.is_contiguous = true;
        auto ret = m_sb_blk_store->alloc_contiguous_blk(sz, hints, &bid);
        if (ret != BlkAllocStatus::SUCCESS) {
            throw homestore::homestore_exception("space not available", homestore_error::space_not_avail);
        }
        assert(ret == BlkAllocStatus::SUCCESS);
        return bid;
    }

    void blkalloc_cp_start(std::shared_ptr< blkalloc_cp > ba_cp) {
        get_data_blkstore()->blkalloc_cp_start(ba_cp);
        get_index_blkstore()->blkalloc_cp_start(ba_cp);
    }

    std::shared_ptr< blkalloc_cp > blkalloc_attach_prepare_cp(std::shared_ptr< blkalloc_cp > cur_ba_cp) {
        return (get_data_blkstore()->attach_prepare_cp(cur_ba_cp));
    }

protected:
    virtual data_blkstore_t::comp_callback data_completion_cb() = 0;
    virtual void process_vdev_error(vdev_info_block* vb) = 0;

    void init_devices() {
        auto& hs_config = HomeStoreStaticConfig::instance();

        /* attach physical devices */
        bool first_time_boot = m_dev_mgr->add_devices(hs_config.input.devices);
        HS_ASSERT_CMP(LOGMSG, m_dev_mgr->get_total_cap() / hs_config.input.devices.size(), >, MIN_DISK_CAP_SUPPORTED);
        HS_ASSERT_CMP(LOGMSG, m_dev_mgr->get_total_cap(), <, MAX_SUPPORTED_CAP);

        /* create blkstore if it is a first time boot */
        if (first_time_boot) {
            create_meta_blkstore(nullptr);
            create_logdev_blkstore(nullptr);
            create_index_blkstore(nullptr);
            create_data_blkstore(nullptr);
        }
        init_done(first_time_boot);
    }

    void init_done(bool first_time_boot) {
        auto cnt = m_format_cnt.fetch_sub(1);
        if (cnt != 1) { return; }
        m_dev_mgr->init_done();
        MetaBlkMgrSI()->start(m_meta_blk_store.get(), m_meta_sb_blob, first_time_boot);
        ResourceMgr::set_total_cap(m_dev_mgr->get_total_cap());
    }

    void close_devices() { m_dev_mgr->close_devices(); }

    void new_vdev_found(DeviceManager* dev_mgr, vdev_info_block* vb) {
        /* create blkstore */
        blkstore_blob* blob = (blkstore_blob*)vb->context_data;
        switch (blob->type) {
        case blkstore_type::DATA_STORE:
            create_data_blkstore(vb);
            break;
        case blkstore_type::INDEX_STORE:
            create_index_blkstore(vb);
            break;
        case blkstore_type::LOGDEV_STORE:
            create_logdev_blkstore(vb);
            break;
        case blkstore_type::META_STORE:
            create_meta_blkstore(vb);
            break;
        default:
            HS_ASSERT(LOGMSG, 0, "Unknown blkstore_type {}", blob->type);
        }
    }

    void create_data_blkstore(vdev_info_block* vb) {
        if (vb == nullptr) {
            /* change it to context */
            struct blkstore_blob blob {};
            blob.type = blkstore_type::DATA_STORE;
            uint64_t size = (data_blkstore_pct * m_dev_mgr->get_total_cap()) / 100;
            size = sisl::round_up(size, HS_STATIC_CONFIG(drive_attr.phys_page_size));
            m_size_avail = size;
            LOGINFO("maximum capacity for data blocks is {}", m_size_avail);
            m_data_blk_store = std::make_unique< data_blkstore_t >(
                m_dev_mgr.get(), m_cache.get(), size, BlkStoreCacheType::WRITEBACK_CACHE, 0, (char*)&blob,
                sizeof(blkstore_blob),
                m_data_pagesz, "data", true, data_completion_cb());
        } else {
            m_data_blk_store = std::make_unique< data_blkstore_t >(
                m_dev_mgr.get(), m_cache.get(), vb, BlkStoreCacheType::WRITEBACK_CACHE, m_data_pagesz,
                                                    "data", (vb->failed ? true : false), true, data_completion_cb());
            if (vb->failed) {
                m_vdev_failed = true;
                LOGINFO("data block store is in failed state");
                throw std::runtime_error("vdev in failed state");
            }
        }
    }

    void create_index_blkstore(vdev_info_block* vb) {
        if (vb == nullptr) {
            struct blkstore_blob blob {};
            blob.type = blkstore_type::INDEX_STORE;
            uint64_t size = (indx_blkstore_pct * m_dev_mgr->get_total_cap()) / 100;
            size = sisl::round_up(size, HS_STATIC_CONFIG(drive_attr.phys_page_size));
            m_index_blk_store = std::make_unique< index_blkstore_t< IndexBuffer > >(
                m_dev_mgr.get(), m_cache.get(), size, BlkStoreCacheType::RD_MODIFY_WRITEBACK_CACHE, 0, (char*)&blob,
                sizeof(blkstore_blob),
                HS_STATIC_CONFIG(drive_attr.atomic_phys_page_size), "index", true);
            ++m_format_cnt;
            m_index_blk_store->format(([this](bool success) { init_done(true); }));
        } else {
            m_index_blk_store = std::make_unique< index_blkstore_t< IndexBuffer > >(
                m_dev_mgr.get(), m_cache.get(), vb, BlkStoreCacheType::RD_MODIFY_WRITEBACK_CACHE,
                HS_STATIC_CONFIG(drive_attr.atomic_phys_page_size), "index", (vb->failed ? true : false), true);
            if (vb->failed) {
                m_vdev_failed = true;
                LOGINFO("index block store is in failed state");
                throw std::runtime_error("vdev in failed state");
            }
        }
    }

    void create_meta_blkstore(vdev_info_block* vb) {
        if (vb == nullptr) {
            struct blkstore_blob blob {};
            blob.type = blkstore_type::META_STORE;
            uint64_t size = (meta_blkstore_pct * m_dev_mgr->get_total_cap()) / 100;
            size = sisl::round_up(size, HS_STATIC_CONFIG(drive_attr.phys_page_size));
            m_meta_blk_store = std::make_unique< meta_blkstore_t >(
                m_dev_mgr.get(), m_cache.get(), size, BlkStoreCacheType::PASS_THRU, 0, (char*)&blob,
                sizeof(blkstore_blob),
                HS_STATIC_CONFIG(drive_attr.phys_page_size), "meta", false);
            ++m_format_cnt;
            m_meta_blk_store->format(([this](bool success) { init_done(true); }));

        } else {
            m_meta_blk_store = std::make_unique< meta_blkstore_t >(
                m_dev_mgr.get(), m_cache.get(), vb, BlkStoreCacheType::PASS_THRU,
                                                                   HS_STATIC_CONFIG(drive_attr.phys_page_size), "meta",
                                                                   (vb->failed ? true : false), false);
            if (vb->failed) {
                m_vdev_failed = true;
                LOGINFO("meta block store is in failed state");
                throw std::runtime_error("vdev in failed state");
            }

            /* get the blkid of homestore super block */
            m_meta_sb_blob = (sb_blkstore_blob*)(&(vb->context_data));
            if (!m_meta_sb_blob->blkid.is_valid()) {
                LOGINFO("init was failed last time. Should retry it with init flag");
                throw homestore::homestore_exception("init was failed last time. Should retry it with init",
                                                     homestore_error::init_failed);
            }
        }
    }

    void create_logdev_blkstore(vdev_info_block* vb) {
        if (vb == nullptr) {
            struct blkstore_blob blob {};
            blob.type = blkstore_type::LOGDEV_STORE;
            uint64_t size = (logdev_blkstore_pct * m_dev_mgr->get_total_cap()) / 100;
            size = sisl::round_up(size, HS_STATIC_CONFIG(drive_attr.phys_page_size));
            m_logdev_blk_store = std::make_unique< BlkStore< VdevVarSizeBlkAllocatorPolicy > >(
                m_dev_mgr.get(), m_cache.get(), size, BlkStoreCacheType::PASS_THRU, 0, (char*)&blob,
                sizeof(blkstore_blob),
                HS_STATIC_CONFIG(drive_attr.atomic_phys_page_size), "logdev", false,
                std::bind(&LogDev::process_logdev_completions, &HomeLogStoreMgr::logdev(), std::placeholders::_1));
            ++m_format_cnt;
            m_logdev_blk_store->format(([this](bool success) { init_done(true); }));
        } else {
            m_logdev_blk_store = std::make_unique< BlkStore< VdevVarSizeBlkAllocatorPolicy > >(
                m_dev_mgr.get(), m_cache.get(), vb, BlkStoreCacheType::PASS_THRU,
                HS_STATIC_CONFIG(drive_attr.atomic_phys_page_size),
                "logdev", (vb->failed ? true : false), false,
                std::bind(&LogDev::process_logdev_completions, &HomeLogStoreMgr::logdev(), std::placeholders::_1));
            if (vb->failed) {
                m_vdev_failed = true;
                LOGINFO("logdev block store is in failed state");
                throw std::runtime_error("vdev in failed state");
            }
        }
    }

    void data_recovery_done() {
        auto& hs_config = HomeStoreStaticConfig::instance();
        if (!m_dev_mgr->is_first_time_boot()) { m_data_blk_store->recovery_done(); }
    }

    void indx_recovery_done() {
        auto& hs_config = HomeStoreStaticConfig::instance();
        if (!m_dev_mgr->is_first_time_boot()) { m_index_blk_store->recovery_done(); }
    }

    int64_t available_size() const { return m_size_avail; }
    void set_available_size(int64_t sz) { m_size_avail = sz; }
    virtual DeviceManager* get_device_manager() override { return m_dev_mgr.get(); }

public:
    /////////////////////////////////////////// static HomeStore member functions /////////////////////////////////
    static void fake_reboot() {
        MetaBlkMgr::fake_reboot();
        IndxMgr::fake_reboot();
        MetaBlkMgrSI()->register_handler("LOG_DEV", HomeLogStoreMgr::meta_blk_found_cb, nullptr);
    }

#if 0
    static void zero_pdev_sbs(const std::vector< dev_info >& devices) { DeviceManager::zero_pdev_sbs(devices); }
#endif

private:
    static iomgr::drive_attributes get_drive_attrs(const std::vector< dev_info >& devices,
                                                   const iomgr_drive_type drive_type) {
        auto drive_iface = iomgr::IOManager::instance().default_drive_interface();
        iomgr::drive_attributes attr = drive_iface->get_attributes(devices[0].dev_names, drive_type);
#ifndef NDEBUG
        for (auto i{1u}; i < devices.size(); ++i) {
            auto observed_attr = drive_iface->get_attributes(devices[i].dev_names, drive_type);
            if (attr != observed_attr) {
                HS_ASSERT(DEBUG, 0,
                          "Expected all phys dev have same attributes, prev device attr={}, this device attr={}",
                          attr.to_json().dump(4), observed_attr.to_json().dump(4));
            }
        }
#endif

        return attr;
    }

protected:
    bool m_vdev_failed = false;
    bool m_print_checksum = true;

    std::unique_ptr< data_blkstore_t > m_data_blk_store;
    std::unique_ptr< index_blkstore_t< IndexBuffer > > m_index_blk_store;
    std::unique_ptr< sb_blkstore_t > m_sb_blk_store;
    std::unique_ptr< logdev_blkstore_t > m_logdev_blk_store;
    std::unique_ptr< meta_blkstore_t > m_meta_blk_store;
    std::unique_ptr< DeviceManager > m_dev_mgr;
    std::unique_ptr< Cache< BlkId > > m_cache;

private:
    uint64_t m_size_avail = 0;
    uint32_t m_data_pagesz = 0;
    std::atomic< uint32_t > m_format_cnt = 1;
    sb_blkstore_blob* m_meta_sb_blob = nullptr;
    const uint64_t data_blkstore_pct = 84;
    const uint64_t indx_blkstore_pct = 3;
    const uint64_t logdev_blkstore_pct = 2;
    const uint64_t meta_blkstore_pct = 1;
};

} // namespace homestore
