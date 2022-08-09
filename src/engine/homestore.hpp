#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <stdexcept>

#include <sisl/fds/malloc_helper.hpp>
#include <sisl/fds/buffer.hpp>
#include <sisl/logging/logging.h>

#include "api/meta_interface.hpp"
#include "engine/blkstore/blkstore.hpp"
#include "engine/common/homestore_config.hpp"
#include "engine/device/device.h"
#include "engine/device/virtual_dev.hpp"
#include "engine/homeds/btree/btree.hpp"
#include "engine/homeds/btree/ssd_btree.hpp"
#include "homeblks/homeblks_config.hpp"
#include "homelogstore/log_store.hpp"
#include "homestore_base.hpp"
#include "engine/common/resource_mgr.hpp"
#include "engine/index/indx_mgr.hpp"

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

template < typename IndexBuffer >
class HomeStore : public HomeStoreBase {
public:
    typedef Cache< BlkId, CacheBuffer< BlkId > > CacheType;

    HomeStore() = default;
    virtual ~HomeStore() = default;

    void init(const hs_input_params& input) {
        if (input.data_devices.empty()) {
            LOGERROR("no data devices given");
            throw std::invalid_argument("null device list");
        }

        sisl::ObjCounterRegistry::enable_metrics_reporting();
        m_status_mgr = std::make_unique< HomeStoreStatusMgr >();
        MetaBlkMgrSI()->register_handler("INDX_MGR_CP", StaticIndxMgr::meta_blk_found_cb, nullptr);

        /* set the homestore static config parameters */
        auto& hs_config = HomeStoreStaticConfig::instance();
        hs_config.input = input;

        HomeStoreDynamicConfig::init_settings_default();

        // Restrict iomanager to throttle upto the app mem size allocated for us
        iomanager.set_io_memory_limit(HS_STATIC_CONFIG(input.io_mem_size()));

        // Start a custom periodic logger
        static std::once_flag flag1;
        std::call_once(flag1, [this]() {
            m_periodic_logger =
                sisl::logging::CreateCustomLogger("homestore", "_periodic", false, true /* tee_to_stdout_stderr */);
        });
        sisl::logging::SetLogPattern("[%D %T.%f] [%^%L%$] [%t] %v", m_periodic_logger);

#ifndef NDEBUG
        flip::Flip::instance().start_rpc_server();
#endif

        start_flush_threads();

        /* create device manager */
        m_dev_mgr = std::make_unique< DeviceManager >(input.data_devices, bind_this(HomeStore::new_vdev_found, 2),
                                                      sizeof(sb_blkstore_blob), VirtualDev::static_process_completions,
                                                      bind_this(HomeStore::process_vdev_error, 1));
        m_dev_mgr->init();
    }

    void start_flush_threads() {
        /* create local flush thread */
        static std::mutex cv_mtx;
        static std::condition_variable flush_thread_cv;
        uint32_t thread_cnt = 0;
        uint32_t max_thread_cnt = HS_DYNAMIC_CONFIG(generic.num_flush_threads);

        for (uint32_t i = 0; i < max_thread_cnt; ++i) {
            iomanager.create_reactor("hs_flush_thread", TIGHT_LOOP | ADAPTIVE_LOOP,
                                     [this, &tl_cv = flush_thread_cv, &tl_mtx = cv_mtx, &thread_cnt](bool is_started) {
                                         if (is_started) {
                                             std::unique_lock< std::mutex > lk{tl_mtx};
                                             ++thread_cnt;
                                             m_flush_threads.push_back(iomanager.iothread_self());
                                             tl_cv.notify_one();
                                         }
                                     });
        }
        {
            std::unique_lock< std::mutex > lk{cv_mtx};
            flush_thread_cv.wait(lk, [&thread_cnt, max_thread_cnt] { return (thread_cnt == max_thread_cnt); });
        }
    }

    iomgr::io_thread_t get_hs_flush_thread() const {
        /* XXX: Does it need to be atomic variable ? Worse case each thread uses it local cache value which shouldn't be
         * bad.
         */
        static int next_thread = 0;
        next_thread = (next_thread + 1) % m_flush_threads.size();
        return m_flush_threads[next_thread];
    }

    uint32_t get_indx_mgr_page_size() const { return (m_dev_mgr->get_atomic_page_size(PhysicalDevGroup::FAST)); }
    void init_cache() {
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

        LOGINFO("HomeStore starting with dynamic config version: {} static config: {}, safe_mode: {}",
                HS_DYNAMIC_CONFIG(version), hs_config.to_json().dump(4),
                HB_DYNAMIC_CONFIG(general_config->boot_safe_mode));

        /* create cache */
        uint64_t cache_size = ResourceMgrSI().get_cache_size();
        m_cache = std::make_unique< CacheType >(cache_size, get_indx_mgr_page_size());
    }

    cap_attrs get_system_capacity() {
        cap_attrs cap;
        cap.used_data_size = get_data_blkstore()->get_used_size();
        cap.used_index_size = get_index_blkstore()->get_used_size();
        cap.used_log_size = get_data_logdev_blkstore()->get_used_size() + get_ctrl_logdev_blkstore()->get_used_size();
        cap.used_metablk_size = get_meta_blkstore()->get_used_size();
        cap.used_total_size = cap.used_data_size + cap.used_index_size + cap.used_log_size + cap.used_metablk_size;
        cap.initial_total_size = get_data_blkstore()->get_size();
        cap.initial_total_data_meta_size = get_data_blkstore()->get_size() + get_index_blkstore()->get_size() +
            get_data_logdev_blkstore()->get_size() + get_ctrl_logdev_blkstore()->get_size() +
            get_meta_blkstore()->get_size();
        return cap;
    }

    virtual BlkStore< BlkBuffer >* get_data_blkstore() const override { return m_data_blk_store.get(); }
    BlkStore< IndexBuffer >* get_index_blkstore() const { return m_index_blk_store.get(); }
    BlkStore<>* get_sb_blkstore() const { return m_sb_blk_store.get(); }
    BlkStore<>* get_meta_blkstore() const { return m_meta_blk_store.get(); }
    JournalVirtualDev* get_data_logdev_blkstore() const override { return m_data_logdev_blk_store.get(); }
    JournalVirtualDev* get_ctrl_logdev_blkstore() const override { return m_ctrl_logdev_blk_store.get(); }

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

    std::shared_ptr< blkalloc_cp > blkalloc_attach_prepare_cp(const std::shared_ptr< blkalloc_cp >& cur_ba_cp) {
        return (get_data_blkstore()->attach_prepare_cp(cur_ba_cp));
    }

protected:
    virtual BlkStore< BlkBuffer >::comp_callback data_completion_cb() = 0;
    virtual void process_vdev_error(vdev_info_block* vb) = 0;

    void init_devices() {
        auto& hs_config = HomeStoreStaticConfig::instance();

        /* attach physical devices */
        const bool first_time_boot = m_dev_mgr->is_first_time_boot();

        /* create blkstore if it is a first time boot */
        if (first_time_boot) {
            init_cache();
            create_meta_blkstore(nullptr);
            create_data_logdev_blkstore(nullptr);
            create_ctrl_logdev_blkstore(nullptr);
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
        ResourceMgrSI().set_total_cap(m_dev_mgr->get_total_cap());
    }

    void close_devices() {
        m_dev_mgr->close_devices();
        m_data_blk_store.reset();
        m_index_blk_store.reset();
        m_sb_blk_store.reset();
        m_meta_blk_store.reset();
        m_data_logdev_blk_store.reset();
        m_ctrl_logdev_blk_store.reset();
        m_dev_mgr.reset();
        m_cache.reset();
    }

    void new_vdev_found(DeviceManager* dev_mgr, vdev_info_block* vb) {
        /* create blkstore */
        blkstore_blob* const blob{reinterpret_cast< blkstore_blob* >(vb->context_data)};
        static std::once_flag flag1;
        std::call_once(flag1, [this]() { init_cache(); });
        switch (blob->type) {
        case blkstore_type::DATA_STORE:
            create_data_blkstore(vb);
            break;
        case blkstore_type::INDEX_STORE:
            create_index_blkstore(vb);
            break;
        case blkstore_type::DATA_LOGDEV_STORE:
            create_data_logdev_blkstore(vb);
            break;
        case blkstore_type::CTRL_LOGDEV_STORE:
            create_ctrl_logdev_blkstore(vb);
            break;
        case blkstore_type::META_STORE:
            create_meta_blkstore(vb);
            break;
        default:
            HS_LOG_ASSERT(0, "Unknown blkstore_type {}", blob->type);
        }
    }

    void create_data_blkstore(vdev_info_block* const vb) {
        const PhysicalDevGroup pdev_group{PhysicalDevGroup::DATA};
        if (vb == nullptr) {
            /* change it to context */
            struct blkstore_blob blob {};
            blob.type = blkstore_type::DATA_STORE;
            const uint64_t size{
                pct_to_size((is_data_drive_hdd() ? hdd_data_blkstore_pct : data_blkstore_pct), pdev_group)};
            m_size_avail = size;
            LOGINFO("maximum capacity for data blocks is {}", m_size_avail);
            m_data_blk_store = std::make_unique< BlkStore< BlkBuffer > >(
                m_dev_mgr.get(), m_cache.get(), size, pdev_group, BlkStoreCacheType::WRITEBACK_CACHE,
                blk_allocator_type_t::varsize, 0, (char*)&blob, sizeof(blkstore_blob), m_data_pagesz, "data", true,
                data_completion_cb());
        } else {
            m_data_blk_store = std::make_unique< BlkStore< BlkBuffer > >(
                m_dev_mgr.get(), m_cache.get(), vb, pdev_group, BlkStoreCacheType::WRITEBACK_CACHE,
                blk_allocator_type_t::varsize, m_data_pagesz, "data", vb->is_failed(), true, data_completion_cb());
            if (vb->is_failed()) {
                m_vdev_failed = true;
                LOGINFO("data block store is in failed state");
                throw std::runtime_error("vdev in failed state");
            }
        }
    }

    void create_index_blkstore(vdev_info_block* const vb) {
        const PhysicalDevGroup pdev_group{PhysicalDevGroup::FAST};
        const auto atomic_phys_page_size{get_indx_mgr_page_size()};
        if (vb == nullptr) {
            struct blkstore_blob blob {};
            blob.type = blkstore_type::INDEX_STORE;
            const uint64_t size{
                pct_to_size((is_data_drive_hdd() ? hdd_indx_blkstore_pct : indx_blkstore_pct), pdev_group)};
            m_index_blk_store = std::make_unique< BlkStore< IndexBuffer > >(
                m_dev_mgr.get(), m_cache.get(), size, pdev_group, BlkStoreCacheType::RD_MODIFY_WRITEBACK_CACHE,
                blk_allocator_type_t::fixed, 0, (char*)&blob, sizeof(blkstore_blob), atomic_phys_page_size, "index",
                true);
        } else {
            m_index_blk_store = std::make_unique< BlkStore< IndexBuffer > >(
                m_dev_mgr.get(), m_cache.get(), vb, pdev_group, BlkStoreCacheType::RD_MODIFY_WRITEBACK_CACHE,
                blk_allocator_type_t::fixed, atomic_phys_page_size, "index", vb->is_failed(), true);
            if (vb->is_failed()) {
                m_vdev_failed = true;
                LOGINFO("index block store is in failed state");
                throw std::runtime_error("vdev in failed state");
            }
        }

        uint64_t mempool_size =
            (HS_DYNAMIC_CONFIG(generic.indx_mempool_percent) * ResourceMgrSI().get_cache_size()) / 100;
        LOGINFO("indx mempool size {}", mempool_size);
        iomanager.create_mempool(atomic_phys_page_size, mempool_size / atomic_phys_page_size);
        hs_utils::set_btree_mempool_size(atomic_phys_page_size);
    }

    void create_meta_blkstore(vdev_info_block* const vb) {
        const PhysicalDevGroup pdev_group{PhysicalDevGroup::META};
        const auto phys_page_size{m_dev_mgr->get_phys_page_size({PhysicalDevGroup::META})};
        if (vb == nullptr) {
            struct blkstore_blob blob {};
            blob.type = blkstore_type::META_STORE;
            const uint64_t size{
                pct_to_size((is_data_drive_hdd() ? hdd_meta_blkstore_pct : meta_blkstore_pct), pdev_group)};
            m_meta_blk_store = std::make_unique< BlkStore<> >(
                m_dev_mgr.get(), m_cache.get(), size, pdev_group, BlkStoreCacheType::PASS_THRU,
                blk_allocator_type_t::varsize, 0, (char*)&blob, sizeof(blkstore_blob), phys_page_size, "meta", false);
        } else {
            m_meta_blk_store = std::make_unique< BlkStore<> >(
                m_dev_mgr.get(), m_cache.get(), vb, pdev_group, BlkStoreCacheType::PASS_THRU,
                blk_allocator_type_t::varsize, phys_page_size, "meta", vb->is_failed(), false);
            if (vb->is_failed()) {
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

    void create_data_logdev_blkstore(vdev_info_block* const vb) {
        const PhysicalDevGroup pdev_group{PhysicalDevGroup::FAST};
        const auto atomic_phys_page_size{m_dev_mgr->get_atomic_page_size({PhysicalDevGroup::FAST})};
        if (vb == nullptr) {
            struct blkstore_blob blob {};
            blob.type = blkstore_type::DATA_LOGDEV_STORE;
            const uint64_t size{pct_to_size(
                (is_data_drive_hdd() ? hdd_data_logdev_blkstore_pct : data_logdev_blkstore_pct), pdev_group)};

            m_data_logdev_blk_store = std::make_unique< JournalVirtualDev >(
                m_dev_mgr.get(), "data_logdev", pdev_group, sizeof(blkstore_blob), 0, true, atomic_phys_page_size,
                std::bind(&LogDev::process_logdev_completions, &HomeLogStoreMgr::data_logdev(), std::placeholders::_1),
                (char*)&blob, size, false);

            ++m_format_cnt;
            m_data_logdev_blk_store->format(([this](bool success) { init_done(true); }));
        } else {
            m_data_logdev_blk_store = std::make_unique< JournalVirtualDev >(
                m_dev_mgr.get(), "data_logdev", vb, pdev_group,
                std::bind(&LogDev::process_logdev_completions, &HomeLogStoreMgr::data_logdev(), std::placeholders::_1),
                vb->is_failed(), false);

            if (vb->is_failed()) {
                m_vdev_failed = true;
                LOGINFO("data logdev block store is in failed state");
                throw std::runtime_error("vdev in failed state");
            }
        }
    }

    void create_ctrl_logdev_blkstore(vdev_info_block* const vb) {
        const PhysicalDevGroup pdev_group{PhysicalDevGroup::FAST};
        const auto atomic_phys_page_size{m_dev_mgr->get_atomic_page_size({PhysicalDevGroup::FAST})};

        if (vb == nullptr) {
            struct blkstore_blob blob {};
            blob.type = blkstore_type::CTRL_LOGDEV_STORE;
            const uint64_t size{pct_to_size(
                (is_data_drive_hdd() ? hdd_ctrl_logdev_blkstore_pct : ctrl_logdev_blkstore_pct), pdev_group)};

            m_ctrl_logdev_blk_store = std::make_unique< JournalVirtualDev >(
                m_dev_mgr.get(), "ctrl_logdev", pdev_group, sizeof(blkstore_blob), 0, true, atomic_phys_page_size,
                std::bind(&LogDev::process_logdev_completions, &HomeLogStoreMgr::ctrl_logdev(), std::placeholders::_1),
                (char*)&blob, size, false);

            ++m_format_cnt;
            m_ctrl_logdev_blk_store->format(([this](bool success) { init_done(true); }));
        } else {
            m_ctrl_logdev_blk_store = std::make_unique< JournalVirtualDev >(
                m_dev_mgr.get(), "ctrl_logdev", vb, pdev_group,
                std::bind(&LogDev::process_logdev_completions, &HomeLogStoreMgr::ctrl_logdev(), std::placeholders::_1),
                vb->is_failed(), false);

            if (vb->is_failed()) {
                m_vdev_failed = true;
                LOGINFO("ctrl logdev block store is in failed state");
                throw std::runtime_error("vdev in failed state");
            }
        }
    }

    uint32_t get_num_streams() const { return (m_data_blk_store->get_vdev()->get_num_streams()); }

    uint64_t get_stream_size() const { return (m_data_blk_store->get_vdev()->get_stream_size()); }

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
        // IndxMgr::fake_reboot();
        HomeLogStoreMgr::fake_reboot();
    }

#if 0
    static void zero_pdev_sbs(const std::vector< dev_info >& devices) { DeviceManager::zero_pdev_sbs(devices); }
#endif

private:
    uint64_t pct_to_size(const float pct, const PhysicalDevGroup pdev_group) const {
        uint64_t sz{static_cast< uint64_t >((pct * static_cast< double >(m_dev_mgr->get_total_cap(pdev_group))) / 100)};
        return sisl::round_up(sz, m_dev_mgr->get_phys_page_size(pdev_group));
    }

protected:
    std::unique_ptr< BlkStore< BlkBuffer > > m_data_blk_store;
    std::unique_ptr< BlkStore< IndexBuffer > > m_index_blk_store;
    std::unique_ptr< BlkStore<> > m_sb_blk_store;
    std::unique_ptr< BlkStore<> > m_meta_blk_store;
    std::unique_ptr< JournalVirtualDev > m_data_logdev_blk_store;
    std::unique_ptr< JournalVirtualDev > m_ctrl_logdev_blk_store;
    std::unique_ptr< DeviceManager > m_dev_mgr;
    std::unique_ptr< CacheType > m_cache;

private:
    std::vector< iomgr::io_thread_t > m_flush_threads;
    static constexpr float data_blkstore_pct{84.0};
    static constexpr float indx_blkstore_pct{3.0};

    static constexpr float data_logdev_blkstore_pct{1.8};
    static constexpr float ctrl_logdev_blkstore_pct{0.2};
    static constexpr float meta_blkstore_pct{0.5};

    static constexpr float hdd_data_blkstore_pct{90.0};
    static constexpr float hdd_meta_blkstore_pct{0.5};
    static constexpr float hdd_indx_blkstore_pct{87.0};

    static constexpr float hdd_data_logdev_blkstore_pct{8};
    static constexpr float hdd_ctrl_logdev_blkstore_pct{2};
};

} // namespace homestore
