#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>

#include <sisl/logging/logging.h>
#include <iomgr/iomgr.hpp>

#include <homestore/homestore_decl.hpp>
#include <homestore/blk.h>

namespace spdlog {
class logger;
} // namespace spdlog

namespace homestore {
class DeviceManager;
class ResourceMgr;
class HomeStoreStatusMgr;
class MetaBlkService;
class LogStoreService;
struct vdev_info_block;
class HomeStore;
class CPManager;
typedef std::shared_ptr< HomeStore > HomeStoreSafePtr;

VENUM(blkstore_type, uint32_t, DATA_STORE = 1, INDEX_STORE = 2, SB_STORE = 3, DATA_LOGDEV_STORE = 4,
      CTRL_LOGDEV_STORE = 5, META_STORE = 6);

#pragma pack(1)
struct blkstore_blob {
    enum blkstore_type type;
};

struct sb_blkstore_blob : blkstore_blob {
    BlkId blkid;
};
#pragma pack()

typedef std::function< void(void) > hs_init_done_cb_t;
typedef std::function< void(void) > hs_init_starting_cb_t;
typedef std::function< void(bool success) > hs_comp_callback;

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
    std::unique_ptr< MetaBlkService > m_meta_service;
    std::unique_ptr< LogStoreService > m_log_service;

    std::unique_ptr< DeviceManager > m_dev_mgr;
    std::shared_ptr< sisl::logging::logger_t > m_periodic_logger;
    std::unique_ptr< HomeStoreStatusMgr > m_status_mgr;
    std::unique_ptr< ResourceMgr > m_resource_mgr;
    std::unique_ptr< CPManager > m_cp_mgr;

    bool m_vdev_failed{false};
    std::atomic< uint32_t > m_format_cnt{1};

    float m_index_store_size_pct{0};
    float m_data_store_size_pct{0};
    float m_meta_store_size_pct{0};
    float m_data_log_store_size_pct{0};
    float m_ctrl_log_store_size_pct{0};

    hs_init_done_cb_t m_init_done_cb{nullptr};
    hs_init_starting_cb_t m_before_init_starting_cb{nullptr};

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

public:
    HomeStore() = default;
    virtual ~HomeStore() = default;

    /////////////////////////////////////////// static HomeStore member functions /////////////////////////////////
    static HomeStoreSafePtr s_instance;

    static void set_instance(const HomeStoreSafePtr& instance) { s_instance = instance; }
    static void reset_instance() { s_instance.reset(); }
    static HomeStore* instance();
    static std::shared_ptr< HomeStore > safe_instance() { return s_instance; }

    static std::shared_ptr< spdlog::logger >& periodic_logger() { return instance()->m_periodic_logger; }

    ///////////////////////////// Member functions /////////////////////////////////////////////
    HomeStore& with_params(const hs_input_params& input);
    HomeStore& with_meta_service(float size_pct);
    HomeStore& with_log_service(float data_size_pct, float ctrl_size_pct);
    HomeStore& after_init_done(hs_init_done_cb_t init_done_cb);
    HomeStore& before_init_devices(hs_init_starting_cb_t init_start_cb);

    void init(bool wait_for_init = false);
    void shutdown(bool wait = true, const hs_comp_callback& done_cb = nullptr);

    iomgr::io_thread_t get_hs_flush_thread() const;
    cap_attrs get_system_capacity() const;
    bool is_first_time_boot() const;

    // Getters
    bool has_index_service() const { return (m_index_store_size_pct != 0); }
    bool has_data_service() const { return (m_data_store_size_pct != 0); }
    bool has_meta_service() const { return (m_meta_store_size_pct != 0); }
    bool has_data_log_service() const { return (m_data_log_store_size_pct != 0); }
    bool has_ctrl_log_service() const { return (m_ctrl_log_store_size_pct != 0); }
    bool has_log_service() const { return (has_data_log_service() || has_ctrl_log_service()); }
    std::string list_services() const {
        std::string str;
        if (has_meta_service()) { str += "meta,"; }
        if (has_data_service()) { str += "data,"; }
        if (has_index_service()) { str += "index,"; }
        if (has_data_log_service()) { str += "data_log,"; }
        if (has_ctrl_log_service()) { str += "ctrl_log,"; }
        return str;
    }

    MetaBlkService& meta_service() { return *m_meta_service; }
    LogStoreService& logstore_service() { return *m_log_service; }
    DeviceManager* device_mgr() { return m_dev_mgr.get(); }
    ResourceMgr& resource_mgr() { return *m_resource_mgr.get(); }
    CPManager& cp_mgr() { return *m_cp_mgr.get(); }

protected:
    virtual void process_vdev_error(vdev_info_block* vb) {}

private:
    void init_cache();
    void init_done(bool first_time_boot);
    void init_devices();
    DeviceManager* get_device_manager() { return m_dev_mgr.get(); }
    uint64_t pct_to_size(float pct, PhysicalDevGroup pdev_group) const;
    void new_vdev_found(DeviceManager* dev_mgr, vdev_info_block* vb);
};

static HomeStore* hs() { return HomeStore::instance(); }
} // namespace homestore
