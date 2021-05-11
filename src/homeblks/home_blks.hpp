#ifndef VOL_CONFIG_HPP
#define VOL_CONFIG_HPP

#include <atomic>
#include <cassert>
#include <condition_variable>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <system_error>
#include <type_traits>
#include <vector>

#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <fds/sparse_vector.hpp>
#include <fds/utils.hpp>
#include <metrics/metrics.hpp>
#include <settings/settings.hpp>
#include <utility/atomic_counter.hpp>

#include "api/meta_interface.hpp"
#include "api/vol_interface.hpp"
#include "engine/blkstore/blkstore.hpp"
#include "engine/homeds/btree/btree.hpp"
#include "engine/homeds/btree/ssd_btree.hpp"
#include "engine/homeds/btree/writeBack_cache.hpp"
#include "engine/homeds/thread/threadpool/thread_pool.h"
#include "engine/homestore.hpp"
#include "homeblks_config.hpp"
#include "homeblks_http_server.hpp"
#include "homeblks_status_mgr.hpp"

#ifndef DEBUG
extern bool same_value_gen;
#endif

namespace homestore {

constexpr uint8_t LBA_BITS{56};

class MappingKey;
class MappingValue;

/* Note: below two structures should not be greater then ssd atomic page size. If it is
 * then we need to use double buffer.
 */

const uint32_t HOMEBLKS_SB_SIZE{HS_STATIC_CONFIG(drive_attr.atomic_phys_page_size)};
constexpr uint32_t HOMEBLKS_SB_MAGIC{0xCEEDDEEB};
constexpr uint16_t HOMEBLKS_SB_VERSION{0x2};

typedef uint32_t homeblks_sb_flag_t;

const uint32_t HOMEBLKS_SB_FLAGS_CLEAN_SHUTDOWN{0x00000001};
struct homeblks_sb {
    uint64_t version;

    uint64_t boot_cnt;
    homeblks_sb_flag_t flags;

    void init_flag(homeblks_sb_flag_t f) { flags = f; }
    void set_flag(homeblks_sb_flag_t bit) { flags |= bit; }
    void clear_flag(homeblks_sb_flag_t bit) { flags &= ~bit; }
    bool test_flag(homeblks_sb_flag_t bit) { return flags & bit; }
} __attribute((packed));

// static_assert(std::is_trivially_copyable< homeblks_sb >::value, "Expecting homeblks_sb to be trivally copyable");
static_assert(std::is_trivially_copyable< BlkId >::value, "Expecting BlkId to be trivally copyable");

using namespace homeds::btree;

#define MappingBtreeDeclType                                                                                           \
    Btree< btree_store_type::SSD_BTREE, MappingKey, MappingValue, btree_node_type::VAR_VALUE,                          \
           btree_node_type::VAR_VALUE >

class HomeBlks;
using HomeBlksSafePtr = boost::intrusive_ptr< HomeBlks >;
struct vol_cp_id;
typedef std::shared_ptr< vol_cp_id > vol_cp_id_ptr;
struct homeblks_cp_id;

typedef std::map< boost::uuids::uuid, std::shared_ptr< homestore::Volume > > vol_map_t;

class HomeBlksMetrics : public sisl::MetricsGroupWrapper {
public:
    explicit HomeBlksMetrics(const char* homeblks_name) : sisl::MetricsGroupWrapper("HomeBlks", homeblks_name) {
        REGISTER_HISTOGRAM(scan_volumes_latency, "Scan Volumes latency");
        register_me_to_farm();
    }
    HomeBlksMetrics(const HomeBlksMetrics&) = delete;
    HomeBlksMetrics(HomeBlksMetrics&&) noexcept = delete;
    HomeBlksMetrics& operator=(const HomeBlksMetrics&) = delete;
    HomeBlksMetrics& operator=(HomeBlksMetrics&&) noexcept = delete;

    ~HomeBlksMetrics() { deregister_me_from_farm(); }
};

typedef WriteBackCacheBuffer< MappingKey, MappingValue, btree_node_type::VAR_VALUE, btree_node_type::VAR_VALUE >
    BLKSTORE_BUFFER_TYPE;

struct HomeBlksRecoveryStats {
    Clock::time_point m_start;  // recovery start time
    uint64_t m_phase0_ms{0};    // time spent in phase0: from init to receipt of meta_blk_recovery_comp_cb;
    uint64_t m_phase1_ms{0};    // time spent in phase1: volume Phase 1
    uint64_t m_phase2_ms{0};    // time spent in phase2: volume Phase 2
    uint64_t m_log_store_ms{0}; // time spent in logstore recovery
    uint64_t m_total_ms{0};     // total: from metablk notify homeblks of comp_cb to init_done;

    void phase0_done() { m_phase0_ms = get_elapsed_time_ms(m_start); }

    void start() { m_start = Clock::now(); }

    void end() {
        m_total_ms = get_elapsed_time_ms(m_start);
        LOGINFO("{}", to_string());
    }

    std::string to_string() {
        return fmt::format("Recovery Total (ms): {}, Recovery Total (ms): {},  Volume Phase-1 (ms): {}, Log Store "
                           "Recovery (ms): {}, Volume Phase-2 (ms): {}",
                           m_total_ms, m_phase0_ms, m_phase1_ms, m_log_store_ms, m_phase2_ms);
    }
};

/**
 * @brief HomeBlks - Implementor of VolInterface.
 *
 * About HomeBlks life cycle: HomeBlks is a pseudo singleton class wherein it can be accessed as singelton, but
 * using that way is strongly discouraged. Upon the start of the application, the main routine or user of HomeBlks
 * library, need to initialize it by calling HomeBlks::init(). This sets the main homeblks object reference count to
 * 2, one for maintaning singleton status, 1 for the fact it is initialized and not shutdown. Whichever submodule,
 * which needs to access the homeblks should get the reference to the homeblks and store it locally by calling
 * HomeBlks::safe_instance(), to guarantee that homeblks are not shutdown underneath them.
 *
 * When the main routine calls, HomeBlks::shutdown(), it simply decrements the initial reference count and wait for
 * ref count to become 1, when every subsystem starts
 */
class HomeBlks : public VolInterface, public HomeStore< BLKSTORE_BUFFER_TYPE > {
public:
    /********************************** APIs exposed to its consumer ******************************/
    static std::string version;

    friend class Volume;

    HomeBlks(const HomeBlks&) = delete;
    HomeBlks(HomeBlks&&) noexcept = delete;
    HomeBlks& operator=(const HomeBlks&) = delete;
    HomeBlks& operator=(HomeBlks&&) noexcept = delete;

    /**
     * @brief Initialize the HomeBlks. Before init called, none of the other HomeBlks methods can be used.
     *
     * @param cfg : Input Parameters to initialize the homeblks.
     * @param fake_reboot: simulate fake reboot, used for testing only
     * @return Pointer to the base VolInterface
     */
    static VolInterface* init(const init_params& cfg, bool fake_reboot = false);

    static bool shutdown(bool force = false);

    /**
     * @brief Get the instance or safe instance of this object. It is expected the caller to use safe_instance() and
     * retain the reference, to ensure that HomeBlks is the last one to be freed.
     *
     * @return HomeBlks*
     */
    static HomeBlks* instance();
    static HomeBlksSafePtr safe_instance();
    static void zero_boot_sbs(const std::vector< dev_info >& devices, iomgr_drive_type drive_type, io_flag oflags);

    virtual ~HomeBlks() override {}
    virtual std::error_condition write(const VolumePtr& vol, const vol_interface_req_ptr& req,
                                       bool part_of_batch = false) override;
    virtual std::error_condition read(const VolumePtr& vol, const vol_interface_req_ptr& req,
                                      bool part_of_batch = false) override;
    virtual std::error_condition sync_read(const VolumePtr& vol, const vol_interface_req_ptr& req) override;
    virtual std::error_condition unmap(const VolumePtr& vol, const vol_interface_req_ptr& req) override;
    virtual void submit_io_batch() override;

    virtual vol_interface_req_ptr create_vol_interface_req(void* const buf, const uint64_t lba, const uint32_t nlbas,
                                                           const bool sync = false, const bool cache = true) override;
    virtual vol_interface_req_ptr create_vol_interface_req(std::vector< iovec > iovecs, const uint64_t lba,
                                                           const uint32_t nlbas, const bool sync = false,
                                                           const bool cache = false) override;

    virtual VolumePtr create_volume(const vol_params& params) override;
    virtual std::error_condition remove_volume(const boost::uuids::uuid& uuid) override;
    virtual VolumePtr lookup_volume(const boost::uuids::uuid& uuid) override;

    virtual SnapshotPtr create_snapshot(const VolumePtr& vol);
    virtual std::error_condition remove_snapshot(const SnapshotPtr& snap);
    virtual SnapshotPtr clone_snapshot(const SnapshotPtr& snap);

    virtual std::error_condition restore_snapshot(const SnapshotPtr& snap);
    virtual void list_snapshot(const VolumePtr&, std::vector< SnapshotPtr > snap_list);
    virtual void read(const SnapshotPtr& snap, const snap_interface_req_ptr& req);
    // virtual void write(const VolumePtr& volptr, std::vector<SnapshotPtr> snap_list);
    // virtual SnapDiffPtr diff_snapshot(const SnapshotPtr& snap1, const SnapshotPtr& snap2);

    virtual const char* get_name(const VolumePtr& vol) override;
    virtual uint32_t get_align_size() override;
    virtual uint64_t get_page_size(const VolumePtr& vol) override;
    virtual uint64_t get_size(const VolumePtr& vol) override;
    virtual boost::uuids::uuid get_uuid(VolumePtr vol) override;
    virtual sisl::blob at_offset(const blk_buf_t& buf, uint32_t offset) override;

    virtual bool vol_state_change(const VolumePtr& vol, vol_state new_state) override;

    virtual void attach_vol_completion_cb(const VolumePtr& vol, const io_comp_callback& cb) override;
    virtual void attach_end_of_batch_cb(const end_of_batch_callback& cb) override;

    virtual bool trigger_shutdown(const shutdown_comp_callback& shutdown_done_cb = nullptr,
                                  bool force = false) override;
    virtual cap_attrs get_system_capacity() override {
        return HomeStore< BLKSTORE_BUFFER_TYPE >::get_system_capacity();
    }
    /**
     * @brief : fix corrupted mapping in volume
     *
     * @param vol : volume pointer that holds the mapping btree being fxied
     *
     * @return : true for a successful fix;
     *           false for a failed fix;
     */
    virtual bool fix_tree(VolumePtr vol, bool verify = false) override;

    /**
     * @brief : get volume state
     *
     * @param vol : volume pointer to whose state is being returned;
     *
     * @return : volume state
     */
    virtual vol_state get_state(VolumePtr vol) override;

    virtual void print_tree(const VolumePtr& vol, bool chksum = true) override;
    virtual bool verify_tree(const VolumePtr& vol) override;
    virtual void print_node(const VolumePtr& vol, uint64_t blkid, bool chksum = true) override;
#if 0
    virtual void zero_pdev_sbs() override { HomeStore< BLKSTORE_BUFFER_TYPE >::zero_pdev_sbs(); }
#endif
public:
    /***************************** APIs exposed to homestore subsystem ***********************/
    uint64_t get_boot_cnt() const {
        auto sb = (homeblks_sb*)m_homeblks_sb_buf.bytes();
        assert(sb->boot_cnt < UINT16_MAX);
        return (uint16_t)sb->boot_cnt;
    }

    bool is_recovery_mode() { return !m_rdy; }
    bool is_shutdown() const { return (m_shutdown_start_time.load(std::memory_order_acquire) != 0); }

    void init_done();
    void inc_sub_system_init_cnt();
    virtual void attach_prepare_indx_cp(std::map< boost::uuids::uuid, indx_cp_ptr >* cur_icp_map,
                                        std::map< boost::uuids::uuid, indx_cp_ptr >* new_icp_map, hs_cp* hcp,
                                        hs_cp* new_hcp) override;
    void do_volume_shutdown(bool force);
    void create_volume(VolumePtr vol);

    void register_status_cb();

    data_blkstore_t::comp_callback data_completion_cb() override;

    /**
     * @brief
     *
     * @param mblk
     * @param has_more
     */
    void meta_blk_found(meta_blk* mblk, sisl::byte_view buf, size_t size);
    void meta_blk_recovery_comp(bool success);

    bool verify_vols();
    bool verify_bitmap();

    HomeBlksStatusMgr* get_status_mgr();

#ifdef _PRERELEASE
    void set_io_flip();
    void set_error_flip();
#endif
    friend void intrusive_ptr_add_ref(HomeBlks* hs) {
        intrusive_ptr_add_ref(static_cast< homestore::HomeStoreBase* >(hs));
    }
    friend void intrusive_ptr_release(HomeBlks* hs) {
        intrusive_ptr_release(static_cast< homestore::HomeStoreBase* >(hs));
    }

public:
    // Other static functions
    static void meta_blk_found_cb(meta_blk* mblk, sisl::byte_view buf, size_t size);
    static void meta_blk_recovery_comp_cb(bool success);

protected:
    void process_vdev_error(vdev_info_block* vb) override;

private:
    HomeBlks(const init_params& cfg);

    // Read volume super block based on blkid
    void homeblks_sb_write();
    homeblks_sb* superblock_init();

    std::error_condition remove_volume_internal(const boost::uuids::uuid& uuid, bool force);
    void vol_mounted(const VolumePtr& vol, vol_state state);
    void vol_state_change(const VolumePtr& vol, vol_state old_state, vol_state new_state);
    void scan_volumes();

    void init_thread();
    void do_shutdown(const shutdown_comp_callback& shutdown_done_cb, bool force);
    blk_buf_t get_valid_buf(const std::vector< blk_buf_t >& bbuf, bool& rewrite);

    void call_multi_vol_completions();
    void migrate_sb();
    void migrate_homeblk_sb();
    void migrate_volume_sb();
    void migrate_logstore_sb();
    void migrate_cp_sb();
    void vol_recovery_start_phase1();
    void vol_recovery_start_phase2();
    void trigger_cp_init(uint32_t vol_mount_cnt);
    void start_home_log_store();

private:
    init_params m_cfg;
    sisl::byte_view m_homeblks_sb_buf;
    // homeblks_sb*  m_homeblks_sb = nullptr; // the homestore super block
    void* m_sb_cookie = nullptr;

    vol_map_t m_volume_map;
    std::recursive_mutex m_vol_lock;
    std::mutex m_shutdown_lock;

    std::atomic< int > m_sub_system_init_cnt = 0;
    std::atomic< bool > m_init_finished = false;
    std::error_condition m_init_failed = no_error;

    out_params m_out_params;
    std::unique_ptr< HomeBlksHttpServer > m_hb_http_server;
    std::unique_ptr< HomeBlksStatusMgr > m_hb_status_mgr;

    std::condition_variable m_cv_init_cmplt; // wait for init to complete
    std::mutex m_cv_mtx;
    bool m_rdy = false;

    std::atomic< uint64_t > m_shutdown_start_time = 0;
    iomgr::timer_handle_t m_shutdown_timer_hdl = iomgr::null_timer_handle;
    shutdown_comp_callback m_shutdown_done_cb;
    bool m_force_shutdown = false;
    bool m_init_error = false;
    bool m_vol_shutdown_cmpltd = false;
    HomeBlksMetrics m_metrics;
    std::atomic< bool > m_start_shutdown;
    iomgr::io_thread_t m_init_thread_id;

    std::unique_ptr< HomeBlksRecoveryStats > m_recovery_stats{nullptr};

    static bool m_meta_blk_found;

    static thread_local std::vector< std::shared_ptr< Volume > >* s_io_completed_volumes;
};

static inline HomeBlksSafePtr HomeBlksPtr() { return HomeBlks::safe_instance(); }
static inline HomeBlks* HomeBlksRawPtr() { return HomeBlks::instance(); }

} // namespace homestore
#endif // OMSTORE_OMSTORE_HPP
