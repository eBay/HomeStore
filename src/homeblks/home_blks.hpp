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
#include <sisl/fds/sparse_vector.hpp>
#include <sisl/fds/buffer.hpp>
#include <sisl/metrics/metrics.hpp>
#include <sisl/settings/settings.hpp>
#include <sisl/utility/atomic_counter.hpp>

#include "api/meta_interface.hpp"
#include "api/vol_interface.hpp"
#include "engine/blkstore/blkstore.hpp"
#include "engine/homeds/btree/btree.hpp"
#include "engine/homeds/btree/ssd_btree.hpp"
#include "engine/homeds/btree/writeBack_cache.hpp"
#include "engine/homeds/thread/threadpool/thread_pool.h"
#include "engine/homestore.hpp"
#include "homeblks_config.hpp"
#include <sisl/sobject/sobject.hpp>

#ifndef DEBUG
extern bool same_value_gen;
#endif

namespace homestore {

constexpr uint8_t LBA_BITS{56};

class MappingKey;
class MappingValue;
class HomeBlksHttpServer;

/* Note: below two structures should not be greater then ssd atomic page size. If it is
 * then we need to use double buffer.
 */

constexpr uint64_t hb_sb_magic{0xCEEDDEEB};
constexpr uint32_t hb_sb_version{0x1};

typedef uint32_t homeblks_sb_flag_t;

const uint32_t HOMEBLKS_SB_FLAGS_CLEAN_SHUTDOWN{0x00000001};
const uint32_t HOMEBLKS_SB_FLAGS_RESTRICTED{0x00000002};
#pragma pack(1)
struct homeblks_sb {
    uint64_t magic = hb_sb_magic;
    uint32_t version = hb_sb_version;
    homeblks_sb_flag_t flags;

    uint64_t boot_cnt;

    void init_flag(homeblks_sb_flag_t f) { flags = f; }
    void set_flag(homeblks_sb_flag_t bit) { flags |= bit; }
    void clear_flag(homeblks_sb_flag_t bit) { flags &= ~bit; }
    bool test_flag(homeblks_sb_flag_t bit) { return flags & bit; }
};
#pragma pack()

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
        REGISTER_COUNTER(boot_cnt, "boot cnt", sisl::_publish_as::publish_as_gauge);
        REGISTER_GAUGE(recovery_phase0_latency, "recovery phase0 latency");
        REGISTER_GAUGE(recovery_phase1_latency, "recovery phase1 latency");
        REGISTER_GAUGE(recovery_phase2_latency, "recovery phase2 latency");
        REGISTER_GAUGE(recovery_log_store_latency, "recovery logstore latency");
        REGISTER_GAUGE(recovery_total_latency, "recovery total latency");
        REGISTER_GAUGE(unclean_shutdown, "unclean shutdown");
        register_me_to_farm();
    }
    HomeBlksMetrics(const HomeBlksMetrics&) = delete;
    HomeBlksMetrics(HomeBlksMetrics&&) noexcept = delete;
    HomeBlksMetrics& operator=(const HomeBlksMetrics&) = delete;
    HomeBlksMetrics& operator=(HomeBlksMetrics&&) noexcept = delete;
    void on_gather();

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
        return fmt::format("Recovery Total (ms): {}, Volume Phase-0 (ms): {},  Volume Phase-1 (ms): {}, Log Store "
                           "Recovery (ms): {}, Volume Phase-2 (ms): {}",
                           m_total_ms, m_phase0_ms, m_phase1_ms, m_log_store_ms, m_phase2_ms);
    }
};

class VolumeIOWatchDog;

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
    static void zero_boot_sbs(const std::vector< dev_info >& devices);

    virtual ~HomeBlks() override;
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
    virtual std::error_condition remove_volume(const boost::uuids::uuid& uuid,
                                               const hs_comp_callback& remove_cb = nullptr) override;
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
    virtual uint64_t get_page_size(const VolumePtr& vol) override;
    virtual uint64_t get_size(const VolumePtr& vol) override;
    virtual std::map<boost::uuids::uuid, uint64_t> get_used_size(const VolumePtr& vol) override;
    virtual boost::uuids::uuid get_uuid(VolumePtr vol) override;
    virtual sisl::blob at_offset(const blk_buf_t& buf, uint32_t offset) override;

    virtual bool vol_state_change(const VolumePtr& vol, vol_state new_state) override;

    virtual void attach_vol_completion_cb(const VolumePtr& vol, const io_comp_callback& cb) override;
    virtual void attach_end_of_batch_cb(const end_of_batch_callback& cb) override;

    virtual bool trigger_shutdown(const hs_comp_callback& shutdown_done_cb = nullptr, bool force = false) override;
    virtual cap_attrs get_system_capacity() override {
        return HomeStore< BLKSTORE_BUFFER_TYPE >::get_system_capacity();
    }

    virtual std::error_condition copy_vol(const boost::uuids::uuid& uuid, const std::string& path) override;

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

    virtual void
    register_status_cb(const std::string& module,
                       const std::function< nlohmann::json(const int verbosity_level) > get_status_cb) override;

    virtual void print_tree(const VolumePtr& vol, bool chksum = true) override;
    virtual bool verify_tree(const VolumePtr& vol) override;
    virtual void print_node(const VolumePtr& vol, uint64_t blkid, bool chksum = true) override;
    virtual void set_indx_btree_start_destroying(const boost::uuids::uuid& uuid) override;
    virtual iomgr::drive_type data_drive_type() override;
#if 0
    virtual void zero_pdev_sbs() override { HomeStore< BLKSTORE_BUFFER_TYPE >::zero_pdev_sbs(); }
#endif
public:
    /***************************** APIs exposed to homestore subsystem ***********************/
    uint64_t get_boot_cnt() const {
        auto sb = (homeblks_sb*)m_homeblks_sb_buf->bytes;
        assert(sb->boot_cnt < UINT16_MAX);
        return (uint16_t)sb->boot_cnt;
    }

    bool is_recovery_mode() { return !m_rdy; }
    bool is_shutdown() const { return (m_shutdown_start_time.load(std::memory_order_acquire) != 0); }
    virtual bool is_destroying(const VolumePtr vol) const override;

    void init_done();
    void inc_sub_system_init_cnt();
    virtual void attach_prepare_indx_cp(std::map< boost::uuids::uuid, indx_cp_ptr >* cur_icp_map,
                                        std::map< boost::uuids::uuid, indx_cp_ptr >* new_icp_map, hs_cp* hcp,
                                        hs_cp* new_hcp) override;
    virtual bool inc_hs_ref_cnt(const boost::uuids::uuid& uuid) override;
    virtual bool dec_hs_ref_cnt(const boost::uuids::uuid& uuid) override;
    virtual bool fault_containment(const boost::uuids::uuid& uuid) override;
    void do_volume_shutdown(bool force);
    void create_volume(VolumePtr vol);
    void move_to_restricted_state();

    BlkStore< BlkBuffer >::comp_callback data_completion_cb() override;

    /**
     * @brief
     *
     * @param mblk
     * @param has_more
     */
    void meta_blk_found(meta_blk* mblk, sisl::byte_view buf, size_t size);
    void meta_blk_recovery_comp(bool success);

    [[nodiscard]] bool verify_vols();
    [[nodiscard]] bool verify_data_bm();
    [[nodiscard]] bool verify_index_bm();
    [[nodiscard]] bool verify_bitmap();
    [[nodiscard]] bool verify_metablk_store();

    [[nodiscard]] sisl::status_response get_status(const sisl::status_request& request);

    [[nodiscard]] bool is_safe_mode();

    [[nodiscard]] std::error_condition mark_vol_offline(const boost::uuids::uuid& uuid);
    [[nodiscard]] std::error_condition mark_vol_online(const boost::uuids::uuid& uuid);

    [[nodiscard]] nlohmann::json dump_disk_metablks(const std::string& client);

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
    void wakeup_init();
    bool is_unclean_shutdown() const;
    void reset_unclean_shutdown();

public:
    // Other static functions
    static void meta_blk_found_cb(meta_blk* mblk, sisl::byte_view buf, size_t size);
    static void meta_blk_recovery_comp_cb(bool success);
    sisl::sobject_ptr sobject() { return m_sobject; }

protected:
    void process_vdev_error(vdev_info_block* vb) override;

private:
    HomeBlks(const init_params& cfg);

    // Read volume super block based on blkid
    void homeblks_sb_write();
    homeblks_sb* superblock_init();

    std::error_condition remove_volume_internal(const boost::uuids::uuid& uuid, bool force,
                                                const hs_comp_callback& remove_cb = nullptr);
    void vol_mounted(const VolumePtr& vol, vol_state state);
    void vol_state_change(const VolumePtr& vol, vol_state old_state, vol_state new_state);
    void scan_volumes();

    void init_thread();
    void do_shutdown(const hs_comp_callback& shutdown_done_cb, bool force);
    blk_buf_t get_valid_buf(const std::vector< blk_buf_t >& bbuf, bool& rewrite);

    virtual void call_multi_completions() override;
    void migrate_sb();
    void migrate_homeblk_sb();
    void migrate_volume_sb();
    void migrate_logstore_sb();
    void migrate_cp_sb();
    void vol_recovery_start_phase1();
    void vol_recovery_start_phase2();
    void trigger_cp_init(uint32_t vol_mount_cnt);
    void start_home_log_store();
    void recover_volumes();
    VolumeIOWatchDog* get_vol_io_wd() const { return m_io_wd.get(); };

private:
    init_params m_cfg;
    sisl::byte_array m_homeblks_sb_buf; // the homestore super block
    void* m_sb_cookie = nullptr;

    vol_map_t m_volume_map;
    std::recursive_mutex m_vol_lock;
    std::mutex m_shutdown_lock;

    std::atomic< int > m_sub_system_init_cnt = 0;
    std::atomic< bool > m_init_finished = false;
    std::error_condition m_init_failed = no_error;

    out_params m_out_params;
    std::unique_ptr< HomeBlksHttpServer > m_hb_http_server;

    std::condition_variable m_cv_init_cmplt;  // wait for init to complete
    std::condition_variable m_cv_wakeup_init; // wait for init to complete
    std::mutex m_cv_mtx;
    bool m_rdy = false;

    std::atomic< uint64_t > m_shutdown_start_time = 0;
    iomgr::timer_handle_t m_shutdown_timer_hdl = iomgr::null_timer_handle;
    hs_comp_callback m_shutdown_done_cb;
    bool m_force_shutdown{false};
    bool m_init_error{false};
    bool m_vol_shutdown_cmpltd{false};
    std::unique_ptr< HomeBlksMetrics > m_metrics;
    std::atomic< bool > m_start_shutdown;
    std::atomic< bool > m_unclean_shutdown = false;
    iomgr::io_thread_t m_init_thread_id;

    std::unique_ptr< HomeBlksRecoveryStats > m_recovery_stats{nullptr};

    static bool m_meta_blk_found;

    static thread_local std::vector< std::shared_ptr< Volume > >* s_io_completed_volumes;

    /* hdd custom threads */
    std::unique_ptr< VolumeIOWatchDog > m_io_wd{nullptr};

    sisl::sobject_ptr m_sobject;
};

static inline HomeBlksSafePtr HomeBlksPtr() { return HomeBlks::safe_instance(); }
static inline HomeBlks* HomeBlksRawPtr() { return HomeBlks::instance(); }

} // namespace homestore
#endif // OMSTORE_OMSTORE_HPP
