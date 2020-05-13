#ifndef VOL_CONFIG_HPP
#define VOL_CONFIG_HPP

#include "api/vol_interface.hpp"
#include "engine/homestore.hpp"
#include <memory>
#include "engine/homeds/btree/btree.hpp"
#include "engine/homeds/btree/ssd_btree.hpp"
#include <engine/blkstore/blkstore.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <async_http/http_server.hpp>
#include "engine/homeds/thread/threadpool/thread_pool.h"
#include <utility/atomic_counter.hpp>
#include <metrics/metrics.hpp>
#include <settings/settings.hpp>
#include "homeblks_config.hpp"
#include <homeds/btree/writeBack_cache.hpp>
#include <fds/sparse_vector.hpp>
#include "meta/meta_blks_mgr.hpp"

#ifndef DEBUG
extern bool same_value_gen;
#endif

namespace homestore {

#define VOL_MAX_IO_SIZE MEMVEC_MAX_IO_SIZE
#define LBA_BITS 56

class MappingKey;
class MappingValue;

/* Note: below two structures should not be greater then ssd atomic page size. If it is
 * then we need to use double buffer.
 */

#define HOMEBLKS_SB_SIZE HS_STATIC_CONFIG(disk_attr.atomic_phys_page_size)
#define HOMEBLKS_SB_MAGIC 0xCEEDDEEB
#define HOMEBLKS_SB_VERSION 0x2

typedef uint32_t homeblks_sb_flag_t;

#define HOMEBLKS_SB_FLAGS_CLEAN_SHUTDOWN 0x00000001UL
struct homeblks_sb {
    uint64_t version;
    boost::uuids::uuid uuid;

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
struct indx_cp_id;

typedef std::map< boost::uuids::uuid, std::shared_ptr< homestore::Volume > > vol_map_t;

class HomeBlksMetrics : public sisl::MetricsGroupWrapper {
public:
    explicit HomeBlksMetrics(const char* homeblks_name) : sisl::MetricsGroupWrapper("HomeBlks", homeblks_name) {
        REGISTER_HISTOGRAM(scan_volumes_latency, "Scan Volumes latency");
        register_me_to_farm();
    }
};

#define BLKSTORE_BUFFER_TYPE                                                                                           \
    WriteBackCacheBuffer< MappingKey, MappingValue, btree_node_type::VAR_VALUE, btree_node_type::VAR_VALUE >

/**
 * @brief HomeBlks - Implementor of VolInterface.
 *
 * About HomeBlks life cycle: HomeBlks is a pseudo singleton class wherein it can be accessed as singelton, but using
 * that way is strongly discouraged. Upon the start of the application, the main routine or user of HomeBlks library,
 * need to initialize it by calling HomeBlks::init(). This sets the main homeblks object reference count to 2, one for
 * maintaning singleton status, 1 for the fact it is initialized and not shutdown. Whichever submodule, which needs to
 * access the homeblks should get the reference to the homeblks and store it locally by calling
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

    /**
     * @brief Initialize the HomeBlks. Before init called, none of the other HomeBlks methods can be used.
     *
     * @param cfg : Input Parameters to initialize the homeblks.
     * @param force_reinit Do we need to forcefully reinitialize the homeblks, even if its initialized already
     * @return Pointer to the base VolInterface
     */
    static VolInterface* init(const init_params& cfg, bool force_reinit = false);

    /**
     * @brief Get the instance or safe instance of this object. It is expected the caller to use safe_instance() and
     * retain the reference, to ensure that HomeBlks is the last one to be freed.
     *
     * @return HomeBlks*
     */
    static HomeBlks* instance();
    static HomeBlksSafePtr safe_instance();

    ~HomeBlks() { m_thread_id.join(); }
    virtual std::error_condition write(const VolumePtr& vol, const vol_interface_req_ptr& req,
                                       bool part_of_batch = false) override;
    virtual std::error_condition read(const VolumePtr& vol, const vol_interface_req_ptr& req,
                                      bool part_of_batch = false) override;
    virtual std::error_condition sync_read(const VolumePtr& vol, const vol_interface_req_ptr& req) override;
    virtual void submit_io_batch() override;

    virtual vol_interface_req_ptr create_vol_interface_req(void* buf, uint64_t lba, uint32_t nlbas,
                                                           bool sync = false) override;

    virtual VolumePtr create_volume(const vol_params& params) override;
    virtual std::error_condition remove_volume(const boost::uuids::uuid& uuid) override;
    virtual VolumePtr lookup_volume(const boost::uuids::uuid& uuid) override;
    virtual SnapshotPtr snap_volume(VolumePtr) override;

    virtual const char* get_name(const VolumePtr& vol) override;
    virtual uint64_t get_page_size(const VolumePtr& vol) override;
    virtual uint64_t get_size(const VolumePtr& vol) override;
    virtual boost::uuids::uuid get_uuid(VolumePtr vol) override;
    virtual homeds::blob at_offset(const blk_buf_t& buf, uint32_t offset) override;

    virtual bool vol_state_change(const VolumePtr& vol, vol_state new_state) override;

    void vol_scan_cmpltd(const VolumePtr& vol, vol_state state, bool success);
    virtual void attach_vol_completion_cb(const VolumePtr& vol, const io_comp_callback& cb) override;
    virtual void attach_end_of_batch_cb(const end_of_batch_callback& cb) override;

    virtual bool shutdown(bool force = false) override;
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

public:
    /***************************** APIs exposed to homestore subsystem ***********************/
    uint64_t get_boot_cnt() const {
        assert(m_homeblks_sb->boot_cnt < UINT16_MAX);
        return (uint16_t)m_homeblks_sb->boot_cnt;
    }

    bool is_shutdown() const { return (m_shutdown_start_time.load() != 0); }

    void init_done(std::error_condition err);
    void inc_sub_system_init_cnt();
    void attach_prepare_volume_cp_id(std::map< boost::uuids::uuid, vol_cp_id_ptr >* cur_id_map,
                                     std::map< boost::uuids::uuid, vol_cp_id_ptr >* new_id_map,
                                     indx_cp_id* home_blks_id);
    void persist_blk_allocator_bitmap();
    void do_volume_shutdown(bool force);

    data_blkstore_t::comp_callback data_completion_cb() override;

    /**
     * @brief
     *
     * @param mblk
     * @param has_more
     */
    void meta_blk_cb_internal(meta_blk* mblk, sisl::aligned_unique_ptr<uint8_t> buf, size_t size);
    void meta_blk_recover_comp_cb_internal(bool success);

#ifdef _PRERELEASE
    void set_io_flip();
    void set_error_flip();
#endif

    friend void intrusive_ptr_add_ref(HomeBlks* hb) { hb->m_usage_counter.increment(1); }
    friend void intrusive_ptr_release(HomeBlks* hb) {
        // If there is only one reference remaining after decrementing, then we are done with shutdown, cleanup the
        // _instance and delete the homeblks.
        if (hb->m_usage_counter.decrement_test_eq(1)) {
            auto p = HomeBlks::_instance.detach();
            assert(p == hb);
            delete hb;
        }
    }

public:
    // All http handlers, TODO: Consider moving this to separate class
    static void get_version(sisl::HttpCallData cd);
    static void get_metrics(sisl::HttpCallData cd);
    static void get_obj_life(sisl::HttpCallData cd);
    static void get_prometheus_metrics(sisl::HttpCallData cd);
    static void get_log_level(sisl::HttpCallData cd);
    static void set_log_level(sisl::HttpCallData cd);
    static void dump_stack_trace(sisl::HttpCallData cd);
    static void verify_hs(sisl::HttpCallData cd);
    static void meta_blk_cb(meta_blk* mblk, sisl::aligned_unique_ptr<uint8_t> buf, size_t size);
    static void meta_blk_recover_comp_cb(bool success);
    static void get_malloc_stats(sisl::HttpCallData cd);

protected:
    void process_vdev_error(vdev_info_block* vb) override;

private:
    HomeBlks(const init_params& cfg);

    // Read volume super block based on blkid
    void homeblks_sb_write();
    void superblock_init();

    void vol_mounted(const VolumePtr& vol, vol_state state);
    void vol_state_change(const VolumePtr& vol, vol_state old_state, vol_state new_state);
    void scan_volumes();

    void init_thread();
    void verify_vols();
    void schedule_shutdown(const shutdown_comp_callback& shutdown_done_cb, bool force);
    void do_shutdown(const shutdown_comp_callback& shutdown_done_cb, bool force);
    blk_buf_t get_valid_buf(const std::vector< blk_buf_t >& bbuf, bool& rewrite);

    void call_multi_vol_completions();
    void migrate_sb();
    void migrate_homeblk_sb();
    void migrate_volume_sb();
    void migrate_logstore_sb();
    void migrate_cp_sb();

private:
    static HomeBlksSafePtr _instance;

    init_params m_cfg;
    std::thread m_thread_id;
    sisl::aligned_unique_ptr< homeblks_sb > m_homeblks_sb; // the homestore super block
    void* m_sb_cookie = nullptr;

    vol_map_t m_volume_map;
    std::recursive_mutex m_vol_lock;
    std::mutex m_shutdown_lock;

    std::atomic< int > m_sub_system_init_cnt = 0;
    std::atomic< bool > m_init_finished = false;
    std::error_condition m_init_failed = no_error;

    out_params m_out_params;
    std::unique_ptr< sisl::HttpServer > m_http_server;

    std::condition_variable m_cv;
    std::mutex m_cv_mtx;
    bool m_rdy = false;

    sisl::atomic_counter< uint64_t > m_usage_counter = 1;

    std::atomic< uint64_t > m_shutdown_start_time = 0;
    iomgr::timer_handle_t m_shutdown_timer_hdl = iomgr::null_timer_handle;
    shutdown_comp_callback m_shutdown_done_cb;
    bool m_force_shutdown = false;
    bool m_init_error = false;
    bool m_vol_shutdown_cmpltd = false;
    HomeBlksMetrics m_metrics;
    std::atomic< bool > m_start_shutdown;

    static thread_local std::vector< std::shared_ptr< Volume > >* s_io_completed_volumes;
};

} // namespace homestore
#endif // OMSTORE_OMSTORE_HPP
