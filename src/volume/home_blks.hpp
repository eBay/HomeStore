#ifndef VOL_CONFIG_HPP
#define VOL_CONFIG_HPP

#include <main/vol_interface.hpp>
#include <memory>
#include <homeds/btree/btree.hpp>
#include <blkstore/blkstore.hpp>
#include <homeds/btree/ssd_btree.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <async_http/http_server.hpp>
#include <threadpool/thread_pool.h>
#include <utility/atomic_counter.hpp>

#ifndef DEBUG
extern bool same_value_gen;
#endif
namespace homestore {

#define VOL_MAX_IO_SIZE MEMVEC_MAX_IO_SIZE
#define LBA_BITS 56

/* 1 % of disk space is reserved for volume sb chunks. With 8k page it
 * will come out to be around 7 GB.
 */
#define MIN_DISK_CAP_SUPPORTED (MIN_CHUNK_SIZE * 100 / 99 + MIN_CHUNK_SIZE)

class MappingKey;
class MappingValue;

enum blkstore_type : uint32_t {
    DATA_STORE = 1,
    METADATA_STORE = 2,
    SB_STORE = 3,
    LOGDEV_STORE = 4,
};

struct blkstore_blob {
    enum blkstore_type type;
};

struct sb_blkstore_blob : blkstore_blob {
    BlkId blkid;
};

/* Note: below two structures should not be greater then ssd atomic page size. If it is
 * then we need to use double buffer.
 */

#define VOL_SB_SIZE HomeStoreConfig::atomic_phys_page_size
#define VOL_SB_MAGIC 0xCEEDDEEB
/* Note: version is same for both vol config and vol sb */
#define VOL_SB_VERSION 0x1
typedef uint32_t vol_cfg_sb_flag_t;

#define HOMEBLKS_SB_FLAGS_CLEAN_SHUTDOWN 0x00000001UL
struct vol_sb_header {
    uint64_t magic;
    uint64_t version;
    uint32_t gen_cnt;
    BlkId blkid;
    uint64_t boot_cnt;
    boost::uuids::uuid uuid;
} __attribute((packed));

struct vol_config_sb : vol_sb_header {
    BlkId vol_list_head;
    int num_vols;
    vol_cfg_sb_flag_t flags;

    void init_flag(vol_cfg_sb_flag_t f) { flags = f; }
    void set_flag(vol_cfg_sb_flag_t bit) { flags |= bit; }
    void clear_flag(vol_cfg_sb_flag_t bit) { flags &= ~bit; }
    bool test_flag(vol_cfg_sb_flag_t bit) { return flags & bit; }
} __attribute((packed));

// static_assert(std::is_trivially_copyable< vol_config_sb >::value, "Expecting vol_config_sb to be trivally copyable");
static_assert(std::is_trivially_copyable< BlkId >::value, "Expecting BlkId to be trivally copyable");

/* If it exceeds 8k then we need to use two buffer to keep the data consistent */
struct vol_ondisk_sb : vol_sb_header {
    BlkId next_blkid;
    BlkId prev_blkid;

    vol_state state;
    uint64_t page_size;
    uint64_t size;
    char vol_name[VOL_NAME_SIZE];
    homeds::btree::btree_super_block btree_sb;

    vol_state get_state() const { return state; }
    uint64_t get_page_size() const { return page_size; }
    uint64_t get_size() const { return size; }
    const char* get_vol_name() const { return vol_name; }
} __attribute((packed));

struct vol_mem_sb {
    sisl::aligned_unique_ptr< vol_ondisk_sb > ondisk_sb;
    std::mutex m_sb_lock; // lock for updating vol's sb
    void lock() { m_sb_lock.lock(); };
    void unlock() { m_sb_lock.unlock(); };
    vol_mem_sb(size_t align_size, size_t ondisk_size) {
        ondisk_sb = sisl::make_aligned_unique< vol_ondisk_sb >(align_size, ondisk_size);
    }
};

using namespace homeds::btree;

#define SHUTDOWN_TIMEOUT_NUM_SECS 300
#define SHUTDOWN_STATUS_CHECK_FREQUENCY_MS 2000

#define BLKSTORE_BUFFER_TYPE                                                                                           \
    BtreeBuffer< MappingKey, MappingValue, btree_node_type::VAR_VALUE, btree_node_type::VAR_VALUE >
#define MappingBtreeDeclType                                                                                           \
    Btree< btree_store_type::SSD_BTREE, MappingKey, MappingValue, btree_node_type::VAR_VALUE,                          \
           btree_node_type::VAR_VALUE, writeback_req >

class HomeBlks;
using HomeBlksSafePtr = boost::intrusive_ptr< HomeBlks >;

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
class HomeBlks : public VolInterface {
    static HomeBlksSafePtr _instance;

    init_params m_cfg;
    std::thread m_thread_id;
    std::unique_ptr< DeviceManager > m_dev_mgr;
    std::unique_ptr< BlkStore< VdevVarSizeBlkAllocatorPolicy > > m_data_blk_store;
    std::unique_ptr< BlkStore< VdevFixedBlkAllocatorPolicy, BLKSTORE_BUFFER_TYPE > > m_metadata_blk_store;
    std::unique_ptr< BlkStore< VdevVarSizeBlkAllocatorPolicy > > m_sb_blk_store;
    std::unique_ptr< BlkStore< VdevVarSizeBlkAllocatorPolicy > > m_logdev_blk_store;
    sisl::aligned_unique_ptr< vol_config_sb > m_cfg_sb;
    std::unique_ptr< Cache< BlkId > > m_cache;
    bool m_rdy;
    std::map< boost::uuids::uuid, std::shared_ptr< Volume > > m_volume_map;
    std::recursive_mutex m_vol_lock;
    vol_mem_sb* m_last_vol_sb;
    bool m_vdev_failed;
    uint64_t m_size_avail;
    uint32_t m_data_pagesz;
    std::atomic< int > m_scan_cnt;
    std::atomic< bool > m_init_failed;
    out_params m_out_params;
    std::unique_ptr< sisl::HttpServer > m_http_server;
    std::atomic< uint64_t > m_shutdown_start_time;
    std::atomic< bool > m_init_finished;
    std::condition_variable m_cv;
    std::mutex m_cv_mtx;
    sisl::atomic_counter< uint64_t > m_usage_counter = 1;
    bool m_print_checksum;
    iomgr::timer_handle_t m_shutdown_timer_hdl = iomgr::null_timer_handle;

public:
    static std::string version;
    static VolInterface* init(const init_params& cfg, bool force_reinit = false);
    static HomeBlks* instance();
    static HomeBlksSafePtr safe_instance();

    ~HomeBlks() { m_thread_id.join(); }
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

    // Sanity check for sb;
    bool vol_sb_sanity(vol_mem_sb* sb);

    // Read volume super block based on blkid
    vol_mem_sb* vol_sb_read(BlkId bid);

    virtual vol_interface_req_ptr create_vol_hb_req() override;
    virtual std::error_condition write(const VolumePtr& vol, uint64_t lba, uint8_t* buf, uint32_t nblks,
                                       const vol_interface_req_ptr& req) override;
    virtual std::error_condition read(const VolumePtr& vol, uint64_t lba, int nblks,
                                      const vol_interface_req_ptr& req) override;
    virtual std::error_condition sync_read(const VolumePtr& vol, uint64_t lba, int nblks,
                                           const vol_interface_req_ptr& req) override;
    virtual VolumePtr create_volume(const vol_params& params) override;

    virtual std::error_condition remove_volume(const boost::uuids::uuid& uuid) override;
    virtual VolumePtr lookup_volume(const boost::uuids::uuid& uuid) override;
    virtual SnapshotPtr snap_volume(VolumePtr) override;

    virtual const char* get_name(const VolumePtr& vol) override;
    virtual uint64_t get_page_size(const VolumePtr& vol) override;
    virtual boost::uuids::uuid get_uuid(VolumePtr vol) override;
    virtual homeds::blob at_offset(const boost::intrusive_ptr< BlkBuffer >& buf, uint32_t offset) override;
    virtual bool vol_state_change(const VolumePtr& vol, vol_state new_state) override;
    void vol_sb_write(vol_mem_sb* sb);
    void vol_sb_init(vol_mem_sb* sb);
    void config_super_block_init(BlkId& bid);
    void config_super_block_write();
    void vol_scan_cmpltd(const VolumePtr& vol, vol_state state, bool success);
    void populate_disk_attrs();
    virtual void attach_vol_completion_cb(const VolumePtr& vol, io_comp_callback cb) override;

    virtual bool shutdown(bool force = false) override;
    virtual bool trigger_shutdown(const shutdown_comp_callback& shutdown_done_cb = nullptr,
                                  bool force = false) override;
    virtual cap_attrs get_system_capacity() override;
    virtual cap_attrs get_vol_capacity(const VolumePtr& vol) override;

    homestore::BlkStore< homestore::VdevVarSizeBlkAllocatorPolicy >* get_data_blkstore();
    homestore::BlkStore< homestore::VdevFixedBlkAllocatorPolicy, BLKSTORE_BUFFER_TYPE >* get_metadata_blkstore();
    homestore::BlkStore< homestore::VdevVarSizeBlkAllocatorPolicy >* get_logdev_blkstore();
    void vol_sb_remove(vol_mem_sb* sb);
    uint32_t get_data_pagesz() const;
    uint64_t get_boot_cnt();
    void init_done(std::error_condition err, const out_params& params);

    void print_tree(const VolumePtr& vol, bool chksum = true);
    void verify_tree(const VolumePtr& vol);
    void print_node(const VolumePtr& vol, uint64_t blkid, bool chksum = true);

#ifndef NDEBUG
    void verify_pending_blks(const VolumePtr& vol);
#endif
#ifdef _PRERELEASE
    void set_io_flip();
    void set_error_flip();
#endif

    bool print_checksum() { return m_print_checksum; }

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

private:
    HomeBlks(const init_params& cfg);
    BlkId alloc_blk();
    static void new_vdev_found(DeviceManager* dev_mgr, vdev_info_block* vb);
    void process_vdev_error(vdev_info_block* vb);
    void create_blkstores();
    void add_devices();
    void vol_mounted(const VolumePtr& vol, vol_state state);
    void vol_state_change(const VolumePtr& vol, vol_state old_state, vol_state new_state);
    boost::intrusive_ptr< BlkBuffer > get_valid_buf(const std::vector< boost::intrusive_ptr< BlkBuffer > >& bbuf,
                                                    bool& rewrite);
    void construct_vol_config_sb(std::vector< boost::intrusive_ptr< BlkBuffer > >& bbuf, bool& rewrite);
    void scan_volumes();
    void create_data_blkstore(vdev_info_block* vb);
    void create_metadata_blkstore(vdev_info_block* vb);
    void create_sb_blkstore(vdev_info_block* vb);
    void create_logdev_blkstore(vdev_info_block* vb);
    bool is_ready();
    void init_thread();
    bool is_shutdown();
    void verify_vols();
    void schedule_shutdown(const shutdown_comp_callback& shutdown_done_cb, bool force);
    bool do_shutdown(const shutdown_comp_callback& shutdown_done_cb, bool force);
    bool do_volume_shutdown(bool force);
};
} // namespace homestore
#endif // OMSTORE_OMSTORE_HPP
