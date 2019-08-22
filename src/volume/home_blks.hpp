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

namespace homestore {

#define VOL_MAX_IO_SIZE MEMVEC_MAX_IO_SIZE
#define LBA_BITS 56

/* 1 % of disk space is reserved for volume sb chunks. With 8k page it
 * will come out to be around 7 GB.
 */
#define MIN_DISK_CAP_SUPPORTED (MIN_CHUNK_SIZE * 100 / 99 + MIN_CHUNK_SIZE)

class MappingKey;
class MappingValue;

enum blkstore_type {
    DATA_STORE = 1,
    METADATA_STORE = 2,
    SB_STORE = 3,
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
#define VOL_SB_VERSION    0x1
typedef uint32_t vol_cfg_sb_flag_t;

#define HOMEBLKS_SB_FLAGS_CLEAN_SHUTDOWN 0x00000001UL
struct vol_sb_header {
    uint64_t magic;
    uint64_t version;
    uint32_t gen_cnt;
    BlkId    blkid;
    uint64_t boot_cnt;
} __attribute((packed));

struct vol_config_sb : vol_sb_header {
    BlkId               vol_list_head;
    int                 num_vols;
    vol_cfg_sb_flag_t   flags;

    void     init_flag(vol_cfg_sb_flag_t f) { flags = f; }
    void     set_flag(vol_cfg_sb_flag_t bit) { flags |= bit; }
    void     clear_flag(vol_cfg_sb_flag_t bit) { flags &= ~bit; }
    bool     test_flag(vol_cfg_sb_flag_t bit) { return flags & bit; }
} __attribute((packed));

//static_assert(std::is_trivially_copyable< vol_config_sb >::value, "Expecting vol_config_sb to be trivally copyable");
static_assert(std::is_trivially_copyable< BlkId >::value, "Expecting BlkId to be trivally copyable");

/* If it exceeds 8k then we need to use two buffer to keep the data consistent */
struct vol_ondisk_sb : vol_sb_header {
    BlkId next_blkid;
    BlkId prev_blkid;

    vol_state                        state;
    uint64_t                         page_size;
    uint64_t                         size;
    boost::uuids::uuid               uuid;
    char                             vol_name[VOL_NAME_SIZE];
    homeds::btree::btree_super_block btree_sb;

    uint64_t get_page_size() const { return page_size; }
} __attribute((packed));

struct vol_mem_sb {
    vol_ondisk_sb *ondisk_sb;
    std::mutex  m_sb_lock; // lock for updating vol's sb
    void lock() { m_sb_lock.lock();};
    void unlock() {m_sb_lock.unlock();};
    ~vol_mem_sb() {free(ondisk_sb);}
};

using namespace homeds::btree;
#define HOMEBLKS_SHUTDOWN (HomeBlks::instance()->is_shutdown())

#define SHUTDOWN_TIMEOUT_NUM_SECS              300

#define BLKSTORE_BUFFER_TYPE                                                                                           \
    BtreeBuffer< MappingKey, MappingValue, btree_node_type::VAR_VALUE,                     \
                                btree_node_type::VAR_VALUE, 4096>
#define MappingBtreeDeclType                                                                                           \
    Btree< btree_store_type::SSD_BTREE, MappingKey, MappingValue, btree_node_type::VAR_VALUE, \
                          btree_node_type::VAR_VALUE, 4096, writeback_req >
class HomeBlks : public VolInterface {
    static HomeBlks* _instance;

    init_params                                                                          m_cfg;
    std::thread                                                                          m_thread_id;
    homestore::DeviceManager*                                                            m_dev_mgr;
    homestore::BlkStore< homestore::VdevVarSizeBlkAllocatorPolicy >*                     m_data_blk_store;
    homestore::BlkStore< homestore::VdevFixedBlkAllocatorPolicy, BLKSTORE_BUFFER_TYPE >* m_metadata_blk_store;
    homestore::BlkStore< homestore::VdevVarSizeBlkAllocatorPolicy >*                     m_sb_blk_store;
    vol_config_sb*                                                                       m_cfg_sb;
    Cache< BlkId >*                                                                      m_cache;
    bool                                                                                 m_rdy;
    std::map< boost::uuids::uuid, std::shared_ptr< homestore::Volume > >                 m_volume_map;
    std::recursive_mutex                                                                 m_vol_lock;
    vol_mem_sb*                                                                          m_last_vol_sb;
    bool                                                                                 m_vdev_failed;
    uint64_t                                                                             m_size_avail;
    uint32_t                                                                             m_data_pagesz;
    std::atomic< int >                                                                   m_scan_cnt;
    std::atomic< bool >                                                                  m_init_failed;
    out_params                                                                           m_out_params;
    std::unique_ptr< sisl::HttpServer >                                                  m_http_server;
    std::atomic< bool >                                                                  m_shutdown;
    std::atomic< bool >                                                                  m_init_finished;
    std::condition_variable                                                              m_cv;
    std::mutex                                                                           m_cv_mtx;
    bool                                                                                 m_print_checksum;

public:
    static VolInterface* init(const init_params& cfg);
    static std::string   version;
    static HomeBlks*     instance();
    // Sanity check for sb;
    bool vol_sb_sanity(vol_mem_sb* sb);
    
    // Read volume super block based on blkid
    vol_mem_sb* vol_sb_read(BlkId bid);

    HomeBlks(const init_params& cfg);
    ~HomeBlks() {  
        m_thread_id.join();
    }
    virtual std::error_condition write(const VolumePtr& vol, uint64_t lba, uint8_t* buf, uint32_t nblks,
                                       const vol_interface_req_ptr& req) override;
    virtual std::error_condition read(const VolumePtr& vol, uint64_t lba, int nblks,
                                      const vol_interface_req_ptr& req) override;
    virtual std::error_condition sync_read(const VolumePtr& vol, uint64_t lba, int nblks,
                                           const vol_interface_req_ptr& req) override;
    virtual VolumePtr            create_volume(const vol_params& params) override;

    virtual std::error_condition remove_volume(const boost::uuids::uuid& uuid) override;
    virtual VolumePtr            lookup_volume(const boost::uuids::uuid& uuid) override;
    virtual const char*          get_name(const VolumePtr& vol) override;
    virtual uint64_t             get_page_size(const VolumePtr& vol) override;
    virtual boost::uuids::uuid   get_uuid(VolumePtr vol) override;
    virtual homeds::blob         at_offset(const boost::intrusive_ptr< BlkBuffer >& buf, uint32_t offset) override;
    virtual bool vol_state_change(const VolumePtr& vol, vol_state new_state) override;
    void                         vol_sb_write(vol_mem_sb* sb);
    void                         vol_sb_init(vol_mem_sb* sb);
    void                         config_super_block_init(BlkId& bid);
    void                         config_super_block_write();
    void                         vol_scan_cmpltd(const VolumePtr& vol, vol_state state, bool success);
    void                         populate_disk_attrs();
    virtual void                 attach_vol_completion_cb(const VolumePtr& vol, io_comp_callback cb) override;

    virtual std::error_condition shutdown(shutdown_comp_callback shutdown_comp_cb, bool force = false) override;
    virtual cap_attrs get_system_capacity() override;
    virtual cap_attrs get_vol_capacity(const VolumePtr& vol) override;

    homestore::BlkStore< homestore::VdevVarSizeBlkAllocatorPolicy >*                     get_data_blkstore();
    homestore::BlkStore< homestore::VdevFixedBlkAllocatorPolicy, BLKSTORE_BUFFER_TYPE >* get_metadata_blkstore();
    void                                                                                 vol_sb_remove(vol_mem_sb* sb);
    uint32_t                                                                             get_data_pagesz() const;
    uint64_t get_boot_cnt();
    void init_done(std::error_condition err, const out_params& params);

    void print_tree(const VolumePtr& vol, bool chksum = true);
    void print_node(const VolumePtr& vol, uint64_t blkid, bool chksum = true);

#ifndef NDEBUG
    void verify_pending_blks(const VolumePtr& vol);
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

private:
    BlkId                             alloc_blk();
    static void                       new_vdev_found(DeviceManager* dev_mgr, vdev_info_block* vb);
    void                              process_vdev_error(vdev_info_block* vb);
    void                              create_blkstores();
    void                              add_devices();
    void                              vol_mounted(const VolumePtr& vol, vol_state state);
    void                              vol_state_change(const VolumePtr& vol, vol_state old_state, vol_state new_state);
    boost::intrusive_ptr< BlkBuffer > get_valid_buf(const std::vector< boost::intrusive_ptr< BlkBuffer > >& bbuf,
                                                    bool&                                                   rewrite);
    void construct_vol_config_sb(std::vector< boost::intrusive_ptr< BlkBuffer > >& bbuf, bool& rewrite);
    void scan_volumes();
    void create_data_blkstore(vdev_info_block* vb);
    void create_metadata_blkstore(vdev_info_block* vb);
    void create_sb_blkstore(vdev_info_block* vb);
    bool is_ready();
    void init_thread();
    void volume_destroy();
    bool is_shutdown();
    void shutdown_process(shutdown_comp_callback shutdown_comp_cb, bool force);

};
} // namespace homestore
#endif // OMSTORE_OMSTORE_HPP
