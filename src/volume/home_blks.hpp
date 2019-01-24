#ifndef VOL_CONFIG_HPP
#define VOL_CONFIG_HPP

#include <main/vol_interface.hpp>
#include <memory>
#include <homeds/btree/btree.hpp>
#include <blkstore/blkstore.hpp>
#include <homeds/btree/ssd_btree.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
//#include <async_http/http_server.hpp>

namespace homestore {

#define VOL_MAX_IO_SIZE MEMVEC_MAX_IO_SIZE

/* 1 % of disk space is reserved for volume sb chunks. With 8k page it
 * will come out to be around 7 GB.
 */
#define MIN_DISK_CAP_SUPPORTED (MIN_CHUNK_SIZE * 100 / 99 + MIN_CHUNK_SIZE)

class MappingKey;
class MappingValue;

enum blkstore_type { DATA_STORE = 1, METADATA_STORE = 2, SB_STORE = 3, };

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
struct vol_sb_header {
    uint64_t magic;
    uint64_t version;
    uint32_t gen_cnt;
    BlkId    blkid;
} __attribute((packed));

struct vol_config_sb : vol_sb_header {
    BlkId vol_list_head;
    int   num_vols;
} __attribute((packed));

/* If it exceeds 8k then we need to use two buffer to keep the data consistent */
struct vol_sb : vol_sb_header {
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

#define BLKSTORE_BUFFER_TYPE                                                                                           \
    homeds::btree::BtreeBuffer< MappingKey, MappingValue, homeds::btree::BTREE_NODETYPE_VAR_VALUE,                     \
                                homeds::btree::BTREE_NODETYPE_VAR_VALUE, 8192 >
#define MappingBtreeDeclType                                                                                           \
    homeds::btree::Btree< homeds::btree::SSD_BTREE, MappingKey, MappingValue, homeds::btree::BTREE_NODETYPE_VAR_VALUE, \
                          homeds::btree::BTREE_NODETYPE_VAR_VALUE, 8192, writeback_req >
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
    std::mutex                                                                           m_vol_lock;
    vol_sb*                                                                              m_last_vol_sb;
    bool                                                                                 m_vdev_failed;
    uint64_t                                                                             m_size_avail;
    uint32_t                                                                             m_data_pagesz;
    std::atomic< int >                                                                   m_scan_cnt;
    std::atomic< bool >                                                                  m_init_failed;
    out_params                                                                           m_out_params;

public:
    static VolInterface* init(const init_params& cfg);
    static HomeBlks*     instance();

    HomeBlks(const init_params& cfg);
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
    virtual uint64_t             get_size(const VolumePtr& vol) override;
    virtual homeds::blob         at_offset(const boost::intrusive_ptr< BlkBuffer >& buf, uint32_t offset) override;
    void                         vol_sb_write(vol_sb* sb);
    void                         vol_sb_write(vol_sb* sb, bool lock);
    void                         vol_sb_init(vol_sb* sb);
    void                         config_super_block_init(BlkId& bid);
    void                         config_super_block_write(bool lock);
    void                         vol_scan_cmpltd(const VolumePtr& vol, vol_state state);
    virtual void attach_vol_completion_cb(const VolumePtr& vol, io_comp_callback cb) override;

    homestore::BlkStore< homestore::VdevVarSizeBlkAllocatorPolicy >*                     get_data_blkstore();
    homestore::BlkStore< homestore::VdevFixedBlkAllocatorPolicy, BLKSTORE_BUFFER_TYPE >* get_metadata_blkstore();
    void                                                                                 vol_sb_remove(vol_sb* sb);
    uint32_t                                                                             get_data_pagesz() const;

#ifndef NDEBUG
    void print_tree(const VolumePtr& vol);
#endif

private:
    BlkId       alloc_blk();
    static void new_vdev_found(DeviceManager* dev_mgr, vdev_info_block* vb);
    void        create_blkstores();
    void        add_devices();
    void        vol_mounted(const VolumePtr& vol, vol_state state);
    void        vol_state_change(const VolumePtr& vol, vol_state old_state, vol_state new_state);
    boost::intrusive_ptr< BlkBuffer > get_valid_buf(const std::vector< boost::intrusive_ptr< BlkBuffer > >& bbuf,
                                                    bool&                                                   rewrite);
    void construct_vol_config_sb(std::vector< boost::intrusive_ptr< BlkBuffer > >& bbuf, bool& rewrite);
    void scan_volumes();
    void create_data_blkstore(vdev_info_block* vb);
    void create_metadata_blkstore(vdev_info_block* vb);
    void create_sb_blkstore(vdev_info_block* vb);
    bool is_ready();
    void init_thread();
};
} // namespace homestore
#endif // OMSTORE_OMSTORE_HPP
