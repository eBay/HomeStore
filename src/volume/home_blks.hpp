#ifndef VOL_CONFIG_HPP
#define VOL_CONFIG_HPP

#include <main/vol_interface.hpp>
#include <memory>
#include <homeds/btree/btree.hpp>
#include <blkstore/blkstore.hpp>
#include <homeds/btree/ssd_btree.hpp>

namespace homestore {

#define VOL_MAX_IO_SIZE MEMVEC_MAX_IO_SIZE

class MappingKey;
class MappingValue;

enum blkstore_type {
    DATA_STORE = 1,
    METADATA_STORE = 2,
    SB_STORE = 3
};

struct blkstore_blob {
    enum blkstore_type type;
};

struct sb_blkstore_blob:blkstore_blob {
   BlkId blkid; 
};

/* Note: below two structures should not be greater then ssd atomic page size. If it is
 * then we need to use double buffer.
 */

#define VOL_SB_SIZE  HomeStoreConfig::atomic_phys_page_size
struct vol_sb_header {
    uint32_t gen_cnt;
    BlkId blkid;
}__attribute((packed));

struct vol_config_sb : vol_sb_header {
    BlkId vol_list_head;
    int num_vols;
}__attribute((packed));

/* If it exceeds 8k then we need to use two buffer to keep the data consistent */
struct vol_sb : vol_sb_header {
    BlkId next_blkid;
    BlkId prev_blkid;

    vol_state state;
    uint64_t page_size;
    uint64_t size;
    boost::uuids::uuid uuid;
    char vol_name[VOL_NAME_SIZE];
    homeds::btree::btree_super_block btree_sb;
}__attribute((packed));

#define BLKSTORE_BUFFER_TYPE homeds::btree::BtreeBuffer<MappingKey, MappingValue,homeds::btree::BTREE_NODETYPE_VAR_VALUE, \
                                                  homeds::btree::BTREE_NODETYPE_VAR_VALUE, 8192>
#define MappingBtreeDeclType     homeds::btree::Btree<homeds::btree::SSD_BTREE, MappingKey, MappingValue, \
                                    homeds::btree::BTREE_NODETYPE_VAR_VALUE, homeds::btree::BTREE_NODETYPE_VAR_VALUE,\
                                    8192, writeback_req>
class HomeBlks:VolInterface {
    static HomeBlks *_instance;
    
    init_params m_cfg;
    std::thread m_thread_id;
    homestore::DeviceManager *m_dev_mgr;
    homestore::BlkStore<homestore::VdevVarSizeBlkAllocatorPolicy> *m_data_blk_store;
    homestore::BlkStore<homestore::VdevFixedBlkAllocatorPolicy, BLKSTORE_BUFFER_TYPE> *m_metadata_blk_store;
    homestore::BlkStore<homestore::VdevVarSizeBlkAllocatorPolicy> *m_sb_blk_store;
    vol_config_sb *m_cfg_sb;
    Cache<BlkId> *m_cache;
    bool m_rdy;
    std::map<boost::uuids::uuid, std::shared_ptr<homestore::Volume>> m_volume_map;
    std::mutex m_vol_lock;
    vol_sb *m_last_vol_sb;
    bool m_vdev_failed;
    uint64_t m_size_avail;
    std::atomic<int> m_scan_cnt;
    std::atomic<bool> m_init_failed;
    out_params  m_out_params;

public:
    static VolInterface *init(init_params &cfg);
    HomeBlks(init_params &cfg);
    virtual std::error_condition write(std::shared_ptr<Volume> vol, uint64_t lba, uint8_t *buf, 
                               uint32_t nblks, boost::intrusive_ptr<volume_req> req) override;
    virtual std::error_condition read(std::shared_ptr<Volume> vol, uint64_t lba, int nblks, boost::intrusive_ptr<volume_req> req) override;
    virtual std::shared_ptr<Volume> createVolume(vol_params &params) override;
    virtual std::error_condition removeVolume(boost::uuids::uuid const &uuid) override;
    virtual std::shared_ptr<Volume> lookupVolume(boost::uuids::uuid const &uuid) override;
    static HomeBlks *instance();
    void vol_sb_write(vol_sb *sb);
    void vol_sb_write(vol_sb *sb, bool lock);
    void vol_sb_init(vol_sb *sb);
    void config_super_block_init(BlkId &bid);
    void config_super_block_write(bool lock);
    void vol_scan_cmpltd(std::shared_ptr<Volume> vol, vol_state state);
    virtual void attach_vol_completion_cb(std::shared_ptr<Volume> vol, io_comp_callback &cb) override;
    homestore::BlkStore<homestore::VdevVarSizeBlkAllocatorPolicy> * get_data_blkstore();
    homestore::BlkStore<homestore::VdevFixedBlkAllocatorPolicy, BLKSTORE_BUFFER_TYPE> * get_metadata_blkstore();
    void vol_sb_remove(vol_sb *sb);
private:
    BlkId alloc_blk();
    static void new_vdev_found(DeviceManager *dev_mgr, vdev_info_block *vb);
    void create_blkstores();
    void add_devices();
    void vol_mounted(std::shared_ptr<Volume> vol, vol_state state);
    void vol_state_change(std::shared_ptr<Volume> vol, vol_state old_state, vol_state new_state);
    boost::intrusive_ptr<BlkBuffer> get_valid_buf(std::vector<boost::intrusive_ptr<BlkBuffer>> bbuf, bool &rewrite);
    void construct_vol_config_sb(std::vector<boost::intrusive_ptr<BlkBuffer>> bbuf, bool &rewrite);
    void scan_volumes();
    void create_data_blkstore(vdev_info_block *vb);
    void create_metadata_blkstore(vdev_info_block *vb);
    void create_sb_blkstore(vdev_info_block *vb);
    bool is_ready();
    void init_thread();
};
}
#endif //OMSTORE_OMSTORE_HPP
