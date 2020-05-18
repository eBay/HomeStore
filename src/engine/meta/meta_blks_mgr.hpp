#pragma once

#include "meta_sb.hpp"

namespace homestore {

struct sb_blkstore_blob;
class BlkBuffer;
template < typename BAllocator, typename Buffer >
class BlkStore;
class VdevVarSizeBlkAllocatorPolicy;

typedef homestore::BlkStore< homestore::VdevVarSizeBlkAllocatorPolicy, BlkBuffer > blk_store_type;

// each subsystem could receive callbacks multiple times;
typedef std::function< void(meta_blk* mblk, sisl::aligned_unique_ptr< uint8_t > buf, size_t size) >
    meta_blk_found_cb;                                                            // new blk found subsystem callback
typedef std::function< void(bool success) > meta_blk_recover_comp_cb;             // recover complete subsystem callback
typedef std::map< meta_sub_type, std::map< uint64_t, meta_blk* > > meta_blks_map; // blkid to meta_blk map;

class MetaBlkMgr {
private:
    static MetaBlkMgr* _instance;
    blk_store_type* m_sb_blk_store = nullptr;                          // super blockstore
    std::mutex m_meta_mtx;                                             // mutex to access to meta_map;
    meta_blks_map m_meta_blks;                                         // used by subsystems meta rec
    std::map< meta_sub_type, meta_blk_found_cb > m_cb_map;             // map of callbacks
    std::map< meta_sub_type, meta_blk_recover_comp_cb > m_comp_cb_map; // map of callbacks
    meta_blk* m_last_mblk = nullptr;                                   // last meta blk;
    meta_blk_sb* m_ssb = nullptr;                                      // meta super super blk;

public:
    /**
     * @brief :
     *
     * @param sb_blk_store : superblock store
     * @param blob : super block store vb context data blob
     * @param init : true of initialized, false if recovery
     * @return
     */
    void init(blk_store_type* sb_blk_store, sb_blkstore_blob* blob, bool is_init);

    /**
     * @brief
     *
     * @return
     */
    static MetaBlkMgr* instance() {
        static std::once_flag flag1;
        std::call_once(flag1, []() { _instance = new MetaBlkMgr(); });

        return _instance;
    }

    MetaBlkMgr(){};

    static void del_instance() { delete _instance; }

    /**
     * @brief :
     */
    ~MetaBlkMgr();

    /**
     * @brief : Register subsystem callbacks
     * @param type : subsystem type
     * @param cb : subsystem cb
     */
    void register_handler(meta_sub_type type, meta_blk_found_cb cb, meta_blk_recover_comp_cb comp_cb);

    /**
     * @brief
     *
     * @param type
     */
    void deregister_handler(meta_sub_type type);

    /**
     * @brief : add subsystem superblock to meta blk mgr
     *
     * @param type : subsystem type
     * @param context_data : subsystem sb
     * @param sz : size of context_data
     * @param cookie : returned handle by meta blk mgr.
     *                 Subsystem is supposed to use this cookie to do update and remove of the sb;
     *
     */
    void add_sub_sb(meta_sub_type type, void* context_data, uint64_t sz, void*& cookie);

    /**
     * @brief : remove subsystem sb based on cookie
     *
     * @param cookie : handle address unique subsystem sb that is being removed;
     *
     * @return : ok on success, not-ok on failure;
     */
    std::error_condition remove_sub_sb(void* cookie);

    /**
     * @brief : update metablk in-place
     *
     * @param type : type of subsytem
     * @param context_data : subsytem sb;
     * @param sz : size of context_data
     * @param cookie : handle to address the unique subsytem sb that is being updated;
     */
    void update_sub_sb(meta_sub_type type, void* context_data, uint64_t sz, void*& cookie);

    /**
     * @brief :
     *
     * @return
     */
    bool migrated();

    void set_migrated();

    /**
     * @brief : Callback to each subsytem for each meta rec based on priority
     *
     * @return :
     */
    void recover(bool do_comp_cb = true);

private:
    /**
     * @brief
     *
     * @param buf
     * @param size
     * @param mblks
     *
     * @return
     */
    void extract_meta_blks(uint8_t* buf, const uint64_t size, std::vector< meta_blk* >& mblks);

    /**
     * @brief : write context_data to blk id;
     *
     * @param bid
     * @param context_data
     * @param sz
     */
    void write_blk(BlkId bid, void* context_data, uint32_t sz);

    /**
     * @brief
     *
     * @param type
     *
     * @return
     */
    bool is_meta_blk_type_valid(meta_sub_type type);

    /**
     * @brief
     *
     * @param total_mblks_cnt
     *
     * @return
     */
    bool sanity_check(const uint64_t total_mblks_cnt);

    /**
     * @brief : write in-memory copy of meta_blk to disk;
     *
     * @param mblk
     *
     * @return
     */
    void write_meta_blk(meta_blk* mblk);

    /**
     * @brief : load meta blk super super block into memory
     *
     * @param bid : the blk id that belongs to meta ssb;
     */
    void load_ssb(sb_blkstore_blob* blob);

    /**
     * @brief : scan the blkstore to load meta blks into memory
     */
    void scan_meta_blks();

    /**
     * @brief : init super super block
     *
     * @return
     */
    void init_ssb();

    /**
     * @brief : Write MetaBlkMgr's superblock to disk;
     */
    void write_ssb();

    /**
     * @brief : Allocate meta BlkId
     *
     * @return : BlkId that is allcoated;
     */
    std::error_condition alloc_meta_blk(BlkId& bid, uint32_t alloc_sz = META_BLK_PAGE_SZ);

    void free_meta_blk(meta_blk* mblk);

    /**
     * @brief : Initialize meta blk
     *
     * @param bid
     *
     * @return
     */
    meta_blk* init_meta_blk(BlkId bid, meta_sub_type type, void* context_data, size_t sz);

    /**
     * @brief : internal implementation of populating and writing a meta block;
     *
     * @param mblk
     * @param context_data
     * @param sz
     */
    void write_meta_blk_internal(meta_blk* mblk, void* context_data, uint64_t sz);
};

class register_subsystem {
public:
    register_subsystem(meta_sub_type type, meta_blk_found_cb cb, meta_blk_recover_comp_cb comp_cb) {
        MetaBlkMgr::instance()->register_handler(type, cb, comp_cb);
    }
};

/* It provides alternate way to module to register itself to metablk at the very beginning of a program */
#define REGISTER_METABLK_SUBSYSTEM(name, type, cb, comp_cb) homestore::register_subsystem name##sub(type, cb, comp_cb);
} // namespace homestore
