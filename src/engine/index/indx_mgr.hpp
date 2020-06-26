#pragma once
#include <cassert>
#include "engine/checkpoint/checkpoint.hpp"
#include "homelogstore/log_store.hpp"
#include <wisr/wisr_ds.hpp>
#include "engine/meta/meta_blks_mgr.hpp"
#include <engine/homestore_base.hpp>
#include <engine/homeds/btree/btree.hpp>

namespace homestore {

struct indx_req;
class indx_tbl;
class IndxMgr;
class indx_mgr;
typedef std::function< void(indx_cp_id_ptr cur_indx_id, hs_cp_id* hb_id, hs_cp_id* new_hb_id) > prepare_cb;
#define indx_mgr_ptr std::shared_ptr< IndxMgr >

/* Journal entry
 * ------------------------------------------------------------------
 * | Journal Hdr | alloc_blkid list | free_blk_entry | key | value |
 * ------------------------------------------------------------------
 */
struct journal_hdr {
    uint32_t alloc_blkid_list_size; // numer of entries
    uint32_t free_blk_entry_size;   // number of entries
    uint32_t key_size;              // actual size in bytes
    uint32_t val_size;              // actual size in bytes
    int64_t cp_cnt;
};

class indx_journal_entry {
private:
    sisl::alignable_blob m_iob;

public:
    uint32_t size(indx_req* ireq) const;
    uint32_t size() const;
    ~indx_journal_entry();

    static journal_hdr* get_journal_hdr(void* m_mem) { return ((journal_hdr*)m_mem); }

    static std::pair< BlkId*, uint32_t > get_alloc_bid_list(void* m_mem) {
        auto hdr = get_journal_hdr(m_mem);
        auto ab_list = (BlkId*)(sizeof(journal_hdr) + (uint64_t)m_mem);
        return (std::make_pair(ab_list, hdr->alloc_blkid_list_size));
    }

    static std::pair< BlkId*, uint32_t > get_free_bid_list(void* m_mem) {
        auto hdr = get_journal_hdr(m_mem);
        auto ab_list = get_alloc_bid_list(m_mem);
        BlkId* fb_list = (BlkId*)(&(ab_list.first[ab_list.second]));
        return (std::make_pair(fb_list, hdr->free_blk_entry_size));
    }

    static std::pair< uint8_t*, uint32_t > get_key(void* m_mem) {
        auto hdr = get_journal_hdr(m_mem);
        auto cp_list = get_free_bid_list(m_mem);
        uint8_t* key = (uint8_t*)(&(cp_list.first[cp_list.second]));
        return (std::make_pair(key, hdr->key_size));
    }

    static std::pair< uint8_t*, uint32_t > get_val(void* m_mem) {
        auto hdr = get_journal_hdr(m_mem);
        auto key = get_key(m_mem);
        uint8_t* val = (uint8_t*)((uint64_t)key.first + key.second);
        return (std::make_pair(val, hdr->val_size));
    }

    /* it update the alloc blk id and checksum */
    sisl::blob create_journal_entry(indx_req* v_req);

    std::string to_string() const { return fmt::format("size= {}", size()); }
};

enum indx_mgr_state { ONLINE = 0, DESTROYING = 1 };
struct destroy_journal_ent {
    indx_mgr_state state;
};

typedef cp_done_cb indxmgr_stop_cb;

/* Checkpoint is loosely defined demarcation of how much data is persisted. It might contain data after this checkpoint
 * also but it defintely contains data upto demarcation line. So IOs in each checkpoint(blkalloc checkpoint,
 * active checkpoint and diff checkpoint) should be idempotent.
 *
 * These are the different classes of checkpoints we have
 *      - Homestore CP :- it is a system CP
 *              - indx CP :- It is a CP for each indx mgr. If it is suspended then all its sub system CPs are suspended.
 *                   - Active CP
 *                   - Diff CP
 *                   - Snap delete/create CP
 *              - Blk Alloc CP  :- It is used to persist the bitmap
 * Homestore CP is scheduled periodically or when externally triggered. It calls prepare flush before doing actual
 * flush. During prepare flush a individual CP can decide if it want to participate in a homestore CP flush.
 *
 * Flow of freeing a blkid
 *      - free blkid is a async process. free blkid is inserted in read blk tracker while it is being read from btree in
 *        match_cb_put_param. CP ref cnt is incremented as we don't allow cp to be taken before blkids are not freed.
 *              - Purpose of read blk tracker is to prevent freeing of Blkids it is being read in other IOs.
 *      - When all the reads are completed then decrement the ref cnt in cp.
 *      - cache is invalidated.
 *      - It is inserted into cpid free list when journal write is completed.
 *      - When blk alloc checkpoint is taken, these free blkid list is purged.
 *      - For further steps check blk alloc base class.
 * Flow of allocating a blkid
 *      - blk id is allocated by consumer. At this point it is set only in cache bitmap.
 *      - entry is updated in a journal with a list of allocated blkid
 *      - blk id is marked allocated in disk bitmap so that it can be persisted. If writing to a journal or indx tbl is
 *        failed then these blk ids will be available to reallocate in next boot.
 * Note :- In a checkpoint it can contain data at least upto the PSN or more. It holds true for all checkpoints/data
 * except free blkid. In disk bm it contain exactly those blkids which are freed upto that checkpoint but it might
 * contain blks which are allocated after this checkpoint.
 */
struct indx_cp_id;
ENUM(cp_state, uint8_t,
     active_cp,  // Active CP
     suspend_cp, // cp is suspended
     destroy_cp  // it is a destroy cp. It is moved to active only in blkalloc checkpoint
);

struct hs_cp_id : cp_id_base {
    /* This list is not lock protected. */
    std::map< boost::uuids::uuid, indx_cp_id_ptr > indx_id_list;
    std::shared_ptr< blkalloc_cp_id > blkalloc_id;

    std::atomic< uint64_t > ref_cnt; // cnt of how many cps are triggered
    uint64_t snt_cnt;
    bool blkalloc_checkpoint = false; // it is set to true in prepare flush stage
};

struct indx_active_info {
    int64_t start_psn = -1; // not inclusive
    int64_t end_psn = -1;   // inclusive
    btree_cp_id_ptr btree_id;
    blkid_list_ptr free_blkid_list;
    indx_active_info(int64_t start_psn, blkid_list_ptr& free_blkid_list) :
            start_psn(start_psn),
            free_blkid_list(free_blkid_list) {}
};

struct indx_diff_info {
    int64_t start_psn = -1; // not inclusive
    int64_t end_psn = -1;   // inclusive
    btree_cp_id_ptr btree_id;
};

struct indx_snap_info {
    std::vector< btree_cp_superblock > snap_delete_list;
    blkid_list_ptr free_blkid_list;
};

/* During prepare flush we decide to take a CP out of active, diff or snap or all 3 cps*/
struct indx_cp_id {
    indx_mgr_ptr indx_mgr;
    cp_state flags = cp_state::active_cp;

    /* metrics */
    int64_t cp_cnt;
    std::atomic< int64_t > indx_size;

    /* cp */
    indx_active_info ainfo;
    indx_diff_info dinfo;
    indx_snap_info sinfo;

    indx_cp_id(int64_t cp_cnt, int64_t start_active_psn, indx_mgr_ptr indx_mgr, blkid_list_ptr& free_blkid_list) :
            indx_mgr(indx_mgr),
            cp_cnt(cp_cnt),
            indx_size(0),
            ainfo(start_active_psn, free_blkid_list) {}

    cp_state state() const { return flags; }
};

/* super block persisted for each CP */
/* it contains the PSN from which journal has to be replayed. */
#define INDX_MGR_VERSION 0x101
struct hs_cp_sb_hdr {
    int version;
    uint32_t indx_cnt;
} __attribute__((__packed__));

struct indx_cp_info {
    int64_t blkalloc_cp_cnt = -1; // cp cnt of last blkalloc checkpoint taken
    int64_t cp_cnt = -1;
    int64_t active_data_psn = -1;
    int64_t diff_data_psn = -1;
    int64_t indx_size = 0;
} __attribute__((__packed__));

struct indx_cp_sb {
    boost::uuids::uuid uuid;
    indx_cp_info cp_info;
    btree_cp_superblock active_btree_info;
    indx_cp_sb(boost::uuids::uuid uuid) : uuid(uuid){};
    indx_cp_sb(){};
} __attribute__((__packed__));

/* this superblock is never changed once indx manager is created */
struct indx_mgr_static_sb {
    logstore_id_t journal_id;
    btree_super_block btree_sb;
} __attribute__((__packed__));

class HomeStoreCP : public CheckPoint< hs_cp_id > {
public:
    HomeStoreCP();
    void try_cp_trigger(hs_cp_id* id);
    virtual void cp_start(hs_cp_id* id);
    virtual void cp_attach_prepare(hs_cp_id* cur_id, hs_cp_id* new_id);
    virtual ~HomeStoreCP();
    void try_cp_start(hs_cp_id* id);
    void indx_tbl_cp_done(hs_cp_id* id);
    void blkalloc_cp(hs_cp_id* id);
};

} // namespace homestore
