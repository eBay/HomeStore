#pragma once
#include <cassert>
#include "engine/checkpoint/checkpoint.hpp"
#include <wisr/wisr_ds.hpp>
#include "engine/meta/meta_blks_mgr.hpp"
#include <engine/homestore_base.hpp>
#include <engine/homeds/btree/btree.hpp>

namespace homestore {

struct indx_req;
class indx_tbl;
class IndxMgr;
class indx_mgr;
using prepare_cb = std::function< void(const indx_cp_ptr& cur_icp, hs_cp* cur_hcp, hs_cp* new_hcp) >;
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
    int64_t cp_id;
};

class indx_journal_entry {
private:
    sisl::io_blob m_iob;

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
    sisl::io_blob create_journal_entry(indx_req* v_req);

    std::string to_string() const { return fmt::format("size= {}", size()); }
};

enum indx_mgr_state { ONLINE = 0, DESTROYING = 1 };
struct destroy_journal_ent {
    indx_mgr_state state;
};

using indxmgr_stop_cb = cp_done_cb;

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
 * Note :- In a checkpoint it can contain data at least upto the seqId or more. It holds true for all checkpoints/data
 * except free blkid. In disk bm it contain exactly those blkids which are freed upto that checkpoint but it might
 * contain blks which are allocated after this checkpoint.
 */
struct indx_cp;

/* CP will always be in this timeline order
 * blkalloc cp ------> diff cp ------> active cp
 * active CP is always ahead or equal to Diff cp. Diff cp is always ahead or equal to blk alloc cp. If active CP is
 * suspended then all cps are suspended.
 */

enum cp_state {
    suspend_cp = 0x0, // cp is suspended
    active_cp = 0x1,  // Active CP
    diff_cp = 0x2,    // Diff CP.
    ba_cp = 0x4,      // blkalloc cp.
};

ENUM(indx_req_state, uint32_t, active_btree, diff_btree);

struct hs_cp : cp_base {
    /* This list is not lock protected. */
    std::map< boost::uuids::uuid, indx_cp_ptr > indx_cp_list;
    std::shared_ptr< blkalloc_cp > ba_cp;

    std::atomic< uint64_t > ref_cnt; // cnt of how many cps are triggered
    uint64_t snt_cnt;
    bool blkalloc_checkpoint = false; // it is set to true in prepare flush stage
};

struct indx_active_cp {
    int64_t start_seqid = -1; // not inclusive
    int64_t end_seqid = -1;   // inclusive
    btree_cp_ptr bcp;
    indx_active_cp(int64_t start_seqid) : start_seqid(start_seqid) {}
    std::string to_string() {
        stringstream ss;
        ss << " start_seqid " << start_seqid << " end_seqid " << end_seqid << " btree checkpoint info "
           << "\n"
           << bcp->to_string();
        return ss.str();
    }
};

struct indx_diff_cp {
    int64_t start_seqid = -1; // not inclusive
    int64_t end_seqid = -1;   // inclusive
    indx_tbl* diff_tbl = nullptr;
    int64_t diff_snap_id = -1;
    btree_cp_ptr bcp;
    indx_diff_cp(int64_t start_seqid) : start_seqid(start_seqid) {}
    std::string to_string() {
        stringstream ss;
        ss << " start_seqid " << start_seqid << " end_seqid " << end_seqid << " diff_snap_id " << diff_snap_id
           << " btree checkpoint info "
           << "\n"
           << bcp->to_string();
        return ss.str();
    }
};

/* During prepare flush we decide to take a CP out of active, diff or snap or all 3 cps*/
struct indx_cp : public boost::intrusive_ref_counter< indx_cp > {
    indx_mgr_ptr indx_mgr;
    int flags = cp_state::active_cp;
    int64_t max_seqid = -1; // max seqid sent on this id

    /* metrics */
    int64_t cp_id;
    std::atomic< int64_t > indx_size;

    /* cp */
    indx_active_cp acp;
    indx_diff_cp dcp;

    std::vector< blkid_list_ptr > user_free_blkid_list; // this blkid list is freed by the user. It is not part of any
                                                        // cp. user first collect it and then later it attaches the list
                                                        // to a cp.
    blkid_list_ptr io_free_blkid_list;                  // list of blk ids freed in a cp

    indx_cp(int64_t cp_id, int64_t start_active_seqid, int64_t start_diff_seqid, indx_mgr_ptr indx_mgr,
            blkid_list_ptr& io_free_blkid_list) :
            indx_mgr(indx_mgr),
            cp_id(cp_id),
            indx_size(0),
            acp(start_active_seqid),
            dcp(start_diff_seqid),
            io_free_blkid_list(io_free_blkid_list) {}

    int state() const { return flags; }
    int64_t get_max_seqid() { return 0; }
    void set_max_seqid(int64_t seqid){};

    std::string to_string() {
        stringstream ss;
        ss << "flags " << flags << " indx cp_id " << cp_id << " indx_size " << indx_size << " active checkpoint "
           << "\n"
           << acp.to_string() << "\n"
           << " diff checkpoint "
           << "\n"
           << dcp.to_string() << "\n"
           << " size freed " << io_free_blkid_list->size() << " user size freed " << user_free_blkid_list.size();
        return ss.str();
    }
};

/* super bcp persisted for each CP */
/* it contains the seqid from which journal has to be replayed. */
#define INDX_MGR_VERSION 0x101
enum meta_hdr_type { INDX_CP, INDX_DESTROY, INDX_UNMAP, SNAP_DESTROY };
struct hs_cp_base_sb {
    boost::uuids::uuid uuid; // Don't populate if it is hs indx meta blk
    meta_hdr_type type;
    uint32_t size;
} __attribute__((__packed__));

struct hs_cp_sb : hs_cp_base_sb {
    int version;
    uint32_t indx_cnt;
} __attribute__((__packed__));

struct indx_cp_sb {
    int64_t blkalloc_cp_id = -1; // cp cnt of last blkalloc checkpoint taken
    int64_t indx_size = 0;

    /* active cp info */
    int64_t active_cp_id = -1;
    int64_t active_data_seqid = -1;

    /* diff cp info */
    int64_t diff_cp_id = -1;
    int64_t diff_data_seqid = -1;
    int64_t diff_max_seqid = -1;
    int64_t diff_snap_id = -1;
    bool snap_cp = false;

    int64_t get_active_data_seqid() const { return active_data_seqid; }
} __attribute__((__packed__));

struct indx_cp_base_sb {
    boost::uuids::uuid uuid;
    indx_cp_sb icp_sb;  // indx cp superblock
    btree_cp_sb acp_sb; // active cp superblock
    btree_cp_sb dcp_sb; // diff cp_superblock
    indx_cp_base_sb(boost::uuids::uuid uuid) : uuid(uuid){};
    indx_cp_base_sb(){};
    std::string to_string() {
        stringstream ss;
        ss << "active_cp_cnt " << icp_sb.active_cp_id << " active_data_seqid " << icp_sb.active_data_seqid
           << " diff_cp_cnt " << icp_sb.diff_cp_id << " diff_Data_seqid " << icp_sb.diff_data_seqid
           << " blkalloc cp cp " << icp_sb.blkalloc_cp_id;
        return ss.str();
    }
} __attribute__((__packed__));

/* this superblock is never changed once indx manager is created */
struct indx_mgr_sb {
    logstore_id_t journal_id = 0;
    btree_super_block btree_sb;
    bool is_snap_enabled = false;
    indx_mgr_sb(btree_super_block btree_sb, logstore_id_t journal_id, bool is_snap_enabled) :
            journal_id(journal_id), btree_sb(btree_sb), is_snap_enabled(is_snap_enabled) {}
    indx_mgr_sb() {}
} __attribute__((__packed__));

class HomeStoreCPMgr : public CPMgr< hs_cp > {
public:
    HomeStoreCPMgr();
    void try_cp_trigger(hs_cp* hcp);
    virtual void cp_start(hs_cp* hcp);
    virtual void cp_attach_prepare(hs_cp* cur_hcp, hs_cp* new_hcp);
    virtual ~HomeStoreCPMgr();
    void try_cp_start(hs_cp* hcp);
    void indx_tbl_cp_done(hs_cp* hcp);
    void blkalloc_cp_start(hs_cp* hcp);
};

} // namespace homestore
