
#pragma once
#include <cassert>
#include "engine/checkpoint/checkpoint.hpp"
#include "homelogstore/log_store.hpp"
#include "api/vol_interface.hpp"
#include "homeblks/home_blks.hpp"
#include <wisr/wisr_ds.hpp>
#include "engine/meta/meta_blks_mgr.hpp"

namespace homestore {
struct volume_req;
class mapping;
class Volume;
struct Free_Blk_Entry;
struct free_blkid;

/* Journal entry
 * --------------------------------------------------------------------
 * | Journal Hdr | alloc_blkid list | checksum list | free_blk_entry |
 * -------------------------------------------------------------------
 */
struct journal_hdr {
    uint64_t lba;
    uint64_t indx_start_lba;
    int nlbas;
    int64_t cp_cnt;
};

class vol_journal_entry {
private:
    void* m_mem = nullptr;

public:
    ~vol_journal_entry();

    /* it update the alloc blk id and checksum */
    sisl::blob create_journal_entry(volume_req* v_req);

    std::string to_string() const {
        auto hdr = (journal_hdr*)m_mem;
        return fmt::format("lba={}, indx_start_lba={}, nlbas={}", hdr->lba, hdr->indx_start_lba, hdr->nlbas);
    }
};

enum indx_mgr_state { ONLINE = 0, DESTROYING = 1 };

struct destroy_journal_ent {
    indx_mgr_state state;
};

ENUM(cp_state, uint8_t,
     active_cp,  // Active CP
     suspend_cp, // cp is suspended
     destroy_cp  // it is a destroy cp. It is moved to active only in blkalloc checkpoint
);

typedef std::function< void(bool success) > cp_done_cb;
typedef cp_done_cb indxmgr_stop_cb;

/* Checkpoint is loosely defined demarcation of how much data is persisted. It might contain data after this checkpoint
 * also but it defintely contains data upto demarcation line. So IOs in each checkpoint(blkalloc checkpoint,
 * active checkpoint and diff checkpoint) should be idempotent.
 *
 * These are the different classes of checkpoints we have
 *      - Homeblks CP
 *              - Volume CP :- If it is suspended then all its sub system CPs are suspended
 *                   - Active CP
 *                   - Diff CP
 *                   - Snap delete/create CP
 *              - Blk Alloc CP  :- It is used to persist the bitmap
 * Homeblks CP is scheduled periodically or when externally triggered. It calls prepare flush before doing actual flush.
 * During prepare flush a individual CP can decide if it want to participate in a homeblks CP flush.
 *
 * Flow of freeing a blkid
 *      - free blkid is inserted in read blk tracker while it is being read from btree in match_cb_put_param.
 *              - Purpose of read blk tracker is to prevent freeing of Blkids it is being read in other IOs.
 *      - When all the reads are completed then blkid is inserted in volume free blkid list.
 *      - cache is invalidated.
 *      - When blk alloc checkpoint is taken, these free blkid list is purged.
 *      - For further steps check blk alloc base class.
 */
struct vol_cp_id;
struct vol_active_info {
    int64_t start_psn = -1; // not inclusive
    int64_t end_psn = -1;   // inclusive
    btree_cp_id_ptr btree_id;
    sisl::wisr_vector< free_blkid >* free_blkid_list;
    vol_active_info(int64_t start_psn, sisl::wisr_vector< free_blkid >* free_blkid_list) :
            start_psn(start_psn),
            free_blkid_list(free_blkid_list) {}
};

struct vol_diff_info {
    int64_t start_psn = -1; // not inclusive
    int64_t end_psn = -1;   // inclusive
    btree_cp_id_ptr btree_id;
};

struct vol_snap_info {
    std::vector< btree_cp_superblock > snap_delete_list;
    std::vector< free_blkid > free_blkid_list;
};

/* During prepare flush we decide to take a CP out of active, diff or snap or all 3 cps*/
struct vol_cp_id {
    std::shared_ptr< Volume > vol;
    cp_state flags = cp_state::active_cp;

    /* metrics */
    int64_t cp_cnt;
    std::atomic< int64_t > vol_size;

    /* cp */
    vol_active_info ainfo;
    vol_diff_info dinfo;
    vol_snap_info sinfo;

    vol_cp_id(int64_t cp_cnt, int64_t start_active_psn, std::shared_ptr< Volume > vol,
              sisl::wisr_vector< free_blkid >* free_blkid_list) :
            vol(vol),
            cp_cnt(cp_cnt),
            vol_size(0),
            ainfo(start_active_psn, free_blkid_list) {}

    cp_state state() const { return flags; }
};

struct indx_cp_id : cp_id_base {
    /* This list is not lock protected. */
    std::map< boost::uuids::uuid, vol_cp_id_ptr > vol_id_list;
    std::shared_ptr< blkalloc_cp_id > blkalloc_id;

    std::atomic< uint64_t > ref_cnt; // cnt of how many cps are triggered
    uint64_t snt_cnt;
    bool blkalloc_checkpoint = false; // it is set to true in prepare flush stage
    bool try_blkalloc_checkpoint =
        false; // it is set to true when someone want to take blkalloc checkpoint on this id. It might happen that it is
               // set to true after prepare flush is already called on this ID. In that case we will try to take blk
               // alloc checkpoint in the next cp.

    /* callback when cp is done */
    std::mutex cb_list_mtx;
    std::vector< cp_done_cb > cb_list;
};

/* it contains the PSN from which journal has to be replayed. */
#define INDX_MGR_VERSION 0x101
struct indx_mgr_cp_sb_hdr {
    int version;
    uint32_t vol_cnt;
} __attribute__((__packed__));

struct vol_cp_superblock {
    int64_t blkalloc_cp_cnt = -1; // cp cnt of last blkalloc checkpoint taken
    int64_t cp_cnt = -1;
    int64_t active_data_psn = -1;
    int64_t vol_size = 0;
} __attribute__((__packed__));

struct indx_mgr_cp_sb {
    boost::uuids::uuid uuid;
    vol_cp_superblock vol_cp_sb;
    btree_cp_superblock active_btree_cp_sb;
    indx_mgr_cp_sb(boost::uuids::uuid uuid) : uuid(uuid){};
    indx_mgr_cp_sb(){};
} __attribute__((__packed__));

struct indx_mgr_active_sb {
    logstore_id_t journal_id;
    MappingBtreeDeclType::btree_super_block btree_sb;
} __attribute__((__packed__));

class IndxCP : public CheckPoint< indx_cp_id > {
public:
    IndxCP();
    void try_cp_trigger(indx_cp_id* id);
    virtual void cp_start(indx_cp_id* id);
    virtual void cp_attach_prepare(indx_cp_id* cur_id, indx_cp_id* new_id);
    virtual ~IndxCP();
    void try_cp_start(indx_cp_id* id);
    void indx_tbl_cp_done(indx_cp_id* id);
    void blkalloc_cp(indx_cp_id* id);
};

class IndxMgr;
/* This message is used to delete indx tables in different thread */
struct indxmgr_msg {
    IndxMgr* object;
    btree_cp_id_ptr btree_id;
};

/* This class is responsible to manage active index and snapshot indx table */
class IndxMgr {
    typedef std::function< void(const boost::intrusive_ptr< volume_req >& vreq, std::error_condition err) > io_done_cb;
    typedef std::function< void(Free_Blk_Entry fbe) > free_blk_callback;
    typedef std::function< void(volume_req* req, BlkId& bid) > pending_read_blk_cb;
    typedef std::function< void(vol_cp_id_ptr cur_vol_id, indx_cp_id* hb_id, indx_cp_id* new_hb_id) > prepare_cb;

private:
    mapping* m_active_map;
    io_done_cb m_io_cb;
    pending_read_blk_cb m_pending_read_blk_cb;
    free_blk_callback m_free_blk_cb;
    std::shared_ptr< HomeLogStore > m_journal;
    log_write_comp_cb_t m_journal_comp_cb;

    /* we can not add a volume in active CP. It can be added only when a new cp is created. volume keeps
     * on using this id until new cp is not created. Once a new cp is created, it will become a part of it.
     */
    vol_cp_id_ptr m_first_cp_id;
    boost::uuids::uuid m_uuid;
    std::string m_name;
    indx_mgr_state m_state = indx_mgr_state::ONLINE;
    indxmgr_stop_cb m_stop_cb;
    bool m_last_cp = false;
    std::mutex prepare_cb_mtx;
    sisl::wisr_vector< prepare_cb > prepare_cb_list;
    indx_mgr_active_sb m_sb;
    sisl::wisr_vector< free_blkid >* m_free_list[MAX_CP_CNT];
    indx_mgr_cp_sb m_last_sb;

    void journal_write(volume_req* vreq);
    void journal_comp_cb(logstore_seq_num_t seq_num, logdev_key ld_key, void* req);
    btree_status_t update_indx_tbl(volume_req* vreq);
    btree_cp_id_ptr get_btree_id(indx_cp_id* cp_id);
    vol_cp_id_ptr get_volume_id(indx_cp_id* cp_id);
    void destroy_indx_tbl(vol_cp_id_ptr vol_id);
    void add_prepare_cb_list(prepare_cb cb);
    void volume_destroy_cp(vol_cp_id_ptr cur_vol_id, indx_cp_id* hb_id, indx_cp_id* new_hb_id);
    void create_first_cp_id(std::shared_ptr< Volume >& vo);

private:
    /*********************** static private members **********************/
    static std::unique_ptr< IndxCP > m_cp;
    static std::atomic< bool > m_shutdown_started;
    static bool m_shutdown_cmplt;
    static iomgr::io_thread_t m_thread_id;
    static iomgr::timer_handle_t m_homeblks_cp_timer_hdl;
    static void* m_meta_blk;
    static std::once_flag m_flag;
    static sisl::aligned_unique_ptr< uint8_t > m_recovery_sb;
    static size_t m_recovery_sb_size;
    static std::map< boost::uuids::uuid, indx_mgr_cp_sb > cp_sb_map;
    static HomeBlks* m_hb; // Hold onto the homeblks to maintain reference
    static void init();

public:
    /* It is called in first time create.
     * @ params params :- vol_params
     *          io_cb :- it is used to send callback with io is completed
     *          free_blk_cb :- It is used to free the blks in case of volume destroy
     *          read_blk_cb :- It is used to notify blks that it is about the be returned in read.
     */
    IndxMgr(std::shared_ptr< Volume > vol, const vol_params& params, io_done_cb io_cb, free_blk_callback free_blk_cb,
            pending_read_blk_cb read_blk_cb);

    /* It is called in recovery.
     * @params sb :- sb require to recover indx mgr active file homeblks.
     *         io_cb :- it is used to send callback with io is completed
     *         free_blk_cb :- It is used to free the blks in case of volume destroy
     *         read_blk_cb :- It is used to notify blks that it is about the be returned in read.
     */
    IndxMgr(std::shared_ptr< Volume > vol, const indx_mgr_active_sb& sb, io_done_cb io_cb,
            free_blk_callback free_blk_cb, pending_read_blk_cb read_blk_cb);
    ~IndxMgr();

    /* create new vol cp id and decide if this volume want to participate in a current cp
     * @params vol_cur_id :- current cp id of this volume
     * @params hb_id :- current id of home_blks
     * @params new_hb_id :- new home blks cp id
     * @return :- return new cp id.
     */
    vol_cp_id_ptr attach_prepare_vol_cp(vol_cp_id_ptr vol_cur_id, indx_cp_id* hb_id, indx_cp_id* new_hb_id);

    /* Get the active indx table
     * @return :- active mapping instance
     */
    mapping* get_active_indx();

    /* write/update indx table for a IO
     * @params req :- It create all information to update the indx mgr and journal
     */
    void update_indx(const boost::intrusive_ptr< volume_req >& vreq);

    /* Get active superblock
     * @return :- get superblock of a active btree. It is immutable structure. It contains all infomation require to
     *            recover active indx tbl. id is zero for active indx table.
     */
    indx_mgr_active_sb get_active_sb();

    /* Destroy all indexes and call homeblks level cp to persist. It assumes that all ios are stopped by volume.
     * It is async call. It is called only once
     * @params cb :- callback when destroy is done.
     */
    void destroy(indxmgr_stop_cb cb);

    /* truncate journal */
    void truncate(vol_cp_id_ptr vol_id);

    /* volume is destroy successfully */
    void destroy_done();

    /* It creates all the indx tables and intialize checkpoint */
    void recovery_start_phase1(std::shared_ptr< Volume > vo);
    void recovery_start_phase2();
    void log_found(logstore_seq_num_t seqnum, log_buffer buf, void* mem);

    /* it flushes free blks to blk allocator */
    void flush_free_blks(vol_cp_id_ptr vol_id, indx_cp_id* indx_id);

    /* it frees the blks and insert it in cp id free blk list. It is called when there is no read pending on this blk */
    void free_blk(Free_Blk_Entry& fbe);
    void update_cp_sb(vol_cp_id_ptr& vol_id, indx_cp_id* indx_id, indx_mgr_cp_sb* sb);
    uint64_t get_last_psn();
    /* It is called when volume is sucessfully create on disk */
    void create_done();

public:
    /*********************** static public functions **********************/
    /* Trigger CP to flush all outstanding IOs. It is a static function and assumes that all ios are stopped by
     * home blks , all outstanding ios and outstanding vol deletes  are completed. It is called only once.
     * @params cb :- callback when shutdown is done.
     */
    static void shutdown(indxmgr_stop_cb cb);

    /* create new vol cp id for all the volumes and also decide what volumes want to participate in a cp
     * @params cur_id :- current vol cp ids map
     *         new_id :- new new cp ids map
     *         hb_id :- home blks cp id
     *         new_hb_id :- new home blks cp id
     */

    static void attach_prepare_vol_cp_id_list(std::map< boost::uuids::uuid, vol_cp_id_ptr >* cur_id,
                                              std::map< boost::uuids::uuid, vol_cp_id_ptr >* new_id, indx_cp_id* hb_id,
                                              indx_cp_id* new_hb_id);

    /* trigger homeblks cp. It first trigger a volume cp followed by blkalloc cp. It is async call.
     * @params cb :- callback when cp is done.
     * @shutdown :- true if it is called by shutdown. This flag makes sure that no other cp is triggered after shutdown
     * cp
     */
    static void trigger_homeblks_cp(cp_done_cb cb = nullptr, bool shutdown = false);

    /* trigger volume CP. It doesn't persist blkalloc */
    static void trigger_vol_cp();

    /* reinitialize indx mgr. It is used in fake reboot */
    static void reinit() { m_shutdown_started = false; }
    static const iomgr::io_thread_t& get_thread_id() { return m_thread_id; }
    static void write_homeblks_cp_sb(indx_cp_id* indx_id);
    static void meta_blk_found_cb(meta_blk* mblk, sisl::aligned_unique_ptr< uint8_t > buf, size_t size);
    static void flush_homeblks_free_blks(indx_cp_id* id);
};
} // namespace homestore
