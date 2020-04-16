#pragma once
#include <cassert>
#include "engine/checkpoint/checkpoint.hpp"
#include "homelogstore/log_store.hpp"
#include "api/vol_interface.hpp"
#include "homeblks/home_blks.hpp"

namespace homestore {
struct volume_req;
class mapping;
class Volume;
struct Free_Blk_Entry;

/* Journal entry
 * --------------------------------------------------------------------
 * | Journal Hdr | alloc_blkid list | checksum list | free_blk_entry |
 * -------------------------------------------------------------------
 */
struct journal_hdr {
    uint64_t lba;
    uint64_t indx_start_lba;
    int nblks;
};

class vol_journal_entry {
private:
    void* m_mem = nullptr;

public:
    ~vol_journal_entry();

    /* it update the alloc blk id and checksum */
    sisl::blob create_journal_entry(volume_req* v_req);
};

enum indx_mgr_state { ONLINE = 0, DESTROYING = 1 };

struct destroy_journal_ent {
    indx_mgr_state state;
};

enum cp_state {
    active_cp = 0,
    suspend_cp, // cp is suspended
    destroy_cp  // it is a destroy cp. It is moved to active only in bitmap checkpoint
};

typedef std::function< void(bool success) > cp_done_cb;
typedef cp_done_cb indxmgr_stop_cb;

struct vol_cp_id;
struct vol_cp_id {
    // Start PSN of different checkpoints in this ID
    int64_t start_active_psn = -1;
    int64_t end_active_psn = -1;
    btree_cp_id_ptr btree_id;
    std::shared_ptr< Volume > vol;
    int flags = cp_state::active_cp;
};

struct indx_cp_id : cp_id_base {
    /* This list is not lock protected. */
    std::map< boost::uuids::uuid, vol_cp_id_ptr > vol_id_list;
    std::atomic< uint64_t > ref_cnt; // cnt of how many cps are triggered
    uint64_t snt_cnt;
    bool bitmap_checkpoint = false;

    /* callback when cp is done */
    std::mutex cb_list_mtx;
    std::vector< cp_done_cb > cb_list;
};

/* it contains the PSN from which journal has to be replayed. */
struct indx_mgr_cp_sb {
    boost::uuids::uuid uuid;
    int64_t active_data_psn;
    int64_t active_btree_psn;
    ;
} __attribute__((__packed__));

struct indx_mgr_active_sb {
    logstore_id_t journal_id;
    MappingBtreeDeclType::btree_super_block btree_sb;
} __attribute__((__packed__));

/* Checkpoint is loosely defined demarcation of how much data is persisted. It might contain data after this checkpoint
 * also but it defintely contains data upto demarcation line. So IOs in each checkpoint(bitmap checkpoint,
 * active checkpoint and diff checkpoint) should be idempotent.
 * We have only one checkpoint object for homeblks. Bitmap checkpoint, active checkpoint and diff checkpoint is sub set
 * of this checkpoint. We can decide in cp_attach_prepare that what we want to do and what volumes want to take part.
 */
class IndxCP : public CheckPoint< indx_cp_id > {
public:
    IndxCP();
    void try_cp_trigger(indx_cp_id* id);
    virtual void cp_start(indx_cp_id* id);
    virtual void cp_attach_prepare(indx_cp_id* cur_id, indx_cp_id* new_id);
    virtual ~IndxCP();
    void try_cp_start(indx_cp_id* id);
    void cp_done(indx_cp_id* id);
    void bitmap_cp_done(indx_cp_id* id);
};

/* This class is responsible to manage active index and snapshot indx table */
class IndxMgr {
    typedef std::function< void(volume_req* req, std::error_condition err) > io_done_cb;
    typedef std::function< void(Free_Blk_Entry fbe) > free_blk_callback;
    typedef std::function< void(volume_req* req, BlkId& bid) > pending_read_blk_cb;

private:
    mapping* m_active_map;
    io_done_cb m_io_cb;
    pending_read_blk_cb m_pending_read_blk_cb;
    std::shared_ptr< HomeLogStore > m_journal;
    log_write_comp_cb_t m_journal_comp_cb;
    cp_state m_flags;

    /* we can not add a volume in active CP. It can be added only when a new cp is created. volume keeps
     * on using this id until new cp is not created. Once a new cp is created, it will become a part of it.
     */
    vol_cp_id_ptr m_first_cp_id;
    boost::uuids::uuid m_uuid;
    indx_mgr_state m_state = indx_mgr_state::ONLINE;
    indxmgr_stop_cb m_stop_cb;

    void journal_write(volume_req* vreq);
    void journal_comp_cb(logstore_seq_num_t seq_num, logdev_key ld_key, void* req);
    btree_status_t update_indx_tbl(volume_req* vreq);
    void cp_done(btree_cp_id* btree_id);
    btree_cp_id_ptr get_btree_id(indx_cp_id* cp_id);
    vol_cp_id_ptr get_volume_id(indx_cp_id* cp_id);
    void suspend_cp(vol_cp_id_ptr vol_id);
    void resume_cp(vol_cp_id_ptr vol_id);

private:
    /*********************** static private members **********************/
    static IndxCP* m_cp;
    static bool m_shutdown_started;
    static bool m_shutdown_cmplt;

    static void init();
    static void write_superblock();

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
     * @params sb :- sb require to recover indx mgr active file system.
     *         io_cb :- it is used to send callback with io is completed
     *         free_blk_cb :- It is used to free the blks in case of volume destroy
     *         read_blk_cb :- It is used to notify blks that it is about the be returned in read.
     */
    IndxMgr(std::shared_ptr< Volume > vol, indx_mgr_active_sb* sb, io_done_cb io_cb, free_blk_callback free_blk_cb,
            pending_read_blk_cb read_blk_cb);
    ~IndxMgr();

    /* create new vol cp id and decide if this volume want to participate in a current cp
     * @params vol_cur_id :- current cp id of this volume
     * @params home_blks_id :- current id of home_blks
     * @return :- return new cp id.
     */
    vol_cp_id_ptr attach_prepare_vol_cp(vol_cp_id_ptr vol_cur_id, indx_cp_id* home_blks_id);

    /* Get the active indx table
     * @return :- active mapping instance
     */
    mapping* get_active_indx();

    /* write/update indx table for a IO
     * @params req :- It create all information to update the indx mgr and journal
     */
    void update_indx(volume_req* req);

    /* Get active superblock
     * @return :- get superblock of a active btree. It is immutable structure. It contains all infomation require to
     *            recover active indx tbl. id is zero for active indx table.
     */
    indx_mgr_active_sb get_active_sb();

    /* Destroy all indexes and call system level cp to persist. It assumes that all ios are stopped by volume.
     * It is async call.
     * @params cb :- callback when destroy is done.
     */
    void destroy(indxmgr_stop_cb cb);

    /* truncate journal */
    void truncate(vol_cp_id_ptr vol_id);

    /* volume is destroy successfully */
    void destroy_done();

public:
    /*********************** static public functions **********************/
    /* Trigger CP to flush all outstanding IOs. It is a static function and assumes that all ios are stopped by
     * home blks and all outstanding ios are completed.
     * @params cb :- callback when shutdown is done.
     */
    static void shutdown(indxmgr_stop_cb cb);

    /* create new vol cp id for all the volumes and also decide what volumes want to participate in a cp
     * @params cur_id :- current vol cp ids map
     *         new_id :- new new cp ids map
     *         home_blks_id :- home blks cp id
     */

    static void attach_prepare_vol_cp_id_list(std::map< boost::uuids::uuid, vol_cp_id_ptr >* cur_id,
                                              std::map< boost::uuids::uuid, vol_cp_id_ptr >* new_id,
                                              indx_cp_id* home_blks_id);

    /* trigger system cp. It first trigger a volume cp followed by bitmap cp. It is async call.
     * @params cb :- callback when cp is done.
     */
    static void trigger_system_cp(cp_done_cb cb = nullptr);

    /* trigger volume CP. It doesn't persist bitmap */
    static void trigger_vol_cp();
};
} // namespace homestore
