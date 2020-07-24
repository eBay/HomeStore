#pragma once
#include <cassert>
#include "engine/checkpoint/checkpoint.hpp"
#include "homelogstore/log_store.hpp"
#include <fds/thread_vector.hpp>
#include <wisr/wisr_ds.hpp>
#include "engine/meta/meta_blks_mgr.hpp"
#include <engine/homestore.hpp>
#include "indx_mgr.hpp"

namespace homestore {
class Blk_Read_Tracker;
struct Free_Blk_Entry;
typedef std::function< void() > trigger_cp_callback;
typedef std::function< void(Free_Blk_Entry& fbe) > free_blk_callback;

typedef boost::intrusive_ptr< indx_req > indx_req_ptr;

#define MAX_FBE_SIZE 1 * 1024 * 1024 // 1 MB
struct indx_req;

class indx_tbl {
    /* these virtual functions should be defined by the consumer */
public:
    /* It is called when its btree consumer has successfully stored the btree superblock */
    virtual ~indx_tbl() = default;
    virtual void create_done() = 0;
    virtual btree_super_block get_btree_sb() = 0;
    virtual btree_status_t update_active_indx_tbl(indx_req* ireq, const btree_cp_id_ptr& btree_id) = 0;
    virtual btree_status_t update_diff_indx_tbl(indx_req* ireq, const btree_cp_id_ptr& btree_id) = 0;
    virtual btree_cp_id_ptr attach_prepare_cp(const btree_cp_id_ptr& cur_cp_id, bool is_last_cp,
                                              bool blkalloc_checkpoint) = 0;
    virtual void flush_free_blks(const btree_cp_id_ptr& btree_id, std::shared_ptr< blkalloc_cp_id >& blkalloc_id) = 0;
    virtual void update_btree_cp_sb(const btree_cp_id_ptr& cp_id, btree_cp_superblock& btree_sb, bool blkalloc_cp) = 0;
    virtual void truncate(const btree_cp_id_ptr& cp_id) = 0;
    virtual btree_status_t destroy(blkid_list_ptr& free_blkid_list, uint64_t& free_node_cnt) = 0;
    virtual void destroy_done() = 0;
    virtual void cp_start(const btree_cp_id_ptr& cp_id, cp_comp_callback cb) = 0;
    virtual btree_status_t recovery_update(logstore_seq_num_t seqnum, journal_hdr* hdr,
                                           const btree_cp_id_ptr& btree_id) = 0;
    virtual void update_indx_alloc_blkids(indx_req* ireq) = 0;
    virtual uint64_t get_used_size() = 0;
    virtual btree_status_t free_user_blkids(blkid_list_ptr free_list, BtreeQueryCursor& cur, int64_t& size) = 0;
    virtual btree_status_t unmap(blkid_list_ptr free_list, BtreeQueryCursor& cur) = 0;
    virtual void get_btreequery_cur(const sisl::blob& b, BtreeQueryCursor& cur) = 0;
};

typedef std::function< void(const boost::intrusive_ptr< indx_req >& ireq, std::error_condition err) > io_done_cb;
typedef std::function< indx_tbl*() > create_indx_tbl;
typedef std::function< indx_tbl*(btree_super_block& sb, btree_cp_superblock& cp_info) > recover_indx_tbl;

class IndxMgr : public std::enable_shared_from_this< IndxMgr > {

public:
    /* It is called in first time create.
     * @params io_cb :- it is used to send callback with io is completed
     * @params recovery_mode :- true :- it is recovery
     *                          false :- it is first time create
     * @params func :- function to create indx table
     */
    IndxMgr(boost::uuids::uuid uuid, std::string name, io_done_cb io_cb, create_indx_tbl func, bool is_snap_enabled);

    /* constructor for recovery */
    IndxMgr(boost::uuids::uuid uuid, std::string name, io_done_cb io_cb, create_indx_tbl create_func,
            recover_indx_tbl recover_func, indx_mgr_static_sb sb);

    virtual ~IndxMgr();

    /* create new indx cp id and decide if this indx mgr want to participate in a current cp
     * @params indx_cur_id :- current cp id of this indx mgr
     * @params hs_id :- current id of home_blks
     * @params new_hs_id :- new home blks cp id
     * @return :- return new cp id.
     */
    indx_cp_id_ptr attach_prepare_indx_cp(const indx_cp_id_ptr& indx_cur_id, hs_cp_id* hs_id, hs_cp_id* new_hs_id);

    /* Get the active indx table
     * @return :- active indx_tbl instance
     */
    indx_tbl* get_active_indx();

    /* write/update indx table for a IO
     * @params req :- It create all information to update the indx mgr and journal
     */
    void update_indx(boost::intrusive_ptr< indx_req > ireq);

    /* Create snapshot. */
    void indx_snap_create();

    /* Get static superblock
     * @return :- get static superblock of indx mgr. It is immutable structure. It contains all infomation require to
     *            recover active and diff indx tbl.
     */
    indx_mgr_static_sb get_static_sb();

    /* Destroy all indexes and call homestore level cp to persist. It assumes that all ios are stopped by indx mgr.
     * It is async call. It is called only once
     * @params cb :- callback when destroy is done.
     */
    void destroy(const indxmgr_stop_cb& cb);

    /* truncate journal */
    void truncate(const indx_cp_id_ptr& indx_id);

    /* indx mgr is destroy successfully */
    void destroy_done();

    /* It creates all the indx tables and intialize checkpoint */
    void recovery_start_phase1();
    void recovery_start_phase2();
    void log_found(logstore_seq_num_t seqnum, log_buffer buf, void* mem);

    /* it flushes free blks to blk allocator */
    void flush_free_blks(const indx_cp_id_ptr& indx_id, hs_cp_id* hb_id);

    void update_cp_sb(indx_cp_id_ptr& indx_id, hs_cp_id* hb_id, indx_cp_io_sb* sb);
    uint64_t get_last_psn();
    /* It is called when super block all indx tables are persisted by its consumer */
    void indx_create_done(indx_tbl* indx_tbl = nullptr);
    void indx_init(); // private api
    std::string get_name();
    uint64_t get_used_size();
    void attach_user_fblkid_list(blkid_list_ptr& free_blkid_list, const cp_done_cb& free_blks_cb, int64_t free_size,
                                 bool last_cp = false);

public:
    /*********************** static public functions **********************/

    template < typename... Args >
    static std::shared_ptr< IndxMgr > make_IndxMgr(Args&&... args) {
        auto indx_ptr = std::make_shared< IndxMgr >(std::forward< Args >(args)...);
        return indx_ptr;
    }

    /* Trigger CP to flush all outstanding IOs. It is a static function and assumes that all ios are stopped by
     * home blks , all outstanding ios and outstanding indx mgr deletes  are completed. It is called only once.
     * @params cb :- callback when shutdown is done.
     */
    static void shutdown(indxmgr_stop_cb cb);

    /* create new indx mgr cp id for all the indx mgr and also decide what indx mgr want to participate in a cp
     * @params cur_id :- current indxmgr cp ids map
     *         new_id :- new new cp ids map
     *         hb_id :- home blks cp id
     *         new_hb_id :- new home blks cp id
     */

    static void attach_prepare_indx_cp_id_list(std::map< boost::uuids::uuid, indx_cp_id_ptr >* cur_id,
                                               std::map< boost::uuids::uuid, indx_cp_id_ptr >* new_id, hs_cp_id* hb_id,
                                               hs_cp_id* new_hb_id);
    /* trigger hs cp. It first trigger a indx mgr cp followed by blkalloc cp. It is async call.
     * @params cb :- callback when cp is done.
     * @shutdown :- true if it is called by shutdown. This flag makes sure that no other cp is triggered after shutdown
     * cp
     */
    static void trigger_hs_cp(const cp_done_cb& cb = nullptr, bool shutdown = false);

    /* trigger indx mgr CP. It doesn't persist blkalloc */
    static void trigger_indx_cp();
    static void trigger_indx_cp_with_cb(const cp_done_cb& cb);

    /* reinitialize indx mgr. It is used in fake reboot */
    static void reinit() { m_shutdown_started = false; }
    static void cp_done(bool blkalloc_cp);

    /* It registers a callback which is triggered at the end of cp.
     * @params cp_done_cb :- callback
     * @params blkalloc_cp :- true :- it is called for every blkalloc cp
     *                        false :- it is called for every indx cp.
     */
    static void register_cp_done_cb(const cp_done_cb& cb, bool blkalloc_cp = false);
    static void write_hs_cp_sb(hs_cp_id* hb_id);
    static const iomgr::io_thread_t& get_thread_id() { return m_thread_id; }
    static void meta_blk_found_cb(meta_blk* mblk, sisl::byte_view buf, size_t size);
    static void flush_hs_free_blks(hs_cp_id* id);
    static void write_meta_blk(void*& mblk, sisl::byte_view buf);

    /* This api insert the free blkids in out_free_list.
     * 1. This api only make sure that  we are not accumulating more then the threshhold.
     * 2. It make sure that CP doesn't happen if there is a pending read on the same blkid.
     *
     * User can fail freeing blkid even after calling this api as it doesn't actually free the blkids.
     *
     * @params
     * @hs_id :- homestore ID to which out_free_list is supposed to attached. If hs_id is null then it takes the latest
     *           one by doing cp_io_enter because it assumes that out_fbe_list will be attached to the cur_cp_id or
     *           later.
     * @out_free_list :- A list which user is using to accumulate free blkids. It will be attached later to a cp.
     * @in_fbe_list :- incoming free blkids that user want to free. This API either free all the blkids in this list or
     *                 none of them.
     * @force :-  true :- it doesn't check the resource usage. It always insert it in out_free_list. It trigger CP if i
     *                    reaches the threshhold.
     *            false :- it fails if resource has reached its threshold. User should trigger cp.
     *
     * @return :- return number of blks freed. return -1 if it can not add more
     */
    static uint64_t free_blk(hs_cp_id* hs_id, blkid_list_ptr& out_fblk_list, std::vector< Free_Blk_Entry >& in_fbe_list,
                             bool force);
    static uint64_t free_blk(hs_cp_id* hs_id, sisl::ThreadVector< homestore::BlkId >* out_fblk_list,
                             std::vector< Free_Blk_Entry >& in_fbe_list, bool force);
    static uint64_t free_blk(hs_cp_id* hs_id, blkid_list_ptr& out_fblk_list, Free_Blk_Entry& fbe, bool force);
    static uint64_t free_blk(hs_cp_id* hs_id, sisl::ThreadVector< homestore::BlkId >* out_fblk_list,
                             Free_Blk_Entry& fbe, bool force);

    /* it erase the free_blkid list and free up the resources. It is called after a free list is attached to a CP
     * and that CP is persisted.
     */
    static void free_blkid_list_flushed(std::vector< BlkId >& fblk_list);
    static void free_blkid_list_flushed(blkid_list_ptr fblk_list);
    static void add_read_tracker(Free_Blk_Entry& bid);
    static void remove_read_tracker(Free_Blk_Entry& fbe);

protected:
    /*********************** virtual functions required to support snapshot  **********************/
    /* These functions are defined so that indx mgr can be used without snapmagr */
    virtual int64_t snap_create(indx_tbl* m_diff_tbl, int64_t start_cp_cnt) {
        assert(0);
        return -1;
    }
    virtual int64_t snap_get_diff_id() {
        assert(0);
        return -1;
    }
    virtual void snap_create_done(uint64_t snap_id, int64_t max_psn, int64_t contiguous_psn, int64_t end_cp_cnt) {
        assert(0);
    }
    virtual btree_super_block snap_get_diff_tbl_sb() {
        assert(0);
        btree_super_block sb;
        return sb;
    }

private:
    /*********************** static private members **********************/
    static std::unique_ptr< HomeStoreCP > m_cp;
    static std::atomic< bool > m_shutdown_started;
    static bool m_shutdown_cmplt;
    static iomgr::io_thread_t m_thread_id;
    static iomgr::io_thread_t m_slow_path_thread_id;
    static iomgr::timer_handle_t m_hs_cp_timer_hdl;
    static void* m_cp_meta_blk;
    static std::once_flag m_flag;
    static sisl::aligned_unique_ptr< uint8_t > m_recovery_sb;
    static size_t m_recovery_sb_size;
    static std::map< boost::uuids::uuid, indx_cp_io_sb > cp_sb_map;
    static std::map< boost::uuids::uuid, std::vector< std::pair< void*, sisl::byte_view > > > indx_meta_map;
    static HomeStoreBase* m_hs; // Hold onto the home store to maintain reference
    static uint64_t memory_used_in_recovery;
    static std::atomic< bool > m_inited;
    static std::mutex cb_list_mtx;
    /* It is called for after every indx cp */
    static std::vector< cp_done_cb > indx_cp_done_cb_list;
    /* it is  called after every homestore cp */
    static std::vector< cp_done_cb > hs_cp_done_cb_list;
    static sisl::atomic_counter< bool > try_blkalloc_checkpoint; // set to true if next checkpoint should be blkalloc
    static std::atomic< uint64_t > hs_fbe_size;
    static std::unique_ptr< Blk_Read_Tracker > m_read_blk_tracker;

    /************************ static private functions **************/
    static void static_init();
    /* it frees the blks and insert it in cp id free blk list. It is called when there is no read pending on this blk */
    static void safe_to_free_blk(Free_Blk_Entry& fbe);

private:
    indx_tbl* m_active_tbl;
    io_done_cb m_io_cb;
    std::shared_ptr< HomeLogStore > m_journal;
    log_req_comp_cb_t m_journal_comp_cb;

    /* we can not add a indx mgr in active CP. It can be added only when a new cp is created. indx mgr keeps
     * on using this id until new cp is not created. Once a new cp is created, it will become a part of it.
     */
    indx_cp_id_ptr m_first_cp_id;
    boost::uuids::uuid m_uuid;
    std::string m_name;
    indx_mgr_state m_state = indx_mgr_state::ONLINE;
    indxmgr_stop_cb m_stop_cb;
    bool m_last_cp = false;
    std::mutex prepare_cb_mtx;
    sisl::wisr_vector< prepare_cb > prepare_cb_list;
    blkid_list_ptr m_free_list[MAX_CP_CNT];
    indx_cp_io_sb m_last_cp_sb;
    std::map< logstore_seq_num_t, log_buffer > seq_buf_map; // used only in recovery
    bool m_recovery_mode = false;
    create_indx_tbl m_create_indx_tbl;
    recover_indx_tbl m_recover_indx_tbl;
    indx_mgr_static_sb m_static_sb;
    uint64_t m_free_list_cnt = 0;
    bool m_is_snap_enabled = false;
    bool m_is_snap_started = false;
    void* m_destroy_meta_blk = nullptr;
    BtreeQueryCursor m_destroy_btree_cur;

    /*************************************** private functions ************************/
    void update_indx_internal(boost::intrusive_ptr< indx_req > ireq);
    void journal_write(indx_req* vreq);
    void journal_comp_cb(logstore_req* req, logdev_key ld_key);
    btree_status_t update_indx_tbl(indx_req* vreq, bool is_active);
    btree_cp_id_ptr get_btree_id(hs_cp_id* cp_id);
    indx_cp_id_ptr get_indx_id(hs_cp_id* cp_id);
    void destroy_indx_tbl();
    void add_prepare_cb_list(prepare_cb cb);
    void indx_destroy_cp(const indx_cp_id_ptr& cur_indx_id, hs_cp_id* hb_id, hs_cp_id* new_hb_id);
    void create_first_cp_id();
    btree_status_t retry_update_indx(const boost::intrusive_ptr< indx_req >& ireq, bool is_active);
    void run_slow_path_thread();
    void create_new_diff_tbl(indx_cp_id_ptr& indx_id);
    void recover_meta_ops();
};

struct Free_Blk_Entry {
    BlkId m_blkId;
    /* These entries are needed only to invalidate cache. We store the actual blkid in journal */
    uint8_t m_blk_offset : NBLKS_BITS;
    uint8_t m_nblks_to_free : NBLKS_BITS;
    hs_cp_id* m_cp_id = nullptr;

    Free_Blk_Entry() {}
    Free_Blk_Entry(const BlkId& blkId) : m_blkId(blkId), m_blk_offset(0), m_nblks_to_free(0) {}
    Free_Blk_Entry(const BlkId& blkId, uint8_t blk_offset, uint8_t nblks_to_free) :
            m_blkId(blkId),
            m_blk_offset(blk_offset),
            m_nblks_to_free(nblks_to_free) {}

    BlkId blk_id() const { return m_blkId; }
    uint8_t blk_offset() const { return m_blk_offset; }
    uint8_t blks_to_free() const { return m_nblks_to_free; }
    BlkId get_free_blkid() { return (m_blkId.get_blkid_at(m_blk_offset, m_nblks_to_free, 1)); }
};

/* any consumer req should be derived from indx_mgr_req. Indx mgr use this as a context to call consumer APIs */
struct indx_req {
public:
    virtual uint32_t get_key_size() = 0;
    virtual uint32_t get_val_size() = 0;
    virtual void fill_key(void* mem, uint32_t size) = 0;
    virtual void fill_val(void* mem, uint32_t size) = 0;
    virtual uint64_t get_seqId() = 0;
    virtual uint32_t get_io_size() = 0;
    virtual void free_yourself() = 0;

public:
    indx_req(uint64_t request_id) : request_id(request_id) {}
    sisl::io_blob create_journal_entry() { return j_ent.create_journal_entry(this); }

    void push_indx_alloc_blkid(BlkId& bid) { indx_alloc_blkid_list.push_back(bid); }

    /* it is used by mapping/consumer to push fbe to free list. These blkds will be freed when entry is completed */
    void indx_push_fbe(std::vector< Free_Blk_Entry >& in_fbe_list) {
        indx_fbe_list.insert(indx_fbe_list.end(), in_fbe_list.begin(), in_fbe_list.end());
    }

    friend void intrusive_ptr_add_ref(indx_req* req) { req->ref_count.increment(1); }
    friend void intrusive_ptr_release(indx_req* req) {
        if (req->ref_count.decrement_testz(1)) { req->free_yourself(); }
    };
    void inc_ref() { intrusive_ptr_add_ref(this); }

public:
    bool resource_full_check = false; // we don't return error for all ios. we set it for trim,
                                      // destroy which can handle io failures and retry
    indx_journal_entry j_ent;
    std::vector< BlkId > indx_alloc_blkid_list;
    std::vector< Free_Blk_Entry > indx_fbe_list;
    hs_cp_id* first_hs_id = nullptr;
    hs_cp_id* hs_id = nullptr;
    indx_cp_id_ptr indx_id = nullptr;
    sisl::atomic_counter< int > ref_count = 1; // Initialize the count
    error_condition indx_err = no_error;
    indx_req_state state = indx_req_state::active_btree;
    uint64_t request_id; // Copy of the id from interface request
    BtreeQueryCursor active_btree_cur;
    BtreeQueryCursor diff_btree_cur;
};
} // namespace homestore
