#pragma once
#include <cassert>
#include "engine/checkpoint/checkpoint.hpp"
#include "homelogstore/log_store.hpp"
#include <wisr/wisr_ds.hpp>
#include "engine/meta/meta_blks_mgr.hpp"
#include <engine/homestore.hpp>
#include "indx_mgr.hpp"

namespace homestore {

struct Free_Blk_Entry;
struct free_blkid;
typedef std::function< void() > trigger_cp_callback;
typedef std::function< void(Free_Blk_Entry& fbe) > free_blk_callback;

typedef boost::intrusive_ptr< indx_req > indx_req_ptr;

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
    sisl::blob create_journal_entry() {
        auto blob = j_ent.create_journal_entry(this);
        return blob;
    }

    void push_indx_alloc_blkid(BlkId& bid) { indx_alloc_blkid_list.push_back(bid); }
    void push_fbe(Free_Blk_Entry& fbe) { fbe_list.push_back(fbe); }
    friend void intrusive_ptr_add_ref(indx_req* req) { req->ref_count.increment(1); }
    friend void intrusive_ptr_release(indx_req* req) {
        if (req->ref_count.decrement_testz(1)) { req->free_yourself(); }
    };
    void inc_ref() { intrusive_ptr_add_ref(this); }

public:
    indx_journal_entry j_ent;
    std::vector< BlkId > indx_alloc_blkid_list;
    std::vector< Free_Blk_Entry > fbe_list;
    hs_cp_id* first_hs_id = nullptr;
    hs_cp_id* hs_id = nullptr;
    indx_cp_id_ptr indx_id = nullptr;
    sisl::atomic_counter< int > ref_count = 1; // Initialize the count
    error_condition indx_err = no_error;
};

class indx_tbl {
    /* these virtual functions should be defined by the consumer */
public:
    /* It is called when its btree consumer has successfully stored the btree superblock */
    virtual ~indx_tbl() = default;
    virtual void create_done() = 0;
    virtual btree_super_block get_btree_sb() = 0;
    virtual btree_status_t update_active_indx_tbl(indx_req* ireq, btree_cp_id_ptr btree_id) = 0;
    virtual btree_cp_id_ptr attach_prepare_cp(btree_cp_id_ptr cur_cp_id, bool is_last_cp) = 0;
    virtual void flush_free_blks(btree_cp_id_ptr btree_id,
                                 std::shared_ptr< homestore::blkalloc_cp_id >& blkalloc_id) = 0;
    virtual void update_btree_cp_sb(btree_cp_id_ptr cp_id, btree_cp_superblock& btree_sb, bool blkalloc_cp) = 0;
    virtual void truncate(btree_cp_id_ptr cp_id) = 0;
    virtual btree_status_t destroy(btree_cp_id_ptr btree_id, free_blk_callback cb) = 0;
    virtual void destroy_done() = 0;
    virtual void cp_start(btree_cp_id_ptr cp_id, cp_comp_callback cb) = 0;
    virtual void recovery_update(journal_hdr* hdr) = 0;
    virtual void update_indx_alloc_blkids(indx_req* ireq) = 0;
};

class IndxMgr : public std::enable_shared_from_this< IndxMgr > {
    typedef std::function< void(const boost::intrusive_ptr< indx_req >& ireq, std::error_condition err) > io_done_cb;
    typedef std::function< indx_tbl*() > create_indx_tbl;
    typedef std::function< indx_tbl*(btree_super_block& sb, btree_cp_superblock& cp_info) > recover_indx_tbl;

public:
    /* It is called in first time create.
     * @params io_cb :- it is used to send callback with io is completed
     * @params recovery_mode :- true :- it is recovery
     *                          false :- it is first time create
     * @params func :- function to create indx table
     */
    IndxMgr(boost::uuids::uuid uuid, std::string name, io_done_cb io_cb, create_indx_tbl func);

    /* constructor for recovery */
    IndxMgr(boost::uuids::uuid uuid, std::string name, io_done_cb io_cb, create_indx_tbl create_func,
            recover_indx_tbl recover_func, indx_mgr_static_sb sb);

    ~IndxMgr();

    /* create new indx cp id and decide if this indx mgr want to participate in a current cp
     * @params indx_cur_id :- current cp id of this indx mgr
     * @params hs_id :- current id of home_blks
     * @params new_hs_id :- new home blks cp id
     * @return :- return new cp id.
     */
    indx_cp_id_ptr attach_prepare_indx_cp(indx_cp_id_ptr indx_cur_id, hs_cp_id* hs_id, hs_cp_id* new_hs_id);

    /* Get the active indx table
     * @return :- active indx_tbl instance
     */
    indx_tbl* get_active_indx();

    /* write/update indx table for a IO
     * @params req :- It create all information to update the indx mgr and journal
     */
    void update_indx(boost::intrusive_ptr< indx_req > ireq);

    /* Get static superblock
     * @return :- get static superblock of indx mgr. It is immutable structure. It contains all infomation require to
     *            recover active and diff indx tbl.
     */
    indx_mgr_static_sb get_static_sb();

    /* Destroy all indexes and call homestore level cp to persist. It assumes that all ios are stopped by indx mgr.
     * It is async call. It is called only once
     * @params cb :- callback when destroy is done.
     */
    void destroy(indxmgr_stop_cb&& cb);

    /* truncate journal */
    void truncate(indx_cp_id_ptr indx_id);

    /* indx mgr is destroy successfully */
    void destroy_done();

    /* It creates all the indx tables and intialize checkpoint */
    void recovery_start_phase1();
    void recovery_start_phase2();
    void log_found(logstore_seq_num_t seqnum, log_buffer buf, void* mem);

    /* it flushes free blks to blk allocator */
    void flush_free_blks(indx_cp_id_ptr indx_id, hs_cp_id* hb_id);

    /* it frees the blks and insert it in cp id free blk list. It is called when there is no read pending on this blk */
    void free_blk(hs_cp_id* hs_id, Free_Blk_Entry& fbe);
    void update_cp_sb(indx_cp_id_ptr& indx_id, hs_cp_id* hb_id, indx_cp_sb* sb);
    uint64_t get_last_psn();
    /* It is called when super block all indx tables are persisted by its consumer */
    void create_done();
    void init();
    std::string get_name();

public:
    /*********************** static public functions **********************/

    template < typename... Args >
    static std::shared_ptr< IndxMgr > make_IndxMgr(Args&&... args) {
        auto indx_ptr = (std::shared_ptr< IndxMgr >(new IndxMgr(std::forward< Args >(args)...)));
        indx_ptr->init();
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
    static void trigger_hs_cp(cp_done_cb cb = nullptr, bool shutdown = false);

    /* trigger indx mgr CP. It doesn't persist blkalloc */
    static void trigger_indx_cp();
    static void trigger_indx_cp_with_cb(cp_done_cb cb);

    /* reinitialize indx mgr. It is used in fake reboot */
    static void reinit() { m_shutdown_started = false; }
    static void cp_done(bool blkalloc_cp);

    /* It registers a callback which is triggered at the end of cp.
     * @params cp_done_cb :- callback
     * @params blkalloc_cp :- true :- it is called for every blkalloc cp
     *                        false :- it is called for every indx cp.
     */
    static void register_cp_done_cb(cp_done_cb cb, bool blkalloc_cp = false);
    static void write_hs_cp_sb(hs_cp_id* hb_id);
    static const iomgr::io_thread_t& get_thread_id() { return m_thread_id; }
    static void meta_blk_found_cb(meta_blk* mblk, sisl::byte_view buf, size_t size);
    static void flush_hs_free_blks(hs_cp_id* id);

private:
    /*********************** static private members **********************/
    static std::unique_ptr< HomeStoreCP > m_cp;
    static std::atomic< bool > m_shutdown_started;
    static bool m_shutdown_cmplt;
    static iomgr::io_thread_t m_thread_id;
    static iomgr::timer_handle_t m_hs_cp_timer_hdl;
    static void* m_meta_blk;
    static std::once_flag m_flag;
    static sisl::aligned_unique_ptr< uint8_t > m_recovery_sb;
    static size_t m_recovery_sb_size;
    static std::map< boost::uuids::uuid, indx_cp_sb > cp_sb_map;
    static HomeStoreBase* m_hs; // Hold onto the home store to maintain reference
    static uint64_t memory_used_in_recovery;
    static bool m_inited;
    static std::mutex cb_list_mtx;
    /* It is called for after every indx cp */
    static std::vector< cp_done_cb > indx_cp_done_cb_list;
    /* it is  called after every homestore cp */
    static std::vector< cp_done_cb > hs_cp_done_cb_list;
    static sisl::atomic_counter< bool > try_blkalloc_checkpoint; // set to true if next checkpoint should be blkalloc

    /************************ static private functions **************/
    static void static_init();

private:
    indx_tbl* m_active_tbl;
    io_done_cb m_io_cb;
    std::shared_ptr< HomeLogStore > m_journal;
    log_write_comp_cb_t m_journal_comp_cb;

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
    sisl::wisr_vector< free_blkid >* m_free_list[MAX_CP_CNT];
    indx_cp_sb m_last_cp_sb;
    std::map< logstore_seq_num_t, log_buffer > seq_buf_map; // used only in recovery
    bool m_recovery_mode = false;
    create_indx_tbl m_create_indx_tbl;
    recover_indx_tbl m_recover_indx_tbl;
    indx_mgr_static_sb m_static_sb;

    /*************************************** private functions ************************/
    void journal_write(indx_req* vreq);
    void journal_comp_cb(logstore_seq_num_t seq_num, logdev_key ld_key, void* req);
    btree_status_t update_active_indx_tbl(indx_req* vreq);
    btree_cp_id_ptr get_btree_id(hs_cp_id* cp_id);
    indx_cp_id_ptr get_indx_id(hs_cp_id* cp_id);
    void destroy_indx_tbl(indx_cp_id_ptr indx_id);
    void add_prepare_cb_list(prepare_cb cb);
    void indx_destroy_cp(indx_cp_id_ptr cur_indx_id, hs_cp_id* hb_id, hs_cp_id* new_hb_id);
    void create_first_cp_id();
    btree_status_t retry_update_active_indx(const boost::intrusive_ptr< indx_req >& ireq);
    void free_blk(indx_cp_id_ptr indx_id, Free_Blk_Entry& fbe);
    void free_blk(indx_cp_id_ptr indx_id, free_blkid& fblkid);
};

struct free_blkid {
    BlkId m_blkId;
    uint8_t m_blk_offset : NBLKS_BITS;
    uint8_t m_nblks_to_free : NBLKS_BITS;

    free_blkid(BlkId b) : m_blkId(b), m_blk_offset(0), m_nblks_to_free(0) {}
    free_blkid() {}
    free_blkid(const BlkId& blkId, uint8_t blk_offset, uint8_t nblks_to_free) :
            m_blkId(blkId), m_blk_offset(blk_offset), m_nblks_to_free(nblks_to_free) {}
    void copy(struct free_blkid& fbe) {
        m_blkId = fbe.m_blkId;
        m_blk_offset = fbe.m_blk_offset;
        m_nblks_to_free = fbe.m_nblks_to_free;
    }
} __attribute__((__packed__));

struct Free_Blk_Entry : free_blkid {
    hs_cp_id* m_cp_id = nullptr;

    Free_Blk_Entry() {}
    Free_Blk_Entry(const BlkId& blkId, uint8_t blk_offset, uint8_t nblks_to_free) :
            free_blkid(blkId, blk_offset, nblks_to_free) {}

    BlkId blk_id() const { return m_blkId; }
    uint8_t blk_offset() const { return m_blk_offset; }
    uint8_t blks_to_free() const { return m_nblks_to_free; }
    BlkId get_free_blkid() { return (m_blkId.get_blkid_at(m_blk_offset, m_nblks_to_free, 1)); }
};

} // namespace homestore
