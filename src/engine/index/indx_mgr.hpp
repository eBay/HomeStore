#pragma once
#include <atomic>
#include <cassert>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <system_error>
#include <vector>

#include <sisl/fds/thread_vector.hpp>
#include <fmt/format.h>
#include <sisl/wisr/wisr_ds.hpp>
#include <sisl/utility/enum.hpp>

#include "api/meta_interface.hpp"
#include "checkpoint.hpp"
#include "engine/homeds/btree/btree_internal.h"
#include "engine/homestore_base.hpp"

#include "homelogstore/logstore_header.hpp"

namespace homestore {
/***************************** forward declarations ************************/

struct indx_req;
class indx_tbl;
class IndxMgr;
class indx_mgr;
typedef std::function< void(const indx_cp_ptr& cur_icp, hs_cp* cur_hcp, hs_cp* new_hcp) > prepare_cb;
typedef std::shared_ptr< IndxMgr > indx_mgr_ptr;
class Blk_Read_Tracker;
struct Free_Blk_Entry;
typedef std::function< void() > trigger_cp_callback;
typedef std::function< void(Free_Blk_Entry& fbe) > free_blk_callback;
typedef boost::intrusive_ptr< indx_req > indx_req_ptr;
class HomeLogStore;

struct indx_req;

#define THIS_INDX_LOG(level, mod, req, msg, ...)                                                                       \
    HS_SUBMOD_LOG(level, mod, req, "indx_tbl", this->get_name(), msg, ##__VA_ARGS__)

#define THIS_INDX_PERIODIC_LOG(level, mod, msg, ...)                                                                   \
    HS_PERIODIC_DETAILED_LOG(level, mod, "indx_tbl", this->get_name(), , , msg, ##__VA_ARGS__)

#define THIS_INDX_CP_LOG(level, cp_id, msg, ...)                                                                       \
    HS_PERIODIC_DETAILED_LOG(level, cp, "cp", cp_id, "indx_tbl", this->get_name(), msg, ##__VA_ARGS__)

using read_indx_comp_cb_t = std::function< void(const indx_req_ptr& ireq, std::error_condition ret) >;

struct indx_test_status {
    static bool indx_create_suspend_cp_test;
};

/********************************* Journal ****************************************************/

/* Journal entry
 * ------------------------------------------------------------------
 * | Journal Hdr | alloc_blkid list | free_blk_entry | key | value |
 * ------------------------------------------------------------------
 */
ENUM(io_state, uint32_t, success, fail);

#pragma pack(1)
struct journal_hdr {
    uint32_t alloc_blkid_list_size; // number of entries
    uint32_t free_blk_entry_size;   // number of entries
    uint32_t key_size;              // actual size in bytes
    uint32_t val_size;              // actual size in bytes
    int64_t cp_id;
    io_state state; // io state (failed or successed), place holder for future use;
    uint8_t padding[4];
};
#pragma pack(0)

class indx_journal_entry {
public:
    sisl::io_blob m_iob;
    uint32_t size(indx_req* const ireq) const;
    uint32_t size() const;
    ~indx_journal_entry();

    static journal_hdr* get_journal_hdr(void* const m_mem) { return static_cast< journal_hdr* >(m_mem); }

    static std::pair< BlkId*, uint32_t > get_alloc_bid_list(void* const m_mem) {
        auto* const hdr{get_journal_hdr(m_mem)};
        auto* const ab_list{reinterpret_cast< BlkId* >(sizeof(journal_hdr) + static_cast< uint8_t* >(m_mem))};
        return (std::make_pair(ab_list, hdr->alloc_blkid_list_size));
    }

    static std::pair< BlkId*, uint32_t > get_free_bid_list(void* const m_mem) {
        auto* const hdr{get_journal_hdr(m_mem)};
        auto ab_list{get_alloc_bid_list(m_mem)};
        BlkId* const fb_list{&(ab_list.first[ab_list.second])};
        return (std::make_pair(fb_list, hdr->free_blk_entry_size));
    }

    static std::pair< uint8_t*, uint32_t > get_key(void* const m_mem) {
        auto* const hdr{get_journal_hdr(m_mem)};
        auto cp_list{get_free_bid_list(m_mem)};
        uint8_t* const key{reinterpret_cast< uint8_t* >(&(cp_list.first[cp_list.second]))};
        return (std::make_pair(key, hdr->key_size));
    }

    static std::pair< uint8_t*, uint32_t > get_val(void* const m_mem) {
        auto* const hdr{get_journal_hdr(m_mem)};
        auto key{get_key(m_mem)};
        uint8_t* const val{key.first + key.second};
        return (std::make_pair(val, hdr->val_size));
    }

    /* it update the alloc blk id and checksum */
    sisl::io_blob create_journal_entry(indx_req* v_req);

    std::string to_string() const { return fmt::format("size= {}", size()); }
};

enum class indx_mgr_state : uint8_t { ONLINE = 0, DESTROYING = 1 };
struct destroy_journal_ent {
    indx_mgr_state state;
};

typedef cp_done_cb indxmgr_stop_cb;

/*************************** Indx MGR CP *************************************************/

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

enum indx_cp_state : int {
    suspend_cp = 0x0, // cp is suspended
    active_cp = 0x1,  // Active CP
    diff_cp = 0x2,    // Diff CP.
    ba_cp = 0x4,      // blkalloc cp.
};

ENUM(indx_req_state, uint32_t, active_btree, diff_btree);
ENUM(hs_cp_state, uint32_t, init, preparing, flushing_indx_tbl, flushing_blkalloc, flushing_sb, notify_user, done);

struct hs_cp : cp_base {
    /* This list is not lock protected. */
    std::map< boost::uuids::uuid, indx_cp_ptr > indx_cp_list;
    std::shared_ptr< blkalloc_cp > ba_cp;
    hs_cp_state hs_state;

    sisl::atomic_counter< uint64_t > ref_cnt; // cnt of how many cps are triggered
    uint64_t snt_cnt;
    bool blkalloc_checkpoint = false; // it is set to true in prepare flush stage
};

struct indx_active_cp {
    seq_id_t start_seqid{-1}; // not inclusive
    seq_id_t end_seqid{-1};   // inclusive
    btree_cp_ptr bcp;
    indx_active_cp(const seq_id_t start_seqid) : start_seqid{start_seqid} {}
    std::string to_string() const {
        return fmt::format("start_seqid={} end_seqid={} btree_cp_info=[{}] ", start_seqid, end_seqid, bcp->to_string());
    }
};

struct indx_diff_cp {
    seq_id_t start_seqid{-1}; // not inclusive
    seq_id_t end_seqid{-1};   // inclusive
    indx_tbl* diff_tbl{nullptr};
    seq_id_t diff_snap_id{-1};
    btree_cp_ptr bcp;
    indx_diff_cp(const seq_id_t start_seqid) : start_seqid{start_seqid} {}
    std::string to_string() const {
        return fmt::format("start_seqid={} end_seqid={} diff_snap_id={} btree_cp_info=[{}]", start_seqid, end_seqid,
                           diff_snap_id, (bcp ? bcp->to_string() : ""));
    }
};

/* During prepare flush we decide to take a CP out of active, diff or snap or all 3 cps*/
struct indx_cp : public boost::intrusive_ref_counter< indx_cp > {
    indx_mgr_ptr indx_mgr;
    int flags{indx_cp_state::active_cp};
    seq_id_t max_seqid{-1}; // max seqid sent on this id

    /* metrics */
    int64_t cp_id;
    std::atomic< int64_t > indx_size;

    /* cp */
    indx_active_cp acp;
    indx_diff_cp dcp;

    std::vector< blkid_list_ptr > user_free_blkid_list; // this blkid list is freed by the user. It is not part of any
                                                        // cp. user first collect it and then later it attaches the list
                                                        // to a cp.

    blkid_list_ptr io_free_blkid_list; // list of blk ids freed in a cp

    indx_cp(const int64_t cp_id, const seq_id_t start_active_seqid, const seq_id_t start_diff_seqid,
            indx_mgr_ptr indx_mgr, blkid_list_ptr& io_free_blkid_list) :
            indx_mgr{indx_mgr},
            cp_id{cp_id},
            indx_size{0},
            acp{start_active_seqid},
            dcp{start_diff_seqid},
            io_free_blkid_list{io_free_blkid_list} {}

    int state() const { return flags; }
    seq_id_t get_max_seqid() const { return 0; }
    void set_max_seqid(const seq_id_t seqid){};

    std::string to_string() const {
        return fmt::format(
            "Flags={} indx_cp_id={} indx_size={} active_checkpoint=[{}] diff_checkpoint=[{}] size_freed={} "
            "user_size_freed={}",
            flags, cp_id, indx_size, acp.to_string(), dcp.to_string(), io_free_blkid_list->size(),
            user_free_blkid_list.size());
    }
};

/************************************************ Superblock ***************************************************/

/* super bcp persisted for each CP */
/* it contains the seqid from which journal has to be replayed. */
static constexpr uint32_t hcp_version{0x1};
static constexpr uint64_t hcp_magic{0xbedabb1e};
static constexpr uint32_t indx_sb_version{0x1};
ENUM(indx_meta_hdr_type, uint32_t, cp, destroy, unmap, snap_destroy);

#pragma pack(1)
struct hs_cp_base_sb {
    uint64_t magic{hcp_magic};
    uint32_t version{hcp_version};
    uint32_t size;
    boost::uuids::uuid uuid; // Don't populate if it is hs indx meta blk
    indx_meta_hdr_type type;
    uint8_t padding[4];
};

struct hs_cp_unmap_sb : hs_cp_base_sb {
    seq_id_t seq_id;
    uint32_t key_size;
    uint8_t padding[4];
};

struct hs_cp_sb : hs_cp_base_sb {
    uint32_t indx_cnt;
    uint8_t padding[4];
};

struct indx_cp_sb {
    int64_t blkalloc_cp_id{-1}; // cp cnt of last blkalloc checkpoint taken
    int64_t indx_size{0};

    /* active cp info */
    int64_t active_cp_id{-1};
    seq_id_t active_data_seqid{-1};

    /* diff cp info */
    int64_t diff_cp_id{-1};
    seq_id_t diff_data_seqid{-1};
    seq_id_t diff_max_seqid{-1};
    int64_t diff_snap_id{-1};
    uint32_t snap_cp{0};
    uint8_t padding[4];

    seq_id_t get_active_data_seqid() const { return active_data_seqid; }
};

struct indx_cp_base_sb {
    boost::uuids::uuid uuid;
    indx_cp_sb icp_sb;  // indx cp superblock
    btree_cp_sb acp_sb; // active cp superblock
    btree_cp_sb dcp_sb; // diff cp_superblock
    indx_cp_base_sb(const boost::uuids::uuid uuid) : uuid{uuid} {};
    indx_cp_base_sb(){};
    std::string to_string() const {
        return fmt::format("active_cp_cnt={} active_data_seqid={} diff_cp_cnt={} diff_data_seqid={} blkalloc_cp_id={} "
                           "indx_size={} btree acp={}",
                           icp_sb.active_cp_id, icp_sb.active_data_seqid, icp_sb.diff_cp_id, icp_sb.diff_data_seqid,
                           icp_sb.blkalloc_cp_id, icp_sb.indx_size, acp_sb.to_string());
    }
};

/* this superblock is never changed once indx manager is created */
struct indx_mgr_sb {
    uint32_t version{indx_sb_version};
    logstore_id_t journal_id{0};
    homeds::btree::btree_super_block btree_sb;
    uint32_t is_snap_enabled{0};
    indx_mgr_sb(const homeds::btree::btree_super_block btree_sb, const logstore_id_t journal_id,
                const bool is_snap_enabled) :
            journal_id{journal_id},
            btree_sb{btree_sb},
            is_snap_enabled{static_cast< uint32_t >(is_snap_enabled ? 0x1 : 0x0)} {}
    indx_mgr_sb() = default;
};
#pragma pack()

class CPWatchdog {
public:
    CPWatchdog();
    void cp_reset();
    void set_cp(hs_cp* const cp);
    void cp_watchdog_timer();
    void stop();

private:
    /* watchdog CP stats */
    std::shared_mutex m_cp_mtx;
    hs_cp* m_cp;
    hs_cp_state m_last_hs_state;
    iomgr::timer_handle_t m_timer_hdl;
    Clock::time_point last_state_ch_time;
    uint64_t m_timer_sec{0};
};

class HomeStoreCPMgr : public CPMgr< hs_cp > {
    CPWatchdog m_wd_cp;

public:
    HomeStoreCPMgr();
    HomeStoreBaseSafePtr m_hs{HomeStoreBase::safe_instance()};

    void try_cp_trigger(hs_cp* const hcp);
    virtual void cp_start(hs_cp* const hcp);
    virtual void cp_attach_prepare(hs_cp* const cur_hcp, hs_cp* const new_hcp);
    virtual ~HomeStoreCPMgr();
    virtual void shutdown() override;
    virtual void cp_reset(hs_cp* const cp) override;

    void try_cp_start(hs_cp* const hcp);
    void indx_tbl_cp_done(hs_cp* const hcp);
    void blkalloc_cp_start(hs_cp* const hcp);
    void write_hs_cp_sb(hs_cp* const hcp);
};

/************************************************ Indx table *****************************************/
class indx_tbl {
    /* these virtual functions should be defined by the consumer */
public:
    /* It is called when its btree consumer has successfully stored the btree superblock */
    virtual ~indx_tbl() = default;
    virtual void create_done() = 0;
    virtual homeds::btree::btree_super_block get_btree_sb() = 0;
    virtual btree_status_t update_active_indx_tbl(const indx_req_ptr& ireq, const btree_cp_ptr& bcp) = 0;
    virtual btree_status_t read_indx(const indx_req_ptr& ireq, const read_indx_comp_cb_t& cb) = 0;
    virtual btree_status_t update_diff_indx_tbl(const indx_req_ptr& ireq, const btree_cp_ptr& bcp) = 0;
    virtual btree_cp_ptr attach_prepare_cp(const btree_cp_ptr& cur_bcp, bool is_last_cp,
                                           const bool blkalloc_checkpoint) = 0;
    virtual void flush_free_blks(const btree_cp_ptr& bcp, std::shared_ptr< blkalloc_cp >& ba_cp) = 0;
    virtual void update_btree_cp_sb(const btree_cp_ptr& bcp, btree_cp_sb& btree_sb, const bool is_blkalloc_cp) = 0;
    virtual void truncate(const btree_cp_ptr& bcp) = 0;
    virtual btree_status_t destroy(blkid_list_ptr& free_blkid_list, uint64_t& free_node_cnt) = 0;
    virtual void destroy_done() = 0;
    virtual void cp_start(const btree_cp_ptr& bcp, cp_comp_callback cb) = 0;
    virtual btree_status_t recovery_update(const logstore_seq_num_t seqnum, journal_hdr* const hdr,
                                           const btree_cp_ptr& bcp) = 0;
    virtual void update_indx_alloc_blkids(const indx_req_ptr& ireq) = 0;
    virtual uint64_t get_used_size() const = 0;
    virtual btree_status_t free_user_blkids(blkid_list_ptr free_list, homeds::btree::BtreeQueryCursor& cur,
                                            int64_t& size) = 0;
    virtual void get_btreequery_cur(const sisl::blob& b, homeds::btree::BtreeQueryCursor& cur) = 0;
    virtual btree_status_t update_oob_unmap_active_indx_tbl(blkid_list_ptr free_list, const seq_id_t seq_id, void* key,
                                                            homeds::btree::BtreeQueryCursor& cur,
                                                            const btree_cp_ptr& bcp, int64_t& size,
                                                            const bool force) = 0;
    virtual uint64_t get_btree_node_cnt() = 0;
    virtual std::string get_cp_flush_status(const btree_cp_ptr& bcp) = 0;
};

typedef std::function< void(const boost::intrusive_ptr< indx_req >& ireq, std::error_condition err) > io_done_cb;
typedef std::function< indx_tbl*() > create_indx_tbl;
typedef std::function< indx_tbl*(homeds::btree::btree_super_block& sb, btree_cp_sb& cp_info) > recover_indx_tbl;
ENUM(indx_recovery_state, uint8_t, create_sb_st, create_indx_tbl_st, create_first_cp_st, io_replay_st,
     meta_ops_replay_st);

/************************************ Static indx manager *****************************************/
/* this class defines all the static members of indx_mgr */
class StaticIndxMgr {
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

    /* create new indx mgr cp for all the indx mgr and also decide what indx mgr want to participate in a cp
     * @params cur_icp :- current indxmgr cp map
     *         new_icp :- new cp map
     *         cur_hcp :- home blks cp
     *         new_hcp :- new home blks cp
     */

    static void attach_prepare_indx_cp_list(std::map< boost::uuids::uuid, indx_cp_ptr >* const cur_icp,
                                            std::map< boost::uuids::uuid, indx_cp_ptr >* const new_icp,
                                            hs_cp* const cur_hcp, hs_cp* const new_hcp);
    /* trigger hs cp. It first trigger a indx mgr cp followed by blkalloc cp. It is async call.
     * @params cb :- callback when cp is done.
     * @shutdown :- true if it is called by shutdown. This flag makes sure that no other cp is triggered after shutdown
     * cp.
     * @force :- it force another CP if a cp is in progress
     */
    static void trigger_hs_cp(const cp_done_cb& cb = nullptr, const bool shutdown = false, const bool force = false);

    /* trigger indx mgr CP. It doesn't persist blkalloc */
    static void trigger_indx_cp();
    static void trigger_indx_cp_with_cb(const cp_done_cb& cb);

    /* reinitialize indx mgr. It is used in fake reboot */
    static void fake_reboot() {
        MetaBlkMgrSI()->register_handler("INDX_MGR_CP", StaticIndxMgr::meta_blk_found_cb, nullptr);
    }
    static void cp_done(const bool blkalloc_cp);
    /* It registers a callback which is triggered at the end of cp.
     * @params cp_done_cb :- callback
     * @params blkalloc_cp :- true :- it is called for every blkalloc cp
     *                        false :- it is called for every indx cp.
     */
    static void register_hs_cp_done_cb(const cp_done_cb& cb, bool const blkalloc_cp = false);
    static void write_hs_cp_sb(hs_cp* const hcp);
    static const iomgr::io_thread_t& get_thread_id() { return m_thread_id; }
    static void meta_blk_found_cb(meta_blk* const mblk, const sisl::byte_view buf, const size_t size);
    static void flush_hs_free_blks(hs_cp* const hcp);
    static void write_meta_blk(void*& mblk, const sisl::byte_array& buf);

    /* This api insert the free blkids in out_free_list.
     * 1. This api only make sure that  we are not accumulating more then the threshhold.
     * 2. It make sure that CP doesn't happen if there is a pending read on the same blkid.
     *
     * User can fail freeing blkid even after calling this api as it doesn't actually free the blkids.
     *
     * @params
     * @hcp :- homestore ID to which out_free_list is supposed to attached. If hcp is null then it takes the latest
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
    static uint64_t free_blk(hs_cp* const hcp, blkid_list_ptr& out_fblk_list,
                             std::vector< Free_Blk_Entry >& in_fbe_list, const bool force,
                             const indx_req* const ireq = nullptr);
    static uint64_t free_blk(hs_cp* const hcp, sisl::ThreadVector< homestore::BlkId >* const out_fblk_list,
                             std::vector< Free_Blk_Entry >& in_fbe_list, const bool force,
                             const indx_req* const ireq = nullptr);
    static uint64_t free_blk(hs_cp* const hcp, blkid_list_ptr& out_fblk_list, Free_Blk_Entry& fbe, const bool force,
                             const indx_req* const ireq = nullptr);
    static uint64_t free_blk(hs_cp* const hcp, sisl::ThreadVector< homestore::BlkId >* const out_fblk_list,
                             Free_Blk_Entry& fbe, const bool force, const indx_req* const ireq = nullptr);

    static void add_read_tracker(const Free_Blk_Entry& bid);
    static void remove_read_tracker(const Free_Blk_Entry& fbe);
    static void hs_cp_suspend();
    static void hs_cp_resume();

protected:
    /*********************** static private members **********************/
    static std::unique_ptr< HomeStoreCPMgr > m_cp_mgr;
    static std::atomic< bool > m_shutdown_started;
    static bool m_shutdown_cmplt;
    static iomgr::io_thread_t m_thread_id;
    static iomgr::io_thread_t m_slow_path_thread_id;
    static iomgr::timer_handle_t m_hs_cp_timer_hdl;
    static void* m_cp_meta_blk;
    static std::once_flag m_flag;
    static std::map< boost::uuids::uuid, indx_cp_base_sb > cp_sb_map;
    static std::map< boost::uuids::uuid, std::vector< std::pair< void*, sisl::byte_array > > > indx_meta_map;
    static HomeStoreBaseSafePtr m_hs; // Hold onto the home store to maintain reference
    static uint64_t memory_used_in_recovery;
    static std::atomic< bool > m_inited;
    static std::mutex cb_list_mtx;
    /* It is called for after every indx cp */
    static std::vector< cp_done_cb > indx_cp_done_cb_list;
    /* it is  called after every homestore cp */
    static std::vector< cp_done_cb > hs_cp_done_cb_list;
    static std::atomic< bool > try_blkalloc_checkpoint; // set to true if next checkpoint should be blkalloc
    static std::unique_ptr< Blk_Read_Tracker > m_read_blk_tracker;

    /************************ static private functions **************/
    static void init();
    /* it frees the blks and insert it in cp free blk list. It is called when there is no read pending on this blk */
    static void safe_to_free_blk(const Free_Blk_Entry& fbe);
};

class IndxMgrMetrics : public sisl::MetricsGroupWrapper {
public:
    explicit IndxMgrMetrics(const char* const indx_name) : sisl::MetricsGroupWrapper{"Index", indx_name} {
        REGISTER_COUNTER(indx_unmap_async_count, "Total number of async unmaps");
        register_me_to_farm();
    }

    IndxMgrMetrics(const IndxMgrMetrics&) = delete;
    IndxMgrMetrics(IndxMgrMetrics&&) noexcept = delete;
    IndxMgrMetrics& operator=(const IndxMgrMetrics&) = delete;
    IndxMgrMetrics& operator=(const IndxMgrMetrics&&) noexcept = delete;
    ~IndxMgrMetrics() { deregister_me_from_farm(); }
};

/************************************************* Indx Mgr *************************************/
class IndxMgr : public StaticIndxMgr, public std::enable_shared_from_this< IndxMgr > {

public:
    /* It is called in first time create.
     * @params io_cb :- it is used to send callback with io is completed
     * @params recovery_mode :- true :- it is recovery
     *                          false :- it is first time create
     * @params func :- function to create indx table
     */
    IndxMgr(const boost::uuids::uuid uuid, std::string name, const io_done_cb& io_cb,
            const read_indx_comp_cb_t& read_cb, const create_indx_tbl& func, const bool is_snap_enabled);

    /* constructor for recovery */
    IndxMgr(const boost::uuids::uuid uuid, std::string name, const io_done_cb& io_cb,
            const read_indx_comp_cb_t& read_cb, const create_indx_tbl& create_func,
            const recover_indx_tbl& recover_func, indx_mgr_sb sb);

    virtual ~IndxMgr();

    /* create new indx cp id and decide if this indx mgr want to participate in a current cp
     * @params cur_icp :- current cp id of this indx mgr
     * @params cur_hcp :- current cp of home_blks
     * @params new_hcp :- new home blks cp cp
     * @return :- return new cp cp.
     */
    indx_cp_ptr attach_prepare_indx_cp(const indx_cp_ptr& cur_icp, hs_cp* const cur_hcp, hs_cp* const new_hcp);

    /* Get the active indx table
     * @return :- active indx_tbl instance
     */
    indx_tbl* get_active_indx();

    /* write/update indx table for a IO
     * @params req :- It create all information to update the indx mgr and journal
     */
    void update_indx(const indx_req_ptr& ireq);

    /**
     * @brief : read and return indx mapping for a IO
     * @param ireq
     * @param cb : it is used to send callback when read is completed.
     * The cb will be passed by mapping layer and triggered after read completes;
     * @return : error condition whether read is success or not;
     */
    void read_indx(const indx_req_ptr& ireq);

    /* Create snapshot. */
    void indx_snap_create();
    /* Get immutable superblock
     * @return :- get static superblock of indx mgr. It is immutable structure. It contains all infomation require to
     *            recover active and diff indx tbl.
     */
    indx_mgr_sb get_immutable_sb();

    /* Destroy all indexes and call homestore level cp to persist. It assumes that all ios are stopped by indx mgr.
     * It is async call. It is called only once
     * @params cb :- callback when destroy is done.
     */
    void destroy(const indxmgr_stop_cb& cb);

    /* truncate journal */
    void truncate(const indx_cp_ptr& icp);

    /* indx mgr is destroy successfully */
    void destroy_done();

    /* It creates all the indx tables and intialize checkpoint */
    void recovery();
    void io_replay();

    /* it flushes free blks to blk allocator */
    void flush_free_blks(const indx_cp_ptr& icp, hs_cp* const hcp);

    void update_cp_sb(indx_cp_ptr& icp, hs_cp* const hcp, indx_cp_base_sb* const sb);
    seq_id_t get_max_seqid_found_in_recovery() const;
    /* It is called when super block all indx tables are persisted by its consumer */
    void indx_create_done(indx_tbl* const indx_tbl = nullptr);
    void indx_init(); // private api
    std::string get_name() const;
    cap_attrs get_used_size() const;
    void attach_user_fblkid_list(blkid_list_ptr& free_blkid_list, const cp_done_cb& free_blks_cb,
                                 const int64_t free_size, const bool last_cp = false);

    /* It registers a callback which is triggered at the end of cp.
     * @params cp_done_cb :- callback
     * @params blkalloc_cp :- true :- it is called for every blkalloc cp
     *                        false :- it is called for every indx cp.
     */
    void register_indx_cp_done_cb(const cp_done_cb& cb, const bool blkalloc_cp = false);
    /* unmap api called by volume layer */
    void unmap(const indx_req_ptr& ireq);
    hs_cp* cp_io_enter();
    void cp_io_exit(hs_cp* const cp);
    btree_cp_ptr get_btree_cp(hs_cp* const hcp);
    bool is_recovery_done() const;
    std::string get_cp_flush_status(const indx_cp_ptr& icp);

protected:
    /*********************** virtual functions required to support snapshot  **********************/
    /* These functions are defined so that indx mgr can be used without snapmagr */
    virtual int64_t snap_create(indx_tbl* const m_diff_tbl, const int64_t start_cp_id) {
        assert(false);
        return -1;
    }
    virtual int64_t snap_get_diff_id() {
        assert(false);
        return -1;
    }
    virtual void snap_create_done(const uint64_t snap_id, const seq_id_t max_seqid, const seq_id_t contiguous_seqid,
                                  const int64_t end_cp_id) {
        assert(false);
    }
    virtual homeds::btree::btree_super_block snap_get_diff_tbl_sb() {
        assert(false);
        homeds::btree::btree_super_block sb;
        return sb;
    }

private:
    indx_tbl* m_active_tbl;
    io_done_cb m_io_cb;
    read_indx_comp_cb_t m_read_cb;
    std::shared_ptr< HomeLogStore > m_journal;
    log_req_comp_cb_t m_journal_comp_cb;

    /* we can not add a indx mgr in active CP. It can be added only when a new cp is created. indx mgr keeps
     * on using this cp until new cp is not created. Once a new cp is created, it will become a part of it.
     */
    static constexpr size_t MAX_CP_CNT{2};
    indx_cp_ptr m_first_icp;
    boost::uuids::uuid m_uuid;
    std::string m_name;
    indx_mgr_state m_state{indx_mgr_state::ONLINE};
    indxmgr_stop_cb m_destroy_done_cb;
    bool m_last_cp{false};

    std::shared_mutex m_prepare_cb_mtx;
    std::unique_ptr< std::vector< prepare_cb > > m_prepare_cb_list;
    blkid_list_ptr m_free_list[MAX_CP_CNT];
    indx_cp_base_sb m_last_cp_sb;
    std::map< logstore_seq_num_t, log_buffer > seq_buf_map; // used only in recovery
    std::atomic< bool > m_recovery_mode{false};
    indx_recovery_state m_recovery_state{indx_recovery_state::create_sb_st};
    create_indx_tbl m_create_indx_tbl;
    recover_indx_tbl m_recover_indx_tbl;
    indx_mgr_sb m_immutable_sb;
    uint64_t m_free_list_cnt{0};
    bool m_is_snap_enabled{false};
    bool m_is_snap_started{false};
    void* m_destroy_meta_blk{nullptr};
    homeds::btree::BtreeQueryCursor m_destroy_btree_cur;
    seq_id_t m_max_seqid_in_recovery{-1};
    std::atomic< bool > m_active_cp_suspend{false};
    IndxMgrMetrics m_metrics;

    /*************************************** private functions ************************/
    void update_indx_internal(const indx_req_ptr& ireq);
    void journal_write(const indx_req_ptr& ireq);
    void journal_comp_cb(logstore_req* const req, const logdev_key ld_key);
    btree_status_t update_indx_tbl(const indx_req_ptr& ireq, const bool is_active);
    indx_cp_ptr get_indx_cp(hs_cp* const hcp);
    void destroy_indx_tbl();
    void add_prepare_cb_list(const prepare_cb& cb);
    /* It registers a callback which is triggered at the end of cp.
     * @params cp_done_cb :- callback
     * @params blkalloc_cp :- true :- it is called for every blkalloc cp
     *                        false :- it is called for every indx cp.
     */
    static void register_hs_cp_done_cb(const cp_done_cb& cb, const bool blkalloc_cp = false);
    void indx_destroy_cp(const indx_cp_ptr& cur_icp, hs_cp* const cur_hcp, hs_cp* const new_hcp);
    void create_first_cp();
    btree_status_t retry_update_indx(const indx_req_ptr& ireq, const bool is_active);
    void run_slow_path_thread();
    void create_new_diff_tbl(indx_cp_ptr& icp);
    void recover_meta_ops();
    void log_found(const logstore_seq_num_t seqnum, const log_buffer buf, void* const mem);
    void on_replay_done(std::shared_ptr< HomeLogStore > store, const logstore_seq_num_t upto_lsn);
    void set_indx_cp_state(const indx_cp_ptr& cur_icp, hs_cp* const cur_hcp);
    void call_prepare_cb(const indx_cp_ptr& cur_icp, hs_cp* const cur_hcp, hs_cp* const new_hcp);
    indx_cp_ptr create_new_indx_cp(const indx_cp_ptr& cur_icp);
    void resume_active_cp();
    void suspend_active_cp();
    sisl::byte_array alloc_unmap_sb(const uint32_t key_size, const seq_id_t seq_id,
                                    homeds::btree::BtreeQueryCursor& unmap_btree_cur);
#ifndef NDEBUG
    void dump_free_blk_list(const blkid_list_ptr& free_blk_list);
#endif
    void unmap_indx_async(const indx_req_ptr& ireq);
    void do_remaining_unmap_internal(void* unmap_meta_blk_cntx, const sisl::byte_array& key, const seq_id_t seqid,
                                     const std::shared_ptr< homeds::btree::BtreeQueryCursor >& btree_cur);
    void do_remaining_unmap(void* unmap_meta_blk_cntx, const sisl::byte_array& key, const seq_id_t seqid,
                            const std::shared_ptr< homeds::btree::BtreeQueryCursor >& btree_cur);
    void write_cp_unmap_sb(void*& unmap_meta_blk_cntx, const uint32_t key_size, const seq_id_t seq_id,
                           homeds::btree::BtreeQueryCursor& unmap_btree_cur, const uint8_t* const key);

    void free_blkid_and_send_completion(const indx_req_ptr& ireq);
};

/*************************************************** indx request ***********************************/

struct Free_Blk_Entry {
    /* These entries are needed only to invalidate cache. We store the actual blkid in journal */
    BlkIdView m_blkid_view;
    hs_cp* m_hcp = nullptr;

    Free_Blk_Entry() {}
    Free_Blk_Entry(const BlkId& blkid) : m_blkid_view{blkid, 0u, 0u} {}
    Free_Blk_Entry(const BlkId& blkid, const blk_count_t blk_offset, const blk_count_t nblks_to_free) :
            m_blkid_view{blkid, blk_offset, nblks_to_free} {
#ifndef NDEBUG
        assert(blk_offset + nblks_to_free <= blkid.get_nblks());
#endif
    }

    BlkId get_base_blkid() const { return m_blkid_view.get_blkid(); }
    uint8_t blk_offset() const { return m_blkid_view.get_view_offset(); }
    uint8_t blks_to_free() const { return m_blkid_view.get_view_nblks(); }
    BlkId get_free_blkid() const { return m_blkid_view.get_view_blkid(); }

    std::string to_string() const {
        return fmt::format("Base blkid={} view/free blkid={}", get_base_blkid(), get_free_blkid());
    }
};

/* any consumer req should be derived from indx_mgr_req. Indx mgr use this as a context to call consumer APIs */
struct indx_req : public sisl::ObjLifeCounter< indx_req > {
public:
    virtual uint32_t get_key_size() const = 0;
    virtual uint32_t get_val_size() const = 0;
    virtual void fill_key(void* const mem, const uint32_t size) = 0;
    virtual void fill_val(void* const mem, const uint32_t size) = 0;
    virtual seq_id_t get_seqid() const = 0;
    virtual uint32_t get_io_size() const = 0;
    virtual void free_yourself() = 0;
    virtual bool is_io_completed() const = 0;

public:
    indx_req(const uint64_t request_id, const Op_type op_type_) : request_id{request_id}, op_type{op_type_} {}
    virtual ~indx_req() = default;
    indx_req(const indx_req&) = delete;
    indx_req(indx_req&&) noexcept = delete;
    indx_req& operator=(const indx_req&) = delete;
    indx_req& operator=(indx_req&&) noexcept = delete;

    sisl::io_blob create_journal_entry() { return j_ent.create_journal_entry(this); }

    void push_indx_alloc_blkid(const BlkId& bid) { indx_alloc_blkid_list.push_back(bid); }

    /* it is used by mapping/consumer to push fbe to free list. These blkds will be freed when entry is completed */
    void indx_push_fbe(std::vector< Free_Blk_Entry >& in_fbe_list) {
        indx_fbe_list.insert(indx_fbe_list.end(), in_fbe_list.begin(), in_fbe_list.end());
    }

    friend void intrusive_ptr_add_ref(indx_req* const req) { req->ref_count.increment(1); }
    friend void intrusive_ptr_release(indx_req* const req) {
        if (req->ref_count.decrement_testz(1)) { req->free_yourself(); }
    };
    void inc_ref() { intrusive_ptr_add_ref(this); }

    /* Op type getters */
    bool is_read() const { return op_type == Op_type::READ; }
    bool is_write() const { return op_type == Op_type::WRITE; }
    bool is_unmap() const { return op_type == Op_type::UNMAP; }
    void get_btree_cursor(homeds::btree::BtreeQueryCursor& unmap_btree_cur) {
        unmap_btree_cur.m_last_key = std::move(active_btree_cur.m_last_key);
        unmap_btree_cur.m_locked_nodes = std::move(active_btree_cur.m_locked_nodes);
    }

    virtual std::string to_string() const = 0;

public:
    bool resource_full_check{false}; // we don't return error for all ios. we set it for trim,
    // destroy which can handle io failures and retry
    indx_journal_entry j_ent;
    std::vector< BlkId > indx_alloc_blkid_list;
    std::vector< Free_Blk_Entry > indx_fbe_list;
    hs_cp* first_hcp{nullptr};
    hs_cp* hcp{nullptr};
    indx_cp_ptr icp{nullptr};
    sisl::atomic_counter< int > ref_count{1}; // Initialize the count
    std::error_condition indx_err{no_error};
    indx_req_state state{indx_req_state::active_btree};
    uint64_t request_id; // Copy of the id from interface request
    Op_type op_type;     // Copy of the op type (read/write/unmap) from interface request
    homeds::btree::BtreeQueryCursor active_btree_cur;
    homeds::btree::BtreeQueryCursor diff_btree_cur;
    homeds::btree::BtreeQueryCursor read_cur;
};

} // namespace homestore
