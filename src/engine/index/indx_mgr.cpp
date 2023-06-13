/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 *********************************************************************************/
#include <csignal>
#include <cstring>
#include <iterator>
#include <shared_mutex>

#include <sisl/utility/thread_factory.hpp>

#include <engine/homeds/btree/btree.hpp>

#include <homelogstore/log_store.hpp>

#include "blk_read_tracker.hpp"
#include "indx_mgr.hpp"
#include "engine/common/resource_mgr.hpp"
#include "engine/homestore.hpp"
#include "test_common/homestore_test_common.hpp"

using namespace homestore;
namespace homestore {
bool vol_test_run{false};
}

SISL_LOGGING_DECL(indx_mgr)

/* Journal entry
 * --------------------------------------------------------------------
 * | Journal Hdr | alloc_blkid list | checksum list | free_blk_entry |
 * -------------------------------------------------------------------
 */
indx_journal_entry::~indx_journal_entry() { m_iob.buf_free(sisl::buftag::data_journal); }

uint32_t indx_journal_entry::size(indx_req* const ireq) const {
    return (sizeof(journal_hdr) + ireq->indx_alloc_blkid_list.size() * sizeof(BlkId) +
            ireq->indx_fbe_list.size() * sizeof(BlkId) + ireq->get_key_size() + ireq->get_val_size());
}

uint32_t indx_journal_entry::size() const {
    HS_DBG_ASSERT_NE(m_iob.bytes, nullptr);
    auto* const hdr{get_journal_hdr(m_iob.bytes)};
    return (sizeof(journal_hdr) + hdr->alloc_blkid_list_size * sizeof(BlkId) +
            hdr->free_blk_entry_size * sizeof(BlkId) + hdr->key_size + hdr->val_size);
}

/* it update the alloc blk id and checksum */
sisl::io_blob indx_journal_entry::create_journal_entry(indx_req* const ireq) {
    const uint32_t size{static_cast< uint32_t >(
        sizeof(journal_hdr) + ireq->indx_alloc_blkid_list.size() * sizeof(BlkId) +
        ireq->indx_fbe_list.size() * sizeof(BlkId) + ireq->get_key_size() + ireq->get_val_size())};
    // TO DO: Might need to address alignment based on data or fast type
    m_iob = hs_utils::create_io_blob(size, HomeLogStoreMgr::data_logdev().is_aligned_buf_needed(size),
                                     sisl::buftag::data_journal, HomeLogStoreMgr::data_logdev().get_align_size());

    uint8_t* mem = m_iob.bytes;

    /* store journal hdr */
    auto* const hdr{get_journal_hdr(mem)};
    hdr->alloc_blkid_list_size = ireq->indx_alloc_blkid_list.size();
    hdr->free_blk_entry_size = ireq->indx_fbe_list.size();
    hdr->key_size = ireq->get_key_size();
    hdr->val_size = ireq->get_val_size();
    /* store cp related info */
    hdr->cp_id = ireq->icp->cp_id;

    /* store alloc blkid */
    auto blkid_pair{get_alloc_bid_list(mem)};
    auto* const blkid{blkid_pair.first};
    for (uint32_t i{0}; i < blkid_pair.second; ++i) {
        blkid[i] = ireq->indx_alloc_blkid_list[i];
    }

    /* store free blk entry */
    auto fbe_pair{get_free_bid_list(mem)};
    auto* const fbe{fbe_pair.first};
    for (uint32_t i{0}; i < fbe_pair.second; ++i) {
        fbe[i] = ireq->indx_fbe_list[i].get_free_blkid();
    }

    /* store key */
    auto key_pair{get_key(mem)};
    ireq->fill_key(key_pair.first, key_pair.second);

    /* store val */
    auto val_pair{get_val(mem)};
    ireq->fill_val(val_pair.first, val_pair.second);

    return m_iob;
}

/****************************************** cp watchdog class ***********************************/
CPWatchdog::CPWatchdog() {
    m_timer_sec = HS_DYNAMIC_CONFIG(generic.cp_watchdog_timer_sec);

#ifdef _PRERELEASE
    const auto timer_sec_ptr = std::getenv(CP_WATCHDOG_TIMER_SEC.c_str());
    if (timer_sec_ptr) { m_timer_sec = std::stoi(std::getenv(CP_WATCHDOG_TIMER_SEC.c_str())); }
#endif

    LOGINFO("CP watchdog timer setting to : {} seconds", m_timer_sec);
    m_timer_hdl =
        iomanager.schedule_global_timer(m_timer_sec * 1000 * 1000 * 1000, true, nullptr, iomgr::thread_regex::all_user,
                                        [this](void* cookie) { cp_watchdog_timer(); });
    cp_reset();
}

void CPWatchdog::cp_reset() {
    std::unique_lock< std::shared_mutex > lk{m_cp_mtx};
    m_cp = nullptr;
    m_last_hs_state = hs_cp_state::init;
}

void CPWatchdog::set_cp(hs_cp* cp) {
    std::unique_lock< std::shared_mutex > lk{m_cp_mtx};
    m_cp = cp;
    m_last_hs_state = m_cp->hs_state;
    last_state_ch_time = Clock::now();
}

void CPWatchdog::stop() {
    //    iomanager.cancel_timer(m_timer_hdl);
    m_timer_hdl = iomgr::null_timer_handle;
    {
        std::unique_lock< std::shared_mutex > lk{m_cp_mtx};
        m_cp = nullptr;
    }
}

void CPWatchdog::cp_watchdog_timer() {
    std::unique_lock< std::shared_mutex > lk{m_cp_mtx};

    // check if any cp to track
    if (!m_cp || (m_cp->hs_state == hs_cp_state::init) || (m_cp->hs_state == hs_cp_state::done)) { return; }

    // state is changed. Return;
    if (m_last_hs_state != m_cp->hs_state) {
        m_last_hs_state = m_cp->hs_state;
        last_state_ch_time = Clock::now();
        return;
    }

    std::string s;
    for (auto& icp_uuid : m_cp->indx_cp_list) {
        auto& icp = icp_uuid.second;
        s += icp->indx_mgr->get_cp_flush_status(icp);
    }

    if (get_elapsed_time_ms(last_state_ch_time) >= m_timer_sec * 1000) {
        LOGINFO("cp state {} is not changed. time elapsed {} Printing cp state {} ", m_last_hs_state,
                get_elapsed_time_ms(last_state_ch_time), s);
    }

    // check if enough time passed since last state change
    uint32_t max_time_multiplier = 12;
    if (get_elapsed_time_ms(last_state_ch_time) < max_time_multiplier * m_timer_sec * 1000) {
        if (m_last_hs_state == hs_cp_state::flushing_indx_tbl) {
            // try to increase queue depth to increase cp speed
            ResourceMgrSI().increase_dirty_buf_qd();
        }
        return;
    }

    HS_REL_ASSERT(0, "cp seems to be stuck. current state is {} total time elapsed {}", m_last_hs_state,
                  get_elapsed_time_ms(last_state_ch_time));
}

/****************************************** IndxCP class ****************************************/

/* these are the stages of CP
 * 1. CP Attach :- It creates new index cp and attaches itself to indx cp. attach CP is called when new CP is
 * started. It can not attach itself to current cp when index mgr is created. However, it creates a cp and attaches
 * that CP is when next time attach is called.
 * 2. CP Prepare :- indx mgr and btree decides if it want to participate in a cp_start.
 * 3. CP start :- when all ios on a CP is completed, it start cp flush
 *                      - It flushes the btree dirty buffers
 *                      - When all buffers are dirtied, it flushes the free blks of indx mgr and brree
 * 4. Start blk alloc cp it is scheduled
 * 5. All indx mgr are notified When cp is done. And it writes the superblock
 * 6. cp end :- CP is completed.
 */

HomeStoreCPMgr::HomeStoreCPMgr() : CPMgr{} { cp_reset(nullptr); }

HomeStoreCPMgr::~HomeStoreCPMgr() {}

void HomeStoreCPMgr::shutdown() {
    m_wd_cp.stop();
    m_hs.reset();
    CPMgr< hs_cp >::shutdown();
}

void HomeStoreCPMgr::cp_start(hs_cp* const hcp) {
#ifdef _PRERELEASE
    if (homestore_flip->test_flip("simulate_slow_dirty_buffer")) {
        static thread_local std::random_device rd{};
        static thread_local std::default_random_engine engine{rd()};
        static thread_local std::uniform_int_distribution< uint32_t > dist{0, max_qd_multiplier};
        auto qd = dist(engine);
        for (uint32_t i = 0; i < qd; ++i) {
            ResourceMgrSI().increase_dirty_buf_qd();
        }
    }
#endif
    iomanager.run_on(IndxMgr::get_thread_id(), [this, hcp](const io_thread_addr_t addr) {
        /* persist bit map first */
        if (hcp->indx_cp_list.size()) {
            if (hcp->blkalloc_checkpoint) {
                /* persist alloc blkalloc. It is a sync call */
                blkalloc_cp_start(hcp);
            }
        }
        hcp->hs_state = hs_cp_state::flushing_indx_tbl;
        hcp->ref_cnt.increment(1);
        HS_PERIODIC_LOG(TRACE, cp, "Starting cp of type {}, number of indexes in cp={}, hcp ref_cnt: {}",
                        (hcp->blkalloc_checkpoint ? "blkalloc" : "Index"), hcp->indx_cp_list.size(),
                        hcp->ref_cnt.get());
        for (auto it{std::begin(hcp->indx_cp_list)}; it != std::end(hcp->indx_cp_list); ++it) {
            if ((it->second != nullptr) && (it->second->state() != indx_cp_state::suspend_cp)) {
                ++hcp->snt_cnt;
                hcp->ref_cnt.increment(1);
                auto indx_mgr{it->second->indx_mgr};
                indx_mgr->get_active_indx()->cp_start(
                    it->second->acp.bcp, ([this, hcp](const btree_cp_ptr& bcp) { indx_tbl_cp_done(hcp); }));
                if (it->second->state() & indx_cp_state::diff_cp) {
                    ++hcp->snt_cnt;
                    hcp->ref_cnt.increment(1);
                    it->second->dcp.diff_tbl->cp_start(
                        it->second->dcp.bcp, ([this, hcp](const btree_cp_ptr& bcp) { indx_tbl_cp_done(hcp); }));
                }
            }
        }
        HS_PERIODIC_LOG(TRACE, cp, "number of indexes participated {}", hcp->snt_cnt);
        indx_tbl_cp_done(hcp);
    });
}

void HomeStoreCPMgr::indx_tbl_cp_done(hs_cp* const hcp) {
    if (!hcp->ref_cnt.decrement_testz(1)) {
        HS_PERIODIC_LOG(TRACE, cp, "return because of hcp ref_cnt: {}", hcp->ref_cnt.get());
        return;
    }

    iomanager.run_on(IndxMgr::get_thread_id(),
                     ([this, hcp](const io_thread_addr_t addr) { indx_tbl_cp_done_internal(hcp); }));
}

void HomeStoreCPMgr::indx_tbl_cp_done_internal(hs_cp* const hcp) {
    HS_PERIODIC_LOG(TRACE, cp, "Cp of type {} is completed", (hcp->blkalloc_checkpoint ? "blkalloc" : "Index"));
    if (hcp->indx_cp_list.size()) {
        if (hcp->blkalloc_checkpoint) {
            /* persist alloc blkalloc. It is a sync call */
            blkalloc_cp_done(hcp);
        } else {
            /* All dirty buffers are flushed. Write super block */
            write_hs_cp_sb(hcp);
        }
    }

    const bool is_blkalloc_cp{hcp->blkalloc_checkpoint};
    hcp->hs_state = hs_cp_state::notify_user;
    /* hcp will be freed after calling cp_end and indx_mgr might get destroy also */
    /* notify all the subsystems. */
    IndxMgr::cp_done(is_blkalloc_cp);
#ifdef _PRERELEASE
    if (homestore_flip->test_flip("simulate_cp_hung")) {
        LOGINFO("flip set for cp hung");
        return;
    }
#endif
    cp_end(hcp);
}

void HomeStoreCPMgr::blkalloc_cp_start(hs_cp* const hcp) {
    HS_PERIODIC_LOG(TRACE, cp, "Cp of type blkalloc, writing bitmap");
    hcp->hs_state = hs_cp_state::flushing_bitmap;

    /* flush all the blks that are freed in this hcp */
    StaticIndxMgr::flush_hs_free_blks(hcp);

    /* persist blk alloc bit maps */
    m_hs->blkalloc_cp_start(hcp->ba_cp);
#ifdef _PRERELEASE
    if (homestore_flip->test_flip("indx_cp_bitmap_abort")) {
        LOGINFO("aborting because of flip");
        std::raise(SIGKILL);
    }
#endif
}

/* This function calls
 * 1. persist blkalloc superblock
 * 2. write superblock
 * 3. truncate  :- it truncate upto the seq number persisted in this hcp.
 * 4. call cb_list
 * 5. notify blk alloc that cp hcp done
 * 6. call cp_end :- read comments over indxmgr::destroy().
 */
void HomeStoreCPMgr::blkalloc_cp_done(hs_cp* const hcp) {

    HS_PERIODIC_LOG(TRACE, cp, "Cp of type blkalloc, writing super block about cp");
    /* All dirty buffers are flushed. Write super block */
    hcp->hs_state = hs_cp_state::flushing_sb;
    write_hs_cp_sb(hcp);

    /* Now it is safe to truncate as blkalloc bitsmaps are persisted */
    for (auto it{std::begin(hcp->indx_cp_list)}; it != std::end(hcp->indx_cp_list); ++it) {
        if ((it->second == nullptr) || (it->second->flags == indx_cp_state::suspend_cp) ||
            !(it->second->flags & indx_cp_state::ba_cp)) {
            continue;
        }
        it->second->indx_mgr->truncate(it->second);
    }
    HomeLogStoreMgrSI().device_truncate();
#ifdef _PRERELEASE
    if (homestore_flip->test_flip("indx_cp_logstore_truncate_abort")) {
        LOGINFO("aborting because of flip");
        raise(SIGKILL);
    }
#endif
}

void HomeStoreCPMgr::write_hs_cp_sb(hs_cp* const hcp) {
    hcp->hs_state = hs_cp_state::flushing_sb;
    IndxMgr::write_hs_cp_sb(hcp);
}

/* It attaches the new CP and prepare for cur cp flush */
void HomeStoreCPMgr::cp_attach_prepare(hs_cp* const cur_cp, hs_cp* const new_cp) {
    cur_cp->hs_state = hs_cp_state::preparing;
    new_cp->hs_state = hs_cp_state::init;
    cur_cp->cp_prepare_start_time = Clock::now();
    IndxMgr::attach_prepare_indx_cp_list(&cur_cp->indx_cp_list, &new_cp->indx_cp_list, cur_cp, new_cp);
}

void HomeStoreCPMgr::cp_reset(hs_cp* const hcp) {
    m_wd_cp.cp_reset();
    auto* const cp{cp_io_enter()};
    if (!cp) return;
    /* set the next cp to track */
    m_wd_cp.set_cp(cp);
    cp_io_exit(cp);
}

/****************************************** IndxMgr class ****************************************/

IndxMgr::IndxMgr(const boost::uuids::uuid uuid, std::string name, const io_done_cb& io_cb,
                 const read_indx_comp_cb_t& read_cb, const create_indx_tbl& func, const bool is_snap_enabled) :
        m_io_cb{io_cb},
        m_read_cb{read_cb},
        m_uuid{uuid},
        m_name{name},
        m_last_cp_sb{m_uuid},
        m_recovery_mode{false},
        m_create_indx_tbl{func},
        m_is_snap_enabled{is_snap_enabled},
        m_metrics{name.c_str()} {
    m_prepare_cb_list = std::make_unique< std::vector< prepare_cb > >();
    m_prepare_cb_list->reserve(4);
    m_active_tbl = m_create_indx_tbl();

    auto hs = HomeStoreBase::safe_instance();
    m_sobject =
        hs->sobject_mgr()->create_object("index", name, std::bind(&IndxMgr::get_status, this, std::placeholders::_1));

    THIS_INDX_LOG(INFO, indx_mgr, , "Creating new log store for name: {}", name);
    m_journal = HomeLogStoreMgrSI().create_new_log_store(HomeLogStoreMgr::DATA_LOG_FAMILY_IDX, false /* append_mode */);
    m_journal_comp_cb = bind_this(IndxMgr::journal_comp_cb, 2);
    m_journal->register_req_comp_cb(m_journal_comp_cb);
    THIS_INDX_LOG(INFO, indx_mgr, , "log_store id {}", m_journal->get_store_id());
    for (size_t i{0}; i < MAX_CP_CNT; ++i) {
        m_free_list[i] = std::make_shared< sisl::ThreadVector< BlkId > >();
    }
}

/* Constructor for recovery */
IndxMgr::IndxMgr(const boost::uuids::uuid uuid, std::string name, const io_done_cb& io_cb,
                 const read_indx_comp_cb_t& read_cb, const create_indx_tbl& create_func,
                 const recover_indx_tbl& recover_func, indx_mgr_sb sb) :
        m_io_cb{io_cb},
        m_read_cb{read_cb},
        m_uuid{uuid},
        m_name{name},
        m_last_cp_sb{m_uuid},
        m_recovery_mode{true},
        m_create_indx_tbl{create_func},
        m_recover_indx_tbl{recover_func},
        m_immutable_sb{sb},
        m_metrics{name.c_str()} {
    m_journal = nullptr;
    m_prepare_cb_list = std::make_unique< std::vector< prepare_cb > >();
    m_prepare_cb_list->reserve(4);

    auto hs = HomeStoreBase::safe_instance();
    m_sobject =
        hs->sobject_mgr()->create_object("index", name, std::bind(&IndxMgr::get_status, this, std::placeholders::_1));

    HS_REL_ASSERT_EQ(m_immutable_sb.version, indx_sb_version);
    m_is_snap_enabled = sb.is_snap_enabled ? true : false;
    THIS_INDX_LOG(INFO, indx_mgr, , "opening journal id {}", (int)sb.journal_id);
    HomeLogStoreMgrSI().open_log_store(
        HomeLogStoreMgr::DATA_LOG_FAMILY_IDX, sb.journal_id,
        false, // Append mode,
        [this](std::shared_ptr< HomeLogStore > logstore) {
            m_journal = logstore;
            m_journal->register_log_found_cb(([this](const logstore_seq_num_t seqnum, const log_buffer buf,
                                                     void* const mem) { this->log_found(seqnum, buf, mem); }));
            m_journal_comp_cb = bind_this(IndxMgr::journal_comp_cb, 2);
            m_journal->register_req_comp_cb(m_journal_comp_cb);
            m_journal->register_log_replay_done_cb(bind_this(IndxMgr::on_replay_done, 2));
        });
    for (size_t i{0}; i < MAX_CP_CNT; ++i) {
        m_free_list[i] = std::make_shared< sisl::ThreadVector< BlkId > >();
    }
}

IndxMgr::~IndxMgr() {
    delete m_active_tbl;
    for (size_t i{0}; i < MAX_CP_CNT; ++i) {
        HS_REL_ASSERT_EQ(m_free_list[i]->size(), 0);
    }

    if (m_shutdown_started) { static std::once_flag flag1; }
}

void IndxMgr::create_first_cp() {
    auto* const icp_sb{&(m_last_cp_sb.icp_sb)};
    const int64_t cp_id{icp_sb->active_cp_id + 1};
    const seq_id_t seqid{icp_sb->active_data_seqid};
    m_first_icp = indx_cp_ptr(new indx_cp{cp_id, seqid, icp_sb->diff_data_seqid, shared_from_this(),
                                          m_free_list[++m_free_list_cnt % MAX_CP_CNT]});
    m_first_icp->acp.bcp = m_active_tbl->attach_prepare_cp(nullptr, false, false);
    if (m_recovery_mode) {
        THIS_INDX_LOG(TRACE, indx_mgr, , "creating indx mgr in recovery mode");
        suspend_active_cp();

        // It will only from blk alloc CP because of unmap recovery.
        m_first_icp->blkalloc_cp_only = true;
        if (!m_is_snap_enabled) { return; }

        /* recover diff table */
        btree_cp_sb dcp_sb; // set it to default if last cp is snap cp
        int64_t diff_snap_id;
        if (m_last_cp_sb.icp_sb.snap_cp) {
            /* if snapshot is taken in last cp then we just call snap create done again. Worse
             * case we end up calling two times. But it cover the crash case where it paniced just after
             * cp superblock is updated and before snap create done is called.
             */
            snap_create_done(m_last_cp_sb.icp_sb.diff_snap_id, m_last_cp_sb.icp_sb.diff_max_seqid,
                             m_last_cp_sb.icp_sb.diff_data_seqid, m_last_cp_sb.icp_sb.diff_cp_id);
            diff_snap_id = snap_get_diff_id();
        } else {
            dcp_sb = m_last_cp_sb.dcp_sb;
            diff_snap_id = m_last_cp_sb.icp_sb.diff_snap_id;
            HS_REL_ASSERT_EQ(diff_snap_id, snap_get_diff_id());
        }
        auto diff_btree_sb{snap_get_diff_tbl_sb()};
        m_first_icp->dcp.diff_tbl = m_recover_indx_tbl(diff_btree_sb, dcp_sb);
        m_first_icp->dcp.diff_snap_id = diff_snap_id;
        m_first_icp->dcp.bcp = m_first_icp->dcp.diff_tbl->attach_prepare_cp(nullptr, false, false);
    } else {
        if (!m_is_snap_enabled) { return; }
        /* create new diff table */
        create_new_diff_tbl(m_first_icp);
    }
}

std::string IndxMgr::get_cp_flush_status(const indx_cp_ptr& icp) {
    return fmt::format("[ [{}] - [{}] - [{}] ]", get_name(), icp->to_string(),
                       m_active_tbl->get_cp_flush_status(icp->acp.bcp));
}

void IndxMgr::indx_create_done(indx_tbl* const indx_tbl) { indx_tbl->create_done(); }

void IndxMgr::indx_init() {
    HS_REL_ASSERT_EQ(m_recovery_mode, false); // it is not called in recovery mode;
    create_first_cp();
    indx_create_done(m_active_tbl);
}

/* Note: snap mgr should not call it multiple times if a snapshot create is in progress. Indx mgr doesn't monitor
 * snapshot progress. It has to be to done in snap mgr.
 */
void IndxMgr::indx_snap_create() {
    THIS_INDX_LOG(TRACE, indx_mgr, , "snapshot create triggered indx name {}", m_name);
    add_prepare_cb_list([this](const indx_cp_ptr& cur_icp, hs_cp* const cur_hcp, hs_cp* const new_hcp) {
        if (cur_icp->flags & indx_cp_state::ba_cp) {
            HS_REL_ASSERT((cur_icp->flags & indx_cp_state::diff_cp), "should be diff cp");
            /* We start snapshot create only if it is a blk alloc checkpoint */
            m_is_snap_started = true;
            m_cp_mgr->attach_cb(cur_hcp, ([this](const bool success) {
                                    /* it is called when CP is completed */
                                    snap_create_done(
                                        m_last_cp_sb.icp_sb.diff_snap_id, m_last_cp_sb.icp_sb.diff_max_seqid,
                                        m_last_cp_sb.icp_sb.diff_data_seqid, m_last_cp_sb.icp_sb.diff_cp_id);
                                    m_is_snap_started = false;
                                }));
        } else {
            /* it is not blk alloc checkpoint. Push this callback again */
            indx_snap_create();
        }
    });
    trigger_hs_cp(nullptr, false /* shutdown */, true /* force */);
}

void IndxMgr::recovery() {
    HS_REL_ASSERT_EQ(m_recovery_mode, true);
    THIS_INDX_LOG(INFO, replay, , "recovery state {}", m_recovery_state);

    switch (m_recovery_state) {
    case indx_recovery_state::create_sb_st: {
        const auto it{cp_sb_map.find(m_uuid)};
        if (it != std::end(cp_sb_map)) { std::memcpy(&m_last_cp_sb, &(it->second), sizeof(m_last_cp_sb)); }
    }
        // fall through
    case indx_recovery_state::create_indx_tbl_st: {
        /* Now we have all the information to create mapping btree */
        m_active_tbl = m_recover_indx_tbl(m_immutable_sb.btree_sb, m_last_cp_sb.acp_sb);
    }
        // fall through
    case indx_recovery_state::create_first_cp_st: {
        create_first_cp();
        m_recovery_state = indx_recovery_state::io_replay_st;
        break; // io replay happens after it is called again after btree replay
    }
    case indx_recovery_state::io_replay_st: {
        HS_REL_ASSERT_NOTNULL(m_journal.get());
        io_replay();
    }
        // fall through
    case indx_recovery_state::meta_ops_replay_st: {
        /* lets go through all index meta blks to see if anything needs to be done */
        recover_meta_ops();
        resume_active_cp();
        THIS_INDX_LOG(INFO, replay, , "recovery completed");
    }
        // fall through
    default: {
        m_recovery_mode = false;
    }
    }
}

void IndxMgr::io_replay() {
    HS_REL_ASSERT_EQ(m_recovery_mode, true);

    /* get the indx id */
    auto* const hcp{m_cp_mgr->cp_io_enter()};
    auto icp{get_indx_cp(hcp)};
    HS_REL_ASSERT_EQ(icp, m_first_icp);
    uint64_t diff_replay_cnt{0};
    uint64_t blk_alloc_replay_cnt{0};
    uint64_t active_replay_cnt{0};
    uint64_t gaps_found_cnt{0};

    /* start replaying the entry in order of seq number */
    int64_t next_replay_seq_num{-1};
    if (m_is_snap_enabled) {
        next_replay_seq_num = m_last_cp_sb.icp_sb.diff_data_seqid + 1;
    } else {
        next_replay_seq_num = m_last_cp_sb.icp_sb.active_data_seqid + 1;
    }
    THIS_INDX_LOG(INFO, replay, , "last cp {} next_replay_seq_num {} seq_buf_map size {}", m_last_cp_sb.to_string(),
                  next_replay_seq_num, seq_buf_map.size());
    uint64_t read_sync_cnt{0};

    auto it{std::cbegin(seq_buf_map)};
    while (it != std::cend(seq_buf_map)) {
        const logstore_seq_num_t seq_num{it->first};
        auto buf{it->second};
        if (buf.bytes() == nullptr) {
            /* do sync read */
            ++read_sync_cnt;
            buf = m_journal->read_sync(seq_num);
            ResourceMgrSI().inc_mem_used_in_recovery(buf.size());
        }
        auto* const hdr{indx_journal_entry::get_journal_hdr(buf.bytes())};
        HS_REL_ASSERT_NOTNULL(hdr);
        /* check if any blkids need to be freed or allocated. */
        HS_REL_ASSERT_GT(hdr->cp_id, -1);
        HS_REL_ASSERT((m_last_cp_sb.icp_sb.blkalloc_cp_id <= m_last_cp_sb.icp_sb.active_cp_id), "blkalloc cp id");
        if (hdr->cp_id > m_last_cp_sb.icp_sb.blkalloc_cp_id) {

            /* free blkids */
            auto fblkid_pair{indx_journal_entry::get_free_bid_list(buf.bytes())};
            for (uint32_t i{0}; i < fblkid_pair.second; ++i) {
                const BlkId fbid(fblkid_pair.first[i]);
                Free_Blk_Entry fbe(fbid, 0, fbid.get_nblks());

                THIS_INDX_LOG(DEBUG, replay, , "free blk id {} sequence number {}", fbid.to_string(), seq_num);
                const auto size{free_blk(nullptr, icp->io_free_blkid_list, fbe, true)};
                HS_DBG_ASSERT_GT(size, 0);

                if (hdr->cp_id > m_last_cp_sb.icp_sb.active_cp_id) {
                    /* TODO: we update size in superblock with each checkpoint. Ideally it
                     * has to be updated only for blk alloc checkpoint.
                     */
                    icp->indx_size.fetch_sub(size, std::memory_order_relaxed);
                }
            }

            /* allocate blkids */
            auto alloc_pair{indx_journal_entry::get_alloc_bid_list(buf.bytes())};
            for (uint32_t i{0}; i < alloc_pair.second; ++i) {
                THIS_INDX_LOG(DEBUG, replay, , "alloc blk id {} sequence number {}", alloc_pair.first[i].to_string(),
                              seq_num);
                m_hs->get_data_blkstore()->reserve_blk(alloc_pair.first[i]);

                if (hdr->cp_id > m_last_cp_sb.icp_sb.active_cp_id) {
                    /* TODO: we update size in superblock with each checkpoint. Ideally it
                     * has to be updated only for blk alloc checkpoint.
                     */
                    icp->indx_size.fetch_add(alloc_pair.first[i].data_size(m_hs->get_data_pagesz()),
                                             std::memory_order_relaxed);
                }
            }
            ++blk_alloc_replay_cnt;
        }

        if (seq_num < next_replay_seq_num) { goto next; }

        while (seq_num != next_replay_seq_num) {
            /* We don't need to fill gap during replay if replication is there. Without replication, we just assume that
             * these IOs are lost and are never going to be recovered.
             */
            m_journal->fill_gap(next_replay_seq_num);
            THIS_INDX_LOG(INFO, replay, , "fill gap seq num {} ", next_replay_seq_num);
            ++next_replay_seq_num;
            ++gaps_found_cnt;
        }

        ++next_replay_seq_num;

        /* update active indx_tbl */
        if (hdr->cp_id > m_last_cp_sb.icp_sb.active_cp_id) {
            THIS_INDX_LOG(DEBUG, replay, , "updating active indx table sequence number {}", seq_num);
            const auto ret{m_active_tbl->recovery_update(seq_num, hdr, icp->acp.bcp)};
            if (ret != btree_status_t::success) { abort(); }
            ++active_replay_cnt;
        }

        if (!m_is_snap_enabled) { goto next; }

        /* update diff indx tbl */
        if (hdr->cp_id > m_last_cp_sb.icp_sb.diff_cp_id) {
            const auto ret{icp->dcp.diff_tbl->recovery_update(seq_num, hdr, icp->dcp.bcp)};
            if (ret != btree_status_t::success) { abort(); }
            ++diff_replay_cnt;
        }
    next:
        ResourceMgrSI().dec_mem_used_in_recovery(buf.size());
        it = seq_buf_map.erase(it);
    }

    HS_DBG_ASSERT_EQ(seq_buf_map.size(), 0);
    THIS_INDX_LOG(INFO, replay, ,
                  "blk alloc replay cnt {} active_replay_cnt {} diff_replay_cnt{} gaps found {} last replay seq num {} "
                  "read_sync_cnt {}",
                  blk_alloc_replay_cnt, active_replay_cnt, diff_replay_cnt, gaps_found_cnt, (next_replay_seq_num - 1),
                  read_sync_cnt);
    m_cp_mgr->cp_io_exit(hcp);
}

void IndxMgr::recover_meta_ops() {
    auto it{indx_meta_map.find(m_uuid)};
    if (it == std::end(indx_meta_map)) { return; }
    std::vector< std::pair< void*, sisl::byte_array > >& meta_blk_list = it->second;

    for (auto& [mblk, buf] : meta_blk_list) {
        auto* const hdr{reinterpret_cast< hs_cp_base_sb* >(buf->bytes)};
        THIS_INDX_LOG(INFO, replay, , "found meta ops {} in recovery", (uint64_t)hdr->type);
        switch (hdr->type) {
        case indx_meta_hdr_type::cp:
            HS_DBG_ASSERT(0, "invalid op");
            break;
        case indx_meta_hdr_type::destroy: {
            uint8_t* const cur_bytes{buf->bytes + sizeof(hs_cp_base_sb)};
            HS_REL_ASSERT_GE(buf->size, static_cast< uint32_t >(hdr->size));
            const uint64_t size{hdr->size - sizeof(hs_cp_base_sb)};
            sisl::blob b(cur_bytes, size);
            m_active_tbl->get_btreequery_cur(b, m_destroy_btree_cur);
            m_destroy_meta_blk = mblk;
            /* it will be destroyed when destroy is called from volume */
            break;
        }
        case indx_meta_hdr_type::unmap: {
            HS_REL_ASSERT_GE(buf->size, (uint32_t)hdr->size);
            auto* const unmap_hdr{reinterpret_cast< hs_cp_unmap_sb* >(buf->bytes)};

            uint8_t* cur_bytes{reinterpret_cast< uint8_t* >(unmap_hdr) + sizeof(hs_cp_unmap_sb)};
            /* get key */
            // TO DO: Might need to address alignment based on data or fast type
            auto key{hs_utils::make_byte_array(unmap_hdr->key_size, false /* aligned */, sisl::buftag::common,
                                               MetaBlkMgrSI()->get_align_size())};
            std::memcpy(key->bytes, (void*)cur_bytes, unmap_hdr->key_size);

            /* get cursor bytes and size */
            cur_bytes = cur_bytes + unmap_hdr->key_size;
            uint64_t cursor_size = hdr->size - sizeof(hs_cp_unmap_sb) - unmap_hdr->key_size;

            /* get cursor */
            std::shared_ptr< homeds::btree::BtreeQueryCursor > unmap_btree_cur(new homeds::btree::BtreeQueryCursor());
            if (cursor_size != 0) {
                sisl::blob b(cur_bytes, cursor_size);
                m_active_tbl->get_btreequery_cur(b, *(unmap_btree_cur.get()));
            }

            do_remaining_unmap_internal(mblk, key, unmap_hdr->seq_id, unmap_btree_cur);
            break;
        }
        case indx_meta_hdr_type::snap_destroy:
            HS_DBG_ASSERT(0, "invalid op");
            break;
        default:
            HS_DBG_ASSERT(0, "invalid op");
        }
    }
    indx_meta_map.erase(m_uuid);
}

indx_mgr_sb IndxMgr::get_immutable_sb() {
    indx_mgr_sb sb(m_active_tbl->get_btree_sb(), m_journal->get_store_id(), m_is_snap_enabled);
    return sb;
}

#ifndef NDEBUG
void IndxMgr::dump_free_blk_list(const blkid_list_ptr& free_blk_list) {
    auto it = free_blk_list->begin(false /* latest */);
    BlkId* bid;
    while ((bid = free_blk_list->next(it)) != nullptr) {
        THIS_INDX_LOG(DEBUG, indx_mgr, , "Freeing blk [{}]", bid->to_string());
    }
}
#endif

void IndxMgr::flush_free_blks(const indx_cp_ptr& icp, hs_cp* const hcp) {
    THIS_INDX_CP_LOG(TRACE, icp->cp_id, "flush free blks");
    /* free blks in a indx mgr */
    hcp->ba_cp->free_blks(icp->io_free_blkid_list);

    /* free all the user free blkid */
    for (size_t i{0}; i < icp->user_free_blkid_list.size(); ++i) {
        hcp->ba_cp->free_blks(icp->user_free_blkid_list[i]);
    }

    /* free blks in a btree */
    m_active_tbl->flush_free_blks(icp->acp.bcp, hcp->ba_cp);
    if (icp->flags & indx_cp_state::diff_cp) { icp->dcp.diff_tbl->flush_free_blks(icp->dcp.bcp, hcp->ba_cp); }
}

void IndxMgr::update_cp_sb(indx_cp_ptr& icp, hs_cp* const hcp, indx_cp_base_sb* const sb) {
    /* copy the last superblock and then override the change values */
    THIS_INDX_CP_LOG(TRACE, icp->cp_id, "updating cp superblock. CP info {}", icp->to_string());
    std::memcpy(sb, &m_last_cp_sb, sizeof(m_last_cp_sb));

    if (icp->flags == indx_cp_state::suspend_cp) {
        /* nothing changed since last superblock */
        return;
    }

    HS_DBG_ASSERT_GE(icp->acp.end_seqid, icp->acp.start_seqid);
    HS_DBG_ASSERT_GT(icp->cp_id, static_cast< int64_t >(m_last_cp_sb.icp_sb.blkalloc_cp_id));
    HS_DBG_ASSERT_EQ(icp->cp_id, static_cast< int64_t >(m_last_cp_sb.icp_sb.active_cp_id + 1));

    sb->uuid = m_uuid;

    /* update blk alloc cp */
    if (icp->flags & indx_cp_state::ba_cp) { sb->icp_sb.blkalloc_cp_id = icp->cp_id; }

    sb->icp_sb.indx_size = icp->indx_size.load() + m_last_cp_sb.icp_sb.indx_size;

    /* update active checkpoint info */
    sb->icp_sb.active_data_seqid = icp->acp.end_seqid;
    sb->icp_sb.active_cp_id = icp->cp_id;

    /* update diff checkpoint info */
    if (icp->flags & indx_cp_state::diff_cp) {
        sb->icp_sb.diff_cp_id = icp->cp_id;
        sb->icp_sb.diff_data_seqid = icp->dcp.end_seqid;
        sb->icp_sb.diff_max_seqid = icp->get_max_seqid();
        sb->icp_sb.diff_snap_id = icp->dcp.diff_snap_id;
        sb->icp_sb.snap_cp = m_is_snap_started ? 1 : 0;
    }

    m_active_tbl->update_btree_cp_sb(icp->acp.bcp, sb->acp_sb, (icp->flags & indx_cp_state::ba_cp));

    /* XXX: we might remove it after diff cp comes */
    HS_REL_ASSERT_EQ(static_cast< int64_t >(sb->icp_sb.active_cp_id), static_cast< int64_t >(sb->acp_sb.cp_id),
                     "indx name {} cp info {}", get_name(), m_last_cp_sb.to_string());
    HS_REL_ASSERT_EQ(static_cast< int64_t >(sb->icp_sb.blkalloc_cp_id),
                     static_cast< int64_t >(sb->acp_sb.blkalloc_cp_id), "indx name {} cp info {}", get_name(),
                     m_last_cp_sb.to_string());

    if (icp->flags & indx_cp_state::diff_cp) {
        icp->dcp.diff_tbl->update_btree_cp_sb(icp->dcp.bcp, sb->dcp_sb, (icp->flags & indx_cp_state::ba_cp));
    }
    std::memcpy(&m_last_cp_sb, sb, sizeof(m_last_cp_sb));
    THIS_INDX_CP_LOG(INFO, icp->cp_id, "updating cp superblock. CP superblock info {}", m_last_cp_sb.to_string());
}

/* It attaches the new CP and prepare for cur cp flush */
indx_cp_ptr IndxMgr::attach_prepare_indx_cp(const indx_cp_ptr& cur_icp, hs_cp* const cur_hcp, hs_cp* const new_hcp) {
    if (cur_icp == nullptr) {
        /* this indx mgr is just created in the last CP. return the first_cp created at the timeof indx mgr
         * creation. And this indx mgr is not going to participate in the current cp. This indx mgr is going to
         * participate in the next cp.
         */
        HS_DBG_ASSERT_NE(m_first_icp, nullptr);
        /* if cur_hcp->blkalloc_checkpoint is set to true then it means it is created/destroy in a same cp.
         * we can not resume CP in this checkpoint. A indx mgr can never be added in a current cp.
         */
        THIS_INDX_CP_LOG(TRACE, 0, "returning first cp");
        return m_first_icp;
    }

    /* Beyond this point we can not change state of the CP */
    set_indx_cp_state(cur_icp, cur_hcp);

    if (cur_icp->flags == indx_cp_state::suspend_cp) {
        /* this indx mgr is not going to participate in a current cp */
        THIS_INDX_CP_LOG(TRACE, cur_icp->cp_id, "cp is suspended");
        return cur_icp;
    }

    if (cur_icp == m_first_icp) { m_first_icp = nullptr; }

    /* call prepare_callback if any. One use case is attaching of free blkIds or attaching a callback to a CP based on
     * its state */
    call_prepare_cb(cur_icp, cur_hcp, new_hcp);

    /* attach the last seqid to this cp. IOs will be replayed after this seqid if this cp is taken successfully */
    cur_icp->acp.end_seqid = m_journal->get_contiguous_issued_seq_num(cur_icp->acp.start_seqid);
    if (cur_icp->flags & indx_cp_state::diff_cp) { cur_icp->dcp.end_seqid = cur_icp->acp.end_seqid; }

    /* prepare btree cp and attach new CP for both active and diff */
    const auto is_ba_cp{cur_icp->flags & indx_cp_state::ba_cp};
    auto active_bcp{m_active_tbl->attach_prepare_cp(cur_icp->acp.bcp, m_last_cp, is_ba_cp)};
    btree_cp_ptr diff_bcp;
    if (cur_icp->flags & indx_cp_state::diff_cp) {
        /* if this diff table is going to a snapshot than this is the last cp on this indx tbl */
        THIS_INDX_CP_LOG(TRACE, cur_icp->cp_id, "it is diff cp");
        diff_bcp =
            cur_icp->dcp.diff_tbl->attach_prepare_cp(cur_icp->dcp.bcp, m_is_snap_started ? true : m_last_cp, is_ba_cp);
    } else {
        // diff cp is not taken yet
        diff_bcp = cur_icp->dcp.bcp;
    }

    /* If it is last cp return nullptr */
    if (m_last_cp) {
        HS_DBG_ASSERT_EQ(active_bcp, nullptr);
        HS_DBG_ASSERT_EQ(diff_bcp, nullptr);
        THIS_INDX_CP_LOG(TRACE, cur_icp->cp_id, "Last cp of this index triggered");
        return nullptr;
    }

    auto new_icp = create_new_indx_cp(cur_icp);
    THIS_INDX_CP_LOG(TRACE, cur_icp->cp_id, "is blk allocator cp? {}", is_ba_cp);

    /* attach btree checkpoint to this new CP */
    new_icp->acp.bcp = active_bcp;
    if (m_is_snap_started) {
        HS_DBG_ASSERT(is_ba_cp, "should be blk alloc cp");
        /* create new diff table */
        /* Here are the steps to create snapshot
         * 1. HS CP trigger is called
         * 2. We create a new diff btree if it is blk alloc checkpoint.
         * 3. We persist a new diff btree information in snapshot. At this point we have two diff btree active. One is
         *    the old CP wich is still active and other in the new CP where new IOs are going on.
         * 4. Persist CP superblock with new diff tree cp information and snap id.
         * 5. After all the buffers are persisted and bitmap is persisted, we call snap_created() api.
         *          - Snap create persist superblock of this snapshot with the updated information.i
         *          - It calls snapshot close which closes the journal for that snapshot and move it into
         *            read only mode.
         *          - User can open it either in read only mode or write only mode. If it is open in write only mode it
         *            will create a new journal
         *
         * Recovery :-
         * 1. If it is crashed between step 3 and step 4, it is going to destroy new diff btree after recovering
         *    it. Recovering of new diff btree is very important otherwise it lead to blkid leak.
         * 2. If it is crashed after step 4 then cp has all the information to execute step 5
         */
        create_new_diff_tbl(new_icp);
    } else {
        HS_REL_ASSERT((!m_is_snap_started || diff_bcp), "m_is_snap_started {} diff_bcp {}", m_is_snap_started,
                      diff_bcp);
        new_icp->dcp.diff_tbl = cur_icp->dcp.diff_tbl;
        new_icp->dcp.diff_snap_id = cur_icp->dcp.diff_snap_id;
        new_icp->dcp.bcp = diff_bcp;
    }
    return new_icp;
}

indx_cp_ptr IndxMgr::create_new_indx_cp(const indx_cp_ptr& cur_icp) {
    /* get free list */
    blkid_list_ptr free_list;
    if (cur_icp->flags & indx_cp_state::ba_cp) {
        free_list = m_free_list[++m_free_list_cnt % MAX_CP_CNT];
        HS_REL_ASSERT_EQ(free_list->size(), 0);
    } else {
        /* we keep accumulating the free blks until blk checkpoint is taken */
        free_list = cur_icp->io_free_blkid_list;
    }

    /* get start sequence ID */
    const seq_id_t acp_start_seq_id{cur_icp->acp.end_seqid};
    const seq_id_t dcp_start_seq_id{cur_icp->flags & indx_cp_state::diff_cp ? cur_icp->dcp.end_seqid
                                                                            : cur_icp->dcp.start_seqid};

    /* create new cp */
    const int64_t cp_id{cur_icp->cp_id + 1};
    indx_cp_ptr new_icp{new indx_cp{cp_id, acp_start_seq_id, dcp_start_seq_id, cur_icp->indx_mgr, free_list}};
    return new_icp;
}

void IndxMgr::set_indx_cp_state(const indx_cp_ptr& cur_icp, hs_cp* const cur_hcp) {
    /* We have to make a decision here to take blk alloc cp or not. We can not reverse our
     * decisioin beyond this point. */

#ifdef _PRERELEASE
    if (cur_icp == m_first_icp) {
        if (homestore_flip->test_flip("indx_create_suspend_cp")) {
            LOGINFO("suspending cp because of flip");
            m_active_cp_suspend = true;
            indx_test_status::indx_create_suspend_cp_test = true;
        }
    }
#endif

    const bool is_ba_cp{cur_hcp->blkalloc_checkpoint};
    if (m_active_cp_suspend.load() || (cur_icp->blkalloc_cp_only && !is_ba_cp)) {
        cur_icp->flags = indx_cp_state::suspend_cp;
        return;
    }

    cur_icp->flags = indx_cp_state::active_cp;

    if (is_ba_cp) {
        cur_icp->flags |= indx_cp_state::ba_cp;
        if (m_is_snap_enabled) { cur_icp->flags |= indx_cp_state::diff_cp; }
    }
    THIS_INDX_CP_LOG(TRACE, cur_icp->cp_id, "cp state {}", cur_icp->flags);
}

void IndxMgr::call_prepare_cb(const indx_cp_ptr& cur_icp, hs_cp* const cur_hcp, hs_cp* const new_hcp) {
    /* Go through the callback who is waiting for prepare to happen. Normally suspend, resume,
     * destroy waits for it. We can not move CP to suspend, active in middle of CP.
     */
    std::unique_ptr< std::vector< prepare_cb > > cb_list;
    {
        /* Go through the callback who is waiting for prepare to happen. Normally suspend, resume,
         * destroy waits for it. We can not move CP to suspend, active in middle of CP.
         */
        std::shared_lock< std::shared_mutex > m{m_prepare_cb_mtx};
        if (m_prepare_cb_list->size() != 0) {
            cb_list = std::move(m_prepare_cb_list);
            m_prepare_cb_list = std::make_unique< std::vector< prepare_cb > >();
            m_prepare_cb_list->reserve(4);
        }
    }

    if (cb_list) {
        THIS_INDX_CP_LOG(TRACE, cur_icp->cp_id, "Attach prepare cp waiting list size = {}", cb_list->size());
        for (auto& prep_cb : *cb_list) {
            prep_cb(cur_icp, cur_hcp, new_hcp);
        }
    }
}

void IndxMgr::create_new_diff_tbl(indx_cp_ptr& icp) {
    icp->dcp.diff_tbl = m_create_indx_tbl();
    icp->dcp.diff_snap_id = snap_create(icp->dcp.diff_tbl, icp->cp_id);
    icp->dcp.bcp = icp->dcp.diff_tbl->attach_prepare_cp(nullptr, false, false);
    indx_create_done(icp->dcp.diff_tbl);
    THIS_INDX_CP_LOG(TRACE, icp->cp_id, "create new diff table");
}

void IndxMgr::truncate(const indx_cp_ptr& icp) {
    m_journal->truncate(icp->acp.end_seqid);
    m_active_tbl->truncate(icp->acp.bcp);
    THIS_INDX_CP_LOG(DEBUG, icp->cp_id, "uuid={} Truncating upto last seqid={}", m_uuid, icp->acp.end_seqid);
}

indx_tbl* IndxMgr::get_active_indx() { return m_active_tbl; }

void IndxMgr::journal_comp_cb(logstore_req* const lreq, const logdev_key ld_key) {
    HS_DBG_ASSERT(ld_key.is_valid(), "key is invalid");
    auto ireq{indx_req_ptr{static_cast< indx_req* >(lreq->cookie),
                           false}}; // Turn it back to smart ptr before doing callback.

    THIS_INDX_LOG(TRACE, indx_mgr, ireq, "Journal write done, lsn={}, log_key=[idx={}, offset={}]", lreq->seq_num,
                  ld_key.idx, ld_key.dev_offset);

    if (ireq->is_unmap() && !ireq->is_io_completed()) {
        /* write information to superblock, start unmap, and then call m_io_cb */
        /* XXX: should we call it in different thread as it write a metablock which is a sync write ? */
        iomanager.run_on(m_thread_id, [this, ireq](const io_thread_addr_t addr) {
            this->unmap_indx_async(ireq);
            free_blkid_and_send_completion(ireq);
        });
    } else {

        /* blk id is alloceted in disk bitmap only after it is writing to journal. check
         * blk_alloctor base class for further explanations. It should be done in cp critical section.
         * Otherwise bitmap won't reflect all the blks allocated in a cp.
         *
         * It is also possible that indx_alloc_blkis list contain the less number of blkids that allocated because of
         * partial writes. We are not freeing it in cache right away. There is no reason to not do it. We are not
         * setting it in disk bitmap so in next reboot it will be available to use.
         */

        for (size_t i{0}; i < ireq->indx_alloc_blkid_list.size(); ++i) {
            m_hs->get_data_blkstore()->reserve_blk(ireq->indx_alloc_blkid_list[i]);

            /* update size */
            ireq->icp->indx_size.fetch_add(ireq->indx_alloc_blkid_list[i].data_size(m_hs->get_data_pagesz()),
                                           std::memory_order_relaxed);
        }
        free_blkid_and_send_completion(ireq);
    }
    logstore_req::free(lreq);
}

void IndxMgr::free_blkid_and_send_completion(const indx_req_ptr& ireq) {
    /* free the blkids */
    const auto free_size{free_blk(ireq->hcp, ireq->icp->io_free_blkid_list, ireq->indx_fbe_list, true, ireq.get())};
    HS_DBG_ASSERT((ireq->indx_fbe_list.size() == 0 || free_size > 0),
                  " ireq->indx_fbe_list.size {}, free_size{}, ireq->indx_fbe_list.size", free_size);
    ireq->icp->indx_size.fetch_sub(free_size, std::memory_order_relaxed);

    /* End of critical section */
    if (ireq->first_hcp) { m_cp_mgr->cp_io_exit(ireq->first_hcp); }
    m_cp_mgr->cp_io_exit(ireq->hcp);

    /* XXX: should we do completion before ending the critical section. We might get some better latency in doing
     * that but my worry is that we might end up in deadlock if we pick new IOs in completion and those IOs need to
     * take cp to free some resources.
     */
    m_io_cb(ireq, ireq->indx_err);
}

void IndxMgr::journal_write(const indx_req_ptr& ireq) {
    /* Journal write is async call. So incrementing the ref on indx req */
    ireq->inc_ref();
    auto b{ireq->create_journal_entry()};
    auto* const lreq{logstore_req::make(m_journal.get(), ireq->get_seqid(), b)};
    lreq->cookie = ireq.get();
    m_journal->write_async(lreq);
}

/* A io can become part of two CPs if btree node is updated with the new CP and few indx mgr IOs
 * is still being done in old CP. Indx is always updated in a mapping sequentially start from
 * lba_start. We keep track of all the CP in a req but update journal with only with
 * the latest CP ids.
 *
 * if fast path not possible:
 * 1. let spdk thread exit;
 * 2. send message to slow-path thread to do the write, and in this slow-path thread, after write completes, do
 * journal write;
 * 3. after jouranl write completes, in journal completion callback, do io callback to caller;
 * */
btree_status_t IndxMgr::update_indx_tbl(const indx_req_ptr& ireq, const bool is_active) {
    if (is_active) {
        auto bcp{ireq->icp->acp.bcp};
        const auto status{m_active_tbl->update_active_indx_tbl(ireq, bcp)};
        if (status == btree_status_t::fast_path_not_possible) {
            /* call run_on in async mode */
            iomanager.run_on(m_slow_path_thread_id, [this, ireq](const io_thread_addr_t addr) mutable {
                THIS_INDX_LOG(DEBUG, indx_mgr, ireq, "Slow path write triggered.");
                HS_DBG_ASSERT_EQ(ireq->state, indx_req_state::active_btree);
                update_indx_internal(ireq);
            });
        }
        return status;
    } else {
        // we are here only when active btree write is in fast path;
        auto bcp{ireq->icp->dcp.bcp};
        auto* const diff_tbl{ireq->icp->dcp.diff_tbl};
        assert(diff_tbl != nullptr);
        const auto status{diff_tbl->update_diff_indx_tbl(ireq, bcp)};

        if (status == btree_status_t::fast_path_not_possible) {
            /* call run_on in async mode */
            iomanager.run_on(m_slow_path_thread_id, [this, ireq](const io_thread_addr_t addr) mutable {
                THIS_INDX_LOG(DEBUG, indx_mgr, ireq, "Slow path write triggered.");
                HS_DBG_ASSERT_EQ(ireq->state, indx_req_state::diff_btree);
                update_indx_internal(ireq);
            });
        }
        return status;
    }
}

bool IndxMgr::is_destroying() { return (m_state == indx_mgr_state::DESTROYING); }

void IndxMgr::do_remaining_unmap_internal(void* const unmap_meta_blk_cntx, const sisl::byte_array& key,
                                          const seq_id_t seqid,
                                          const std::shared_ptr< homeds::btree::BtreeQueryCursor >& btree_cur) {
    /* enter into critical section */
    auto* const hcp{m_cp_mgr->cp_io_enter()};
    auto cur_icp{get_indx_cp(hcp)};
    auto btree_id{get_indx_cp(hcp)->acp.bcp};

    /* collect all the free blkids */
    blkid_list_ptr free_list{std::make_shared< sisl::ThreadVector< BlkId > >()};
    int64_t free_size{0};
    btree_status_t ret = btree_status_t::success;
    do {
        ret = m_active_tbl->update_oob_unmap_active_indx_tbl(free_list, seqid, key->bytes, *(btree_cur.get()), btree_id,
                                                             free_size, m_recovery_mode ? true : false /* force */);
    } while (
        (ret == btree_status_t::resource_full) &&
        (get_elapsed_time_ms(hcp->cp_prepare_start_time) < HS_DYNAMIC_CONFIG(generic.cp_watchdog_timer_sec) * 1000));

    cur_icp->user_free_blkid_list.push_back(free_list);
    cur_icp->indx_size.fetch_sub(free_size, std::memory_order_relaxed);

#ifdef _PRERELEASE
    if (homestore_flip->test_flip("unmap_post_free_blks_abort_before_cp")) {
        LOGINFO("aborting because of flip");
        raise(SIGKILL);
    }
#endif

    if (ret == btree_status_t::crc_mismatch) {
        // move volume to offline mode and don't do anything
        THIS_INDX_LOG(ERROR, indx_mgr, , "hit crc mismatch error. Discontinuing unmap");
        m_hs->fault_containment(m_uuid);
        goto out;
    } else if (ret != btree_status_t::success) {
        HS_REL_ASSERT_EQ(m_recovery_mode, false);
        THIS_INDX_LOG(TRACE, indx_mgr, , "unmap btree ret status resource_full");
        m_cp_mgr->attach_cb(hcp, ([this, key, btree_cur, unmap_meta_blk_cntx, seqid](bool success) mutable {
                                // update the meta blk and requeue it
                                this->do_remaining_unmap(unmap_meta_blk_cntx, key, seqid, btree_cur);
                            }));
    } else {
        m_cp_mgr->attach_cb(hcp, ([this, key, unmap_meta_blk_cntx](bool success) {
#ifdef _PRERELEASE
                                if (homestore_flip->test_flip("unmap_pre_sb_remove_abort")) {
                                    LOGINFO("aborting because of flip");
                                    raise(SIGKILL);
                                }
#endif
                                /* remove the meta blk which is used to track unmap progress */
                                const auto ret{MetaBlkMgrSI()->remove_sub_sb(unmap_meta_blk_cntx)};
                                if (ret != no_error) {
                                    HS_REL_ASSERT(false, "failed to remove subsystem with status: {}", ret.message());
                                }
                            }));
    }

out:
    m_cp_mgr->cp_io_exit(hcp);
}

sisl::byte_array IndxMgr::alloc_unmap_sb(const uint32_t key_size, const seq_id_t seq_id,
                                         homeds::btree::BtreeQueryCursor& unmap_btree_cur) {
    const sisl::blob& cursor_blob = unmap_btree_cur.serialize();
    const uint64_t size{cursor_blob.size + sizeof(hs_cp_unmap_sb) + key_size};
    // TO DO: Might need to address alignment based on data or fast type
    sisl::byte_array b{hs_utils::make_byte_array(size, MetaBlkMgrSI()->is_aligned_buf_needed(size),
                                                 sisl::buftag::metablk, MetaBlkMgrSI()->get_align_size())};
    hs_cp_unmap_sb* const mhdr{new (b->bytes) hs_cp_unmap_sb()};
    mhdr->uuid = m_uuid;
    mhdr->type = indx_meta_hdr_type::unmap;
    mhdr->seq_id = seq_id;
    mhdr->size = size;
    mhdr->key_size = key_size;
    if (cursor_blob.size) {
        std::memcpy(b->bytes + sizeof(hs_cp_unmap_sb) + key_size, cursor_blob.bytes, cursor_blob.size);
    }
    return b;
}

void IndxMgr::write_cp_unmap_sb(void*& unmap_meta_blk_cntx, const uint32_t key_size, const seq_id_t seq_id,
                                homeds::btree::BtreeQueryCursor& unmap_btree_cur, const uint8_t* const key) {
    auto b{alloc_unmap_sb(key_size, seq_id, unmap_btree_cur)};
    std::memcpy(b->bytes + sizeof(hs_cp_unmap_sb), key, key_size);
    write_meta_blk(unmap_meta_blk_cntx, b);
}

void IndxMgr::unmap_indx_async(const indx_req_ptr& ireq) {
    // TO DO: Might need to address alignment based on data or fast type
    auto key{hs_utils::make_byte_array(ireq->get_key_size(), false /* aligned */, sisl::buftag::common,
                                       MetaBlkMgrSI()->get_align_size())};
    std::shared_ptr< homeds::btree::BtreeQueryCursor > unmap_btree_cur(new homeds::btree::BtreeQueryCursor());

    ireq->fill_key(key->bytes, ireq->get_key_size());
    ireq->get_btree_cursor(*(unmap_btree_cur.get()));

    // do remaining unmap
    do_remaining_unmap(nullptr, key, ireq->get_seqid(), unmap_btree_cur);
}

void IndxMgr::do_remaining_unmap(void* unmap_meta_blk_cntx, const sisl::byte_array& key, const seq_id_t seqid,
                                 const std::shared_ptr< homeds::btree::BtreeQueryCursor >& btree_cur) {
    /* persist superblock */
    COUNTER_INCREMENT(m_metrics, indx_unmap_async_count, 1);
    write_cp_unmap_sb(unmap_meta_blk_cntx, key->size, seqid, *(btree_cur.get()), key->bytes);
#ifdef _PRERELEASE
    if (homestore_flip->test_flip("unmap_post_sb_write_abort")) {
        LOGINFO("aborting because of flip");
        raise(SIGKILL);
    }
#endif
    add_prepare_cb_list([this, key, btree_cur, unmap_meta_blk_cntx,
                         seqid](const indx_cp_ptr& cur_icp, hs_cp* const cur_hcp, hs_cp* const new_hcp) mutable {
        if (is_destroying() || m_shutdown_started.load()) {
            THIS_INDX_LOG(TRACE, indx_mgr, , "skipping map because it is in destroying state");
            return;
        }
        if (cur_icp->flags & indx_cp_state::ba_cp) {
            do_remaining_unmap_internal(unmap_meta_blk_cntx, key, seqid, btree_cur);
        } else {
            do_remaining_unmap(unmap_meta_blk_cntx, key, seqid, btree_cur);
        }
    });
}

void IndxMgr::unmap(const indx_req_ptr& ireq) { update_indx(ireq); }

// round robin
iomgr::io_thread_t IndxMgr::get_next_btree_write_thread() {
    // it is okay if m_btree_write_thrd_idx overflows;
    return m_btree_write_thread_ids[m_btree_write_thrd_idx++ % HS_DYNAMIC_CONFIG(generic.num_btree_write_threads)];
}

void IndxMgr::update_indx(const indx_req_ptr& ireq) {
    /* do btree write in user thread */
    Clock::time_point start_time = Clock::now();

    iomanager.run_on(get_next_btree_write_thread(), [this, ireq, start_time](const io_thread_addr_t addr) mutable {
        /* Entered into critical section. CP is not triggered in this critical section */
        auto time_spent = get_elapsed_time_ns(start_time);
        HISTOGRAM_OBSERVE(m_metrics, btree_msg_time, time_spent);
        ireq->hcp = m_cp_mgr->cp_io_enter();
        ireq->icp = get_indx_cp(ireq->hcp);
        ireq->state = indx_req_state::active_btree;
        update_indx_internal(ireq);
    });
}

/* * this function can be called either in fast path or slow path * */
void IndxMgr::update_indx_internal(const indx_req_ptr& ireq) {
    auto ret{btree_status_t::success};
    switch (ireq->state) {
    case indx_req_state::active_btree:
        /* update active btree */
        THIS_INDX_LOG(TRACE, indx_mgr, ireq, "updating active btree");
        ret = update_indx_tbl(ireq, true /* is_active */);
        /* we call cp exit on both the CPs only when journal is written otherwise there could be blkid leak */
        if (ret == btree_status_t::cp_mismatch) { ret = retry_update_indx(ireq, true /* is_active */); }
        /* TODO : we don't allow partial failure for now. If we have to allow that we have to support undo */
        THIS_INDX_LOG(TRACE, indx_mgr, ireq, "updating active btree status {}", ret);
        if (ret != btree_status_t::success && ret != btree_status_t::fast_path_not_possible) {
            THIS_INDX_LOG(INFO, indx_mgr, ireq, "return val unexpected: {}", ret);
        }

        if (ret == btree_status_t::fast_path_not_possible) { return; }

        /* fall through */
    case indx_req_state::diff_btree:

        /* TODO :- We have to handle the case if a write is only partially written in active indx tbl */
        THIS_INDX_LOG(TRACE, indx_mgr, ireq, "updating diff btree");
        ireq->state = indx_req_state::diff_btree;
        /* update diff btree. */
        if (m_is_snap_enabled) {
            ret = update_indx_tbl(ireq, false);
            /* we call cp exit on both the CPs only when journal is written otherwise there could be blkid leak */
            if (ret == btree_status_t::cp_mismatch) { ret = retry_update_indx(ireq.get(), false); }
            if (ret != btree_status_t::success && ret != btree_status_t::fast_path_not_possible) {
                THIS_INDX_LOG(INFO, indx_mgr, ireq, "return val unexpected: {}", ret);
            }
        }

        THIS_INDX_LOG(TRACE, indx_mgr, ireq, "updating diff btree status {}", ret);
        if (ret == btree_status_t::fast_path_not_possible) { return; }

        break;

    default:
        HS_REL_ASSERT(false, "Unsupported ireq state: ", ireq->state);
    }

    if (ret != btree_status_t::success) {
        if (ret == btree_status_t::space_not_avail) {
            THIS_INDX_LOG(INFO, indx_mgr, ireq, "no space available on device");
            ireq->indx_err = std::errc::no_space_on_device;
        } else if (ret == btree_status_t::crc_mismatch) {
            ireq->indx_err = homestore_error::btree_crc_mismatch;
        } else {
            ireq->indx_err = homestore_error::btree_write_failed;
        }
    }

    /* XXX: should we skip updating journal in error path ? */

    /* Update allocate blkids in indx req */
    m_active_tbl->update_indx_alloc_blkids(ireq);

    /* In case of failure we will still update the journal with entries of whatever is written. */
    /* update journal. Journal writes are not expected to fail. It is async call/ */
    journal_write(ireq);
}

/* It is called when first update failed because btree is updated by latest CP and indx mgr got old cp */
btree_status_t IndxMgr::retry_update_indx(const indx_req_ptr& ireq, const bool is_active) {
    ireq->first_hcp = ireq->hcp;
    /* try again to get the new cp */
    ireq->hcp = m_cp_mgr->cp_io_enter();
    ireq->icp = get_indx_cp(ireq->hcp);
    HS_REL_ASSERT((ireq->hcp != ireq->first_hcp), "cp is same");
    const auto ret{update_indx_tbl(ireq.get(), is_active)};

    /* we can not get mismatch again as we only have two cps pending at any given time */
    HS_REL_ASSERT_NE(ret, btree_status_t::cp_mismatch);
    return ret;
}

btree_cp_ptr IndxMgr::get_btree_cp(hs_cp* const hcp) {
    auto icp{get_indx_cp(hcp)};
    if (icp) { return (icp->acp.bcp); }
    return nullptr;
}

indx_cp_ptr IndxMgr::get_indx_cp(hs_cp* const hcp) {
    auto it{hcp->indx_cp_list.find(m_uuid)};
    indx_cp_ptr bcp;
    if (it == std::end(hcp->indx_cp_list)) {
        /* indx mgr is just created. So take the first cp. */
        HS_DBG_ASSERT_NE(m_first_icp, nullptr);
        return (m_first_icp);
    } else {
        HS_DBG_ASSERT_NE(it->second, nullptr);
        return (it->second);
    }
}

/* Steps involved in indx destroy. Note that blkids is available to allocate as soon as it is set in blkalloc. So we
 * need to make sure that blkids of btree won't be resued until indx mgr is not destroy and until its data blkids
 * and btree blkids are not persisted. indx mgr destroye is different that IO because there is no journal entry of free
 * blks as we have in regular IO.Steps:-
 * 1. Write a journal entry that this indx mgr is destroying. There is no purpose of it. It is only used for a sanity
 * check that there are no ios after this entry.
 * 2. We move the cp to suspended state.
 * 3. We destroy btree. Btree traverses the tree
 *      a. Btree free all the indx mgr blkids and accumumlate it in a indx mgr cp
 *      b. Btree free all its blocks and accumulate in writeback cache layer.
 * 4. Resume CP when blkalloc checkpoint to true.
 * 5. Both blkalloc checkpoint and indx mgr checkpoint happen in a same CP. It trigger indx mgr checkpoint followed by
 * blkalloc checkpoint. indx mgr checkpoint flush all the blkids in btree and indx mgr to blkalloc. And blkalloc
 * checkpoint persist the blkalloc.
 * 6. Free super block after bit map is persisted. CP is finished only after super block is persisted. It will
 * prevent another cp to start.
 * 7. Make all the free blkids available to reuse in blk allocator.
 */
void IndxMgr::destroy(const indxmgr_stop_cb& cb) {
    /* we can assume that there is no io going on this indx mgr now */
    THIS_INDX_LOG(INFO, indx_mgr, , "Destroying Indx Manager");
    m_destroy_done_cb = cb;
    m_state = indx_mgr_state::DESTROYING;

    // wait for the current cp to complete to make sure that no unmap is in process
    register_indx_cp_done_cb(([this](bool success) {
        iomanager.run_on(m_thread_id, [this](const io_thread_addr_t addr) { this->destroy_indx_tbl(); });
    }));
}

void IndxMgr::destroy_indx_tbl() {
    /* free all blkids of btree in memory */
    blkid_list_ptr free_list{std::make_shared< sisl::ThreadVector< BlkId > >()};
    int64_t free_size{0};
    const btree_status_t ret{m_active_tbl->free_user_blkids(free_list, m_destroy_btree_cur, free_size)};
    if (ret != btree_status_t::success) {
        if (ret != btree_status_t::resource_full) {
            /* we try to destroy it during reboot */
            m_destroy_done_cb(false);
            return;
        }
        THIS_INDX_LOG(INFO, indx_mgr, , "free_user_blkids btree ret status resource_full cur {}",
                      m_destroy_btree_cur.to_string());
        const sisl::blob& cursor_blob{m_destroy_btree_cur.serialize()};
        if (cursor_blob.size == 0) { HS_REL_ASSERT_EQ(free_size, 0); }
        attach_user_fblkid_list(
            free_list, ([this](const bool success) {
                /* persist superblock */
                const sisl::blob& cursor_blob{m_destroy_btree_cur.serialize()};
                if (cursor_blob.size) {
                    const uint64_t size{cursor_blob.size + sizeof(hs_cp_base_sb)};
                    // TO DO: Might need to address alignment based on data or fast type
                    sisl::byte_array b{hs_utils::make_byte_array(size, MetaBlkMgrSI()->is_aligned_buf_needed(size),
                                                                 sisl::buftag::metablk,
                                                                 MetaBlkMgrSI()->get_align_size())};
                    hs_cp_base_sb* const mhdr{new (b->bytes) hs_cp_base_sb()};
                    mhdr->uuid = m_uuid;
                    mhdr->type = indx_meta_hdr_type::destroy;
                    mhdr->size = cursor_blob.size + sizeof(hs_cp_base_sb);
                    std::memcpy(b->bytes + sizeof(hs_cp_base_sb), cursor_blob.bytes, cursor_blob.size);
#ifdef _PRERELEASE
                    if (homestore_flip->test_flip("indx_del_partial_free_data_blks_before_meta_write")) {
                        LOGINFO("aborting because of flip");
                        std::raise(SIGKILL);
                    }
#endif
                    write_meta_blk(m_destroy_meta_blk, b);
#ifdef _PRERELEASE
                    if (homestore_flip->test_flip("indx_del_partial_free_data_blks_after_meta_write")) {
                        LOGINFO("aborting because of flip");
                        std::raise(SIGKILL);
                    }
#endif
                }

                /* send message to thread to start freeing the blkid */
                iomanager.run_on(m_thread_id, [this](const io_thread_addr_t addr) { this->destroy_indx_tbl(); });
            }),
            free_size);
        return;
    }

    THIS_INDX_LOG(INFO, indx_mgr, , "All user logs are collected");

    // make sure that all free blks are persisted before we start destroying btree */
    attach_user_fblkid_list(free_list, ([this](bool success) {
                                blkid_list_ptr free_list = std::make_shared< sisl::ThreadVector< BlkId > >();
                                uint64_t free_node_cnt = 0;

                                // set the state in the consumer so that it destroyes this volume before marking
                                // recovery of btree completed.
                                StaticIndxMgr::m_hs->set_indx_btree_start_destroying(m_uuid);
                                if (m_active_tbl->destroy(free_list, free_node_cnt) != btree_status_t::success) {
                                    /* we try to destroy it during reboot */
                                    m_destroy_done_cb(false);
                                    return;
                                }
#ifdef _PRERELEASE
                                if (homestore_flip->test_flip("indx_del_partial_free_indx_blks")) {
                                    LOGINFO("aborting because of flip");
                                    std::raise(SIGKILL);
                                }
#endif

                                THIS_INDX_LOG(INFO, indx_mgr, , "Collected all the btree blocks {}", free_node_cnt);
                                attach_user_fblkid_list(
                                    free_list, ([this](bool success) {

#ifdef _PRERELEASE
                                        if (homestore_flip->test_flip("indx_del_free_blks_completed")) {
                                            LOGINFO("aborting because of flip");
                                            raise(SIGKILL);
                                        }
#endif
                                        /* remove the meta blk which is used to track vol destroy progress */
                                        if (m_destroy_meta_blk) {
                                            const auto ret{MetaBlkMgrSI()->remove_sub_sb(m_destroy_meta_blk)};
                                            if (ret != no_error) {
                                                HS_REL_ASSERT(false, "failed to remove subsystem with status: {}",
                                                              ret.message());
                                            }
                                        }
                                        m_destroy_done_cb(success);
                                    }),
                                    0, true);
                            }),
                            free_size);
}

void IndxMgr::attach_user_fblkid_list(blkid_list_ptr& free_blkid_list, const cp_done_cb& free_blks_cb,
                                      const int64_t free_size, const bool last_cp) {
    add_prepare_cb_list(([this, free_blkid_list, free_blks_cb, free_size,
                          last_cp](const indx_cp_ptr& cur_icp, hs_cp* const cur_hcp, hs_cp* const new_hcp) mutable {
        if (cur_icp->flags & indx_cp_state::ba_cp) {
            cur_icp->user_free_blkid_list.push_back(free_blkid_list);
            cur_icp->indx_size.fetch_sub(free_size, std::memory_order_relaxed);
            m_cp_mgr->attach_cb(cur_hcp, std::move(free_blks_cb));
            if (last_cp) { m_last_cp = true; }
        } else {
            /* try again in the next cp */
            attach_user_fblkid_list(free_blkid_list, free_blks_cb, free_size, last_cp);
        }
    }));
}

void IndxMgr::add_prepare_cb_list(const prepare_cb& cb) {
    std::unique_lock< std::shared_mutex > lk(m_prepare_cb_mtx);
    m_prepare_cb_list->push_back(cb);
}

void IndxMgr::suspend_active_cp() {
    HS_REL_ASSERT_EQ(m_active_cp_suspend.load(), false);
    m_active_cp_suspend = true;
}

void IndxMgr::resume_active_cp() {
    HS_REL_ASSERT_EQ(m_active_cp_suspend.load(), true);
    m_active_cp_suspend = false;
}

void IndxMgr::destroy_done() {
    m_active_tbl->destroy_done();
    HomeLogStoreMgrSI().remove_log_store(HomeLogStoreMgr::DATA_LOG_FAMILY_IDX, m_journal->get_store_id());
}

void IndxMgr::log_found(const logstore_seq_num_t seqnum, const log_buffer log_buf, void* const mem) {
    std::map< logstore_seq_num_t, log_buffer >::iterator it;
    bool happened;
    if (ResourceMgrSI().can_add_mem_in_recovery(log_buf.size())) {
        std::tie(it, happened) = seq_buf_map.emplace(std::make_pair(seqnum, log_buf));
        ResourceMgrSI().inc_mem_used_in_recovery(log_buf.size());
    } else {
        log_buffer nullbuf;
        std::tie(it, happened) = seq_buf_map.emplace(std::make_pair(seqnum, nullbuf));
    }
    if (seqnum > m_max_seqid_in_recovery) { m_max_seqid_in_recovery = seqnum; }
    HS_REL_ASSERT(happened, "happened");
}

void IndxMgr::on_replay_done([[maybe_unused]] std::shared_ptr< HomeLogStore > store,
                             const logstore_seq_num_t upto_lsn) {
    m_max_seqid_in_recovery = std::max(m_max_seqid_in_recovery, upto_lsn);
}

void IndxMgr::read_indx(const boost::intrusive_ptr< indx_req >& ireq) {
    const auto ret{m_active_tbl->read_indx(ireq.get(), m_read_cb)};

    if (ret == btree_status_t::fast_path_not_possible) {
        iomanager.run_on(m_slow_path_thread_id, [this, ireq](const io_thread_addr_t addr) mutable {
            THIS_INDX_LOG(DEBUG, indx_mgr, ireq, "Slow path write triggered.");
            const auto status{m_active_tbl->read_indx(ireq.get(), m_read_cb)};

            // no expect has_more in read case;
            HS_DBG_ASSERT_NE(status, btree_status_t::has_more);

            // this read could either fail or succeed, in either case, mapping layer will callback to client;
        });
    }
}

cap_attrs IndxMgr::get_used_size() const {
    cap_attrs attrs;
    if (is_recovery_done()) {
        attrs.used_data_size = m_last_cp_sb.icp_sb.indx_size;
        attrs.used_index_size = m_active_tbl->get_used_size();
        THIS_INDX_LOG(DEBUG, indx_mgr, , "tree used index size {} node cnt {}", attrs.used_index_size / 4096,
                      m_active_tbl->get_btree_node_cnt());
        attrs.used_total_size = attrs.used_data_size + attrs.used_index_size;
    } else {
        LOGWARN("Recovery in progress, not able to servie this request.");
    }
    return attrs;
}

seq_id_t IndxMgr::get_max_seqid_found_in_recovery() const { return m_max_seqid_in_recovery; }
std::string IndxMgr::get_name() const { return m_name; }

void IndxMgr::register_indx_cp_done_cb(const cp_done_cb& cb, const bool blkalloc_cp) {
    add_prepare_cb_list(
        ([this, cb, blkalloc_cp](const indx_cp_ptr& cur_icp, hs_cp* const cur_hcp, hs_cp* const new_hcp) mutable {
            if (blkalloc_cp) {
                if (cur_icp->flags & indx_cp_state::ba_cp) {
                    m_cp_mgr->attach_cb(cur_hcp, std::move(cb));
                } else {
                    /* try again in the next cp */
                    register_indx_cp_done_cb(cb, blkalloc_cp);
                }
            } else {
                m_cp_mgr->attach_cb(cur_hcp, std::move(cb));
            }
        }));
}

bool IndxMgr::is_recovery_done() const {
    /* this volume hasn't participated in a cp if first cp is not null. We can add more conditions in future */
    return (!m_recovery_mode && (m_first_icp ? false : true));
}

hs_cp* IndxMgr::cp_io_enter() { return (m_cp_mgr->cp_io_enter()); }

void IndxMgr::cp_io_exit(hs_cp* const hcp) { m_cp_mgr->cp_io_exit(hcp); }

sisl::status_response IndxMgr::get_status(const sisl::status_request& request) {
    return {};
}


/********************** Static Indx mgr functions *********************************/

void StaticIndxMgr::init() {
    m_hs = HomeStoreBase::safe_instance();
    m_shutdown_started.store(false);
    try_blkalloc_checkpoint.store(false);

    ResourceMgrSI().register_dirty_buf_exceed_cb(
        []([[maybe_unused]] int64_t dirty_buf_count) { IndxMgr::trigger_indx_cp(); });

    ResourceMgrSI().register_free_blks_exceed_cb(
        []([[maybe_unused]] int64_t free_blks_count) { IndxMgr::trigger_hs_cp(); });

    ResourceMgrSI().register_journal_exceed_cb([]([[maybe_unused]] int64_t journal_size) { IndxMgr::trigger_hs_cp(); });

    m_cp_mgr = std::unique_ptr< HomeStoreCPMgr >(new HomeStoreCPMgr{});
    m_read_blk_tracker = std::unique_ptr< Blk_Read_Tracker >(new Blk_Read_Tracker{IndxMgr::safe_to_free_blk});

    start_threads();

    IndxMgr::m_inited.store(true, std::memory_order_release);
}

void StaticIndxMgr::start_threads() {
    std::atomic< int64_t > thread_cnt{0};
    int expected_thread_cnt{0};

    /* start the timer for blkalloc checkpoint */
    LOGINFO("blkalloc cp timer is set to {} usec", HS_DYNAMIC_CONFIG(generic.blkalloc_cp_timer_us));
    m_hs_cp_timer_hdl =
        iomanager.schedule_global_timer(HS_DYNAMIC_CONFIG(generic.blkalloc_cp_timer_us) * 1000, true, nullptr,
                                        iomgr::thread_regex::all_user, [](void* cookie) { trigger_hs_cp(); });
    iomanager.create_reactor("indx_mgr", INTERRUPT_LOOP, [&thread_cnt](bool is_started) {
        if (is_started) {
            IndxMgr::m_thread_id = iomanager.iothread_self();
            ++thread_cnt;
        }
    });

    expected_thread_cnt++;

    /* start btree slow path thread */
    iomanager.create_reactor("indx_mgr_btree_slow", INTERRUPT_LOOP, [&thread_cnt](bool is_started) {
        if (is_started) {
            IndxMgr::m_slow_path_thread_id = iomanager.iothread_self();
            ++thread_cnt;
        }
    });
    ++expected_thread_cnt;

    const auto nthreads = HS_DYNAMIC_CONFIG(generic.num_btree_write_threads);
    IndxMgr::m_btree_write_thread_ids.reserve(nthreads);
    std::mutex mtx;
    for (uint32_t i = 0; i < nthreads; ++i) {
        /* start user thread for btree write operations */
        iomanager.create_reactor("indx_mgr_btree_write_" + std::to_string(i), INTERRUPT_LOOP,
                                 [&thread_cnt, &mtx](bool is_started) {
                                     if (is_started) {
                                         {
                                             std::unique_lock< std::mutex > lk{mtx};
                                             IndxMgr::m_btree_write_thread_ids.push_back(iomanager.iothread_self());
                                         }
                                         ++thread_cnt;
                                     }
                                 });
        ++expected_thread_cnt;
    }

    while (thread_cnt.load(std::memory_order_acquire) != expected_thread_cnt) {}
}

void StaticIndxMgr::flush_hs_free_blks(hs_cp* const hcp) {
    for (auto it{std::begin(hcp->indx_cp_list)}; it != std::end(hcp->indx_cp_list); ++it) {
        if (it->second == nullptr || !(it->second->flags & indx_cp_state::ba_cp)) {
            /* nothing to free. */
            continue;
        }
        /* free blks in a indx mgr */
        it->second->indx_mgr->flush_free_blks(it->second, hcp);
    }
}

void StaticIndxMgr::write_hs_cp_sb(hs_cp* const hcp) {
    const uint64_t size{sizeof(indx_cp_base_sb) * hcp->indx_cp_list.size() + sizeof(hs_cp_sb)};
    // TO DO: Might need to address alignment based on data or fast type
    sisl::byte_array b{hs_utils::make_byte_array(size, MetaBlkMgrSI()->is_aligned_buf_needed(size),
                                                 sisl::buftag::metablk, MetaBlkMgrSI()->get_align_size())};
    hs_cp_sb* const hdr{new (b->bytes) hs_cp_sb()};
    hdr->type = indx_meta_hdr_type::cp;
    int indx_cnt{0};
    indx_cp_base_sb* const indx_cp_base_sb_list{
        reinterpret_cast< indx_cp_base_sb* >(reinterpret_cast< uint8_t* >(hdr) + sizeof(hs_cp_sb))};
    for (auto it{std::begin(hcp->indx_cp_list)}; it != std::end(hcp->indx_cp_list); ++it) {
        auto icp = it->second;
        it->second->indx_mgr->update_cp_sb(icp, hcp, &indx_cp_base_sb_list[indx_cnt++]);
    }
    hdr->indx_cnt = indx_cnt;

    write_meta_blk(m_cp_meta_blk, b);
}

void StaticIndxMgr::attach_prepare_indx_cp_list(std::map< boost::uuids::uuid, indx_cp_ptr >* const cur_icp,
                                                std::map< boost::uuids::uuid, indx_cp_ptr >* const new_icp,
                                                hs_cp* const cur_hcp, hs_cp* const new_hcp) {
    if (try_blkalloc_checkpoint.load() || cur_hcp->ba_cp == nullptr) {
        new_hcp->ba_cp = m_hs->blkalloc_attach_prepare_cp(cur_hcp ? cur_hcp->ba_cp : nullptr);
        new_hcp->ba_cp->notify_size_on_done([](const uint64_t size) { ResourceMgrSI().dec_free_blk(size); });
        if (cur_hcp && cur_hcp->ba_cp) {
            cur_hcp->blkalloc_checkpoint = true;
            try_blkalloc_checkpoint.store(false);
        }
    } else {
        new_hcp->ba_cp = cur_hcp->ba_cp;
    }
    m_hs->attach_prepare_indx_cp(cur_icp, new_icp, cur_hcp, new_hcp);
}

void StaticIndxMgr::cp_done(const bool is_ba_cp) {
    std::unique_lock< std::mutex > lk{cb_list_mtx};
    if (is_ba_cp) {
        for (size_t i{0}; i < indx_cp_done_cb_list.size(); ++i) {
            indx_cp_done_cb_list[i](true);
        }
    } else {
        for (size_t i{0}; i < hs_cp_done_cb_list.size(); ++i) {
            hs_cp_done_cb_list[i](true);
        }
    }
}

void StaticIndxMgr::trigger_indx_cp() { m_cp_mgr->trigger_cp(); }
void StaticIndxMgr::trigger_indx_cp_with_cb(const cp_done_cb& cb) { m_cp_mgr->trigger_cp(cb); }
void StaticIndxMgr::trigger_hs_cp(const cp_done_cb& cb, const bool shutdown, const bool force) {
    if (!m_inited.load(std::memory_order_acquire)) {
        if (cb) { cb(true); }
        return;
    }
    /* set bit map checkpoint , resume cp and trigger it */
    if (!m_cp_mgr) {
        if (cb) { cb(true); }
        return;
    }
    bool expected{false};
    bool desired{shutdown};

    /* Make sure that no cp is triggered after shutdown is called */
    if (!m_shutdown_started.compare_exchange_strong(expected, desired)) {
        if (cb) { cb(false); }
        return;
    }
    try_blkalloc_checkpoint.store(true);
    /* This callback is called atleast in a blkalloc cp or a cp after that */
    m_cp_mgr->trigger_cp(cb, force);
}

void StaticIndxMgr::shutdown(indxmgr_stop_cb cb) {
    if (!m_inited.load(std::memory_order_acquire)) {
        LOGINFO("Indx Mgr not inited");
        cb(true);
        return;
    }
    LOGINFO("Indx Mgr shutdown started");
    iomanager.cancel_timer(m_hs_cp_timer_hdl);
    m_hs_cp_timer_hdl = iomgr::null_timer_handle;

    trigger_hs_cp(([cb](const bool success) {
                      /* verify that all the indx mgr have called their last cp */
                      if (m_cp_mgr) { m_cp_mgr->shutdown(); }
                      m_read_blk_tracker = nullptr;
                      m_hs.reset();
                      IndxMgr::m_btree_write_thread_ids.clear();
                      IndxMgr::m_btree_write_thread_ids.shrink_to_fit();
                      cb(success);
                  }),
                  true, true);
}

void StaticIndxMgr::meta_blk_found_cb(meta_blk* const mblk, const sisl::byte_view buf, const size_t size) {
    auto* const meta_hdr{reinterpret_cast< hs_cp_base_sb* >(buf.bytes())};
    HS_REL_ASSERT_EQ(meta_hdr->version, hcp_version);
    HS_REL_ASSERT_EQ(meta_hdr->magic, hcp_magic);
    if (meta_hdr->type == indx_meta_hdr_type::cp) {
        m_cp_meta_blk = mblk;
        hs_cp_sb* const cp_hdr{reinterpret_cast< hs_cp_sb* >(buf.bytes())};
        indx_cp_base_sb* const cp_sb{reinterpret_cast< indx_cp_base_sb* >(buf.bytes() + sizeof(hs_cp_sb))};

#ifndef NDEBUG
        // uint64_t temp_size{sizeof(hs_cp_sb_hdr) + hdr->indx_cnt * sizeof(indx_cp_sb)};
        // temp_size = sisl::round_up(size, HS_STATIC_CONFIG(drive_attr.align_size));
        // assert(size == temp_size);
#endif

        for (uint32_t i{0}; i < cp_hdr->indx_cnt; ++i) {
            bool happened{false};
            std::map< boost::uuids::uuid, indx_cp_base_sb >::iterator it;
            std::tie(it, happened) = cp_sb_map.emplace(std::make_pair(cp_sb[i].uuid, cp_sb[i]));
            HS_REL_ASSERT(happened, "happened is false");
        }
    } else {
        auto search{indx_meta_map.find(meta_hdr->uuid)};
        if (search == std::end(indx_meta_map)) {
            bool happened{false};
            std::vector< std::pair< void*, sisl::byte_array > > vec;
            std::tie(search, happened) = indx_meta_map.emplace(std::make_pair(meta_hdr->uuid, vec));
            HS_REL_ASSERT(happened, "happened is false");
        }
        // TO DO: Might need to address alignment based on data or fast type
        search->second.push_back(
            std::make_pair(mblk, hs_utils::extract_byte_array(buf, true, MetaBlkMgrSI()->get_align_size())));
    }
}

void StaticIndxMgr::write_meta_blk(void*& write_mblk, const sisl::byte_array& buf) {
    if (write_mblk) {
        MetaBlkMgrSI()->update_sub_sb((void*)buf->bytes, buf->size, write_mblk);
    } else {
        /* first time update */
        MetaBlkMgrSI()->add_sub_sb("INDX_MGR_CP", (void*)buf->bytes, buf->size, write_mblk);
    }
}

void StaticIndxMgr::register_hs_cp_done_cb(const cp_done_cb& cb, const bool is_blkalloc_cp) {
    std::unique_lock< std::mutex > lk{cb_list_mtx};
    if (is_blkalloc_cp) {
        indx_cp_done_cb_list.push_back(cb);
    } else {
        hs_cp_done_cb_list.push_back(cb);
    }
}

uint64_t StaticIndxMgr::free_blk(hs_cp* const hcp, blkid_list_ptr& out_fblk_list, Free_Blk_Entry& fbe, const bool force,
                                 const indx_req* const ireq) {
    return free_blk(hcp, out_fblk_list.get(), fbe, force);
}

uint64_t StaticIndxMgr::free_blk(hs_cp* hcp, sisl::ThreadVector< homestore::BlkId >* const out_fblk_list,
                                 Free_Blk_Entry& fbe, const bool force, const indx_req* const ireq) {
    if (!force && !ResourceMgrSI().can_add_free_blk(1)) {
        /* caller will trigger homestore cp */
        return 0;
    }

    /* incrementing the ref count. It will be decremented later when read blk tracker is ready to free the blk */
    if (!hcp) {
        hcp = m_cp_mgr->cp_io_enter();
    } else {
        m_cp_mgr->cp_inc_ref(hcp, 1);
    }

    auto* const data_blkstore_ptr{m_hs->get_data_blkstore()};
    const uint64_t free_blk_size{fbe.blks_to_free() * m_hs->get_data_pagesz()};
    ResourceMgrSI().inc_free_blk(free_blk_size);
    fbe.m_hcp = hcp;
    out_fblk_list->push_back(fbe.get_free_blkid());
    m_read_blk_tracker->safe_free_blks(fbe);
    HS_REL_ASSERT_GT(free_blk_size, 0);

    // release on realtime bitmap;
    const auto ret{data_blkstore_ptr->free_on_realtime(fbe.get_free_blkid())};
    if (ireq) {
        HS_REL_ASSERT(ret, "fail to free on realtime bm ireq {}", ireq->to_string());
    } else {
        HS_REL_ASSERT(ret, "free failed on realtime bitmap.");
    }
    return free_blk_size;
}

uint64_t StaticIndxMgr::free_blk(hs_cp* const hcp, blkid_list_ptr& out_fblk_list,
                                 std::vector< Free_Blk_Entry >& in_fbe_list, const bool force,
                                 const indx_req* const ireq) {
    return (free_blk(hcp, out_fblk_list.get(), in_fbe_list, force));
}

uint64_t StaticIndxMgr::free_blk(hs_cp* const hcp, sisl::ThreadVector< homestore::BlkId >* const out_fblk_list,
                                 std::vector< Free_Blk_Entry >& in_fbe_list, const bool force,
                                 const indx_req* const ireq) {
    if (!force && !ResourceMgrSI().can_add_free_blk(in_fbe_list.size())) {
        /* caller will trigger homestore cp */
        return 0;
    }

    uint64_t free_blk_size{0};
    for (auto& fbe : in_fbe_list) {
        free_blk_size += free_blk(hcp, out_fblk_list, fbe, true);
    }
    return free_blk_size;
}

void StaticIndxMgr::remove_read_tracker(const Free_Blk_Entry& fbe) { m_read_blk_tracker->remove(fbe); }

void StaticIndxMgr::add_read_tracker(const Free_Blk_Entry& fbe) { m_read_blk_tracker->insert(fbe); }
void StaticIndxMgr::hs_cp_suspend() { m_cp_mgr->cp_suspend(); }
void StaticIndxMgr::hs_cp_resume() { m_cp_mgr->cp_resume(); }

void StaticIndxMgr::safe_to_free_blk(const Free_Blk_Entry& fbe) {
    /* We don't allow cp to complete until all required blkids are freed. We increment the ref count in
     * update_indx_tbl by number of free blk entries.
     */
    auto* const hcp{fbe.m_hcp};
    assert(hcp);
    /* invalidate the cache */
    const auto page_sz{m_hs->get_data_pagesz()};
    m_hs->get_data_blkstore()->free_blk(fbe.get_base_blkid(), (fbe.blk_offset() * page_sz),
                                        (fbe.blks_to_free() * page_sz), true /* cache only */);
    m_cp_mgr->cp_io_exit(hcp);
    /* We have already free the blk after journal write is completed. We are just holding a cp for free to complete
     */
}

std::unique_ptr< HomeStoreCPMgr > StaticIndxMgr::m_cp_mgr;
std::atomic< bool > StaticIndxMgr::m_shutdown_started;
iomgr::io_thread_t StaticIndxMgr::m_thread_id;
iomgr::io_thread_t StaticIndxMgr::m_slow_path_thread_id;
std::vector< iomgr::io_thread_t > StaticIndxMgr::m_btree_write_thread_ids;
std::atomic< uint32_t > StaticIndxMgr::m_btree_write_thrd_idx{0};
iomgr::timer_handle_t StaticIndxMgr::m_hs_cp_timer_hdl = iomgr::null_timer_handle;
void* StaticIndxMgr::m_cp_meta_blk{nullptr};
std::once_flag StaticIndxMgr::m_flag;
std::map< boost::uuids::uuid, indx_cp_base_sb > StaticIndxMgr::cp_sb_map;
HomeStoreBaseSafePtr StaticIndxMgr::m_hs;
uint64_t StaticIndxMgr::memory_used_in_recovery{0};
std::atomic< bool > StaticIndxMgr::m_inited{false};
HomeStoreBaseSafePtr HomeStoreBase::s_instance;
std::mutex StaticIndxMgr::cb_list_mtx;
std::vector< cp_done_cb > StaticIndxMgr::indx_cp_done_cb_list;
std::vector< cp_done_cb > StaticIndxMgr::hs_cp_done_cb_list;
std::atomic< bool > StaticIndxMgr::try_blkalloc_checkpoint;
std::map< boost::uuids::uuid, std::vector< std::pair< void*, sisl::byte_array > > > StaticIndxMgr::indx_meta_map;
std::unique_ptr< Blk_Read_Tracker > StaticIndxMgr::m_read_blk_tracker;

bool indx_test_status::indx_create_suspend_cp_test{false};
