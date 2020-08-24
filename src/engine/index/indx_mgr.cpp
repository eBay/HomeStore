#include "indx_mgr.hpp"
#include "blk_read_tracker.hpp"
#include <utility/thread_factory.hpp>
#include <shared_mutex>
#include "homelogstore/log_store.hpp"
#include "engine/index/resource_mgr.hpp"
#include <engine/homeds/btree/btree.hpp>

using namespace homestore;
SDS_LOGGING_DECL(indx_mgr)
/* Journal entry
 * --------------------------------------------------------------------
 * | Journal Hdr | alloc_blkid list | checksum list | free_blk_entry |
 * -------------------------------------------------------------------
 */
indx_journal_entry::~indx_journal_entry() { m_iob.buf_free(); }

uint32_t indx_journal_entry::size(indx_req* ireq) const {
    return (sizeof(journal_hdr) + ireq->indx_alloc_blkid_list.size() * sizeof(BlkId) +
            ireq->indx_fbe_list.size() * sizeof(BlkId) + ireq->get_key_size() + ireq->get_val_size());
}

uint32_t indx_journal_entry::size() const {
    HS_ASSERT_CMP(DEBUG, m_iob.bytes, !=, nullptr);
    auto hdr = get_journal_hdr(m_iob.bytes);
    return (sizeof(journal_hdr) + hdr->alloc_blkid_list_size * sizeof(BlkId) +
            hdr->free_blk_entry_size * sizeof(BlkId) + hdr->key_size + hdr->val_size);
}

/* it update the alloc blk id and checksum */
sisl::io_blob indx_journal_entry::create_journal_entry(indx_req* ireq) {
    uint32_t size = sizeof(journal_hdr) + ireq->indx_alloc_blkid_list.size() * sizeof(BlkId) +
        ireq->indx_fbe_list.size() * sizeof(BlkId) + ireq->get_key_size() + ireq->get_val_size();

    uint32_t align = 0;
    if (HomeLogStore::is_aligned_buf_needed(size)) { align = HS_STATIC_CONFIG(disk_attr.align_size); }
    m_iob.buf_alloc(size, align);

    uint8_t* mem = m_iob.bytes;

    /* store journal hdr */
    auto hdr = get_journal_hdr(mem);
    hdr->alloc_blkid_list_size = ireq->indx_alloc_blkid_list.size();
    hdr->free_blk_entry_size = ireq->indx_fbe_list.size();
    hdr->key_size = ireq->get_key_size();
    hdr->val_size = ireq->get_val_size();
    /* store cp related info */
    hdr->cp_id = ireq->icp->cp_id;

    /* store alloc blkid */
    auto blkid_pair = get_alloc_bid_list(mem);
    auto blkid = blkid_pair.first;
    for (uint32_t i = 0; i < blkid_pair.second; ++i) {
        blkid[i] = ireq->indx_alloc_blkid_list[i];
    }

    /* store free blk entry */
    auto fbe_pair = get_free_bid_list(mem);
    auto fbe = fbe_pair.first;
    for (uint32_t i = 0; i < fbe_pair.second; ++i) {
        fbe[i] = ireq->indx_fbe_list[i].get_free_blkid();
    }

    /* store key */
    auto key_pair = get_key(mem);
    ireq->fill_key(key_pair.first, key_pair.second);

    /* store val */
    auto val_pair = get_val(mem);
    ireq->fill_val(val_pair.first, val_pair.second);

    return m_iob;
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

HomeStoreCPMgr::HomeStoreCPMgr() : CPMgr() {
    auto cp = get_cur_cp();
    cp_attach_prepare(nullptr, cp);
}

HomeStoreCPMgr::~HomeStoreCPMgr() {}

void HomeStoreCPMgr::cp_start(hs_cp* hcp) {
    iomanager.run_on(IndxMgr::get_thread_id(), [this, hcp](io_thread_addr_t addr) {
        hcp->ref_cnt.increment(1);
        HS_LOG(TRACE, cp, "Starting cp of type {}, number of indexes in cp={}",
               (hcp->blkalloc_checkpoint ? "blkalloc" : "Index"), hcp->indx_cp_list.size());
        for (auto it = hcp->indx_cp_list.begin(); it != hcp->indx_cp_list.end(); ++it) {
            if (it->second != nullptr && (it->second->state() != cp_state::suspend_cp)) {
                ++hcp->snt_cnt;
                hcp->ref_cnt.increment(1);
                auto indx_mgr = it->second->indx_mgr;
                indx_mgr->get_active_indx()->cp_start(
                    it->second->acp.bcp, ([this, hcp](const btree_cp_ptr& bcp) { indx_tbl_cp_done(hcp); }));
                if (it->second->state() & cp_state::diff_cp) {
                    ++hcp->snt_cnt;
                    hcp->ref_cnt.increment(1);
                    it->second->dcp.diff_tbl->cp_start(
                        it->second->dcp.bcp, ([this, hcp](const btree_cp_ptr& bcp) { indx_tbl_cp_done(hcp); }));
                }
            }
        }
        HS_LOG(TRACE, cp, "number of indexes participated {}", hcp->snt_cnt);
        indx_tbl_cp_done(hcp);
    });
}

void HomeStoreCPMgr::indx_tbl_cp_done(hs_cp* hcp) {
    if (!hcp->ref_cnt.decrement_testz(1)) { return; }

    HS_LOG(TRACE, cp, "Cp of type {} is completed", (hcp->blkalloc_checkpoint ? "blkalloc" : "Index"));
    if (hcp->blkalloc_checkpoint) {
        /* flush all the blks that are freed in this hcp */
        StaticIndxMgr::flush_hs_free_blks(hcp);

        /* persist alloc blkalloc. It is a sync call */
        blkalloc_cp_start(hcp);
    } else {
        /* All dirty buffers are flushed. Write super block */
        IndxMgr::write_hs_cp_sb(hcp);
    }

    bool is_blkalloc_cp = hcp->blkalloc_checkpoint;
    /* hcp will be freed after calling cp_end and indx_mgr might get destroy also */
    /* notify all the subsystems. */
    IndxMgr::cp_done(is_blkalloc_cp);
    cp_end(hcp);
}

/* This function calls
 * 1. persist blkalloc superblock
 * 2. write superblock
 * 3. truncate  :- it truncate upto the seq number persisted in this hcp.
 * 4. call cb_list
 * 5. notify blk alloc that cp hcp done
 * 6. call cp_end :- read comments over indxmgr::destroy().
 */
void HomeStoreCPMgr::blkalloc_cp_start(hs_cp* hcp) {
    HS_LOG(TRACE, indx_mgr, "Cp of type blkalloc, writing super block about cp");

    /* persist blk alloc bit maps */
    HomeStoreBase::instance()->blkalloc_cp_start(hcp->ba_cp);

    /* All dirty buffers are flushed. Write super block */
    IndxMgr::write_hs_cp_sb(hcp);

    /* Now it is safe to truncate as blkalloc bitsmaps are persisted */
    for (auto it = hcp->indx_cp_list.begin(); it != hcp->indx_cp_list.end(); ++it) {
        if (it->second == nullptr || it->second->flags == cp_state::suspend_cp ||
            !(it->second->flags & cp_state::ba_cp)) {
            continue;
        }
        it->second->indx_mgr->truncate(it->second);
    }
    home_log_store_mgr.device_truncate();
}

/* It attaches the new CP and prepare for cur cp flush */
void HomeStoreCPMgr::cp_attach_prepare(hs_cp* cur_cp, hs_cp* new_cp) {
    IndxMgr::attach_prepare_indx_cp_list(cur_cp ? &cur_cp->indx_cp_list : nullptr, &new_cp->indx_cp_list, cur_cp,
                                         new_cp);
}

/****************************************** IndxMgr class ****************************************/


IndxMgr::IndxMgr(boost::uuids::uuid uuid, std::string name, const io_done_cb& io_cb, const read_indx_comp_cb_t& read_cb,
                 const create_indx_tbl& func, bool is_snap_enabled) :
        m_io_cb(io_cb),
        m_read_cb(read_cb),
        m_uuid(uuid),
        m_name(name),
        m_last_cp_sb(m_uuid),
        m_recovery_mode(false),
        m_create_indx_tbl(func),
        m_is_snap_enabled(is_snap_enabled) {
    m_prepare_cb_list = std::make_unique< std::vector< prepare_cb > >();
    m_prepare_cb_list->reserve(4);
    m_active_tbl = m_create_indx_tbl();

    m_journal = HomeLogStoreMgr::instance().create_new_log_store();
    m_journal_comp_cb = bind_this(IndxMgr::journal_comp_cb, 2);
    m_journal->register_req_comp_cb(m_journal_comp_cb);
    for (int i = 0; i < MAX_CP_CNT; ++i) {
        m_free_list[i] = std::make_shared< sisl::ThreadVector< BlkId > >();
    }
}

/* Constructor for recovery */
IndxMgr::IndxMgr(boost::uuids::uuid uuid, std::string name, const io_done_cb& io_cb, const read_indx_comp_cb_t& read_cb,
                 const create_indx_tbl& create_func, const recover_indx_tbl& recover_func, indx_mgr_sb sb) :
        m_io_cb(io_cb),
        m_read_cb(read_cb),
        m_uuid(uuid),
        m_name(name),
        m_last_cp_sb(m_uuid),
        m_recovery_mode(true),
        m_create_indx_tbl(create_func),
        m_recover_indx_tbl(recover_func),
        m_immutable_sb(sb) {
    m_journal = nullptr;
    m_prepare_cb_list = std::make_unique< std::vector< prepare_cb > >();
    m_prepare_cb_list->reserve(4);

    m_is_snap_enabled = sb.is_snap_enabled;
    HomeLogStoreMgr::instance().open_log_store(
        sb.journal_id, ([this](std::shared_ptr< HomeLogStore > logstore) {
            m_journal = logstore;
            m_journal->register_log_found_cb(
                ([this](logstore_seq_num_t seqnum, log_buffer buf, void* mem) { this->log_found(seqnum, buf, mem); }));
            m_journal_comp_cb = bind_this(IndxMgr::journal_comp_cb, 2);
            m_journal->register_req_comp_cb(m_journal_comp_cb);
        }));
    for (int i = 0; i < MAX_CP_CNT; ++i) {
        m_free_list[i] = std::make_shared< sisl::ThreadVector< BlkId > >();
    }
}

IndxMgr::~IndxMgr() {
    delete m_active_tbl;
    for (uint32_t i = 0; i < MAX_CP_CNT; ++i) {
        HS_ASSERT_CMP(RELEASE, m_free_list[i]->size(), ==, 0);
    }

    if (m_shutdown_started) { static std::once_flag flag1; }
}

void IndxMgr::create_first_cp() {
    auto icp_sb = &(m_last_cp_sb.icp_sb);
    int64_t cp_id = icp_sb->active_cp_id + 1;
    int64_t seqid = icp_sb->active_data_seqid;
    m_first_icp = indx_cp_ptr(new indx_cp(cp_id, seqid, icp_sb->diff_data_seqid, shared_from_this(),
                                          m_free_list[++m_free_list_cnt % MAX_CP_CNT]));
    m_first_icp->acp.bcp = m_active_tbl->attach_prepare_cp(nullptr, false, false);
    if (m_recovery_mode) {
        THIS_INDX_LOG(TRACE, indx_mgr, , "creating indx mgr in recovery mode ");
        suspend_active_cp();
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
            HS_ASSERT_CMP(RELEASE, diff_snap_id, ==, snap_get_diff_id());
        }
        auto diff_btree_sb = snap_get_diff_tbl_sb();
        m_first_icp->dcp.diff_tbl = m_recover_indx_tbl(diff_btree_sb, dcp_sb);
        m_first_icp->dcp.diff_snap_id = diff_snap_id;
        m_first_icp->dcp.bcp = m_first_icp->dcp.diff_tbl->attach_prepare_cp(nullptr, false, false);
    } else {
        if (!m_is_snap_enabled) { return; }
        /* create new diff table */
        create_new_diff_tbl(m_first_icp);
    }
}

void IndxMgr::indx_create_done(indx_tbl* indx_tbl) { indx_tbl->create_done(); }

void IndxMgr::indx_init() {
    HS_ASSERT_CMP(RELEASE, m_recovery_mode, ==, false); // it is not called in recovery mode;
    create_first_cp();
    indx_create_done(m_active_tbl);
    std::call_once(m_flag, []() { StaticIndxMgr::init(); });
}

/* Note: snap mgr should not call it multiple times if a snapshot create is in progress. Indx mgr doesn't monitor
 * snapshot progress. It has to be to done in snap mgr.
 */
void IndxMgr::indx_snap_create() {
    THIS_INDX_LOG(TRACE, indx_mgr, , "snapshot create triggered indx name {}", m_name);
    add_prepare_cb_list(
        [this](const indx_cp_ptr& cur_icp, hs_cp* cur_hcp, hs_cp* new_hcp) {
            if (cur_icp->flags & cp_state::ba_cp) {
                HS_ASSERT(RELEASE, (cur_icp->flags & cp_state::diff_cp), "should be diff cp");
                /* We start snapshot create only if it is a blk alloc checkpoint */
                m_is_snap_started = true;
                m_cp_mgr->attach_cb(cur_hcp, ([this](bool success) {
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
    HS_ASSERT_CMP(RELEASE, m_recovery_mode, ==, true);
    THIS_INDX_LOG(INFO, base, , "recovery state {}", m_recovery_state);
    switch (m_recovery_state) {
    case indx_recovery_state::create_sb_st: {
        auto it = cp_sb_map.find(m_uuid);
        if (it != cp_sb_map.end()) { memcpy(&m_last_cp_sb, &(it->second), sizeof(m_last_cp_sb)); }
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
        io_replay();
    }
    // fall through
    case indx_recovery_state::meta_ops_replay_st: {
        /* lets go through all index meta blks to see if anything needs to be done */
        recover_meta_ops();
    }
    // fall through
    default: {
        m_recovery_mode = false;
    }
    }
    THIS_INDX_LOG(INFO, base, , "recovery completed");
}

void IndxMgr::io_replay() {
    HS_ASSERT_CMP(RELEASE, m_recovery_mode, ==, true);
    std::call_once(m_flag, []() { StaticIndxMgr::init(); });

    /* get the indx id */
    auto hcp = m_cp_mgr->cp_io_enter();
    auto icp = get_indx_cp(hcp);
    HS_ASSERT_CMP(RELEASE, icp, ==, m_first_icp);
    uint64_t diff_replay_cnt = 0;
    uint64_t blk_alloc_replay_cnt = 0;
    uint64_t active_replay_cnt = 0;
    uint64_t gaps_found_cnt = 0;

    THIS_INDX_LOG(INFO, base, , "last cp {} ", m_last_cp_sb.to_string());
    /* start replaying the entry in order of seq number */
    int64_t next_replay_seq_num = -1;
    if (m_is_snap_enabled) {
        next_replay_seq_num = m_last_cp_sb.icp_sb.diff_data_seqid + 1;
    } else {
        next_replay_seq_num = m_last_cp_sb.icp_sb.active_data_seqid + 1;
    }

    auto it = seq_buf_map.cbegin();
    while (it != seq_buf_map.cend()) {
        logstore_seq_num_t seq_num = it->first;
        auto buf = it->second;
        if (buf.bytes() == nullptr) {
            /* do sync read */
            buf = m_journal->read_sync(seq_num);
            ResourceMgr::inc_mem_used_in_recovery(buf.size());
        }
        auto hdr = indx_journal_entry::get_journal_hdr(buf.bytes());
        HS_ASSERT_NOTNULL(RELEASE, hdr);
        /* check if any blkids need to be freed or allocated. */
        HS_ASSERT_CMP(RELEASE, hdr->cp_id, >, -1);
        HS_ASSERT(RELEASE, (m_last_cp_sb.icp_sb.blkalloc_cp_id <= m_last_cp_sb.icp_sb.active_cp_id), "blkalloc cp id");
        if (hdr->cp_id > m_last_cp_sb.icp_sb.blkalloc_cp_id) {

            /* free blkids */
            auto fblkid_pair = indx_journal_entry::get_free_bid_list(buf.bytes());
            for (uint32_t i = 0; i < fblkid_pair.second; ++i) {
                BlkId fbid(fblkid_pair.first[i]);
                Free_Blk_Entry fbe(fbid, 0, fbid.get_nblks());
                auto size = free_blk(nullptr, icp->io_free_blkid_list, fbe, true);
                HS_ASSERT_CMP(DEBUG, size, >, 0);
                if (hdr->cp_id > m_last_cp_sb.icp_sb.active_cp_id) {
                    /* TODO: we update size in superblock with each checkpoint. Ideally it
                     * has to be updated only for blk alloc checkpoint.
                     */
                    icp->indx_size.fetch_sub(size, std::memory_order_relaxed);
                }
            }

            /* allocate blkids */
            auto alloc_pair = indx_journal_entry::get_alloc_bid_list(buf.bytes());
            for (uint32_t i = 0; i < alloc_pair.second; ++i) {
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
            ++next_replay_seq_num;
            ++gaps_found_cnt;
        }

        ++next_replay_seq_num;

        /* update active indx_tbl */
        if (hdr->cp_id > m_last_cp_sb.icp_sb.active_cp_id) {
            auto ret = m_active_tbl->recovery_update(seq_num, hdr, icp->acp.bcp);
            if (ret != btree_status_t::success) { abort(); }
            ++active_replay_cnt;
        }

        if (!m_is_snap_enabled) { goto next; }

        /* update diff indx tbl */
        if (hdr->cp_id > m_last_cp_sb.icp_sb.diff_cp_id) {
            auto ret = icp->dcp.diff_tbl->recovery_update(seq_num, hdr, icp->dcp.bcp);
            if (ret != btree_status_t::success) { abort(); }
            ++diff_replay_cnt;
        }
    next:
        ResourceMgr::dec_mem_used_in_recovery(buf.size());
        it = seq_buf_map.erase(it);
    }

    HS_ASSERT_CMP(DEBUG, seq_buf_map.size(), ==, 0);
    THIS_INDX_LOG(INFO, base, , "blk alloc replay cnt {} active_replay_cnt {} diff_replay_cnt{} gaps found {}",
                  blk_alloc_replay_cnt, active_replay_cnt, diff_replay_cnt, gaps_found_cnt);
    resume_active_cp();
    m_cp_mgr->cp_io_exit(hcp);
}

void IndxMgr::recover_meta_ops() {
    auto it = indx_meta_map.find(m_uuid);
    if (it == indx_meta_map.end()) { return; }
    std::vector< std::pair< void*, sisl::byte_view > >& meta_blk_list = it->second;
    for (uint32_t i = 0; i < meta_blk_list.size(); ++i) {
        auto hdr = (hs_cp_base_sb*)(meta_blk_list[i].second.bytes());
        THIS_INDX_LOG(INFO, base, , "found meta ops {} in recovery", (uint64_t)hdr->type);
        switch (hdr->type) {
        case INDX_CP:
            HS_ASSERT(DEBUG, 0, "invalid op");
            break;
        case INDX_DESTROY: {
            uint64_t cur_bytes = (uint64_t)(meta_blk_list[i].second.bytes()) + sizeof(hs_cp_base_sb);
            HS_ASSERT_CMP(RELEASE, meta_blk_list[i].second.size(), >=, (uint32_t)hdr->size);
            uint64_t size = hdr->size - sizeof(hs_cp_base_sb);
            sisl::blob b((uint8_t*)cur_bytes, size);
            m_active_tbl->get_btreequery_cur(b, m_destroy_btree_cur);
            m_destroy_meta_blk = meta_blk_list[i].first;
            /* it will be destroyed when destroy is called from volume */
            break;
        }
        case INDX_UNMAP:
            HS_ASSERT(DEBUG, 0, "invalid op");
            break;
        case SNAP_DESTROY:
            HS_ASSERT(DEBUG, 0, "invalid op");
            break;
        default:
            HS_ASSERT(DEBUG, 0, "invalid op");
        }
    }
}

indx_mgr_sb IndxMgr::get_immutable_sb() {
    indx_mgr_sb sb(m_active_tbl->get_btree_sb(), m_journal->get_store_id(), m_is_snap_enabled);
    return sb;
}

void IndxMgr::flush_free_blks(const indx_cp_ptr& icp, hs_cp* hcp) {
    THIS_INDX_LOG(TRACE, cp, , "flush free blks");
    /* free blks in a indx mgr */
    hcp->ba_cp->free_blks(icp->io_free_blkid_list);

    /* free all the user free blkid */
    for (uint32_t i = 0; i < icp->user_free_blkid_list.size(); ++i) {
        hcp->ba_cp->free_blks(icp->user_free_blkid_list[i]);
    }

    /* free blks in a btree */
    m_active_tbl->flush_free_blks(icp->acp.bcp, hcp->ba_cp);
    if (icp->flags & cp_state::diff_cp) { icp->dcp.diff_tbl->flush_free_blks(icp->dcp.bcp, hcp->ba_cp); }
}


void IndxMgr::update_cp_sb(indx_cp_ptr& icp, hs_cp* hcp, indx_cp_base_sb* sb) {
    /* copy the last superblock and then override the change values */
    THIS_INDX_LOG(TRACE, cp, , "updating cp superblock. CP info {}", icp->to_string());
    memcpy(sb, &m_last_cp_sb, sizeof(m_last_cp_sb));

    if (icp->flags == cp_state::suspend_cp) {
        /* nothing changed since last superblock */
        return;
    }

    HS_ASSERT_CMP(DEBUG, icp->acp.end_seqid, >=, icp->acp.start_seqid);
    HS_ASSERT_CMP(DEBUG, icp->cp_id, >, (int64_t)m_last_cp_sb.icp_sb.blkalloc_cp_id);
    HS_ASSERT_CMP(DEBUG, icp->cp_id, ==, (int64_t)(m_last_cp_sb.icp_sb.active_cp_id + 1));

    sb->uuid = m_uuid;

    /* update blk alloc cp */
    if (icp->flags & cp_state::ba_cp) { sb->icp_sb.blkalloc_cp_id = icp->cp_id; }

    sb->icp_sb.indx_size = icp->indx_size.load() + m_last_cp_sb.icp_sb.indx_size;

    /* update active checkpoint info */
    sb->icp_sb.active_data_seqid = icp->acp.end_seqid;
    sb->icp_sb.active_cp_id = icp->cp_id;

    /* update diff checkpoint info */
    if (icp->flags & cp_state::diff_cp) {
        sb->icp_sb.diff_cp_id = icp->cp_id;
        sb->icp_sb.diff_data_seqid = icp->dcp.end_seqid;
        sb->icp_sb.diff_max_seqid = icp->get_max_seqid();
        sb->icp_sb.diff_snap_id = icp->dcp.diff_snap_id;
        sb->icp_sb.snap_cp = m_is_snap_started;
    }

    m_active_tbl->update_btree_cp_sb(icp->acp.bcp, sb->acp_sb, (icp->flags & cp_state::ba_cp));

    if (icp->flags & cp_state::diff_cp) {
        icp->dcp.diff_tbl->update_btree_cp_sb(icp->dcp.bcp, sb->dcp_sb, (icp->flags & cp_state::ba_cp));
    }
    memcpy(&m_last_cp_sb, sb, sizeof(m_last_cp_sb));
    THIS_INDX_LOG(TRACE, cp, , "updating cp superblock. CP superblock info {}", m_last_cp_sb.to_string());
}

/* It attaches the new CP and prepare for cur cp flush */
indx_cp_ptr IndxMgr::attach_prepare_indx_cp(const indx_cp_ptr& cur_icp, hs_cp* cur_hcp, hs_cp* new_hcp) {
    if (cur_icp == nullptr) {
        /* this indx mgr is just created in the last CP. return the first_cp created at the timeof indx mgr
         * creation. And this indx mgr is not going to participate in the current cp. This indx mgr is going to
         * participate in the next cp.
         */
        HS_ASSERT_CMP(DEBUG, m_first_icp, !=, nullptr);
        /* if cur_hcp->blkalloc_checkpoint is set to true then it means it is created/destroy in a same cp.
         * we can not resume CP in this checkpoint. A indx mgr can never be added in a current cp.
         */
        THIS_INDX_LOG(TRACE, cp, , "returning first cp");
        return m_first_icp;
    }

    /* Beyond this point we can not change state of the CP */
    set_indx_cp_state(cur_icp, cur_hcp);

    if (cur_icp->flags == cp_state::suspend_cp) {
        /* this indx mgr is not going to participate in a current cp */
        THIS_INDX_LOG(TRACE, cp, , "cp is suspended");
        return cur_icp;
    }

    if (cur_icp == m_first_icp) { m_first_icp = nullptr; }

    /* call prepare_callback if any. One use case is attaching of free blkIds or attaching a callback to a CP based on
     * its state */
    call_prepare_cb(cur_icp, cur_hcp, new_hcp);

    /* attach the last seqid to this cp. IOs will be replayed after this seqid if this cp is taken successfully */
    cur_icp->acp.end_seqid = m_journal->get_contiguous_issued_seq_num(cur_icp->acp.start_seqid);
    if (cur_icp->flags & cp_state::diff_cp) { cur_icp->dcp.end_seqid = cur_icp->acp.end_seqid; }

    /* prepare btree cp and attach new CP for both active and diff */
    auto is_ba_cp = cur_icp->flags & cp_state::ba_cp;
    auto active_bcp = m_active_tbl->attach_prepare_cp(cur_icp->acp.bcp, m_last_cp, is_ba_cp);
    btree_cp_ptr diff_bcp;
    if (cur_icp->flags & cp_state::diff_cp) {
        /* if this diff table is going to a snapshot than this is the last cp on this indx tbl */
        THIS_INDX_LOG(TRACE, cp, , "it is diff cp");
        diff_bcp =
            cur_icp->dcp.diff_tbl->attach_prepare_cp(cur_icp->dcp.bcp, m_is_snap_started ? true : m_last_cp, is_ba_cp);
    } else {
        // diff cp is not taken yet
        diff_bcp = cur_icp->dcp.bcp;
    }

    /* If it is last cp return nullptr */
    if (m_last_cp) {
        HS_ASSERT_CMP(DEBUG, active_bcp, ==, nullptr);
        HS_ASSERT_CMP(DEBUG, diff_bcp, ==, nullptr);
        THIS_INDX_LOG(TRACE, cp, , "Last cp of this index triggered");
        return nullptr;
    }

    auto new_icp = create_new_indx_cp(cur_icp);
    THIS_INDX_LOG(TRACE, cp, , "is blk allocator cp {}", is_ba_cp);

    /* attach btree checkpoint to this new CP */
    new_icp->acp.bcp = active_bcp;
    if (m_is_snap_started) {
        HS_ASSERT(DEBUG, is_ba_cp, "should be blk alloc cp");
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
        HS_ASSERT(RELEASE, (!m_is_snap_started || diff_bcp), "m_is_snap_started {} diff_bcp {}", m_is_snap_started,
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
    if (cur_icp->flags & cp_state::ba_cp) {
        free_list = m_free_list[++m_free_list_cnt % MAX_CP_CNT];
        HS_ASSERT_CMP(RELEASE, free_list->size(), ==, 0);
    } else {
        /* we keep accumulating the free blks until blk checkpoint is not taken */
        free_list = cur_icp->io_free_blkid_list;
    }

    /* get start sequence ID */
    int64_t acp_start_seq_id = cur_icp->acp.end_seqid;
    int64_t dcp_start_seq_id = cur_icp->flags & cp_state::diff_cp ? cur_icp->dcp.end_seqid : cur_icp->dcp.start_seqid;

    /* create new cp */
    int64_t cp_id = cur_icp->cp_id + 1;
    indx_cp_ptr new_icp(new indx_cp(cp_id, acp_start_seq_id, dcp_start_seq_id, cur_icp->indx_mgr, free_list));
    return new_icp;
}

void IndxMgr::set_indx_cp_state(const indx_cp_ptr& cur_icp, hs_cp* cur_hcp) {
    /* We have to make a decision here to take blk alloc cp or not. We can not reverse our
     * decisioin beyond this point. */
    if (m_active_cp_suspend.load()) {
        cur_icp->flags = cp_state::suspend_cp;
        return;
    }
    cur_icp->flags = cp_state::active_cp;

    bool is_ba_cp = cur_hcp->blkalloc_checkpoint;
    if (is_ba_cp) {
        cur_icp->flags |= cp_state::ba_cp;
        if (m_is_snap_enabled) { cur_icp->flags |= cp_state::diff_cp; }
    }
    THIS_INDX_LOG(TRACE, cp, , "cp state {}", cur_icp->flags);
}

void IndxMgr::call_prepare_cb(const indx_cp_ptr& cur_icp, hs_cp* cur_hcp, hs_cp* new_hcp) {
    /* Go through the callback who is waiting for prepare to happen. Normally suspend, resume,
     * destroy waits for it. We can not move CP to suspend, active in middle of CP.
     */
    std::unique_ptr< std::vector< prepare_cb > > cb_list;
    {
        /* Go through the callback who is waiting for prepare to happen. Normally suspend, resume,
         * destroy waits for it. We can not move CP to suspend, active in middle of CP.
         */
        std::shared_lock< std::shared_mutex > m(m_prepare_cb_mtx);
        if (m_prepare_cb_list->size() != 0) {
            cb_list = std::move(m_prepare_cb_list);
            m_prepare_cb_list = std::make_unique< std::vector< prepare_cb > >();
            m_prepare_cb_list->reserve(4);
        }
    }

    if (cb_list) {
        THIS_INDX_LOG(TRACE, indx_mgr, , "Attach prepare cp waiting list size = {}", cb_list->size());
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
    THIS_INDX_LOG(TRACE, cp, , "create new diff table");
}

void IndxMgr::truncate(const indx_cp_ptr& icp) {
    m_journal->truncate(icp->acp.end_seqid);
    m_active_tbl->truncate(icp->acp.bcp);
    THIS_INDX_LOG(DEBUG, indx_mgr, , "uuid={} Truncating upto last seqid={}", m_uuid,
                  m_last_cp_sb.icp_sb.get_active_data_seqid());
}

indx_tbl* IndxMgr::get_active_indx() { return m_active_tbl; }

void IndxMgr::journal_comp_cb(logstore_req* lreq, logdev_key ld_key) {
    HS_ASSERT(DEBUG, ld_key.is_valid(), "key is invalid");
    auto ireq = indx_req_ptr((indx_req*)lreq->cookie, false); // Turn it back to smart ptr before doing callback.

    THIS_INDX_LOG(TRACE, indx_mgr, ireq, "Journal write done, lsn={}, log_key=[idx={}, offset={}]", lreq->seq_num,
                  ld_key.idx, ld_key.dev_offset);

    /* blk id is alloceted in disk bitmap only after it is writing to journal. check
     * blk_alloctor base class for further explanations. It should be done in cp critical section.
     * Otherwise bitmap won't reflect all the blks allocated in a cp.
     *
     * It is also possible that indx_alloc_blkis list contain the less number of blkids that allocated because of
     * partial writes. We are not freeing it in cache right away. There is no reason to not do it. We are not
     * setting it in disk bitmap so in next reboot it will be available to use.
     */

    for (uint32_t i = 0; i < ireq->indx_alloc_blkid_list.size(); ++i) {
        m_hs->get_data_blkstore()->reserve_blk(ireq->indx_alloc_blkid_list[i]);
        /* update size */
        ireq->icp->indx_size.fetch_add(ireq->indx_alloc_blkid_list[i].data_size(m_hs->get_data_pagesz()),
                                       std::memory_order_relaxed);
    }

    /* free the blkids */
    auto free_size = free_blk(ireq->hcp, ireq->icp->io_free_blkid_list, ireq->indx_fbe_list, true);
    HS_ASSERT(DEBUG, (ireq->indx_fbe_list.size() == 0 || free_size > 0),
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
    logstore_req::free(lreq);
}

void IndxMgr::journal_write(indx_req* ireq) {
    auto b = ireq->create_journal_entry();
    auto lreq = logstore_req::make(m_journal.get(), ireq->get_seqid(), b);
    lreq->cookie = (void*)ireq;
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
btree_status_t IndxMgr::update_indx_tbl(indx_req* ireq, bool is_active) {
    if (is_active) {
        auto bcp = ireq->icp->acp.bcp;
        auto status = m_active_tbl->update_active_indx_tbl(ireq, bcp);
        if (status == btree_status_t::fast_path_not_possible) {
            /* call run_on in async mode */
            iomanager.run_on(m_slow_path_thread_id, [this, ireq](io_thread_addr_t addr) mutable {
                THIS_INDX_LOG(DEBUG, indx_mgr, ireq, "Slow path write triggered.");
                HS_ASSERT_CMP(DEBUG, ireq->state, ==, indx_req_state::active_btree);
                update_indx_internal(ireq);
            });
        }
        return status;
    } else {
        // we are here only when active btree write is in fast path;
        auto bcp = ireq->icp->dcp.bcp;
        auto diff_tbl = ireq->icp->dcp.diff_tbl;
        assert(diff_tbl != nullptr);
        auto status = diff_tbl->update_diff_indx_tbl(ireq, bcp);

        if (status == btree_status_t::fast_path_not_possible) {
            /* call run_on in async mode */
            iomanager.run_on(m_slow_path_thread_id, [this, ireq](io_thread_addr_t addr) mutable {
                THIS_INDX_LOG(DEBUG, indx_mgr, ireq, "Slow path write triggered.");
                HS_ASSERT_CMP(DEBUG, ireq->state, ==, indx_req_state::diff_btree);
                update_indx_internal(ireq);
            });
        }
        return status;
    }
}

void IndxMgr::update_indx(indx_req_ptr ireq) {
    /* Journal write is async call. So incrementing the ref on indx req */
    ireq->inc_ref();

    /* Entered into critical section. CP is not triggered in this critical section */
    ireq->hcp = m_cp_mgr->cp_io_enter();
    ireq->icp = get_indx_cp(ireq->hcp);

    ireq->state = indx_req_state::active_btree;
    update_indx_internal(ireq);
}

/* * this function can be called either in fast path or slow path * */
void IndxMgr::update_indx_internal(indx_req_ptr ireq) {
    auto ret = btree_status_t::success;
    switch (ireq->state) {
    case indx_req_state::active_btree:
        /* update active btree */
        THIS_INDX_LOG(TRACE, indx_mgr, ireq, "updating active btree");
        ret = update_indx_tbl(ireq.get(), true /* is_active */);
        /* we call cp exit on both the CPs only when journal is written otherwise there could be blkid leak */
        if (ret == btree_status_t::cp_mismatch) { ret = retry_update_indx(ireq, true /* is_active */); }
        /* TODO : we don't allow partial failure for now. If we have to allow that we have to support undo */
        THIS_INDX_LOG(TRACE, indx_mgr, ireq, "updating active btree status {}", ret);
        if (ret != btree_status_t::success && ret != btree_status_t::fast_path_not_possible) {
            HS_ASSERT(DEBUG, false, "return val unexpected: {}", ret);
        }

        if (ret == btree_status_t::fast_path_not_possible) { return; }

        /* fall through */
    case indx_req_state::diff_btree:
        THIS_INDX_LOG(TRACE, indx_mgr, ireq, "updating diff btree");
        ireq->state = indx_req_state::diff_btree;
        /* update diff btree. */
        if (m_is_snap_enabled) {
            auto ret = update_indx_tbl(ireq.get(), false);
            /* we call cp exit on both the CPs only when journal is written otherwise there could be blkid leak */
            if (ret == btree_status_t::cp_mismatch) { ret = retry_update_indx(ireq.get(), false); }
            if (ret != btree_status_t::success && ret != btree_status_t::fast_path_not_possible) {
                HS_ASSERT(DEBUG, false, "return val unexpected: {}", ret);
            }
        }

        THIS_INDX_LOG(TRACE, indx_mgr, ireq, "updating diff btree status {}", ret);
        if (ret == btree_status_t::fast_path_not_possible) { return; }

        break;

    default:
        HS_ASSERT(RELEASE, false, "Unsupported ireq state: ", ireq->state);
    }

    if (ret != btree_status_t::success) { ireq->indx_err = btree_write_failed; }

    /* Update allocate blkids in indx req */
    m_active_tbl->update_indx_alloc_blkids(ireq.get());

    /* In case of failure we will still update the journal with entries of whatever is written. */
    /* update journal. Journal writes are not expected to fail. It is async call/ */
    journal_write(ireq.get());
}

/* It is called when first update failed because btree is updated by latest CP and indx mgr got old cp */
btree_status_t IndxMgr::retry_update_indx(const indx_req_ptr& ireq, bool is_active) {
    ireq->first_hcp = ireq->hcp;
    /* try again to get the new cp */
    ireq->hcp = m_cp_mgr->cp_io_enter();
    ireq->icp = get_indx_cp(ireq->hcp);
    HS_ASSERT(RELEASE, (ireq->hcp != ireq->first_hcp), "cp is same");
    auto ret = update_indx_tbl(ireq.get(), is_active);

    /* we can not get mismatch again as we only have two cps pending at any given time */
    HS_ASSERT_CMP(RELEASE, ret, !=, btree_status_t::cp_mismatch);
    return ret;
}

btree_cp_ptr IndxMgr::get_btree_cp(hs_cp* hcp) {
    auto icp = get_indx_cp(hcp);
    if (icp) { return (icp->acp.bcp); }
    return nullptr;
}

indx_cp_ptr IndxMgr::get_indx_cp(hs_cp* hcp) {
    auto it = hcp->indx_cp_list.find(m_uuid);
    indx_cp_ptr bcp;
    if (it == hcp->indx_cp_list.end()) {
        /* indx mgr is just created. So take the first cp. */
        HS_ASSERT_CMP(DEBUG, m_first_icp, !=, nullptr);
        return (m_first_icp);
    } else {
        HS_ASSERT_CMP(DEBUG, it->second, !=, nullptr);
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
    THIS_INDX_LOG(INFO, base, , "Destroying Indx Manager");
    m_stop_cb = cb;
    iomanager.run_on(m_thread_id, [this](io_thread_addr_t addr) { this->destroy_indx_tbl(); });
}

void IndxMgr::destroy_indx_tbl() {
    /* free all blkids of btree in memory */
    blkid_list_ptr free_list = std::make_shared< sisl::ThreadVector< BlkId > >();
    int64_t free_size = 0;
    btree_status_t ret = m_active_tbl->free_user_blkids(free_list, m_destroy_btree_cur, free_size);
    if (ret != btree_status_t::success) {
        HS_ASSERT_CMP(RELEASE, ret, ==, btree_status_t::resource_full);
        THIS_INDX_LOG(INFO, base, , "free_user_blkids btree ret status resource_full");
        attach_user_fblkid_list(free_list, ([this](bool success) {
                                    /* persist superblock */
                                    const sisl::blob& cursor_blob = m_destroy_btree_cur.serialize();
                                    if (cursor_blob.size) {
                                        uint64_t size = cursor_blob.size + sizeof(hs_cp_base_sb);
                                        uint32_t align = 0;
                                        if (meta_blk_mgr->is_aligned_buf_needed(size)) {
                                            align = HS_STATIC_CONFIG(disk_attr.align_size);
                                            size = sisl::round_up(size, align);
                                        }
                                        sisl::byte_view b(size, align);
                                        hs_cp_base_sb* mhdr = (hs_cp_base_sb*)b.bytes();
                                        mhdr->uuid = m_uuid;
                                        mhdr->type = INDX_DESTROY;
                                        mhdr->size = cursor_blob.size + sizeof(hs_cp_base_sb);
                                        memcpy((uint8_t*)((uint64_t)b.bytes() + sizeof(hs_cp_base_sb)),
                                               cursor_blob.bytes, cursor_blob.size);
                                        write_meta_blk(m_destroy_meta_blk, b);
                                    }

                                    /* send message to thread to start freeing the blkid */
                                    iomanager.run_on(m_thread_id,
                                                     [this](io_thread_addr_t addr) { this->destroy_indx_tbl(); });
                                }),
                                free_size);
        return;
    }

    THIS_INDX_LOG(TRACE, indx_mgr, , "All user logs are collected");
    uint64_t free_node_cnt = 0;
    m_active_tbl->destroy(free_list, free_node_cnt);
    attach_user_fblkid_list(free_list, ([this](bool success) {
                                /* remove the meta blk which is used to track vol destroy progress */
                                if (m_destroy_meta_blk) { MetaBlkMgr::instance()->remove_sub_sb(m_destroy_meta_blk); }
                                m_stop_cb(success);
                            }),
                            free_size, true);
}

void IndxMgr::attach_user_fblkid_list(blkid_list_ptr& free_blkid_list, const cp_done_cb& free_blks_cb,
                                      int64_t free_size, bool last_cp) {
    add_prepare_cb_list(([this, free_blkid_list, free_blks_cb, free_size,
                          last_cp](const indx_cp_ptr& cur_icp, hs_cp* cur_hcp, hs_cp* new_hcp) mutable {
        if (cur_icp->flags & cp_state::ba_cp) {
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
    HS_ASSERT_CMP(RELEASE, m_active_cp_suspend.load(), ==, false);
    m_active_cp_suspend = true;
}

void IndxMgr::resume_active_cp() {
    HS_ASSERT_CMP(RELEASE, m_active_cp_suspend.load(), ==, true);
    m_active_cp_suspend = false;
}

void IndxMgr::destroy_done() {
    m_active_tbl->destroy_done();
    home_log_store_mgr.remove_log_store(m_journal->get_store_id());
}

void IndxMgr::log_found(logstore_seq_num_t seqnum, log_buffer log_buf, void* mem) {
    std::map< logstore_seq_num_t, log_buffer >::iterator it;
    bool happened;
    if (ResourceMgr::can_add_mem_in_recovery(log_buf.size())) {
        std::tie(it, happened) = seq_buf_map.emplace(std::make_pair(seqnum, log_buf));
        ResourceMgr::inc_mem_used_in_recovery(log_buf.size());
    } else {
        log_buffer nullbuf;
        std::tie(it, happened) = seq_buf_map.emplace(std::make_pair(seqnum, nullbuf));
    }
    if (seqnum > m_max_seqid_in_recovery) { m_max_seqid_in_recovery = seqnum; }
    HS_ASSERT(RELEASE, happened, "happened");
}

void IndxMgr::read_indx(const boost::intrusive_ptr< indx_req >& ireq) {
    auto ret = m_active_tbl->read_indx(ireq.get(), m_read_cb);

    if (ret == btree_status_t::fast_path_not_possible) {
        iomanager.run_on(m_slow_path_thread_id, [this, ireq](io_thread_addr_t addr) mutable {
            THIS_INDX_LOG(DEBUG, indx_mgr, ireq, "Slow path write triggered.");
            auto status = m_active_tbl->read_indx(ireq.get(), m_read_cb);

            // no expect has_more in read case;
            HS_ASSERT_CMP(DEBUG, status, !=, btree_status_t::has_more);

            // this read could either fail or succeed, in either case, mapping layer will callback to client;
        });
    }
}

cap_attrs IndxMgr::get_used_size() {
    cap_attrs attrs;
    attrs.used_data_size = m_last_cp_sb.icp_sb.indx_size;
    attrs.used_index_size = m_active_tbl->get_used_size();
    attrs.used_total_size = attrs.used_data_size + attrs.used_index_size;
    return attrs;
}

int64_t IndxMgr::get_max_seqid_found_in_recovery() { return m_max_seqid_in_recovery; }
std::string IndxMgr::get_name() { return m_name; }

void IndxMgr::register_indx_cp_done_cb(const cp_done_cb& cb, bool blkalloc_cp) {
    add_prepare_cb_list(([this, cb, blkalloc_cp](const indx_cp_ptr& cur_icp, hs_cp* cur_hcp, hs_cp* new_hcp) mutable {
        if (blkalloc_cp) {
            if (cur_icp->flags & cp_state::ba_cp) {
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

/********************** Static Indx mgr functions *********************************/

REGISTER_METABLK_SUBSYSTEM(indx_mgr, "INDX_MGR_CP", StaticIndxMgr::meta_blk_found_cb, nullptr)

void StaticIndxMgr::init() {
    static std::atomic< int64_t > thread_cnt = 0;
    int expected_thread_cnt = 0;
    HS_ASSERT(DEBUG, !m_inited, "init is true");
    m_hs = HomeStoreBase::instance();
    m_shutdown_started.store(false);
    try_blkalloc_checkpoint.set(false);

    m_cp_mgr = std::unique_ptr< HomeStoreCPMgr >(new HomeStoreCPMgr());
    m_read_blk_tracker = std::unique_ptr< Blk_Read_Tracker >(new Blk_Read_Tracker(IndxMgr::safe_to_free_blk));
    /* start the timer for blkalloc checkpoint */
    m_hs_cp_timer_hdl =
        iomanager.schedule_global_timer(HS_DYNAMIC_CONFIG(generic.blkalloc_cp_timer_us) * 1000, true, nullptr,
                                        iomgr::thread_regex::all_user, [](void* cookie) { trigger_hs_cp(); });
    auto sthread = sisl::named_thread("indx_mgr", []() mutable {
        iomanager.run_io_loop(false, nullptr, [](bool is_started) {
            if (is_started) {
                IndxMgr::m_thread_id = iomanager.iothread_self();
                thread_cnt++;
            }
        });
    });
    sthread.detach();
    expected_thread_cnt++;

    auto sthread2 = sisl::named_thread("indx_mgr_btree_slow", []() {
        iomanager.run_io_loop(false, nullptr, [](bool is_started) {
            if (is_started) {
                IndxMgr::m_slow_path_thread_id = iomanager.iothread_self();
                thread_cnt++;
            }
        });
    });

    sthread2.detach();
    expected_thread_cnt++;

    while (thread_cnt.load(std::memory_order_acquire) != expected_thread_cnt) {}
    IndxMgr::m_inited.store(true, std::memory_order_release);
}

void StaticIndxMgr::flush_hs_free_blks(hs_cp* hcp) {
    for (auto it = hcp->indx_cp_list.begin(); it != hcp->indx_cp_list.end(); ++it) {
        if (it->second == nullptr || !(it->second->flags & cp_state::ba_cp)) {
            /* nothing to free. */
            continue;
        }
        /* free blks in a indx mgr */
        it->second->indx_mgr->flush_free_blks(it->second, hcp);
    }
}

void StaticIndxMgr::write_hs_cp_sb(hs_cp* hcp) {
    uint64_t size = sizeof(indx_cp_base_sb) * hcp->indx_cp_list.size() + sizeof(hs_cp_sb);
    uint32_t align = 0;
    if (meta_blk_mgr->is_aligned_buf_needed(size)) {
        align = HS_STATIC_CONFIG(disk_attr.align_size);
        size = sisl::round_up(size, align);
    }
    sisl::byte_view b(size, align);

    hs_cp_sb* hdr = (hs_cp_sb*)b.bytes();
    hdr->version = INDX_MGR_VERSION;
    hdr->type = meta_hdr_type::INDX_CP;
    int indx_cnt = 0;
    indx_cp_base_sb* indx_cp_base_sb_list = (indx_cp_base_sb*)((uint64_t)hdr + sizeof(hs_cp_sb));
    for (auto it = hcp->indx_cp_list.begin(); it != hcp->indx_cp_list.end(); ++it) {
        auto icp = it->second;
        it->second->indx_mgr->update_cp_sb(icp, hcp, &indx_cp_base_sb_list[indx_cnt++]);
    }
    hdr->indx_cnt = indx_cnt;

    write_meta_blk(m_cp_meta_blk, b);
}

void StaticIndxMgr::attach_prepare_indx_cp_list(std::map< boost::uuids::uuid, indx_cp_ptr >* cur_icp,
                                                std::map< boost::uuids::uuid, indx_cp_ptr >* new_icp, hs_cp* cur_hcp,
                                                hs_cp* new_hcp) {
    if (cur_hcp == nullptr || try_blkalloc_checkpoint.get()) {
        new_hcp->ba_cp = HomeStoreBase::instance()->blkalloc_attach_prepare_cp(cur_hcp ? cur_hcp->ba_cp : nullptr);
        if (cur_hcp) {
            cur_hcp->blkalloc_checkpoint = true;
            try_blkalloc_checkpoint.set(false);
        }
    } else {
        new_hcp->ba_cp = cur_hcp->ba_cp;
    }
    m_hs->attach_prepare_indx_cp(cur_icp, new_icp, cur_hcp, new_hcp);
}

void StaticIndxMgr::cp_done(bool is_ba_cp) {
    std::unique_lock< std::mutex > lk(cb_list_mtx);
    if (is_ba_cp) {
        for (uint32_t i = 0; i < indx_cp_done_cb_list.size(); ++i) {
            indx_cp_done_cb_list[i](true);
        }
    } else {
        for (uint32_t i = 0; i < hs_cp_done_cb_list.size(); ++i) {
            hs_cp_done_cb_list[i](true);
        }
    }
}

void StaticIndxMgr::trigger_indx_cp() { m_cp_mgr->trigger_cp(); }
void StaticIndxMgr::trigger_indx_cp_with_cb(const cp_done_cb& cb) { m_cp_mgr->trigger_cp(cb); }
void StaticIndxMgr::trigger_hs_cp(const cp_done_cb& cb, bool shutdown, bool force) {
    if (!m_inited.load(std::memory_order_acquire)) {
        if (cb) { cb(true); }
        return;
    }
    /* set bit map checkpoint , resume cp and trigger it */
    if (!m_cp_mgr) {
        if (cb) { cb(true); }
        return;
    }
    bool expected = false;
    bool desired = shutdown;

    /* Make sure that no cp is triggered after shutdown is called */
    if (!m_shutdown_started.compare_exchange_strong(expected, desired)) {
        if (cb) { cb(false); }
        return;
    }
    try_blkalloc_checkpoint.set(true);
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
    trigger_hs_cp(([cb](bool success) {
                      /* verify that all the indx mgr have called their last cp */
                      if (m_cp_mgr) { m_cp_mgr->shutdown(); }
                      m_read_blk_tracker = nullptr;
                      cb(success);
                  }),
                  true, true);
}

void StaticIndxMgr::meta_blk_found_cb(meta_blk* mblk, sisl::byte_view buf, size_t size) {
    auto meta_hdr = (hs_cp_base_sb*)buf.bytes();
    if (meta_hdr->type == INDX_CP) {
        m_cp_meta_blk = mblk;
        hs_cp_sb* cp_hdr = (hs_cp_sb*)buf.bytes();
        HS_ASSERT_CMP(RELEASE, (int)(cp_hdr->version), ==, INDX_MGR_VERSION);
        indx_cp_base_sb* cp_sb = (indx_cp_base_sb*)((uint64_t)buf.bytes() + sizeof(hs_cp_sb));

#ifndef NDEBUG
        // uint64_t temp_size = sizeof(hs_cp_sb_hdr) + hdr->indx_cnt * sizeof(indx_cp_sb);
        // temp_size = sisl::round_up(size, HS_STATIC_CONFIG(disk_attr.align_size));
        // assert(size == temp_size);
#endif

        for (uint32_t i = 0; i < cp_hdr->indx_cnt; ++i) {
            bool happened{false};
            std::map< boost::uuids::uuid, indx_cp_base_sb >::iterator it;
            std::tie(it, happened) = cp_sb_map.emplace(std::make_pair(cp_sb[i].uuid, cp_sb[i]));
            HS_ASSERT(RELEASE, happened, "happened is false");
        }
    } else {
        auto search = indx_meta_map.find(meta_hdr->uuid);
        if (search == indx_meta_map.end()) {
            bool happened = false;
            std::vector< std::pair< void*, sisl::byte_view > > vec;
            std::tie(search, happened) = indx_meta_map.emplace(std::make_pair(meta_hdr->uuid, vec));
            HS_ASSERT(RELEASE, happened, "happened is false");
        }
        search->second.push_back(std::make_pair(mblk, buf));
    }
}

void StaticIndxMgr::write_meta_blk(void*& write_mblk, sisl::byte_view buf) {
    if (write_mblk) {
        MetaBlkMgr::instance()->update_sub_sb((void*)buf.bytes(), buf.size(), write_mblk);
    } else {
        /* first time update */
        MetaBlkMgr::instance()->add_sub_sb("INDX_MGR_CP", (void*)buf.bytes(), buf.size(), write_mblk);
    }
}

void StaticIndxMgr::register_hs_cp_done_cb(const cp_done_cb& cb, bool is_blkalloc_cp) {
    std::unique_lock< std::mutex > lk(cb_list_mtx);
    if (is_blkalloc_cp) {
        indx_cp_done_cb_list.push_back(cb);
    } else {
        hs_cp_done_cb_list.push_back(cb);
    }
}

uint64_t StaticIndxMgr::free_blk(hs_cp* hcp, blkid_list_ptr& out_fblk_list, Free_Blk_Entry& fbe, bool force) {
    return free_blk(hcp, out_fblk_list.get(), fbe, force);
}

uint64_t StaticIndxMgr::free_blk(hs_cp* hcp, sisl::ThreadVector< homestore::BlkId >* out_fblk_list, Free_Blk_Entry& fbe,
                                 bool force) {
    if (!force && !ResourceMgr::can_add_free_blk(1)) {
        /* caller will trigger homestore cp */
        return 0;
    }

    /* incrementing the ref count. It will be decremented later when read blk tracker is ready to free the blk */
    if (!hcp) {
        hcp = m_cp_mgr->cp_io_enter();
    } else {
        m_cp_mgr->cp_inc_ref(hcp, 1);
    }

    uint64_t free_blk_size = fbe.blks_to_free() * m_hs->get_data_pagesz();
    ResourceMgr::inc_free_blk(free_blk_size);
    fbe.m_hcp = hcp;
    out_fblk_list->push_back(fbe.get_free_blkid());
    m_read_blk_tracker->safe_free_blks(fbe);

    HS_ASSERT_CMP(RELEASE, free_blk_size, >, 0);
    return free_blk_size;
}

uint64_t StaticIndxMgr::free_blk(hs_cp* hcp, blkid_list_ptr& out_fblk_list, std::vector< Free_Blk_Entry >& in_fbe_list,
                                 bool force) {
    return (free_blk(hcp, out_fblk_list.get(), in_fbe_list, force));
}

uint64_t StaticIndxMgr::free_blk(hs_cp* hcp, sisl::ThreadVector< homestore::BlkId >* out_fblk_list,
                                 std::vector< Free_Blk_Entry >& in_fbe_list, bool force) {
    if (!force && !ResourceMgr::can_add_free_blk(in_fbe_list.size())) {
        /* caller will trigger homestore cp */
        return 0;
    }

    uint64_t free_blk_size = 0;
    for (uint32_t i = 0; i < in_fbe_list.size(); ++i) {
        free_blk_size += free_blk(hcp, out_fblk_list, in_fbe_list[i], true);
    }
    return free_blk_size;
}

void StaticIndxMgr::remove_read_tracker(Free_Blk_Entry& fbe) { m_read_blk_tracker->remove(fbe); }

void StaticIndxMgr::add_read_tracker(Free_Blk_Entry& fbe) { m_read_blk_tracker->insert(fbe); }

void StaticIndxMgr::safe_to_free_blk(Free_Blk_Entry& fbe) {
    /* We don't allow cp to complete until all required blkids are freed. We increment the ref count in
     * update_indx_tbl by number of free blk entries.
     */
    auto hcp = fbe.m_hcp;
    assert(hcp);
    /* invalidate the cache */
    auto page_sz = m_hs->get_data_pagesz();
    m_hs->get_data_blkstore()->free_blk(fbe.m_blkId, (fbe.m_blk_offset * page_sz), (fbe.m_nblks_to_free * page_sz),
                                        true);
    m_cp_mgr->cp_io_exit(hcp);
    /* We have already free the blk after journal write is completed. We are just holding a cp for free to complete
     */
}

std::unique_ptr< HomeStoreCPMgr > StaticIndxMgr::m_cp_mgr;
std::atomic< bool > StaticIndxMgr::m_shutdown_started;
iomgr::io_thread_t StaticIndxMgr::m_thread_id;
iomgr::io_thread_t StaticIndxMgr::m_slow_path_thread_id;
iomgr::timer_handle_t StaticIndxMgr::m_hs_cp_timer_hdl = iomgr::null_timer_handle;
void* StaticIndxMgr::m_cp_meta_blk = nullptr;
std::once_flag StaticIndxMgr::m_flag;
sisl::aligned_unique_ptr< uint8_t > StaticIndxMgr::m_recovery_sb;
std::map< boost::uuids::uuid, indx_cp_base_sb > StaticIndxMgr::cp_sb_map;
size_t StaticIndxMgr::m_recovery_sb_size = 0;
HomeStoreBase* StaticIndxMgr::m_hs;
uint64_t StaticIndxMgr::memory_used_in_recovery = 0;
std::atomic< bool > StaticIndxMgr::m_inited = false;
HomeStoreBase::HomeStoreBaseSafePtr HomeStoreBase::_instance;
std::mutex StaticIndxMgr::cb_list_mtx;
std::vector< cp_done_cb > StaticIndxMgr::indx_cp_done_cb_list;
std::vector< cp_done_cb > StaticIndxMgr::hs_cp_done_cb_list;
sisl::atomic_counter< bool > StaticIndxMgr::try_blkalloc_checkpoint;
std::map< boost::uuids::uuid, std::vector< std::pair< void*, sisl::byte_view > > > StaticIndxMgr::indx_meta_map;
std::unique_ptr< Blk_Read_Tracker > StaticIndxMgr::m_read_blk_tracker;
std::atomic< int64_t > ResourceMgr::m_hs_dirty_buf_cnt;
std::atomic< int64_t > ResourceMgr::m_hs_fb_cnt;
std::atomic< int64_t > ResourceMgr::m_hs_fb_size;
std::atomic< int64_t > ResourceMgr::m_memory_used_in_recovery;
uint64_t ResourceMgr::m_total_cap;
