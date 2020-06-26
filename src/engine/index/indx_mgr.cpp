#include "indx_mgr_api.hpp"
#include <utility/thread_factory.hpp>
#include "engine/common/homestore_io_blob.hpp"

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
            ireq->fbe_list.size() * sizeof(BlkId) + ireq->get_key_size() + ireq->get_val_size());
}

uint32_t indx_journal_entry::size() const {
    assert(m_iob.bytes != nullptr);
    auto hdr = get_journal_hdr(m_iob.bytes);
    return (sizeof(journal_hdr) + hdr->alloc_blkid_list_size * sizeof(BlkId) +
            hdr->free_blk_entry_size * sizeof(BlkId) + hdr->key_size + hdr->val_size);
}

/* it update the alloc blk id and checksum */
sisl::blob indx_journal_entry::create_journal_entry(indx_req* ireq) {
    uint32_t size = sizeof(journal_hdr) + ireq->indx_alloc_blkid_list.size() * sizeof(BlkId) +
        ireq->fbe_list.size() * sizeof(BlkId) + ireq->get_key_size() + ireq->get_val_size();

    uint32_t align = 0;
    if (HomeLogStore::is_aligned_buf_needed(size)) { align = HS_STATIC_CONFIG(disk_attr.align_size); }

    m_iob.buf_alloc(size, align);

    uint8_t* mem = m_iob.bytes;

    /* store journal hdr */
    auto hdr = get_journal_hdr(mem);
    hdr->alloc_blkid_list_size = ireq->indx_alloc_blkid_list.size();
    hdr->free_blk_entry_size = ireq->fbe_list.size();
    hdr->key_size = ireq->get_key_size();
    hdr->val_size = ireq->get_val_size();
    /* store cp related info */
    hdr->cp_cnt = ireq->indx_id->cp_cnt;

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
        fbe[i] = ireq->fbe_list[i].get_free_blkid();
    }

    /* store key */
    auto key_pair = get_key(mem);
    ireq->fill_key(key_pair.first, key_pair.second);

    /* store val */
    auto val_pair = get_val(mem);
    ireq->fill_val(val_pair.first, val_pair.second);

    sisl::blob data((uint8_t*)mem, size);

    return data;
}

/****************************************** IndxCP class ****************************************/

/* these are the stages of CP
 * 1. CP Attach :- It creates new index cp id and attaches itself to indx cp. attach CP is called when new CP is
 * started. It can not attach itself to current cp when index mgr is created. However, it creates a cp_id and attaches
 * that CP is when next time attach is called.
 * 2. CP Prepare :- indx mgr and btree decides if it want to participate in a cp_start.
 * 3. CP start :- when all ios on a CP is completed, it start cp flush
 *                      - It flushes the btree dirty buffers
 *                      - When all buffers are dirtied, it flushes the free blks of indx mgr and brree
 * 4. Start blk alloc cp it is scheduled
 * 5. All indx mgr are notified When cp is done. And it writes the superblock
 * 6. cp end :- CP is completed.
 */

HomeStoreCP::HomeStoreCP() : CheckPoint(10) {
    auto cp_id = get_cur_cp_id();
    cp_attach_prepare(nullptr, cp_id);
}

HomeStoreCP::~HomeStoreCP() {}

void HomeStoreCP::cp_start(hs_cp_id* id) {
    iomanager.run_on(IndxMgr::get_thread_id(), [this, id](io_thread_addr_t addr) {
        ++id->ref_cnt;
        for (auto it = id->indx_id_list.begin(); it != id->indx_id_list.end(); ++it) {
            if (it->second != nullptr && (it->second->state() == cp_state::active_cp)) {
                ++id->snt_cnt;
                ++id->ref_cnt;
                auto indx_mgr = it->second->indx_mgr;
                indx_mgr->get_active_indx()->cp_start(it->second->ainfo.btree_id,
                                                      ([this, id](btree_cp_id_ptr btree_id) { indx_tbl_cp_done(id); }));
            }
        }
        indx_tbl_cp_done(id);
    });
}

void HomeStoreCP::indx_tbl_cp_done(hs_cp_id* id) {
    auto cnt = id->ref_cnt.fetch_sub(1);
    if (cnt != 1) { return; }

    if (id->blkalloc_checkpoint) {
        /* flush all the blks that are freed in this id */
        IndxMgr::flush_hs_free_blks(id);
        /* persist alloc blkalloc. It is a sync call */
        blkalloc_cp(id);
    } else {
        /* All dirty buffers are flushed. Write super block */
        IndxMgr::write_hs_cp_sb(id);
    }

    bool blkalloc_cp = id->blkalloc_checkpoint;
    /* id will be freed after calling cp_end and indx_mgr might get destroy also */
    cp_end(id);

    /* notify all the subsystems. */
    IndxMgr::cp_done(blkalloc_cp);
}

/* This function calls
 * 1. persist blkalloc superblock
 * 2. write superblock
 * 3. truncate  :- it truncate upto the seq number persisted in this id.
 * 4. call cb_list
 * 5. notify blk alloc that cp id done
 * 6. call cp_end :- read comments over indxmgr::destroy().
 */
void HomeStoreCP::blkalloc_cp(hs_cp_id* id) {
    /* persist blk alloc bit maps */
    HomeStoreBase::instance()->blkalloc_cp_start(id->blkalloc_id);

    /* All dirty buffers are flushed. Write super block */
    IndxMgr::write_hs_cp_sb(id);

    /* Now it is safe to truncate as blkalloc bitsmaps are persisted */
    for (auto it = id->indx_id_list.begin(); it != id->indx_id_list.end(); ++it) {
        if (it->second == nullptr || it->second->flags != cp_state::active_cp) { continue; }
        it->second->indx_mgr->truncate(it->second);
    }
    home_log_store_mgr.device_truncate();
}

/* It attaches the new CP and prepare for cur cp flush */
void HomeStoreCP::cp_attach_prepare(hs_cp_id* cur_id, hs_cp_id* new_id) {
    IndxMgr::attach_prepare_indx_cp_id_list(cur_id ? &cur_id->indx_id_list : nullptr, &new_id->indx_id_list, cur_id,
                                            new_id);
}

/****************************************** IndxMgr class ****************************************/

REGISTER_METABLK_SUBSYSTEM(indx_mgr, "INDX_MGR_CP", IndxMgr::meta_blk_found_cb, nullptr)

IndxMgr::IndxMgr(boost::uuids::uuid uuid, std::string name, io_done_cb io_cb, create_indx_tbl func) :
        m_io_cb(io_cb),
        m_uuid(uuid),
        m_name(name),
        prepare_cb_list(4),
        m_last_cp_sb(m_uuid),
        m_recovery_mode(false),
        m_create_indx_tbl(func) {
    m_active_tbl = m_create_indx_tbl();

    m_journal = HomeLogStoreMgr::instance().create_new_log_store();
    m_journal_comp_cb =
        std::bind(&IndxMgr::journal_comp_cb, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
    for (int i = 0; i < MAX_CP_CNT; ++i) {
        m_free_list[i] = std::make_shared< sisl::ThreadVector< BlkId > >();
    }
}

/* Constructor for recovery */
IndxMgr::IndxMgr(boost::uuids::uuid uuid, std::string name, io_done_cb io_cb, create_indx_tbl create_func,
                 recover_indx_tbl recover_func, indx_mgr_static_sb sb) :
        m_io_cb(io_cb),
        m_uuid(uuid),
        m_name(name),
        prepare_cb_list(4),
        m_last_cp_sb(m_uuid),
        m_recovery_mode(true),
        m_create_indx_tbl(create_func),
        m_recover_indx_tbl(recover_func),
        m_static_sb(sb) {

    m_journal = nullptr;
    HomeLogStoreMgr::instance().open_log_store(
        sb.journal_id, ([this](std::shared_ptr< HomeLogStore > logstore) {
            m_journal = logstore;
            m_journal->register_log_found_cb(
                ([this](logstore_seq_num_t seqnum, log_buffer buf, void* mem) { this->log_found(seqnum, buf, mem); }));
        }));
    m_journal_comp_cb =
        std::bind(&IndxMgr::journal_comp_cb, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
    for (int i = 0; i < MAX_CP_CNT; ++i) {
        m_free_list[i] = std::make_shared< sisl::ThreadVector< BlkId > >();
    }
}

IndxMgr::~IndxMgr() {
    delete m_active_tbl;
    for (uint32_t i = 0; i < MAX_CP_CNT; ++i) {
        assert(m_free_list[i]->size() == 0);
    }

    if (m_shutdown_started) { static std::once_flag flag1; }
}

void IndxMgr::create_first_cp_id() {
    auto cp_info = &(m_last_cp_sb.cp_info);
    int64_t cp_cnt = cp_info->cp_cnt + 1;
    int64_t psn = cp_info->active_data_psn;
    m_first_cp_id = std::make_shared< indx_cp_id >(cp_cnt, psn, shared_from_this(), m_free_list[cp_cnt % MAX_CP_CNT]);
    m_first_cp_id->ainfo.btree_id = m_active_tbl->attach_prepare_cp(nullptr, false, false);
}

void IndxMgr::create_done() { m_active_tbl->create_done(); }

void IndxMgr::init() {
    /* Below functions would be called later if it is in recovery mode */
    if (!m_recovery_mode) {
        create_first_cp_id();
        std::call_once(m_flag, []() { IndxMgr::static_init(); });
    }
}

void IndxMgr::static_init() {
    assert(!m_inited);
    m_hs = HomeStoreBase::instance();
    m_shutdown_started.store(false);
    try_blkalloc_checkpoint.set(false);

    m_cp = std::unique_ptr< HomeStoreCP >(new HomeStoreCP());
    /* start the timer for blkalloc checkpoint */
    m_hs_cp_timer_hdl =
        iomanager.schedule_global_timer(60 * 1000 * 1000 * 1000ul, true, nullptr, iomgr::thread_regex::all_io,
                                        [](void* cookie) { trigger_hs_cp(nullptr, false); });
    auto sthread = sisl::named_thread("indx_mgr", []() mutable {
        iomanager.run_io_loop(false, nullptr, [](bool is_started) {
            if (is_started) {
                IndxMgr::m_thread_id = iomanager.iothread_self();
                IndxMgr::m_inited = true;
            }
        });
    });
    sthread.detach();
    while (!IndxMgr::m_inited.load(std::memory_order_relaxed)) {}
}

void IndxMgr::recovery_start_phase1() {
    assert(m_recovery_mode);
    auto it = cp_sb_map.find(m_uuid);
    if (it != cp_sb_map.end()) { memcpy(&m_last_cp_sb, &(it->second), sizeof(m_last_cp_sb)); }

    /* Now we have all the information to create mapping btree */

    m_active_tbl = m_recover_indx_tbl(m_static_sb.btree_sb, m_last_cp_sb.active_btree_info);
    create_first_cp_id();
}

void IndxMgr::recovery_start_phase2() {
    assert(m_recovery_mode);
    std::call_once(m_flag, []() { IndxMgr::static_init(); });

    /* get the indx id */
    auto hs_id = m_cp->cp_io_enter();
    auto indx_id = get_indx_id(hs_id);
    assert(indx_id != nullptr);

    /* start replaying the entry in order of seq number */
    for (auto it = seq_buf_map.cbegin(); it != seq_buf_map.cend(); ++it) {
        logstore_seq_num_t seq_num = it->first;
        auto buf = it->second;
        if (buf.bytes() == nullptr) {
            /* do sync read */
            buf = m_journal->read_sync(seq_num);
        }
        auto hdr = indx_journal_entry::get_journal_hdr(buf.bytes());
        assert(hdr != nullptr);
        /* check if any blkids need to be freed or allocated. */
        assert(hdr->cp_cnt > -1);
        assert(m_last_cp_sb.cp_info.blkalloc_cp_cnt <= m_last_cp_sb.cp_info.cp_cnt);
        if (hdr->cp_cnt > m_last_cp_sb.cp_info.blkalloc_cp_cnt) {

            /* free blkids */
            auto fbe_pair = indx_journal_entry::get_free_bid_list(buf.bytes());
            for (uint32_t i = 0; i < fbe_pair.second; ++i) {
                BlkId fbid(fbe_pair.first[i]);
                free_blk(indx_id, fbid);
            }

            /* allocate blkids */
            auto alloc_pair = indx_journal_entry::get_alloc_bid_list(buf.bytes());
            for (uint32_t i = 0; i < alloc_pair.second; ++i) {
                m_hs->get_data_blkstore()->alloc_blk(alloc_pair.first[i]);
                indx_id->indx_size += alloc_pair.first[i].data_size(m_hs->get_data_pagesz());
            }
        }
        if (seq_num <= m_last_cp_sb.cp_info.active_data_psn) { /* it is already persisted */
            continue;
        }
        /* update indx_tbl */
        auto ret = m_active_tbl->recovery_update(seq_num, hdr, indx_id->ainfo.btree_id);
        if (ret != btree_status_t::success) { abort(); }
    }

    m_cp->cp_io_exit(hs_id);
    seq_buf_map.erase(seq_buf_map.begin(), seq_buf_map.end());
}

indx_mgr_static_sb IndxMgr::get_static_sb() {
    indx_mgr_static_sb sb;
    sb.btree_sb = m_active_tbl->get_btree_sb();
    sb.journal_id = m_journal->get_store_id();
    return sb;
}

void IndxMgr::flush_hs_free_blks(hs_cp_id* hs_id) {
    for (auto it = hs_id->indx_id_list.begin(); it != hs_id->indx_id_list.end(); ++it) {
        if (it->second == nullptr || it->second->flags != cp_state::active_cp) {
            /* nothing to free. */
            continue;
        }
        /* free blks in a indx mgr */
        it->second->indx_mgr->flush_free_blks(it->second, hs_id);
    }
}

void IndxMgr::flush_free_blks(indx_cp_id_ptr indx_id, hs_cp_id* hs_id) {
    /* free blks in a indx mgr */
    hs_id->blkalloc_id->free_blks(indx_id->ainfo.free_blkid_list);
    /* free blks in a btree */
    m_active_tbl->flush_free_blks(indx_id->ainfo.btree_id, hs_id->blkalloc_id);
}

void IndxMgr::write_hs_cp_sb(hs_cp_id* hs_id) {
    LOGINFO("superblock is written");
    uint64_t size = sizeof(indx_cp_sb) * hs_id->indx_id_list.size() + sizeof(hs_cp_sb_hdr);
    uint32_t align = 0;
    if (meta_blk_mgr->is_aligned_buf_needed(size)) {
        align = HS_STATIC_CONFIG(disk_attr.align_size);
        size = sisl::round_up(size, align);
    }
    sisl::byte_view b(size, align);

    hs_cp_sb_hdr* hdr = (hs_cp_sb_hdr*)b.bytes();
    hdr->version = INDX_MGR_VERSION;
    int indx_cnt = 0;
    indx_cp_sb* indx_cp_sb_list = (indx_cp_sb*)((uint64_t)hdr + sizeof(hs_cp_sb_hdr));
    for (auto it = hs_id->indx_id_list.begin(); it != hs_id->indx_id_list.end(); ++it) {
        auto indx_id = it->second;
        it->second->indx_mgr->update_cp_sb(indx_id, hs_id, &indx_cp_sb_list[indx_cnt++]);
    }
    hdr->indx_cnt = indx_cnt;

    if (m_meta_blk) {
        MetaBlkMgr::instance()->update_sub_sb("INDX_MGR_CP", (void*)b.bytes(), size, m_meta_blk);
    } else {
        /* first time update */
        MetaBlkMgr::instance()->add_sub_sb("INDX_MGR_CP", (void*)b.bytes(), size, m_meta_blk);
    }
    LOGINFO("superblock is written");
}

void IndxMgr::update_cp_sb(indx_cp_id_ptr& indx_id, hs_cp_id* hs_id, indx_cp_sb* sb) {
    if (indx_id->flags != cp_state::active_cp) {
        /* nothing changed since last superblock */
        memcpy(sb, &m_last_cp_sb, sizeof(m_last_cp_sb));
        return;
    }

    assert(indx_id->ainfo.end_psn >= indx_id->ainfo.start_psn);
    assert(indx_id->cp_cnt > m_last_cp_sb.cp_info.blkalloc_cp_cnt);
    assert(indx_id->cp_cnt == m_last_cp_sb.cp_info.cp_cnt + 1);

    sb->cp_info.active_data_psn = indx_id->ainfo.end_psn;
    sb->cp_info.blkalloc_cp_cnt = hs_id->blkalloc_checkpoint ? indx_id->cp_cnt : m_last_cp_sb.cp_info.blkalloc_cp_cnt;
    sb->cp_info.indx_size = indx_id->indx_size.load() + m_last_cp_sb.cp_info.indx_size;
    sb->cp_info.cp_cnt = indx_id->cp_cnt;
    sb->uuid = m_uuid;
    m_active_tbl->update_btree_cp_sb(indx_id->ainfo.btree_id, sb->active_btree_info, hs_id->blkalloc_checkpoint);
    memcpy(&m_last_cp_sb, sb, sizeof(m_last_cp_sb));
}

void IndxMgr::attach_prepare_indx_cp_id_list(std::map< boost::uuids::uuid, indx_cp_id_ptr >* cur_indx_id,
                                             std::map< boost::uuids::uuid, indx_cp_id_ptr >* new_indx_id,
                                             hs_cp_id* hs_id, hs_cp_id* new_hs_id) {
    if (hs_id == nullptr || try_blkalloc_checkpoint.get()) {
        new_hs_id->blkalloc_id =
            HomeStoreBase::instance()->blkalloc_attach_prepare_cp(hs_id ? hs_id->blkalloc_id : nullptr);
        if (hs_id) {
            hs_id->blkalloc_checkpoint = true;
            try_blkalloc_checkpoint.set(false);
        }
    } else {
        new_hs_id->blkalloc_id = hs_id->blkalloc_id;
    }
    m_hs->attach_prepare_indx_cp_id(cur_indx_id, new_indx_id, hs_id, new_hs_id);
}

/* It attaches the new CP and prepare for cur cp flush */
indx_cp_id_ptr IndxMgr::attach_prepare_indx_cp(indx_cp_id_ptr cur_indx_id, hs_cp_id* hs_id, hs_cp_id* new_hs_id) {

    if (cur_indx_id == nullptr) {
        /* this indx mgr is just created in the last CP. return the first_cp_id created at the timeof indx mgr creation.
         * And this indx mgr is not going to participate in the current cp. This indx mgr is going to participate in
         * the next cp.
         */
        assert(m_first_cp_id != nullptr);
        /* if hs_id->blkalloc_checkpoint is set to true then it means it is created/destroy in a same cp.
         * we can not resume CP in this checkpoint. A indx mgr can never be added in a current cp.
         */
        return m_first_cp_id;
    }

    if (cur_indx_id == m_first_cp_id) { m_first_cp_id = nullptr; }

    /* Go through the callback who is waiting for prepare to happen. Normally suspend, resume,
     * destroy waits for it. We can not move CP to suspend, active in middle of CP.
     */
    auto cb_list_copy = prepare_cb_list.get_copy_and_reset();
    for (uint32_t i = 0; i < cb_list_copy->size(); ++i) {
        (*cb_list_copy)[i](cur_indx_id, hs_id, new_hs_id);
    }

    if (cur_indx_id->flags == cp_state::suspend_cp) {
        /* this indx mgr is not going to participate in a current cp */
        return cur_indx_id;
    }

    if (m_shutdown_started.load()) {
        m_last_cp = true; // it is set to true even if indx mgr is deleted
    }
    auto btree_id = m_active_tbl->attach_prepare_cp(cur_indx_id->ainfo.btree_id, m_last_cp, hs_id->blkalloc_checkpoint);
    cur_indx_id->ainfo.end_psn = m_journal->get_contiguous_issued_seq_num(cur_indx_id->ainfo.start_psn);
    if (m_last_cp) {
        assert(btree_id == nullptr);
        HS_SUBMOD_LOG(INFO, base, , "indx tbl", cur_indx_id->indx_mgr->get_name(),
                      "last cp of this indx mgr triggered");
        return nullptr;
    }
    /* create new cp */
    blkid_list_ptr free_list;
    if (hs_id->blkalloc_checkpoint) {
        free_list = m_free_list[++m_free_list_cnt % MAX_CP_CNT];
        assert(free_list->size() == 0);
    } else {
        /* we keep accumulating the free blks until blk checkpoint is not taken */
        free_list = cur_indx_id->ainfo.free_blkid_list;
    }
    int64_t cp_cnt = cur_indx_id->cp_cnt + 1;
    indx_cp_id_ptr new_indx_id(new indx_cp_id(cp_cnt, cur_indx_id->ainfo.end_psn, cur_indx_id->indx_mgr, free_list));
    new_indx_id->ainfo.btree_id = btree_id;

    return new_indx_id;
}

void IndxMgr::truncate(indx_cp_id_ptr indx_id) {
    m_journal->truncate(indx_id->ainfo.end_psn);
    m_active_tbl->truncate(indx_id->ainfo.btree_id);
    LOGINFO("uuid {} last psn {}", m_uuid, m_last_cp_sb.cp_info.active_data_psn);
}

void IndxMgr::cp_done(bool blkalloc_cp) {
    std::unique_lock< std::mutex > lk(cb_list_mtx);
    if (blkalloc_cp) {
        for (uint32_t i = 0; i < indx_cp_done_cb_list.size(); ++i) {
            indx_cp_done_cb_list[i](true);
        }
    } else {
        for (uint32_t i = 0; i < hs_cp_done_cb_list.size(); ++i) {
            hs_cp_done_cb_list[i](true);
        }
    }
}

indx_tbl* IndxMgr::get_active_indx() { return m_active_tbl; }

void IndxMgr::journal_comp_cb(logstore_seq_num_t seq_num, logdev_key ld_key, void* req) {
    assert(ld_key.is_valid());
    auto ireq = indx_req_ptr((indx_req*)req, false); // Turn it back to smart ptr before doing callback.

    HS_SUBMOD_LOG(TRACE, indx_mgr, , "indx mgr", m_name, "Journal write done, lsn={}, log_key=[idx={}, offset={}]",
                  seq_num, ld_key.idx, ld_key.dev_offset);

    /* blk id is alloceted in disk bitmap only after it is writing to journal. check
     * blk_alloctor base class for further explanations. It should be done in cp critical section.
     * Otherwise bitmap won't reflect all the blks allocated in a cp.
     *
     * It is also possible that indx_alloc_blkis list contain the less number of blkids that allocated because of
     * partial writes. We are not freeing it in cache right away. There is no reason to not do it. We are not setting it
     * in disk bitmap so in next reboot it will be available to use.
     */

    for (uint32_t i = 0; i < ireq->indx_alloc_blkid_list.size(); ++i) {
        m_hs->get_data_blkstore()->alloc_blk(ireq->indx_alloc_blkid_list[i]);
        /* update size */
        ireq->indx_id->indx_size += ireq->indx_alloc_blkid_list[i].data_size(m_hs->get_data_pagesz());
    }

    /* free the blkids */
    for (uint32_t i = 0; i < ireq->fbe_list.size(); ++i) {
        free_blk(ireq->indx_id, ireq->fbe_list[i]);
        ireq->fbe_list[i].m_cp_id = ireq->hs_id;
    }

    /* Increment the reference count by the number of free blk entries. Freing of blk is an async process. So we don't
     * want to take a checkpoint until these blkids by its consumer. Blk ids are freed in IndxMgr::free_blk.
     */
    m_cp->cp_inc_ref(ireq->hs_id, ireq->fbe_list.size());

    /* End of critical section */
    if (ireq->first_hs_id) { m_cp->cp_io_exit(ireq->first_hs_id); }
    m_cp->cp_io_exit(ireq->hs_id);

    /* XXX: should we do completion before ending the critical section. We might get some better latency in doing
     * that but my worry is that we might end up in deadlock if we pick new IOs in completion and those IOs need to
     * take cp to free some resources.
     */
    m_io_cb(ireq, ireq->indx_err);
}

void IndxMgr::journal_write(indx_req* ireq) {
    auto b = ireq->create_journal_entry();
    m_journal->write_async(ireq->get_seqId(), b, ireq, m_journal_comp_cb);
}

/* A io can become part of two CPs if btree node is updated with the new CP and few indx mgr IOs
 * is still being done in old CP. Indx is always updated in a mapping sequentially start from
 * lba_start. We keep track of all the CP in a req but update journal with only with
 * the latest CP ids.
 */
btree_status_t IndxMgr::update_active_indx_tbl(indx_req* ireq) {

    auto btree_id = ireq->indx_id->ainfo.btree_id;
    auto status = m_active_tbl->update_active_indx_tbl(ireq, btree_id);

    return status;
}

void IndxMgr::update_indx(indx_req_ptr ireq) {
    int retry_cnt = 0;
    /* Journal write is async call. So incrementing the ref on indx req */
    ireq->inc_ref();

    /* Entered into critical section. CP is not triggered in this critical section */
    ireq->hs_id = m_cp->cp_io_enter();
    ireq->indx_id = get_indx_id(ireq->hs_id);
    if (!ireq->indx_id) { ireq->indx_id = m_first_cp_id; }

    /* update active btree */
    auto ret = update_active_indx_tbl(ireq.get());
    /* we call cp exit on both the CPs only when journal is written otherwise there could be blkid leak */
    if (ret == btree_status_t::cp_id_mismatch) { ret = retry_update_active_indx(ireq); }

    if (ret != btree_status_t::success) { ireq->indx_err = btree_write_failed; }
    /* TODO update diff btree */
    /* Update allocate blkids in indx req */
    m_active_tbl->update_indx_alloc_blkids(ireq.get());
    /* In case of failure we will still update the journal with entries of whatever is written. */
    /* update journal. Journal writes are not expected to fail. It is async call/ */
    journal_write(ireq.get());
}

/* It is called when first update failed because btree is updated by latest CP and indx mgr got old cp */
btree_status_t IndxMgr::retry_update_active_indx(const indx_req_ptr& ireq) {
    ireq->first_hs_id = ireq->hs_id;
    /* try again to get the new cp */
    ireq->hs_id = m_cp->cp_io_enter();
    assert(ireq->hs_id != ireq->first_hs_id);
    auto ret = update_active_indx_tbl(ireq.get());

    /* we can not get mismatch again as we only have two cps pending at any given time */
    assert(ret != btree_status_t::cp_id_mismatch);
    return ret;
}

btree_cp_id_ptr IndxMgr::get_btree_id(hs_cp_id* cp_id) {
    auto indx_id = get_indx_id(cp_id);
    if (indx_id) { return (indx_id->ainfo.btree_id); }
    return nullptr;
}

indx_cp_id_ptr IndxMgr::get_indx_id(hs_cp_id* cp_id) {
    auto it = cp_id->indx_id_list.find(m_uuid);
    indx_cp_id_ptr btree_id;
    if (it == cp_id->indx_id_list.end()) {
        /* indx mgr is just created. So take the first id. */
        return (nullptr);
    } else {
        assert(it->second != nullptr);
        return (it->second);
    }
}

void IndxMgr::trigger_indx_cp() { m_cp->trigger_cp(nullptr); }
void IndxMgr::trigger_indx_cp_with_cb(cp_done_cb cb) { m_cp->trigger_cp(cb); }

void IndxMgr::trigger_hs_cp(cp_done_cb cb, bool shutdown) {
    if (!m_inited.load(std::memory_order_relaxed)) {
        cb(true);
        return;
    }
    /* set bit map checkpoint , resume cp and trigger it */
    if (!m_cp) {
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
    m_cp->trigger_cp(cb);
}

/* Steps involved in indx destroy. Note that blkids is available to allocate as soon as it is set in blkalloc. So we
 * need to make sure that blkids of btree won't be resued until indx mgr is not destroy and until its data blkids
 * and btree blkids are not persisted. indx mgr destroye is different that IO because there is no journal entry of free
 * blks as we have in regular IO.Steps:-
 * 1. Write a journal entry that this indx mgr is destroying. There is no purpose of it. It is only used for a sanity
 * check that there are no ios after this entry.
 * 2. We move the cp to suspended state.
 *       Note :- we don't want cp to be taken while we are setting suspend flag. That is why it is called in
 *       checkpoint critical section.
 * 3. We destroy btree. Btree traverses the tree
 *      a. Btree free all the indx mgr blkids and accumumlate it in a indx mgr cp_id
 *      b. Btree free all its blocks and accumulate in writeback cache layer.
 * 4. Resume CP when blkalloc checkpoint to true.
 * 5. Both blkalloc checkpoint and indx mgr checkpoint happen in a same CP. It trigger indx mgr checkpoint followed by
 * blkalloc checkpoint. indx mgr checkpoint flush all the blkids in btree and indx mgr to blkalloc. And blkalloc
 * checkpoint persist the blkalloc.
 * 6. Free super block after bit map is persisted. CP is finished only after super block is persisted. It will
 * prevent another cp to start.
 * 7. Make all the free blkids available to reuse in blk allocator.
 */
void IndxMgr::destroy(indxmgr_stop_cb&& cb) {
    /* we can assume that there is no io going on this indx mgr now */
    HS_SUBMOD_LOG(INFO, base, , "indx mgr", m_name, "Destroying Indx Manager");
    destroy_journal_ent* jent = nullptr;
    uint32_t align = 0;

    if (m_journal->is_aligned_buf_needed(sizeof(destroy_journal_ent))) {
        align = HS_STATIC_CONFIG(disk_attr.align_size);
    }

    sisl::alignable_blob iob(sizeof(destroy_journal_ent), align);
    jent = (destroy_journal_ent*)(iob.bytes);
    jent->state = indx_mgr_state::DESTROYING;

    m_stop_cb = std::move(cb);
    m_journal->append_async(
        iob, nullptr, ([this, iob](logstore_seq_num_t seq_num, logdev_key key, void* cookie) mutable {
            iob.buf_free();
            add_prepare_cb_list([this](indx_cp_id_ptr cur_indx_id, hs_cp_id* hb_id, hs_cp_id* new_hb_id) {
                /* suspend current cp */
                cur_indx_id->flags = cp_state::suspend_cp;
                iomanager.run_on(m_thread_id,
                                 [this, cur_indx_id](io_thread_addr_t addr) { this->destroy_indx_tbl(cur_indx_id); });
            });
        }));
}

void IndxMgr::destroy_indx_tbl(indx_cp_id_ptr indx_id) {
    /* free all blkids of btree in memory */
    HS_SUBMOD_LOG(INFO, base, , "indx", m_name, "Destroying Index btree");

    if (m_active_tbl->destroy(indx_id->ainfo.btree_id, ([this, indx_id](Free_Blk_Entry& fbe) mutable {
                                  free_blk(indx_id, fbe);
                              })) != btree_status_t::success) {
        /* destroy is failed. We are going to retry it in next boot */
        LOGERROR("btree destroy failed");
        assert(0);
        m_stop_cb(false);
    }
    add_prepare_cb_list(([this](indx_cp_id_ptr cur_indx_id, hs_cp_id* hb_id, hs_cp_id* new_hb_id) {
        this->indx_destroy_cp(cur_indx_id, hb_id, new_hb_id);
    }));
}

void IndxMgr::indx_destroy_cp(indx_cp_id_ptr cur_indx_id, hs_cp_id* hb_id, hs_cp_id* new_hb_id) {
    assert(cur_indx_id->flags == cp_state::suspend_cp);
    assert(!m_shutdown_started.load());
    HS_SUBMOD_LOG(INFO, base, , "indx", m_name, "CP during destroy");

    if (hb_id->blkalloc_checkpoint) {
        cur_indx_id->flags = cp_state::active_cp;
        m_cp->attach_cb(hb_id, std::move(m_stop_cb));
        m_last_cp = true;
    } else {
        /* add it self again to the cb list for next cp which could be blkalloc checkpoint */
        add_prepare_cb_list(([this](indx_cp_id_ptr cur_indx_id, hs_cp_id* hb_id, hs_cp_id* new_hb_id) {
            this->indx_destroy_cp(cur_indx_id, hb_id, new_hb_id);
        }));
    }
}

void IndxMgr::add_prepare_cb_list(prepare_cb cb) {
    std::unique_lock< std::mutex > lk(prepare_cb_mtx);
    prepare_cb_list.push_back(cb);
}

void IndxMgr::shutdown(indxmgr_stop_cb cb) {
    if (!m_inited.load(std::memory_order_relaxed)) { cb(true); }
    LOGINFO("indx mgr shutdown started");
    iomanager.cancel_timer(m_hs_cp_timer_hdl, false);
    m_hs_cp_timer_hdl = iomgr::null_timer_handle;
    trigger_hs_cp(([cb](bool success) {
                      /* verify that all the indx mgr have called their last cp */
                      assert(success);
                      if (m_cp) {
                          auto cp_id = m_cp->cp_io_enter();
                          assert(cp_id->indx_id_list.size() == 0);
                      }
                      cb(success);
                  }),
                  true);
}

void IndxMgr::destroy_done() {
    m_active_tbl->destroy_done();
    home_log_store_mgr.remove_log_store(m_journal->get_store_id());
}

#define THRESHHOLD_MEMORY 500 * 1024 // 500K
void IndxMgr::log_found(logstore_seq_num_t seqnum, log_buffer log_buf, void* mem) {
    std::map< logstore_seq_num_t, log_buffer >::iterator it;
    bool happened;
    if (memory_used_in_recovery > THRESHHOLD_MEMORY) {
        log_buffer nullbuf;
        std::tie(it, happened) = seq_buf_map.emplace(std::make_pair(seqnum, nullbuf));
    } else {
        std::tie(it, happened) = seq_buf_map.emplace(std::make_pair(seqnum, log_buf));
        memory_used_in_recovery += log_buf.size();
    }
    assert(happened);
}

void IndxMgr::meta_blk_found_cb(meta_blk* mblk, sisl::byte_view buf, size_t size) {
    m_meta_blk = mblk;
    hs_cp_sb_hdr* hdr = (hs_cp_sb_hdr*)buf.bytes();
    assert(hdr->version == INDX_MGR_VERSION);
    indx_cp_sb* cp_sb = (indx_cp_sb*)((uint64_t)buf.bytes() + sizeof(hs_cp_sb_hdr));

#ifndef NDEBUG
    uint64_t temp_size = sizeof(hs_cp_sb_hdr) + hdr->indx_cnt * sizeof(indx_cp_sb);
    temp_size = sisl::round_up(size, HS_STATIC_CONFIG(disk_attr.align_size));
    assert(size == temp_size);
#endif

    for (uint32_t i = 0; i < hdr->indx_cnt; ++i) {
        bool happened{false};
        std::map< boost::uuids::uuid, indx_cp_sb >::iterator it;
        std::tie(it, happened) = cp_sb_map.emplace(std::make_pair(cp_sb[i].uuid, cp_sb[i]));
        assert(happened);
    }
}

/* It is called to free the blks and insert it into list */
void IndxMgr::free_blk(indx_cp_id_ptr indx_id, Free_Blk_Entry& fbe) {
    BlkId fblkid = fbe.get_free_blkid();
    free_blk(indx_id, fblkid);
}

void IndxMgr::free_blk(indx_cp_id_ptr indx_id, BlkId& fblkid) {
    indx_id->ainfo.free_blkid_list->push_back(fblkid);
    indx_id->indx_size.fetch_sub(fblkid.get_nblks() * m_hs->get_data_pagesz());
}

void IndxMgr::safe_to_free_blk(hs_cp_id* hs_id, Free_Blk_Entry& fbe) {
    /* We don't allow cp to complete until all required blkids are freed. We increment the ref count in update_indx_tbl
     * by number of free blk entries.
     */
    assert(hs_id);
    /* invalidate the cache */
    auto page_sz = m_hs->get_data_pagesz();
    m_hs->get_data_blkstore()->free_blk(fbe.m_blkId, (fbe.m_blk_offset * page_sz), (fbe.m_nblks_to_free * page_sz),
                                        true);
    m_cp->cp_io_exit(hs_id);
    /* We have already free the blk after journal write is completed. We are just holding a cp for free to complete */
}

void IndxMgr::register_cp_done_cb(cp_done_cb cb, bool blkalloc_cp) {
    std::unique_lock< std::mutex > lk(cb_list_mtx);
    if (blkalloc_cp) {
        indx_cp_done_cb_list.push_back(cb);
    } else {
        hs_cp_done_cb_list.push_back(cb);
    }
}

uint64_t IndxMgr::get_used_size() { return (m_last_cp_sb.cp_info.indx_size + m_active_tbl->get_used_size()); }

uint64_t IndxMgr::get_last_psn() { return m_last_cp_sb.cp_info.active_data_psn; }
std::string IndxMgr::get_name() { return m_name; }

std::unique_ptr< HomeStoreCP > IndxMgr::m_cp;
std::atomic< bool > IndxMgr::m_shutdown_started;
iomgr::io_thread_t IndxMgr::m_thread_id;
iomgr::timer_handle_t IndxMgr::m_hs_cp_timer_hdl = iomgr::null_timer_handle;
void* IndxMgr::m_meta_blk = nullptr;
std::once_flag IndxMgr::m_flag;
sisl::aligned_unique_ptr< uint8_t > IndxMgr::m_recovery_sb;
std::map< boost::uuids::uuid, indx_cp_sb > IndxMgr::cp_sb_map;
size_t IndxMgr::m_recovery_sb_size = 0;
HomeStoreBase* IndxMgr::m_hs;
uint64_t IndxMgr::memory_used_in_recovery = 0;
std::atomic< bool > IndxMgr::m_inited = false;
HomeStoreBase::HomeStoreBaseSafePtr HomeStoreBase::_instance;
std::mutex IndxMgr::cb_list_mtx;
std::vector< cp_done_cb > IndxMgr::indx_cp_done_cb_list;
std::vector< cp_done_cb > IndxMgr::hs_cp_done_cb_list;
sisl::atomic_counter< bool > IndxMgr::try_blkalloc_checkpoint;
