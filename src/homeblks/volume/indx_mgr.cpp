#include "indx_mgr.hpp"
#include "mapping.hpp"

using namespace homestore;
/* Journal entry
 * --------------------------------------------------------------------
 * | Journal Hdr | alloc_blkid list | checksum list | free_blk_entry |
 * -------------------------------------------------------------------
 */
vol_journal_entry::~vol_journal_entry() {
    if (m_mem) { free(m_mem); }
}

/* it update the alloc blk id and checksum */
sisl::blob vol_journal_entry::create_journal_entry(volume_req* v_req) {
    uint32_t size = sizeof(journal_hdr) + v_req->csum_list.size() * sizeof(uint16_t) +
        v_req->alloc_blkid_list.size() * sizeof(BlkId) + v_req->fbe_list.size() * sizeof(Free_Blk_Entry);
    m_mem = malloc(size);
    /* store journal hdr */
    auto hdr = (journal_hdr*)m_mem;
    hdr->lba = v_req->lba();
    hdr->nlbas = v_req->nlbas();
    hdr->indx_start_lba = v_req->indx_start_lba;

    /* store alloc blkid */
    auto blkid = (BlkId*)((uint64_t)m_mem + sizeof(journal_hdr));
    for (uint32_t i = 0; i < v_req->alloc_blkid_list.size(); ++i) {
        blkid[i] = v_req->alloc_blkid_list[i];
    }

    /* store csum */
    auto csum = (uint16_t*)(&blkid[v_req->alloc_blkid_list.size()]);
    for (uint32_t i = 0; i < v_req->csum_list.size(); ++i) {
        csum[i] = v_req->csum_list[i];
    }

    /* store free blk entry */
    auto fbe = (Free_Blk_Entry*)(&csum[v_req->csum_list.size()]);
    for (uint32_t i = 0; i < v_req->fbe_list.size(); ++i) {
        fbe[i] = v_req->fbe_list[i];
    }
    sisl::blob data((uint8_t*)m_mem, size);

    HS_SUBMOD_LOG(TRACE, volume, v_req, "vol", v_req->vol()->get_name(),
                  "Write to journal size={} lsn={}, journal_hdr:[{}], n_ids={}, n_csum={}, n_fbes={}", size,
                  v_req->seqId, to_string(), v_req->alloc_blkid_list.size(), v_req->csum_list.size(),
                  v_req->fbe_list.size());
    return data;
}

/****************************************** IndxCP class ****************************************/

/* This is the hirarchy of cp
 * - Indx CP ID.
 *      - Per Volume CP
 *          - Per btree CP
 * these are the stages of CP
 * 1. CP Attach :- It creates new volume cp id and attaches itself to indx cp. attach CP is called when new CP is
 * started. It can not attach itself to current cp when volume is created. However, it creates a cp_id and attaches that
 * CP is when next time attach is called.
 * 2. CP Prepare :- Volume decides if it want to participate in a cp_start.
 * 3. CP done :- All volumes are notified When cp is done.
 */

IndxCP::IndxCP() : CheckPoint(10) {
    auto cp_id = get_cur_cp_id();
    cp_attach_prepare(nullptr, cp_id);
}

IndxCP::~IndxCP() {}

void IndxCP::cp_start(indx_cp_id* id) {
    iomgr_msg io_msg;
    io_msg.m_type = RUN_METHOD;
    auto run_method = sisl::ObjectAllocator< run_method_t >::make_object();
    /* start CP in indx mgr thread */
    *run_method = ([this, id]() {
        ++id->ref_cnt;
        for (auto it = id->vol_id_list.begin(); it != id->vol_id_list.end(); ++it) {
            if (it->second != nullptr && it->second->flags == cp_state::active_cp) {
                ++id->snt_cnt;
                ++id->ref_cnt;
                auto indx_mgr = it->second->vol->get_indx_mgr();
                indx_mgr->get_active_indx()->cp_start(it->second->btree_id,
                                                      ([this, id](btree_cp_id_ptr btree_id) { cp_done(id); }));
            }
        }
        cp_done(id);
    });
    io_msg.m_data_buf = (void*)run_method;
    iomanager.send_msg(IndxMgr::get_thread_num(), io_msg);
}

void IndxCP::cp_done(indx_cp_id* id) {
    auto cnt = id->ref_cnt.fetch_sub(1);
    if (cnt != 1) { return; }

    /* All dirty buffers are flushed. Write super block */
    IndxMgr::write_cp_super_block(id);
    if (id->bitmap_checkpoint) {
        /* persist alloc bitmap. It is a sync call */
        HomeBlks::instance()->persist_blk_allocator_bitmap();
        bitmap_cp_done(id);
    } else {
        cp_end(id);
    }
    /* notify all the subsystems which can trigger CP. They can check if they require new cp to be triggered. */
    mapping::cp_done(IndxMgr::trigger_vol_cp);
}

/* This function calls
 * 1. truncate  :- it truncate upto the seq number persisted in this id.
 * 2. call cb_list
 * 3. call cp_end :- read comments over indxmgr::destroy().
 */
void IndxCP::bitmap_cp_done(indx_cp_id* id) {
    for (auto it = id->vol_id_list.begin(); it != id->vol_id_list.end(); ++it) {
        if (it->second == nullptr || it->second->flags != cp_state::active_cp) { continue; }
        it->second->vol->truncate(it->second);
    }
    home_log_store_mgr.device_truncate();
    for (uint32_t i = 0; i < id->cb_list.size(); ++i) {
        id->cb_list[i](true);
    }
    cp_end(id);
    /* id will be freed after checkpoint and volume might get destroy also */
}

/* It attaches the new CP and prepare for cur cp flush */
void IndxCP::cp_attach_prepare(indx_cp_id* cur_id, indx_cp_id* new_id) {
    IndxMgr::attach_prepare_vol_cp_id_list(cur_id ? &cur_id->vol_id_list : nullptr, &new_id->vol_id_list, cur_id);
}

/****************************************** IndxMgr class ****************************************/

IndxMgr::IndxMgr(std::shared_ptr< Volume > vol, const vol_params& params, io_done_cb io_cb,
                 free_blk_callback free_blk_cb, pending_read_blk_cb read_blk_cb) :
        m_io_cb(io_cb),
        m_pending_read_blk_cb(read_blk_cb),
        m_first_cp_id(new vol_cp_id()),
        m_uuid(params.uuid),
        m_name(params.vol_name),
        prepare_cb_list(4) {
    static std::once_flag flag1;
    m_active_map = new mapping(params.size, params.page_size, params.vol_name, free_blk_cb, IndxMgr::trigger_vol_cp,
                               m_pending_read_blk_cb);

    m_journal = HomeLogStoreMgr::instance().create_new_log_store();
    m_journal_comp_cb =
        std::bind(&IndxMgr::journal_comp_cb, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);

    m_first_cp_id->btree_id = m_active_map->attach_prepare_cp(nullptr, false);
    m_first_cp_id->vol = vol;
    std::call_once(flag1, []() { IndxMgr::init(); });
}

IndxMgr::IndxMgr(std::shared_ptr< Volume > vol, indx_mgr_active_sb* sb, io_done_cb io_cb, free_blk_callback free_blk_cb,
                 pending_read_blk_cb read_blk_cb) :
        m_io_cb(io_cb),
        m_pending_read_blk_cb(read_blk_cb),
        m_first_cp_id(new vol_cp_id()),
        prepare_cb_list(4) {}

IndxMgr::~IndxMgr() {
    delete m_active_map;

    if (m_shutdown_started) { static std::once_flag flag1; }
}

indx_mgr_active_sb IndxMgr::get_active_sb() {
    indx_mgr_active_sb sb;
    sb.btree_sb = m_active_map->get_btree_sb();
    sb.journal_id = m_journal->get_store_id();
    return sb;
}

void IndxMgr::init() {
    m_cp = std::unique_ptr< IndxCP >(new IndxCP());
    m_shutdown_started.store(false);
    auto sthread = std::thread([]() mutable {
        IndxMgr::m_thread_num = sisl::ThreadLocalContext::my_thread_num();
        LOGINFO("{} thread entered", m_thread_num);
        iomanager.run_io_loop(false, nullptr, ([](const iomgr_msg& io_msg) {}));
        LOGINFO("{} thread exit", m_thread_num);
    });
    sthread.detach();

    /* start the timer for bitmap checkpoint */
    m_system_cp_timer_hdl = iomanager.schedule_timer(60 * 1000 * 1000 * 1000ul, true, nullptr, false,
                                                     [](void* cookie) { trigger_system_cp(nullptr, false); });
    write_cp_super_block(nullptr);
}

void IndxMgr::write_cp_super_block(indx_cp_id* id) {
    LOGINFO("superblock is written");
    uint8_t* mem = nullptr;
    uint64_t size = (id ? (sizeof(indx_mgr_cp_sb) * id->snt_cnt) : 0) + sizeof(indx_mgr_cp_sb_hdr);
    int ret = posix_memalign((void**)&(mem), HS_STATIC_CONFIG(disk_attr.align_size), size);
    if (ret != 0) {
        assert(0);
        throw std::bad_alloc();
    }

    indx_mgr_cp_sb_hdr* hdr = (indx_mgr_cp_sb_hdr*)mem;
    hdr->version = INDX_MGR_VERSION;

    if (id) {
        uint8_t* temp = (uint8_t*)((uint64_t)mem + sizeof(indx_mgr_cp_sb_hdr));
        for (auto it = id->vol_id_list.begin(); it != id->vol_id_list.end(); ++it) {
            if (it->second == nullptr || it->second->flags != cp_state::active_cp) { continue; }
            auto vol_id = it->second;
            auto sb = (indx_mgr_cp_sb*)temp;
            sb->uuid = vol_id->vol->get_uuid();
            sb->active_data_psn = vol_id->end_active_psn;
            sb->active_btree_psn = vol_id->btree_id->end_seq_id;
            temp = (uint8_t*)((uint64_t)temp + sizeof(indx_mgr_cp_sb));
        }
    }

    if (m_meta_blk) {
        MetaBlkMgr::instance()->update_sub_sb(meta_sub_type::INDX_MGR_CP, mem, size, m_meta_blk);
    } else {
        /* first time update */
        MetaBlkMgr::instance()->add_sub_sb(meta_sub_type::INDX_MGR_CP, mem, size, m_meta_blk);
    }
    LOGINFO("superblock is written");
    free(mem);
}

void IndxMgr::attach_prepare_vol_cp_id_list(std::map< boost::uuids::uuid, vol_cp_id_ptr >* cur_vols_id,
                                            std::map< boost::uuids::uuid, vol_cp_id_ptr >* new_vols_id,
                                            indx_cp_id* home_blks_id) {
    HomeBlks::instance()->attach_prepare_volume_cp_id(cur_vols_id, new_vols_id, home_blks_id);
}

/* It attaches the new CP and prepare for cur cp flush */
vol_cp_id_ptr IndxMgr::attach_prepare_vol_cp(vol_cp_id_ptr cur_vol_id, indx_cp_id* home_blks_id) {

    if (cur_vol_id == nullptr) {
        /* this volume is just created in the last CP. return the first_cp_id created at the time of volume creation.
         * And this volume is not going to participate in the current cp. This volume is going to participate in
         * the next cp.
         */
        assert(m_first_cp_id != nullptr);
        /* if home_blks_id->bitmap_checkpoint is set to true then it means it is created/destroy in a same cp.
         * we can not resume CP in this checkpoint. A volume can never be added in a current cp.
         */
        return m_first_cp_id;
    }

    if (cur_vol_id == m_first_cp_id) { m_first_cp_id = nullptr; }

    /* Go through the callback who is waiting for prepare to happen. Normally suspend, resume,
     * destroy waits for it. We can not move CP to suspend, active in middle of CP.
     */
    auto cb_list_copy = prepare_cb_list.get_copy_and_reset();
    for (uint32_t i = 0; i < cb_list_copy->size(); ++i) {
        (*cb_list_copy)[i](cur_vol_id, home_blks_id);
    }

    if (cur_vol_id->flags == cp_state::suspend_cp) {
        /* this volume is not going to participate in a current cp */
        return cur_vol_id;
    }

    if (m_shutdown_started.load()) {
        m_last_cp = true; // it is set to true even if volume is deleted
    }
    auto btree_id = m_active_map->attach_prepare_cp(cur_vol_id->btree_id, m_last_cp);
    if (m_last_cp) {
        assert(btree_id == nullptr);
        HS_SUBMOD_LOG(INFO, base, , "vol", cur_vol_id->vol->get_name(), "last cp of this volume triggered");
        return nullptr;
    }

    /* create new cp */
    vol_cp_id_ptr new_vol_id(new vol_cp_id());
    new_vol_id->end_active_psn = m_journal->get_contiguous_issued_seq_num(cur_vol_id->start_active_psn);
    new_vol_id->start_active_psn = cur_vol_id->end_active_psn;
    new_vol_id->btree_id = btree_id;
    new_vol_id->vol = cur_vol_id->vol;
    return new_vol_id;
}

void IndxMgr::truncate(vol_cp_id_ptr vol_id) {
    m_journal->truncate(vol_id->end_active_psn);
    m_active_map->truncate(vol_id->btree_id);
}

mapping* IndxMgr::get_active_indx() { return m_active_map; }

void IndxMgr::journal_comp_cb(logstore_seq_num_t seq_num, logdev_key ld_key, void* req) {
    assert(ld_key.is_valid());
    auto vreq = volume_req_ptr((volume_req*)req, false); // Turn it back to smart ptr before doing callback.
    uint64_t lba_written = vreq->indx_start_lba - vreq->lba();

    HS_SUBMOD_LOG(TRACE, volume, vreq, "vol", vreq->vol()->get_name(),
                  "Journal write done, lsn={}, log_key=[idx={}, offset={}]", seq_num, ld_key.idx, ld_key.dev_offset);

    if (lba_written == vreq->nlbas()) {
        m_io_cb(vreq, no_error);
    } else {
        /* partial write */
        assert(lba_written < vreq->nlbas());
        m_io_cb(vreq, homestore_error::btree_write_failed);
    }

    /* End of critical section */
    m_cp->cp_io_exit(vreq->cp_id);
}

void IndxMgr::journal_write(volume_req* vreq) {
    auto b = vreq->create_journal_entry();
    m_journal->write_async(vreq->seqId, b, vreq, m_journal_comp_cb);
}

btree_status_t IndxMgr::update_indx_tbl(volume_req* vreq) {
    std::array< uint16_t, CS_ARRAY_STACK_SIZE > carr;
    uint64_t offset = 0;

    for (uint32_t i = 0; i < vreq->iface_req->nlbas; ++i) {
        carr[i] = vreq->csum_list[i];
    }

    uint64_t start_lba = vreq->lba();
    int csum_indx = 0;

    /* get volume cp id */
    auto btree_id = get_btree_id(vreq->cp_id);
    for (uint32_t i = 0; i < vreq->alloc_blkid_list.size(); ++i) {

        /* TODO mapping should accept req so that it doesn't need to build value two times */
        auto blkid = vreq->alloc_blkid_list[i];
        uint32_t page_size = vreq->vol()->get_page_size();
        uint32_t nlbas = blkid.data_size(HomeBlks::instance()->get_data_pagesz()) / page_size;
        uint32_t blk_offset = 0;

        /* we don't want to write same lba multiple times in a io. In case of partial write and write failure we will
         * call this function multiple times for the same io.
         */
        if (start_lba < vreq->indx_start_lba) {
            if ((vreq->indx_start_lba - start_lba) >= nlbas) {
                start_lba += nlbas;
                csum_indx += nlbas;
                continue;
            } else {
                start_lba = vreq->indx_start_lba;
                csum_indx += (vreq->indx_start_lba - start_lba);
                blk_offset = (vreq->indx_start_lba - start_lba) * page_size / HomeBlks::instance()->get_data_pagesz();
                nlbas -= (vreq->indx_start_lba - start_lba);
            }
        }
        MappingKey key(start_lba, nlbas);
        ValueEntry ve(vreq->seqId, blkid, blk_offset, nlbas, &carr[csum_indx]);
        MappingValue value(ve);

        /* update active btree.indx_start_lba is updated upto the point it is written. It points to the first lba in
         * this range which is not written.
         */
        auto ret = m_active_map->put(vreq, key, value, btree_id, vreq->indx_start_lba);
        if (ret != btree_status_t::success) { return ret; }

        start_lba += nlbas;
        csum_indx += nlbas;
    }
    return btree_status_t::success;
}

void IndxMgr::update_indx(const volume_req_ptr& vreq) {
    int retry_cnt = 0;
    vreq->inc_ref();

retry:
    /* Entered into critical section. CP is not triggered in this critical section */
    vreq->cp_id = m_cp->cp_io_enter();

    /* update active btree */
    auto ret = update_indx_tbl(vreq.get());
    if (ret == btree_status_t::cp_id_mismatch) {
        m_cp->cp_io_exit(vreq->cp_id);
        assert(!retry_cnt);
        ++retry_cnt;
        goto retry;
    }

    /* In case of failure we will still update the journal with entries of whatever is written. */
    /* update journal. Journal writes are not expected to fail */
    journal_write(vreq.get());
}

btree_cp_id_ptr IndxMgr::get_btree_id(indx_cp_id* cp_id) {
    auto it = cp_id->vol_id_list.find(m_uuid);
    btree_cp_id_ptr btree_id;
    if (it == cp_id->vol_id_list.end() || it->second == nullptr) {
        /* volume is just created. So take the first id. */
        btree_id = m_first_cp_id->btree_id;
    } else {
        btree_id = it->second->btree_id;
    }
    assert(btree_id != nullptr);
    return btree_id;
}

vol_cp_id_ptr IndxMgr::get_volume_id(indx_cp_id* cp_id) {
    auto it = cp_id->vol_id_list.find(m_uuid);
    vol_cp_id_ptr btree_id;
    if (it == cp_id->vol_id_list.end() || it->second == nullptr) {
        /* volume is just created. So take the first id. */
        return (m_first_cp_id);
    } else {
        return (it->second);
    }
}

void IndxMgr::trigger_vol_cp() { m_cp->trigger_cp(); }

void IndxMgr::trigger_system_cp(cp_done_cb cb, bool shutdown) {
    /* set bit map checkpoint , resume cp and trigger it */
    if (!m_cp) {
        if (cb) { cb(true); }
        return;
    }
    bool expected = false;
    bool desired = shutdown;
    auto cp_id = m_cp->cp_io_enter();

    /* Make sure that no cp is triggered after shutdown is called */
    if (!m_shutdown_started.compare_exchange_strong(expected, desired)) {
        if (cb) { cb(false); }
        m_cp->cp_io_exit(cp_id);
        return;
    }
    cp_id->bitmap_checkpoint = true;
    if (cb) {
        std::unique_lock< std::mutex > lk(cp_id->cb_list_mtx);
        cp_id->cb_list.push_back(([cb](bool success) {
            assert(success);
            if (cb) { cb(success); }
        }));
    }
    m_cp->trigger_cp(cp_id);
    m_cp->cp_io_exit(cp_id);
}

/* Steps involved in vol destroy. Note that blkids is available to allocate as soon as it is set in bitmap. So we
 * need to make sure that blkids of btree won't be resued until volume is not destroy and until its data blkids
 * and btree blkids are not persisted. Vol destroye is different that IO because there is no journal entry of free
 * blks as we have in regular IO.Steps:-
 * 1. Write a journal entry that this volume is destroying. On recovery if we found this entry and volume is not
 * destroy then we free the blkids of this volume before we replay further entries.
 * 2. We move the cp to suspended state.
 *       Note :- we don't want cp to be taken while we are setting suspend flag. That is why it is called in
 *       checkpoint critical section.
 * 3. We destroy btree. Btree traverses the tree
 *      a. Btree free all the volume blkids and set in a bit map
 *      b. Btree free all its blocks and set in writeback cache layer.
 * At this point volume blkids can be reused by some other volume but btree blkids won't be used until
 * checkpoint is not taken.
 * 4. Resume CP and set bitmap checkpoint to true. This also has to be done in checkpoint critical section as we
 * don't want cp to be taken while we are working on this.
 * 5. Both bitmap checkpoint and volume checkpoint happen in a same CP. It trigger volume checkpoint followed by
 * bitmap checkpoint. Volume checkpoint flush all the blkids in btree to bitmap. And bitmap checkpoint persist
 * the bitmap. checkpoint class make sure that no 2 CPs can not happen in parallel. It prevent from reusing the
 * blkids.
 * 6. Free super block after bit map is persisted. CP is finished only after super block is persisted. It will
 * prevent another cp to start. Another CP might reusing the btree blocks freed by this volume. If we allow
 * other CP to happen before this volume sb is destroy then btree won't be intact and we couldn't able to free
 * volume data blocks.
 */
void IndxMgr::destroy(indxmgr_stop_cb cb) {
    /* we can assume that there is no io going on this volume now */
    HS_SUBMOD_LOG(INFO, base, , "vol", m_name, "Destroying Indx Manager");

    destroy_journal_ent* jent = (destroy_journal_ent*)malloc(sizeof(destroy_journal_ent));
    jent->state = indx_mgr_state::DESTROYING;
    sisl::blob b((uint8_t*)jent, sizeof(destroy_journal_ent));
    m_stop_cb = cb;
    m_journal->append_async(b, b.bytes, ([this](logstore_seq_num_t seq_num, logdev_key key, void* cookie) {
                                free(cookie);
                                add_prepare_cb_list(([this](vol_cp_id_ptr cur_cp_id, indx_cp_id* home_blks_id) {
                                    /* it is called while attaching a new CP id. Suspend this cp and call
                                     * destroy indx table.
                                     */
                                    cur_cp_id->flags = cp_state::suspend_cp;
                                    iomgr_msg io_msg;
                                    io_msg.m_type = RUN_METHOD;
                                    auto btree_id = cur_cp_id->btree_id;
                                    auto run_method = sisl::ObjectAllocator< run_method_t >::make_object();
                                    *run_method = ([this, btree_id]() { this->destroy_indx_tbl(btree_id); });
                                    io_msg.m_data_buf = (void*)run_method;
                                    iomanager.send_msg(m_thread_num, io_msg);
                                }));
                            }));
}

void IndxMgr::destroy_indx_tbl(btree_cp_id_ptr btree_id) {
    /* free all blkids of btree in memory */
    HS_SUBMOD_LOG(INFO, base, , "vol", m_name, "Destroying Index btree");
    if (m_active_map->destroy(btree_id) != btree_status_t::success) {
        /* destroy is failed. We will destroy this volume in next boot */
        m_stop_cb(false);
    }
    add_prepare_cb_list(([this](vol_cp_id_ptr cur_vol_id, indx_cp_id* home_blks_id) {
        this->volume_destroy_cp(cur_vol_id, home_blks_id);
    }));
}

void IndxMgr::volume_destroy_cp(vol_cp_id_ptr cur_vol_id, indx_cp_id* home_blks_id) {
    assert(cur_vol_id->flags == cp_state::suspend_cp);
    assert(!m_shutdown_started.load());
    HS_SUBMOD_LOG(INFO, base, , "vol", m_name, "CP during destroy");

    if (home_blks_id->bitmap_checkpoint) {
        /* this is a bitmap checkpoint. move it to active. this is the last cp of this volume. */
        cur_vol_id->flags = cp_state::active_cp;
        std::unique_lock< std::mutex > lk(home_blks_id->cb_list_mtx);
        home_blks_id->cb_list.push_back(m_stop_cb);
        m_last_cp = true;
    } else {
        /* add it self again to the cb list for next cp which could be bitmap checkpoint */
        add_prepare_cb_list(([this](vol_cp_id_ptr cur_vol_id, indx_cp_id* home_blks_id) {
            this->volume_destroy_cp(cur_vol_id, home_blks_id);
        }));
    }
}

void IndxMgr::add_prepare_cb_list(prepare_cb cb) {
    std::unique_lock< std::mutex > lk(prepare_cb_mtx);
    prepare_cb_list.push_back(cb);
}

void IndxMgr::shutdown(indxmgr_stop_cb cb) {
    iomanager.cancel_timer(m_system_cp_timer_hdl, false);
    m_system_cp_timer_hdl = iomgr::null_timer_handle;
    trigger_system_cp(cb, true);
}

void IndxMgr::destroy_done() {
    m_active_map->destroy_done();
    home_log_store_mgr.remove_log_store(m_journal->get_store_id());
}

std::unique_ptr< IndxCP > IndxMgr::m_cp;
std::atomic< bool > IndxMgr::m_shutdown_started;
int IndxMgr::m_thread_num;
iomgr::timer_handle_t IndxMgr::m_system_cp_timer_hdl = iomgr::null_timer_handle;
void* IndxMgr::m_meta_blk = nullptr;
