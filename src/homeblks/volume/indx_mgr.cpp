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
sisl::blob vol_journal_entry::create_journal_entry(volume_req* vreq) {
    uint32_t size = sizeof(journal_hdr) + vreq->csum_list.size() * sizeof(uint16_t) +
        vreq->alloc_blkid_list.size() * sizeof(BlkId) + vreq->fbe_list.size() * sizeof(free_blkid);
    m_mem = malloc(size);
    /* store journal hdr */
    auto hdr = (journal_hdr*)m_mem;
    hdr->lba = vreq->lba();
    hdr->nlbas = vreq->nlbas();
    hdr->indx_start_lba = vreq->indx_start_lba;
    hdr->cp_cnt = vreq->vol_id->cp_cnt;

    /* store alloc blkid */
    auto blkid = (BlkId*)((uint64_t)m_mem + sizeof(journal_hdr));
    for (uint32_t i = 0; i < vreq->alloc_blkid_list.size(); ++i) {
        blkid[i] = vreq->alloc_blkid_list[i];
    }

    /* store csum */
    auto csum = (uint16_t*)(&blkid[vreq->alloc_blkid_list.size()]);
    for (uint32_t i = 0; i < vreq->csum_list.size(); ++i) {
        csum[i] = vreq->csum_list[i];
    }

    /* store free blk entry */
    auto fbe = (free_blkid*)(&csum[vreq->csum_list.size()]);
    for (uint32_t i = 0; i < vreq->fbe_list.size(); ++i) {
        fbe[i].copy(vreq->fbe_list[i]);
    }
    sisl::blob data((uint8_t*)m_mem, size);

    HS_SUBMOD_LOG(TRACE, volume, vreq, "vol", vreq->vol()->get_name(),
                  "Write to journal size={} lsn={}, journal_hdr:[{}], n_ids={}, n_csum={}, n_fbes={}", size,
                  vreq->seqId, to_string(), vreq->alloc_blkid_list.size(), vreq->csum_list.size(),
                  vreq->fbe_list.size());
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
 * 2. CP Prepare :- Volume and btree decides if it want to participate in a cp_start.
 * 3. CP start :- when all ios on a CP is completed, it start cp flush
 *                      - It flushes the btree dirty buffers
 *                      - When all buffers are dirtied, it flushes the free blks of volume and brree
 * 4. Start blk alloc cp it is scheduled
 * 5. All volumes are notified When cp is done. And it writes the superblock
 * 6. cp end :- CP is completed.
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
                indx_mgr->get_active_indx()->cp_start(it->second->ainfo.btree_id,
                                                      ([this, id](btree_cp_id_ptr btree_id) { indx_tbl_cp_done(id); }));
            }
        }
        indx_tbl_cp_done(id);
    });
    io_msg.m_data_buf = (void*)run_method;
    iomanager.send_msg(IndxMgr::get_thread_num(), io_msg);
}

void IndxCP::indx_tbl_cp_done(indx_cp_id* id) {
    auto cnt = id->ref_cnt.fetch_sub(1);
    if (cnt != 1) { return; }

    /* flush all the blks that are freed in this id */
    IndxMgr::flush_homeblks_free_blks(id);
    if (id->blkalloc_checkpoint) {
        /* persist alloc blkalloc. It is a sync call */
        blkalloc_cp(id);
    } else {
        if (id->try_blkalloc_checkpoint != id->blkalloc_checkpoint) {
            /* it is supposed to take blk alloc checkpoint but couldn't do it. So try taking it in the next cp */
            IndxMgr::trigger_homeblks_cp();
        }
        /* All dirty buffers are flushed. Write super block */
        IndxMgr::write_homeblks_cp_sb(id);
        /* notify all the subhomeblkss which can trigger CP. They can check if they require new cp to be triggered. */
        mapping::cp_done(IndxMgr::trigger_vol_cp);
        cp_end(id);
    }
}

/* This function calls
 * 1. persist blkalloc superblock
 * 2. truncate  :- it truncate upto the seq number persisted in this id.
 * 3. write superblock
 * 4. call cb_list
 * 5. notify blk alloc that cp id done
 * 6. call cp_end :- read comments over indxmgr::destroy().
 */
void IndxCP::blkalloc_cp(indx_cp_id* id) {
    /* persist blk alloc bit maps */
    HomeBlks::instance()->blkalloc_cp_start(id->blkalloc_id);

    /* Now it is safe to truncate as blkalloc bitsmaps are persisted */
    for (auto it = id->vol_id_list.begin(); it != id->vol_id_list.end(); ++it) {
        if (it->second == nullptr || it->second->flags != cp_state::active_cp) { continue; }
        it->second->vol->truncate(it->second);
    }
    home_log_store_mgr.device_truncate();

    /* All dirty buffers are flushed. Write super block */
    IndxMgr::write_homeblks_cp_sb(id);

    /* call all the callbacks which are waiting for this cp to be completed. One example is volume destroy */
    for (uint32_t i = 0; i < id->cb_list.size(); ++i) {
        id->cb_list[i](true);
    }

    /* blk alloc cp done must be called before we call cp end because we want blk alloc to start sweeping the buffers
     * from staging bitmap.
     * Also notify all the subhomeblkss which can trigger CP. They can check if they require new cp to be triggered.
     */
    HomeBlks::instance()->blkalloc_cp_done(id->blkalloc_id);
    mapping::cp_done(IndxMgr::trigger_vol_cp);

    cp_end(id);
    /* id will be freed after checkpoint and volume might get destroy also */
}

/* It attaches the new CP and prepare for cur cp flush */
void IndxCP::cp_attach_prepare(indx_cp_id* cur_id, indx_cp_id* new_id) {
    if (cur_id == nullptr || cur_id->try_blkalloc_checkpoint) {
        new_id->blkalloc_id = HomeBlks::instance()->blkalloc_attach_prepare_cp(cur_id ? cur_id->blkalloc_id : nullptr);
        if (cur_id) { cur_id->blkalloc_checkpoint = true; }
    } else {
        new_id->blkalloc_id = cur_id->blkalloc_id;
    }
    IndxMgr::attach_prepare_vol_cp_id_list(cur_id ? &cur_id->vol_id_list : nullptr, &new_id->vol_id_list, cur_id,
                                           new_id);
}

/****************************************** IndxMgr class ****************************************/

REGISTER_METABLK_SUBSYSTEM(indx_mgr, "INDX_MGR_CP", IndxMgr::meta_blk_found_cb, nullptr)

IndxMgr::IndxMgr(std::shared_ptr< Volume > vol, const vol_params& params, io_done_cb io_cb,
                 free_blk_callback free_blk_cb, pending_read_blk_cb read_blk_cb) :
        m_io_cb(io_cb),
        m_pending_read_blk_cb(read_blk_cb),
        m_uuid(params.uuid),
        m_name(params.vol_name),
        prepare_cb_list(4),
        m_last_sb(m_uuid) {
    m_active_map = new mapping(params.size, params.page_size, params.vol_name, free_blk_cb, IndxMgr::trigger_vol_cp,
                               m_pending_read_blk_cb);

    m_journal = HomeLogStoreMgr::instance().create_new_log_store();
    m_journal_comp_cb =
        std::bind(&IndxMgr::journal_comp_cb, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
    for (int i = 0; i < MAX_CP_CNT; ++i) {
        m_free_list[i] = new sisl::wisr_vector< free_blkid >(100);
    }

    create_first_cp_id(vol);
    std::call_once(m_flag, []() { IndxMgr::init(); });
}

IndxMgr::IndxMgr(std::shared_ptr< Volume > vol, const indx_mgr_active_sb& sb, io_done_cb io_cb,
                 free_blk_callback free_blk_cb, pending_read_blk_cb read_blk_cb) :
        m_io_cb(io_cb),
        m_pending_read_blk_cb(read_blk_cb),
        m_uuid(vol->get_uuid()),
        m_name(vol->get_name()),
        prepare_cb_list(4),
        m_last_sb(m_uuid) {
    m_journal = nullptr;
    m_sb = sb;
    m_free_blk_cb = free_blk_cb;
    HomeLogStoreMgr::instance().open_log_store(
        sb.journal_id, ([this](std::shared_ptr< HomeLogStore > logstore) {
            m_journal = logstore;
            m_journal->register_log_found_cb(
                ([this](logstore_seq_num_t seqnum, log_buffer buf, void* mem) { this->log_found(seqnum, buf, mem); }));
        }));
    m_journal_comp_cb =
        std::bind(&IndxMgr::journal_comp_cb, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
    if (vol->get_state() == vol_state::DESTROYING) { m_state = indx_mgr_state::DESTROYING; }
    for (int i = 0; i < MAX_CP_CNT; ++i) {
        m_free_list[i] = new sisl::wisr_vector< free_blkid >(100);
    }
}

IndxMgr::~IndxMgr() {
    delete m_active_map;
    for (uint32_t i = 0; i < MAX_CP_CNT; ++i) {
        delete m_free_list[i];
    }

    if (m_shutdown_started) { static std::once_flag flag1; }
}

void IndxMgr::init() {
    m_hb = HomeBlks::instance();
    m_cp = std::unique_ptr< IndxCP >(new IndxCP());
    m_shutdown_started.store(false);
    /* start the timer for blkalloc checkpoint */
    m_homeblks_cp_timer_hdl = iomanager.schedule_timer(60 * 1000 * 1000 * 1000ul, true, nullptr, false,
                                                       [](void* cookie) { trigger_homeblks_cp(nullptr, false); });
    auto sthread = std::thread([]() mutable {
        IndxMgr::m_thread_num = sisl::ThreadLocalContext::my_thread_num();
        LOGINFO("{} thread entered", m_thread_num);
        iomanager.run_io_loop(false, nullptr, ([](const iomgr_msg& io_msg) {}));
        LOGINFO("{} thread exit", m_thread_num);
    });
    sthread.detach();
}

void IndxMgr::recovery_start_phase1(std::shared_ptr< Volume > vol) {
    auto it = cp_sb_map.find(m_uuid);
    if (it != cp_sb_map.end()) { memcpy(&m_last_sb, &(it->second), sizeof(m_last_sb)); }

    /* Now we have all the information to create mapping btree */
    m_active_map = new mapping(vol->get_size(), vol->get_page_size(), vol->get_name(), m_sb.btree_sb, m_free_blk_cb,
                               IndxMgr::trigger_vol_cp, m_pending_read_blk_cb, &(m_last_sb.active_btree_cp_sb));
    create_first_cp_id(vol);
}

void IndxMgr::create_first_cp_id(std::shared_ptr< Volume >& vol) {
    auto vol_cp_sb = &(m_last_sb.vol_cp_sb);
    int64_t cp_cnt = vol_cp_sb->cp_cnt + 1;
    int64_t psn = vol_cp_sb->active_data_psn;
    m_first_cp_id = std::make_shared< vol_cp_id >(cp_cnt, psn, vol, m_free_list[cp_cnt % MAX_CP_CNT]);
    m_first_cp_id->ainfo.btree_id = m_active_map->attach_prepare_cp(nullptr, false);
}

void IndxMgr::recovery_start_phase2() {
    std::call_once(m_flag, []() { IndxMgr::init(); });
    /* start replaying the entry */
}

indx_mgr_active_sb IndxMgr::get_active_sb() {
    indx_mgr_active_sb sb;
    sb.btree_sb = m_active_map->get_btree_sb();
    sb.journal_id = m_journal->get_store_id();
    return sb;
}

void IndxMgr::flush_homeblks_free_blks(indx_cp_id* indx_id) {
    for (auto it = indx_id->vol_id_list.begin(); it != indx_id->vol_id_list.end(); ++it) {
        if (it->second == nullptr || it->second->flags != cp_state::active_cp) {
            /* nothing to free. */
            continue;
        }
        /* free blks in a volume */
        it->second->vol->flush_free_blks(it->second, indx_id);
    }
}

void IndxMgr::flush_free_blks(vol_cp_id_ptr vol_id, indx_cp_id* indx_id) {
    /* free blks in a volume */
    auto blkid_list = vol_id->ainfo.free_blkid_list->get_copy_and_reset();
    for (uint32_t i = 0; i < blkid_list->size(); ++i) {
        auto fbe = (*blkid_list)[i];
        m_hb->get_data_blkstore()->free_blk(fbe.m_blkId, m_hb->get_data_pagesz() * fbe.m_blk_offset,
                                            m_hb->get_data_pagesz() * fbe.m_nblks_to_free, indx_id->blkalloc_id);
    }
    /* free blks in a btree */
    m_active_map->flush_free_blks(vol_id->ainfo.btree_id, indx_id->blkalloc_id);
}

void IndxMgr::write_homeblks_cp_sb(indx_cp_id* indx_id) {
    LOGINFO("superblock is written");
    uint8_t* mem = nullptr;
    uint64_t size = sizeof(indx_mgr_cp_sb) * indx_id->vol_id_list.size() + sizeof(indx_mgr_cp_sb_hdr);
    size = sisl::round_up(size , HS_STATIC_CONFIG(disk_attr.align_size));
    int ret = posix_memalign((void**)&(mem), HS_STATIC_CONFIG(disk_attr.align_size), size);
    if (ret != 0) {
        assert(0);
        throw std::bad_alloc();
    }

    indx_mgr_cp_sb_hdr* hdr = (indx_mgr_cp_sb_hdr*)mem;
    hdr->version = INDX_MGR_VERSION;
    int vol_cnt = 0;
    indx_mgr_cp_sb* vol_cp_sb_list = (indx_mgr_cp_sb*)((uint64_t)mem + sizeof(indx_mgr_cp_sb_hdr));
    for (auto it = indx_id->vol_id_list.begin(); it != indx_id->vol_id_list.end(); ++it) {
        auto vol_id = it->second;
        it->second->vol->update_cp_sb(vol_id, indx_id, &vol_cp_sb_list[vol_cnt++]);
    }
    hdr->vol_cnt = vol_cnt;

    if (m_meta_blk) {
        MetaBlkMgr::instance()->update_sub_sb("INDX_MGR_CP", mem, size, m_meta_blk);
    } else {
        /* first time update */
        MetaBlkMgr::instance()->add_sub_sb("INDX_MGR_CP", mem, size, m_meta_blk);
    }
    LOGINFO("superblock is written");
    free(mem);
}

void IndxMgr::update_cp_sb(vol_cp_id_ptr& vol_id, indx_cp_id* indx_id, indx_mgr_cp_sb* sb) {
    if (vol_id->flags != cp_state::active_cp) {
        /* nothing changed since last superblock */
        memcpy(sb, &m_last_sb, sizeof(m_last_sb));
        return;
    }

    assert(vol_id->ainfo.end_psn >= vol_id->ainfo.start_psn);
    assert(vol_id->cp_cnt > m_last_sb.vol_cp_sb.blkalloc_cp_cnt);
    assert(vol_id->cp_cnt == m_last_sb.vol_cp_sb.cp_cnt + 1);

    sb->vol_cp_sb.active_data_psn = vol_id->ainfo.end_psn;
    sb->vol_cp_sb.blkalloc_cp_cnt = indx_id->blkalloc_checkpoint ? vol_id->cp_cnt : m_last_sb.vol_cp_sb.blkalloc_cp_cnt;
    sb->vol_cp_sb.vol_size = vol_id->vol_size.load() + m_last_sb.vol_cp_sb.vol_size;
    sb->vol_cp_sb.cp_cnt = vol_id->cp_cnt;
    sb->uuid = m_uuid;
    m_active_map->update_btree_cp_sb(vol_id->ainfo.btree_id, sb->active_btree_cp_sb, indx_id->blkalloc_checkpoint);
    memcpy(&m_last_sb, sb, sizeof(m_last_sb));
}

void IndxMgr::attach_prepare_vol_cp_id_list(std::map< boost::uuids::uuid, vol_cp_id_ptr >* cur_vols_id,
                                            std::map< boost::uuids::uuid, vol_cp_id_ptr >* new_vols_id,
                                            indx_cp_id* indx_id, indx_cp_id* new_indx_id) {
    m_hb->attach_prepare_volume_cp_id(cur_vols_id, new_vols_id, indx_id, new_indx_id);
}

/* It attaches the new CP and prepare for cur cp flush */
vol_cp_id_ptr IndxMgr::attach_prepare_vol_cp(vol_cp_id_ptr cur_vol_id, indx_cp_id* indx_id, indx_cp_id* new_indx_id) {

    if (cur_vol_id == nullptr) {
        /* this volume is just created in the last CP. return the first_cp_id created at the time of volume creation.
         * And this volume is not going to participate in the current cp. This volume is going to participate in
         * the next cp.
         */
        assert(m_first_cp_id != nullptr);
        /* if indx_id->blkalloc_checkpoint is set to true then it means it is created/destroy in a same cp.
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
        (*cb_list_copy)[i](cur_vol_id, indx_id, new_indx_id);
    }

    if (cur_vol_id->flags == cp_state::suspend_cp) {
        /* this volume is not going to participate in a current cp */
        return cur_vol_id;
    }

    if (m_shutdown_started.load()) {
        m_last_cp = true; // it is set to true even if volume is deleted
    }
    auto btree_id = m_active_map->attach_prepare_cp(cur_vol_id->ainfo.btree_id, m_last_cp);
    cur_vol_id->ainfo.end_psn = m_journal->get_contiguous_issued_seq_num(cur_vol_id->ainfo.start_psn);
    if (m_last_cp) {
        assert(btree_id == nullptr);
        HS_SUBMOD_LOG(INFO, base, , "vol", cur_vol_id->vol->get_name(), "last cp of this volume triggered");
        return nullptr;
    }

    /* create new cp */
    int64_t cp_cnt = cur_vol_id->cp_cnt + 1;
    vol_cp_id_ptr new_vol_id(
        new vol_cp_id(cp_cnt, cur_vol_id->ainfo.end_psn, cur_vol_id->vol, m_free_list[cp_cnt % MAX_CP_CNT]));
    new_vol_id->ainfo.btree_id = btree_id;

    return new_vol_id;
}

void IndxMgr::truncate(vol_cp_id_ptr vol_id) {
    m_journal->truncate(vol_id->ainfo.end_psn);
    m_active_map->truncate(vol_id->ainfo.btree_id);
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
    auto btree_id = vreq->vol_id->ainfo.btree_id;
    for (uint32_t i = 0; i < vreq->alloc_blkid_list.size(); ++i) {

        /* TODO mapping should accept req so that it doesn't need to build value two times */
        auto blkid = vreq->alloc_blkid_list[i];
        uint32_t page_size = vreq->vol()->get_page_size();
        uint32_t nlbas = blkid.data_size(m_hb->get_data_pagesz()) / page_size;
        vreq->vol_id->vol_size.fetch_add(blkid.data_size(m_hb->get_data_pagesz()));
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
                blk_offset = (vreq->indx_start_lba - start_lba) * page_size / m_hb->get_data_pagesz();
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

    /* Increment the reference count by the number of free blk entries. Freing of blk is an async process. So we don't
     * want to take a checkpoint until these blkids are not freed in blk allocator. Blk ids are freed in
     * IndxMgr::free_blk.
     */
    m_cp->cp_inc_ref(vreq->cp_id, vreq->fbe_list.size());
    return btree_status_t::success;
}

void IndxMgr::update_indx(const volume_req_ptr& vreq) {
    int retry_cnt = 0;
    /* Journal write is async call. So incrementing the ref on volume */
    vreq->inc_ref();

retry:
    /* Entered into critical section. CP is not triggered in this critical section */
    vreq->cp_id = m_cp->cp_io_enter();
    vreq->vol_id = get_volume_id(vreq->cp_id);
    if (!vreq->vol_id) { vreq->vol_id = m_first_cp_id; }

    /* update active btree */
    auto ret = update_indx_tbl(vreq.get());
    if (ret == btree_status_t::cp_id_mismatch) {
        m_cp->cp_io_exit(vreq->cp_id);
        assert(!retry_cnt);
        ++retry_cnt;
        goto retry;
    }

    /* In case of failure we will still update the journal with entries of whatever is written. */
    /* update journal. Journal writes are not expected to fail. It is async call/ */
    journal_write(vreq.get());
}

btree_cp_id_ptr IndxMgr::get_btree_id(indx_cp_id* cp_id) {
    auto vol_id = get_volume_id(cp_id);
    if (vol_id) { return (vol_id->ainfo.btree_id); }
    return nullptr;
}

vol_cp_id_ptr IndxMgr::get_volume_id(indx_cp_id* cp_id) {
    auto it = cp_id->vol_id_list.find(m_uuid);
    vol_cp_id_ptr btree_id;
    if (it == cp_id->vol_id_list.end()) {
        /* volume is just created. So take the first id. */
        return (nullptr);
    } else {
        assert(it->second != nullptr);
        return (it->second);
    }
}

void IndxMgr::trigger_vol_cp() { m_cp->trigger_cp(); }

void IndxMgr::trigger_homeblks_cp(cp_done_cb cb, bool shutdown) {
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
    cp_id->try_blkalloc_checkpoint = true;
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

/* Steps involved in vol destroy. Note that blkids is available to allocate as soon as it is set in blkalloc. So we
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
 * 4. Resume CP when blkalloc checkpoint to true.
 * 5. Both blkalloc checkpoint and volume checkpoint happen in a same CP. It trigger volume checkpoint followed by
 * blkalloc checkpoint. Volume checkpoint flush all the blkids in btree to blkalloc. And blkalloc checkpoint persist
 * the blkalloc. checkpoint class make sure that no 2 CPs can not happen in parallel. It prevent from reusing the
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
                                add_prepare_cb_list(
                                    ([this](vol_cp_id_ptr cur_vol_id, indx_cp_id* indx_id, indx_cp_id* new_indx_id) {
                                        /* suspend current cp */
                                        cur_vol_id->flags = cp_state::suspend_cp;
                                        iomgr_msg io_msg;
                                        io_msg.m_type = RUN_METHOD;
                                        auto run_method = sisl::ObjectAllocator< run_method_t >::make_object();
                                        *run_method = ([this, cur_vol_id]() { this->destroy_indx_tbl(cur_vol_id); });
                                        io_msg.m_data_buf = (void*)run_method;
                                        iomanager.send_msg(m_thread_num, io_msg);
                                    }));
                            }));
}

void IndxMgr::destroy_indx_tbl(vol_cp_id_ptr vol_id) {
    /* free all blkids of btree in memory */
    HS_SUBMOD_LOG(INFO, base, , "vol", m_name, "Destroying Index btree");

    if (m_active_map->destroy(vol_id->ainfo.btree_id, vol_id) != btree_status_t::success) {
        /* destroy is failed. We are going ahead to delete the volume. Worse case scneario we are going
         * to leak some blks. It will be recoverd by running homestore fixer.
         */
        LOGERROR("btree destroy failed");
        assert(0);
    }
    add_prepare_cb_list(([this](vol_cp_id_ptr cur_vol_id, indx_cp_id* indx_id, indx_cp_id* new_indx_id) {
        this->volume_destroy_cp(cur_vol_id, indx_id, new_indx_id);
    }));
}

void IndxMgr::volume_destroy_cp(vol_cp_id_ptr cur_vol_id, indx_cp_id* indx_id, indx_cp_id* new_indx_id) {
    assert(cur_vol_id->flags == cp_state::suspend_cp);
    assert(!m_shutdown_started.load());
    HS_SUBMOD_LOG(INFO, base, , "vol", m_name, "CP during destroy");

    if (indx_id->blkalloc_checkpoint) {
        cur_vol_id->flags = cp_state::active_cp;
        std::unique_lock< std::mutex > lk(indx_id->cb_list_mtx);
        indx_id->cb_list.push_back(m_stop_cb);
        m_last_cp = true;
    } else {
        /* add it self again to the cb list for next cp which could be blkalloc checkpoint */
        add_prepare_cb_list(([this](vol_cp_id_ptr cur_vol_id, indx_cp_id* indx_id, indx_cp_id* new_indx_id) {
            this->volume_destroy_cp(cur_vol_id, indx_id, new_indx_id);
        }));
    }
}

void IndxMgr::add_prepare_cb_list(prepare_cb cb) {
    std::unique_lock< std::mutex > lk(prepare_cb_mtx);
    prepare_cb_list.push_back(cb);
}

void IndxMgr::shutdown(indxmgr_stop_cb cb) {
    iomanager.cancel_timer(m_homeblks_cp_timer_hdl, false);
    m_homeblks_cp_timer_hdl = iomgr::null_timer_handle;
    trigger_homeblks_cp(cb, true);
}

void IndxMgr::destroy_done() {
    m_active_map->destroy_done();
    home_log_store_mgr.remove_log_store(m_journal->get_store_id());
}

void IndxMgr::log_found(logstore_seq_num_t seqnum, log_buffer log_buf, void* mem) {}

void IndxMgr::meta_blk_found_cb(meta_blk* mblk, sisl::aligned_unique_ptr< uint8_t > buf, size_t size) {
    m_meta_blk = mblk;
    indx_mgr_cp_sb_hdr* hdr = (indx_mgr_cp_sb_hdr*)buf.get();
    assert(hdr->version == INDX_MGR_VERSION);
    indx_mgr_cp_sb* cp_sb = (indx_mgr_cp_sb*)((uint64_t)buf.get() + sizeof(indx_mgr_cp_sb_hdr));

#ifndef NDEBUG
    uint64_t temp_size = sizeof(indx_mgr_cp_sb_hdr) + hdr->vol_cnt * sizeof(indx_mgr_cp_sb);
    temp_size = sisl::round_up(size, HS_STATIC_CONFIG(disk_attr.align_size));
    assert(size == temp_size);
#endif

    for (uint32_t i = 0; i < hdr->vol_cnt; ++i) {
        bool happened{false};
        std::map< boost::uuids::uuid, indx_mgr_cp_sb >::iterator it;
        std::tie(it, happened) = cp_sb_map.emplace(std::make_pair(cp_sb[i].uuid, cp_sb[i]));
        assert(happened);
    }
}

void IndxMgr::free_blk(Free_Blk_Entry& fbe) {
    auto cp_id = fbe.m_cp_id;
    auto vol_id = fbe.m_vol_id;

    free_blkid fblkid;
    fblkid.copy(fbe);

    vol_id->ainfo.free_blkid_list->push_back(fblkid);
    vol_id->vol_size.fetch_sub(fbe.m_nblks_to_free * m_hb->get_data_pagesz());

    /* We don't allow cp to complete until all required blkids are freed. We increment the ref count in update_indx_tbl
     * by number of free blk entries.
     */
    if (cp_id) { m_cp->cp_io_exit(cp_id); }
}

std::unique_ptr< IndxCP > IndxMgr::m_cp;
std::atomic< bool > IndxMgr::m_shutdown_started;
int IndxMgr::m_thread_num;
iomgr::timer_handle_t IndxMgr::m_homeblks_cp_timer_hdl = iomgr::null_timer_handle;
void* IndxMgr::m_meta_blk = nullptr;
std::once_flag IndxMgr::m_flag;
sisl::aligned_unique_ptr< uint8_t > IndxMgr::m_recovery_sb;
std::map< boost::uuids::uuid, indx_mgr_cp_sb > IndxMgr::cp_sb_map;
size_t IndxMgr::m_recovery_sb_size = 0;
HomeBlks* IndxMgr::m_hb;

