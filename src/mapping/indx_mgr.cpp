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
    hdr->lba = v_req->lba;
    hdr->nlba = v_req->nlbas;

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
    return data;
}

IndxCP::IndxCP() : CheckPoint(10) {
    auto cp_id = get_cur_cp_id();
    cp_prepare(nullptr, cp_id);
}

IndxCP::~IndxCP() {}

void IndxCP::suspend_diff_cp() { /* TODO : implement it in snapshot */ }

void IndxCP::resume_diff_cp() { /* TODO: implement it in snapshot */ }

void IndxCP::cp_start(indx_cp_id* id) {
    /* decrement the ref cnt */
    int cnt = id->ref_cnt.fetch_sub(1);
    if (cnt != 1) {
        /* wait for it to be zero */
        return;
    }
    flush_dirty_buffers(id);
}

void IndxCP::flush_dirty_buffers(indx_cp_id* id) {}

void IndxCP::cp_prepare(indx_cp_id* prev_id, indx_cp_id* cur_id) {
/* Get the last contiguous seq ID */
#if 0
    cur_id->last_active_psn = prev_id->active_psn = journal->get_last_issued_contiguous_id(prev_id->last_active_psn);
    prev_id->last_diff_psn = prev_id->diff_psn = journal->get_last_issued_contiguous_id(prev_id->last_diff_psn);
#endif
}

void IndxCP::recovery_done() {}

IndxMgr::IndxMgr(bool init, const vol_params& params, io_done_cb io_cb, free_blk_callback free_blk_cb,
                 pending_read_blk_cb read_blk_cb) :
        m_io_cb(io_cb), m_pending_read_blk_cb(read_blk_cb) {
    if (!init) {
        recovery();
        return;
    }
    m_cp = new IndxCP();
    /* TODO :- give different vol_name to active and diff */
    m_active_map =
        new mapping(params.size, params.page_size, params.vol_name, nullptr, free_blk_cb, m_pending_read_blk_cb);

    m_diff_map = new mapping(params.size, params.page_size, params.vol_name, nullptr, nullptr, nullptr);

    journal = HomeLogStoreMgr::instance().create_new_log_store();
    m_journal_comp_cb =
        std::bind(&IndxMgr::journal_comp_cb, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
}

IndxMgr::~IndxMgr() {
    delete m_cp;
    delete m_diff_map;
    delete m_active_map;
}

void IndxMgr::truncate() {
    auto cp_id = m_cp->get_cur_cp_id();
    /* TODO update superblock */
    //    journal->truncate(cp_id->last_diff_psn);
}

void IndxMgr::recovery() {}

mapping* IndxMgr::get_active_indx() { return m_active_map; }

void IndxMgr::journal_comp_cb(logstore_seq_num_t seq_num, bool status, void* req) {
    auto vreq = boost::intrusive_ptr< volume_req >((volume_req*)req, false);
    journal_comp_cb_internal(vreq);
}

void IndxMgr::journal_comp_cb_internal(volume_req_ptr& vreq) {
    m_io_cb(vreq);
    int cnt = vreq->cp_id->ref_cnt.fetch_sub(1);
    if (cnt == 1) { /* send signal to the thread to do cp start */ }
}

void IndxMgr::journal_write(volume_req_ptr& vreq) {
    auto b = vreq->create_journal_entry();
    vreq->inc_ref_cnt();
    journal->write_async(vreq->seqId, b, vreq.get(), m_journal_comp_cb);
}

void IndxMgr::update_indx_tbl(volume_req_ptr& vreq) {
    std::array< uint16_t, CS_ARRAY_STACK_SIZE > carr;
    uint64_t offset = 0;

    for (uint32_t i = 0; i < vreq->nlbas; ++i) {
        carr[i] = vreq->csum_list[i];
    }

    uint32_t start_lba = vreq->lba;
    int csum_indx = 0;
    for (uint32_t i = 0; i < vreq->alloc_blkid_list.size(); ++i) {

        /* TODO mapping should accept req so that it doesn't need to build value two times */
        auto blkid = vreq->alloc_blkid_list[i];
        uint32_t page_size = vreq->vol_instance->get_page_size();
        uint32_t nlbas = blkid.data_size(page_size) / page_size;
        MappingKey key(start_lba, nlbas);
        ValueEntry ve(vreq->seqId, blkid, 0, nlbas, &carr[csum_indx]);
        MappingValue value(ve);

        /* update active btree */
        m_active_map->put(vreq, key, value);

        /* update diff btree */
        m_diff_map->put(nullptr, key, value);
        start_lba += nlbas;
        csum_indx += nlbas;
    }
}

void IndxMgr::update_indx(volume_req_ptr& vreq) {

    /* Entered into critical section. CP is not triggered in this critical section */
    vreq->cp_id = m_cp->cp_io_enter();

    /* update active btree */
    update_indx_tbl(vreq);

    /* update journal. Journal writes are not expected to fail */
    vreq->cp_id->ref_cnt++;
    journal_write(vreq);

    /* End of critical section */
    m_cp->cp_io_exit(vreq->cp_id);
}

void IndxMgr::destroy() {
    m_diff_map->destroy();
    m_active_map->destroy();
}
