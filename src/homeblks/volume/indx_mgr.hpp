#pragma once
#include <cassert>
#include "engine/checkpoint/checkpoint.hpp"
#include "homelogstore/log_store.hpp"
#include "api/vol_interface.hpp"

namespace homestore {
struct volume_req;
class mapping;
struct Free_Blk_Entry;

/* Journal entry
 * --------------------------------------------------------------------
 * | Journal Hdr | alloc_blkid list | checksum list | free_blk_entry |
 * -------------------------------------------------------------------
 */
struct journal_hdr {
    uint64_t lba;
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

struct journal_alloc_entry {
    BlkId id;
    uint16_t checksum;
};

struct journal_free_entry {
    BlkId id;
};

struct indx_cp_id : cp_id {
    // Start PSN of different checkpoints in this ID
    uint64_t active_psn = 0;
    uint64_t diff_psn = 0;
    uint64_t last_active_psn = 0;
    uint64_t last_diff_psn = 0;

    /* It keeps track of outstanding journal writes. We start with one , increment it before writing to a journal
     * and decrememnt it on every journal completion and cp_start.
     */
    std::atomic< uint64_t > ref_cnt = 1;
};

class IndxCP : public CheckPoint< indx_cp_id > {
public:
    IndxCP();
    void recovery_done();
    void suspend_diff_cp();
    void resume_diff_cp();
    void flush_dirty_buffers(indx_cp_id* id);
    virtual void cp_start(indx_cp_id* id);
    virtual void cp_prepare(indx_cp_id* prev_id, indx_cp_id* cur_id);
    virtual ~IndxCP();
};

class IndxMgr {
    typedef std::function< void(volume_req* req) > io_done_cb;
    typedef std::function< void(Free_Blk_Entry fbe) > free_blk_callback;
    typedef std::function< void(volume_req* req, BlkId& bid) > pending_read_blk_cb;

private:
    mapping* m_active_map;
    mapping* m_diff_map;
    IndxCP* m_cp;
    io_done_cb m_io_cb;
    pending_read_blk_cb m_pending_read_blk_cb;
    std::shared_ptr< HomeLogStore > journal;
    log_write_comp_cb_t m_journal_comp_cb;

    void recovery();
    void journal_comp_cb_internal(volume_req* req);
    void journal_write(volume_req* vreq);
    void journal_comp_cb(logstore_seq_num_t seq_num, logdev_key ld_key, void* req);
    void update_indx_tbl(volume_req* vreq);

public:
    IndxMgr(bool init, const vol_params& params, io_done_cb io_cb, free_blk_callback free_blk_cb,
            pending_read_blk_cb read_blk_cb);
    ~IndxMgr();

    /* Get the active indx table */
    mapping* get_active_indx();

    /* write/update indx table for a IO */
    void update_indx(volume_req* req);
    void destroy();
    void truncate();
};
} // namespace homestore
