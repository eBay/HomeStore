#include <boost/smart_ptr/intrusive_ref_counter.hpp>
#include "replication/repl_dev/solo_repl_dev.h"
#include "replication/repl_dev/common.h"
#include <homestore/blkdata_service.hpp>
#include <homestore/logstore_service.hpp>
#include <homestore/superblk_handler.hpp>
#include "common/homestore_assert.hpp"

namespace homestore {
SoloReplDev::SoloReplDev(superblk< repl_dev_superblk >&& rd_sb, bool load_existing) :
        m_rd_sb{std::move(rd_sb)}, m_group_id{m_rd_sb->group_id} {
    if (load_existing) {
        logstore_service().open_logdev(m_rd_sb->logdev_id, flush_mode_t::TIMER);
        logstore_service()
            .open_log_store(m_rd_sb->logdev_id, m_rd_sb->logstore_id, true /* append_mode */)
            .thenValue([this](auto log_store) {
                m_data_journal = std::move(log_store);
                m_rd_sb->logstore_id = m_data_journal->get_store_id();
                m_data_journal->register_log_found_cb(bind_this(SoloReplDev::on_log_found, 3));
            });
    } else {
        m_logdev_id = logstore_service().create_new_logdev(flush_mode_t::TIMER);
        m_data_journal = logstore_service().create_new_log_store(m_logdev_id, true /* append_mode */);
        m_rd_sb->logstore_id = m_data_journal->get_store_id();
        m_rd_sb->logdev_id = m_logdev_id;
        m_rd_sb.write();
    }
}

void SoloReplDev::async_alloc_write(sisl::blob const& header, sisl::blob const& key, sisl::sg_list const& value,
                                    repl_req_ptr_t rreq, trace_id_t tid) {
    if (!rreq) { auto rreq = repl_req_ptr_t(new repl_req_ctx{}); }

    incr_pending_request_num();
    auto status = rreq->init(repl_key{.server_id = 0, .term = 1, .dsn = 1, .traceID = tid},
                             value.size ? journal_type_t::HS_DATA_LINKED : journal_type_t::HS_DATA_INLINED, true,
                             header, key, value.size, m_listener);
    HS_REL_ASSERT_EQ(status, ReplServiceError::OK, "Error in allocating local blks");
    // If it is header only entry, directly write to the journal
    if (rreq->has_linked_data() && !rreq->has_state(repl_req_state_t::DATA_WRITTEN)) {
        // Write the data
        data_service().async_write(value, rreq->local_blkid()).thenValue([this, rreq = std::move(rreq)](auto&& err) {
            HS_REL_ASSERT(!err, "Error in writing data"); // TODO: Find a way to return error to the Listener
            write_journal(std::move(rreq));
        });
    } else {
        write_journal(std::move(rreq));
    }
}

void SoloReplDev::write_journal(repl_req_ptr_t rreq) {
    rreq->create_journal_entry(false /* raft_buf */, 1);

    m_data_journal->append_async(
        sisl::io_blob{rreq->raw_journal_buf(), rreq->journal_entry_size(), false /* is_aligned */},
        nullptr /* cookie */, [this, rreq](int64_t lsn, sisl::io_blob&, homestore::logdev_key, void*) mutable {
            rreq->set_lsn(lsn);
            m_listener->on_pre_commit(rreq->lsn(), rreq->header(), rreq->key(), rreq);

            auto cur_lsn = m_commit_upto.load();
            if (cur_lsn < lsn) { m_commit_upto.compare_exchange_strong(cur_lsn, lsn); }

            data_service().commit_blk(rreq->local_blkid());
            m_listener->on_commit(rreq->lsn(), rreq->header(), rreq->key(), rreq->local_blkid(), rreq);
            decr_pending_request_num();
        });
}

void SoloReplDev::on_log_found(logstore_seq_num_t lsn, log_buffer buf, void* ctx) {
    repl_journal_entry const* entry = r_cast< repl_journal_entry const* >(buf.bytes());
    uint32_t remain_size = buf.size() - sizeof(repl_journal_entry);
    HS_REL_ASSERT_EQ(entry->major_version, repl_journal_entry::JOURNAL_ENTRY_MAJOR,
                     "Mismatched version of journal entry found");

    uint8_t const* raw_ptr = r_cast< uint8_t const* >(entry) + sizeof(repl_journal_entry);
    sisl::blob header{raw_ptr, entry->user_header_size};
    HS_REL_ASSERT_GE(remain_size, entry->user_header_size, "Invalid journal entry, header_size mismatch");
    raw_ptr += entry->user_header_size;
    remain_size -= entry->user_header_size;

    sisl::blob key{raw_ptr, entry->key_size};
    HS_REL_ASSERT_GE(remain_size, entry->key_size, "Invalid journal entry, key_size mismatch");
    raw_ptr += entry->key_size;
    remain_size -= entry->key_size;

    sisl::blob value_blob{raw_ptr, remain_size};
    MultiBlkId blkid;
    if (remain_size) { blkid.deserialize(value_blob, true /* copy */); }

    m_listener->on_pre_commit(lsn, header, key, nullptr);

    auto cur_lsn = m_commit_upto.load();
    if (cur_lsn < lsn) { m_commit_upto.compare_exchange_strong(cur_lsn, lsn); }

    m_listener->on_commit(lsn, header, key, blkid, nullptr);
}

folly::Future< std::error_code > SoloReplDev::async_read(MultiBlkId const& bid, sisl::sg_list& sgs, uint32_t size,
                                                         bool part_of_batch, trace_id_t tid) {
    if (is_stopping()) {
        LOGINFO("repl dev is being shutdown!");
        return folly::makeFuture< std::error_code >(std::make_error_code(std::errc::operation_canceled));
    }
    incr_pending_request_num();
    auto result = data_service().async_read(bid, sgs, size, part_of_batch);
    decr_pending_request_num();
    return result;
}

folly::Future< std::error_code > SoloReplDev::async_free_blks(int64_t, MultiBlkId const& bid, trace_id_t tid) {
    if (is_stopping()) {
        LOGINFO("repl dev is being shutdown!");
        return folly::makeFuture< std::error_code >(std::make_error_code(std::errc::operation_canceled));
    }
    incr_pending_request_num();
    auto result = data_service().async_free_blk(bid);
    decr_pending_request_num();
    return result;
}

uint32_t SoloReplDev::get_blk_size() const { return data_service().get_blk_size(); }

void SoloReplDev::cp_flush(CP*) {
    auto lsn = m_commit_upto.load();
    m_rd_sb->durable_commit_lsn = lsn;
    m_rd_sb->checkpoint_lsn = lsn;
    m_rd_sb.write();
}

void SoloReplDev::cp_cleanup(CP*) { /* m_data_journal->truncate(m_rd_sb->checkpoint_lsn); */ }

} // namespace homestore
