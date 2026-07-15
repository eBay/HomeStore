#include <latch>
#include <boost/smart_ptr/intrusive_ref_counter.hpp>
#include "replication/repl_dev/solo_repl_dev.h"
#include "replication/repl_dev/common.h"
#include "common/coro_helpers.hpp" // detail::detach_then
#include <sisl/async/when_all.hpp> // sisl::async::when_all
#include <homestore/homestore.hpp>
#include <homestore/blkdata_service.hpp>
#include <homestore/logstore_service.hpp>
#include <homestore/superblk_handler.hpp>
#include "common/homestore_assert.hpp"
#include "common/homestore_config.hpp"
#include <iomgr/iomgr_flip.hpp>

SISL_LOGGING_DECL(solorepl)

namespace homestore {
SoloReplDev::SoloReplDev(superblk< solo_repl_dev_superblk >&& rd_sb, bool load_existing) :
        m_rd_sb{std::move(rd_sb)}, m_group_id{m_rd_sb->group_id} {
    auto const gid = m_rd_sb->group_id;
    if (load_existing) {
        m_logdev_id = m_rd_sb->logdev_id;
        logstore_service().open_logdev(m_rd_sb->logdev_id, flush_mode_t::TIMER | flush_mode_t::INLINE, gid);
        detail::detach_then(
            logstore_service().open_log_store(m_rd_sb->logdev_id, m_rd_sb->logstore_id, true /* append_mode */),
            [this](auto log_store) {
                m_data_journal = std::move(log_store);
                m_rd_sb->logstore_id = m_data_journal->get_store_id();
                m_data_journal->register_log_found_cb(bind_this(SoloReplDev::on_log_found, 3));
                m_is_recovered = true;
            });
        m_commit_upto = m_rd_sb->durable_commit_lsn;
    } else {
        m_logdev_id = logstore_service().create_new_logdev(flush_mode_t::TIMER | flush_mode_t::INLINE, gid);
        m_data_journal = logstore_service().create_new_log_store(m_logdev_id, true /* append_mode */);
        m_rd_sb->logstore_id = m_data_journal->get_store_id();
        m_rd_sb->logdev_id = m_logdev_id;
        m_rd_sb->checkpoint_lsn = -1;
        m_rd_sb.write();
        m_is_recovered = true;
    }
}

void SoloReplDev::async_alloc_write(sisl::blob const& header, sisl::blob const& key, sisl::sg_list const& value,
                                    repl_req_ptr_t rreq, io_batch* batch, trace_id_t tid) {
    if (!rreq) { rreq = repl_req_ptr_t(new repl_req_ctx{}); }

    incr_pending_request_num();
    auto status = rreq->init(repl_key{.server_id = 0, .term = 1, .dsn = 1, .traceID = tid},
                             value.size ? journal_type_t::HS_DATA_LINKED : journal_type_t::HS_DATA_INLINED, true,
                             header, key, value.size, m_listener);
    HS_REL_ASSERT_EQ(status, ReplServiceError::OK, "Error in allocating local blks");
    // If it is header only entry, directly write to the journal
    if (rreq->has_linked_data() && !rreq->has_state(repl_req_state_t::DATA_WRITTEN)) {
        // Write the data. Read rreq->local_blkids() into a local BEFORE the lambda's `rreq = std::move(rreq)`:
        // they are sibling arguments to detach_then, whose evaluation order is unspecified, so moving rreq first
        // would null it before local_blkids() runs.
        auto const blkids = rreq->local_blkids();
        detail::detach_then(data_service().async_write(value, blkids),
                            [this, rreq = std::move(rreq)](iomgr::io_result const& r) mutable {
                                HS_REL_ASSERT(bool(r), "Error in writing data"); // TODO: return error to the Listener
                                write_journal(std::move(rreq));
                            });
    } else {
        write_journal(std::move(rreq));
    }
}

// destroy is only called in worker thread;
void SoloReplDev::destroy() {
    HS_REL_ASSERT(iomanager.am_i_worker_reactor(), "Destroy should be called in worker thread");
    while (!m_is_recovered) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    hs()->logstore_service().remove_log_store(m_logdev_id, m_data_journal->get_store_id());
    hs()->logstore_service().destroy_log_dev(m_logdev_id);

    m_rd_sb.destroy();
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

            for (const auto& blkid : rreq->local_blkids()) {
                (void)data_service().commit_blk(blkid);
            }
            m_listener->on_commit(rreq->lsn(), rreq->header(), rreq->key(), rreq->local_blkids(), rreq);
            decr_pending_request_num();
        });
}

status SoloReplDev::alloc_blks(uint32_t data_size, const blk_alloc_hints& hints,
                               std::vector< multi_blk_id >& out_blkids) {
    if (is_stopping()) { return std::unexpected(std::make_error_condition(std::errc::operation_canceled)); }

    incr_pending_request_num();
    auto blk_result =
        data_service().alloc_blk_list(sisl::round_up(uint32_cast(data_size), data_service().get_blk_size()), hints);
    if (!blk_result) {
        DEBUG_ASSERT(false, "Unable to allocate blks");
        decr_pending_request_num();
        return std::unexpected(blk_result.error());
    }
    for (auto& blkid : blk_result.value()) {
        out_blkids.emplace_back(blkid);
    }
    decr_pending_request_num();
    return ok();
}

sisl::async::task< iomgr::io_result > SoloReplDev::async_write(const std::vector< multi_blk_id >& blkids,
                                                               sisl::sg_list const& value, io_batch* batch,
                                                               trace_id_t tid) {
    if (is_stopping()) { co_return std::unexpected(std::make_error_condition(std::errc::operation_canceled)); }

    incr_pending_request_num();
    HS_REL_ASSERT_GT(blkids.size(), 0, "Empty blkid vec");
    // Each piece's sg_list must outlive the (lazy) async_write tasks (reserved so the by-reference tasks never see
    // a reallocation), kept in a frame-local vector until the fan-out below completes.
    std::vector< sisl::sg_list > piece_sgs;
    piece_sgs.reserve(blkids.size());
    std::vector< sisl::async::task< iomgr::io_result > > futs;
    futs.reserve(blkids.size());
    sisl::sg_iterator sg_it{value.iovs};

    for (const auto& blkid : blkids) {
        auto sgs_size = blkid.blk_count() * data_service().get_blk_size();
        const auto iovs = sg_it.next_iovs(sgs_size);
        uint32_t total_size = 0;
        for (auto& iov : iovs) {
            total_size += iov.iov_len;
        }
        if (total_size != sgs_size) {
            LOGINFO("Block size mismatch total_size={} sgs_size={}", total_size, sgs_size);
            decr_pending_request_num();
            co_return std::unexpected(std::make_error_condition(std::errc::invalid_argument));
        }
        piece_sgs.push_back(sisl::sg_list{sgs_size, iovs});
        futs.emplace_back(data_service().async_write(piece_sgs.back(), blkid, batch));
    }

    auto const results = co_await sisl::async::when_all(std::move(futs));
    decr_pending_request_num();
    for (const auto& r : results) {
        if (sisl_unlikely(!r)) { co_return std::unexpected(std::make_error_condition(std::errc::io_error)); }
    }
    co_return iomgr::io_result{0};
}

void SoloReplDev::async_write_journal(const std::vector< multi_blk_id >& blkids, sisl::blob const& header,
                                      sisl::blob const& key, uint32_t data_size, repl_req_ptr_t rreq, trace_id_t tid) {
    if (is_stopping()) { return; }
    incr_pending_request_num();

    // We expect clients to provide valid repl req ctx with blocks allocated.
    HS_REL_ASSERT(rreq, "Invalid repl req ctx");
    rreq->add_state(repl_req_state_t::BLK_ALLOCATED);
    rreq->set_local_blkids(blkids);
    auto status = rreq->init(repl_key{.server_id = 0, .term = 1, .dsn = 1, .traceID = tid},
                             data_size ? journal_type_t::HS_DATA_LINKED : journal_type_t::HS_DATA_INLINED, true, header,
                             key, data_size, m_listener);
    HS_REL_ASSERT_EQ(status, ReplServiceError::OK, "Error in initializing repl req context.");

    // Write to journal.
    write_journal(std::move(rreq));
}

void SoloReplDev::on_log_found(logstore_seq_num_t lsn, log_buffer buf, void* ctx) {
    auto cur_lsn = m_commit_upto.load();

    bool force_replay = false;
    if (SISL_OPTIONS.count("solo_force_replay")) { force_replay = SISL_OPTIONS["solo_force_replay"].as< bool >(); }

    if (cur_lsn >= lsn and !force_replay) {
        // Already committed
        LOGINFO("SoloReplDev skipping already committed log_entry lsn={}, m_commit_upto at lsn={}", lsn, cur_lsn);
        return;
    }

    repl_journal_entry const* entry = r_cast< repl_journal_entry const* >(buf.bytes());
    uint32_t remain_size = buf.size() - sizeof(repl_journal_entry);
    HS_REL_ASSERT_EQ(entry->major_version, repl_journal_entry::JOURNAL_ENTRY_MAJOR,
                     "Mismatched version of journal entry found");
    HS_LOG(DEBUG, solorepl, "SoloReplDev found journal entry at lsn={}", lsn);

    uint8_t const* raw_ptr = r_cast< uint8_t const* >(entry) + sizeof(repl_journal_entry);
    sisl::blob header{raw_ptr, entry->user_header_size};
    HS_REL_ASSERT_GE(remain_size, entry->user_header_size, "Invalid journal entry, header_size mismatch");
    raw_ptr += entry->user_header_size;
    remain_size -= entry->user_header_size;

    sisl::blob key{raw_ptr, entry->key_size};
    HS_REL_ASSERT_GE(remain_size, entry->key_size, "Invalid journal entry, key_size mismatch");
    raw_ptr += entry->key_size;
    remain_size -= entry->key_size;

    std::vector< multi_blk_id > blkids;
    while (remain_size > 0) {
        multi_blk_id blkid;
        sisl::blob value_blob{raw_ptr, sizeof(blk_id)};
        blkid.deserialize(value_blob, true /* copy */);
        raw_ptr += sizeof(blk_id);
        remain_size -= sizeof(blk_id);
        blkids.push_back(blkid);
    }

    m_listener->on_pre_commit(lsn, header, key, nullptr /* context */);
    if (cur_lsn < lsn) {
        // we will only be here when we experienced a crash recocovery;
        m_commit_upto.compare_exchange_strong(cur_lsn, lsn);
    }

    for (const auto& blkid : blkids) {
        (void)data_service().commit_blk(blkid);
    }

    m_listener->on_commit(lsn, header, key, blkids, nullptr /* context */);
}

sisl::async::task< iomgr::io_result > SoloReplDev::async_read(multi_blk_id const& bid, sisl::sg_list& sgs,
                                                              uint32_t size, io_batch* batch, trace_id_t tid) {
    if (is_stopping()) { co_return std::unexpected(std::make_error_condition(std::errc::operation_canceled)); }
    incr_pending_request_num();
    auto result = data_service().async_read(bid, sgs, size, batch);
    decr_pending_request_num();
    co_return co_await std::move(result);
}

sisl::async::task< iomgr::io_result > SoloReplDev::async_free_blks(int64_t, multi_blk_id const& bid, trace_id_t tid) {
    if (is_stopping()) { co_return std::unexpected(std::make_error_condition(std::errc::operation_canceled)); }
    incr_pending_request_num();
    auto result = data_service().async_free_blk(bid);
    decr_pending_request_num();
    co_return co_await std::move(result);
}

uint32_t SoloReplDev::get_blk_size() const { return data_service().get_blk_size(); }

void SoloReplDev::cp_flush(CP*) {
    auto lsn = m_commit_upto.load();
    m_rd_sb->durable_commit_lsn = lsn;
    // Store the LSN's for last 3 checkpoints
    m_rd_sb->last_checkpoint_lsn_2 = m_rd_sb->last_checkpoint_lsn_1;
    m_rd_sb->last_checkpoint_lsn_1 = m_rd_sb->checkpoint_lsn;
    m_rd_sb->checkpoint_lsn = lsn;
    HS_LOG(INFO, solorepl, "dev={} cp flush cp_lsn={} cp_lsn_1={} cp_lsn_2={}", boost::uuids::to_string(group_id()),
           lsn, m_rd_sb->last_checkpoint_lsn_1, m_rd_sb->last_checkpoint_lsn_2);
    m_rd_sb.write();
}

void SoloReplDev::truncate() {
    // Ignore truncate when HS is initializing. And we need atleast 3 checkpoints to start truncating.
    if (homestore::hs()->is_initializing() || m_rd_sb->last_checkpoint_lsn_2 <= 0) { return; }

    // Truncate is safe anything below last_checkpoint_lsn - 2 as all the free blks
    // before that will be flushed in the last_checkpoint.
    HS_LOG(INFO, solorepl, "dev={} truncating at lsn={}", boost::uuids::to_string(group_id()),
           m_rd_sb->last_checkpoint_lsn_2);
    m_data_journal->truncate(m_rd_sb->last_checkpoint_lsn_2, false /*in-memory-only*/);
}

void SoloReplDev::cp_cleanup(CP*) {
#ifdef _PRERELEASE
    if (iomgr_flip::instance()->test_flip("solo_repl_dev_manual_truncate")) { return; }
#endif
    // cp_cleanup is called after all components' CP flush is done.
    // We call truncate during cp clean up.
    truncate();
}

} // namespace homestore
