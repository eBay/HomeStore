#include <homestore/blkdata_service.hpp>
#include <homestore/logstore_service.hpp>
#include <homestore/superblk_handler.hpp>
#include "common/homestore_assert.hpp"
#include "replication/repl_dev/solo_repl_dev.h"

namespace homestore {
SoloReplDev::SoloReplDev(superblk< repl_dev_superblk > const& rd_sb, bool load_existing) :
        m_rd_sb{rd_sb}, m_group_id{m_rd_sb->gid} {
    if (load_existing) {
        logstore_service().open_log_store(LogStoreService::DATA_LOG_FAMILY_IDX, m_rd_sb->data_journal_id, true,
                                          bind_this(SoloReplDev::on_data_journal_created, 1));
    } else {
        m_data_journal =
            logstore_service().create_new_log_store(LogStoreService::DATA_LOG_FAMILY_IDX, true /* append_mode */);
        m_rd_sb->data_journal_id = m_data_journal->get_store_id();
    }
}

void SoloReplDev::on_data_journal_created(shared< HomeLogStore > log_store) {
    m_data_journal = std::move(log_store);
    m_rd_sb->data_journal_id = m_data_journal->get_store_id();
    m_data_journal->register_log_found_cb(bind_this(SoloReplDev::on_log_found, 3));
}

void SoloReplDev::async_alloc_write(sisl::blob const& header, sisl::blob const& key, sisl::sg_list const& value,
                                    intrusive< repl_req_ctx > rreq) {
    if (!rreq) { auto rreq = intrusive< repl_req_ctx >(new repl_req_ctx{}); }
    rreq->header = header;
    rreq->key = key;
    rreq->value = std::move(value);

    // If it is header only entry, directly write to the journal
    if (rreq->value.size) {
        // Step 1: Alloc Blkid
        auto status = data_service().alloc_blks(uint32_cast(rreq->value.size),
                                                m_listener->get_blk_alloc_hints(rreq->header, rreq), rreq->local_blkid);
        HS_REL_ASSERT_EQ(status, BlkAllocStatus::SUCCESS);

        // Write the data
        data_service()
            .async_write(rreq->value, rreq->local_blkid)
            .thenValue([this, rreq = std::move(rreq)](auto&& err) {
                HS_REL_ASSERT(!err, "Error in writing data"); // TODO: Find a way to return error to the Listener
                write_journal(std::move(rreq));
            });
    } else {
        write_journal(std::move(rreq));
    }
}

void SoloReplDev::write_journal(intrusive< repl_req_ctx > rreq) {
    uint32_t entry_size = sizeof(repl_journal_entry) + rreq->header.size + rreq->key.size +
        (rreq->value.size ? rreq->local_blkid.serialized_size() : 0);
    rreq->alloc_journal_entry(entry_size);
    rreq->journal_entry->code = journal_type_t::HS_DATA;
    rreq->journal_entry->user_header_size = rreq->header.size;
    rreq->journal_entry->key_size = rreq->key.size;

    uint8_t* raw_ptr = uintptr_cast(rreq->journal_entry) + sizeof(repl_journal_entry);
    if (rreq->header.size) {
        std::memcpy(raw_ptr, rreq->header.bytes, rreq->header.size);
        raw_ptr += rreq->header.size;
    }

    if (rreq->key.size) {
        std::memcpy(raw_ptr, rreq->key.bytes, rreq->key.size);
        raw_ptr += rreq->key.size;
    }

    if (rreq->value.size) {
        auto b = rreq->local_blkid.serialize();
        std::memcpy(raw_ptr, b.bytes, b.size);
        raw_ptr += b.size;
    }

    m_data_journal->append_async(sisl::io_blob{rreq->journal_buf.get(), entry_size, false /* is_aligned */},
                                 nullptr /* cookie */,
                                 [this, rreq](int64_t lsn, sisl::io_blob&, homestore::logdev_key, void*) mutable {
                                     rreq->lsn = lsn;
                                     m_listener->on_pre_commit(rreq->lsn, rreq->header, rreq->key, rreq);

                                     auto cur_lsn = m_commit_upto.load();
                                     if (cur_lsn < lsn) { m_commit_upto.compare_exchange_strong(cur_lsn, lsn); }

                                     data_service().commit_blk(rreq->local_blkid);
                                     m_listener->on_commit(rreq->lsn, rreq->header, rreq->key, rreq->local_blkid, rreq);
                                 });
}

void SoloReplDev::on_log_found(logstore_seq_num_t lsn, log_buffer buf, void* ctx) {
    repl_journal_entry* entry = r_cast< repl_journal_entry* >(buf.bytes());
    uint32_t remain_size = buf.size() - sizeof(repl_journal_entry);
    HS_REL_ASSERT_EQ(entry->major_version, repl_journal_entry::JOURNAL_ENTRY_MAJOR,
                     "Mismatched version of journal entry found");
    HS_REL_ASSERT_EQ(entry->code, journal_type_t::HS_DATA, "Found a journal entry which is not data");

    uint8_t* raw_ptr = r_cast< uint8_t* >(entry) + sizeof(repl_journal_entry);
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
                                                         bool part_of_batch) {
    return data_service().async_read(bid, sgs, size, part_of_batch);
}

void SoloReplDev::async_free_blks(int64_t, MultiBlkId const& bid) { data_service().async_free_blk(bid); }

uint32_t SoloReplDev::get_blk_size() const { return data_service().get_blk_size(); }

void SoloReplDev::cp_flush(CP*) {
    auto lsn = m_commit_upto.load();
    m_rd_sb->commit_lsn = lsn;
    m_rd_sb->checkpoint_lsn = lsn;
    m_rd_sb.write();
}

void SoloReplDev::cp_cleanup(CP*) { m_data_journal->truncate(m_rd_sb->checkpoint_lsn); }

void repl_req_ctx::alloc_journal_entry(uint32_t size) {
    journal_buf = std::unique_ptr< uint8_t[] >(new uint8_t[size]);
    journal_entry = new (journal_buf.get()) repl_journal_entry();
}

repl_req_ctx::~repl_req_ctx() {
    if (journal_entry) { journal_entry->~repl_journal_entry(); }
}
} // namespace homestore