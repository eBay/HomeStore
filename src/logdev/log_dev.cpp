#include "log_dev.hpp"

namespace homestore {
void LogDev::load(uint64_t dev_offset) {
    do_load(dev_offset);
    m_log_records.reinit(m_log_idx);
    m_last_flush_idx = m_log_idx - 1;
}

void LogDev::do_load(uint64_t device_cursor) {
    auto store = HomeBlks::instance()->get_logdev_blkstore();
    bool read_more = true;

    while (read_more) {
        // Read the data in bulk (of say 512K) and then process each log group header
        auto buf = std::make_shared< sisl::byte_array >(bulk_read_size, dma_boundary);
        auto rbuf = buf->bytes;

        auto group_dev_offset = device_cursor;
        store->read(device_cursor, bulk_read_size, (void*)rbuf);
        auto this_read_remains = bulk_read_size;
        device_cursor += bulk_read_size;

        // Loop thru the entire bulk read buffer and process one log group at a time.
        while (this_read_remains > 0) {
            auto header = (log_group_header*)rbuf;
            if (header->magic_word() != LOG_GROUP_HDR_MAGIC) {
                // HS_ASSERT_CMP(RELEASE, m_last_crc, ==, INVALID_CRC32_VALUE, "Invalid magic, and its not first
                // record!");
                read_more = false;
                break;
            }

            // We can only do crc match in read if we have read all the blocks. We don't want to aggressively read more
            // data than we need to just to compare CRC for read operation. It can be done during recovery.
            if (header->total_size() > this_read_remains) {
                read_more = true;
                device_cursor -= (header->total_size() - this_read_remains); // Adjust the cursor back
                break;
            }

            // TODO: Generalize this by validating multiple things
            // a) Header magic match
            // b) This CRC match
            // c) Previous CRC match
            // d) If any mismatch, keep reading next N (512) blocks and see if it has data (log_idx > prev_log_idx)
            uint32_t crc = crc32_ieee(init_crc32, ((uint8_t*)rbuf) + sizeof(log_group_header),
                                      header->total_size() - sizeof(log_group_header));
            HS_ASSERT_CMP(RELEASE, header->this_group_crc(), ==, crc, "CRC mismatch on read data");
            m_last_crc = crc;

            // Loop through each record within the log group and do a callback
            auto i = 0u;
            while (i < header->nrecords()) {
                auto* rec = header->nth_record(i);
                uint32_t data_offset = (rec->offset + (rec->is_inlined ? 0 : header->oob_data_offset));

                // Do a callback on the found log entry
                log_buffer b(buf, data_offset, rec->size);
                m_logfound_cb(log_key{header->start_idx() + i, group_dev_offset}, b);
                ++i;
            }

            m_log_idx = header->start_idx() + i;
            group_dev_offset += header->total_size();
            rbuf += header->total_size();
            this_read_remains -= header->total_size();
        }
    }
}

int64_t LogDev::append(uint8_t* data, uint32_t size, void* cb_context) {
    auto idx = m_log_idx.fetch_add(1, std::memory_order_acq_rel);
    flush_if_needed(size, idx);
    m_log_records.create(idx, data, size, cb_context);
    return idx;
}

log_buffer LogDev::read(const log_key& key) {
    static thread_local sisl::aligned_unique_ptr< uint8_t > _read_buf;

    // First read the offset and read the log_group. Then locate the log_idx within that and get the actual data
    // Read about 4K of buffer
    if (!_read_buf) { _read_buf = sisl::make_aligned_unique< uint8_t >(dma_boundary, initial_read_size); }
    auto rbuf = _read_buf.get();
    auto store = HomeBlks::instance()->get_logdev_blkstore();
    store->read(key.dev_offset, initial_read_size, (void*)rbuf);

    auto header = (log_group_header*)rbuf;
    HS_ASSERT_CMP(RELEASE, header->magic_word(), ==, LOG_GROUP_HDR_MAGIC, "Log header corrupted with magic mismatch!");
    HS_ASSERT_CMP(RELEASE, header->start_idx(), <=, key.idx, "log key offset does not match with log_idx");
    HS_ASSERT_CMP(RELEASE, (header->start_idx() + header->nrecords()), >, key.idx,
                  "log key offset does not match with log_idx");
    HS_ASSERT_CMP(LOGMSG, header->total_size(), >=, header->_inline_data_offset(),
                  "Inconsistent size data in log group");

    // We can only do crc match in read if we have read all the blocks. We don't want to aggressively read more data
    // than we need to just to compare CRC for read operation. It can be done during recovery.
    if (header->total_size() <= initial_read_size) {
        uint32_t crc = crc32_ieee(init_crc32, ((uint8_t*)rbuf) + sizeof(log_group_header),
                                  header->total_size() - sizeof(log_group_header));
        HS_ASSERT_CMP(RELEASE, header->this_group_crc(), ==, crc, "CRC mismatch on read data");
    }

    serialized_log_record* rec = header->nth_record(key.idx - header->start_log_idx);
    uint32_t data_offset = (rec->offset + (rec->is_inlined ? 0 : header->oob_data_offset));

    log_buffer b(std::make_shared< sisl::byte_array >((size_t)rec->size));
    if ((data_offset + b.size()) < initial_read_size) {
        std::memcpy((void*)b.data(), (void*)(rbuf + data_offset), b.size()); // Already read them enough, copy the data
    } else {
        auto first_part_size = initial_read_size - data_offset;
        std::memcpy((void*)b.data(), (void*)(rbuf + data_offset), first_part_size);

        auto second_part_size = b.size() - first_part_size;
        if (second_part_size > initial_read_size) {
            rbuf = (uint8_t*)std::aligned_alloc(dma_boundary, sisl::round_up(second_part_size, dma_boundary));
        }
        store->read(key.dev_offset + data_offset + first_part_size, second_part_size, (void*)rbuf);
        std::memcpy((void*)(b.data() + first_part_size), (void*)rbuf, second_part_size);
        if (second_part_size > initial_read_size) { std::free(rbuf); }
    }

    return b;
}

#if 0
//
// calculate crc based on input buffers splitted in multiple buffers in MemVector;
//
uint32_t LogDev::get_crc_and_len(struct iovec* iov, int iovcnt, uint64_t& len) {
    uint32_t crc = init_crc32;
    len = 0;
    for (int i = 0; i < iovcnt; i++) {
        crc = crc32_ieee(crc, (unsigned char*)(iov[i].iov_base), iov[i].iov_len);
        len += iov[i].iov_len;
    }

    return crc;
}

//
//
// With group commit, the through put will be much better;
//
// Note:
// 1. This routine is supposed to be called by group commit, which is single threaded.
//    Hence no lock is needed.
//    If group commit design has changed to support Multi-threading, update this routine with lock protection;
// 2. mvec can take multiple data buffer, and crc will be calculated for all the buffers;
//
// TODO:
// 1. Avoid new and Memory should come from pre-allocated buffer when group-commit kicks in
//

bool LogDev::write_at_offset(const uint64_t offset, struct iovec* iov_i, int iovcnt_i, logdev_comp_callback cb) {

    m_comp_cb = cb;
    uint64_t len = 0;
    uint32_t crc = get_crc_and_len(iov_i, iovcnt_i, len);

    const int    iovcnt = iovcnt_i + 1; // add header slot
    struct iovec iov[iovcnt];

    LogDevRecordHeader* hdr = nullptr;
    int                 ret = posix_memalign((void**)&hdr, LOGDEV_BLKSIZE, LOGDEV_BLKSIZE);
    if (ret != 0) {
        throw std::bad_alloc();
    }

    std::memset((void*)hdr, 0, sizeof(LogDevRecordHeader));

    hdr->h.m_version = LOG_DEV_RECORD_HDR_VER;
    hdr->h.m_magic = LOG_DEV_RECORD_HDR_MAGIC;
    hdr->h.m_crc = crc;
    hdr->h.m_prev_crc = m_last_crc;
    hdr->h.m_len = len;

    iov[0].iov_base = (uint8_t*)hdr;
    iov[0].iov_len = LOGDEV_BLKSIZE;

    if (!copy_iov(&iov[1], iov_i, iovcnt_i)) {
        return false;
    }

    m_last_crc = hdr->h.m_crc;

    auto req = logdev_req::make_request();

    bool success = HomeBlks::instance()->get_logdev_blkstore()->write_at_offset(offset, iov, iovcnt, to_wb_req(req));

    free(hdr);
    return success;
}

bool LogDev::append_write(struct iovec* iov_i, int iovcnt_i, uint64_t& out_offset, logdev_comp_callback cb) {
    m_comp_cb = cb;
    uint64_t len = 0; 
    uint32_t crc = get_crc_and_len(iov_i, iovcnt_i, len);

    const int iovcnt = iovcnt_i + 1;  // add header slot
    struct iovec iov[iovcnt];

    LogDevRecordHeader *hdr = nullptr;
    int ret = posix_memalign((void**)&hdr, LOGDEV_BLKSIZE, LOGDEV_BLKSIZE);
    if (ret != 0 ) {
        throw std::bad_alloc();
    }

    std::memset((void*)hdr, 0, sizeof(LogDevRecordHeader));

    hdr->h.m_version = LOG_DEV_RECORD_HDR_VER;
    hdr->h.m_magic = LOG_DEV_RECORD_HDR_MAGIC;
    hdr->h.m_crc = crc;
    hdr->h.m_prev_crc = m_last_crc;
    hdr->h.m_len = len;

    iov[0].iov_base = (uint8_t*)hdr;
    iov[0].iov_len = LOGDEV_BLKSIZE;

    copy_iov(&iov[1], iov_i, iovcnt_i);
    
    m_last_crc = hdr->h.m_crc;

    auto req = logdev_req::make_request();

    bool success = HomeBlks::instance()->get_logdev_blkstore()->append_write(iov, iovcnt, out_offset, to_wb_req(req));

    free(hdr);
    return success;
}
//
// Reserve size of offset
//
uint64_t LogDev::reserve(const uint64_t size) { return HomeBlks::instance()->get_logdev_blkstore()->reserve(size); }

//
// truncate
//
void LogDev::truncate(const uint64_t offset) { HomeBlks::instance()->get_logdev_blkstore()->truncate(offset); }

ssize_t LogDev::readv(const uint64_t offset, struct iovec* iov_i, int iovcnt_i) {
    int          iovcnt = iovcnt_i + 1;
    struct iovec iov[iovcnt];

    LogDevRecordHeader* hdr = nullptr;
    int                 ret = posix_memalign((void**)&hdr, LOGDEV_BLKSIZE, LOGDEV_BLKSIZE);
    if (ret != 0) {
        throw std::bad_alloc();
    }
    std::memset((void*)hdr, 0, sizeof(LogDevRecordHeader));

    iov[0].iov_base = (uint8_t*)hdr;
    iov[0].iov_len = sizeof(LogDevRecordHeader);

    // copy pointers and length
    copy_iov(&iov[1], iov_i, iovcnt_i);

    HomeBlks::instance()->get_logdev_blkstore()->readv(offset, iov, iovcnt);

    if (!header_verify(hdr)) {
        HS_ASSERT(DEBUG, 0, "Log header corrupted!");
        return -1;
    }

    auto len = hdr->h.m_len;
    free(hdr);
    return len;
}

bool LogDev::copy_iov(struct iovec* dest, struct iovec* src, int iovcnt) {
    for (int i = 0; i < iovcnt; i++) {
        dest[i].iov_base = src[i].iov_base;
        dest[i].iov_len = src[i].iov_len;

#ifndef NDEBUG
        if (src[i].iov_len % LOGDEV_BLKSIZE) {
            HS_LOG(ERROR, logdev, "Invalid iov_len, must be {} aligned. ", LOGDEV_BLKSIZE);
            return false;
        }
#endif
    }
    return true;
}

bool LogDev::header_verify(LogDevRecordHeader* hdr) {
    // header version and crc verification
    if ((hdr->h.m_version != LOG_DEV_RECORD_HDR_VER) || (hdr->h.m_magic != LOG_DEV_RECORD_HDR_MAGIC)) {
        return false;
    }

    return true;
}

//
// read
//
ssize_t LogDev::read(const uint64_t offset, const uint64_t size, const void* buf) {
    HomeBlks::instance()->get_logdev_blkstore()->read(offset, size, buf);

    LogDevRecordHeader* hdr = (LogDevRecordHeader*)((unsigned char*)buf + sizeof(LogDevRecordHeader));

    if (!header_verify(hdr)) {
        HS_ASSERT(DEBUG, 0, "Log header corrupted!");
        return -1;
    }

    // skip header and caculate crc of the data buffer
    uint32_t crc = crc32_ieee(init_crc32, (unsigned char*)((char*)buf + sizeof(LogDevRecordHeader)), hdr->h.m_len);

    HS_ASSERT_CMP(DEBUG, hdr->h.m_len, ==, size, "Log size mismatch from input size: {} : {}", hdr->h.m_len, size);
    HS_ASSERT_CMP(DEBUG, hdr->h.m_crc, ==, crc, "Log header CRC mismatch: {} : {}", hdr->h.m_crc, crc);

    return hdr->h.m_len;
}
#endif

/*
 * This method prepares the log records to be flushed and returns the log_group which is fully prepared
 */
LogGroup* LogDev::prepare_flush(int32_t estimated_records) {
    int64_t flushing_upto_idx = 0u;

    assert(estimated_records > 0);
    auto lg = LogGroup::make_log_group((uint32_t)estimated_records);
    m_log_records.foreach_active(m_last_flush_idx + 1, [&](int64_t idx, int64_t upto_idx, log_record& record) -> bool {
        if (lg->add_record(record, idx)) {
            flushing_upto_idx = upto_idx;
            return true;
        } else {
            return false;
        }
    });
    lg->finish();
    lg->m_flush_log_idx_from = m_last_flush_idx + 1;
    lg->m_flush_log_idx_upto = flushing_upto_idx;
    lg->m_log_dev_offset = HomeBlks::instance()->get_logdev_blkstore()->reserve(lg->header()->group_size);

    LOGINFO("Flushing upto log_idx={}");
    LOGINFO("Log Group: {}", *lg);
    return lg;
}

// This method checks if in case we were to add a record of size provided, do we enter into a state which exceeds our
// threshold. If so, it first flushes whats accumulated so far and then add the pending flush size counter with the new
// record size
void LogDev::flush_if_needed(const uint32_t new_record_size, logid_t new_idx) {
    // If after adding the record size, if we have enough to flush, attempt to flush by setting the atomic bool
    // variable.
    auto pending_sz = m_pending_flush_size.fetch_add(new_record_size, std::memory_order_relaxed) + new_record_size;
    if (pending_sz >= flush_data_threshold_size) {
        LOGTRACE("Pending size {} if added with new_record_size {} will be {} greater than flush data threshold {}, "
                 "hence flushing now",
                 pending_sz, new_record_size, flush_data_threshold_size);

        bool expected_flushing = false;
        if (m_is_flushing.compare_exchange_strong(expected_flushing, true, std::memory_order_acq_rel)) {
            // We were able to win the flushing competition and now we gather all the flush data and reserve a slot.
            if (new_idx == -1) new_idx = m_log_idx.load(std::memory_order_relaxed);
            auto lg = prepare_flush(new_idx - m_last_flush_idx + 4); // Estimate 4 more extra in case of parallel writes
            m_pending_flush_size.fetch_sub(lg->actual_data_size(), std::memory_order_relaxed);
            LOGTRACE("Flush prepared, pending flush size is {}", m_pending_flush_size.load(std::memory_order_relaxed));
            do_flush(lg);
        } else {
            LOGTRACE("Back to back flushing, will let the current flush to finish and perform this flush");
        }
    }
}

void LogDev::do_flush(LogGroup* lg) {
    auto* store = HomeBlks::instance()->get_logdev_blkstore();
    // auto offset = store->reserve(lg->data_size() + sizeof(log_group_header));

    auto req = logdev_req::make_request();
    req->m_log_group = lg;
    store->write_at_offset(lg->m_log_dev_offset, lg->iovecs().data(), (int)lg->iovecs().size(), to_wb_req(req));
}

void LogDev::process_logdev_completions(const boost::intrusive_ptr< blkstore_req< BlkBuffer > >& bs_req) {
    auto req = to_logdev_req(bs_req);
    if (req->is_read) {
        // update logdev read metrics;
    } else {
        // update logdev write metrics;
        on_flush_completion(req->m_log_group);
    }
}

void LogDev::on_flush_completion(LogGroup* lg) {
    m_log_records.complete(lg->m_flush_log_idx_from, lg->m_flush_log_idx_upto);
    m_last_flush_idx = lg->m_flush_log_idx_upto;

    for (auto idx = lg->m_flush_log_idx_from; idx <= lg->m_flush_log_idx_upto; ++idx) {
        auto& record = m_log_records.at(idx);
        m_append_comp_cb(log_key{idx, lg->m_log_dev_offset}, record.context);
    }
#if 0
        if (upto_idx > (m_last_truncate_idx + LogDev::truncate_idx_frequency)) {
            std::cout << "Truncating upto log_idx = " << upto_idx << "\n";
            m_log_records.truncate();
        }
#endif
    m_last_crc = lg->header()->cur_grp_crc;
    m_is_flushing.store(false, std::memory_order_release);

    // Try to do chain flush if its really needed.
    flush_if_needed(0);
}
} // namespace homestore
