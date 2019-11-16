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

    store->lseek(device_cursor);
    while (read_more) {
        // Read the data in bulk (of say 512K) and then process each log group header
        auto buf = std::make_shared< sisl::byte_array >(bulk_read_size, dma_boundary);
        auto rbuf = buf->bytes;
        ssize_t this_read_remains;

        uint64_t log_group_offset;
        do {
            log_group_offset = store->seeked_pos();
            this_read_remains = store->read((void*)rbuf, bulk_read_size);
            if (this_read_remains != 0) { break; }

            // We have come to the end of the device, seek to start and read the remaining
            store->lseek(0);
        } while (true);

        // Loop thru the entire bulk read buffer and process one log group at a time.
        while (this_read_remains > 0) {
            auto header = read_validate_header(rbuf, this_read_remains, &read_more);
            if (header == nullptr) {
                assert(read_more == false);
                break;
            }

            if (read_more) {
                // We have partial header, need to read more
                store->lseek(log_group_offset);
                break;
            }

            // Loop through each record within the log group and do a callback
            auto i = 0u;
            while (i < header->nrecords()) {
                auto* rec = header->nth_record(i);
                uint32_t data_offset = (rec->offset + (rec->is_inlined ? 0 : header->oob_data_offset));

                // Do a callback on the found log entry
                log_buffer b(buf, data_offset, rec->size);
                m_logfound_cb(log_key{header->start_idx() + i, log_group_offset}, b);
                ++i;
            }

            m_log_idx = header->start_idx() + i;
            log_group_offset += header->total_size();
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
    store->pread((void*)rbuf, initial_read_size, key.dev_offset);

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
        crc32_t crc = crc32_ieee(init_crc32, ((uint8_t*)rbuf) + sizeof(log_group_header),
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
        store->pread((void*)rbuf, second_part_size, key.dev_offset + data_offset + first_part_size);
        std::memcpy((void*)(b.data() + first_part_size), (void*)rbuf, second_part_size);
        if (second_part_size > initial_read_size) { std::free(rbuf); }
    }

    return b;
}

log_group_header* LogDev::read_validate_header(uint8_t* buf, uint32_t size, bool* read_more) {
    auto header = (log_group_header*)buf;
    if (header->magic_word() != LOG_GROUP_HDR_MAGIC) {
        auto store = HomeBlks::instance()->get_logdev_blkstore();
        auto cur_pos = store->seeked_pos();

        // We do not have the magic, its now to determine if it is indeed corruption in the data or we reached the end
        // of the cycle. The way to determine is keep reading all 512 block boundary and try to see if we see any valid
        // headers and whose log_idx > our idx
        std::shared_ptr< sisl::byte_array > safe_buf;
        while ((safe_buf = read_next_header(max_blks_read_for_additional_check)) != nullptr) {
            auto header = (log_group_header*)safe_buf.get();
            HS_ASSERT_CMP(RELEASE, m_log_idx.load(std::memory_order_acquire), >, header->start_idx(),
                          "Found a header with future log_idx after reaching end of log. Hence rbuf which was read "
                          "must have been corrupted");
        }

        store->lseek(cur_pos); // Seek it back since cursor would have moved whatever we have read
        *read_more = false;
        return nullptr;
    }

    // We don't have all the buffers for this group yet, try to read more later.
    if (header->total_size() > size) {
        *read_more = true;
        return header;
    }

    // Compute CRC of the data and validate
    crc32_t crc = crc32_ieee(init_crc32, ((uint8_t*)buf) + sizeof(log_group_header),
                             header->total_size() - sizeof(log_group_header));
    HS_ASSERT_CMP(RELEASE, header->this_group_crc(), ==, crc, "CRC mismatch on read data");

    // Validate previous CRC that we have seen
    if (m_last_crc != INVALID_CRC32_VALUE) {
        HS_ASSERT_CMP(RELEASE, header->prev_group_crc(), ==, m_last_crc,
                      "Prev CRC value does not match with whats in header");
    }

    m_last_crc = crc;
    *read_more = false;
    return header;
}

std::shared_ptr< sisl::byte_array > LogDev::read_next_header(uint32_t max_buf_reads) {
    uint32_t read_count = 0;

    auto store = HomeBlks::instance()->get_logdev_blkstore();
    while (read_count < max_buf_reads) {
        auto tmp_buf = std::make_shared< sisl::byte_array >(dma_boundary, dma_boundary);
        auto read_bytes = store->read((void*)tmp_buf.get(), dma_boundary);
        if (read_bytes == 0) {
            store->lseek(0);
            continue;
        }
        assert(read_bytes >= (ssize_t)sizeof(log_group_header));
        ++read_count;

        auto header = (log_group_header*)tmp_buf.get();
        if (header->magic_word() == LOG_GROUP_HDR_MAGIC) { return tmp_buf; }
    }
    return nullptr;
}

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
    lg->m_log_dev_offset = HomeBlks::instance()->get_logdev_blkstore()->alloc_blk(lg->header()->group_size);

    LOGINFO("Flushing upto log_idx={}");
    LOGINFO("Log Group: {}", *lg);
    return lg;
}

// This method checks if in case we were to add a record of size provided, do we enter into a state which exceeds
// our threshold. If so, it first flushes whats accumulated so far and then add the pending flush size counter with
// the new record size
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
    store->pwritev(lg->iovecs().data(), (int)lg->iovecs().size(), lg->m_log_dev_offset, to_wb_req(req));
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
