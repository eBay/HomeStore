#include "log_dev.hpp"
#include "log_store.hpp"

namespace homestore {

static constexpr logdev_key out_of_bound_ld_key = {std::numeric_limits< logid_t >::max(), 0};
REGISTER_METABLK_SUBSYSTEM(log_dev, "LOG_DEV", HomeLogStoreMgr::meta_blk_found_cb, nullptr)

void HomeLogStoreMgr::meta_blk_found_cb(meta_blk* mblk, sisl::byte_view buf, size_t size) {
    HomeLogStoreMgr::instance().m_log_dev.meta_blk_found(mblk, buf, size);
}

/////////////////////////////////////// HomeLogStoreMgr Section ///////////////////////////////////////
void HomeLogStoreMgr::start(bool format) {
    m_log_dev.register_store_found_cb(std::bind(&HomeLogStoreMgr::__on_log_store_found, this, std::placeholders::_1));
    m_log_dev.register_append_cb(std::bind(&HomeLogStoreMgr::__on_io_completion, this, std::placeholders::_1,
                                           std::placeholders::_2, std::placeholders::_3, std::placeholders::_4,
                                           std::placeholders::_5));
    m_log_dev.register_logfound_cb(std::bind(&HomeLogStoreMgr::__on_logfound, this, std::placeholders::_1,
                                             std::placeholders::_2, std::placeholders::_3, std::placeholders::_4));

    // Start the logdev
    m_log_dev.start(format);

    // If there are any unopened storeids found, loop and check again if they are indeed open later. Unopened log store
    // could be possible if the ids are deleted, but it is delayed to remove from store id reserver. In that case,
    // do the remove from store id reserver now.
    // TODO: At present we are assuming all unopened store ids could be removed. In future have a callback to this
    // start routine, which takes the list of unopened store ids and can return a new set, which can be removed.
    m_id_logstore_map.withWLock([&](auto& m) {
        for (auto it = m_unopened_store_id.begin(); it != m_unopened_store_id.end();) {
            if (m.find(*it) == m.end()) {
                // Not opened even on second time check, simply unreserve id
                m_log_dev.unreserve_store_id(*it);
            }
            it = m_unopened_store_id.erase(it);
        }

        // Also call the logstore to inform that start/replay is completed.
        if (!format) {
            for (auto& p : m) {
                auto& lstore = p.second.m_log_store;
                if (lstore && lstore->m_replay_done_cb) { lstore->m_replay_done_cb(lstore); }
            }
        }
    });
}

void HomeLogStoreMgr::stop() {
    m_id_logstore_map.wlock()->clear();
    m_log_dev.stop();
}

std::shared_ptr< HomeLogStore > HomeLogStoreMgr::create_new_log_store() {
    auto store_id = m_log_dev.reserve_store_id(true /* persist */);
    auto lstore = std::make_shared< HomeLogStore >(store_id);
    m_id_logstore_map.wlock()->insert(std::make_pair<>(store_id, logstore_info_t{lstore, nullptr}));
    return lstore;
}

void HomeLogStoreMgr::open_log_store(logstore_id_t store_id, const log_store_opened_cb_t& on_open_cb) {
    m_id_logstore_map.wlock()->insert(std::make_pair<>(store_id, logstore_info_t{nullptr, on_open_cb}));
}

void HomeLogStoreMgr::remove_log_store(logstore_id_t store_id) {
    LOGINFO("Removing log store id {}", store_id);
    m_id_logstore_map.wlock()->erase(store_id);
    m_log_dev.unreserve_store_id(store_id);
}

#if 0
std::shared_ptr< HomeLogStore > HomeLogStoreMgr::open_log_store(logstore_id_t store_id) {
    auto m = m_id_logstore_map.rlock();
    auto it = m->find(store_id);
    if (it == m->end()) {
        LOGERROR("Store Id {} is not loaded yet, but asked to open, it may not have been created before", store_id);
        return nullptr;
    }
    return it->second;
}
#endif

void HomeLogStoreMgr::__on_log_store_found(logstore_id_t store_id) {
    auto m = m_id_logstore_map.rlock();
    auto it = m->find(store_id);
    if (it == m->end()) {
        LOGERROR("Store Id {} found but not opened yet, ignoring the store", store_id);
        m_unopened_store_id.insert(store_id);
        return;
    }

    LOGINFO("Found a logstore store_id={}, Creating a new HomeLogStore instance", store_id);
    auto& l_info = const_cast< logstore_info_t& >(it->second);
    l_info.m_log_store = std::make_shared< HomeLogStore >(store_id);
    if (l_info.m_on_log_store_opened) l_info.m_on_log_store_opened(l_info.m_log_store);
}

void HomeLogStoreMgr::__on_io_completion(logstore_id_t id, logdev_key ld_key, logdev_key flush_ld_key,
                                         uint32_t nremaining_in_batch, void* ctx) {
    auto req = (logstore_req*)ctx;
    HomeLogStore* log_store = req->log_store;

    HS_ASSERT_CMP(LOGMSG, log_store->m_store_id, ==, id, "Expecting store id in log store and io completion to match");
    (req->is_write) ? log_store->on_write_completion(req, ld_key, flush_ld_key, nremaining_in_batch)
                    : log_store->on_read_completion(req, ld_key);
}

void HomeLogStoreMgr::__on_logfound(logstore_id_t id, logstore_seq_num_t seq_num, logdev_key ld_key, log_buffer buf) {
    auto it = m_id_logstore_map.rlock()->find(id);
    auto& log_store = it->second.m_log_store;
    log_store->on_log_found(seq_num, ld_key, buf);
}

logdev_key HomeLogStoreMgr::device_truncate(bool dry_run) {
    logdev_key min_safe_ld_key = out_of_bound_ld_key;

    m_id_logstore_map.withRLock([&](auto& id_logstore_map) {
        for (auto& id_logstore : id_logstore_map) {
            auto& store_ptr = id_logstore.second.m_log_store;
            auto store_key = store_ptr->get_safe_truncation_log_dev_key();
            if (store_key.idx < min_safe_ld_key.idx) { min_safe_ld_key = store_key; }
        }
    });
    LOGINFO("Request to truncate the log device, safe log dev key to truncate = {}", min_safe_ld_key);

    if (min_safe_ld_key == out_of_bound_ld_key) {
        /* XXX: not sure if this check should be here or in device truncate */
        return min_safe_ld_key;
    }
    // Got the safest log id to truncate and actually truncate upto the safe log idx to the log device
    if (!dry_run && (min_safe_ld_key.idx >= 0)) m_log_dev.truncate(min_safe_ld_key);
    return min_safe_ld_key;
}

/////////////////////////////////////// HomeLogStore Section ///////////////////////////////////////
HomeLogStore::HomeLogStore(logstore_id_t id) : m_store_id(id) {
    m_truncation_barriers.reserve(10000);
    m_safe_truncate_ld_key = {-1, 0};
}

void HomeLogStore::write_async(logstore_req* req, const log_req_comp_cb_t& cb) {
    HS_ASSERT(LOGMSG, ((cb != nullptr) || (m_comp_cb != nullptr)),
              "Expected either cb is not null or default cb registered");
    req->cb = cb;
    m_records.create(req->seq_num);
    HomeLogStoreMgr::logdev().append_async(m_store_id, req->seq_num, req->data.bytes, req->data.size, (void*)req);
}

void HomeLogStore::write_async(logstore_seq_num_t seq_num, const sisl::io_blob& b, void* cookie,
                               const log_write_comp_cb_t& cb) {
    // Form an internal request and issue the write
    auto* req = logstore_req::make(this, seq_num, b, true /* is_write_req */);
    req->cookie = cookie;
    write_async(req, [cb](logstore_req* req, logdev_key written_lkey) {
        cb(req->seq_num, req->data, written_lkey, req->cookie);
        logstore_req::free(req);
    });
}

int64_t HomeLogStore::append_async(const sisl::io_blob& b, void* cookie, const log_write_comp_cb_t& cb) {
    auto seq_num = m_seq_num.fetch_add(1, std::memory_order_acq_rel);
    write_async(seq_num, b, cookie, cb);
    return seq_num;
}

log_buffer HomeLogStore::read_sync(logstore_seq_num_t seq_num) {
    auto record = m_records.at(seq_num);
    logdev_key ld_key = record.m_dev_key;

    LOGTRACE("Reading store/lsn={}:{} mapped to logdev_key=[idx={} dev_offset={}]", m_store_id, seq_num, ld_key.idx,
             ld_key.dev_offset);
    return HomeLogStoreMgr::logdev().read(ld_key);
}
#if 0
void HomeLogStore::read_async(logstore_req* req, const log_found_cb_t& cb) {
    HS_ASSERT(LOGMSG, ((cb != nullptr) || (m_comp_cb != nullptr)),
              "Expected either cb is not null or default cb registered");
    auto record = m_records.at(req->seq_num);
    logdev_key ld_key = record.m_dev_key;
    req->cb = cb;
    HomeLogStoreMgr::logdev().read_async(ld_key, (void*)req);
}

void HomeLogStore::read_async(logstore_seq_num_t seq_num, void* cookie, const log_found_cb_t& cb) {
    auto record = m_records.at(seq_num);
    logdev_key ld_key = record.m_dev_key;
    sisl::io_blob b;
    auto* req = logstore_req::make(this, seq_num, &b, false /* not write */);
    read_async(req, [cookie, cb](logstore_seq_num_t seq_num, log_buffer log_buf, void* cookie) {
            cb(seq, log_buf, cookie);
            logstore_req::free(req);
            });
}
#endif

void HomeLogStore::on_write_completion(logstore_req* req, logdev_key ld_key, logdev_key flush_ld_key,
                                       uint32_t nremaining_in_batch) {
    // Upon completion, create the mapping between seq_num and log dev key
    m_records.update(req->seq_num, [&](logstore_record& rec) -> bool {
        rec.m_dev_key = ld_key;
        LOGDEBUG("Completed write of lsn {}:{} logdev_key={}", m_store_id, req->seq_num, ld_key);
        return true;
    });
    // assert(flush_ld_key.idx >= m_last_flush_ldkey.idx);

    update_truncation_barrier(req->seq_num, ld_key, nremaining_in_batch);
    (req->cb) ? req->cb(req, ld_key) : m_comp_cb(req, ld_key);
}

void HomeLogStore::on_read_completion(logstore_req* req, logdev_key ld_key) {
    (req->cb) ? req->cb(req, ld_key) : m_comp_cb(req, ld_key);
}

void HomeLogStore::on_log_found(logstore_seq_num_t seq_num, logdev_key ld_key, log_buffer buf) {
    // Upon completion, create the mapping between seq_num and log dev key
    m_records.create_and_complete(seq_num, ld_key);
    atomic_update_max(m_seq_num, seq_num + 1, std::memory_order_acq_rel);
    atomic_update_min(m_last_truncated_seq_num, seq_num - 1, std::memory_order_acq_rel);

    update_truncation_barrier(seq_num, ld_key, 0 /* nremaining_in_batch */);
    if (m_found_cb != nullptr) m_found_cb(seq_num, buf, nullptr);
}

void HomeLogStore::update_truncation_barrier(logstore_seq_num_t seq_num, logdev_key flush_ld_key,
                                             uint32_t nremaining_in_batch) {
    if (seq_num > m_flush_batch_max.seq_num) { m_flush_batch_max = {seq_num, flush_ld_key}; }

    if (nremaining_in_batch == 0) {
        // We are the last in batch, create a truncation barrier
        assert(m_flush_batch_max.seq_num != -1);
        create_truncation_barrier();
        m_flush_batch_max = {-1, {-1, 0}}; // Reset the flush batch for next batch.
    }
}

void HomeLogStore::create_truncation_barrier() {
    if (m_truncation_barriers.size() && (m_truncation_barriers.back().seq_num >= m_flush_batch_max.seq_num)) {
        m_truncation_barriers.back().ld_key = m_flush_batch_max.ld_key;
    } else {
        m_truncation_barriers.push_back(m_flush_batch_max);
    }
}

void HomeLogStore::truncate(logstore_seq_num_t upto_seq_num, bool in_memory_truncate_only) {
#if 0
    if (!iomanager.is_io_thread()) {
        LOGDFATAL("Expected truncate to be called from iomanager thread. Ignoring truncate");
        return;
    }
#endif

    // First try to block the flushing of logdevice and if we are successfully able to do, then
    auto shared_this = shared_from_this();
    bool locked_now = HomeLogStoreMgr::logdev().try_lock_flush([shared_this, upto_seq_num, in_memory_truncate_only]() {
        shared_this->do_truncate(upto_seq_num);
        if (!in_memory_truncate_only) home_log_store_mgr.device_truncate();
    });

    if (locked_now) { HomeLogStoreMgr::logdev().unlock_flush(); }
}

void HomeLogStore::do_truncate(logstore_seq_num_t upto_seq_num) {
    int ind = search_max_le(upto_seq_num);
    if (ind < 0) {
        LOGINFO("Truncate req for lsn={}:{}, possibly already truncated, ignoring", m_store_id, upto_seq_num);
        return;
    }

    *m_safe_truncate_ld_key.wlock() = m_truncation_barriers[ind].ld_key;
    LOGINFO("Truncate req for lsn={}:{}, truncating upto the nearest safe truncate barrier <ind={} lsn={} log_id={}>, ",
            m_store_id, upto_seq_num, ind, m_truncation_barriers[ind].seq_num, *m_safe_truncate_ld_key.rlock());

    m_last_truncated_seq_num.store(m_truncation_barriers[ind].seq_num, std::memory_order_release);
    m_records.truncate(m_truncation_barriers[ind].seq_num);
    m_truncation_barriers.erase(m_truncation_barriers.begin(), m_truncation_barriers.begin() + ind + 1);
}

int HomeLogStore::search_max_le(logstore_seq_num_t input_sn) {
    int mid = 0;
    int start = -1;
    int end = m_truncation_barriers.size();

    while ((end - start) > 1) {
        mid = start + (end - start) / 2;
        auto& mid_entry = m_truncation_barriers[mid];

        if (mid_entry.seq_num == input_sn) {
            return mid;
        } else if (mid_entry.seq_num > input_sn) {
            end = mid;
        } else {
            start = mid;
        }
    }

    return (end - 1);
}

void HomeLogStore::foreach (int64_t start_idx, const std::function< bool(logstore_seq_num_t, log_buffer) >& cb) {
    m_records.foreach_completed(0, [&](long int cur_idx, long int max_idx, homestore::logstore_record& record) -> bool {
        // do a sync read
        auto log_buf = HomeLogStoreMgr::logdev().read(record.m_dev_key);
        return cb(cur_idx, log_buf);
    });
}

logstore_seq_num_t HomeLogStore::get_contiguous_issued_seq_num(logstore_seq_num_t from) {
    return (logstore_seq_num_t)m_records.active_upto(from + 1);
}

logstore_seq_num_t HomeLogStore::get_contiguous_completed_seq_num(logstore_seq_num_t from) {
    return (logstore_seq_num_t)m_records.completed_upto(from + 1);
}
} // namespace homestore
