#include "engine/common/homestore_assert.hpp"
#include "log_dev.hpp"
#include "log_store.hpp"

namespace homestore {
SDS_LOGGING_DECL(logstore)

static constexpr logdev_key out_of_bound_ld_key = {std::numeric_limits< logid_t >::max(), 0};
REGISTER_METABLK_SUBSYSTEM(log_dev, "LOG_DEV", HomeLogStoreMgr::meta_blk_found_cb, nullptr)

#define THIS_LOGSTORE_LOG(level, msg, ...) HS_SUBMOD_LOG(level, logstore, , "store", m_store_id, msg, __VA_ARGS__)

void HomeLogStoreMgr::meta_blk_found_cb(meta_blk* mblk, sisl::byte_view buf, size_t size) {
    HomeLogStoreMgr::instance().m_log_dev.meta_blk_found(mblk, buf, size);
}

/////////////////////////////////////// HomeLogStoreMgr Section ///////////////////////////////////////
void HomeLogStoreMgr::start(bool format) {
    m_log_dev.register_store_found_cb(bind_this(HomeLogStoreMgr::__on_log_store_found, 2));
    m_log_dev.register_append_cb(bind_this(HomeLogStoreMgr::__on_io_completion, 5));
    m_log_dev.register_logfound_cb(bind_this(HomeLogStoreMgr::__on_logfound, 4));

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
                if (lstore && lstore->m_replay_done_cb) {
                    lstore->m_replay_done_cb(lstore, lstore->m_seq_num.load(std::memory_order_acquire) - 1);
                }
            }
        }
    });
}

void HomeLogStoreMgr::stop() {
    m_id_logstore_map.wlock()->clear();
    m_log_dev.stop();
}

std::shared_ptr< HomeLogStore > HomeLogStoreMgr::create_new_log_store(bool append_mode) {
    auto store_id = m_log_dev.reserve_store_id();
    std::shared_ptr< HomeLogStore > lstore;

    lstore = std::make_shared< HomeLogStore >(store_id, append_mode, 0);
    m_id_logstore_map.wlock()->insert(std::make_pair<>(store_id, logstore_info_t{lstore, nullptr, append_mode}));
    COUNTER_INCREMENT(m_metrics, logstores_count, 1);
    return lstore;
}

void HomeLogStoreMgr::open_log_store(logstore_id_t store_id, bool append_mode,
                                     const log_store_opened_cb_t& on_open_cb) {
    COUNTER_INCREMENT(m_metrics, logstores_count, 1);
    m_id_logstore_map.wlock()->insert(std::make_pair<>(store_id, logstore_info_t{nullptr, on_open_cb, append_mode}));
}

void HomeLogStoreMgr::remove_log_store(logstore_id_t store_id) {
    LOGINFO("Removing log store id {}", store_id);
    m_id_logstore_map.wlock()->erase(store_id);
    m_log_dev.unreserve_store_id(store_id);
    COUNTER_DECREMENT(m_metrics, logstores_count, 1);
}

void HomeLogStoreMgr::__on_log_store_found(logstore_id_t store_id, const logstore_meta& meta) {
    auto m = m_id_logstore_map.rlock();
    auto it = m->find(store_id);
    if (it == m->end()) {
        LOGERROR("Store Id {} found but not opened yet, ignoring the store", store_id);
        m_unopened_store_id.insert(store_id);
        return;
    }

    LOGINFO("Found a logstore store_id={} with start seq_num={}, Creating a new HomeLogStore instance", store_id,
            meta.m_first_seq_num);
    auto& l_info = const_cast< logstore_info_t& >(it->second);
    l_info.m_log_store = std::make_shared< HomeLogStore >(store_id, l_info.append_mode, meta.m_first_seq_num);
    if (l_info.m_on_log_store_opened) l_info.m_on_log_store_opened(l_info.m_log_store);
}

static thread_local std::vector< HomeLogStore* > _cur_flush_batch_stores;

void HomeLogStoreMgr::__on_io_completion(logstore_id_t id, logdev_key ld_key, logdev_key flush_ld_key,
                                         uint32_t nremaining_in_batch, void* ctx) {
    auto req = (logstore_req*)ctx;
    HomeLogStore* log_store = req->log_store;

    if (req->is_write) {
        auto it = m_last_flush_info.find(id);
        if ((it == m_last_flush_info.end()) || (it->second != flush_ld_key.idx)) {
            // first time completion in this batch for a given store_id
            m_last_flush_info.insert_or_assign(id, flush_ld_key.idx);
            _cur_flush_batch_stores.push_back(log_store);
        }

        HS_LOG_ASSERT_EQ(log_store->m_store_id, id, "Expecting store id in log store and io completion to match");
        log_store->on_write_completion(req, ld_key);

        if (nremaining_in_batch == 0) {
            // This batch is completed, call all log stores participated in this batch about the end of batch
            HS_LOG_ASSERT_GT(_cur_flush_batch_stores.size(), 0U, "Expecting one store to be flushed in batch");
            for (auto& l : _cur_flush_batch_stores) {
                l->on_batch_completion(flush_ld_key);
            }
            _cur_flush_batch_stores.clear();
        }
    } else {
        log_store->on_read_completion(req, ld_key);
    }
}

void HomeLogStoreMgr::__on_logfound(logstore_id_t id, logstore_seq_num_t seq_num, logdev_key ld_key, log_buffer buf) {
    auto it = m_id_logstore_map.rlock()->find(id);
    auto& log_store = it->second.m_log_store;
    log_store->on_log_found(seq_num, ld_key, buf);
}

void HomeLogStoreMgr::device_truncate(const device_truncate_cb_t& cb, bool wait_till_done, bool dry_run) {
    std::mutex _mtx;
    std::condition_variable _cv;
    bool trunc_done = false;

    bool locked_now = m_log_dev.try_lock_flush([this, cb, dry_run, wait_till_done, &_mtx, &_cv, &trunc_done]() {
        logdev_key trunc_upto = do_device_truncate(dry_run);
        if (cb) { cb(trunc_upto); }

        if (wait_till_done) {
            std::lock_guard< std::mutex > lk(_mtx);
            trunc_done = true;
            _cv.notify_one();
        }
    });
    if (locked_now) { m_log_dev.unlock_flush(); }

    if (wait_till_done) {
        std::unique_lock< std::mutex > lk(_mtx);
        _cv.wait(lk, [&] { return trunc_done; });
    }
}

logdev_key HomeLogStoreMgr::do_device_truncate(bool dry_run) {
    static thread_local std::vector< std::shared_ptr< HomeLogStore > > m_min_trunc_stores;
    static thread_local std::vector< std::shared_ptr< HomeLogStore > > m_non_participating_stores;

    m_min_trunc_stores.clear();
    m_non_participating_stores.clear();
    logdev_key min_safe_ld_key = out_of_bound_ld_key;

    m_id_logstore_map.withRLock([&](auto& id_logstore_map) {
        for (auto& id_logstore : id_logstore_map) {
            auto& store_ptr = id_logstore.second.m_log_store;
            const auto& trunc_info = store_ptr->pre_device_truncation();
            if (!trunc_info.pending_dev_truncation && !trunc_info.active_writes_not_part_of_truncation) {
                // This log store neither have any pending device truncation nor active logstore io going on for now.
                // Ignore this log store for min safe boundary calculation.
                LOGINFOMOD(logstore, "Logstore id={} is not participating in the current truncation",
                           store_ptr->get_store_id())
                m_non_participating_stores.push_back(store_ptr);
                continue;
            }

            if (trunc_info.ld_key.idx > min_safe_ld_key.idx) { continue; }

            if (trunc_info.ld_key.idx < min_safe_ld_key.idx) {
                // New minimum safe l entry
                min_safe_ld_key = trunc_info.ld_key;
                m_min_trunc_stores.clear();
            }
            m_min_trunc_stores.push_back(store_ptr);
        }
    });

    if (min_safe_ld_key == out_of_bound_ld_key) {
        LOGINFOMOD(logstore, "No log store append on any log stores, skipping device truncation");
        return min_safe_ld_key;
    } else {
        LOGINFOMOD(logstore, "Request to truncate the log device, safe log dev key to truncate = {}", min_safe_ld_key);
        // We call post device truncation only to the log stores whose prepared truncation points are fully truncated or
        // to stores which didn't particpate in this device truncation.
        for (auto& store_ptr : m_min_trunc_stores) {
            store_ptr->post_device_truncation(min_safe_ld_key);
        }
        for (auto& store_ptr : m_non_participating_stores) {
            store_ptr->post_device_truncation(min_safe_ld_key);
        }
        m_min_trunc_stores.clear(); // Not clearing here, would cause a shared_ptr ref holding.
        m_non_participating_stores.clear();
    }
    // Got the safest log id to truncate and actually truncate upto the safe log idx to the log device
    if (!dry_run && (min_safe_ld_key.idx >= 0)) m_log_dev.truncate(min_safe_ld_key);
    return min_safe_ld_key;
}

/////////////////////////////////////// HomeLogStore Section ///////////////////////////////////////
HomeLogStore::HomeLogStore(logstore_id_t id, bool append_mode, logstore_seq_num_t start_lsn) :
        m_store_id{id},
        m_records{"HomeLogStoreRecords", start_lsn - 1},
        m_append_mode{append_mode},
        m_seq_num{start_lsn} {
    m_truncation_barriers.reserve(10000);
    m_safe_truncation_boundary.seq_num.store(start_lsn - 1, std::memory_order_release);
}

void HomeLogStore::write_async(logstore_req* req, const log_req_comp_cb_t& cb) {
    HS_ASSERT(LOGMSG, ((cb != nullptr) || (m_comp_cb != nullptr)),
              "Expected either cb is not null or default cb registered");
    req->cb = cb;
    req->start_time = Clock::now();

#ifndef NDEBUG
    auto trunc_upto_lsn = truncated_upto();
    if (req->seq_num <= trunc_upto_lsn) {
        THIS_LOGSTORE_LOG(ERROR, "Assert: Appending lsn={} lesser than or equal to truncated_upto_lsn={}", req->seq_num,
                          trunc_upto_lsn);
        HS_DEBUG_ASSERT(0, "Assertion");
    }
#endif

    m_records.create(req->seq_num);
    COUNTER_INCREMENT(home_log_store_mgr.m_metrics, logstore_append_count, 1);
    HISTOGRAM_OBSERVE(home_log_store_mgr.m_metrics, logstore_record_size, req->data.size);
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
    HS_DEBUG_ASSERT_EQ(m_append_mode, true, "append_async can be called only on append only mode");
    auto seq_num = m_seq_num.fetch_add(1, std::memory_order_acq_rel);
    write_async(seq_num, b, cookie, cb);
    return seq_num;
}

log_buffer HomeLogStore::read_sync(logstore_seq_num_t seq_num) {
    auto record = m_records.at(seq_num);
    logdev_key ld_key = record.m_dev_key;
    if (ld_key.idx == -1) { return log_buffer(); }

    auto start_time = Clock::now();
    THIS_LOGSTORE_LOG(TRACE, "Reading lsn={}:{} mapped to logdev_key=[idx={} dev_offset={}]", seq_num, ld_key.idx,
                      ld_key.dev_offset);
    COUNTER_INCREMENT(home_log_store_mgr.m_metrics, logstore_read_count, 1);
    auto b = HomeLogStoreMgr::logdev().read(ld_key);
    HISTOGRAM_OBSERVE(home_log_store_mgr.m_metrics, logstore_read_latency, get_elapsed_time_us(start_time));
    return b;
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

void HomeLogStore::on_write_completion(logstore_req* req, logdev_key ld_key) {
    // Upon completion, create the mapping between seq_num and log dev key
    m_records.update(req->seq_num, [&](logstore_record& rec) -> bool {
        rec.m_dev_key = ld_key;
        THIS_LOGSTORE_LOG(DEBUG, "Completed write of lsn {} logdev_key={}", req->seq_num, ld_key);
        return true;
    });
    // assert(flush_ld_key.idx >= m_last_flush_ldkey.idx);

    // Update the maximum lsn we have seen for this batch for this store, it is needed to create truncation barrier
    m_flush_batch_max_lsn = std::max(m_flush_batch_max_lsn, req->seq_num);

    HISTOGRAM_OBSERVE(home_log_store_mgr.m_metrics, logstore_append_latency, get_elapsed_time_us(req->start_time));
    (req->cb) ? req->cb(req, ld_key) : m_comp_cb(req, ld_key);
}

void HomeLogStore::on_read_completion(logstore_req* req, logdev_key ld_key) {
    (req->cb) ? req->cb(req, ld_key) : m_comp_cb(req, ld_key);
}

void HomeLogStore::on_log_found(logstore_seq_num_t seq_num, logdev_key ld_key, log_buffer buf) {
    THIS_LOGSTORE_LOG(DEBUG, "Found a log lsn={} logdev_key={}", seq_num, ld_key);

    if (seq_num <= m_safe_truncation_boundary.seq_num.load(std::memory_order_acquire)) {
        THIS_LOGSTORE_LOG(TRACE, "Log lsn={} is already truncated on per device, ignoring", seq_num);
        return;
    }

    // Create the mapping between seq_num and log dev key
    m_records.create_and_complete(seq_num, ld_key);
    atomic_update_max(m_seq_num, seq_num + 1, std::memory_order_acq_rel);
    m_flush_batch_max_lsn = std::max(m_flush_batch_max_lsn, seq_num);

    if (m_found_cb != nullptr) m_found_cb(seq_num, buf, nullptr);
    on_batch_completion(ld_key); // Log replay will always be on non-batch mode, so call batch completion everytime.
}

void HomeLogStore::on_batch_completion(const logdev_key& flush_batch_ld_key) {
    assert(m_flush_batch_max_lsn != std::numeric_limits< logstore_seq_num_t >::min());

    // Create a new truncation barrier for this completion key
    if (m_truncation_barriers.size() && (m_truncation_barriers.back().seq_num >= m_flush_batch_max_lsn)) {
        m_truncation_barriers.back().ld_key = flush_batch_ld_key;
    } else {
        m_truncation_barriers.push_back({m_flush_batch_max_lsn, flush_batch_ld_key});
    }
    m_flush_batch_max_lsn = std::numeric_limits< logstore_seq_num_t >::min(); // Reset the flush batch for next batch.
}

void HomeLogStore::truncate(logstore_seq_num_t upto_seq_num, bool in_memory_truncate_only) {
#if 0
    if (!iomanager.is_io_thread()) {
        LOGDFATAL("Expected truncate to be called from iomanager thread. Ignoring truncate");
        return;
    }
#endif

#ifndef NDEBUG
    auto s = m_safe_truncation_boundary.seq_num.load(std::memory_order_acquire);
    // Don't check this if we don't know our truncation boundary. The call is made to inform us about
    // correct truncation point.
    if (s != -1) {
        HS_DEBUG_ASSERT_LE(upto_seq_num, get_contiguous_completed_seq_num(s),
                           "Logstore {} expects truncation to be contiguously completed", m_store_id);
    }
#endif

    // First try to block the flushing of logdevice and if we are successfully able to do, then
    auto shared_this = shared_from_this();
    bool locked_now = HomeLogStoreMgr::logdev().try_lock_flush([shared_this, upto_seq_num, in_memory_truncate_only]() {
        shared_this->do_truncate(upto_seq_num);
        if (!in_memory_truncate_only) home_log_store_mgr.do_device_truncate();
    });

    if (locked_now) { HomeLogStoreMgr::logdev().unlock_flush(); }
}

// NOTE: This method assumes the flush lock is already acquired by the caller
void HomeLogStore::do_truncate(logstore_seq_num_t upto_seq_num) {
    m_records.truncate(upto_seq_num);
    m_safe_truncation_boundary.seq_num.store(upto_seq_num, std::memory_order_release);

    // Need to update the superblock with meta, we don't persist yet, will be done as part of log dev truncation
    HomeLogStoreMgr::logdev().update_store_meta(m_store_id, logstore_meta{upto_seq_num + 1}, false /* persist_now */);

    int ind = search_max_le(upto_seq_num);
    if (ind < 0) {
        // m_safe_truncation_boundary.pending_dev_truncation = false;
        THIS_LOGSTORE_LOG(INFO,
                          "Truncate upto lsn={}, possibly already truncated so ignoring. Current safe device "
                          "truncation barrier=<log_id={}>",
                          upto_seq_num, m_safe_truncation_boundary.ld_key);
        return;
    }

    THIS_LOGSTORE_LOG(
        INFO, "Truncate upto lsn={}, nearest safe device truncation barrier <ind={} log_id={}>, is_last_barrier={}",
        upto_seq_num, ind, m_truncation_barriers[ind].ld_key, (ind == (int)m_truncation_barriers.size() - 1));

    m_safe_truncation_boundary.ld_key = m_truncation_barriers[ind].ld_key;
    m_safe_truncation_boundary.pending_dev_truncation = true;

    m_truncation_barriers.erase(m_truncation_barriers.begin(), m_truncation_barriers.begin() + ind + 1);
}

// NOTE: This method assumes the flush lock is already acquired by the caller
const truncation_info& HomeLogStore::pre_device_truncation() {
    m_safe_truncation_boundary.active_writes_not_part_of_truncation = (m_truncation_barriers.size() > 0);
    return m_safe_truncation_boundary;
}

// NOTE: This method assumes the flush lock is already acquired by the caller
void HomeLogStore::post_device_truncation(const logdev_key& trunc_upto_loc) {
    if (trunc_upto_loc.idx >= m_safe_truncation_boundary.ld_key.idx) {
        // This method is expected to be called always with this
        m_safe_truncation_boundary.pending_dev_truncation = false;
        m_safe_truncation_boundary.ld_key = trunc_upto_loc;
    } else {
        HS_RELEASE_ASSERT(0,
                          "We expect post_device_truncation to be called only for logstores which has min of all "
                          "truncation boundaries");
    }
}

void HomeLogStore::fill_gap(logstore_seq_num_t seq_num) {
    HS_DEBUG_ASSERT_EQ(m_records.status(seq_num).is_hole, true, "Attempted to fill gap lsn={} which has valid data",
                       seq_num);

    logdev_key empty_ld_key;
    m_records.create_and_complete(seq_num, empty_ld_key);
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

logstore_meta logstore_meta::default_value() { return logstore_meta{-1}; }
void logstore_meta::init(logstore_meta& meta) { meta.m_first_seq_num = 0; }
void logstore_meta::clear(logstore_meta& meta) { meta.m_first_seq_num = -1; }
bool logstore_meta::is_valid(const logstore_meta& meta) { return meta.m_first_seq_num >= 0; }

} // namespace homestore
