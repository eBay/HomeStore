#include "log_dev.hpp"
#include "log_store.hpp"

namespace homestore {

static constexpr logdev_key out_of_bound_ld_key = {std::numeric_limits< logid_t >::max(), 0};

/////////////////////////////////////// HomeLogStoreMgr Section ///////////////////////////////////////
void HomeLogStoreMgr::start(bool format) {
    auto ld = LogDev::instance();
    ld->register_store_found_cb(std::bind(&HomeLogStoreMgr::__on_log_store_found, this, std::placeholders::_1));
    ld->register_append_cb(std::bind(&HomeLogStoreMgr::__on_io_completion, this, std::placeholders::_1,
                                     std::placeholders::_2, std::placeholders::_3, std::placeholders::_4));
    ld->register_logfound_cb(std::bind(&HomeLogStoreMgr::__on_logfound, this, std::placeholders::_1,
                                       std::placeholders::_2, std::placeholders::_3, std::placeholders::_4));

    // Start the logdev
    ld->start(format);
}

std::shared_ptr< HomeLogStore > HomeLogStoreMgr::create_new_log_store() {
    auto store_id = LogDev::instance()->reserve_store_id(true /* persist */);
    auto lstore = std::make_shared< HomeLogStore >(store_id);
    m_id_logstore_map.wlock()->insert(std::make_pair<>(store_id, lstore));
    return lstore;
}

std::shared_ptr< HomeLogStore > HomeLogStoreMgr::open_log_store(logstore_id_t store_id) {
    auto m = m_id_logstore_map.rlock();
    auto it = m->find(store_id);
    if (it == m->end()) {
        LOGERROR("Store Id {} is not loaded yet, but asked to open, it may not have been created before", store_id);
        return nullptr;
    }
    return it->second;
}

void HomeLogStoreMgr::__on_log_store_found(logstore_id_t store_id) {
    auto lstore = std::make_shared< HomeLogStore >(store_id);
    m_id_logstore_map.wlock()->insert(std::make_pair<>(store_id, lstore));
}

void HomeLogStoreMgr::__on_io_completion(logstore_id_t id, logdev_key ld_key, logdev_key flush_ld_key, void* ctx) {
    auto req = (logstore_req*)ctx;
    HomeLogStore* log_store = req->log_store;

    HS_ASSERT_CMP(LOGMSG, log_store->m_store_id, ==, id, "Expecting store id in log store and io completion to match");
    (req->is_write) ? log_store->on_write_completion(req, ld_key, flush_ld_key)
                    : log_store->on_read_completion(req, ld_key);
}

void HomeLogStoreMgr::__on_logfound(logstore_id_t id, logstore_seq_num_t seq_num, logdev_key ld_key, log_buffer buf) {
    auto it = m_id_logstore_map.rlock()->find(id);
    auto& log_store = it->second;
    log_store->on_log_found(seq_num, ld_key, buf);
}

void HomeLogStoreMgr::dev_truncate() {
    logdev_key min_safe_ld_key = out_of_bound_ld_key;

    m_id_logstore_map.withRLock([&](auto& id_logstore_map) {
        for (auto& id_logstore : id_logstore_map) {
            auto& store_ptr = id_logstore.second;
            auto store_key = store_ptr->get_safe_truncation_log_dev_key();
            if (store_key.idx < min_safe_ld_key.idx) { min_safe_ld_key = store_key; }
        }
    });

    // Got the safest log id to trucate and actually truncate upto the safe log idx to the log device
    // LogDev::instance().truncate(min_safe_ld_key);
}

/////////////////////////////////////// HomeLogStore Section ///////////////////////////////////////
HomeLogStore::HomeLogStore(logstore_id_t id) : m_store_id(id) {
    m_truncation_barriers.reserve(10000);
    m_safe_truncate_ld_key = out_of_bound_ld_key;
}

void HomeLogStore::write_async(logstore_req* req, const log_req_comp_cb_t& cb) {
    HS_ASSERT(LOGMSG, ((cb != nullptr) || (m_comp_cb != nullptr)),
              "Expected either cb is not null or default cb registered");
    req->cb = cb;
    LogDev::instance()->append_async(m_store_id, req->seq_num, req->data.bytes, req->data.size, (void*)req);
}

void HomeLogStore::write_async(logstore_seq_num_t seq_num, const sisl::blob& b, void* cookie,
                               const log_write_comp_cb_t& cb) {
    // Form an internal request and issue the write
    auto* req = logstore_req::make(this, seq_num, b, true /* is_write_req */);
    write_async(req, [cb, cookie](logstore_req* req, bool status) {
        cb(req->seq_num, status, cookie);
        logstore_req::free(req);
    });
}

void HomeLogStore::append_async(const sisl::blob& b, void* cookie, const log_write_comp_cb_t& cb) {
    write_async(m_seq_num.fetch_add(1, std::memory_order_acq_rel), b, cookie, cb);
}

void HomeLogStore::on_write_completion(logstore_req* req, logdev_key ld_key, logdev_key flush_ld_key) {
    // Upon completion, create the mapping between seq_num and log dev key
    m_records.create_and_complete(req->seq_num, ld_key);
    assert(flush_ld_key.idx >= m_last_flush_ldkey.idx);

    if (flush_ld_key == m_last_flush_ldkey) {
        // We are still in the same flush idx, so keep updating the maximum sn's and its log_idx
        if (req->seq_num > m_flush_batch_max.seq_num) { m_flush_batch_max = {req->seq_num, flush_ld_key}; }
    } else {
        // We have a new flush sequence, create a truncation barrier on old flush batch and start the new batch
        create_truncation_barrier();
        m_flush_batch_max = {req->seq_num, flush_ld_key};
    }
    (req->cb) ? req->cb(req, true) : m_comp_cb(req, true);
}

void HomeLogStore::on_read_completion(logstore_req* req, logdev_key ld_key) {
    (req->cb) ? req->cb(req, true) : m_comp_cb(req, true);
}

void HomeLogStore::on_log_found(logstore_seq_num_t seq_num, logdev_key ld_key, log_buffer buf) {
    // Upon completion, create the mapping between seq_num and log dev key
    m_records.create_and_complete(seq_num, ld_key);
    atomic_update_max(m_seq_num, seq_num + 1, std::memory_order_acq_rel);
    if (m_found_cb) m_found_cb(seq_num, buf, nullptr);
}

void HomeLogStore::create_truncation_barrier() {
    if (m_truncation_barriers.size() && (m_truncation_barriers.back().seq_num >= m_flush_batch_max.seq_num)) {
        m_truncation_barriers.back().ld_key = m_flush_batch_max.ld_key;
    } else {
        m_truncation_barriers.push_back(m_flush_batch_max);
    }
}

void HomeLogStore::truncate(logstore_seq_num_t upto_seq_num, bool in_memory_truncate_only) {
    // First try to block the flushing of logdevice and if we are successfully able to do, then
    bool locked_now = LogDev::instance()->try_lock_flush([this, upto_seq_num, in_memory_truncate_only]() {
        do_truncate(upto_seq_num);
        if (!in_memory_truncate_only) home_log_store_mgr.dev_truncate();
    });

    if (locked_now) { LogDev::instance()->unlock_flush(); }
}

void HomeLogStore::do_truncate(logstore_seq_num_t upto_seq_num) {
    int ind = search_max_le(upto_seq_num);
    *m_safe_truncate_ld_key.wlock() = (ind < 0) ? out_of_bound_ld_key : m_truncation_barriers[ind].ld_key;
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

} // namespace homestore