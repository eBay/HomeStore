#include "log_dev.hpp"
#include "log_store.hpp"

namespace homestore {
folly::Synchronized< std::map< logstore_id_t, std::shared_ptr< HomeLogStore > > > HomeLogStore::m_id_logstore_map;

void HomeLogStore::start(bool format) {
    auto ld = LogDev::instance();
    ld->register_store_found_cb(__on_log_store_found);
    ld->register_append_cb(__on_io_completion);
    ld->register_logfound_cb(__on_logfound);

    // Start the logdev
    ld->start(format);
}

std::shared_ptr< HomeLogStore > HomeLogStore::create_new_log_store() {
    auto store_id = LogDev::instance()->reserve_store_id(true /* persist */);
    auto lstore = std::make_shared< HomeLogStore >(store_id);
    m_id_logstore_map.wlock()->insert(std::make_pair<>(store_id, lstore));
    return lstore;
}

std::shared_ptr< HomeLogStore > HomeLogStore::open_log_store(logstore_id_t store_id) {
    auto m = m_id_logstore_map.rlock();
    auto it = m->find(store_id);
    if (it == m->end()) {
        LOGERROR("Store Id {} is not loaded yet, but asked to open, it may not have been created before", store_id);
        return nullptr;
    }
    return it->second;
}

void HomeLogStore::__on_log_store_found(logstore_id_t store_id) {
    auto lstore = std::make_shared< HomeLogStore >(store_id);
    m_id_logstore_map.wlock()->insert(std::make_pair<>(store_id, lstore));
}

void HomeLogStore::__on_io_completion(logstore_id_t id, logdev_key ld_key, void* ctx) {
    auto req = (logstore_req*)ctx;
    HomeLogStore* log_store = req->log_store;

    HS_ASSERT_CMP(LOGMSG, log_store->m_store_id, ==, id, "Expecting store id in log store and io completion to match");
    (req->is_write) ? log_store->on_write_completion(req, ld_key) : log_store->on_read_completion(req, ld_key);
}

void HomeLogStore::__on_logfound(logstore_id_t id, logstore_seq_num_t seq_num, logdev_key ld_key, log_buffer buf) {
    auto it = m_id_logstore_map.rlock()->find(id);
    auto& log_store = it->second;
    log_store->on_log_found(seq_num, ld_key, buf);
}

HomeLogStore::HomeLogStore(logstore_id_t id) : m_store_id(id) {}

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

void HomeLogStore::on_write_completion(logstore_req* req, const logdev_key& ld_key) {
    // Upon completion, create the mapping between seq_num and log dev key
    m_records.create_and_complete(req->seq_num, ld_key);
    (req->cb) ? req->cb(req, true) : m_comp_cb(req, true);
}

void HomeLogStore::on_read_completion(logstore_req* req, const logdev_key& ld_key) {
    (req->cb) ? req->cb(req, true) : m_comp_cb(req, true);
}

void HomeLogStore::on_log_found(logstore_seq_num_t seq_num, logdev_key ld_key, log_buffer buf) {
    // Upon completion, create the mapping between seq_num and log dev key
    m_records.create_and_complete(seq_num, ld_key);
    atomic_update_max(m_seq_num, seq_num + 1, std::memory_order_acq_rel);
    if (m_found_cb) m_found_cb(seq_num, buf, nullptr);
}
} // namespace homestore