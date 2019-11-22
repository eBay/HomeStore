#include "log_dev.hpp"
#include "log_store.hpp"

namespace homestore {
folly::Synchronized< std::map< logstore_id_t, std::shared_ptr< HomeLogStore > > >  HomeLogStore::m_id_logstore_map;

void HomeLogStore::start(bool format) {
    auto ld = LogDev::instance();
    ld->register_store_found_cb(on_log_store_found);
    ld->register_append_cb(on_append_completion);
    ld->register_logfound_cb(on_logfound);

    // Start the logdev
    ld->start(format);
}

std::shared_ptr< HomeLogStore > HomeLogStore::create_new_log_store() {
    auto store_id = LogDev::instance()->reserve_store_id(true /* persist */);
    auto lstore = std::make_shared< HomeLogStore >(store_id);
    m_id_logstore_map.wlock()->insert(std::make_pair<>(store_id, lstore));
    return lstore;
}

std::shared_ptr< HomeLogStore > HomeLogStore::open_log_store(logstore_id_t store_id) {
    auto it = m_id_logstore_map.rlock()->find(store_id);
    if (it == m_id_logstore_map.end()) {
        LOGERROR("Store Id {} is not loaded yet, but asked to open, it may not have been created before", store_id);
        return nullptr;
    }
    return it->second;
}

void HomeLogStore::on_log_store_found(logstore_id_t store_id) {
    auto lstore = std::make_shared< HomeLogStore >(store_id);
    m_id_logstore_map.wlock()->insert(std::make_pair<>(store_id, lstore));
}

void HomeLogStore::on_append_completion(logstore_id_t id, logdev_key ld_key, void* ctx) {}
void HomeLogStore::on_logfound(logstore_id_t id, logdev_key ld_key, log_buffer buf) {}

HomeLogStore::HomeLogStore(logstore_id_t id) : m_store_id(id) {}

} // namespace homestore