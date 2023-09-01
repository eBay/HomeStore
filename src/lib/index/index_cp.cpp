#include "index/index_cp.hpp"
#include "index/wb_cache.hpp"

namespace homestore {
IndexCPCallbacks::IndexCPCallbacks(std::unique_ptr< IndexWBCache > wb_cache) { m_wb_cache = std::move(wb_cache); }

std::unique_ptr< CPContext > IndexCPCallbacks::on_switchover_cp(CP* cur_cp, CP* new_cp) {
    return m_wb_cache->create_cp_context(new_cp->id());
}

folly::Future< bool > IndexCPCallbacks::cp_flush(CP* cp) {
    auto ctx = s_cast< IndexCPContext* >(cp->context(cp_consumer_t::INDEX_SVC));
    return m_wb_cache->async_cp_flush(ctx);
}

void IndexCPCallbacks::cp_cleanup(CP* cp) {}

int IndexCPCallbacks::cp_progress_percent() { return 100; }

} // namespace homestore
