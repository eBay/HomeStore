#include "index/index_cp.hpp"
#include "index/wb_cache.hpp"

namespace homestore {
IndexCPCallbacks::IndexCPCallbacks(IndexWBCache* wb_cache) : m_wb_cache{wb_cache} {}

std::unique_ptr< CPContext > IndexCPCallbacks::on_switchover_cp(CP* cur_cp, CP* new_cp) override {
    return m_wb_cache->create_cp_context(new_cp->id());
}

void IndexCPCallbacks::cp_flush(CP* cp, cp_flush_done_cb_t&& done_cb) override {
    auto ctx = s_cast< TestCPContext* >(cp->context(cp_consumer_t::HS_CLIENT));
    ctx->validate(cp->id());
    done_cb(cp);
}

void IndexCPCallbacks::cp_cleanup(CP* cp) override {}

int IndexCPCallbacks::cp_progress_percent() override { return 100; }

} // namespace homestore