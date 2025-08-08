#include <sisl/utility/enum.hpp>
#include "index/index_cp.h"

namespace homestore {
IndexCPCallbacks::IndexCPCallbacks() : m_store_cp_callbacks{enum_count< IndexStore::Type >()} {}

std::unique_ptr< CPContext > IndexCPCallbacks::on_switchover_cp(CP* cur_cp, CP* new_cp) {
    std::vector< unique< CPContext > > store_contexts;
    store_contexts.reserve(enum_count< IndexStore::Type >());
    for (auto& cp_callbacks : m_store_cp_callbacks) {
        store_contexts.emplace_back(cp_callbacks ? std::move(cp_callbacks->on_switchover_cp(cur_cp, new_cp)) : nullptr);
    }
    return std::make_unique< IndexCPContext >(new_cp, std::move(store_contexts));
}

folly::Future< bool > IndexCPCallbacks::cp_flush(CP* cp) {
    std::vector< folly::Future< bool > > futs;
    for (auto& cp_callbacks : m_store_cp_callbacks) {
        if (cp_callbacks) { futs.emplace_back(cp_callbacks->cp_flush(cp)); }
    }

    return folly::collectAllUnsafe(futs).thenValue([](auto&& vf) {
        bool all_success = true;
        for (auto const& success : vf) {
            if (!success.value()) {
                all_success = false;
                break;
            }
        }
        return folly::makeFuture< bool >(std::move(all_success));
    });
}

void IndexCPCallbacks::cp_cleanup(CP* cp) {
    for (auto& cp_callbacks : m_store_cp_callbacks) {
        if (cp_callbacks) { cp_callbacks->cp_cleanup(cp); }
    }
}

int IndexCPCallbacks::cp_progress_percent() {
    uint32_t count = 0;
    uint32_t pct = 0;
    for (auto& cp_callbacks : m_store_cp_callbacks) {
        if (cp_callbacks) {
            pct += cp_callbacks->cp_progress_percent();
            ++count;
        }
    }
    return (count) ? pct / count : 100;
}

void IndexCPCallbacks::register_consumer(IndexStore::Type store_type, unique< CPCallbacks > store_cp_cbs) {
    // As soon as store cp callbacks is registered, we need to provide them the option to create new cp context
    if (store_cp_cbs) {
        auto cpg = cp_mgr().cp_guard();
        auto ctx = s_cast< IndexCPContext* >(cpg.context(cp_consumer_t::INDEX_SVC));
        ctx->m_store_contexts[(size_t)store_type] = std::move(store_cp_cbs->on_switchover_cp(nullptr, cpg.get()));
    }
    m_store_cp_callbacks[uint32_cast(store_type)] = std::move(store_cp_cbs);
}

/////////////////////// IndexCPContext section ///////////////////////////
IndexCPContext::IndexCPContext(CP* cp, std::vector< unique< CPContext > > store_ctxs) :
        CPContext(cp), m_store_contexts{std::move(store_ctxs)} {}

} // namespace homestore