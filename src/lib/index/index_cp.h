/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 *********************************************************************************/
#pragma once
#include <string>
#include <memory>
#include <vector>

#include <folly/futures/Future.h>
#include <homestore/checkpoint/cp_mgr.hpp>
#include <homestore/checkpoint/cp.hpp>
#include <homestore/homestore_decl.hpp>
#include <homestore/index/index_common.h>

namespace homestore {
class IndexCPCallbacks : public CPCallbacks {
public:
    IndexCPCallbacks();
    virtual ~IndexCPCallbacks() = default;

public:
    std::unique_ptr< CPContext > on_switchover_cp(CP* cur_cp, CP* new_cp) override;
    folly::Future< bool > cp_flush(CP* cp) override;
    void cp_cleanup(CP* cp) override;
    int cp_progress_percent() override;

    void register_consumer(IndexStore::Type store_type, unique< CPCallbacks > store_cp_cbs);

private:
    std::vector< unique< CPCallbacks > > m_store_cp_callbacks;
};

struct IndexCPContext : public CPContext {
public:
    std::vector< unique< CPContext > > m_store_contexts;

public:
    IndexCPContext(CP* cp, std::vector< unique< CPContext > > store_ctxs);
    ~IndexCPContext() = default;

    template < typename T >
    static T* convert(CPContext* ctx, IndexStore::Type store_type) {
        return r_cast< T* >((r_cast< IndexCPContext* >(ctx))->m_store_contexts[uint32_cast(store_type)].get());
    }

    template < typename T >
    static T* store_context(CP* cp, IndexStore::Type store_type) {
        return convert< T >(cp->context(cp_consumer_t::INDEX_SVC), store_type);
    }
};
} // namespace homestore
