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
#include <vector>
#include <sisl/fds/thread_vector.hpp>
#include "blk.h"
#include "engine/common/homestore_header.hpp"

namespace homestore {
class HomeStoreBase;

typedef boost::intrusive_ptr< HomeStoreBase > HomeStoreBaseSafePtr;

using blkid_list_ptr = std::shared_ptr< sisl::ThreadVector< BlkId > >;
typedef std::function< void(uint64_t) > notify_size_freed_cb_t;

struct blkalloc_cp {
public:
    bool suspend{false};
    std::vector< blkid_list_ptr > free_blkid_list_vector;
    HomeStoreBaseSafePtr m_hs;
    notify_size_freed_cb_t m_notify_free;

public:
    blkalloc_cp();
    [[nodiscard]] bool is_suspend() const { return suspend; }
    void suspend_cp() { suspend = true; }
    void resume_cp() { suspend = false; }
    void free_blks(const blkid_list_ptr& list);
    void notify_size_on_done(notify_size_freed_cb_t cb) { m_notify_free = std::move(cb); }
    ~blkalloc_cp();
};
} // namespace homestore
