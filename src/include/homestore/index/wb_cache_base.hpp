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

#include <memory>
#include <boost/intrusive_ptr.hpp>
#include <sisl/utility/atomic_counter.hpp>
#include <homestore/blk.h>
#include <homestore/index/index_internal.hpp>

namespace homestore {

class BtreeNode;
using BtreeNodePtr = boost::intrusive_ptr< BtreeNode >;
typedef std::function< BtreeNodePtr(const IndexBufferPtr&) > node_initializer_t;

struct CPContext;

class IndexWBCacheBase {
public:
    virtual ~IndexWBCacheBase() = default;

    /// @brief Allocate the buffer and initialize the btree node. It adds the node to the wb cache.
    /// @tparam K Key type of the Index
    /// @param node_initializer Callback to be called upon which buffer is turned into btree node
    /// @return Node which was created by the node_initializer
    virtual BtreeNodePtr alloc_buf(node_initializer_t&& node_initializer) = 0;

    /// @brief Write buffer
    /// @param buf
    /// @param context
    virtual void write_buf(const BtreeNodePtr& node, const IndexBufferPtr& buf, CPContext* context) = 0;

    virtual void read_buf(bnodeid_t id, BtreeNodePtr& node, node_initializer_t&& node_initializer) = 0;

    virtual bool get_writable_buf(const BtreeNodePtr& node, CPContext* context) = 0;

    virtual void link_buf(IndexBufferPtr& up, IndexBufferPtr& down, CPContext* context) = 0;

    /// @brief Free the buffer allocated and remove it from wb cache
    /// @param buf
    /// @param context
    virtual void free_buf(const IndexBufferPtr& buf, CPContext* context) = 0;

    /// @brief Copy buffer
    /// @param cur_buf
    /// @return
    // virtual IndexBufferPtr copy_buffer(const IndexBufferPtr& cur_buf, const CPContext* context) const = 0;
};

} // namespace homestore
