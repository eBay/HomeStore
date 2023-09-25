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

    /// @brief Reallocate the buffer from writeback cache perspective. Typically buffer itself is not modified.
    /// @param buf Buffer to reallocate
    virtual void realloc_buf(const IndexBufferPtr& buf) = 0;

    /// @brief Write buffer
    /// @param buf
    /// @param context
    virtual void write_buf(const BtreeNodePtr& node, const IndexBufferPtr& buf, CPContext* context) = 0;

    virtual void read_buf(bnodeid_t id, BtreeNodePtr& node, node_initializer_t&& node_initializer) = 0;

    /// @brief Start a chain of related btree buffers. Typically a chain is creating from second and third pairs and
    /// then first is prepended to the chain. In case the second buffer is already with the WB cache, it will create a
    /// new buffer for both second and third.
    /// @param second Second btree buffer in the chain. It will be updated to copy of second buffer if buffer already
    /// has dependencies.
    /// @param third Thrid btree buffer in the chain. It will be updated to copy of third buffer if buffer already
    /// has dependencies.
    /// @return Returns if the buffer had to be copied
    virtual std::tuple< bool, bool > create_chain(IndexBufferPtr& second, IndexBufferPtr& third, CPContext* cp_ctx) = 0;

    /// @brief Prepend to the chain that was already created with second
    /// @param first
    /// @param second
    virtual void prepend_to_chain(const IndexBufferPtr& first, const IndexBufferPtr& second) = 0;

    /// @brief Free the buffer allocated and remove it from wb cache
    /// @param buf
    /// @param context
    virtual void free_buf(const IndexBufferPtr& buf, CPContext* context) = 0;

    /// @brief Copy buffer
    /// @param cur_buf
    /// @return
    virtual IndexBufferPtr copy_buffer(const IndexBufferPtr& cur_buf) const = 0;
};

} // namespace homestore
