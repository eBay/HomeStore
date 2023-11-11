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
#include <homestore/homestore_decl.hpp>
#include <homestore/btree/detail/btree_internal.hpp>

namespace homestore {

using bnodeid_t = uint64_t;
typedef int64_t cp_id_t;

static constexpr uint64_t indx_sb_magic{0xbedabb1e};
static constexpr uint32_t indx_sb_version{0x2};

#pragma pack(1)
struct index_table_sb {
    uint64_t magic{indx_sb_magic};
    uint32_t version{indx_sb_version};
    uuid_t uuid;        // UUID of the index
    uuid_t parent_uuid; // UUID of the parent container of index (controlled by user)

    // Btree Section
    bnodeid_t root_node{empty_bnodeid}; // Btree Root Node ID
    uint64_t link_version{0};
    int64_t index_size{0}; // Size of the Index
    // seq_id_t last_seq_id{-1};           // TODO: See if this is needed

    uint32_t user_sb_size; // Size of the user superblk
    uint8_t user_sb_bytes[0];
};
#pragma pack()

// An Empty base class to have the IndexService not having to template and refer the IndexTable virtual class
class IndexTableBase {
public:
    virtual ~IndexTableBase() = default;
    virtual uuid_t uuid() const = 0;
    virtual uint64_t used_size() const = 0;
    virtual void destroy() = 0;
};

enum class index_buf_state_t : uint8_t {
    CLEAN,    // Buffer is clean
    DIRTY,    // Buffer is dirty and yet to start flush
    FLUSHING, // Buffer is current flushing
};

///////////////////////// Btree Node and Buffer Portion //////////////////////////


// Multiple IndexBuffer could point to the same NodeBuffer if its clean.
struct NodeBuffer;
typedef std::shared_ptr< NodeBuffer > NodeBufferPtr;
struct NodeBuffer {
    uint8_t* m_bytes{nullptr};                                          // Actual data buffer
    std::atomic< index_buf_state_t > m_state{index_buf_state_t::CLEAN}; // Is buffer yet to persist?
    NodeBuffer(uint32_t buf_size, uint32_t align_size);
    ~NodeBuffer();
};

// IndexBuffer is for each CP. The dependent index buffers are chained using
// m_next_buffer and each buffer is flushed only its wait_for_leaders reaches 0
// which means all its dependent buffers are flushed.
struct IndexBuffer;
typedef std::shared_ptr< IndexBuffer > IndexBufferPtr;
struct IndexBuffer {
    NodeBufferPtr m_node_buf;
    BlkId m_blkid;                              // BlkId where this needs to be persisted
    std::weak_ptr< IndexBuffer > m_next_buffer; // Next buffer in the chain
    // Number of leader buffers we are waiting for before we write this buffer
    sisl::atomic_counter< int > m_wait_for_leaders{0};

    IndexBuffer(BlkId blkid, uint32_t buf_size, uint32_t align_size);
    IndexBuffer(NodeBufferPtr node_buf, BlkId blkid);
    ~IndexBuffer();

    BlkId blkid() const { return m_blkid; }
    uint8_t* raw_buffer() {
        RELEASE_ASSERT(m_node_buf, "Node buffer null blkid {}", m_blkid.to_integer());
        return m_node_buf->m_bytes;
    }

    bool is_clean() const {
        RELEASE_ASSERT(m_node_buf, "Node buffer null blkid {}", m_blkid.to_integer());
        return (m_node_buf->m_state.load() == index_buf_state_t::CLEAN);
    }

    index_buf_state_t state() const {
        RELEASE_ASSERT(m_node_buf, "Node buffer null blkid {}", m_blkid.to_integer());
        return m_node_buf->m_state;
    }

    void set_state(index_buf_state_t state) {
        RELEASE_ASSERT(m_node_buf, "Node buffer null blkid {}", m_blkid.to_integer());
        m_node_buf->m_state = state;
    }

    std::string to_string() const {
        auto str = fmt::format("IndexBuffer {} blkid={}", reinterpret_cast< void* >(const_cast< IndexBuffer* >(this)),
                               m_blkid.to_integer());
        if (m_node_buf == nullptr) {
            fmt::format_to(std::back_inserter(str), " node_buf=nullptr");
        } else {
            fmt::format_to(std::back_inserter(str), " state={} node_buf={}",
                           static_cast< int >(m_node_buf->m_state.load()), static_cast< void* >(m_node_buf->m_bytes));
        }
        fmt::format_to(std::back_inserter(str), " next_buffer={} wait_for={}",
                       m_next_buffer.lock() ? reinterpret_cast< void* >(m_next_buffer.lock().get()) : 0,
                       m_wait_for_leaders.get());
        return str;
    }
};

class BtreeNode;
typedef boost::intrusive_ptr< BtreeNode > BtreeNodePtr;

struct IndexBtreeNode {
public:
    IndexBufferPtr m_idx_buf;     // Buffer backing this node
    cp_id_t m_last_mod_cp_id{-1}; // This node is previously modified by the cp id;

public:
    IndexBtreeNode(const IndexBufferPtr& buf) : m_idx_buf{buf} {}
    ~IndexBtreeNode() { m_idx_buf.reset(); }
    uint8_t* raw_buffer() { return m_idx_buf->raw_buffer(); }
    static IndexBtreeNode* convert(BtreeNode* bt_node);
};

} // namespace homestore
