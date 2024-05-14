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
#include <homestore/superblk_handler.hpp>

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
    bnodeid_t super_node{empty_bnodeid}; // Btree Root Node ID
    uint64_t super_link_version{0};
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

    static bool is_valid_btree_node(sisl::blob const& buf);
    static cp_id_t modified_cp_id(sisl::blob const& buf);
};

enum class index_buf_state_t : uint8_t {
    CLEAN,    // Buffer is clean
    DIRTY,    // Buffer is dirty and yet to start flush
    FLUSHING, // Buffer is current flushing
};

///////////////////////// Btree Node and Buffer Portion //////////////////////////

// IndexBuffer is for each CP. The dependent index buffers are chained using
// m_up_buffer and each buffer is flushed only its wait_for_leaders reaches 0
// which means all its dependent buffers are flushed.
struct IndexBuffer;
typedef std::shared_ptr< IndexBuffer > IndexBufferPtr;
struct IndexBuffer {
    BlkId m_blkid;                                                      // BlkId where this needs to be persisted
    cp_id_t m_dirtied_cp_id{-1};                                        // Last CP that dirtied this index buffer
    cp_id_t m_created_cp_id{-1};                                        // CP id when this buffer is created.
    std::atomic< index_buf_state_t > m_state{index_buf_state_t::CLEAN}; // Is buffer yet to persist?
    uint8_t m_is_meta_buf{false};                                       // Is the index buffer writing to metablk?
    uint8_t* m_bytes{nullptr};                                          // Actual data buffer

    std::weak_ptr< IndexBuffer > m_up_buffer;               // Parent buffer in the chain to persisted
    sisl::atomic_counter< int > m_wait_for_down_buffers{0}; // Number of children need to wait for before persisting
#ifndef NDEBUG
    // Down buffers are not mandatory members, but only to keep track of any bugs and asserts
    std::vector< std::weak_ptr< IndexBuffer > > m_down_buffers;
#endif

    IndexBuffer(BlkId blkid, uint32_t buf_size, uint32_t align_size);
    IndexBuffer(uint8_t* raw_bytes, BlkId blkid);
    ~IndexBuffer();

    BlkId blkid() const { return m_blkid; }
    uint8_t* raw_buffer() { return m_bytes; }
    bool is_clean() const { return (m_state.load() == index_buf_state_t::CLEAN); }
    index_buf_state_t state() const { return m_state.load(); }
    void set_state(index_buf_state_t st) { m_state.store(st); }
    void mark_meta_buf() { m_is_meta_buf = true; }

    std::string to_string() const {
        return fmt::format("IndexBuffer={} node_id={} state={} created_cp={} dirtied_cp={} up_buffer={} "
                           "down_wait_count={} node_buf={}",
                           voidptr_cast(const_cast< IndexBuffer* >(this)), m_blkid.to_integer(), int_cast(state()),
                           m_created_cp_id, m_dirtied_cp_id,
                           voidptr_cast(m_up_buffer.lock() ? m_up_buffer.lock().get() : nullptr),
                           m_wait_for_down_buffers.get(), voidptr_cast(m_bytes));
    }
};

// This is a special buffer which is used to write to the meta block
struct MetaIndexBuffer : public IndexBuffer {
    MetaIndexBuffer(superblk< index_table_sb >& sb);

private:
    superblk< index_table_sb >& m_sb;
};

class BtreeNode;
typedef boost::intrusive_ptr< BtreeNode > BtreeNodePtr;

struct IndexBtreeNode {
public:
    IndexBufferPtr m_idx_buf; // Buffer backing this node

public:
    IndexBtreeNode(const IndexBufferPtr& buf) : m_idx_buf{buf} {}
    ~IndexBtreeNode() { m_idx_buf.reset(); }
    uint8_t* raw_buffer() { return m_idx_buf->raw_buffer(); }
    static IndexBtreeNode* convert(BtreeNode* bt_node);
};

} // namespace homestore
