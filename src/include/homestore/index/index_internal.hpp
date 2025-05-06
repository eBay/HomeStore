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
#include <homestore/btree/detail/btree_node.hpp>
#include <homestore/superblk_handler.hpp>

#pragma once
#ifdef StoreSpecificBtreeNode
#undef StoreSpecificBtreeNode
#endif

#define StoreSpecificBtreeNode homestore::IndexBtreeNode

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
    uint64_t root_link_version{0};      // Link version to btree root node
    int64_t index_size{0};              // Size of the Index
    // seq_id_t last_seq_id{-1};           // TODO: See if this is needed

    uint32_t ordinal{0}; // Ordinal of the Index

    uint32_t user_sb_size; // Size of the user superblk
    uint8_t user_sb_bytes[0];
};
#pragma pack()

struct IndexBuffer;
using IndexBufferPtr = std::shared_ptr< IndexBuffer >;
using IndexBufferPtrList = folly::small_vector< IndexBufferPtr, 3 >;

// An Empty base class to have the IndexService not having to template and refer the IndexTable virtual class
class IndexTableBase {
public:
    virtual ~IndexTableBase() = default;
    virtual uuid_t uuid() const = 0;
    virtual void recovery_completed() = 0;
    virtual uint32_t ordinal() const = 0;
    virtual uint64_t used_size() const = 0;
    virtual btree_status_t destroy() = 0;
    virtual void stop() = 0;
    virtual void repair_node(IndexBufferPtr const& buf) = 0;
    virtual void repair_root_node(IndexBufferPtr const& buf) = 0;
    virtual void delete_stale_children(IndexBufferPtr const& buf) = 0;
    virtual void audit_tree() = 0;
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
struct IndexBuffer : public sisl::ObjLifeCounter< IndexBuffer > {
    BlkId m_blkid;                                                      // BlkId where this needs to be persisted
    cp_id_t m_dirtied_cp_id{-1};                                        // Last CP that dirtied this index buffer
    cp_id_t m_created_cp_id{-1};                                        // CP id when this buffer is created.
    std::atomic< index_buf_state_t > m_state{index_buf_state_t::CLEAN}; // Is buffer yet to persist?
    uint8_t* m_bytes{nullptr};                                          // Actual data buffer
    uint32_t m_node_level{0};                                           // levels of the node in the btree

    std::shared_ptr< IndexBuffer > m_up_buffer;             // Parent buffer in the chain to persisted
    sisl::atomic_counter< int > m_wait_for_down_buffers{0}; // Number of children need to wait for before persisting
#ifndef NDEBUG
    // Down buffers are not mandatory members, but only to keep track of any bugs and asserts
    std::vector< std::weak_ptr< IndexBuffer > > m_down_buffers;
    std::mutex m_down_buffers_mtx;
    std::shared_ptr< IndexBuffer > m_prev_up_buffer; // Keep a copy for debugging
#endif

#ifdef _PRERELEASE
    bool m_crash_flag_on{false};
    void set_crash_flag() { m_crash_flag_on = true; }
#endif

    uint32_t m_index_ordinal{0};  // Ordinal of the index table this buffer belongs to, used only during recovery
    uint8_t m_is_meta_buf{false}; // Is the index buffer writing to metablk?
    bool m_node_freed{false};

    IndexBuffer(BlkId blkid, uint32_t buf_size, uint32_t align_size);
    IndexBuffer(uint8_t* raw_bytes, BlkId blkid);
    virtual ~IndexBuffer();

    BlkId blkid() const { return m_blkid; }
    uint8_t* raw_buffer() { return m_bytes; }
    bool is_clean() const { return (m_state.load() == index_buf_state_t::CLEAN); }
    index_buf_state_t state() const { return m_state.load(); }
    void set_state(index_buf_state_t st) { m_state.store(st); }
    bool is_meta_buf() const { return m_is_meta_buf; }

    std::string to_string() const;
    std::string to_string_dot() const;

    void add_down_buffer(const IndexBufferPtr& buf);

    void remove_down_buffer(const IndexBufferPtr& buf);
#ifndef NDEBUG
    bool is_in_down_buffers(const IndexBufferPtr& buf);
#endif
};

// This is a special buffer which is used to write to the meta block
struct MetaIndexBuffer : public IndexBuffer {
    MetaIndexBuffer(superblk< index_table_sb >& sb);
    MetaIndexBuffer(shared< MetaIndexBuffer > const& other);
    virtual ~MetaIndexBuffer();
    void copy_sb_to_buf();

    bool m_valid{true};
    superblk< index_table_sb >& m_sb;
};

struct IndexBtreeNode : public BtreeNode {
public:
    IndexBufferPtr m_idx_buf; // Buffer backing this node

public:
    template < typename... Args >
    IndexBtreeNode(Args&&... args) : BtreeNode(std::forward< Args >(args)...) {}
    virtual ~IndexBtreeNode() { m_idx_buf.reset(); }

    void attach_buf(IndexBufferPtr const& buf) { m_idx_buf = buf; }
    uint8_t* raw_buffer() { return m_idx_buf->raw_buffer(); }
};

} // namespace homestore
