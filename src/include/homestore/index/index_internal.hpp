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
    uuid_t m_uuid; // UUID of the index

    // Btree Section
    bnodeid_t root_node{empty_bnodeid}; // Btree Root Node ID
    int64_t index_size{0};              // Size of the Index
    // seq_id_t last_seq_id{-1};           // TODO: See if this is needed
};
#pragma pack()

// An Empty base class to have the IndexService not having to template and refer the IndexTable virtual class
class IndexTableBase {
public:
    virtual ~IndexTableBase() = default;
    virtual uuid_t uuid() const = 0;
};

enum class index_buf_state_t : uint8_t {
    CLEAN,    // Buffer is clean
    DIRTY,    // Buffer is dirty and yet to start flush
    FLUSHING, // Buffer is current flushing
};

///////////////////////// Btree Node and Buffer Portion //////////////////////////
class IndexBuffer;
typedef std::shared_ptr< IndexBuffer > IndexBufferPtr;

class IndexBuffer {
private:
    uint8_t* m_node_buf{nullptr};                            // Actual buffer
    index_buf_state_t m_buf_state{index_buf_state_t::CLEAN}; // Is buffer yet to persist?
    BlkId m_blkid;                                           // BlkId where this needs to be persisted
    IndexBufferPtr m_next_buffer{nullptr};                   // Next buffer in the chain
    // Number of leader buffers we are waiting for before we write this buffer
    sisl::atomic_counter< int > m_wait_for_leaders{0};

public:
    IndexBuffer(BlkId blkid, uint32_t buf_size, uint32_t align_size);

    BlkId blkid() const { return m_blkid; }
    uint8_t* raw_buffer() { return m_node_buf; }

    bool is_clean() const { return (m_buf_state == index_buf_state_t::CLEAN); }
};

class BtreeNode;
typedef boost::intrusive_ptr< BtreeNode > BtreeNodePtr;

struct IndexBtreeNode {
public:
    IndexBufferPtr m_idx_buf;    // Buffer backing this node
    cp_id_t m_last_mod_cp_id{0}; // This node is previously modified by the cp id;

public:
    IndexBtreeNode(const IndexBufferPtr& buf) : m_idx_buf{buf} {}
    uint8_t* raw_buffer() { return m_idx_buf->raw_buffer(); }
    static IndexBtreeNode* convert(const BtreeNodePtr& bt_node);
};

} // namespace homestore