#pragma once
#include <homestore/checkpoint/cp.hpp>
#include <homestore/btree/detail/btree_internal.hpp>

namespace homestore {
class COWBtree;

struct COWBtreeNode {
public:
    // Is the buffer for the node is currently being flushed
    std::atomic< bool > m_is_buf_flushing{false};

    struct FlushInfo {
        BtreeNodePtr node;
        uint8_t* buf{nullptr};

        FlushInfo() = default;
        FlushInfo(BtreeNodePtr n, uint8_t* b) : node{std::move(n)}, buf{b} {}
        FlushInfo(FlushInfo const& other) = delete;
        FlushInfo& operator=(FlushInfo const& other) = delete;
        ~FlushInfo();

        FlushInfo(FlushInfo&& other) {
            node = std::move(other.node);
            buf = other.buf;
            other.buf = nullptr;
        }

        FlushInfo& operator=(FlushInfo&& other) {
            node = std::move(other.node);
            buf = other.buf;
            other.buf = nullptr;
            return *this;
        }
        uint8_t* bytes() { return buf; }
    };

    static COWBtreeNode* construct(BtreeNodePtr const& node);
    static void destruct(BtreeNode* node);
    static COWBtreeNode* convert(BtreeNodePtr const& node);
    static COWBtreeNode* convert(BtreeNode* node);

private:
    COWBtreeNode() = default;
    ~COWBtreeNode() = default;

public:
    FlushInfo prepare_flush_buf(COWBtree const& bt, BtreeNodePtr node, cp_id_t cur_cp_id);
    void release_buf(uint8_t* buf);
    BtreeNode* to_btree_node();
};

} // namespace homestore