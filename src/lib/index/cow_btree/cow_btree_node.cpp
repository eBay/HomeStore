#include <homestore/btree/detail/btree_node.hpp>
#include "index/cow_btree/cow_btree_cp.h"
#include "index/cow_btree/cow_btree_node.h"
#include "index/cow_btree/cow_btree.h"
#include "common/homestore_utils.hpp"
#include "common/homestore_assert.hpp"

namespace homestore {
BtreeNode* COWBtreeNode::to_btree_node() { return r_cast< BtreeNode* >(uintptr_cast(this) + sizeof(COWBtreeNode)); }

COWBtreeNode* COWBtreeNode::construct(BtreeNodePtr const& node) {
    return new (uintptr_cast(node.get()) - sizeof(COWBtreeNode)) COWBtreeNode();
}

void COWBtreeNode::destruct(BtreeNode* node) {
    HS_DBG_ASSERT_EQ(COWBtreeNode::convert(node)->m_is_buf_flushing.load(), false,
                     "A destructing node shouldn't be flushing the buffer with cp, but here it is shared.",
                     fmt::ptr(node->get_phys_node_buf()));

    // Release the node buffer
    hs_utils::iobuf_free(node->get_phys_node_buf(), sisl::buftag::btree_node);

    // Release the entire BtreeNode covering structure
    uint8_t* ptr = uintptr_cast(node) - sizeof(COWBtreeNode);
    r_cast< COWBtreeNode* >(ptr)->~COWBtreeNode();
    delete[] ptr;
}

COWBtreeNode* COWBtreeNode::convert(BtreeNodePtr const& n) {
    return r_cast< COWBtreeNode* >(uintptr_cast(n.get()) - sizeof(COWBtreeNode));
}

COWBtreeNode* COWBtreeNode::convert(BtreeNode* n) {
    return r_cast< COWBtreeNode* >(uintptr_cast(n) - sizeof(COWBtreeNode));
}

COWBtreeNode::FlushInfo COWBtreeNode::prepare_flush_buf(COWBtree const& bt, BtreeNodePtr node, cp_id_t cur_cp_id) {
    bool expected = false;
    // If the buffer is already flushing, we need to make a copy, otherwise it is safe to mark it as flushing and let
    // flush thread use the same buffer.
    uint8_t* ret_buf = m_is_buf_flushing.compare_exchange_strong(expected, true) ? node->get_phys_node_buf() : nullptr;

    // If the buffer for the current version was written as part of previous cp (exactly 1 behind requested cp),
    // then we need to check if previous cp is still in flushing. If so, we have to make a copy and use new version
    // to write. We preserve existing version in the dirty list until it is flushed.
    auto const node_cp_id = node->get_modified_cp_id();
    if (node_cp_id == (cur_cp_id - 1)) {
        if (ret_buf == nullptr) {
            // We couldn't share the buffer, because the node physical buffer is already shared.
            auto new_buf = hs_utils::iobuf_alloc(node->node_size(), sisl::buftag::btree_node, bt.align_size());
            std::memcpy(new_buf, node->get_phys_node_buf(), node->node_size());
            ret_buf = new_buf;
            node->set_phys_node_buf(new_buf);
        }
    } else {
        HS_DBG_ASSERT_NE((void*)ret_buf, (void*)nullptr,
                         "Node={} was modified by earlier cp_id, but we couldn't share the buffer.", node->to_string());
    }
    node->set_modified_cp_id(cur_cp_id);
    return FlushInfo{std::move(node), ret_buf};
}

void COWBtreeNode::release_buf(uint8_t* buf) {
    auto flushing_flag_on = m_is_buf_flushing.exchange(false);
    if (!flushing_flag_on) {
        // Looks like the earlier buffer which was shared to us has been released and a new copy was used. So we
        // need to free the buffer
        hs_utils::iobuf_free(buf, sisl::buftag::btree_node);
    } else {
        HS_DBG_ASSERT_EQ((void*)buf, (void*)to_btree_node()->get_phys_node_buf(),
                         "Buffer is not same as the one we shared to flush. buf={}", fmt::ptr(buf));
    }
}

COWBtreeNode::FlushInfo::~FlushInfo() {
    if (buf) { COWBtreeNode::convert(node)->release_buf(buf); }
}

} // namespace homestore