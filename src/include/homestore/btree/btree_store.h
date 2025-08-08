#pragma once

#include <folly/futures/Future.h>
#include <homestore/btree/detail/btree_internal.hpp>
#include <homestore/homestore_decl.hpp>

namespace homestore {

class BtreeBase;
class UnderlyingBtree;
class CPContext;

class BtreeStore : public IndexStore {
public:
    BtreeStore() = default;
    virtual ~BtreeStore() = default;

    // All Btree related operations
    virtual unique< UnderlyingBtree > create_underlying_btree(BtreeBase& btree, bool load_existing) = 0;
    virtual folly::Future< folly::Unit > destroy_underlying_btree(BtreeBase& btree) = 0;

#if 0
    // Called whenever a particular btree node has been freed. The underlying implementation could use this oppurtunity
    // to free any contexts stored for this node.
    virtual void on_node_freed(BtreeNode* node) = 0;
#endif

    // When a particular btree is to be destroyed, some stores can support fast destroy mechanism, where all the btree
    // nodes can be freed in one go (in a single Checkpoint) without merging the tree and collapsing the tree. This
    // saves lots of IOs while destroying a btree. The requirement from the store is that it should be able to destroy
    // and free all nodes within single checkpoint. If store doesn't support, then btree library itself will keep
    // merging entities and collapsing the tree.
    virtual bool is_fast_destroy_supported() const = 0;

    virtual bool is_ephemeral() const = 0;

    virtual uint32_t max_node_size() const = 0;
};
} // namespace homestore