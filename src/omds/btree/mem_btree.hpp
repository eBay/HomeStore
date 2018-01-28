/*
 * mem_btree.hpp
 *
 *  Created on: 14-Jun-2016
 *      Author: Hari Kadayam
 *
 *  Copyright © 2016 Kadayam, Hari. All rights reserved.
 */
#pragma once

#include <iostream>
#include <assert.h>
#include <pthread.h>
#include <vector>
#include <atomic>

#include "btree.hpp"
#include "omds/memory/composite_allocator.hpp"
#include "omds/memory/chunk_allocator.hpp"
#include "omds/memory/sys_allocator.hpp"
#include "omds/utility/atomic_counter.hpp"
#include "omds/btree/simple_node.hpp"
#include "omds/btree/varlen_node.hpp"

namespace omds { namespace btree {
template< typename K, typename V, size_t NodeSize = 8192 >
class MemBtree : public Btree< K, V, NodeSize > {
public:
    MemBtree(BtreeConfig &cfg) :
            Btree< K, V, NodeSize >() {
        this->init_btree(cfg);

        cfg.set_node_header_size(0); // No additional header for in-memory btree
        BtreeNodeAllocator< NodeSize >::create();
        this->create_root_node();
    }

protected:
    AbstractNodePtr alloc_node(btree_nodetype_t btype, bool is_leaf) override {
        AbstractNode<K, V, NodeSize> *n;
        uint8_t *mem = BtreeNodeAllocator< NodeSize >::allocate();

        switch (btype) {
        case BTREE_NODETYPE_SIMPLE: {
            // Initialize both perpetual and transient portion of the node
            auto sn = new(mem) SimpleNode< K, V, NodeSize >((bnodeid_t) mem, true, true);
            n = (AbstractNode< K, V, NodeSize > *) sn;
            break;
        }

        case BTREE_NODETYPE_VAR_KEY: {
            auto vn = new(mem)
                    VarObjectNode< K, V, BTREE_NODETYPE_VAR_KEY, NodeSize >(*this->get_config(), (bnodeid_t) mem, true, true);
            n = (AbstractNode< K, V, NodeSize > *) vn;
            break;
        }

        case BTREE_NODETYPE_VAR_VALUE: {
            auto vn = new(mem)
                    VarObjectNode< K, V, BTREE_NODETYPE_VAR_VALUE, NodeSize >(*this->get_config(), (bnodeid_t) mem, true, true);
            n = (AbstractNode< K, V, NodeSize > *) vn;
            break;
        }

        case BTREE_NODETYPE_VAR_OBJECT: {
            auto vn = new(mem)
                    VarObjectNode< K, V, BTREE_NODETYPE_VAR_OBJECT, NodeSize >(*this->get_config(), (bnodeid_t) mem, true, true);
            n = (AbstractNode< K, V, NodeSize > *) vn;
            break;
        }

        default:
            assert(0);
            return nullptr;
        }

        // We are referencing twice, one for alloc and other for read - so that mem is not freed upon release
        n->ref_node();
        //n->ref_node();
        return AbstractNodePtr(n);
    }

    AbstractNodePtr read_node(bnodeid_t id) override {
        AbstractNode<K, V, NodeSize> *n = (AbstractNode<K, V, NodeSize> *)(uint8_t *)id.m_x;
        // n->ref_node();
        return AbstractNodePtr(n);
    }

    void write_node(AbstractNodePtr n) override {
    }

    void release_node(AbstractNodePtr n) override {
        if (n->deref_node()) {
            BtreeNodeAllocator<NodeSize>::deallocate((uint8_t *)n.get());
        }
    }

    void free_node(AbstractNodePtr n) override {
        if (n->deref_node()) {
            BtreeNodeAllocator<NodeSize>::deallocate((uint8_t *)n.get());
        }
    }

private:

};

} }
