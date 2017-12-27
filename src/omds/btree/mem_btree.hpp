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

namespace omds { namespace btree {
template< typename K, typename V >
class MemBtree : public Btree< K, V > {
public:
    MemBtree(BtreeConfig &cfg) :
            Btree< K, V >() {
        this->init_btree(cfg);

        m_allocators.add(std::make_unique< omds::ChunkMemAllocator<0, 0> >(cfg.get_node_size(),
                                                                           this->get_max_nodes() * cfg.get_node_size()));
        m_allocators.add(std::make_unique< SysMemAllocator >());
        this->create_root_node();
    }

protected:
    virtual uint32_t get_node_header_size() const override {
        return sizeof(AbstractNode<K, V>);
    }

    AbstractNode<K, V> *alloc_node(btree_nodetype_t btype, bool is_leaf) override {
        AbstractNode<K, V> *n;
        uint8_t *mem = m_allocators.allocate(this->get_config()->get_node_size());

        if (btype == BTREE_NODETYPE_SIMPLE) {
            // Initialize both perpetual and transient portion of the node
            SimpleNode <K, V> *sn = new (mem) SimpleNode< K, V >((bnodeid_t) mem, true, true);
            n = (AbstractNode<K, V> *) sn;
        } else {
            assert(0);
        }

        // We are referencing twice, one for alloc and other for read - so that mem is not freed upon release
        n->ref_node();
        n->ref_node();
        return n;
    }

    AbstractNode<K, V> *read_node(bnodeid_t id) override {
        AbstractNode<K, V> *n = (AbstractNode<K, V> *)(uint8_t *)id.m_x;
        n->ref_node();
        return n;
    }

    void write_node(AbstractNode<K, V> *n) override {
    }

    void release_node(AbstractNode<K, V> *n) override {
        if (n->deref_node()) {
            m_allocators.deallocate((uint8_t *) n);
        }
    }

    void free_node(AbstractNode<K, V> *n) override {
        if (n->deref_node()) {
            m_allocators.deallocate((uint8_t *) n);
        }
    }

private:
    omds::StackedMemAllocator m_allocators;
};

} }
