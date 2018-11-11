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

#include "homeds/memory/composite_allocator.hpp"
#include "homeds/memory/chunk_allocator.hpp"
#include "homeds/memory/sys_allocator.hpp"
#include "homeds/utility/atomic_counter.hpp"
#include "btree_store.hpp"
#include "btree_node.h"
#include "physical_node.hpp"

namespace homeds { namespace btree {

struct mem_btree_node_header {
    /* TODO: do we need to have magic or version number */
    homeds::atomic_counter<uint16_t> refcount;
};

#define MemBtreeNode  BtreeNode<MEM_BTREE, K, V, InteriorNodeType, LeafNodeType, NodeSize, empty_writeback_req>
#define MemBtreeStore BtreeStore<MEM_BTREE, K, V, InteriorNodeType, LeafNodeType, NodeSize, empty_writeback_req>

template<
        typename K,
        typename V,
        btree_node_type InteriorNodeType,
        btree_node_type LeafNodeType,
        size_t NodeSize
        >
class MemBtreeStore {
    typedef std::function< void (boost::intrusive_ptr<empty_writeback_req> cookie, std::error_condition status) > comp_callback;

public:
    using HeaderType = mem_btree_node_header;
  
    BtreeStore(BtreeConfig &cfg, void *btree_specific_context) {
        m_cfg = cfg;
        m_cfg.set_node_area_size(NodeSize - sizeof(MemBtreeNode) - sizeof(LeafPhysicalNode));
    }
    
    static std::unique_ptr<MemBtreeStore> init_btree(BtreeConfig &cfg, void *btree_specific_context, comp_callback comp_cb) {
        return (std::make_unique<BtreeStore>(cfg, btree_specific_context));
    }

    static uint8_t *get_physical(const MemBtreeNode *bn) {
        return (uint8_t *)((uint8_t *)bn + sizeof(MemBtreeNode));
    }

    static uint32_t get_node_area_size(MemBtreeStore *store) {
        return NodeSize - sizeof(MemBtreeNode) - sizeof(LeafPhysicalNode);
    }

    static boost::intrusive_ptr<MemBtreeNode> alloc_node(MemBtreeStore *store, bool is_leaf) {
        uint8_t *mem = BtreeNodeAllocator< NodeSize >::allocate();
        auto btree_node = new (mem) MemBtreeNode();

        if (is_leaf) {
            auto n = new(mem + sizeof(MemBtreeNode)) VariantNode<LeafNodeType, K, V, NodeSize>((bnodeid_t)mem, true,
                                                                                                       store->m_cfg);
        } else {
            auto n = new(mem + sizeof(MemBtreeNode)) VariantNode<InteriorNodeType, K, V, NodeSize>((bnodeid_t)mem, true,
                                                                                                     store->m_cfg);
        }
        auto mbh = (mem_btree_node_header *)btree_node;
        mbh->refcount.increment();
        return (boost::intrusive_ptr<MemBtreeNode>((MemBtreeNode *)mem));
    }

    static boost::intrusive_ptr<MemBtreeNode> read_node(MemBtreeStore *store, bnodeid_t id) {
        auto bn = reinterpret_cast<MemBtreeNode*>(static_cast<uint64_t>(id.m_x));
        return boost::intrusive_ptr<MemBtreeNode>(bn);
    }

    static void write_node(MemBtreeStore *store, boost::intrusive_ptr<MemBtreeNode> bn,
                    std::deque<boost::intrusive_ptr<empty_writeback_req>> &dependent_req_q,
                    boost::intrusive_ptr<empty_writeback_req> cookie, bool is_sync) {
    }

    static void free_node(MemBtreeStore *store, boost::intrusive_ptr<MemBtreeNode> bn,
                   std::deque<boost::intrusive_ptr<empty_writeback_req>> &dependent_req_q) {
        auto mbh = (mem_btree_node_header *)bn.get();
        if (mbh->refcount.decrement_testz()) {
            // TODO: Access the VariantNode area and call its destructor as well
            bn->~MemBtreeNode();
            BtreeNodeAllocator<NodeSize>::deallocate((uint8_t *)bn.get());
        }
    }

    static void read_node_lock(MemBtreeStore *store,
                               boost::intrusive_ptr<MemBtreeNode> bn,
                               bool is_write_modifiable,  
                               std::deque<boost::intrusive_ptr<empty_writeback_req>> *dependent_req_q) {
    }

    static void ref_node(MemBtreeNode *bn) {
        auto mbh = (mem_btree_node_header *)bn;
        mbh->refcount.increment();
    }

    static bool deref_node(MemBtreeNode *bn) {
        auto mbh = (mem_btree_node_header *)bn;
        return mbh->refcount.decrement_testz();
    }
    
private:
    BtreeConfig m_cfg;
 
};

} }
