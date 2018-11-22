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

    static boost::intrusive_ptr<MemBtreeNode> alloc_node(MemBtreeStore *store, bool is_leaf,
            bool &is_new_allocation,// indicates if allocated node is same as copy_from
            boost::intrusive_ptr<MemBtreeNode> copy_from = nullptr) {

        if (copy_from!= nullptr) {
            is_new_allocation =  false;
            return boost::intrusive_ptr<MemBtreeNode > (copy_from.get());
        }

        is_new_allocation =  true;
        uint8_t *mem = BtreeNodeAllocator< NodeSize >::allocate();
        auto btree_node = new (mem) MemBtreeNode();

        if (is_leaf) {
            bnodeid_t bid(reinterpret_cast<std::uintptr_t>(mem),0);
            auto n = new(mem + sizeof(MemBtreeNode)) VariantNode<LeafNodeType, K, V, NodeSize>(&bid, true, store->m_cfg);
        } else {
            bnodeid_t bid(reinterpret_cast<std::uintptr_t>(mem),0);
            auto n = new(mem + sizeof(MemBtreeNode)) VariantNode<InteriorNodeType, K, V, NodeSize>(&bid, true, store->m_cfg);
        }
        auto mbh = (mem_btree_node_header *)btree_node;
        mbh->refcount.increment();

        boost::intrusive_ptr<MemBtreeNode> new_node = (boost::intrusive_ptr<MemBtreeNode>((MemBtreeNode *)mem));
        
        return new_node;
    }

    static boost::intrusive_ptr<MemBtreeNode> read_node(MemBtreeStore *store, bnodeid_t id) {
        auto bn = reinterpret_cast<MemBtreeNode*>(static_cast<uint64_t>(id.m_id));
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

    static void copy_node(MemBtreeStore *store, boost::intrusive_ptr<MemBtreeNode> copy_from,
                boost::intrusive_ptr<MemBtreeNode> copy_to) {
        int sizeOfTransientHeaders = sizeof(MemBtreeNode);
        void* copy_to_ptr = (void*)((uint8_t*)copy_to.get()+ sizeOfTransientHeaders);
        void* copy_from_ptr = (void*)((uint8_t*)copy_from.get()+ sizeOfTransientHeaders);

        auto pheader_copy_to = reinterpret_cast<LeafPhysicalNode*>(copy_to_ptr);
        bnodeid_t original_id = pheader_copy_to->get_node_id();
        memcpy(copy_to_ptr, copy_from_ptr, NodeSize - sizeOfTransientHeaders);

        original_id.m_pc_gen_flag = pheader_copy_to->get_node_id().m_pc_gen_flag;
        pheader_copy_to->set_node_id(original_id);
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
