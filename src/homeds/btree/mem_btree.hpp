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
#include <utility/atomic_counter.hpp>
#include "btree_store.hpp"
#include "btree_node.h"
#include "physical_node.hpp"

namespace homeds { namespace btree {

struct mem_btree_node_header {
    uint64_t magic;
    sisl::atomic_counter<uint16_t> refcount;
};

#define MemBtreeNode  BtreeNode<btree_store_type::MEM_BTREE, K, V, InteriorNodeType, LeafNodeType, NodeSize, empty_writeback_req>
#define MemBtreeStore BtreeStore<btree_store_type::MEM_BTREE, K, V, InteriorNodeType, LeafNodeType, NodeSize, empty_writeback_req>
#define membtree_multinode_req_ptr boost::intrusive_ptr < btree_multinode_req < empty_writeback_req > > 

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
    
    static std::unique_ptr<MemBtreeStore> init_btree(BtreeConfig &cfg, void *btree_specific_context, 
                                            comp_callback comp_cb, bool is_in_recovery = false) {
        return (std::make_unique<BtreeStore>(cfg, btree_specific_context));
    }
    static void recovery_cmpltd(MemBtreeStore *store) {};

    static uint8_t *get_physical(const MemBtreeNode *bn) {
        return (uint8_t *)((uint8_t *)bn + sizeof(MemBtreeNode));
    }

    static uint32_t get_node_area_size(MemBtreeStore *store) {
        return NodeSize - sizeof(MemBtreeNode) - sizeof(LeafPhysicalNode);
    }

    static boost::intrusive_ptr<MemBtreeNode> alloc_node(MemBtreeStore *store, bool is_leaf,
            bool &is_new_allocation, // indicates if allocated node is same as copy_from
            boost::intrusive_ptr<MemBtreeNode> copy_from = nullptr) {
        if (copy_from!= nullptr) {
            is_new_allocation =  false;
            return copy_from;

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
        mbh->magic = 0xDEADBEEF;
        mbh->refcount.set(1);

        boost::intrusive_ptr<MemBtreeNode> new_node = (boost::intrusive_ptr<MemBtreeNode>((MemBtreeNode *)mem));
       
        return new_node;
    }

    static boost::intrusive_ptr<MemBtreeNode> read_node(MemBtreeStore *store, bnodeid_t id) {
        auto bn = reinterpret_cast<MemBtreeNode*>(static_cast<uint64_t>(id.m_id));
        return boost::intrusive_ptr<MemBtreeNode>(bn);
    }

    static btree_status_t write_node(MemBtreeStore *store, boost::intrusive_ptr<MemBtreeNode> bn,
                                        membtree_multinode_req_ptr op) {
        return btree_status_t::success;
    }


    static void free_node(MemBtreeStore *store, boost::intrusive_ptr<MemBtreeNode> bn, 
                            membtree_multinode_req_ptr op, bool mem_only = false) {
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

    /* TODO: three copies huh.. ? it is not the most efficient way. We might need to change it later */
    static void swap_node(MemBtreeStore *impl, boost::intrusive_ptr<MemBtreeNode> node1, boost::intrusive_ptr<MemBtreeNode> node2) {
        /* copy the contents */
        int sizeOfTransientHeaders = sizeof(MemBtreeNode);
        uint32_t size = NodeSize - sizeOfTransientHeaders;
        void *temp = malloc(size);
        void *buf1 = (void *)((uint8_t *)node1.get() + sizeOfTransientHeaders);
        void *buf2 = (void *)((uint8_t *)node2.get() + sizeOfTransientHeaders);
        bnodeid_t id1 = node1->get_node_id();
        bnodeid_t id2 = node2->get_node_id();
        memcpy(temp, buf1, size);
        memcpy(buf1, buf2, size);
        memcpy(buf2, temp, size);

        /* set the node ids */
        node1->set_node_id(id1);
        node1->init();
        node2->set_node_id(id2);
        node2->init();
        free(temp);
    }

    static btree_status_t refresh_node(MemBtreeStore *impl, boost::intrusive_ptr<MemBtreeNode> bn, 
                    membtree_multinode_req_ptr op, bool is_write_modifiable) {
        return btree_status_t::success;
    }

    static void ref_node(MemBtreeNode *bn) {
        auto mbh = (mem_btree_node_header *)bn;
        assert(mbh->magic == 0xDEADBEEF);
        mbh->refcount.increment();
    }


    static void deref_node(MemBtreeNode *bn) {
        auto mbh = (mem_btree_node_header *)bn;
        assert(mbh->magic == 0xDEADBEEF);
        if (mbh->refcount.decrement_testz()) {
            mbh->magic = 0;
            bn->~MemBtreeNode();
            BtreeNodeAllocator<NodeSize>::deallocate((uint8_t *)bn);
        }
    }
    
private:
    BtreeConfig m_cfg;
 
};
} }
