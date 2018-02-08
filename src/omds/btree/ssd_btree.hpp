/*
 * ssd_btree.hpp
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

#include "omds/memory/composite_allocator.hpp"
#include "omds/memory/chunk_allocator.hpp"
#include "omds/memory/sys_allocator.hpp"
#include "blkstore/blkstore.hpp"
#include "btree_specific_impl.hpp"
#include "btree_node.h"
#include "physical_node.hpp"

namespace omds { namespace btree {
#define SSDBtreeNodeDeclType BtreeNode<SSD_BTREE, K, V, InteriorNodeType, LeafNodeType, NodeSize>

template<
        typename K,
        typename V,
        btree_node_type InteriorNodeType,
        btree_node_type LeafNodeType,
        size_t NodeSize
        >
class BtreeSpecificImpl<SSD_BTREE, K, V, InteriorNodeType, LeafNodeType, NodeSize> {
    using HeaderType = omstore::BlkBuffer;

    static uint8_t *get_physical(const SSDBtreeNodeDeclType *bn) {
        omstore::BlkBuffer *bbuf = const_cast<>(bn)->get_impl_node();
        omds::blob b = bbuf->at_offset(0);
        assert(b.size == NodeSize);
        return b.bytes;
    }

    static uint32_t get_node_area_size() {
        return NodeSize - sizeof(SSDBtreeNodeDeclType) - sizeof(LeafPhysicalNodeDeclType);
    }

    static boost::intrusive_ptr<MemBtreeNodeDeclType> alloc_node(bool is_leaf) {
        uint8_t *mem = BtreeNodeAllocator< NodeSize >::allocate();
        auto bn = new (mem) MemBtreeNodeDeclType();

        if (is_leaf) {
            auto n = new(mem + sizeof(MemBtreeNodeDeclType)) VariantNode<LeafNodeType, K, V, NodeSize>((bnodeid_t)mem, true);
        } else {
            auto n = new(mem + sizeof(MemBtreeNodeDeclType)) VariantNode<InteriorNodeType, K, V, NodeSize>((bnodeid_t)mem, true);
        }
        ref_node(bn);
        return (boost::intrusive_ptr<MemBtreeNodeDeclType>((MemBtreeNodeDeclType *)mem));
    }

};

template< typename K, typename V, size_t NodeSize = 8192 >
class SSDBtree : public Btree< K, V, NodeSize > {
public:
    SSDBtree(BtreeConfig &cfg) :
            Btree< K, V, NodeSize >() {
        this->init_btree(cfg);

        cfg.set_node_header_size(0);
        BtreeNodeAllocator< NodeSize >::create();
        this->create_root_node();
    }

protected:
    BtreeNodePtr alloc_node(btree_node_type btype, bool is_leaf) override {
        PhysicalNode< K, V, NodeSize > *n;
        uint8_t *mem = BtreeNodeAllocator< NodeSize >::allocate();

        switch (btype) {
        case BTREE_NODETYPE_SIMPLE: {
            // Initialize both perpetual and transient portion of the node
            auto sn = new(mem) SimpleNode< K, V, NodeSize >((bnodeid_t) mem, true, true);
            n = (PhysicalNode< K, V, NodeSize > *) sn;
            break;
        }

        case BTREE_NODETYPE_VAR_KEY: {
            auto vn = new(mem)
                    VarObjectNode< K, V, BTREE_NODETYPE_VAR_KEY, NodeSize >(*this->get_config(), (bnodeid_t) mem, true,
                                                                            true);
            n = (PhysicalNode< K, V, NodeSize > *) vn;
            break;
        }

        case BTREE_NODETYPE_VAR_VALUE: {
            auto vn = new(mem)
                    VarObjectNode< K, V, BTREE_NODETYPE_VAR_VALUE, NodeSize >(*this->get_config(), (bnodeid_t) mem,
                                                                              true, true);
            n = (PhysicalNode< K, V, NodeSize > *) vn;
            break;
        }

        case BTREE_NODETYPE_VAR_OBJECT: {
            auto vn = new(mem)
                    VarObjectNode< K, V, BTREE_NODETYPE_VAR_OBJECT, NodeSize >(*this->get_config(), (bnodeid_t) mem,
                                                                               true, true);
            n = (PhysicalNode< K, V, NodeSize > *) vn;
            break;
        }

        default:
            assert(0);
            return nullptr;
        }

        // We are referencing twice, one for alloc and other for read - so that mem is not freed upon release
        n->ref_node();
        //n->ref_node();
        return BtreeNodePtr(n);
    }

    BtreeNodePtr read_node(bnodeid_t id) override {
        PhysicalNode< K, V, NodeSize > *n = (PhysicalNode< K, V, NodeSize > *) (uint8_t *) id.m_x;
        // n->ref_node();
        return BtreeNodePtr(n);
    }

    void write_node(BtreeNodePtr n) override {
    }

    void release_node(BtreeNodePtr n) override {
        if (n->deref_node()) {
            BtreeNodeAllocator< NodeSize >::deallocate((uint8_t *) n.get());
        }
    }

    void free_node(BtreeNodePtr n) override {
        if (n->deref_node()) {
            BtreeNodeAllocator< NodeSize >::deallocate((uint8_t *) n.get());
        }
    }

private:

};

} }

#if 0
#ifndef SSDBTREE_KVSTORE_HPP_
#define SSDBTREE_KVSTORE_HPP_

#include "btree.hpp"

typedef struct
{
	btree_node_type btype;
	bool isLeaf;
} ssdbtree_cb_context_t;

#ifdef VTABLE_DEBUG
uint8_t *OmDB::leaf_vtable_ptr = nullptr;
uint8_t *OmDB::int_vtable_ptr = nullptr;
#endif

template<typename K, typename V>
class SSDBtreeCallbackInterface;

template<typename K, typename V>
class SSDBtreeKVStore: public BtreeKVStore<K, V>
{
public:
	SSDBtreeKVStore(BtreeConfig cfg) :
					BtreeKVStore<K, V>(cfg)
	{
		// Create an underlying memory blkstore
		this->setBlkStore(createBlkStore(this->getMaxNodes(), this->getNodeSize()));
		this->createRootNode();
	}

	virtual ~SSDBtreeKVStore()
	{
	}

private:
	BtreeAbstractNode *allocNode(btree_node_type btype, bool isLeaf)
	{
		SSDBlk ssdBlk(PAGEID64_INVALID, this->getNodeSize());

		ssdbtree_cb_context_t cbContext;
		cbContext.btype = btype;
		cbContext.isLeaf = isLeaf;

#if 0
		cout << "Allocating SSDBtreeNode " << endl;
#endif
		// In SSD version, SSDBlkStore is being registered with the
		// callback which actually does the initialization. By the
		// time allocBlk is returned, BtreeAbstractNode is already
		// created out of the mem, so just typecast it.
		this->getBlkStore()->alloc(this->getNodeSize(), &ssdBlk, (void *) &cbContext);
		BtreeAbstractNode *n = (BtreeAbstractNode *) ssdBlk.getMemoryPortion(0).getMem();

#ifdef VTABLE_DEBUG
		assert((OmDBGlobals::extract_vtable_ptr(ssdBlk.getMemoryPortion().getMem()) == OmDBGlobals::get_vtable_ptr(true)) ||
						(OmDBGlobals::extract_vtable_ptr(ssdBlk.getMemoryPortion().getMem()) == OmDBGlobals::get_vtable_ptr(false)));
#endif
		return n;
	}

	BtreeAbstractNode *readNode(bnodeid_t nodePtr)
	{
		BlkStoreFlags readFlags;
		SSDBlk ssdBlk(to64bitId(nodePtr), this->getNodeSize());

#if 0
		printf("Reading SSDBtreeNode 0x%x\n", nodePtr);
#endif

		// Same case as allocNode. Initialization if needed of memory is already
		// done by the callback registered with SSDBlkStore. So just typecast it
		this->getBlkStore()->read(ssdBlk, NO_FLAGS, &readFlags, nullptr);
		BtreeAbstractNode *n = (BtreeAbstractNode *)ssdBlk.getMemoryPortion(0).getMem();
		assert(n->getNodeId() == nodePtr);

#ifdef VTABLE_DEBUG
		assert((OmDBGlobals::extract_vtable_ptr(ssdBlk.getMemoryPortion().getMem()) == OmDBGlobals::get_vtable_ptr(true)) ||
						(OmDBGlobals::extract_vtable_ptr(ssdBlk.getMemoryPortion().getMem()) == OmDBGlobals::get_vtable_ptr(false)));
#endif

		return n;
	}

	void writeNode(BtreeAbstractNode *node)
	{
		// Reference is completely maintained by the SSDBlkStore for SSDBtreeKVStore
		SSDBlk ssdBlk(to64bitId(node->getNodeId()), this->getNodeSize());
		ssdBlk.getMemoryPortion(0).setMem((uint8_t *) node);
		ssdBlk.getMemoryPortion(0).setSize(this->getNodeSize());

		this->getBlkStore()->write(ssdBlk);
	}

	void releaseNode(BtreeAbstractNode *node)
	{
		SSDBlk ssdBlk(to64bitId(node->getNodeId()), this->getNodeSize());
		ssdBlk.getMemoryPortion(0).setMem((uint8_t *) node);
		ssdBlk.getMemoryPortion(0).setSize(this->getNodeSize());

		this->getBlkStore()->release(ssdBlk);
	}

	void freeNode(BtreeAbstractNode *node)
	{
		SSDBlk ssdBlk(to64bitId(node->getNodeId()), this->getNodeSize());
		ssdBlk.getMemoryPortion(0).setMem((uint8_t *) node);
		ssdBlk.getMemoryPortion(0).setSize(this->getNodeSize());

		this->getBlkStore()->free(ssdBlk, NO_FLAGS);
	}
protected:
	BlkStore *createBlkStore(uint32_t maxNodes, uint32_t nodeSize)
	{
		SSDBlkStoreConfig cfg;
		cfg.setSize(maxNodes * nodeSize);
		cfg.setDefaultPageSize(nodeSize);
		cfg.setDynamicAlloc(false);
		cfg.setCacheType(BlkStoreCache::WRITETHRU_CACHE);
		//cfg.setCacheEntries((maxNodes * 90)/100);
		//cfg.setCacheEntries((maxNodes * 102)/100);
		cfg.setCacheEntries( (maxNodes * 10) / 100);
		cfg.setTotalMirrors(0);
		cfg.setCBIface(new SSDBtreeCallbackInterface<K, V>(this));

		return new SSDBlkStore(cfg);
	}
};

template<typename K, typename V>
class SSDBtreeCallbackInterface: public SSDBlkStoreCallbackInterface
{
private:
	SSDBtreeKVStore<K, V> *m_btree;

public:
	SSDBtreeCallbackInterface(SSDBtreeKVStore<K, V> *btree)
	{
		m_btree = btree;
	}

	uint8_t *extractKey(uint8_t *mem, uint32_t *pSize)
	{
		//BtreeAbstractNode *n = (BtreeAbstractNode *)mem;
		BtreeSimpleNode<K, V> *n = (BtreeSimpleNode<K, V> *) mem;
		uint8_t *pNodeId = (uint8_t *) &n->getPerpetualHeader()->nodeId;
		*pSize = sizeof(bnodeid_t);
		return pNodeId;
	}

	atomic<int16_t> *extractReference(uint8_t *mem)
	{
		BtreeAbstractNode *n = (BtreeAbstractNode *) mem;
		return &n->getTransientHeader()->refCount;
	}

	void initBlk(uint8_t *mem, blk_init_params_t *params, void *cbContext)
	{
		ssdbtree_cb_context_t *context = (ssdbtree_cb_context_t *) cbContext;
		btree_node_type btype;
		bool isLeaf;

		if (params->newAlloc) {
			btype = context->btype;
			isLeaf = context->isLeaf;
		} else if (params->readFromStorage) {
			// Need to do basic initialization to get the node type.
			// Then based on node type need to initialize corresponding
			// derived class
			BtreeSimpleNode<K, V> *tmpn = new (mem) BtreeSimpleNode<K, V>(to32bitId(params->id), false, false);
			btype = tmpn->getNodeType();
			isLeaf = tmpn->isLeaf();
		} else {
#ifdef VTABLE_DEBUG
			assert((OmDBGlobals::extract_vtable_ptr(mem) == OmDBGlobals::get_vtable_ptr(true)) ||
							(OmDBGlobals::extract_vtable_ptr(mem) == OmDBGlobals::get_vtable_ptr(false)));
#endif
			// Already initialized
			return;
		}

		switch (btype) {
		case BTREE_NODETYPE_SIMPLE:
			if (isLeaf) {
				BtreeSimpleNode<K, V> *sn __attribute__((unused)) =
				new (mem) BtreeSimpleNode<K, V>(to32bitId(params->id), params->newAlloc,
				                                (params->readFromStorage || params->newAlloc));

#ifdef VTABLE_DEBUG
				if(OmDBGlobals::get_vtable_ptr(true) == nullptr) {
					OmDBGlobals::set_vtable_ptr(OmDB::extract_vtable_ptr(mem), true);
				} else {
					assert(OmDBGlobals::get_vtable_ptr(true) == OmDBGlobals::extract_vtable_ptr(mem));
				}
#endif
			} else {
				BtreeSimpleNode<K, BNodeptr> *sn __attribute__((unused)) =
				new (mem) BtreeSimpleNode<K, BNodeptr>(to32bitId(params->id), params->newAlloc,
				                                       (params->readFromStorage || params->newAlloc));

#ifdef VTABLE_DEBUG
				if(OmDBGlobals::get_vtable_ptr(false) == nullptr) {
					OmDBGlobals::set_vtable_ptr(OmDBGlobals::extract_vtable_ptr(mem), false);
				} else {
					assert(OmDBGlobals::get_vtable_ptr(false) == OmDBGlobals::extract_vtable_ptr(mem));
				}
#endif
			}
			break;

		default:
			assert(0);
			break;
		}

	}

	void deinitBlk(uint8_t *mem, void *cbContext)
	{
#if 0
		BtreeAbstractNode *n = (BtreeAbstractNode *)mem;
		n->~BtreeAbstractNode();
#endif
	}
};
#endif

