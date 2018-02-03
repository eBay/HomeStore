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

#include "btree.hpp"
#include "omds/memory/composite_allocator.hpp"
#include "omds/memory/chunk_allocator.hpp"
#include "omds/memory/sys_allocator.hpp"
#include "omds/utility/atomic_counter.hpp"
#include "omds/btree/simple_node.hpp"
#include "omds/btree/varlen_node.hpp"
#include "blkstore/blkstore.hpp"

namespace omds { namespace btree {

template <typename K, typename V, size_t NodeSize>
class BtreeNodeBuffer : public omstore::CacheRecord {
    PhysicalNode<K, V, NodeSize> m_bt_node;

public:
    BtreeNodeBuffer() {
        m_bt_node.reset_reference();
    }

    const omstore::BlkId &get_key() const {
        omstore::BlkId b(m_bt_node.get_node_id().to_integer(), 1);
        return b;
    }

    void set_key(omstore::BlkId &b) {
        m_bt_node.set_node_id(b.get_id());
    }

    void set_memvec(const omds::MemVector< BLKSTORE_BLK_SIZE > &vec) {
#ifndef NDEBUG
        omds::blob b;
        vec.get(&b);
        assert(b.bytes == (void *)this);
        assert(b.size == NodeSize);
#endif
    }

    const omds::MemVector< BLKSTORE_BLK_SIZE > &get_memvec() const {
        const omds::MemVector< BLKSTORE_BLK_SIZE > mvec((uint8_t *)this, (uint32_t)NodeSize, 0);
        return mvec;
    }

    omds::MemVector< BLKSTORE_BLK_SIZE > &get_memvec_mutable() {
        const omds::MemVector< BLKSTORE_BLK_SIZE > mvec((uint8_t *)this, (uint32_t)NodeSize, 0);
        return mvec;
    }

    omds::blob at_offset(uint32_t offset) const {
        omds::blob b;
        get_memvec().get(&b, offset);
        return b;
    }

    friend void intrusive_ptr_add_ref(BtreeNodeBuffer<K, V, NodeSize> *buf) {
        buf->m_bt_node.ref_node();
    }

    friend void intrusive_ptr_release(BtreeNodeBuffer<K, V, NodeSize> *buf) {
        if (buf->m_bt_node.deref_node()) {

        }
        if (buf->m_refcount.decrement_testz()) {
            // First free the bytes it covers
            omds::blob blob;
            buf->m_mem.get(&blob);
            free((void *) blob.bytes);

            // Then free the record itself
            omds::ObjectAllocator< CacheBufferType >::deallocate(buf);
        }
    }

    static CacheBuffer<K> *make_object() {
        return omds::ObjectAllocator< CacheBufferType >::make_object();
    }

    //////////// Mandatory IntrusiveHashSet definitions ////////////////
    static void ref(BtreeNodeBuffer<K, V, NodeSize> &b) {
        b.m_bt_node.ref_node();
    }

    static void deref(BtreeNodeBuffer<K, V, NodeSize> &b) {
        b.m_bt_node.deref_node();
    }

    static bool deref_testz(BtreeNodeBuffer<K, V, NodeSize> &b) {
        return b.m_refcount.decrement_testz();
    }

    static bool deref_test_le(BtreeNodeBuffer<K, V, NodeSize> &b, int32_t check) {
        return b.m_refcount.decrement_test_le(check);
    }

    static const BlkId *extract_key(const BtreeNodeBuffer<K, V, NodeSize> &b) {
        return &(b.m_key);
    }

    static uint32_t get_size(const CurrentEvictor::EvictRecordType *rec) {
        const CacheBuffer<K> *cbuf = static_cast<const CacheBuffer<K> *>(CacheRecord::evict_to_cache_record(rec));
        return cbuf->get_memvec().size();
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

