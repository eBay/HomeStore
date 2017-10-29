/*
 * SSDBtreeKVStore.hpp
 *
 *  Created on: 02-Sep-2016
 *      Author: hkadayam
 */
#ifndef SSDBTREE_KVSTORE_HPP_
#define SSDBTREE_KVSTORE_HPP_

#include "btree.hpp"

typedef struct
{
	btree_nodetype_t btype;
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
	BtreeAbstractNode *allocNode(btree_nodetype_t btype, bool isLeaf)
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
		btree_nodetype_t btype;
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

