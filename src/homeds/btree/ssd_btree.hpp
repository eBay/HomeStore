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

#include "homeds/memory/composite_allocator.hpp"
#include "homeds/memory/chunk_allocator.hpp"
#include "homeds/memory/sys_allocator.hpp"
#include "cache/cache.h"
#include "blkstore/blkstore.hpp"
#include "btree_specific_impl.hpp"
#include "btree_node.h"
#include "physical_node.hpp"

namespace homeds { namespace btree {
#define SSDBtreeNodeDeclType BtreeNode<SSD_BTREE, K, V, InteriorNodeType, LeafNodeType, NodeSize>
#define SSDBtreeImpl BtreeSpecificImpl<SSD_BTREE, K, V, InteriorNodeType, LeafNodeType, NodeSize>
#define BtreeBufferDeclType BtreeBuffer<K, V, InteriorNodeType, LeafNodeType, NodeSize>

/* The class BtreeBuffer represents the buffer type that is used to interact with the BlkStore. It will have
 * all the SSD Btree Node declarative type. Hence in-memory representation of this buffer is as follows
 *
 *   ****************Cache Buffer************************
 *   *    ****************Cache Record***************   *
 *   *    *   ************Hash Node**************   *   *
 *   *    *   * Singly Linked list of hash node *   *   *
 *   *    *   ***********************************   *   *
 *   *    *******************************************   *
 *   * BlkId                                            *
 *   * Memvector of actual buffer                       *
 *   * Usage Reference counter                          *
 *   ****************************************************
 *   ************** Transient Header ********************
 *   * Upgraders count                                  *
 *   * Reader Write Lock                                *
 *   ****************************************************
 */
template<
        typename K,
        typename V,
        btree_node_type InteriorNodeType,
        btree_node_type LeafNodeType,
        size_t NodeSize
>
class BtreeBuffer : public homestore::CacheBuffer< homestore::BlkId > {
public:
    static BtreeBuffer *make_object() {
        return homeds::ObjectAllocator< SSDBtreeNodeDeclType >::make_object();
    }
};

struct btree_device_info {
    homestore::DeviceManager *dev_mgr;
    homestore::Cache< homestore::BlkId > *cache;
    homestore::vdev_info_block *vb;
    uint64_t size;
    bool new_device;
};

template<
        typename K,
        typename V,
        btree_node_type InteriorNodeType,
        btree_node_type LeafNodeType,
        size_t NodeSize
        >
class BtreeSpecificImpl<SSD_BTREE, K, V, InteriorNodeType, LeafNodeType, NodeSize> {
public:
    using HeaderType = BtreeBuffer<K, V, InteriorNodeType, LeafNodeType, NodeSize>;

    static std::unique_ptr<SSDBtreeImpl> init_btree(BtreeConfig &cfg, void *btree_specific_context) {
        return std::make_unique<SSDBtreeImpl>(btree_specific_context);
    }

    BtreeSpecificImpl(void *btree_specific_context) {
        auto bt_dev_info = (btree_device_info *)btree_specific_context;

        // Create or load the Blkstore out of this info
        if (bt_dev_info->new_device) {
            m_blkstore = new homestore::BlkStore<homestore::VdevFixedBlkAllocatorPolicy, BtreeBufferDeclType>(
                bt_dev_info->dev_mgr, bt_dev_info->cache, bt_dev_info->size, homestore::BlkStoreCacheType::WRITETHRU_CACHE, 0,
                (std::bind(&BtreeSpecificImpl::process_completions,
                           this, std::placeholders::_1)));
        } else {
            m_blkstore = new homestore::BlkStore<homestore::VdevFixedBlkAllocatorPolicy, BtreeBufferDeclType>
                (bt_dev_info->dev_mgr, bt_dev_info->cache, bt_dev_info->vb, homestore::BlkStoreCacheType::WRITETHRU_CACHE,
                 (std::bind(&BtreeSpecificImpl::process_completions,
                            this, std::placeholders::_1)));
        }
    }

    void
    process_completions(void *bs_req) {
        //do nothing
    }

    static uint8_t *get_physical(const SSDBtreeNodeDeclType *bn) {
        BtreeBufferDeclType *bbuf = (BtreeBufferDeclType *)(bn);
        homeds::blob b = bbuf->at_offset(0);
        assert(b.size == NodeSize);
        return b.bytes;
    }

    static uint32_t get_node_area_size(SSDBtreeImpl *impl) {
        return NodeSize - sizeof(SSDBtreeNodeDeclType) - sizeof(LeafPhysicalNodeDeclType);
    }

    static boost::intrusive_ptr<SSDBtreeNodeDeclType> alloc_node(SSDBtreeImpl *impl, bool is_leaf) {
        homestore::blk_alloc_hints hints;
        homestore::BlkId blkid;
        auto safe_buf = impl->m_blkstore->alloc_blk_cached(1, hints, &blkid);

        // Access the physical node buffer and initialize it
        homeds::blob b = safe_buf->at_offset(0);
        assert(b.size == NodeSize);
        if (is_leaf) {
            bnodeid_t bid(blkid.to_integer());
            auto n = new (b.bytes) VariantNode<LeafNodeType, K, V, NodeSize>(&bid, true);
        } else {
            bnodeid_t bid(blkid.to_integer());
            auto n = new (b.bytes) VariantNode<InteriorNodeType, K, V, NodeSize>(&bid, true);
        }

        return boost::static_pointer_cast<SSDBtreeNodeDeclType>(safe_buf);
    }

    static boost::intrusive_ptr<SSDBtreeNodeDeclType> read_node(SSDBtreeImpl *impl, bnodeid_t id) {
        // Read the data from the block store
        homestore::BlkId blkid(id.to_integer());
        struct homestore::blkstore_req<BtreeBufferDeclType> *req = new struct homestore::blkstore_req<BtreeBufferDeclType>();
        req->isSyncCall=true;
        req->is_read=true;
        auto safe_buf = impl->m_blkstore->read(blkid, 0, NodeSize, req);

        return boost::static_pointer_cast<SSDBtreeNodeDeclType>(safe_buf);
    }

    static void write_node(SSDBtreeImpl *impl, boost::intrusive_ptr<SSDBtreeNodeDeclType> bn) {
        homestore::BlkId blkid(bn->get_node_id().to_integer());
        struct homestore::blkstore_req<BtreeBufferDeclType> *req = new struct homestore::blkstore_req<BtreeBufferDeclType>();
        req->isSyncCall=true;
        req->is_read=false;
        impl->m_blkstore->write(blkid, boost::dynamic_pointer_cast<BtreeBufferDeclType>(bn), req);
    }

    static void free_node(SSDBtreeImpl *impl, boost::intrusive_ptr<SSDBtreeNodeDeclType> bn) {
        homestore::BlkId blkid(bn->get_node_id().to_integer());
        impl->m_blkstore->free_blk(blkid, boost::none, boost::none);
    }

    static void ref_node(SSDBtreeNodeDeclType *bn) {
        homestore::CacheBuffer< homestore::BlkId >::ref((homestore::CacheBuffer<homestore::BlkId> &)*bn);
    }

    static bool deref_node(SSDBtreeNodeDeclType *bn) {
        return homestore::CacheBuffer< homestore::BlkId >::deref_testz((homestore::CacheBuffer<homestore::BlkId> &)*bn);
    }
private:
    homestore::BlkStore<homestore::VdevFixedBlkAllocatorPolicy, BtreeBufferDeclType> *m_blkstore;
};
} }


