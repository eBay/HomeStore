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
#include "homeds/btree/btree_specific_impl.hpp"
#include "homeds/btree/btree_node.h"
#include "homeds/btree/physical_node.hpp"

using namespace homestore;

namespace homeds {
namespace btree {

using SSDBtreeNode = BtreeNode< SSD_BTREE, K, V, InteriorNodeType, LeafNodeType >
#define SSDBtreeImpl BtreeSpecificImpl< SSD_BTREE, K, V, InteriorNodeType, LeafNodeType >
#define BtreeBufferDeclType BtreeBuffer< K, V, InteriorNodeType, LeafNodeType >

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
    template < typename K, typename V, btree_node_type InteriorNodeType, btree_node_type LeafNodeType, >
    class BtreeBuffer : public CacheBuffer< BlkId > {
public:
    static BtreeBuffer* make_object() { return homeds::ObjectAllocator< SSDBtreeNode >::make_object(); }
};

struct btree_device_info {
    DeviceManager* dev_mgr;
    Cache< homestore::BlkId >* cache;
    vdev_info_block* vb;
    uint64_t size;
    bool new_device;
};

template < typename K, typename V, btree_node_type InteriorNodeType, btree_node_type LeafNodeType, >
class BtreeSpecificImpl< SSD_BTREE, K, V, InteriorNodeType, LeafNodeType > {
public:
    using HeaderType = BtreeBuffer< K, V, InteriorNodeType, LeafNodeType >;

    static std::unique_ptr< SSDBtreeImpl > init_btree(BtreeConfig& cfg, void* btree_specific_context) {
        return std::make_unique< SSDBtreeImpl >(btree_specific_context);
    }

    BtreeSpecificImpl(void* btree_specific_context) {
        auto bt_dev_info = (btree_device_info*)btree_specific_context;

        // Create or load the Blkstore out of this info
        if (bt_dev_info->new_device) {
            m_blkstore = new BlkStore< VdevFixedBlkAllocatorPolicy, BtreeBufferDeclType >(
                bt_dev_info->dev_mgr, bt_dev_info->cache, bt_dev_info->size, BlkStoreCacheType::WRITETHRU_CACHE, 0);
        } else {
            m_blkstore = new BlkStore< VdevFixedBlkAllocatorPolicy, BtreeBufferDeclType >(
                bt_dev_info->dev_mgr, bt_dev_info->cache, bt_dev_info->vb, BlkStoreCacheType::WRITETHRU_CACHE);
        }
    }

    static uint8_t* get_physical(const SSDBtreeNode* bn) {
        BtreeBufferDeclType* bbuf = (BtreeBufferDeclType*)(bn);
        homeds::blob b = bbuf->at_offset(0);
        assert(b.size == m_node_size);
        return b.bytes;
    }

    static uint32_t get_node_area_size(SSDBtreeImpl* impl) {
        return m_node_size - sizeof(SSDBtreeNode) - sizeof(LeafPhysicalNodeDeclType);
    }

    static boost::intrusive_ptr< SSDBtreeNode > alloc_node(SSDBtreeImpl* impl, bool is_leaf) {
        blk_alloc_hints hints;
        BlkId blkid;
        auto safe_buf = impl->m_blkstore->alloc_blk_cached(1 * BLKSTORE_PAGE_SIZE, hints, &blkid);

        // Access the physical node buffer and initialize it
        homeds::blob b = safe_buf->at_offset(0);
        assert(b.size == m_node_size);
        if (is_leaf) {
            auto n = new (b.bytes) VariantNode< LeafNodeType, K, V >((bnodeid_t)blkid.get_id(), true);
        } else {
            auto n = new (b.bytes) VariantNode< InteriorNodeType, K, V >((bnodeid_t)blkid.get_id(), true);
        }

        return boost::static_pointer_cast< SSDBtreeNode >(safe_buf);
    }

    static boost::intrusive_ptr< SSDBtreeNode > read_node(SSDBtreeImpl* impl, bnodeid_t id) {
        // Read the data from the block store
        BlkId blkid(id.to_integer());
        auto safe_buf = impl->m_blkstore->read(blkid, 0, m_node_size);

        return boost::static_pointer_cast< SSDBtreeNode >(safe_buf);
    }

    static void write_node(SSDBtreeImpl* impl, boost::intrusive_ptr< SSDBtreeNode > bn) {
        BlkId blkid(bn->get_node_id().to_integer());
        impl->m_blkstore->write(blkid, boost::dynamic_pointer_cast< BtreeBufferDeclType >(bn));
    }

    static void free_node(SSDBtreeImpl* impl, boost::intrusive_ptr< SSDBtreeNode > bn) {
        BlkId blkid(bn->get_node_id().to_integer());
        impl->m_blkstore->free_blk(blkid, boost::none, boost::none);
    }

    static void ref_node(SSDBtreeNode* bn) { CacheBuffer< BlkId >::ref((CacheBuffer< BlkId >&)*bn); }

    static void deref_node(SSDBtreeNode* bn) {
        // return CacheBuffer< BlkId >::deref_testz((CacheBuffer<BlkId> &)*bn);
        return CacheBuffer< BlkId >::deref((CacheBuffer< BlkId >&)*bn);
    }

private:
    BlkStore< VdevFixedBlkAllocatorPolicy, BtreeBufferDeclType >* m_blkstore;
};
} // namespace btree
} // namespace homeds
