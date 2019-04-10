//
// Created by Kadayam, Hari on 31/01/18.
//

#ifndef OMSTORE_BACKING_BTREE_HPP
#define OMSTORE_BACKING_BTREE_HPP

#include "physical_node.hpp"
#include <boost/intrusive_ptr.hpp>
#include <queue>

namespace homeds {
namespace btree {

#define btree_store_t BtreeStore< BtreeStoreType, K, V, InteriorNodeType, LeafNodeType, NodeSize, btree_req_type >

template < btree_store_type BtreeStoreType, typename K, typename V, btree_node_type InteriorNodeType,
           btree_node_type LeafNodeType, size_t NodeSize, typename btree_req_type >
class BtreeNode;

#define btree_node_t BtreeNode< BtreeStoreType, K, V, InteriorNodeType, LeafNodeType, NodeSize, btree_req_type >
#define BtreeNodePtr boost::intrusive_ptr< btree_node_t >

template < btree_store_type BtreeStoreType, typename K, typename V, btree_node_type InteriorNodeType,
           btree_node_type LeafNodeType, size_t NodeSize, typename btree_req_type >
class BtreeStore {
    typedef std::function< void(boost::intrusive_ptr< btree_req_type > cookie, btree_status_t status) >
        comp_callback;

public:
    using HeaderType = homeds::btree::EmptyClass;

    static std::unique_ptr< btree_store_t > init_btree(BtreeConfig& cfg, void* btree_specific_context,
                                                       comp_callback comp_cb);
    static uint8_t*                         get_physical(const btree_node_t* bn);
    static uint32_t                         get_node_area_size(btree_store_t* store);

    static BtreeNodePtr alloc_node(btree_store_t* store, bool is_leaf,
                                   bool&        is_new_allocation, // indicates if allocated node is same as copy_from
                                   BtreeNodePtr copy_from = nullptr);
    static BtreeNodePtr read_node(btree_store_t* store, bnodeid_t id);

    static btree_status_t         write_node(btree_store_t* store, BtreeNodePtr bn, btree_multinode_req_ptr op);
    static void         free_node(btree_store_t* store, BtreeNodePtr bn, btree_multinode_req_ptr op, bool mem_only = false);
    static btree_status_t refresh_node(btree_store_t *store, BtreeNodePtr bn, 
                btree_multinode_req_ptr op, bool is_write_modifiable);

    static void         swap_node(btree_store_t* store, BtreeNodePtr node1, BtreeNodePtr node2);
    static void         copy_node(btree_store_t* store, BtreeNodePtr copy_from, BtreeNodePtr copy_to);
    static void         ref_node(btree_node_t* bn);
    static bool         deref_node(btree_node_t* bn);
};
} // namespace btree
} // namespace homeds
#endif // OMSTORE_BACKING_BTREE_HPP
