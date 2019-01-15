//
// Created by Kadayam, Hari on 31/01/18.
//

#ifndef OMSTORE_BACKING_BTREE_HPP
#define OMSTORE_BACKING_BTREE_HPP

#include "physical_node.hpp"
#include <boost/intrusive_ptr.hpp>
#include <queue>

namespace homeds { namespace btree {

#define BtreeSpecificImplDeclType BtreeSpecificImpl< BtreeType, K, V, InteriorNodeType,\
                                         LeafNodeType, NodeSize, btree_req_type >

template< btree_type BtreeType, typename K, typename V, btree_node_type InteriorNodeType,
          btree_node_type LeafNodeType, size_t NodeSize , typename btree_req_type >


class BtreeNode;

#define BtreeNodeDeclType BtreeNode<BtreeType, K, V, InteriorNodeType, \
                                    LeafNodeType, NodeSize, btree_req_type>

template<
        btree_type BtreeType,
        typename K,
        typename V,
        btree_node_type InteriorNodeType,
        btree_node_type LeafNodeType,
        size_t NodeSize,
        typename btree_req_type >
class BtreeSpecificImpl {
    typedef std::function< void (boost::intrusive_ptr<btree_req_type> cookie, 
        std::error_condition status) > comp_callback;
public:
    using HeaderType = homeds::btree::EmptyClass;

#if 0
#define call_variant_method(bn, mname, ...) \
        ( \
            ((VariantNode< LeafNodeType, K, V, NodeSize > *)get_physical(bn))->is_leaf() ? \
               ((VariantNode< LeafNodeType, K, V, NodeSize > *)get_physical(bn))->mname(__VA_ARGS__) : \
               ((VariantNode< InteriorNodeType, K, V, NodeSize > *)get_physical(bn))->mname(__VA_ARGS__) \
        )
#endif

    static std::unique_ptr<BtreeSpecificImplDeclType> init_btree(BtreeConfig &cfg, 
                    void *btree_specific_context, comp_callback comp_cb, bool is_in_recovery = false);
    static void recovery_cmpltd(BtreeSpecificImplDeclType *impl);
    static uint8_t *get_physical(const BtreeNodeDeclType *bn);
    static uint32_t get_node_area_size(BtreeSpecificImplDeclType *impl);

    static boost::intrusive_ptr<BtreeNodeDeclType> alloc_node(BtreeSpecificImplDeclType *impl, bool is_leaf,
            bool &is_new_allocation,// indicates if allocated node is same as copy_from
            boost::intrusive_ptr<BtreeNodeDeclType> copy_from = nullptr);
    static boost::intrusive_ptr<BtreeNodeDeclType> read_node(BtreeSpecificImplDeclType *impl, bnodeid_t id);
    static void write_node(BtreeSpecificImplDeclType *impl, 
                           boost::intrusive_ptr<BtreeNodeDeclType> bn, 
                           std::deque<boost::intrusive_ptr<btree_req_type>> &dependent_req_q, 
                           boost::intrusive_ptr<btree_req_type> cookie, bool is_sync);
    static void free_node(BtreeSpecificImplDeclType *impl, 
                          boost::intrusive_ptr<BtreeNodeDeclType> bn, 
                          std::deque<boost::intrusive_ptr<btree_req_type>> &dependent_req_q);
    static void read_node_lock(BtreeSpecificImplDeclType *impl, 
                               boost::intrusive_ptr<BtreeNodeDeclType> bn, bool is_write_modifiable,  
                               std::deque<boost::intrusive_ptr<btree_req_type>> *dependent_req_q);

    static void copy_node(BtreeSpecificImplDeclType *impl, boost::intrusive_ptr<BtreeNodeDeclType> copy_from, boost::intrusive_ptr<BtreeNodeDeclType> copy_to);
    static void swap_node(BtreeSpecificImplDeclType *impl, boost::intrusive_ptr<BtreeNodeDeclType> node1, boost::intrusive_ptr<BtreeNodeDeclType> node2);
    static void ref_node(BtreeNodeDeclType *bn);
    static void deref_node(BtreeNodeDeclType *bn);
};
} }
#endif //OMSTORE_BACKING_BTREE_HPP
