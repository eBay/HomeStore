//
// Created by Kadayam, Hari on 31/01/18.
//

#ifndef OMSTORE_BACKING_BTREE_HPP
#define OMSTORE_BACKING_BTREE_HPP

#include "physical_node.hpp"
#include <boost/intrusive_ptr.hpp>

namespace omds { namespace btree {

#define BtreeSpecificImplDeclType BtreeSpecificImpl<BtreeType, K, V, InteriorNodeType, LeafNodeType, NodeSize>

template< btree_type BtreeType, typename K, typename V, btree_node_type InteriorNodeType,
          btree_node_type LeafNodeType,size_t NodeSize >
class BtreeNode;

#define BtreeNodeDeclType BtreeNode<BtreeType, K, V, InteriorNodeType, LeafNodeType, NodeSize>

template<
        btree_type BtreeType,
        typename K,
        typename V,
        btree_node_type InteriorNodeType,
        btree_node_type LeafNodeType,
        size_t NodeSize>
class BtreeSpecificImpl {
public:
    using HeaderType = omds::btree::EmptyClass;

#if 0
#define call_variant_method(bn, mname, ...) \
        ( \
            ((VariantNode< LeafNodeType, K, V, NodeSize > *)get_physical(bn))->is_leaf() ? \
               ((VariantNode< LeafNodeType, K, V, NodeSize > *)get_physical(bn))->mname(__VA_ARGS__) : \
               ((VariantNode< InteriorNodeType, K, V, NodeSize > *)get_physical(bn))->mname(__VA_ARGS__) \
        )
#endif

    static uint8_t *get_physical(const BtreeNodeDeclType *bn);
    static uint32_t get_node_area_size();

    static boost::intrusive_ptr<BtreeNodeDeclType> alloc_node(bool is_leaf);
    static boost::intrusive_ptr<BtreeNodeDeclType> read_node(bnodeid_t id);
    static void ref_node(BtreeNodeDeclType *bn);
    static bool deref_node(BtreeNodeDeclType *bn);
    static void write_node(boost::intrusive_ptr<BtreeNodeDeclType> bn);
    static void free_node(boost::intrusive_ptr<BtreeNodeDeclType> bn);
};
} }
#endif //OMSTORE_BACKING_BTREE_HPP
