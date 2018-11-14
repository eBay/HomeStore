//
// Created by Kadayam, Hari on 02/02/18.
//

#pragma once

#include "physical_node.hpp"
#include "btree_internal.h"
#include "btree_specific_impl.hpp"

namespace homeds { namespace btree {

typedef struct {
    homeds::atomic_counter< uint16_t > upgraders;
    folly::SharedMutexReadPriority lock;
} transient_hdr_t;

template< btree_node_type NodeType, typename K, typename V, size_t NodeSize >
class VariantNode {
public:
    VariantNode( bnodeid_t id, bool init, const BtreeConfig &cfg);
    VariantNode( bnodeid_t *id, bool init, const BtreeConfig &cfg);
    void get(int ind, BtreeValue *outval, bool copy) const;

    // Insert the key and value in provided index
    // Assumption: Node lock is already taken
    void insert(int ind, const BtreeKey &key, const BtreeValue &val);

#ifndef NDEBUG
    std::string to_string() const;
#endif

    void remove(int ind);
    void remove(int ind_s,int ind_e);
    void update(int ind, const BtreeValue &val);
    void update(int ind, const BtreeKey &key, const BtreeValue &val);

    uint32_t move_out_to_right_by_entries(const BtreeConfig &cfg, VariantNode<NodeType, K, V, NodeSize> *other_node,
                                          uint32_t nentries);
    uint32_t move_out_to_right_by_size(const BtreeConfig &cfg, VariantNode<NodeType, K, V, NodeSize> *other_node,
                                       uint32_t size);
    uint32_t move_in_from_right_by_entries(const BtreeConfig &cfg, VariantNode<NodeType, K, V, NodeSize> *other_node,
                                           uint32_t nentries);
    uint32_t move_in_from_right_by_size(const BtreeConfig &cfg, VariantNode<NodeType, K, V, NodeSize> *other_node,
                                        uint32_t size);
    
    uint32_t get_available_size(const BtreeConfig &cfg) const;
    bool is_split_needed(const BtreeConfig &cfg, const BtreeKey &key, const BtreeValue &value, int *out_ind_hint) const;

    uint32_t get_nth_obj_size(int ind) const;
    void get_nth_key(int ind, BtreeKey *outkey, bool copykey) const;
    void get_nth_value(int ind, BtreeValue *outval, bool copy) const;
    int compare_nth_key(const BtreeKey &cmp_key, int ind) const;
    int compare_nth_key_range(const BtreeSearchRange &range, int ind) const;

private:
    /////////////// Other Internal Methods /////////////
    void set_nth_obj(int ind, const BtreeKey &k, const BtreeValue &v);
    uint32_t get_available_entries(const BtreeConfig &cfg) const;
    inline uint32_t get_obj_key_size(int ind) const;
    inline uint32_t get_obj_value_size(int ind) const;
    uint8_t *get_nth_obj(int ind);

    void set_nth_key(int ind, const BtreeKey &k);
    void set_nth_value(int ind, const BtreeValue &v);
};

#define LeafVariantNodeDeclType           VariantNode< LeafNodeType, K, V, NodeSize >
#define InteriorVariantNodeDeclType       VariantNode< InteriorNodeType, K, V, NodeSize >
#define LeafPhysicalNodeDeclType          PhysicalNode< LeafVariantNodeDeclType, K, V, NodeSize >
#define InteriorPhysicalNodeDeclType      PhysicalNode< InteriorVariantNodeDeclType, K, V, NodeSize >

#define to_variant_node(bn)  \
        ( \
            ((LeafVariantNodeDeclType *)BtreeSpecificImplDeclType::get_physical(bn))->is_leaf() ? \
                (LeafVariantNodeDeclType *)BtreeSpecificImplDeclType::get_physical((bn)) :   \
                (InteriorVariantNodeDeclType *)BtreeSpecificImplDeclType::get_physical((bn)) \
        )

#define to_variant_node_const(bn)  \
        ( \
            ((const LeafVariantNodeDeclType *)BtreeSpecificImplDeclType::get_physical(bn))->is_leaf() ? \
                (const LeafVariantNodeDeclType *)BtreeSpecificImplDeclType::get_physical((bn)) :        \
                (const InteriorVariantNodeDeclType *)BtreeSpecificImplDeclType::get_physical((bn))      \
        )

#define to_physical_node(bn) \
        ( \
            ((LeafPhysicalNodeDeclType *)BtreeSpecificImplDeclType::get_physical(bn))->is_leaf() ? \
                 (LeafPhysicalNodeDeclType *)BtreeSpecificImplDeclType::get_physical((bn)) :       \
                 (InteriorPhysicalNodeDeclType *)BtreeSpecificImplDeclType::get_physical((bn))     \
        )

#define to_physical_node_const(bn) \
        ( \
            ((const LeafPhysicalNodeDeclType *)BtreeSpecificImplDeclType::get_physical(bn))->is_leaf() ? \
                 (const LeafPhysicalNodeDeclType *)BtreeSpecificImplDeclType::get_physical((bn)) :       \
                 (const InteriorPhysicalNodeDeclType *)BtreeSpecificImplDeclType::get_physical((bn))     \
        )

#define call_variant_method(bn, mname, ...)        (to_variant_node(bn)->mname(__VA_ARGS__))
#define call_variant_method_const(bn, mname, ...)  (to_variant_node_const(bn)->mname(__VA_ARGS__))
#define call_physical_method(bn, mname, ...)       (to_physical_node(bn)->mname(__VA_ARGS__))
#define call_physical_method_const(bn, mname, ...) (to_physical_node_const(bn)->mname(__VA_ARGS__))

#define BtreeNodeDeclType BtreeNode<BtreeType, K, V, InteriorNodeType, LeafNodeType, NodeSize, btree_req_type>
template<
        btree_type BtreeType,
        typename K,
        typename V,
        btree_node_type InteriorNodeType,
        btree_node_type LeafNodeType,
        size_t NodeSize,
        typename btree_req_type
        >
class BtreeNode : public BtreeSpecificImplDeclType::HeaderType {
private:
    transient_hdr_t m_common_header;

public:
    BtreeNode();
    ~BtreeNode() = default;
    void init_btree_node();

    // All CRUD on a node
    // Base methods provided by PhysicalNodes
    bool put(const BtreeKey &key, const BtreeValue &val, PutType put_type, std::shared_ptr<BtreeValue> &existing_val);
    auto find(const BtreeSearchRange &range, BtreeKey *outkey, BtreeValue *outval) const;
    bool remove_one(const BtreeSearchRange &range, BtreeKey *outkey, BtreeValue *outval);

    // Methods the variant nodes need to override from
    void get(int ind, BtreeValue *outval, bool copy) const;
    void insert(const BtreeKey &key, const BtreeValue &val);
    void insert(int ind, const BtreeKey &key, const BtreeValue &val);
    void remove(int ind);
    void remove(int ind_s, int ind_e);
    void update(int ind, const BtreeValue &val);
    void update(int ind, const BtreeKey &key, const BtreeValue &val);

#ifndef NDEBUG
    std::string to_string() const;
#endif

    /* Provides the occupied data size within the node */
    bool is_leaf() const;
    void set_leaf(bool leaf);
    uint32_t get_total_entries() const;
    uint32_t get_available_size(const BtreeConfig &cfg) const;
    bnodeid_t get_node_id() const;
    void set_node_id(bnodeid_t id);
    bnodeid_t get_next_bnode() const;
    void set_next_bnode(bnodeid_t b);
    bnodeid_t get_edge_id() const;
    void invalidate_edge();
    void set_edge_id(bnodeid_t edge);

    void set_valid_node(bool valid);
    bool is_valid_node() const;

    void get_last_key(BtreeKey *out_lastkey);
    void get_first_key(BtreeKey *out_firstkey);
    uint32_t get_occupied_size(const BtreeConfig &cfg) const;
    void get_adjacent_indicies(uint32_t cur_ind, vector< int > &indices_list, uint32_t max_indices) const;

    uint64_t get_gen() const;
    void inc_gen();
    void flip_pc_gen_flag();
    void set_gen(uint64_t g);

    ///////////// Move and Delete related operations on a node //////////////
    bool is_split_needed(const BtreeConfig &cfg, const BtreeKey &k, const BtreeValue &v, int *out_ind_hint) const;
    bool is_merge_needed(const BtreeConfig &cfg) const;

    /* Following methods need to make best effort to move from other node upto provided entries or size. It should
     * return how much it was able to move actually (either entries or size)
     */
    uint32_t move_out_to_right_by_entries(const BtreeConfig &cfg, boost::intrusive_ptr<BtreeNodeDeclType> &other_node,
                                          uint32_t nentries);
    uint32_t move_out_to_right_by_size(const BtreeConfig &cfg, boost::intrusive_ptr<BtreeNodeDeclType> &other_node,
                                       uint32_t size);
    uint32_t move_in_from_right_by_entries(const BtreeConfig &cfg, boost::intrusive_ptr<BtreeNodeDeclType> &other_node,
                                           uint32_t nentries);
    uint32_t move_in_from_right_by_size(const BtreeConfig &cfg, boost::intrusive_ptr<BtreeNodeDeclType> &other_node,
                                        uint32_t size);
    
    void lock(homeds::thread::locktype l);
    void unlock(homeds::thread::locktype l);
    void lock_upgrade();
    void lock_acknowledge();
    bool any_upgrade_waiters();

    friend void intrusive_ptr_add_ref(BtreeNodeDeclType *n) {
        BtreeSpecificImplDeclType::ref_node(n);
    }

    friend void intrusive_ptr_release(BtreeNodeDeclType *n) {
        if (BtreeSpecificImplDeclType::deref_node(n)) {
            n->~BtreeNodeDeclType();
            BtreeNodeAllocator<NodeSize>::deallocate((uint8_t *)n);
        }
    }
    void get_nth_key(int ind, BtreeKey *outkey, bool copy) const;
protected:
    uint32_t get_nth_obj_size(int ind) const;
    void get_nth_value(int ind, BtreeValue *outval, bool copy) const;

    // Compares the nth key (n=ind) with given key (cmp_key) and returns -1, 0, 1 if cmp_key <=> nth_key respectively
    int compare_nth_key(const BtreeKey &cmp_key, int ind) const;
    int compare_nth_key_range(const BtreeSearchRange &range, int ind) const;
};
}}
