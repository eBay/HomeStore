//
// Created by Kadayam, Hari on 02/02/18.
//

#pragma once

#include "physical_node.hpp"
#include "btree_internal.h"
#include "btree_store.hpp"
#include <utility/atomic_counter.hpp>
#include <utility/obj_life_counter.hpp>
#include <cstdint>

namespace homeds {
namespace btree {

// using namespace sisl;
struct transient_hdr_t {
    sisl::atomic_counter< uint16_t > upgraders;
    folly::SharedMutexReadPriority lock;
    /* these variables are accessed without taking lock and are not expected to change after init */
    bool is_leaf;
#ifndef NDEBUG
    int is_lock;
#endif
    transient_hdr_t() :
            upgraders(0),
            is_leaf(false)
#ifndef NDEBUG
            ,
            is_lock(-1)
#endif
                {};
};

template < btree_node_type NodeType, typename K, typename V >
class VariantNode {
public:
    VariantNode(bnodeid_t id, bool init, const BtreeConfig& cfg);
    VariantNode(bnodeid_t* id, bool init, const BtreeConfig& cfg);
    void get(int ind, BtreeValue* outval, bool copy) const;

    // Insert the key and value in provided index
    // Assumption: Node lock is already taken
    btree_status_t insert(int ind, const BtreeKey& key, const BtreeValue& val);

#ifndef NDEBUG
    std::string to_string() const;
#endif

    void remove(int ind);
    void remove(int ind_s, int ind_e);
    void update(int ind, const BtreeValue& val);
    void update(int ind, const BtreeKey& key, const BtreeValue& val);

    uint32_t move_out_to_right_by_entries(const BtreeConfig& cfg, VariantNode< NodeType, K, V >* other_node,
                                          uint32_t nentries);
    uint32_t move_out_to_right_by_size(const BtreeConfig& cfg, VariantNode< NodeType, K, V >* other_node,
                                       uint32_t size);
    uint32_t move_in_from_right_by_entries(const BtreeConfig& cfg, VariantNode< NodeType, K, V >* other_node,
                                           uint32_t nentries);
    uint32_t move_in_from_right_by_size(const BtreeConfig& cfg, VariantNode< NodeType, K, V >* other_node,
                                        uint32_t size);

    uint32_t get_available_size(const BtreeConfig& cfg) const;
    bool is_split_needed(const BtreeConfig& cfg, const BtreeKey& key, const BtreeValue& value, int* out_ind_hint,
                         btree_put_type& putType, BtreeUpdateRequest< K, V >* bur = nullptr) const;

    uint32_t get_nth_obj_size(int ind) const;
    void get_nth_key(int ind, BtreeKey* outkey, bool copykey) const;
    void get_nth_value(int ind, BtreeValue* outval, bool copy) const;
    int compare_nth_key(const BtreeKey& cmp_key, int ind) const;
    int compare_nth_key_range(const BtreeSearchRange& range, int ind) const;
    bool overlap_nth_key_range(const BtreeSearchRange& range, int ind) const;
    void get_edge_value(BtreeValue* outval) const;
    void set_nth_key(uint32_t ind, BtreeKey* key);

private:
    /////////////// Other Internal Methods /////////////
    void set_nth_obj(int ind, const BtreeKey& k, const BtreeValue& v);
    uint32_t get_available_entries(const BtreeConfig& cfg) const;
    inline uint32_t get_obj_key_size(int ind) const;
    inline uint32_t get_obj_value_size(int ind) const;
    uint8_t* get_nth_obj(int ind);
    void set_nth_value(int ind, const BtreeValue& v);
};

#define LeafVariantNode VariantNode< LeafNodeType, K, V >
#define InteriorVariantNode VariantNode< InteriorNodeType, K, V >
#define LeafPhysicalNode PhysicalNode< LeafVariantNode, K, V >
#define InteriorPhysicalNode PhysicalNode< InteriorVariantNode, K, V >
#define BtreeNodePtr boost::intrusive_ptr< btree_node_t >

#define to_variant_node(bn)                                                                                            \
    (((LeafVariantNode*)btree_store_t::get_physical(bn))->is_leaf()                                                    \
         ? (LeafVariantNode*)btree_store_t::get_physical((bn))                                                         \
         : (InteriorVariantNode*)btree_store_t::get_physical((bn)))

#define to_variant_node_const(bn)                                                                                      \
    (((const LeafVariantNode*)btree_store_t::get_physical(bn))->is_leaf()                                              \
         ? (const LeafVariantNode*)btree_store_t::get_physical((bn))                                                   \
         : (const InteriorVariantNode*)btree_store_t::get_physical((bn)))

#define to_physical_node(bn)                                                                                           \
    (((LeafPhysicalNode*)btree_store_t::get_physical(bn))->is_leaf()                                                   \
         ? (LeafPhysicalNode*)btree_store_t::get_physical((bn))                                                        \
         : (InteriorPhysicalNode*)btree_store_t::get_physical((bn)))

#define to_physical_node_const(bn)                                                                                     \
    (((const LeafPhysicalNode*)btree_store_t::get_physical(bn))->is_leaf()                                             \
         ? (const LeafPhysicalNode*)btree_store_t::get_physical((bn))                                                  \
         : (const InteriorPhysicalNode*)btree_store_t::get_physical((bn)))

#define call_variant_method(bn, mname, ...) (to_variant_node(bn)->mname(__VA_ARGS__))
#define call_variant_method_const(bn, mname, ...) (to_variant_node_const(bn)->mname(__VA_ARGS__))
#define call_physical_method(bn, mname, ...) (to_physical_node(bn)->mname(__VA_ARGS__))
#define call_physical_method_const(bn, mname, ...) (to_physical_node_const(bn)->mname(__VA_ARGS__))

template < btree_store_type BtreeStoreType, typename K, typename V, btree_node_type InteriorNodeType,
           btree_node_type LeafNodeType, typename btree_req_type >
class BtreeNode
        : public btree_store_t::HeaderType,
          sisl::ObjLifeCounter< BtreeNode< BtreeStoreType, K, V, InteriorNodeType, LeafNodeType, btree_req_type > > {
public:
    transient_hdr_t m_common_header;

public:
    BtreeNode();
    ~BtreeNode() = default;
    void init_btree_node();

    // All CRUD on a node
    // Base methods provided by PhysicalNodes
    bool put(const BtreeKey& key, const BtreeValue& val, btree_put_type put_type, BtreeValue& existing_val);
    auto find(const BtreeKey& find_key, BtreeValue* outval, bool copy_val = true) const;
    auto find(const BtreeSearchRange& range, BtreeKey* outkey, BtreeValue* outval, bool copy_key = true,
              bool copy_val = true) const;
    uint32_t get_all(const BtreeSearchRange& range, uint32_t max_count, int& start_ind, int& end_ind,
                     std::vector< std::pair< K, V > >* out_values = nullptr);
    bool remove_one(const BtreeSearchRange& range, BtreeKey* outkey, BtreeValue* outval);

    // Methods the variant nodes need to override from
    void get(int ind, BtreeValue* outval, bool copy) const;
    btree_status_t insert(const BtreeKey& key, const BtreeValue& val);
    btree_status_t insert(int ind, const BtreeKey& key, const BtreeValue& val);
    void remove(int ind);
    void remove(int ind_s, int ind_e);
    void update(int ind, const BtreeValue& val);
    void update(int ind, const BtreeKey& key, const BtreeValue& val);
    std::string to_string() const;

    /* Provides the occupied data size within the node */
    bool is_leaf() const;
    void set_leaf(bool leaf);
    uint32_t get_total_entries() const;
    void set_total_entries(uint32_t);
    uint32_t get_available_size(const BtreeConfig& cfg) const;
    bnodeid_t get_node_id() const;
    uint64_t get_node_id_int() const;
    void set_node_id(bnodeid_t id);
    bnodeid_t get_next_bnode() const;
    void set_next_bnode(bnodeid_t b);
    bnodeid_t get_edge_id() const;
    void invalidate_edge();
    void set_edge_id(bnodeid_t edge);

    void set_valid_node(bool valid);
    bool is_valid_node() const;
    void init();

    void get_last_key(BtreeKey* out_lastkey);
    void get_first_key(BtreeKey* out_firstkey);
    uint32_t get_occupied_size(const BtreeConfig& cfg) const;
    void get_adjacent_indicies(uint32_t cur_ind, vector< int >& indices_list, uint32_t max_indices) const;

    uint64_t get_gen() const;
    void inc_gen();
    void flip_pc_gen_flag();
    void set_gen(uint64_t g);

    ///////////// Move and Delete related operations on a node //////////////
    bool is_split_needed(const BtreeConfig& cfg, const BtreeKey& k, const BtreeValue& v, int* out_ind_hint,
                         btree_put_type& putType, BtreeUpdateRequest< K, V >* bur = nullptr) const;
    bool is_merge_needed(const BtreeConfig& cfg) const;

    /* Following methods need to make best effort to move from other node upto provided entries or size. It should
     * return how much it was able to move actually (either entries or size)
     */
    uint32_t move_out_to_right_by_entries(const BtreeConfig& cfg, boost::intrusive_ptr< BtreeNode >& other_node,
                                          uint32_t nentries);
    uint32_t move_out_to_right_by_size(const BtreeConfig& cfg, boost::intrusive_ptr< BtreeNode >& other_node,
                                       uint32_t size);
    uint32_t move_in_from_right_by_entries(const BtreeConfig& cfg, boost::intrusive_ptr< BtreeNode >& other_node,
                                           uint32_t nentries);
    uint32_t move_in_from_right_by_size(const BtreeConfig& cfg, boost::intrusive_ptr< BtreeNode >& other_node,
                                        uint32_t size);

    void lock(homeds::thread::locktype l);
    void unlock(homeds::thread::locktype l);
    void lock_upgrade();
    void lock_acknowledge();
    bool any_upgrade_waiters();

    friend void intrusive_ptr_add_ref(btree_node_t* n) { btree_store_t::ref_node(n); }

    friend void intrusive_ptr_release(btree_node_t* n) { btree_store_t::deref_node(n); }
    void get_nth_key(int ind, BtreeKey* outkey, bool copy) const;
    void set_nth_key(uint32_t ind, BtreeKey* key);

protected:
    uint32_t get_nth_obj_size(int ind) const;
    void get_nth_value(int ind, BtreeValue* outval, bool copy) const;
    void get_nth_element(int ind, BtreeKey* out_key, BtreeValue* out_val, bool is_copy) const;

protected:
    // Compares the nth key (n=ind) with given key (cmp_key) and returns -1, 0, 1 if cmp_key <=> nth_key respectively
    int compare_nth_key(const BtreeKey& cmp_key, int ind) const;
    int compare_nth_key_range(const BtreeSearchRange& range, int ind) const;
    bool overlap_nth_key_range(const BtreeSearchRange& range, int ind) const;
    void get_edge_value(BtreeValue* outval) const;
};
} // namespace btree
} // namespace homeds
