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

#define btree_store_t BtreeStore< BtreeStoreType, K, V, InteriorNodeType, LeafNodeType >

template < btree_store_type BtreeStoreType, typename K, typename V, btree_node_type InteriorNodeType,
           btree_node_type LeafNodeType >
class BtreeNode;

template < btree_store_type BtreeStoreType, typename K, typename V, btree_node_type InteriorNodeType,
           btree_node_type LeafNodeType >
class Btree;
#define btree_t Btree< BtreeStoreType, K, V, InteriorNodeType, LeafNodeType >

#define btree_node_t BtreeNode< BtreeStoreType, K, V, InteriorNodeType, LeafNodeType >
#define BtreeNodePtr boost::intrusive_ptr< btree_node_t >

template < btree_store_type BtreeStoreType, typename K, typename V, btree_node_type InteriorNodeType,
           btree_node_type LeafNodeType >
class BtreeStore {
    struct superblock;

public:
    using HeaderType = homeds::btree::EmptyClass;

    static std::unique_ptr< btree_store_t > init_btree(btree_t* base_btree, BtreeConfig& cfg);
    static uint8_t* get_physical(const btree_node_t* bn);
    static uint32_t get_node_area_size(btree_store_t* store);
    static void update_sb(btree_store_t* store, btree_super_block& sb, btree_cp_superblock* cp_sb, bool is_recovery);
    static btree_cp_id_ptr attach_prepare_cp(btree_store_t* store, const btree_cp_id_ptr& cur_cp_id, bool is_last_cp,
                                             bool blkalloc_checkpoint);
    static void cp_start(btree_store_t* store, const btree_cp_id_ptr& cp_id, cp_comp_callback cb);
    static void truncate(btree_store_t* store, const btree_cp_id_ptr& cp_id);
    static void destroy_done(btree_store_t* store);
    static void flush_free_blks(btree_store_t* store, const btree_cp_id_ptr& btree_id,
                                std::shared_ptr< homestore::blkalloc_cp_id >& blkalloc_id);

    static BtreeNodePtr alloc_node(btree_store_t* store, bool is_leaf,
                                   bool& is_new_allocation, // indicates if allocated node is same as copy_from
                                   const BtreeNodePtr& copy_from = nullptr);
    static BtreeNodePtr read_node(btree_store_t* store, bnodeid_t id);

    static btree_status_t write_node(btree_store_t* store, const BtreeNodePtr& bn, const BtreeNodePtr& dependent_bn,
                                     const btree_cp_id_ptr& cp_id);
    static void free_node(btree_store_t* store, const BtreeNodePtr& bn, bool mem_only, const btree_cp_id_ptr& cp_id);
    static btree_status_t refresh_node(btree_store_t* store, const BtreeNodePtr& bn, bool is_write_modifiable,
                                       const btree_cp_id_ptr& cp_id);

    static void swap_node(btree_store_t* store, const BtreeNodePtr& node1, const BtreeNodePtr& node2);
    static void copy_node(btree_store_t* store, const BtreeNodePtr& copy_from, const BtreeNodePtr& copy_to);
    static void ref_node(btree_node_t* bn);
    static bool deref_node(btree_node_t* bn);
    static btree_status_t write_node_sync(btree_store_t* store, const BtreeNodePtr& bn);
    static void cp_done(trigger_cp_callback cb);
    static void create_done(btree_store_t* store, bnodeid_t m_root_node);

    // Journal entry section
    static sisl::io_blob make_journal_entry(journal_op op, bool is_root, bt_node_gen_pair pair);
    static inline constexpr btree_journal_entry* blob_to_entry(const sisl::io_blob& b);
    static void append_node_to_journal(sisl::io_blob& j_iob, bt_journal_node_op node_op, const BtreeNodePtr& node,
                                       const btree_cp_id_ptr& cp_id, bool append_last_key = false);
    static void write_journal_entry(btree_store_t* store, const btree_cp_id_ptr& cp_id, sisl::io_blob& j_iob);
};

} // namespace btree
} // namespace homeds
#endif // OMSTORE_BACKING_BTREE_HPP
