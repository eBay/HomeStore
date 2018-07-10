/*
 *  Created on: 14-May-2016
 *      Author: Hari Kadayam
 *
 *  Copyright © 2016 Kadayam, Hari. All rights reserved.
 */
#pragma once

#include <iostream>
#include <cassert>
#include <pthread.h>
#include <vector>
#include <atomic>
#include <array>
#include "homeds/thread/lock.hpp"
#include "btree_internal.h"
#include "btree_stats.hpp"
#include "btree_node.cpp"
#include "physical_node.hpp"
#include <sds_logging/logging.h>
#include <boost/intrusive_ptr.hpp>
#include <csignal>

using namespace std;
using namespace homeds::thread;

#ifndef NDEBUG
#define MAX_BTREE_DEPTH   100
#endif

SDS_LOGGING_DECL(VMOD_BTREE_MERGE, VMOD_BTREE_SPLIT)

namespace homeds { namespace btree {

#if 0
#define container_of(ptr, type, member) ({                      \
        (type *)( (char *)ptr - offsetof(type,member) );})
#endif

#define BtreeDeclType Btree<BtreeType, K, V, InteriorNodeType, LeafNodeType, NodeSize>
#define BtreeNodePtr boost::intrusive_ptr< BtreeNodeDeclType >

template<
        btree_type BtreeType,
        typename K,
        typename V,
        btree_node_type InteriorNodeType,
        btree_node_type LeafNodeType,
        size_t NodeSize = 8192>
class Btree
{
public:
#ifdef CLASS_DEFINITIONS
    Btree(BtreeConfig &cfg);

    /*
     * This function inserts the key/value pair into btree. The BtreeKey and BtreeValue must be overridden by the
     * caller. If key already present will return false.
     */
    bool insert(BtreeKey &k, BtreeValue &v);

    /*
     * Given a key, returns the value. Returns if object found or not
     */
    bool get(BtreeKey &key, BtreeValue *outval);

    /*
     * Given a startKey and endKey, gets any key within the range
     */
    bool get_any(BtreeRegExKey &rkey, BtreeValue *outval);

    /*
     * Remove the key from the btree. Returns true if found and removed
     */
    bool remove(BtreeKey &key);

    /*
     * Remove any one key between start key to end key. Returns true if found and removed. Second version has
     * additional parameter left_leaning, which means while removing, try to give preference to left.
     */
    bool remove_any(BtreeRegExKey &rkey);

    /*
     * Update the key with new value. If upsert is false, will fail if key does not exist. If upsert is true, will do
     * insert if key does not exist.
     */
    bool update(BtreeKey& key, BtreeValue& val, bool upsert = true);

    /*
     * Update the key with new_val if the cur_val is equal to old_val. Following operation is done atomically.
     * Returns true if successful, else false.
     */
    bool find_and_modify(BtreeKey &key, BtreeValue &new_val, BtreeValue &old_val);

#endif
    virtual ~Btree() = default;

private:
#ifdef CLASS_DEFINITIONS
    bool do_insert(BtreeNodePtr my_node, homeds::thread::locktype_t curlock, BtreeKey& k, BtreeValue& v, int ind_hint);

    bool do_get(BtreeNodePtr mynode, BtreeKey &key, BtreeValue *outval);

    btree_status_t do_remove(BtreeNodePtr mynode, homeds::thread::locktype_t curlock, BtreeKey &key);

    bool upgrade_node(BtreeNodePtr mynode, BtreeNodePtr childnode, homeds::thread::locktype_t &curlock,
                      homeds::thread::locktype_t child_curlock);
    void split_node(BtreeNodePtr parent_node, BtreeNodePtr child_node, uint32_t parent_ind, BtreeKey **out_split_key);
    bool merge_nodes(BtreeNodePtr parent_node, std::vector<uint32_t> &indices_list);

    PhysicalNode* get_child_node(BtreeNodePtr int_node, homeds::thread::locktype_t curlock, BtreeKey& key, uint32_t &outind);
    PhysicalNode* get_child_node_range(BtreeNodePtr int_node, KeyRegex& kr, uint32_t &outind, bool *isfound);

    void check_split_root();
    void check_collapse_root();

    BtreeNodePtr alloc_leaf_node();
    BtreeNodePtr alloc_interior_node();
    void lock_node(BtreeNodePtr node, homeds::thread::locktype_t type);
    void unlock_node(BtreeNodePtr node, bool release);

protected:
    virtual uint32_t get_node_size() {return m_btree_cfg.get_node_size();};
    virtual uint32_t get_max_objs() {return m_btree_cfg.get_max_objs();};
    virtual uint32_t get_max_nodes() {return m_max_nodes;};
    virtual void create_root_node();
#endif

private:
    bnodeid_t m_root_node;
    homeds::thread::RWLock m_btree_lock;

    uint32_t m_max_nodes;
    BtreeConfig m_btree_cfg;
    BtreeStats m_stats;

    std::unique_ptr<BtreeSpecificImplDeclType> m_btree_specific_impl;

#ifndef NDEBUG
    static thread_local int wr_locked_count;
    static thread_local std::array<BtreeNodeDeclType *, MAX_BTREE_DEPTH> wr_locked_nodes;

    static thread_local int rd_locked_count;
    static thread_local std::array<BtreeNodeDeclType *, MAX_BTREE_DEPTH> rd_locked_nodes;
#endif

    ////////////////// Implementation /////////////////////////
public:

    static BtreeDeclType *create_btree(BtreeConfig &cfg, void *btree_specific_context) {
        auto impl_ptr = BtreeSpecificImplDeclType::init_btree(cfg, btree_specific_context);
        return new Btree(cfg, std::move(impl_ptr));
    }

    Btree(BtreeConfig &cfg, std::unique_ptr<BtreeSpecificImplDeclType> btree_specific_impl) :
            m_btree_cfg(cfg) {
        m_btree_specific_impl = std::move(btree_specific_impl);
        BtreeNodeAllocator< NodeSize >::create();

        // TODO: Check if node_area_size need to include persistent header
        uint32_t node_area_size = BtreeSpecificImplDeclType::get_node_area_size(m_btree_specific_impl.get());
        m_btree_cfg.set_node_area_size(node_area_size);

        // calculate number of nodes
        uint32_t max_leaf_nodes = (m_btree_cfg.get_max_objs() *
                                   (m_btree_cfg.get_max_key_size() + m_btree_cfg.get_max_value_size()))
                                  / node_area_size + 1;
        max_leaf_nodes += (100 * max_leaf_nodes) / 60; // Assume 60% btree full

        m_max_nodes = max_leaf_nodes + ((double) max_leaf_nodes * 0.05) + 1; // Assume 5% for interior nodes
        create_root_node();
    }

    void put(const BtreeKey &k, const BtreeValue &v, PutType put_type) {
        homeds::thread::locktype acq_lock = homeds::thread::LOCKTYPE_READ;
        int ind;

#ifndef NDEBUG
        init_lock_debug();
        //assert(OmDB::getGlobalRefCount() == 0);
#endif

        m_btree_lock.read_lock();

	int retry_cnt = 0;
    retry:
	assert(rd_locked_count == 0 && wr_locked_count == 0);
        BtreeNodePtr root = BtreeSpecificImplDeclType::read_node(m_btree_specific_impl.get(), m_root_node);
        lock_node(root, acq_lock);
        bool is_leaf = root->is_leaf();

	retry_cnt++;
        if (root->is_split_needed(m_btree_cfg, k, v, &ind)) {
            // Time to do the split of root.
            unlock_node(root, acq_lock);
            m_btree_lock.unlock();
            check_split_root(k, v);

	    assert(rd_locked_count == 0 && wr_locked_count == 0);
            // We must have gotten a new root, need to start from scratch.
            m_btree_lock.read_lock();
            goto retry;
        } else if ((is_leaf) && (acq_lock != homeds::thread::LOCKTYPE_WRITE)) {
            // Root is a leaf, need to take write lock, instead of read, retry
            unlock_node(root, acq_lock);
            acq_lock = homeds::thread::LOCKTYPE_WRITE;
            goto retry;
        } else {
            bool success = do_put(root, acq_lock, k, v, ind, put_type);
            if (success == false) {
                // Need to start from top down again, since there is a race between 2 inserts or deletes.
                acq_lock = homeds::thread::LOCKTYPE_READ;
		assert(rd_locked_count == 0 && wr_locked_count == 0);
                goto retry;
            }
        }

        m_btree_lock.unlock();

#ifndef NDEBUG
        check_lock_debug();
        //assert(OmDB::getGlobalRefCount() == 0);
#endif
    }

    bool get(const BtreeKey &key, BtreeValue *outval) {
        return get(key, nullptr, outval);
    }

    bool get(const BtreeKey &key, BtreeKey *outkey, BtreeValue *outval) {
        return get_any(BtreeSearchRange(key), outkey, outval);
    }

    bool get_any(const BtreeSearchRange &range, BtreeKey *outkey, BtreeValue *outval) {
        bool is_found;
#ifndef NDEBUG
        init_lock_debug();
#endif
        //assert(OmDB::getGlobalRefCount() == 0);

        m_btree_lock.read_lock();
        BtreeNodePtr root = BtreeSpecificImplDeclType::read_node(m_btree_specific_impl.get(), m_root_node);
        lock_node(root, homeds::thread::locktype::LOCKTYPE_READ);

        is_found = do_get(root, range, outkey, outval);
        m_btree_lock.unlock();

        // TODO: Assert if key returned from do_get is same as key requested, incase of perfect match

#ifndef NDEBUG
        check_lock_debug();
        //assert(OmDB::getGlobalRefCount() == 0);
#endif
        return is_found;
    }

    /* Given a regex key, tries to get all data that falls within the regex. Returns all the values
     * and also number of values that fall within the ranges */
//    uint32_t get_multi(const BtreeSearchRange &range, std::vector<std::pair<BtreeKey *, BtreeValue *>> outval) {
//    }

    bool remove_any(const BtreeSearchRange &range, BtreeKey *outkey, BtreeValue *outval) {
        homeds::thread::locktype acq_lock = homeds::thread::locktype::LOCKTYPE_READ;
        bool is_found = false;

#ifndef NDEBUG
        init_lock_debug();
#endif

#ifdef REFCOUNT_DEBUG
        assert(OmDBGlobals::getGlobalRefCount() == 0);
#endif

        m_btree_lock.read_lock();

    retry:
        BtreeNodePtr root = BtreeSpecificImplDeclType::read_node(m_btree_specific_impl.get(), m_root_node);
        lock_node(root, acq_lock);
        bool is_leaf = root->is_leaf();

        if (root->get_total_entries() == 0) {
            if (is_leaf) {
                // There are no entries in btree.
                unlock_node(root, acq_lock);
                m_btree_lock.unlock();
                return false;
            }
            assert(root->get_edge_id() != INVALID_BNODEID);
            unlock_node(root, acq_lock);
            m_btree_lock.unlock();

            check_collapse_root();

            // We must have gotten a new root, need to
            // start from scratch.
            m_btree_lock.read_lock();
            goto retry;
        } else if ((is_leaf) && (acq_lock != homeds::thread::LOCKTYPE_WRITE)) {
            // Root is a leaf, need to take write lock, instead
            // of read, retry
            unlock_node(root, acq_lock);
            acq_lock = homeds::thread::LOCKTYPE_WRITE;
            goto retry;
        } else {
            btree_status_t status = do_remove(root, acq_lock, range, outkey, outval);
            if (status == BTREE_RETRY) {
                // Need to start from top down again, since
                // there is a race between 2 inserts or deletes.
                acq_lock = homeds::thread::LOCKTYPE_READ;
                goto retry;
            } else if (status == BTREE_ITEM_FOUND) {
                is_found = true;
            } else {
                is_found = false;
            }
        }

        m_btree_lock.unlock();
#ifndef NDEBUG
        check_lock_debug();
#endif

#ifdef REFCOUNT_DEBUG
        assert(OmDBGlobals::getGlobalRefCount() == 0);
#endif
        return is_found;
    }

    bool remove(const BtreeKey &key, BtreeValue *outval) {
        return remove_any(BtreeSearchRange(key), nullptr, outval);
    }

    const BtreeStats &get_stats() const {
        return m_stats;
    }

private:
    bool do_get(BtreeNodePtr my_node, const BtreeSearchRange &range, BtreeKey *outkey, BtreeValue *outval) {
        if (my_node->is_leaf()) {
            auto result = my_node->find(range, outkey, outval);
            unlock_node(my_node, homeds::thread::locktype::LOCKTYPE_READ);
            return (result.found);
        }

        BNodeptr child_ptr;
        my_node->find(range, nullptr, &child_ptr);
        BtreeNodePtr child_node = BtreeSpecificImplDeclType::read_node(m_btree_specific_impl.get(), child_ptr.get_node_id());

        lock_node(child_node, homeds::thread::LOCKTYPE_READ);
        unlock_node(my_node, homeds::thread::locktype::LOCKTYPE_READ);
        return (do_get(child_node, range, outkey, outval));
    }

#ifdef NEED_REWRITE
    uint32_t do_multiget(BtreeNodePtr my_node, const BtreeRegExKey &rkey, uint32_t max_nvalues,
                         std::vector<std::pair<BtreeKey *, BtreeValue *>> &out_values) {
        if (my_node->is_leaf()) {
            auto result = my_node->find(key, outkey, outval);
            unlock_node(my_node, true);
            return (result.match_type != NO_MATCH);
        }

        BNodeptr child_ptr;
        auto result = my_node->find(rkey, nullptr, &child_ptr);
        BtreeNodePtr child_node = read_node(child_ptr.get_node_id());

        lock_node(child_node, homeds::thread::LOCKTYPE_READ);
        unlock_node(my_node, true);
        return (do_multiget(child_node, rkey, max_nvalues, out_values));
    }
#endif

    /* This function upgrades the node lock and take required steps if things have
     * changed during the upgrade.
     *
     * Inputs:
     * myNode - Node to upgrade
     * childNode - In case childNode needs to be unlocked. Could be nullptr
     * curLock - Input/Output: current lock type
     *
     * Returns - If successfully able to upgrade, return true, else false.
     *
     * About Locks: This function expects the myNode to be locked and if childNode is not nullptr, expects
     * it to be locked too. If it is able to successfully upgrade it continue to retain its
     * old lock. If failed to upgrade, will release all locks.
     */
    bool upgrade_node(BtreeNodePtr my_node, BtreeNodePtr child_node, homeds::thread::locktype &cur_lock,
                      homeds::thread::locktype child_cur_lock) {
        uint64_t prev_gen;
        bool ret = true;

        if (cur_lock == homeds::thread::LOCKTYPE_WRITE) {
            ret = true;
            goto done;
        }

        prev_gen = my_node->get_gen();
        if (child_node) {
            unlock_node(child_node, child_cur_lock);
        }

#ifndef NDEBUG
        // Explicitly dec and incr, for upgrade, since it does not call top level functions to lock/unlock node
        dec_check_lock_debug(my_node, LOCKTYPE_READ);
#endif

        my_node->lock_upgrade();
        my_node->lock_acknowledge();

#ifndef NDEBUG
        inc_lock_debug(my_node, LOCKTYPE_WRITE);
#endif

        // If the node has been made invalid (probably by mergeNodes) ask caller to start over again, but before that
        // cleanup or free this node if there is no one waiting.
        if (!my_node->is_valid_node()) {
            if (my_node->any_upgrade_waiters()) {
                // Still some one else is waiting, we are not the last.
                unlock_node(my_node, homeds::thread::LOCKTYPE_WRITE);
            } else {
                // No else is waiting for this node and this is an invalid node, free it up.
                assert(my_node->get_total_entries() == 0);
                unlock_node(my_node, homeds::thread::LOCKTYPE_WRITE);

                // Its ok to free after unlock, because the chain has been already cut when the node is invalidated.
                // So no one would have entered here after the chain is cut.
                BtreeSpecificImplDeclType::free_node(m_btree_specific_impl.get(), my_node);
                m_stats.dec_count(my_node->is_leaf() ? BTREE_STATS_LEAF_NODE_COUNT : BTREE_STATS_INT_NODE_COUNT);
            }
            ret = false;
            goto done;
        }

        // If node has been updated, while we have upgraded, ask caller to start all over again.
        if (prev_gen != my_node->get_gen()) {
            unlock_node(my_node, homeds::thread::LOCKTYPE_WRITE);
            ret = false;
            goto done;
        }

        // The node was not changed by anyone else during upgrade.
        cur_lock = homeds::thread::LOCKTYPE_WRITE;
        if (child_node) {
            lock_node(child_node, child_cur_lock);
        }

    done:
        if (ret == false) {
            // if (child_node) release_node(child_node);
        }
        return ret; // We have successfully upgraded the node.
    }

#if 0
    /* This method tries to get the child node from an interior parent node, based on the key. It also provides the
     * index within the parent node, which is pointing to the child node. In case if the child node is an edge node,
     * instead of creating a new child node */
    BtreeNodePtr get_child_node(BtreeNodePtr int_node, homeds::thread::locktype curlock, const BtreeKey &key,
                                 int *out_ind) {
        BNodeptr childptr;

        if (*out_ind == -1) {
            auto result = int_node->find(BtreeSearchRange(key), nullptr, nullptr);
            *out_ind = result.end_of_search_index;
        }

        // During Insert, it is possible to get the last entry where in it needs to insert
        // the data. In those cases, we will try to accommodate with the previous entry
        // and update its key to this entry.
        if (*out_ind == int_node->get_total_entries()) {
            childptr.set_node_id(int_node->get_edge_id());

            if (!childptr.is_valid_ptr()) {
                if (upgrade_node(int_node, nullptr /* childNode */, curlock, homeds::thread::LOCKTYPE_NONE) == false) {
                    return nullptr;
                }

                if (*out_ind == 0) {
                    // If index is 0 and this is the last entry, it is a nullptr node.
                    // We should never get to nullptr node after upgradeNode is successful.
                    assert(0);
                    return nullptr;
                }

                // Update the previous entry to cover this key as well.
                (*out_ind)--;
                int_node->get(*out_ind, &childptr, false /* copy */);
                int_node->update(*out_ind, key, childptr);
            }
        } else {
            int_node->get(*out_ind, &childptr, false /* copy */);
        }

        return read_node(childptr.get_node_id());
    }
#endif

    BtreeNodePtr get_child_node(BtreeNodePtr int_node, const BtreeSearchRange &range,
                                       uint32_t *outind, bool *is_found) {
        BNodeptr child_ptr;

        auto result = int_node->find(range, nullptr, nullptr);
        *is_found = result.found;
        *outind = result.end_of_search_index;

        if (*outind == int_node->get_total_entries()) {
            //assert(!(*isFound));
            child_ptr.set_node_id(int_node->get_edge_id());

            // If bsearch points to last index, it means the search has not found entry unless it is an edge value.
            if (!child_ptr.is_valid_ptr()) {
                return nullptr;
            } else {
                *is_found = true;
            }
        } else {
            int_node->get(*outind, &child_ptr, false /* copy */);
            *is_found = true;
        }

        return BtreeSpecificImplDeclType::read_node(m_btree_specific_impl.get(), child_ptr.get_node_id());
    }

    /* This function does the heavy lifiting of co-ordinating inserts. It is a recursive function which walks
     * down the tree.
     *
     * NOTE: It expects the node it operates to be locked (either read or write) and also the node should not be full.
     *
     * Input:
     * myNode      = Node it operates on
     * curLock     = Type of lock held for this node
     * k           = Key to insert
     * v           = Value to insert
     * ind_hint    = If we already know which slot to insert to, if not -1
     * put_type    = Type of the put (refer to structure PutType)
     */
    bool do_put(BtreeNodePtr my_node, homeds::thread::locktype curlock, const BtreeKey &k, const BtreeValue &v,
                int ind_hint, PutType put_type) {

#ifndef NDEBUG
	int temp_rd_locked_count = rd_locked_count;
	int temp_wr_locked_count = wr_locked_count;

	/* lets take into account the parent lock as it will be unlocked in this function */
	if (curlock == LOCKTYPE_WRITE) {
		temp_wr_locked_count--;
	} else if(curlock == LOCKTYPE_READ) {
		temp_rd_locked_count--;
	} else {
		assert(0);
	}
 #endif
        if (my_node->is_leaf()) {
            assert(curlock == LOCKTYPE_WRITE);

            bool ret = my_node->put(k, v, put_type);
            if (ret) {
                BtreeSpecificImplDeclType::write_node(m_btree_specific_impl.get(), my_node);
                m_stats.inc_count(BTREE_STATS_OBJ_COUNT);
            }
            unlock_node(my_node, curlock);
#ifndef NDEBUG
	    assert(rd_locked_count == temp_rd_locked_count 
			&& wr_locked_count == temp_wr_locked_count);
#endif
#ifndef NDEBUG
            //my_node->print();
#endif
            return ret;
        }

    retry:
        homeds::thread::locktype child_cur_lock = homeds::thread::LOCKTYPE_NONE;

        // Get the childPtr for given key.
        uint32_t ind = ind_hint;
        bool is_found;
        BtreeNodePtr child_node = get_child_node(my_node, BtreeSearchRange(k), &ind, &is_found);
        if (!is_found || (child_node == nullptr)) {
            // Either the node was updated or mynode is freed. Just proceed again from top.
                unlock_node(my_node, curlock);
		assert(rd_locked_count == temp_rd_locked_count 
				&& wr_locked_count == temp_wr_locked_count);
		return false;
        }

        // Directly get write lock for leaf, since its an insert.
        child_cur_lock = (child_node->is_leaf()) ? LOCKTYPE_WRITE : LOCKTYPE_READ;
        lock_node(child_node, child_cur_lock);

        // Check if child node is full and a hint on where would next child goes in.
        // TODO: Do minimal check and merge nodes for optimization.
        if (child_node->is_split_needed(m_btree_cfg, k, v, &ind_hint)) {
            // Time to split the child, but we need to convert ours to write lock
            if (upgrade_node(my_node, child_node, curlock, child_cur_lock) == false) {
		assert(rd_locked_count == temp_rd_locked_count 
			&& wr_locked_count == temp_wr_locked_count);
                return (false);
            }

            // We need to upgrade the child to WriteLock
            if (upgrade_node(child_node, nullptr, child_cur_lock, LOCKTYPE_NONE) == false) {
                // Since we have parent node write locked, child node should never have any issues upgrading.
                assert(0);
                unlock_node(my_node, homeds::thread::LOCKTYPE_WRITE);
		assert(rd_locked_count == temp_rd_locked_count 
			&& wr_locked_count == temp_wr_locked_count);
                return (false);
            }

            // Real time to split the node and get point at which it was split
            K split_key;
            split_node(my_node, child_node, ind, &split_key);
            ind_hint = -1; // Since split is needed, hint is no longer valid

            // After split, parentNode would have split, retry search and walk down.
            unlock_node(child_node, homeds::thread::LOCKTYPE_WRITE);
            m_stats.inc_count(BTREE_STATS_SPLIT_COUNT);
            goto retry;
        }

        unlock_node(my_node, curlock);

#ifndef NDEBUG
	/* lets take into account of child lock as it is locked in this function */
	if (child_cur_lock == LOCKTYPE_WRITE) {
		temp_wr_locked_count++;
	} else if (child_cur_lock == LOCKTYPE_READ) {
		temp_rd_locked_count++;
	} else {
		assert(0);
	}
	assert(rd_locked_count == temp_rd_locked_count 
			&& wr_locked_count == temp_wr_locked_count);
#endif
        return (do_put(child_node, child_cur_lock, k, v, ind_hint, put_type));

        // Warning: Do not access childNode or myNode beyond this point, since it would
        // have been unlocked by the recursive function and it could also been deleted.
    }

    btree_status_t do_remove(BtreeNodePtr my_node, homeds::thread::locktype curlock, const BtreeSearchRange &range,
                             BtreeKey *outkey, BtreeValue *outval) {
        if (my_node->is_leaf()) {
            assert(curlock == LOCKTYPE_WRITE);

            bool is_found = my_node->remove_one(range, outkey, outval);
            if (is_found) {
                BtreeSpecificImplDeclType::write_node(m_btree_specific_impl.get(), my_node);
                m_stats.dec_count(BTREE_STATS_OBJ_COUNT);
            } else {
#ifndef NDEBUG
                //my_node->to_string();
#endif
            }

            unlock_node(my_node, curlock);
	    if (is_found == true) {
			return BTREE_ITEM_FOUND;
	    } else {
			return BTREE_NOT_FOUND;
	    }
        }

    retry:
        locktype child_cur_lock = LOCKTYPE_NONE;

        // Get the childPtr for given key.
        uint32_t ind;

        bool is_found = true;
        BtreeNodePtr child_node = get_child_node(my_node, range, &ind, &is_found);
        if (!is_found || (child_node == nullptr)) {
            unlock_node(my_node, curlock);
            return BTREE_NOT_FOUND;
        }

        // Directly get write lock for leaf, since its a delete.
        child_cur_lock = (child_node->is_leaf()) ? LOCKTYPE_WRITE : LOCKTYPE_READ;
        lock_node(child_node, child_cur_lock);

        // Check if child node is minimal.
        if (child_node->is_merge_needed(m_btree_cfg)) {
            // If we are unable to upgrade the node, ask the caller to retry.
            if (upgrade_node(my_node, child_node, curlock, child_cur_lock) == false) {
                return BTREE_RETRY;
            }

#define MAX_ADJANCENT_INDEX   3

            // We do have the write lock and hence can remove entries. Get a list of entries around the minimal child
            // node. Use the list of child entries and merge/share the keys among them.
            vector< int > indices_list;
            my_node->get_adjacent_indicies(ind, indices_list, MAX_ADJANCENT_INDEX);

            // There has to be at least 2 nodes to merge or share. If not let the node be and proceed further down.
            if (indices_list.size() > 1) {
                // It is safe to unlock child without upgrade, because child node would not be deleted, since its
                // parent (myNode) is being write locked by this thread. In fact upgrading would be a problem, since
                // this child might be a middle child in the list of indices, which means we might have to lock one in
                // left against the direction of intended locking (which could cause deadlock).
                unlock_node(child_node, child_cur_lock);
                auto result = merge_nodes(my_node, indices_list);
                if (result.merged) {
                    // Retry only if we merge them.
                    //release_node(child_node);
                    m_stats.inc_count(BTREE_STATS_MERGE_COUNT);
                    goto retry;
                } else {
                    lock_node(child_node, child_cur_lock);
                }
            }
        }

        unlock_node(my_node, curlock);
        return (do_remove(child_node, child_cur_lock, range, outkey, outval));

        // Warning: Do not access childNode or myNode beyond this point, since it would
        // have been unlocked by the recursive function and it could also been deleted.
    }

    void check_split_root(const BtreeKey &k, const BtreeValue &v) {
        int ind;
        K split_key;
        BtreeNodePtr new_root_int_node = nullptr;

        m_btree_lock.write_lock();
        BtreeNodePtr root = BtreeSpecificImplDeclType::read_node(m_btree_specific_impl.get(), m_root_node);
        lock_node(root, locktype::LOCKTYPE_WRITE);

        if (!root->is_split_needed(m_btree_cfg, k, v, &ind)) {
            unlock_node(root, homeds::thread::LOCKTYPE_WRITE);
            goto done;
        }

        // Create a new root node and split them
        new_root_int_node = alloc_interior_node();
        split_node(new_root_int_node, root, new_root_int_node->get_total_entries(), &split_key);
        unlock_node(root, homeds::thread::LOCKTYPE_WRITE);

        m_root_node = new_root_int_node->get_node_id();

       // DCVLOG(VMOD_BTREE_SPLIT, 4) << "New Root Node: \n" << new_root_int_node->to_string();

        //release_node(new_root_int_node);
    done:
        m_btree_lock.unlock();
    }

    void check_collapse_root() {
        BtreeNodePtr child_node = nullptr;

        m_btree_lock.write_lock();
        BtreeNodePtr root = BtreeSpecificImplDeclType::read_node(m_btree_specific_impl.get(), m_root_node);
        lock_node(root, locktype::LOCKTYPE_WRITE);

        if (root->get_total_entries() != 0) {
            unlock_node(root, locktype::LOCKTYPE_WRITE);
            goto done;
        }

        assert(root->get_edge_id() != INVALID_BNODEID);
        child_node = BtreeSpecificImplDeclType::read_node(m_btree_specific_impl.get(), root->get_edge_id());
        assert(child_node != nullptr);

        // Elevate the edge child as root.
        unlock_node(root, locktype::LOCKTYPE_WRITE);
        BtreeSpecificImplDeclType::free_node(m_btree_specific_impl.get(), root);
        m_stats.dec_count(BTREE_STATS_INT_NODE_COUNT);
        m_root_node = child_node->get_node_id();

        //release_node(child_node);
    done:
        m_btree_lock.unlock();
    }

    void split_node(BtreeNodePtr parent_node, BtreeNodePtr child_node, uint32_t parent_ind,
                    BtreeKey *out_split_key) {
        BNodeptr nptr;

        // Create a new child node and split the keys by half.
        BtreeNodePtr child_node1 = child_node;
        BtreeNodePtr child_node2 = child_node->is_leaf() ? alloc_leaf_node() : alloc_interior_node();

        child_node2->set_next_bnode(child_node1->get_next_bnode());
        child_node1->set_next_bnode(child_node2->get_node_id());
        child_node1->move_out_to_right_by_size(m_btree_cfg, child_node2, m_btree_cfg.get_split_size());

        // Update the existing parent node entry to point to second child ptr.
        nptr.set_node_id(child_node2->get_node_id());
        parent_node->update(parent_ind, nptr);

        // Insert the last entry in first child to parent node
        child_node1->get_last_key(out_split_key);

        nptr.set_node_id(child_node1->get_node_id());
        parent_node->insert(*out_split_key, nptr);

        BtreeSpecificImplDeclType::write_node(m_btree_specific_impl.get(), child_node1);
        BtreeSpecificImplDeclType::write_node(m_btree_specific_impl.get(), child_node2);
        BtreeSpecificImplDeclType::write_node(m_btree_specific_impl.get(), parent_node);
        //release_node(child_node2);

#ifndef NDEBUG
         LOGERRORMOD(VMOD_BTREE_SPLIT,
                     "After split\n#####################\nParent node:\n{}\nChild node1:\n{}\nChild node2:\n{}",
                     parent_node->to_string(),
                     child_node1->to_string(),
                     child_node2->to_string());
#endif

        // NOTE: Do not access parentInd after insert, since insert would have
        // shifted parentNode to the right.
    }

    auto merge_nodes(BtreeNodePtr parent_node, std::vector< int > &indices_list) {
        struct merge_info {
            BtreeNodePtr node;
            uint16_t  parent_index;
            bool freed;
            bool modified;
        };

        struct {
            bool     merged;  // Have we merged at all
            uint32_t nmerged; // If we merged, how many are the final result of nodes
        } ret{false, 0};

        std::vector< merge_info > minfo;
        BNodeptr child_ptr;
        uint32_t ndeleted_nodes = 0;

        // Loop into all index and initialize list
        minfo.reserve(indices_list.size());
        for (auto i = 0u; i < indices_list.size(); i++) {
            parent_node->get(indices_list[i], &child_ptr, false /* copy */);

            merge_info m;
            m.node = BtreeSpecificImplDeclType::read_node(m_btree_specific_impl.get(), child_ptr.get_node_id());
            m.freed = false;
            m.modified = false;
            m.parent_index = indices_list[i];
            minfo.push_back(m);
            lock_node(m.node, locktype::LOCKTYPE_WRITE);
        }


#ifndef NDEBUG
        if (sds_logging::module_level_VMOD_BTREE_MERGE <= spdlog::level::level_enum::err) {
            LOGINFOMOD(VMOD_BTREE_MERGE, "Before Merge Nodes:\nParent node:\n{}", parent_node->to_string());
            for (auto i = 0u; i < minfo.size(); ++i) {
                LOGINFOMOD(VMOD_BTREE_MERGE, "Child node {}\n{}", i + 1, minfo[i].node->to_string());
            }
        }
#endif

        // Rebalance entries for each of the node and mark any node to be removed, if empty.
        auto i = 0U; auto j = 1U;
        auto balanced_size = m_btree_cfg.get_ideal_fill_size();
        while ((i < indices_list.size() - 1) && (j < indices_list.size())) {
            minfo[j].parent_index -= ndeleted_nodes; // Adjust the parent index for deleted nodes

            if (minfo[i].node->get_occupied_size(m_btree_cfg) < balanced_size) {
                // We have room to pull some from next node
                uint32_t pull_size = balanced_size - minfo[i].node->get_occupied_size(m_btree_cfg);
                if (minfo[i].node->move_in_from_right_by_size(m_btree_cfg, minfo[j].node, pull_size)) {
                    minfo[i].modified = true;
                    ret.merged = true;
                }

                if (minfo[j].node->get_total_entries() == 0) {
                    // We have removed all the entries from the next node, remove the entry in parent and move on to
                    // the next node.
                    minfo[j].freed = true;
                    parent_node->remove(minfo[j].parent_index);
                    minfo[i].node->set_next_bnode(minfo[j].node->get_next_bnode());
                    ndeleted_nodes++;
                    j++;
                    continue;
                }
            }

            // If we have reached the last node on second iterator and if that is minimal, we can relax the ideal size
            // and get all in and try to avoid additional minimal node hanging around.
            if ((j == minfo.size()-1) &&
                    (minfo[j].node->get_occupied_size(m_btree_cfg) <= m_btree_cfg.get_merge_suggested_size()) &&
                    balanced_size != NodeSize) {
                balanced_size = NodeSize;
                continue;
            }

            i = j++;
            minfo[i].parent_index -= ndeleted_nodes; // Adjust the parent index for deleted nodes (i.e. removed entries)
        }

        // Its time to write the parent node and loop again to write all modified nodes and free freed nodes
//        DCVLOG(VMOD_BTREE_MERGE, 4) << "After merging node\n########################Parent Node: "
  //                                  << parent_node->to_string();
        BtreeSpecificImplDeclType::write_node(m_btree_specific_impl.get(), parent_node);
        assert(!minfo[0].freed); // If we merge it, we expect the left most one has at least 1 entry.
        // TODO: Above assumption will not be valid if we are merging all empty nodes. Need to study that.

        for (auto n = 0u; n < minfo.size(); n++) {
            if (minfo[n].modified && !minfo[n].freed) {
                // If we have indeed modified, lets get the last key and put in the entry into parent node
                BNodeptr nptr(minfo[n].node->get_node_id());
                if (minfo[n].parent_index == parent_node->get_total_entries()) {
                    parent_node->update(minfo[n].parent_index, nptr);
                } else {
                    K last_key;
                    minfo[n].node->get_last_key(&last_key);
                    parent_node->update(minfo[n].parent_index, last_key, nptr);
                }

               // DCVLOG(VMOD_BTREE_MERGE, 4) << "Child Node " << n << ":\n" << minfo[n].node->to_string();
                BtreeSpecificImplDeclType::write_node(m_btree_specific_impl.get(), minfo[n].node);
            }
        }

        // Loop again in reverse order to unlock the nodes. freeable nodes need to be unlocked and freed
        for (int n = minfo.size()-1; n >= 0; n--) {
            if (minfo[n].freed) {
                LOGDEBUGMOD(VMOD_BTREE_MERGE, "Child Node {}: Freeing the node id = {}", n, minfo[n].node->get_node_id().to_integer());
                if (minfo[n].node->any_upgrade_waiters()) {
                    minfo[n].node->set_valid_node(false);
                    unlock_node(minfo[n].node, locktype::LOCKTYPE_WRITE);
                } else {
                    unlock_node(minfo[n].node, locktype::LOCKTYPE_WRITE);
                    BtreeSpecificImplDeclType::free_node(m_btree_specific_impl.get(), minfo[n].node);
                    m_stats.dec_count(minfo[n].node->is_leaf() ? BTREE_STATS_LEAF_NODE_COUNT : BTREE_STATS_INT_NODE_COUNT);
                }
            } else {
                unlock_node(minfo[n].node, locktype::LOCKTYPE_WRITE);
            }
        }

        ret.nmerged = minfo.size() - ndeleted_nodes;
        return ret;
    }

    BtreeNodePtr alloc_leaf_node() {
        BtreeNodePtr n = BtreeSpecificImplDeclType::alloc_node(m_btree_specific_impl.get(), true /* is_leaf */);
        n->set_leaf(true);
        m_stats.inc_count(BTREE_STATS_LEAF_NODE_COUNT);
        return n;
    }

    BtreeNodePtr alloc_interior_node() {
        BtreeNodePtr n = BtreeSpecificImplDeclType::alloc_node(m_btree_specific_impl.get(), false /* isLeaf */);
        n->set_leaf(false);
        m_stats.inc_count(BTREE_STATS_INT_NODE_COUNT);
        return n;
    }

    void lock_node(BtreeNodePtr node, homeds::thread::locktype type) {
        node->lock(type);
#ifndef NDEBUG
        inc_lock_debug(node, type);
#endif
    }

    void unlock_node(BtreeNodePtr node, homeds::thread::locktype type) {
        node->unlock(type);
#ifndef NDEBUG
        dec_check_lock_debug(node, type);
#endif
#if 0
        if (release) {
            release_node(node);
        }
#endif
    }

#ifndef NDEBUG
    static void init_lock_debug() {
        rd_locked_count = 0;
        wr_locked_count = 0;
    }

    static void check_lock_debug() {
        if (wr_locked_count != 0) {
            LOGERROR("There are {} write locks held on the exit of API", wr_locked_count);
            assert(0);
        }

        if (rd_locked_count != 0) {
            LOGERROR("There are {} read locks held on the exit of API", rd_locked_count);
            assert(0);
        }
    }

    static void inc_lock_debug(BtreeNodePtr node, locktype ltype) {
        if (ltype == LOCKTYPE_WRITE) {
            wr_locked_nodes[wr_locked_count++] = node.get();
        } else if (ltype == LOCKTYPE_READ) {
            rd_locked_nodes[rd_locked_count++] = node.get();
        }
//        std::cout << "lock_node: node = " << (void *)node << " Locked count = " << locked_count << std::endl;
    }

    static void dec_check_lock_debug(BtreeNodePtr node, locktype ltype) {
        std::array<BtreeNodeDeclType *, MAX_BTREE_DEPTH> *pnodes;
        int *pcount;
        if (ltype == LOCKTYPE_WRITE) {
            pnodes = &wr_locked_nodes;
            pcount = &wr_locked_count;
        } else {
            pnodes = &rd_locked_nodes;
            pcount = &rd_locked_count;
        }

        // std::cout << "unlock_node: node = " << (void *)node << " Locked count = " << locked_count << std::endl;
        if (node == pnodes->at(*pcount - 1)) {
            (*pcount)--;
        } else if ((*pcount > 1) && (node == pnodes->at((*pcount)-2))) {
            pnodes->at(*(pcount)-2) = pnodes->at((*pcount)-1);
            (*pcount)--;
        } else {
            if (*pcount > 1) {
                LOGERROR("unlock_node: node = {} Locked count = {} Expecting nodes = {} or {}",
                         (void *) node.get(),
                         (*pcount),
                         (void *) pnodes->at(*(pcount)-1),
                         (void *) pnodes->at(*(pcount)-2));
            } else {
                LOGERROR("unlock_node: node = {} Locked count = {} Expecting node = {}",
                         (void *) node.get(),
                         (*pcount),
                         (void *) pnodes->at(*(pcount)-1));
            }
            assert(0);
        }
    }
#endif

protected:
    void create_root_node() {
        // Assign one node as root node and initially root is leaf
        BtreeNodePtr root = alloc_leaf_node();
        m_root_node = root->get_node_id();
        BtreeSpecificImplDeclType::write_node(m_btree_specific_impl.get(), root);
    }

    virtual uint32_t get_max_nodes() {
        return m_max_nodes;
    }

    BtreeConfig *get_config() {
        return &m_btree_cfg;
    }

#if 0
    void release_node(BtreeNodePtr node)
    {
        node->derefNode();
    }
#endif
};

#ifndef NDEBUG
template<btree_type BtreeType, typename K, typename V, btree_node_type InteriorNodeType, btree_node_type LeafNodeType,
        size_t NodeSize>
thread_local int BtreeDeclType::wr_locked_count = 0;

template<btree_type BtreeType, typename K, typename V, btree_node_type InteriorNodeType, btree_node_type LeafNodeType,
        size_t NodeSize>
thread_local std::array<BtreeNodeDeclType *, MAX_BTREE_DEPTH> BtreeDeclType::wr_locked_nodes = {{}};

template<btree_type BtreeType, typename K, typename V, btree_node_type InteriorNodeType, btree_node_type LeafNodeType,
        size_t NodeSize>
thread_local int BtreeDeclType::rd_locked_count = 0;

template<btree_type BtreeType, typename K, typename V, btree_node_type InteriorNodeType, btree_node_type LeafNodeType,
        size_t NodeSize>
thread_local std::array<BtreeNodeDeclType *, MAX_BTREE_DEPTH> BtreeDeclType::rd_locked_nodes = {{}};

#endif

}}
