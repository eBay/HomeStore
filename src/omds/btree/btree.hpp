/*
 * btree.hpp
 *
 *  Created on: 14-May-2016
 *      Author: Hari Kadayam
 *
 *  Copyright © 2016 Kadayam, Hari. All rights reserved.
 */
#ifndef BTREE_KVSTORE_CPP_
#define BTREE_KVSTORE_CPP_
#include <iostream>
#include <cassert>
#include <pthread.h>
#include <vector>
#include <atomic>
#include <array>
#include "omds/thread/lock.hpp"
#include "btree_internal.h"
#include "btree_stats.hpp"
#include "abstract_node.hpp"
#include "omds/utility/logging.hpp"
#include <boost/intrusive_ptr.hpp>

using namespace std;
using namespace omds::thread;

#ifndef NDEBUG
#define MAX_BTREE_DEPTH   100
#endif

#ifndef BTREE_VMOD_NAME
#define BTREE_VMOD_NAME    btree
#endif

#define VMOD_BTREE_WRITE     BOOST_PP_CAT(BOOST_PP_CAT(BTREE_VMOD_NAME, _), btwrite)
#define VMOD_BTREE_DELETE    BOOST_PP_CAT(BOOST_PP_CAT(BTREE_VMOD_NAME, _), btdelete)
#define VMOD_BTREE_GET       BOOST_PP_CAT(BOOST_PP_CAT(BTREE_VMOD_NAME, _), btget)
#define VMOD_BTREE_SPLIT     BOOST_PP_CAT(BOOST_PP_CAT(BTREE_VMOD_NAME, _), btsplit)
#define VMOD_BTREE_MERGE     BOOST_PP_CAT(BOOST_PP_CAT(BTREE_VMOD_NAME, _), btmerge)

#define BTREE_VMODULES       \
        VMOD_BTREE_WRITE,    \
        VMOD_BTREE_DELETE,   \
        VMOD_BTREE_GET,      \
        VMOD_BTREE_SPLIT,    \
        VMOD_BTREE_MERGE

REGISTER_VMODULES(BTREE_VMODULES);

namespace omds { namespace btree {

#if 0
#define container_of(ptr, type, member) ({                      \
        (type *)( (char *)ptr - offsetof(type,member) );})
#endif

#define AbstractNodePtr boost::intrusive_ptr< AbstractNode<K, V, NodeSize> >

template<typename K, typename V, size_t NodeSize>
class Btree
{
#ifdef CLASS_DEFINITIONS
public:
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

protected:
    /* Method to allocate/read/write/refcount nodes. Overriding methods need to implement device specific
     * way to do this operation */
    virtual AbstractNodePtr alloc_node(btree_nodetype_t btype, bool is_leaf) = 0;
    virtual AbstractNodePtr read_node(bnodeid_t node_ptr) = 0;
    virtual void write_node(AbstractNodePtr node) = 0;
    virtual void release_node(AbstractNodePtr node) = 0;
    virtual void free_node(AbstractNodePtr node) = 0;

private:
#ifdef CLASS_DEFINITIONS
    bool do_insert(AbstractNodePtr my_node, omds::thread::locktype_t curlock, BtreeKey& k, BtreeValue& v, int ind_hint);

    bool do_get(AbstractNodePtr mynode, BtreeKey &key, BtreeValue *outval);

    btree_status_t do_remove(AbstractNodePtr mynode, omds::thread::locktype_t curlock, BtreeKey &key);

    bool upgrade_node(AbstractNodePtr mynode, AbstractNodePtr childnode, omds::thread::locktype_t &curlock,
                      omds::thread::locktype_t child_curlock);
    void split_node(AbstractNodePtr parent_node, AbstractNodePtr child_node, uint32_t parent_ind, BtreeKey **out_split_key);
    bool merge_nodes(AbstractNodePtr parent_node, std::vector<uint32_t> &indices_list);

    AbstractNode* get_child_node(AbstractNodePtr int_node, omds::thread::locktype_t curlock, BtreeKey& key, uint32_t &outind);
    AbstractNode* get_child_node_range(AbstractNodePtr int_node, KeyRegex& kr, uint32_t &outind, bool *isfound);

    void check_split_root();
    void check_collapse_root();

    AbstractNodePtr alloc_leaf_node();
    AbstractNodePtr alloc_interior_node();
    void lock_node(AbstractNodePtr node, omds::thread::locktype_t type);
    void unloc_node(AbstractNodePtr node, bool release);

protected:
    virtual uint32_t get_node_size() {return m_btree_cfg.get_node_size();};
    virtual uint32_t get_max_objs() {return m_btree_cfg.get_max_objs();};
    virtual uint32_t get_max_nodes() {return m_max_nodes;};
    virtual void create_root_node();
#endif

private:
    bnodeid_t m_root_node;
    omds::thread::RWLock m_btree_lock;

    uint32_t m_max_nodes;
    BtreeConfig m_btree_cfg;
    bool m_inited;
    BtreeStats m_stats;

#ifndef NDEBUG
    static thread_local int locked_count;
    static thread_local std::array<AbstractNode<K, V, NodeSize> *, MAX_BTREE_DEPTH> locked_nodes;
#endif

    ////////////////// Implementation /////////////////////////
public:
    Btree() :
            m_inited(false) {}

    void put(const BtreeKey &k, const BtreeValue &v, PutType put_type) {
        omds::thread::locktype acq_lock = omds::thread::LOCKTYPE_READ;
        int ind;

#ifndef NDEBUG
        init_lock_debug();
        //assert(OmDB::getGlobalRefCount() == 0);
#endif

        m_btree_lock.read_lock();

    retry:
        AbstractNodePtr root = read_node(m_root_node);
        lock_node(root, acq_lock);
        bool is_leaf = root->is_leaf();

        if (root->is_split_needed(m_btree_cfg, k, v, &ind)) {
            // Time to do the split of root.
            unlock_node(root, true);
            m_btree_lock.unlock();
            check_split_root(k, v);

            // We must have gotten a new root, need to
            // start from scratch.
            m_btree_lock.read_lock();
            goto retry;
        } else if ((is_leaf) && (acq_lock != omds::thread::LOCKTYPE_WRITE)) {
            // Root is a leaf, need to take write lock, instead
            // of read, retry
            unlock_node(root, true);
            acq_lock = omds::thread::LOCKTYPE_WRITE;
            goto retry;
        } else {
            bool success = do_put(root, acq_lock, k, v, ind, put_type);
            if (success == false) {
                // Need to start from top down again, since
                // there is a race between 2 inserts or deletes.
                acq_lock = omds::thread::LOCKTYPE_READ;
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
        AbstractNodePtr root = read_node(m_root_node);
        lock_node(root, omds::thread::locktype::LOCKTYPE_READ);

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
    uint32_t get_multi(const BtreeSearchRange &range, std::vector<std::pair<BtreeKey *, BtreeValue *>> outval) {
    }

    bool remove_any(const BtreeSearchRange &range, BtreeKey *outkey, BtreeValue *outval) {
        omds::thread::locktype acq_lock = omds::thread::locktype::LOCKTYPE_READ;
        bool is_found = false;

#ifndef NDEBUG
        init_lock_debug();
#endif

#ifdef REFCOUNT_DEBUG
        assert(OmDBGlobals::getGlobalRefCount() == 0);
#endif

        m_btree_lock.read_lock();

    retry:
        AbstractNodePtr root = read_node(m_root_node);
        lock_node(root, acq_lock);
        bool is_leaf = root->is_leaf();

        if (root->get_total_entries() == 0) {
            if (is_leaf) {
                // There are no entries in btree.
                unlock_node(root, true);
                m_btree_lock.unlock();
                return false;
            }
            assert(root->get_edge_id() != INVALID_BNODEID);
            unlock_node(root, true);
            m_btree_lock.unlock();

            check_collapse_root();

            // We must have gotten a new root, need to
            // start from scratch.
            m_btree_lock.read_lock();
            goto retry;
        } else if ((is_leaf) && (acq_lock != omds::thread::LOCKTYPE_WRITE)) {
            // Root is a leaf, need to take write lock, instead
            // of read, retry
            unlock_node(root, true);
            acq_lock = omds::thread::LOCKTYPE_WRITE;
            goto retry;
        } else {
            btree_status_t status = do_remove(root, acq_lock, range, outkey, outval);
            if (status == BTREE_RETRY) {
                // Need to start from top down again, since
                // there is a race between 2 inserts or deletes.
                acq_lock = omds::thread::LOCKTYPE_READ;
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
    bool do_get(AbstractNodePtr my_node, const BtreeSearchRange &range, BtreeKey *outkey, BtreeValue *outval) {
        if (my_node->is_leaf()) {
            auto result = my_node->find(range, outkey, outval);
            unlock_node(my_node, true);
            return (result.found);
        }

        BNodeptr child_ptr;
        auto result = my_node->find(range, nullptr, &child_ptr);
        AbstractNodePtr child_node = read_node(child_ptr.get_node_id());

        lock_node(child_node, omds::thread::LOCKTYPE_READ);
        unlock_node(my_node, true);
        return (do_get(child_node, range, outkey, outval));
    }

#ifdef NEED_REWRITE
    uint32_t do_multiget(AbstractNodePtr my_node, const BtreeRegExKey &rkey, uint32_t max_nvalues,
                         std::vector<std::pair<BtreeKey *, BtreeValue *>> &out_values) {
        if (my_node->is_leaf()) {
            auto result = my_node->find(key, outkey, outval);
            unlock_node(my_node, true);
            return (result.match_type != NO_MATCH);
        }

        BNodeptr child_ptr;
        auto result = my_node->find(rkey, nullptr, &child_ptr);
        AbstractNodePtr child_node = read_node(child_ptr.get_node_id());

        lock_node(child_node, omds::thread::LOCKTYPE_READ);
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
    bool upgrade_node(AbstractNodePtr my_node, AbstractNodePtr child_node, omds::thread::locktype &cur_lock,
                      omds::thread::locktype child_cur_lock) {
        uint64_t prev_gen;
        bool ret = true;

        if (cur_lock == omds::thread::LOCKTYPE_WRITE) {
            ret = true;
            goto done;
        }

        prev_gen = my_node->get_gen();
        if (child_node) {
            unlock_node(child_node, false);
        }
        my_node->lock_upgrade();
        my_node->lock_acknowledge();

        // If the node has been made invalid (probably by mergeNodes)
        // ask caller to start over again, but before that cleanup or free
        // this node if there is no one waiting.
        if (!my_node->is_valid_node()) {
            if (my_node->any_upgrade_waiters()) {
                // Still some one else is waiting, we are not the last.
                unlock_node(my_node, true);
            } else {
                // No else is waiting for this node and this is an invalid
                // node, free it up.
                assert(my_node->get_total_entries() == 0);
                unlock_node(my_node, false);

                // Its ok to free after unlock, because the chain has been already
                // cut when the node is invalidated. So no one would have entered here
                // after the chain is cut.
                free_node(my_node);
                m_stats.dec_count(my_node->is_leaf() ? BTREE_STATS_LEAF_NODE_COUNT : BTREE_STATS_INT_NODE_COUNT);
            }
            ret = false;
            goto done;
        }

        // If node has been updated, while we have upgraded, ask caller
        // to start all over again.
        if (prev_gen != my_node->get_gen()) {
            unlock_node(my_node, true);
            ret = false;
            goto done;
        }

        // The node was not changed by anyone else during upgrade.
        cur_lock = omds::thread::LOCKTYPE_WRITE;
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
    AbstractNodePtr get_child_node(AbstractNodePtr int_node, omds::thread::locktype curlock, const BtreeKey &key,
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
                if (upgrade_node(int_node, nullptr /* childNode */, curlock, omds::thread::LOCKTYPE_NONE) == false) {
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

    AbstractNodePtr get_child_node(AbstractNodePtr int_node, const BtreeSearchRange &range,
                                       int *outind, bool *is_found) {
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

        return read_node(child_ptr.get_node_id());
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
    bool do_put(AbstractNodePtr my_node, omds::thread::locktype curlock, const BtreeKey &k, const BtreeValue &v,
                int ind_hint, PutType put_type) {
        if (my_node->is_leaf()) {
            assert(curlock == LOCKTYPE_WRITE);

            bool ret = my_node->put(k, v, put_type);
            if (ret) {
                write_node(my_node);
                m_stats.inc_count(BTREE_STATS_OBJ_COUNT);
            }
            unlock_node(my_node, true);

#ifndef NDEBUG
            //my_node->print();
#endif
            return ret;
        }

    retry:
        omds::thread::locktype child_cur_lock = omds::thread::LOCKTYPE_NONE;

        // Get the childPtr for given key.
        int ind = ind_hint;
        bool is_found;
        AbstractNodePtr child_node = get_child_node(my_node, BtreeSearchRange(k), &ind, &is_found);
        if (!is_found || (child_node == nullptr)) {
            // Either the node was updated or mynode is freed. Just proceed again from top.
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
                return (false);
            }

            // We need to upgrade the child to WriteLock
            if (upgrade_node(child_node, nullptr, child_cur_lock, LOCKTYPE_NONE) == false) {
                // Since we have parent node write locked, child node should never have any issues upgrading.
                assert(0);
                unlock_node(my_node, true);
                return (false);
            }

            // Real time to split the node and get point at which it was split
            K split_key;
            split_node(my_node, child_node, ind, &split_key);
            ind_hint = -1; // Since split is needed, hint is no longer valid

            // After split, parentNode would have split, retry search and walk down.
            unlock_node(child_node, true);
            m_stats.inc_count(BTREE_STATS_SPLIT_COUNT);
            goto retry;
        }

        unlock_node(my_node, true);
        return (do_put(child_node, child_cur_lock, k, v, ind_hint, put_type));

        // Warning: Do not access childNode or myNode beyond this point, since it would
        // have been unlocked by the recursive function and it could also been deleted.
    }

    btree_status_t do_remove(AbstractNodePtr my_node, omds::thread::locktype curlock, const BtreeSearchRange &range,
                             BtreeKey *outkey, BtreeValue *outval) {
        if (my_node->is_leaf()) {
            assert(curlock == LOCKTYPE_WRITE);

            bool is_found = my_node->remove_one(range, outkey, outval);
            if (is_found) {
                write_node(my_node);
                m_stats.dec_count(BTREE_STATS_OBJ_COUNT);
            } else {
#ifndef NDEBUG
                my_node->to_string();
                assert(0);
#endif
            }

            unlock_node(my_node, true);
            return is_found ? BTREE_ITEM_FOUND : BTREE_NOT_FOUND;
        }

    retry:
        locktype child_cur_lock = LOCKTYPE_NONE;

        // Get the childPtr for given key.
        int ind;

        bool is_found = true;
        AbstractNodePtr child_node = get_child_node(my_node, range, &ind, &is_found);
        if (!is_found || (child_node == nullptr)) {
            unlock_node(my_node, true);
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
                unlock_node(child_node, false);
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

        unlock_node(my_node, true);
        return (do_remove(child_node, child_cur_lock, range, outkey, outval));

        // Warning: Do not access childNode or myNode beyond this point, since it would
        // have been unlocked by the recursive function and it could also been deleted.
    }

    void check_split_root(const BtreeKey &k, const BtreeValue &v) {
        int ind;
        K split_key;
        AbstractNodePtr new_root_int_node = nullptr;

        m_btree_lock.write_lock();
        AbstractNodePtr root = read_node(m_root_node);
        lock_node(root, locktype::LOCKTYPE_WRITE);

        if (!root->is_split_needed(m_btree_cfg, k, v, &ind)) {
            unlock_node(root, true);
            goto done;
        }

        // Create a new root node and split them
        new_root_int_node = alloc_interior_node();
        split_node(new_root_int_node, root, new_root_int_node->get_total_entries(), &split_key);
        unlock_node(root, true);

        m_root_node = new_root_int_node->get_node_id();

        DCVLOG(VMOD_BTREE_SPLIT, 4) << "New Root Node: \n" << new_root_int_node->to_string();

        //release_node(new_root_int_node);
    done:
        m_btree_lock.unlock();
    }

    void check_collapse_root() {
        AbstractNodePtr child_node = nullptr;

        m_btree_lock.write_lock();
        AbstractNodePtr root = read_node(m_root_node);
        lock_node(root, locktype::LOCKTYPE_WRITE);

        if (root->get_total_entries() != 0) {
            unlock_node(root, true);
            goto done;
        }

        assert(root->get_edge_id() != INVALID_BNODEID);
        child_node = read_node(root->get_edge_id());
        assert(child_node != nullptr);

        // Elevate the edge child as root.
        unlock_node(root, false);
        free_node(root);
        m_stats.dec_count(BTREE_STATS_INT_NODE_COUNT);
        m_root_node = child_node->get_node_id();

        //release_node(child_node);
    done:
        m_btree_lock.unlock();
    }

    void split_node(AbstractNodePtr parent_node, AbstractNodePtr child_node, uint32_t parent_ind,
                    BtreeKey *out_split_key) {
        BNodeptr nptr;

        // Create a new child node and split the keys by half.
        AbstractNodePtr child_node1 = child_node;
        AbstractNodePtr child_node2 = child_node->is_leaf() ? alloc_leaf_node() : alloc_interior_node();

        child_node2->set_next_bnode(child_node1->get_next_bnode());
        child_node1->set_next_bnode(child_node2->get_node_id());
        child_node1->move_out_to_right_by_size(m_btree_cfg, *child_node2, m_btree_cfg.get_split_size());

        // Update the existing parent node entry to point to second child ptr.
        nptr.set_node_id(child_node2->get_node_id());
        parent_node->update(parent_ind, nptr);

        // Insert the last entry in first child to parent node
        child_node1->get_last_key(out_split_key);
        nptr.set_node_id(child_node1->get_node_id());
        parent_node->insert(*out_split_key, nptr);

        write_node(child_node1);
        write_node(child_node2);
        write_node(parent_node);
        //release_node(child_node2);

#ifndef NDEBUG
        if (CVLOG_IS_ON(VMOD_BTREE_SPLIT, 4)) {
            LOG(INFO) << "After split\n#####################";
            LOG(INFO) << "Parent node:\n" << parent_node->to_string();
            LOG(INFO) << "Child node1:\n" << child_node1->to_string();
            LOG(INFO) << "Child node2:\n" << child_node2->to_string();
        }
#endif

        // NOTE: Do not access parentInd after insert, since insert would have
        // shifted parentNode to the right.
    }

#if 0
    bool merge_nodes(AbstractNodePtr parent_node, vector< int > &indices_list) {
        vector< AbstractNodePtr  > nodes(indices_list.size());
        BNodeptr child_ptr;
        uint32_t ntotal_entries = 0;
        int i;
        int n;
        bool ret = true;
        AbstractNodePtr cur_last_n = nullptr;
        AbstractNodePtr prev_last_n = nullptr;

        for (i = 0; i < indices_list.size(); i++) {
            parent_node->get(indices_list[i], &child_ptr, false /* copy */);

            nodes[i] = read_node(child_ptr.get_node_id());
            lock_node(nodes[i], locktype::LOCKTYPE_WRITE);
            ntotal_entries += nodes[i]->get_total_entries();
        }

#if 0
        #ifdef DEBUG
        cout << "Before Merge Nodes" << endl;
        cout << "#####################" << endl;
        cout << "Parent Node " << endl;
        AbstractNode::castAndPrint(parent_node);
        cout << "Child Node(s) " << endl;
        for (i = 0; i < indices_list.size(); i++) {
            AbstractNode::castAndPrint(nodes[i]);
        }
#endif
#endif

        // Fill only upto 90% of keys, beyond which will cause subsequent
        // insert to split again.
#define FILL_PERCENT 0.9
        uint32_t max_fill_entries = (double) nodes[0]->get_max_entries(m_btree_cfg) * FILL_PERCENT;

        uint32_t new_node_count = (ntotal_entries - 1) / max_fill_entries + 1;
        if (new_node_count >= indices_list.size()) {
            // We share equally across all available nodes
            max_fill_entries = (ntotal_entries - 1) / indices_list.size() + 1;
            assert(max_fill_entries <= nodes[0]->get_max_entries(m_btree_cfg));

            // We do share only if even after splitting, amount of entries remain is better than minimal nodes. Use the
            // last node, since it will have least entries
            if (nodes[new_node_count - 1]->is_minimal(max_fill_entries)) {
                ret = false;
                goto done;
            }
        }

        do_merge_nodes(nodes, 0, 0, max_fill_entries);

        // Now that we merged the nodes, we will update the parent indices with corresponding nodes last key.
        // Start from the last to first, to cover edge entries as well.
        i = indices_list.size() - 1;
        n = new_node_count - 1;

        while ((i >= 0) && (n >= 0)) {
            BNodeptr nptr(nodes[n]->get_node_id());
            if (indices_list[i] == parent_node->get_total_entries()) {
                parent_node->update(indices_list[i], nptr);
            } else {
                K last_key;
                nodes[n]->get_last_key(&last_key);
                parent_node->update(indices_list[i], last_key, nptr);
            }
            i--;
            n--;
        }
        assert(n == -1);

        // Remove the extra entries from parent node.
        while (i >= 0) {
            parent_node->remove(indices_list[i--]);
        }

        // Write parent node to store
        write_node(parent_node);

        // Point the remaining last node next to current last node next
        cur_last_n = nodes[new_node_count - 1];
        prev_last_n = nodes[nodes.size() - 1];
        cur_last_n->set_next_bnode(prev_last_n->get_next_bnode());

#if 0
#ifdef DEBUG
        cout << "After Merge Nodes" << endl;
        cout << "#####################" << endl;
        cout << "Parent Node " << endl;
        AbstractNode::castAndPrint(parent_node);
        cout << "Child Node(s) " << endl;
#endif
#endif

        done:
        // Unlock all the nodes, so that caller can choose to restart.
        for (n = 0; n < nodes.size(); n++) {
            bool free_n = false;

#if 0
            #ifdef DEBUG
            AbstractNode::castAndPrint(nodes[n]);
#endif
#endif
            if (n >= new_node_count) {
                // Free up remaining nodes only if nodes does not have upgrade waiters. Any upgrade waiters would just
                // invalidate this node, which will be freed by last waiter.
                if (nodes[n]->any_upgrade_waiters()) {
                    nodes[n]->set_valid_node(false);
                } else {
                    free_n = true;
                }
            }

            // If we have merged and not going to free the node we need to write it to store.
            if (ret && !free_n) {
                write_node(nodes[n]);
            }

            if (free_n) {
                unlock_node(nodes[n], false);
                assert(nodes[n]->get_total_entries() == 0);
                free_node(nodes[n]);
            } else {
                unlock_node(nodes[n], true);
            }
        }

        return ret;
    }

    /*
     * This function recursively merges with next node in-place. Each iteration accommodates
     * what is left over from previous node and move over its right keys to next node (by
     * recursing). In case current node has more room, pull in until we are full.
     *
     */
    void do_merge_nodes(vector< AbstractNodePtr  > &nodes, uint32_t node_start_ind, int prev_entry_count,
                        uint32_t max_fill_entries) {
        assert(prev_entry_count >= 0);

        if (node_start_ind == nodes.size()) {
            return;
        }

        AbstractNodePtr n = nodes[node_start_ind];

        // We can only fill maxFillEntries and out of which prevEntryCount has to be accommodated.
        int avail_slots = max_fill_entries - n->get_total_entries() - prev_entry_count;

        // If we have still more room, just pull in most from next nodes as much as possible.
        uint32_t next_node_ind = node_start_ind + 1;
        while ((avail_slots > 0) && (next_node_ind < nodes.size())) {
            AbstractNodePtr nextn = nodes[next_node_ind++];
            uint32_t pull_entries = min(avail_slots, (int) nextn->get_total_entries());
            n->move_in_from_right_by_entries(*nextn, pull_entries);

            avail_slots -= pull_entries;
        }

        uint32_t arrear_entry_count = (avail_slots < 0) ? (avail_slots * (-1)) : 0;
        do_merge_nodes(nodes, node_start_ind + 1, arrear_entry_count, max_fill_entries);

        // Now we should have room to write all prev nodes arrear entries.
        if (prev_entry_count != 0) {
            assert(node_start_ind != 0);
            AbstractNodePtr prevn = nodes[node_start_ind - 1];
            prevn->move_out_to_right_by_entries(*n, prev_entry_count);
        }
    }
#endif

    auto merge_nodes(AbstractNodePtr parent_node, std::vector< int > &indices_list) {
        struct merge_info {
            AbstractNodePtr node;
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
        for (auto i = 0; i < indices_list.size(); i++) {
            parent_node->get(indices_list[i], &child_ptr, false /* copy */);

            merge_info m;
            m.node = read_node(child_ptr.get_node_id());
            m.freed = false;
            m.modified = false;
            m.parent_index = indices_list[i];
            minfo.push_back(m);
            lock_node(m.node, locktype::LOCKTYPE_WRITE);
        }


#ifndef NDEBUG
        if (CVLOG_IS_ON(VMOD_BTREE_MERGE, 4)) {
            LOG(INFO) << "Before Merge Nodes:\nParent node:\n" << parent_node->to_string();
            for (auto i = 0; i < minfo.size(); i++) {
                LOG(INFO) << "Child node " << i + 1 << "\n" << minfo[i].node->to_string();
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
                if (minfo[i].node->move_in_from_right_by_size(m_btree_cfg, *minfo[j].node, pull_size)) {
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
                    balanced_size != m_btree_cfg.get_node_size()) {
                balanced_size = m_btree_cfg.get_node_size();
                continue;
            }

            i = j++;
            minfo[i].parent_index -= ndeleted_nodes; // Adjust the parent index for deleted nodes (i.e. removed entries)
        }

        // Its time to write the parent node and loop again to write all modified nodes and free freed nodes
        DCVLOG(VMOD_BTREE_MERGE, 4) << "After merging node\n########################Parent Node: "
                                    << parent_node->to_string();
        write_node(parent_node);
        assert(!minfo[0].freed); // If we merge it, we expect the left most one has at least 1 entry.
        // TODO: Above assumption will not be valid if we are merging all empty nodes. Need to study that.

        for (auto n = 0; n < minfo.size(); n++) {
            if (minfo[n].freed) {
                DCVLOG(VMOD_BTREE_MERGE, 2) << "Child Node " << n << ": Freeing the node id = "
                                            << minfo[n].node->get_node_id().to_integer();
                if (minfo[n].node->any_upgrade_waiters()) {
                    minfo[n].node->set_valid_node(false);
                } else {
                    free_node(minfo[n].node);
                    m_stats.dec_count(minfo[n].node->is_leaf() ? BTREE_STATS_LEAF_NODE_COUNT : BTREE_STATS_INT_NODE_COUNT);
                }
            } else if (minfo[n].modified) {
                // If we have indeed modified, lets get the last key and put in the entry into parent node
                BNodeptr nptr(minfo[n].node->get_node_id());
                if (minfo[n].parent_index == parent_node->get_total_entries()) {
                    parent_node->update(minfo[n].parent_index, nptr);
                } else {
                    K last_key;
                    minfo[n].node->get_last_key(&last_key);
                    parent_node->update(minfo[n].parent_index, last_key, nptr);
                }

                DCVLOG(VMOD_BTREE_MERGE, 4) << "Child Node " << n << ":\n" << minfo[n].node->to_string();
                write_node(minfo[n].node);
            }
        }

        // Loop again in reverse order to unlock the nodes. Freed nodes need not be unlocked
        for (int n = minfo.size()-1; n >= 0; n--) {
            if (!minfo[n].freed) {
                unlock_node(minfo[n].node, true);
#ifndef DEBUG
            } else {
                // We need to explicitly removed the order, other it will cause false assert
                dec_check_lock_debug(minfo[n].node);
#endif
            }
        }

        ret.nmerged = minfo.size() - ndeleted_nodes;
        return ret;
    }

    AbstractNodePtr alloc_leaf_node() {
        AbstractNodePtr n = alloc_node(m_btree_cfg.get_leaf_node_type(), true /* isLeaf */);
        n->set_leaf(true);
        m_stats.inc_count(BTREE_STATS_LEAF_NODE_COUNT);
        return n;
    }

    AbstractNodePtr alloc_interior_node() {
        AbstractNodePtr n = alloc_node(m_btree_cfg.get_interior_node_type(), false /* isLeaf */);
        n->set_leaf(false);
        m_stats.inc_count(BTREE_STATS_INT_NODE_COUNT);
        return n;
    }

    void lock_node(AbstractNodePtr node, omds::thread::locktype type) {
        node->lock(type);
#ifndef NDEBUG
        inc_lock_debug(node);
#endif
    }

    void unlock_node(AbstractNodePtr node, bool release) {
        node->unlock();
#ifndef NDEBUG
        dec_check_lock_debug(node);
#endif
#if 0
        if (release) {
            release_node(node);
        }
#endif
    }

#ifndef NDEBUG
    static void init_lock_debug() {
        locked_count = 0;
    }

    static void check_lock_debug() {
        if (locked_count != 0) {
            LOG(ERROR) << "There are " << locked_count << " on the exit of API";
            assert(0);
        }
    }

    static void inc_lock_debug(AbstractNodePtr node) {
        locked_nodes[locked_count++] = node.get();
//        std::cout << "lock_node: node = " << (void *)node << " Locked count = " << locked_count << std::endl;
    }

    static void dec_check_lock_debug(AbstractNodePtr node) {
        // std::cout << "unlock_node: node = " << (void *)node << " Locked count = " << locked_count << std::endl;
        if (node == locked_nodes[locked_count - 1]) {
            locked_count--;
        } else if ((locked_count > 1) && (node == locked_nodes[locked_count-2])) {
            locked_nodes[locked_count-2] = locked_nodes[locked_count-1];
            locked_count--;
        } else {
            if (locked_count > 1) {
                LOG(ERROR) << "unlock_node: node = " << (void *) node.get() << " Locked count = " << locked_count
                          << " Expecting nodes = " << (void *) locked_nodes[locked_count - 1] << " or "
                          << (void *) locked_nodes[locked_count - 2];
            } else {
                LOG(ERROR) << "unlock_node: node = " << (void *) node.get() << " Locked count = " << locked_count
                          << " Expecting node = " << (void *) locked_nodes[locked_count - 1];
            }
            assert(0);
        }
    }
#endif

protected:
    void init_btree(const BtreeConfig &cfg) {
        m_btree_cfg = cfg;

        // TODO: Raise Exception when maxObjs > 2 Billion
        assert(m_btree_cfg.get_node_size() != 0);

        // Give leeway for node header in node size.
        uint32_t node_area_size = m_btree_cfg.get_node_size() - m_btree_cfg.get_node_header_size() -
                sizeof(AbstractNode<K, V, NodeSize>);

        // calculate number of nodes
        uint32_t max_leaf_nodes = (m_btree_cfg.get_max_objs() *
                                   (m_btree_cfg.get_max_key_size() + m_btree_cfg.get_max_value_size()))
                                  / node_area_size + 1;
        max_leaf_nodes += (100 * max_leaf_nodes) / 60; // Assume 60% btree full

        // Assume 5% for interior nodes
        m_max_nodes = max_leaf_nodes + ((double) max_leaf_nodes * 0.05) + 1;

        m_btree_cfg.calculate_max_leaf_entries_per_node();
        m_btree_cfg.calculate_max_interior_entries_per_node();

        m_root_node = INVALID_BNODEID;

        m_inited = true;
    }

    void create_root_node() {
        // Assign one node as root node and initially root is leaf
        AbstractNodePtr root = alloc_leaf_node();
        m_root_node = root->get_node_id();
        write_node(root);
        //release_node(root);
    }

    virtual uint32_t get_max_nodes() {
        return m_max_nodes;
    }

    BtreeConfig *get_config() {
        return &m_btree_cfg;
    }

#if 0
    void release_node(AbstractNodePtr node)
    {
        node->derefNode();
    }
#endif
};

#ifndef NDEBUG
template <typename K, typename V, size_t NodeSize>
thread_local int Btree<K, V, NodeSize>::locked_count = 0;

template <typename K, typename V, size_t NodeSize>
thread_local std::array<AbstractNode<K, V, NodeSize> *, MAX_BTREE_DEPTH> Btree<K, V, NodeSize>::locked_nodes = {{}};
#endif

}}
#endif
