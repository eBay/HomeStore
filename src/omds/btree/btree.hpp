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
#include "omds/thread/lock.hpp"
#include "btree_internal.h"
#include "abstract_node.hpp"

using namespace std;
using namespace omds::thread;

namespace omds { namespace btree {

#if 0
#define container_of(ptr, type, member) ({                      \
        (type *)( (char *)ptr - offsetof(type,member) );})
#endif


static __thread int btree_locked_count;

template<typename K, typename V>
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
    virtual AbstractNode<K, V> *alloc_node(btree_nodetype_t btype, bool is_leaf) = 0;
    virtual uint32_t get_node_header_size() const = 0;
    virtual AbstractNode<K, V> *read_node(bnodeid_t node_ptr) = 0;
    virtual void write_node(AbstractNode<K, V> *node) = 0;
    virtual void release_node(AbstractNode<K, V> *node) = 0;
    virtual void free_node(AbstractNode<K, V> *node) = 0;

private:
#ifdef CLASS_DEFINITIONS
    bool do_insert(AbstractNode<K, V> *my_node, omds::thread::locktype_t curlock, BtreeKey& k, BtreeValue& v, int ind_hint);

    bool do_get(AbstractNode<K, V> *mynode, BtreeKey &key, BtreeValue *outval);

    btree_status_t do_remove(AbstractNode<K, V> *mynode, omds::thread::locktype_t curlock, BtreeKey &key);

    bool upgrade_node(AbstractNode<K, V> *mynode, AbstractNode<K, V> *childnode, omds::thread::locktype_t &curlock,
                      omds::thread::locktype_t child_curlock);
    void split_node(AbstractNode<K, V> *parent_node, AbstractNode<K, V> *child_node, uint32_t parent_ind, BtreeKey **out_split_key);
    bool merge_nodes(AbstractNode<K, V> *parent_node, std::vector<uint32_t> &indices_list);

    AbstractNode* get_child_node(AbstractNode<K, V> *int_node, omds::thread::locktype_t curlock, BtreeKey& key, uint32_t &outind);
    AbstractNode* get_child_node_range(AbstractNode<K, V> *int_node, KeyRegex& kr, uint32_t &outind, bool *isfound);

    void check_split_root();
    void check_collapse_root();

    AbstractNode<K, V> *alloc_leaf_node();
    AbstractNode<K, V> *alloc_interior_node();
    void lock_node(AbstractNode<K, V> *node, omds::thread::locktype_t type);
    void unloc_node(AbstractNode<K, V> *node, bool release);

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

    ////////////////// Implementation /////////////////////////
public:
    Btree() : m_inited(false) {}

    void put(const BtreeKey &k, const BtreeValue &v, PutType put_type) {
        omds::thread::locktype acq_lock = omds::thread::LOCKTYPE_READ;
        int ind;

        assert(btree_locked_count == 0);
        //assert(OmDB::getGlobalRefCount() == 0);

        m_btree_lock.read_lock();

    retry:
        AbstractNode<K, V> *root = read_node(m_root_node);
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

#ifdef DEBUG
        if (btree_locked_count != 0) {
            cout << "Locked count for insert = " << btree_locked_count << endl;
        }
        assert(btree_locked_count == 0);
#endif
        //assert(OmDB::getGlobalRefCount() == 0);
    }

    bool get(const BtreeKey &key, BtreeValue *outval) {
        return get(key, nullptr, outval);
    }

    bool get(const BtreeKey &key, BtreeKey *outkey, BtreeValue *outval) {
        return get_any(BtreeSearchRange(key), outkey, outval);
    }

    bool get_any(const BtreeSearchRange &range, BtreeKey *outkey, BtreeValue *outval) {
        bool is_found;
        assert(btree_locked_count == 0);
        //assert(OmDB::getGlobalRefCount() == 0);

        m_btree_lock.read_lock();
        AbstractNode<K, V> *root = read_node(m_root_node);
        lock_node(root, omds::thread::locktype::LOCKTYPE_READ);

        is_found = do_get(root, range, outkey, outval);
        m_btree_lock.unlock();

        // TODO: Assert if key returned from do_get is same as key requested, incase of perfect match
        assert(btree_locked_count == 0);
        //assert(OmDB::getGlobalRefCount() == 0);
        return is_found;
    }

    /* Given a regex key, tries to get all data that falls within the regex. Returns all the values
     * and also number of values that fall within the ranges */
    uint32_t get_multi(const BtreeSearchRange &range, std::vector<std::pair<BtreeKey *, BtreeValue *>> outval) {
    }

    bool remove_any(const BtreeSearchRange &range, BtreeKey *outkey, BtreeValue *outval) {
        omds::thread::locktype acq_lock = omds::thread::locktype::LOCKTYPE_READ;
        bool is_found = false;

        assert(btree_locked_count == 0);
#ifdef REFCOUNT_DEBUG
        assert(OmDBGlobals::getGlobalRefCount() == 0);
#endif

        m_btree_lock.read_lock();

    retry:
        AbstractNode<K, V> *root = read_node(m_root_node);
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
        assert(btree_locked_count == 0);
#ifdef REFCOUNT_DEBUG
        assert(OmDBGlobals::getGlobalRefCount() == 0);
#endif
        return is_found;
    }

    bool remove(const BtreeKey &key, BtreeValue *outval) {
        remove_any(BtreeSearchRange(key), nullptr, outval);
    }

private:
    bool do_get(AbstractNode<K, V> *my_node, const BtreeSearchRange &range, BtreeKey *outkey, BtreeValue *outval) {
        if (my_node->is_leaf()) {
            auto result = my_node->find(range, outkey, outval);
            unlock_node(my_node, true);
            return (result.found);
        }

        BNodeptr child_ptr;
        auto result = my_node->find(range, nullptr, &child_ptr);
        AbstractNode<K, V> *child_node = read_node(child_ptr.get_node_id());

        lock_node(child_node, omds::thread::LOCKTYPE_READ);
        unlock_node(my_node, true);
        return (do_get(child_node, range, outkey, outval));
    }

#ifdef NEED_REWRITE
    uint32_t do_multiget(AbstractNode<K, V> *my_node, const BtreeRegExKey &rkey, uint32_t max_nvalues,
                         std::vector<std::pair<BtreeKey *, BtreeValue *>> &out_values) {
        if (my_node->is_leaf()) {
            auto result = my_node->find(key, outkey, outval);
            unlock_node(my_node, true);
            return (result.match_type != NO_MATCH);
        }

        BNodeptr child_ptr;
        auto result = my_node->find(rkey, nullptr, &child_ptr);
        AbstractNode<K, V> *child_node = read_node(child_ptr.get_node_id());

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
    bool upgrade_node(AbstractNode<K, V> *my_node, AbstractNode<K, V> *child_node, omds::thread::locktype &cur_lock,
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
            if (child_node) release_node(child_node);
        }
        return ret; // We have successfully upgraded the node.
    }

#if 0
    /* This method tries to get the child node from an interior parent node, based on the key. It also provides the
     * index within the parent node, which is pointing to the child node. In case if the child node is an edge node,
     * instead of creating a new child node */
    AbstractNode<K, V> *get_child_node(AbstractNode<K, V> *int_node, omds::thread::locktype curlock, const BtreeKey &key,
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

    AbstractNode<K, V> *get_child_node(AbstractNode<K, V> *int_node, const BtreeSearchRange &range,
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
    bool do_put(AbstractNode<K, V> *my_node, omds::thread::locktype curlock, const BtreeKey &k, const BtreeValue &v,
                int ind_hint, PutType put_type) {
        if (my_node->is_leaf()) {
            assert(curlock == LOCKTYPE_WRITE);

            bool ret = my_node->put(k, v, put_type);
            if (ret) {
                write_node(my_node);
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
        AbstractNode<K, V> *child_node = get_child_node(my_node, BtreeSearchRange(k), &ind, &is_found);
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
            goto retry;
        }

        unlock_node(my_node, true);
        return (do_put(child_node, child_cur_lock, k, v, ind_hint, put_type));

        // Warning: Do not access childNode or myNode beyond this point, since it would
        // have been unlocked by the recursive function and it could also been deleted.
    }

    btree_status_t do_remove(AbstractNode<K, V> *my_node, omds::thread::locktype curlock, const BtreeSearchRange &range,
                             BtreeKey *outkey, BtreeValue *outval) {
        if (my_node->is_leaf()) {
            assert(curlock == LOCKTYPE_WRITE);

            bool is_found = my_node->remove_one(range, outkey, outval);
            if (is_found) {
                write_node(my_node);
            }

            unlock_node(my_node, true);
            return is_found ? BTREE_ITEM_FOUND : BTREE_NOT_FOUND;
        }

    retry:
        locktype child_cur_lock = LOCKTYPE_NONE;

        // Get the childPtr for given key.
        int ind;

        bool is_found = true;
        AbstractNode<K, V> *child_node = get_child_node(my_node, range, &ind, &is_found);
        if (!is_found || (child_node == nullptr)) {
            unlock_node(my_node, true);
            return BTREE_NOT_FOUND;
        }

        // Directly get write lock for leaf, since its a delete.
        child_cur_lock = (child_node->is_leaf()) ? LOCKTYPE_WRITE : LOCKTYPE_READ;
        lock_node(child_node, child_cur_lock);

        // Check if child node is minimal.
        if (child_node->is_merge_neeeded(m_btree_cfg)) {
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
                    release_node(child_node);
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
        AbstractNode<K, V> *new_root_int_node = nullptr;

        m_btree_lock.write_lock();
        AbstractNode<K, V> *root = read_node(m_root_node);
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

#ifndef NDEBUG
        //cout << "New Root node " << endl;
        //new_root_int_node->print();
#endif

        release_node(new_root_int_node);
        done:
        m_btree_lock.unlock();
    }

    void check_collapse_root() {
        AbstractNode<K, V> *child_node = nullptr;

        m_btree_lock.write_lock();
        AbstractNode<K, V> *root = read_node(m_root_node);
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
        m_root_node = child_node->get_node_id();

        release_node(child_node);
        done:
        m_btree_lock.unlock();
    }

    void split_node(AbstractNode<K, V> *parent_node, AbstractNode<K, V> *child_node, uint32_t parent_ind,
                    BtreeKey *out_split_key) {
        BNodeptr nptr;

        // Create a new child node and split the keys by half.
        AbstractNode<K, V> *child_node1 = child_node;
        AbstractNode<K, V> *child_node2 = child_node->is_leaf() ? alloc_leaf_node() : alloc_interior_node();

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
        release_node(child_node2);

#if 0
        #ifndef NDEBUG
        cout << "After split " << endl;
        cout << "#####################" << endl;
        parent_node->print();
        child_node1->print();
        child_node2->print();
#endif
#endif

        // NOTE: Do not access parentInd after insert, since insert would have
        // shifted parentNode to the right.
    }

#if 0
    bool merge_nodes(AbstractNode<K, V> *parent_node, vector< int > &indices_list) {
        vector< AbstractNode<K, V> * > nodes(indices_list.size());
        BNodeptr child_ptr;
        uint32_t ntotal_entries = 0;
        int i;
        int n;
        bool ret = true;
        AbstractNode<K, V> *cur_last_n = nullptr;
        AbstractNode<K, V> *prev_last_n = nullptr;

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
    void do_merge_nodes(vector< AbstractNode<K, V> * > &nodes, uint32_t node_start_ind, int prev_entry_count,
                        uint32_t max_fill_entries) {
        assert(prev_entry_count >= 0);

        if (node_start_ind == nodes.size()) {
            return;
        }

        AbstractNode<K, V> *n = nodes[node_start_ind];

        // We can only fill maxFillEntries and out of which prevEntryCount has to be accommodated.
        int avail_slots = max_fill_entries - n->get_total_entries() - prev_entry_count;

        // If we have still more room, just pull in most from next nodes as much as possible.
        uint32_t next_node_ind = node_start_ind + 1;
        while ((avail_slots > 0) && (next_node_ind < nodes.size())) {
            AbstractNode<K, V> *nextn = nodes[next_node_ind++];
            uint32_t pull_entries = min(avail_slots, (int) nextn->get_total_entries());
            n->move_in_from_right_by_entries(*nextn, pull_entries);

            avail_slots -= pull_entries;
        }

        uint32_t arrear_entry_count = (avail_slots < 0) ? (avail_slots * (-1)) : 0;
        do_merge_nodes(nodes, node_start_ind + 1, arrear_entry_count, max_fill_entries);

        // Now we should have room to write all prev nodes arrear entries.
        if (prev_entry_count != 0) {
            assert(node_start_ind != 0);
            AbstractNode<K, V> *prevn = nodes[node_start_ind - 1];
            prevn->move_out_to_right_by_entries(*n, prev_entry_count);
        }
    }
#endif

    auto merge_nodes(AbstractNode<K, V> *parent_node, std::vector< int > &indices_list) {
        struct merge_info {
            AbstractNode<K, V> *node;
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

            minfo[i].node = read_node(child_ptr.get_node_id());
            minfo[i].freed = false;
            minfo[i].modified = false;
            minfo[i].parent_index = indices_list[i];
            lock_node(minfo[i].node, locktype::LOCKTYPE_WRITE);
        }

        // Rebalance entries for each of the node and mark any node to be removed, if empty.
        auto i = 0U; auto j = 1U;
        auto balanced_size = m_btree_cfg.get_ideal_fill_size();
        while ((i < indices_list.size() - 1) && (j < indices_list.size())) {
            minfo[j].parent_ind -= ndeleted_nodes; // Adjust the parent index for deleted nodes

            if (minfo[i].node->get_occupied_size(m_btree_cfg) < balanced_size) {
                // We have room to pull some from next node
                uint32_t pull_size = balanced_size - minfo[i].node->get_occupied_size(m_btree_cfg);
                if (minfo[i].node->move_in_from_right_by_size(*minfo[j].node, pull_size)) {
                    minfo[i].modified = true;
                    ret.merged = true;
                }

                if (minfo[j].node->get_total_entries() == 0) {
                    // We have removed all the entries from the next node, remove the entry in parent and move on to
                    // the next node.
                    minfo[j].freed = true;
                    parent_node->remove(minfo[j].parent_ind);
                    minfo[i].node->set_next_bnode(minfo[j].node->get_next_bnode());
                    ndeleted_nodes++; j++;
                    continue;
                }
            } else if (minfo[i].modified) {
                // We reached maximum amount which can be pulled in, if we have indeed modified, lets get the last
                // key and put in the entry into parent node
                BNodeptr nptr(minfo[i].node->get_node_id());
                if (minfo[i].parent_ind == parent_node->get_total_entries()) {
                    parent_node->update(minfo[i].parent_ind, nptr);
                } else {
                    K last_key;
                    minfo[i].node->get_last_key(&last_key);
                    parent_node->update(minfo[i].parent_ind, last_key, nptr);
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
            minfo[i].parent_ind -= ndeleted_nodes; // Adjust the parent index for deleted nodes (i.e. removed entries)
        }

        // Its time to write the parent node and loop again to write all modified nodes and free freed nodes
        write_node(parent_node);
        assert(!minfo[0].freed); // If we merge it, we expect the left most one has at least 1 entry.
        // TODO: Above assumption will not be valid if we are merging all empty nodes. Need to study that.
        if (minfo[0].modified) write_node(minfo[0].node);
        for (auto n = 1; n < minfo.size(); n++) {
            if (minfo[n].freed) {
                if (minfo[n]->any_upgrade_waiters()) {
                    minfo[n].node->set_valid_node(false);
                } else {
                    free_node(minfo[n].node);
                }
            } else if (minfo[n].modified) {
                write_node(minfo[n].node);
            }
        }

        // Loop again in reverse order to unlock the nodes. Freed nodes need not be unlocked
        for (auto n = minfo.size()-1; n >= 0; n--) {
            if (!minfo[n].freed) {
                unlock_node(minfo[n].node, true);
            }
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

        ret.nmerged = minfo.size() - ndeleted_nodes;
        return ret;
    }

    AbstractNode<K, V> *alloc_leaf_node() {
        AbstractNode<K, V> *n = alloc_node(m_btree_cfg.get_leaf_node_type(), true /* isLeaf */);
        n->set_leaf(true);
        return n;
    }

    AbstractNode<K, V> *alloc_interior_node() {
        AbstractNode<K, V> *n = alloc_node(m_btree_cfg.get_interior_node_type(), false /* isLeaf */);
        n->set_leaf(false);
        return n;
    }

    void lock_node(AbstractNode<K, V> *node, omds::thread::locktype type) {
        node->lock(type);
        btree_locked_count++;
    }

    void unlock_node(AbstractNode<K, V> *node, bool release) {
        node->unlock();
        btree_locked_count--;
        if (release) {
            release_node(node);
        }
    }

protected:
    void init_btree(const BtreeConfig &cfg) {
        m_btree_cfg = cfg;

        // TODO: Raise Exception when maxObjs > 2 Billion
        assert(m_btree_cfg.get_node_size() != 0);

        // Give leeway for node header in node size.
        uint32_t node_area_size = m_btree_cfg.get_node_size() - get_node_header_size();

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
#ifdef DEBUG
        btree_locked_count = 0;
#endif
    }

    void create_root_node() {
        // Assign one node as root node and initially root is leaf
        AbstractNode<K, V> *root = alloc_leaf_node();
        if (root == nullptr) {
            cout << "allocLeafNode root is nullptr" << endl;
        }
        m_root_node = root->get_node_id();
        write_node(root);
        release_node(root);
    }

    virtual uint32_t get_max_nodes() {
        return m_max_nodes;
    }

    BtreeConfig *get_config() {
        return &m_btree_cfg;
    }

#if 0
    void release_node(AbstractNode<K, V> *node)
    {
        node->derefNode();
    }
#endif
};

}}
#endif
