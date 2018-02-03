/*
 * varlen_node.hpp
 *
 *  Created on: 18-Feb-2017
 *      Author: hkadayam
 */

#ifndef BTREE_VARLEN_NODE_HPP_
#define BTREE_VARLEN_NODE_HPP_

#include "physical_node.hpp"
#include <cassert>

namespace omds { namespace btree {

struct btree_obj_record {

};

struct var_value_record : public btree_obj_record {
    uint16_t m_obj_offset:14;
    uint16_t reserved:2;
} __attribute((packed));

struct var_key_record : public btree_obj_record {
    uint16_t m_obj_offset:14;
    uint16_t reserved:2;
} __attribute((packed));

struct var_obj_record : public btree_obj_record {
    uint16_t m_obj_offset:14;
    uint16_t reserved1:2;

    uint16_t m_keylen:14;
    uint16_t reserved2:2;
} __attribute((packed));

struct var_node_header {
    uint16_t m_last_offset;
} __attribute((packed));

#define memrshift(ptr, size) (memmove(ptr, ptr+size, size))
#define memlshift(ptr, size) (memmove(ptr, ptr-size, size))

template< typename K, typename V >
class VarValueNode : public AbstractNode<K, V> {
    VarValueNode(const BtreeConfig &cfg, bnodeid_t id, bool init_pers, bool init_trans) :
            AbstractNode(id, init_pers, init_trans) {
        this->set_node_type(BTREE_NODETYPE_VAR_VALUE);
        if (init_pers) {
            get_node_header()->m_last_offset = (uint16_t) (this->get_node_space() + cfg.get_node_size() -
                                                           (uint8_t *) this);
        }
    }

    // Insert the key and value in provided index
    // Assumption: Node lock is already taken
    void insert(int ind, const BtreeKey &key, const BtreeValue &val) override {
        // TODO: Validate the available space is present
        assert(ind <= get_total_entries());

        // Determine the ptr and size for moving record
        uint8_t *rec_ptr = (uint8_t *) get_nth_record(ind);
        int obj_size = K::get_fixed_size() + val.get_blob_size();

        uint8_t *obj_ptr;
        if (get_total_entries() == 0) {
            obj_ptr = get_node_space() + get_node_header()->m_last_offset - obj_size;
        } else if (ind == get_total_entries()) {
            obj_ptr = get_nth_obj(ind - 1) - obj_size;
        } else {
            // Determine the current ind ptr and last ptr
            obj_ptr = get_nth_obj(ind);
            uint8_t *last_obj_ptr = get_nth_obj(get_total_entries() - 1);

            // Shift the object data to the left and then record to the right.
            memmove(last_obj_ptr - obj_size, last_obj_ptr, get_objs_len(ind, get_total_entries() - 1));
            memmove(rec_ptr + sizeof(var_value_record), rec_ptr,
                    (get_total_entries() - ind) * sizeof(var_value_record));
        }

        // Populate the new record
        var_value_record *r = (var_value_record *) rec_ptr;
        r->m_obj_offset = obj_ptr - get_node_space();

        // Fill in the new key in object area
        uint32_t s;
        memcpy(obj_ptr, key.get_blob(&s), K::get_fixed_size());
        assert(s == K::get_fixed_size());

        // Fill in the new value in object area
        obj_ptr += s;
        memcpy(obj_ptr, val.get_blob(&s), val.get_blob_size());
        assert(s == val.get_blob_size());

        // Increment the entries
        inc_entries();

        // At this point, subsequent entries offset need to be adjusted to the left
        for (auto i = ind + 1; i < get_total_entries(); i++) {
            var_value_record *r = get_nth_record(i);
            r->m_obj_offset -= obj_size;
        }

        // Finally increment generation
        inc_gen();

#ifdef DEBUG
        //print();
#endif
    }

    void update(uint32_t ind, BtreeValue &val) {
        assert(ind <= get_total_entries());

        // If we are updating the edge value, none of the other logic matter.
        // Just update edge value and move on
        if (ind == get_total_entries()) {
            assert(!is_leaf());
            set_edge_value(val);
            goto done;
        }

        // Determine the current obj ptr and last object ptr.
        uint8_t *obj_ptr = get_nth_obj(ind);
        uint8_t *last_obj_ptr = get_nth_obj(get_total_entries() - 1);

        // Compute the difference between old and new lenght
        int cur_len = get_nth_obj_size(ind);
        int new_len = K::get_fixed_size() + val.get_blob_size();
        int diff_len = cur_len - new_len;

        // Move the data to left or right based on expand or shrink space
        memmove(last_obj_ptr + diff_len, last_obj_ptr,
                get_objs_len(ind + 1, get_total_entries() - 1) + diff_len);
        obj_ptr += diff_len;

        // Update the value in the write_ptr
        uint32_t sz;
        uint8_t *val_ptr = val.get_blob(&sz);
        memcpy(obj_ptr + K::get_fixed_size(), val_ptr, sz);

        // Update all the entries upto this with this new offset
        for (auto i = ind; i < get_total_entries(); i++) {
            var_value_record *r = get_nth_record(i);
            r->m_obj_offset += diff_len;
        }

        done:
        // TODO: Check if we need to upgrade the gen and impact of doing
        // so with performance. It is especially needed for non similar
        // key/value pairs
        inc_gen();
    }

    void remove(int ind) {
        if (ind == get_total_entries()) {
            assert(!is_leaf());
            set_edge_value(INVALID_BNODEID);
            goto done;
        }

        uint8_t *obj_ptr = get_nth_obj(ind);
        uint8_t *last_obj_ptr = get_nth_obj(get_total_entries() - 1);
        int obj_size = get_nth_obj_size(ind);

        memmove(last_obj_ptr + obj_size, last_obj_ptr,
                get_objs_len(ind + 1, get_total_entries() - 1));

        // At this point, subsequent entries offset need to be adjusted to the left
        for (auto i = ind + 1; i < get_total_entries(); i++) {
            var_value_record *r = get_nth_record(i);
            r->m_obj_offset += obj_size;
        }

        if (ind < get_total_entries() - 1) {
            uint8_t *rec_ptr = (uint8_t *) get_nth_record(ind + 1);
            memmove(rec_ptr - sizeof(var_value_record), rec_ptr,
                    (get_total_entries() - ind) * sizeof(var_value_record));
        }
        dec_entries();
        done:
        inc_gen();
    }

    void get(int ind, BtreeValue *outval, bool copy) {
        // Need edge index
        if (ind == get_total_entries()) {
            assert(!is_leaf());

            assert(has_valid_edge());
            get_edge_value(outval);
        } else {
            get_nth_value(ind, outval, copy);
        }
    }

    uint32_t get_occupied_size() const {
        return this->get_node_area_size()
    }

    void move_out_right(AbstractNode &othern, uint32_t nentries) {

    }

    // This method verifies if we can safely insert an entry into the node.
    // It will operate on node being full/free. For range key, if there is
    // a match, but not a full match, it will assume atleast 3 such values
    // need to be inserted.
    bool is_split_needed(BtreeConfig &cfg, BtreeKey &key, BtreeValue &value, int *out_ind_hint) {
        V curval;
        int size_needed;

        bool found = find(key, nullptr, &curval, out_ind_hint);
        if (!found) {
            // We need to insert, this newly. Find out if we have space for value.
            size_needed = key.get_blob_size() + sizeof(var_value_record);
            size_needed += (is_leaf() ? value.get_blob_size() : BNodeptr::get_size());
        } else {
            // This is an update. We need the difference in current vs new value.
            // Please note that it can be negative, since value could be shrinking as well.
            size_needed = (is_leaf() ? value.get_blob_size() : BNodeptr::get_size());
            size_needed -= curval.get_blob_size();

            if (key.is_range_key()) {
                BtreeRangeKey &rkey = static_cast<BtreeRangeKey &>(key);
                K match_key;
                static_assert((std::is_base_of< BtreeRangeKey, K >::value),
                              "K must be a derived class of BtreeRangeKey");

                // For a range key, get the matched key and compare if both keys
                // are fully matched. If not fully matched, update might be
                // partial and hence we might need to create 3 entries.
                get_nth_key(*out_ind_hint, &match_key, false /* copy */);
                assert(match_key.is_range() == true);

                if (!rkey.is_full_match(match_key)) {
                    size_needed += (curval.get_blob_size() * 2);
                }
            }
        }

        return (size_needed > get_free_space());
    }

private:
    ////////// Overridden private methods //////////////
    int get_nth_obj_size(int ind) {
        assert(ind < get_total_entries());

        if (ind == 0) {
            return (get_last_offset() - get_nth_record(ind)->m_obj_offset);
        } else {
            return get_nth_obj(ind) - get_nth_obj(ind - 1);
        }
    }

    void set_nth_obj(int ind, BtreeKey &k, BtreeValue &v) {
        uint8_t *obj = get_nth_obj(ind);

        uint32_t sz;
        uint8_t *ptr = k.get_blob(&sz);
        memcpy(obj, ptr, sz);

        obj += sz;
        ptr = v.get_blob(&sz);
        memcpy(obj, ptr, sz);
    }

    void get_nth_key(int ind, BtreeKey *outkey, bool copy) {
        assert(ind < get_total_entries());

        uint8_t *obj = get_nth_obj(ind);
        if (copy) {
            outkey->copy_blob(obj, K::get_fixed_size());
        } else {
            outkey->set_blob(obj, K::get_fixed_size());
        }
    }

    void get_nth_value(int ind, BtreeValue *outval, bool copy) {
        assert(ind < get_total_entries());

        uint8_t *obj = get_nth_obj(ind);
        uint32_t size = get_nth_obj_size(ind);
        if (copy) {
            outval->copy_blob(obj + K::get_fixed_size(), size - K::get_fixed_size());
        } else {
            outval->set_blob(obj + K::get_fixed_size(), size - K::get_fixed_size());
        }
    }

    var_value_record *get_nth_record(int ind) {
        uint8_t *ptr = get_node_space() + sizeof(var_node_header) + (sizeof(var_value_record) * ind);
        return (var_value_record *) ptr;
    }

    ///////////// Other Private Methods //////////////////
    uint8_t *get_nth_obj(int ind) {
        assert(ind < get_total_entries());

        return get_node_space() + get_nth_record(ind)->m_obj_offset;
    }

    uint16_t get_last_offset() {
        return get_node_header()->m_last_offset;
    }

    inline var_node_header *get_node_header() {
        return (var_node_header *) (get_node_space());
    }

    // Gets the length of objects between start and end index
    inline uint32_t get_objs_len(int start_ind, int end_ind) {
        if (end_ind < start_ind) {
            return 0;
        }

        int start_offset = (start_ind == 0) ? get_last_offset() : get_nth_record(start_ind - 1)->m_obj_offset;
        int end_offset = get_nth_record(end_ind)->m_obj_offset;

        return start_offset - end_offset;
    }

    int get_free_space() {
        return (get_last_offset() - (sizeof(var_value_record) * get_total_entries()) - sizeof(var_node_header));
    }
};
}
}

#endif /* BTREE_VARLEN_NODE_HPP_ */
