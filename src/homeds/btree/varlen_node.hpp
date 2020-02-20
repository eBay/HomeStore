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
#include "boost/range/irange.hpp"
#include <sds_logging/logging.h>

SDS_LOGGING_DECL(btree_generics)

namespace homeds { namespace btree {

struct btree_obj_record {
    uint16_t m_obj_offset:14;
    uint16_t reserved:2;
} __attribute((packed));;

struct var_value_record : public btree_obj_record {
    uint16_t m_value_len:14;
    uint16_t reserved:2;
} __attribute((packed));

struct var_key_record : public btree_obj_record {
    uint16_t m_key_len:14;
    uint16_t reserved:2;
} __attribute((packed));

struct var_obj_record : public btree_obj_record {
    uint16_t m_key_len:14;
    uint16_t reserved:2;

    uint16_t m_value_len:14;
    uint16_t reserved2:2;
} __attribute((packed));

struct var_node_header {
    uint16_t m_tail_arena_offset;       // Tail side of the arena where new keys are inserted
    uint16_t m_available_space;
    uint16_t m_init_available_space; // remember initial node area size to later use for compaction
    //TODO: 
    // We really dont require storing m_init_available_space in each node. 
    // Instead add method in variant node to fetch config
} __attribute((packed));

#define memrshift(ptr, size) (memmove(ptr, ptr+size, size))
#define memlshift(ptr, size) (memmove(ptr, ptr-size, size))

#define NodeTypeImpl btree_node_type::VAR_VALUE
#define VariableNode VariantNode<btree_node_type::VAR_VALUE, K, V>
#define VariantNodeType VariantNode<NodeType, K, V>
        
template< btree_node_type NodeType, typename K, typename V>
struct VarNodeSpecificImpl {
    static uint16_t get_nth_key_len(const VariantNodeType *node, int ind) {return 0;}
    static uint16_t get_nth_value_len(const VariantNodeType *node, int ind) {return 0;}
    static uint16_t get_record_size(const VariantNodeType *node) {return 0;}

    static void set_nth_key_len(const VariantNodeType *node, uint8_t *rec_ptr, uint16_t key_len) {assert(0);}
    static void set_nth_value_len(const VariantNodeType *node, uint8_t *rec_ptr, uint16_t value_len) {assert(0);}
};

/**
 * Internal format of variable node:
 * [var node header][Record][Record].. ...  ... [key][value][key][value]
 *  key and value both can be variying. However for now, we only support variable value. Key is fixed always.
 *  
 */
 
template< typename K, typename V >
class VariableNode : public PhysicalNode<VariableNode,K, V> {
public:
    friend struct VarNodeSpecificImpl<NodeTypeImpl, K, V>;

    VariableNode( bnodeid_t id, bool init,const BtreeConfig &cfg) :
            PhysicalNode<VariableNode, K, V>(id, init) {
        this->set_node_type(NodeTypeImpl);
        if (init) {
            // Tail arena points to the edge of the node as data arena grows backwards. Entire space is now available
            // except for the header itself
            get_var_node_header()->m_init_available_space= cfg.get_node_area_size();
            get_var_node_header()->m_tail_arena_offset = cfg.get_node_area_size();
            get_var_node_header()->m_available_space = get_var_node_header()->m_tail_arena_offset - sizeof(var_node_header);
        }
    }

    VariableNode( bnodeid_t* id, bool init,const BtreeConfig &cfg) :
            PhysicalNode<VariableNode, K, V>(id, init) {
        this->set_node_type(NodeTypeImpl);
        if (init) {
            // Tail arena points to the edge of the node as data arena grows backwards. Entire space is now available
            // except for the header itself
            get_var_node_header()->m_init_available_space= cfg.get_node_area_size();
            get_var_node_header()->m_tail_arena_offset = cfg.get_node_area_size();
            get_var_node_header()->m_available_space = get_var_node_header()->m_tail_arena_offset - sizeof(var_node_header);
        }

    }
    
    /* Insert the key and value in provided index
     * Assumption: Node lock is already taken */
    btree_status_t insert(int ind, const BtreeKey &key, const BtreeValue &val) {
        LOGTRACEMOD(btree_generics, "{}:{}",key.to_string(),val.to_string());
        auto sz = insert(ind, key.get_blob(), val.get_blob());
#ifndef NDEBUG
        validate_sanity();
#endif
        if (sz == 0) {
            return btree_status_t::insert_failed;
        }
        return btree_status_t::success;
    }

#ifndef NDEBUG
    void validate_sanity() {
        int i=0;
        //validate if keys are in ascending orde
        K prevKey;
        while(i<(int)this->get_total_entries()) {
            K key;
            get_nth_key(i,&key,false);
            uint64_t kp = *(uint64_t*)key.get_blob().bytes;
            if(i>0 && prevKey.compare(&key)>0){
                LOGDEBUGMOD(btree_generics, "non sorted entry : {} -> {} ", kp, this->to_string());
                assert(0);
            }
            prevKey = key;
            i++;
        }
        
    }
#endif

    /* Update a value in a given index to the provided value. It will support change in size of the new value.
     * Assumption: Node lock is already taken, size check for the node to support new value is already done */
    void update(int ind, const BtreeValue &val)  {
        // If we are updating the edge value, none of the other logic matter. Just update edge value and move on
        if (ind == (int)this->get_total_entries()) {
            assert(!this->is_leaf());
            this->set_edge_value(val);
            this->inc_gen();
            return;
        }
        
        K key;
        get_nth_key(ind,&key,true);
        update(ind,key,val);
    }

    // TODO - currently we do not support variable size key
    void update(int ind, const BtreeKey &key, const BtreeValue &val)  {
        LOGTRACEMOD(btree_generics, "Update called:{}",this->to_string());
        assert(ind <= (int)this->get_total_entries());

        // If we are updating the edge value, none of the other logic matter. Just update edge value and move on
        if (ind == (int)this->get_total_entries()) {
            assert(!this->is_leaf());
            this->set_edge_value(val);
            this->inc_gen();
            return;
        }

        // Determine if we are doing same size update or smaller size update, in that case, reuse the space.
        uint16_t nth_key_len = get_nth_key_len(ind);
        uint16_t new_obj_size = nth_key_len + val.get_blob_size();
        uint16_t cur_obj_size = get_nth_obj_size(ind);

        if (cur_obj_size >= new_obj_size) {
            uint8_t *val_ptr = (uint8_t *)get_nth_obj(ind) + nth_key_len;
            homeds::blob vblob = val.get_blob();
            //we can avoid memcpy if addresses of val_ptr and vblob.bytes is same. In place update
            if(val_ptr != vblob.bytes) {
                //TODO - we can reclaim space if new obj size is lower than cur obj size
                // Same or smaller size update, just copy the value blob
                LOGTRACEMOD(btree_generics, "Not an in-place update, have to copying data of size {}", vblob.size);
                memcpy(val_ptr, vblob.bytes, vblob.size);
            }else{
                // do nothing
                LOGTRACEMOD(btree_generics, "In place update, not copying data.");
            }
            this->inc_gen();
            return;
        }
        
        remove(ind);
        insert(ind, key, val);
        LOGTRACEMOD(btree_generics, "Size changed for either key or value. Had to delete and insert :{}",this->to_string());
       
    }

    void remove(int ind)  {
        remove(ind,ind);
    }

    //ind_s and ind_e are inclusive
    void remove(int ind_s,int ind_e)  {
        int total_entries = this->get_total_entries();
        assert(total_entries >= ind_s);
        assert(total_entries >=ind_e);
        int recSize = get_record_size();
        int no_of_elem = ind_e-ind_s+1;
        if (ind_e == (int)this->get_total_entries()) {
            assert(!this->is_leaf() && this->has_valid_edge());

            //TODO-we should not use BtreeNodeINfo instead use abstract type
            BtreeNodeInfo last_1_val;

            // Set the last key/value as edge entry and by decrementing entry count automatically removed the last entry.
            get_nth_value(ind_s - 1, &last_1_val, false);
            this->set_edge_value(last_1_val);

            for(int i=ind_s;i<total_entries;i++) {
                get_var_node_header()->m_available_space += get_nth_key_len(i) + get_nth_value_len(i) + recSize;
            }
            this->sub_entries(total_entries-ind_s+1);
        }else {
            //claim available memory
            for(int i=ind_s;i<=ind_e;i++) {
                get_var_node_header()->m_available_space += get_nth_key_len(i) + get_nth_value_len(i) + recSize;
            }
            uint8_t *rec_ptr = get_nth_record_mutable(ind_s);
            memmove(rec_ptr, rec_ptr + recSize*no_of_elem, (this->get_total_entries() - ind_e -1 ) * recSize);

            this->sub_entries(no_of_elem);
        }
        this->inc_gen();
    }

    void get(int ind, BtreeValue *outval, bool copy) const  {
        // Need edge index
        if (ind == (int)this->get_total_entries()) {
            assert(!this->is_leaf());

            assert(this->has_valid_edge());
            this->get_edge_value(outval);
        } else {
            this->get_nth_value(ind, outval, copy);
        }
    }
    
    std::string to_string() const {
        std::stringstream ss;
        ss << "###################" << endl;
        ss << "-------------------------------" << endl;
        ss << "id=" << this->get_node_id().to_string() << " nEntries=" << this->get_total_entries() << " leaf?=" << this->is_leaf();

        if (!this->is_leaf()) {
            bnodeid_t edge_id;
            edge_id = this->get_edge_id();
            ss << " edge_id=" << static_cast<uint64_t>(edge_id.m_id);
        }
        ss << "\n-------------------------------" << endl;
        for (uint32_t i = 0; i < this->get_total_entries(); i++) {
            ss << "Key=";
            K key;
            get_nth_key(i, &key, false);
            ss << key.to_string();

            // TODO: Override the << in ostream for Value
            ss << " Val=";
            if (this->is_leaf()) {
                V val;
                get(i, &val, false);
                ss << val.to_string();
            } else {
                BtreeNodeInfo p;
                get(i, &p, false);
                ss << p;
            }
            ss << "\n";
        }
        return ss.str();
    }

    uint32_t get_available_size(const BtreeConfig &cfg) const  {
        return get_var_node_header_const()->m_available_space;
    }

    bool is_split_needed(const BtreeConfig &cfg, const BtreeKey &key, const BtreeValue &val,
                         int *out_ind_hint, btree_put_type &putType, BtreeUpdateRequest<K,V> *ureq = nullptr) const  {
        uint32_t size_needed=0;
        if(!this->is_leaf()) {// if internal node, size is atmost one additional entry, size of K/V
            size_needed = key.get_blob_size() + val.get_blob_size() + get_record_size();
        } else {
            //leaf node,
            if (ureq) {
                //TODO - determine size needed for non-callback based range updates in future
                assert(ureq->callback() != nullptr);
                /* If there is an overlap then we can add 2 more keys :- one in the front and other in the tail.
                 * Here assumption is that size of a value added is not going to change because of overlaps.
                 */
                size_needed = val.get_blob_size() + (2 * (key.get_blob_size() + get_record_size()));
            } else {
                // NOTE : size_needed is just an guess here. Actual implementation of Mapping key/value can have 
                // specific logic which determines of size changes on insert or update.
                auto result = this->find(key, nullptr, nullptr/*amdesai - Commented - &curval*/);
                if (!result.found)  { // We need to insert, this newly. Find out if we have space for value.
                    size_needed = key.get_blob_size() + val.get_blob_size() + get_record_size();
                } else if (this->is_leaf()) {
                    //for internal nodes, size does not change on updates
                    // Its an update, see how much additioanl space needed
                    V existingVal;
                    get(result.end_of_search_index, &existingVal, false);
                    size_needed =
                        existingVal.estimate_size_after_append(val) - get_nth_value_len(result.end_of_search_index);
                }
            }
        }
        uint32_t alreadyFilledSize = cfg.get_node_area_size() - get_available_size(cfg);
        return alreadyFilledSize + size_needed >= cfg.get_ideal_fill_size();
    }

    uint32_t move_out_to_right_by_entries(const BtreeConfig &cfg, VariableNode* o, uint32_t nentries)  {
        auto &other = static_cast<VariableNode &>(*o);

        auto this_gen = this->get_gen();
        auto other_gen = other.get_gen();

        assert(nentries > 0);
        int start_ind = this->get_total_entries() - 1;
        int end_ind = this->get_total_entries() - nentries - 1;

        auto ind = start_ind;
        while (ind < end_ind) {
            // Get the ith key and value blob and then remove the entry from here and insert to the other node
            homeds::blob kb;
            kb.bytes = (uint8_t *)get_nth_obj(ind);
            kb.size = get_nth_key_len(ind);

            homeds::blob vb;
            vb.bytes = kb.bytes + kb.size;
            vb.size = get_nth_value_len(ind);

            auto sz = other.insert(0, kb, vb);
            if (!sz) {
                break;
            }
            ind--;
        }

        if (!this->is_leaf() && (other.get_total_entries() != 0)) {
            // Incase this node is an edge node, move the stick to the right hand side node
            other.set_edge_id(this->get_edge_id());
            this->invalidate_edge();
        }
        remove(ind+1, start_ind); // Remove all entries in bulk

        // Remove and insert would have set the gen multiple increments, just reset it to increment only by 1
        // TODO: This is bit ugly but needed in-order to avoid repeat the same code again, but see if we can produce
        // interface around it.
        this->set_gen(this_gen + 1);
        other.set_gen(other_gen + 1);

        return (uint32_t)(start_ind - ind);
    }

    uint32_t move_out_to_right_by_size(const BtreeConfig &cfg, VariableNode* o, uint32_t size_to_move)  {
        auto &other = static_cast<VariableNode &>(*o);
        uint32_t moved_size = 0U;
        auto this_gen = this->get_gen();
        auto other_gen = other.get_gen();

        int ind = this->get_total_entries() - 1;
        while (ind > 0) {
            homeds::blob kb;
            kb.bytes = (uint8_t *)get_nth_obj(ind);
            kb.size = get_nth_key_len(ind);

            homeds::blob vb;
            vb.bytes = kb.bytes + kb.size;
            vb.size = get_nth_value_len(ind);

            auto sz = other.insert(0, kb, vb); // Keep on inserting on the first index, thus moving everything to right
            if (!sz) break;
            moved_size += sz;
            ind--;
            if ((kb.size + vb.size + get_record_size()) > size_to_move) {
                // We reached threshold of how much we could move
                break;
            }
            size_to_move -= sz;
        }
        remove(ind+1, this->get_total_entries()-1);

        if (!this->is_leaf() && (other.get_total_entries() != 0)) {
            // Incase this node is an edge node, move the stick to the right hand side node
            other.set_edge_id(this->get_edge_id());
            this->invalidate_edge();
        }

        // Remove and insert would have set the gen multiple increments, just reset it to increment only by 1
        // TODO: This is bit ugly but needed in-order to avoid repeat the same code again, but see if we can produce
        // interface around it.
        this->set_gen(this_gen + 1);
        other.set_gen(other_gen + 1);

        return moved_size;
    }

    uint32_t move_in_from_right_by_entries(const BtreeConfig &cfg, VariableNode* o, uint32_t nentries)  {
        auto &other = static_cast<VariableNode &>(*o);

        auto this_gen = this->get_gen();
        auto other_gen = other.get_gen();
        nentries = std::min(nentries, other.get_total_entries());

        assert(nentries > 0);
        int other_ind = 0;
        while (nentries) {
            // Get the ith key and value blob and then remove the entry from here and insert to the other node
            homeds::blob kb;
            kb.bytes = (uint8_t *)other.get_nth_obj(other_ind);
            kb.size = other.get_nth_key_len(other_ind);

            homeds::blob vb;
            vb.bytes = kb.bytes + kb.size;
            vb.size = other.get_nth_value_len(other_ind);

            auto sz = insert(this->get_total_entries(), kb, vb);
            if (!sz) {
                break;
            }
            nentries--;
            other_ind++;
        }

        other.remove(0, other_ind-1); // Remove all entries in bulk
        assert(other.get_total_entries() == nentries);

        if (!other.is_leaf() && (other.get_total_entries() == 0)) {
            // Incase other node is an edge node and we moved all the data into this node, move over the edge info as well.
            this->set_edge_id(other.get_edge_id());
            other.invalidate_edge();
        }

        // Remove and insert would have set the gen multiple increments, just reset it to increment only by 1
        // TODO: This is bit ugly but needed in-order to avoid repeat the same code again, but see if we can produce
        // interface around it.
        this->set_gen(this_gen + 1);
        other.set_gen(other_gen + 1);

        return (uint32_t)(other_ind);
    }

    uint32_t move_in_from_right_by_size(const BtreeConfig &cfg, VariableNode* o, uint32_t size_to_move)  {
        auto &other = static_cast<VariableNode &>(*o);
        uint32_t moved_size = 0U;
        auto this_gen = this->get_gen();
        auto other_gen = other.get_gen();

        int ind = 0;
        while (ind < (int)this->get_total_entries()) {
            homeds::blob kb;
            kb.bytes = (uint8_t *)other.get_nth_obj(ind);
            kb.size = other.get_nth_key_len(ind);

            homeds::blob vb;
            vb.bytes = kb.bytes + kb.size;
            vb.size = other.get_nth_value_len(ind);

            if ((kb.size + vb.size + other.get_record_size()) > size_to_move) {
                // We reached threshold of how much we could move
                break;
            }
            auto sz = insert(this->get_total_entries(), kb, vb); // Keep on inserting on the last index.
            if (!sz) break;
            moved_size += sz;
            ind++; size_to_move -= sz;
        }
        if (ind) other.remove(0, ind-1);

        if (!other.is_leaf() && (other.get_total_entries() == 0)) {
            // Incase other node is an edge node and we moved all the data into this node, move over the edge info as well.
            this->set_edge_id(other.get_edge_id());
            other.invalidate_edge();
        }

        // Remove and insert would have set the gen multiple increments, just reset it to increment only by 1
        // TODO: This is bit ugly but needed in-order to avoid repeat the same code again, but see if we can produce
        // interface around it.
        this->set_gen(this_gen + 1);
        other.set_gen(other_gen + 1);

        return moved_size;
    }
    
    uint32_t get_nth_obj_size(int ind) const  {
        return get_nth_key_len(ind) + get_nth_value_len(ind);
    }

    void set_nth_key(uint32_t ind, BtreeKey *key){
        assert(ind < this->get_total_entries());
        assert(key->get_blob().size == get_nth_key_len(ind));
        V value;
        uint8_t *obj = (uint8_t *)get_nth_obj(ind);
        memcpy(obj,key->get_blob().bytes,key->get_blob().size);
    }
    
    void get_nth_key(int ind, BtreeKey *outkey, bool copy) const  {
        assert(ind < (int)this->get_total_entries());

        uint8_t *obj = (uint8_t *)get_nth_obj(ind);
        if (copy) {
            outkey->copy_blob({obj, get_nth_key_len(ind)});
        } else {
            outkey->set_blob({obj, get_nth_key_len(ind)});
        }
    }

    void get_nth_value(int ind, BtreeValue *outval, bool copy) const  {
        assert(ind < (int)this->get_total_entries());

        uint8_t *obj = (uint8_t *)get_nth_obj(ind);
        if (copy) {
            outval->copy_blob({obj + get_nth_key_len(ind), get_nth_value_len(ind)});
        } else {
            outval->set_blob({obj + get_nth_key_len(ind), get_nth_value_len(ind)});
        }
    }

    int compare_nth_key(const BtreeKey &cmp_key, int ind) const  {
        K nth_key;
        get_nth_key(ind, &nth_key, false /* copyKey */);
        return nth_key.compare(&cmp_key);
    }

    int compare_nth_key_range(const BtreeSearchRange &range, int ind) const  {
        K nth_key;
        get_nth_key(ind, &nth_key, false /* copyKey */);
        return nth_key.compare_range(range);
    }

private:
    uint32_t insert(int ind, const homeds::blob &key_blob, const homeds::blob &val_blob)  {
        assert(ind <= (int)this->get_total_entries());
        LOGTRACEMOD(btree_generics, "{}:{}:{}:{}",ind ,get_var_node_header()->m_tail_arena_offset,get_arena_free_space() ,get_var_node_header()->m_available_space);
        uint16_t obj_size = key_blob.size + val_blob.size;
        uint16_t to_insert_size = obj_size + get_record_size();
        if (to_insert_size > get_var_node_header()->m_available_space) {
            LOGDEBUG("insert failed insert size {} available size {}", to_insert_size, 
                        get_var_node_header()->m_available_space);
            return 0;
        }

        // If we don't have enough space in the tail arena area, we need to compact and get the space.
        if (to_insert_size > get_arena_free_space()) {
            compact();
            assert(to_insert_size <= get_arena_free_space()); // Expect after compaction to have available space to insert
        }

        // Create a room for a new record
        uint8_t *rec_ptr = (uint8_t *) get_nth_record_mutable(ind);
        memmove((void *)(rec_ptr + get_record_size()), rec_ptr, (this->get_total_entries() - ind) * get_record_size());

        // Move up the tail area
        assert(get_var_node_header()->m_tail_arena_offset > obj_size);
        get_var_node_header()->m_tail_arena_offset -= obj_size;
        get_var_node_header()->m_available_space -= (obj_size+get_record_size());

        // Create a new record
        set_nth_key_len(rec_ptr, key_blob.size);
        set_nth_value_len(rec_ptr, val_blob.size);
        set_record_data_offset(rec_ptr, get_var_node_header()->m_tail_arena_offset);
        
        // Copy the contents of key and value in the offset
        uint8_t *raw_data_ptr = offset_to_ptr_mutable(get_var_node_header()->m_tail_arena_offset);
        memmove(raw_data_ptr, key_blob.bytes, key_blob.size);
        raw_data_ptr += key_blob.size;
        memmove(raw_data_ptr, val_blob.bytes, val_blob.size);
        
        // Increment the entries and generation number
        this->inc_entries();
        this->inc_gen();

#ifndef NDEBUG
        validate_sanity();
#endif
        
#ifdef DEBUG
        //print();
#endif
        return to_insert_size;
    }

    /*
     * This method compacts and provides contiguous tail arena space 
     * so that available space == tail arena space
     * */
    void compact() {
#ifndef NDEBUG
        validate_sanity();
#endif
        // temp ds to sort records in stack space 
        struct Record{
            uint16_t m_obj_offset;
            uint16_t orig_record_index;
        };

        uint32_t no_of_entries = this->get_total_entries();
        if (no_of_entries == 0) {
            // this happens when  there is only entry and in update, we first remove and than insert
            get_var_node_header()->m_tail_arena_offset = get_var_node_header()->m_init_available_space;
            LOGTRACEMOD(btree_generics, "Full available size reclaimed");
            return;
        }
        Record rec[no_of_entries]; 

        uint32_t ind = 0;
        while (ind < no_of_entries) {
            btree_obj_record *rec_ptr = (btree_obj_record*)(get_nth_record_mutable(ind));
            rec[ind].m_obj_offset = rec_ptr->m_obj_offset;
            rec[ind].orig_record_index = ind;
            ind++;
        }

        //use comparator to sort based on m_obj_offset in desc order
        std::sort(rec, rec + no_of_entries,
                  [](Record const & a, Record const & b) -> bool
                  { return b.m_obj_offset < a.m_obj_offset; } );

        uint16_t last_offset= get_var_node_header()->m_init_available_space;

        ind=0;
        uint16_t sparce_space =0;
        //loop records 
        while (ind < no_of_entries) {
            uint16_t total_key_value_len = get_nth_key_len(rec[ind].orig_record_index)
                                           + get_nth_value_len(rec[ind].orig_record_index);
            sparce_space = last_offset- (rec[ind].m_obj_offset+ total_key_value_len);
            if (sparce_space > 0) {
                //do compaction
                uint8_t *old_key_ptr = (uint8_t *)get_nth_obj(rec[ind].orig_record_index);
                uint8_t *raw_data_ptr = old_key_ptr+sparce_space;
                memmove(raw_data_ptr, old_key_ptr, total_key_value_len);

                //update original record
                btree_obj_record *rec_ptr = (btree_obj_record*)(get_nth_record_mutable(rec[ind].orig_record_index));
                rec_ptr->m_obj_offset+=sparce_space;

                last_offset = rec_ptr->m_obj_offset;
               
            } else {
                assert(sparce_space == 0);
                last_offset = rec[ind].m_obj_offset;
            }
            ind++;
        }
        get_var_node_header()->m_tail_arena_offset = last_offset;
#ifndef NDEBUG
        validate_sanity();
#endif
        LOGTRACEMOD(btree_generics, "Sparse space reclaimed:{}",sparce_space);
    }

    // See template specialization below for each nodetype
    uint16_t get_nth_key_len(int ind) const {
        return VarNodeSpecificImpl<NodeTypeImpl, K, V>::get_nth_key_len(this, ind);
    }
    uint16_t get_nth_value_len(int ind) const {
        return VarNodeSpecificImpl<NodeTypeImpl, K, V>::get_nth_value_len(this, ind);
    }
    uint16_t get_record_size() const {
        return VarNodeSpecificImpl< NodeTypeImpl, K, V >::get_record_size(this);
    }

    void set_nth_key_len(uint8_t *rec_ptr, uint16_t key_len) {
        VarNodeSpecificImpl< NodeTypeImpl, K, V >::set_nth_key_len(this, rec_ptr, key_len);
    }
    void set_nth_value_len(uint8_t *rec_ptr, uint16_t value_len) {
        VarNodeSpecificImpl< NodeTypeImpl, K, V >::set_nth_value_len(this, rec_ptr, value_len);
    }

    const uint8_t *get_nth_record(int ind) const {
        return this->get_node_area() + sizeof(var_node_header) + (ind * get_record_size());
    }
    uint8_t *get_nth_record_mutable(int ind) {
        return this->get_node_area_mutable() + sizeof(var_node_header) + (ind * get_record_size());
    }

    const uint8_t *get_nth_obj(int ind) const {
        return offset_to_ptr(((btree_obj_record *) get_nth_record(ind))->m_obj_offset);
    }
    uint8_t *get_nth_obj_mutable(int ind) {
        return offset_to_ptr_mutable(((btree_obj_record *) get_nth_record(ind))->m_obj_offset);
    }

    void set_record_data_offset(uint8_t *rec_ptr, uint16_t offset) {
        auto r = (btree_obj_record *)rec_ptr;
        r->m_obj_offset = offset;
    }

    uint8_t *offset_to_ptr_mutable(uint16_t offset) {
        return this->get_node_area_mutable() + offset;
    }

    const uint8_t *offset_to_ptr(uint16_t offset) const {
        return this->get_node_area() + offset;
    }

    ///////////// Other Private Methods //////////////////
    inline var_node_header *get_var_node_header() {
        return (var_node_header *) (this->get_node_area_mutable());
    }

    inline const var_node_header *get_var_node_header_const() const {
        return (const var_node_header *) (this->get_node_area());
    }

    uint16_t get_arena_free_space() {
        return get_var_node_header()->m_tail_arena_offset - sizeof(var_node_header) -
                (this->get_total_entries() * get_record_size());
    }
};

/***************** Template Specialization for variable key records ******************/
template< typename K, typename V >
struct VarNodeSpecificImpl<btree_node_type::VAR_KEY, K, V > {
    static uint16_t get_nth_key_len(const VariantNode<btree_node_type::VAR_KEY, K, V > *node, int ind) {
        return ((const var_key_record *) node->get_nth_record(ind))->m_key_len;
    }

    static uint16_t get_nth_value_len(const VariantNode< btree_node_type::VAR_KEY, K, V > *node, int ind) {
        return V::get_fixed_size();
    }

    static uint16_t get_record_size(const VariantNode< btree_node_type::VAR_KEY, K, V > *node) {
        return sizeof(var_key_record);
    }

    static void set_nth_key_len(const VariantNode< btree_node_type::VAR_KEY, K, V > *node, uint8_t *rec_ptr, uint16_t key_len) {
        ((var_key_record *)rec_ptr)->m_key_len = key_len;
    }

    static void set_nth_value_len(const VariantNode< btree_node_type::VAR_KEY, K, V > *node, uint8_t *rec_ptr,
                                  uint16_t value_len) {
        assert(value_len == V::get_fixed_size());
    }
};

/***************** Template Specialization for variable value records ******************/
template< typename K, typename V >
struct VarNodeSpecificImpl<btree_node_type::VAR_VALUE , K, V > {
    static uint16_t get_nth_key_len(const VariantNode<btree_node_type::VAR_VALUE, K, V > *node, int ind) {
        return K::get_fixed_size();
    }

    static uint16_t get_nth_value_len(const VariantNode< btree_node_type::VAR_VALUE, K, V > *node, int ind) {
        return ((const var_value_record *)node->get_nth_record(ind))->m_value_len;
    }

    static uint16_t get_record_size(const VariantNode< btree_node_type::VAR_VALUE, K, V > *node) {
        return sizeof(var_value_record);
    }

    static void set_nth_key_len(const VariantNode< btree_node_type::VAR_VALUE, K, V > *node, uint8_t *rec_ptr,
                                uint16_t key_len) {
        assert(key_len == K::get_fixed_size());
    }

    static void set_nth_value_len(const VariantNode< btree_node_type::VAR_VALUE, K, V > *node, uint8_t *rec_ptr,
                                  uint16_t value_len) {
        ((var_value_record *)rec_ptr)->m_value_len = value_len;
    }
};

/***************** Template Specialization for variable object records ******************/
template< typename K, typename V >
struct VarNodeSpecificImpl<btree_node_type::VAR_OBJECT, K, V> {
    static uint16_t get_nth_key_len(const VariantNode<btree_node_type::VAR_OBJECT, K, V> *node, int ind) {
        return ((const var_obj_record *)node->get_nth_record(ind))->m_key_len;
    }

    static uint16_t get_nth_value_len(const VariantNode< btree_node_type::VAR_OBJECT, K, V > *node, int ind) {
        return ((const var_value_record *)node->get_nth_record(ind))->m_value_len;
    }

    static uint16_t get_record_size(const VariantNode< btree_node_type::VAR_OBJECT, K, V > *node) {
        return sizeof(var_value_record);
    }

    static void set_nth_key_len(const VariantNode< btree_node_type::VAR_OBJECT, K, V > *node, uint8_t *rec_ptr,
                                uint16_t key_len) {
        ((var_obj_record *)rec_ptr)->m_key_len = key_len;
    }

    static void set_nth_value_len(const VariantNode< btree_node_type::VAR_OBJECT, K, V > *node, uint8_t *rec_ptr,
                                  uint16_t value_len) {
        ((var_obj_record *)rec_ptr)->m_value_len = value_len;
    }
};

#if 0
template< typename K, typename V, btree_node_type NodeType >
uint16_t VarObjectNode< K, V, btree_node_type::VAR_KEY >::get_nth_value_len(int ind) const {
    return V::get_blob_size();
}

template< typename K, typename V, btree_node_type NodeType >
uint16_t VarObjectNode< K, V, btree_node_type::VAR_KEY >::get_record_size() const {
    return sizeof(var_key_record);
}

template< typename K, typename V, btree_node_type NodeType >
void VarObjectNode< K, V, btree_node_type::VAR_KEY >::set_nth_key_len(uint8_t *rec_ptr, uint16_t key_len) {
    ((var_key_record *)rec_ptr)->m_key_len = key_len;
}

template< typename K, typename V, btree_node_type NodeType >
void VarObjectNode< K, V, btree_node_type::VAR_KEY >::set_nth_value_len(uint8_t *rec_ptr, uint16_t value_len) {
    assert(value_len == V::get_blob_size());
}

/***************** Template Specialization for variable value records ******************/
template< typename K, typename V, btree_node_type NodeType >
uint16_t VarObjectNode< K, V, btree_node_type::VAR_VALUE >::get_nth_key_len(int ind) const {
    return K::get_blob_size();
}

template< typename K, typename V, btree_node_type NodeType >
uint16_t VarObjectNode< K, V, btree_node_type::VAR_VALUE >::get_nth_value_len(int ind) const {
    return ((const var_value_record *)get_nth_record_const(ind))->m_value_len;
}

template< typename K, typename V, btree_node_type NodeType >
uint16_t VarObjectNode< K, V, btree_node_type::VAR_VALUE >::get_record_size() const {
    return sizeof(var_value_record);
}

template< typename K, typename V, btree_node_type NodeType >
void VarObjectNode< K, V, btree_node_type::VAR_VALUE >::set_nth_key_len(uint8_t *rec_ptr, uint16_t key_len) {
    assert(key_len == K::get_blob_size());
}

template< typename K, typename V, btree_node_type NodeType >
void VarObjectNode< K, V, btree_node_type::VAR_VALUE >::set_nth_value_len(uint8_t *rec_ptr, uint16_t value_len) {
    ((var_value_record *)rec_ptr)->m_value_len = value_len;
}

/***************** Template Specialization for variable object records ******************/
template< typename K, typename V, btree_node_type NodeType >
uint16_t VarObjectNode< K, V, btree_node_type::VAR_VALUE >::get_nth_key_len(int ind) const {
    return ((const var_obj_record *)get_nth_record_const(ind))->m_key_len;
}

template< typename K, typename V, btree_node_type NodeType >
uint16_t VarObjectNode< K, V, btree_node_type::VAR_VALUE >::get_nth_value_len(int ind) const {
    return ((const var_obj_record *)get_nth_record_const(ind))->m_value_len;
}

template< typename K, typename V, btree_node_type NodeType >
uint16_t VarObjectNode< K, V, btree_node_type::VAR_VALUE >::get_record_size() const {
    return sizeof(var_obj_record);
}

template< typename K, typename V, btree_node_type NodeType >
void VarObjectNode< K, V, btree_node_type::VAR_VALUE >::set_nth_key_len(uint8_t *rec_ptr, uint16_t key_len) {
    ((var_obj_record *)rec_ptr)->m_key_len = key_len;
}

template< typename K, typename V, btree_node_type NodeType >
void VarObjectNode< K, V, btree_node_type::VAR_VALUE >::set_nth_value_len(uint8_t *rec_ptr, uint16_t value_len) {
    ((var_obj_record *)rec_ptr)->m_value_len = value_len;
}
#endif

} }

#endif /* BTREE_VARLEN_NODE_HPP_ */
