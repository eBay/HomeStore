#pragma once

#include "engine/homeds/btree/ssd_btree.hpp"
#include "engine/homeds/btree/btree.hpp"
#include "engine/blkalloc/blk.h"
#include <csignal>
#include "engine/common/error.h"
#include "engine/homeds/array/blob_array.h"
#include <math.h>
#include <sds_logging/logging.h>
#include <utility/obj_life_counter.hpp>
#include "homeblks/home_blks.hpp"
#include "engine/index/indx_mgr_api.hpp"
#include <cstring>

SDS_LOGGING_DECL(volume)

using namespace homeds;
using namespace homeds::btree;
#define MAX_NUM_LBA ((1 << NBLKS_BITS) - 1)

#define LBA_MASK 0xFFFFFFFFFFFF
#define CS_ARRAY_STACK_SIZE 256 // equals 2^N_LBA_BITS //TODO - put static assert
namespace homestore {
struct volume_req;

enum op_type {
    UPDATE_VAL_ONLY = 0,      // it only update the value
    UPDATE_VAL_AND_FREE_BLKS, // it update the value and also update the free blks
    READ_VAL_WITH_seqid,
    FREE_ALL_USER_BLKID,
    READ_VAL
};

// std::variant
struct mapping_op_cntx {
    op_type op = UPDATE_VAL_ONLY;
    union {
        struct volume_req* vreq;
        sisl::ThreadVector< BlkId >* free_list;
    } u;
    int64_t seqid = INVALID_SEQ_ID;
    uint64_t free_blk_size = 0;
};

struct LbaId {
    // size of lba start and num of lba can be reduced for future use
    uint64_t m_lba_start : LBA_BITS; // start of lba range
    uint64_t m_n_lba : NBLKS_BITS;   // number of lba's from start(inclusive)

    LbaId() : m_lba_start(0), m_n_lba(0) {}

    LbaId(const LbaId& other) : m_lba_start(other.m_lba_start), m_n_lba(other.m_n_lba) {}

    LbaId(uint64_t lbaId) { LbaId(lbaId & LBA_MASK, lbaId >> LBA_BITS); }

    LbaId(uint64_t lba_start, uint64_t n_lba) : m_lba_start(lba_start), m_n_lba(n_lba) { assert(n_lba < MAX_NUM_LBA); }

    uint64_t end() { return m_lba_start + m_n_lba - 1; }

    bool is_invalid() { return m_lba_start == 0 && m_n_lba == 0; }

} __attribute__((__packed__));

// MappingKey is fixed size
class MappingKey : public homeds::btree::ExtentBtreeKey, public sisl::ObjLifeCounter< MappingKey > {
    LbaId m_lbaId;
    LbaId* m_lbaId_ptr;

public:
    MappingKey() : ObjLifeCounter(), m_lbaId_ptr(&m_lbaId) {}

    MappingKey(const MappingKey& other) :
            ExtentBtreeKey(),
            ObjLifeCounter(),
            m_lbaId(other.get_lbaId()),
            m_lbaId_ptr(&m_lbaId) {}

    MappingKey(uint64_t lba_start, uint64_t n_lba) :
            ObjLifeCounter(),
            m_lbaId(lba_start, n_lba),
            m_lbaId_ptr(&m_lbaId) {}

    LbaId get_lbaId() const { return *m_lbaId_ptr; }

    uint64_t start() const { return m_lbaId_ptr->m_lba_start; }

    uint64_t end() const { return start() + get_n_lba() - 1; }

    uint16_t get_n_lba() const { return m_lbaId_ptr->m_n_lba; }

    /* used by btree to compare the end key of input with end key
     * It return the result of
     *                 *(this) - *(input)
     */
    virtual int compare_end(const BtreeKey* input) const override {
        MappingKey* o = (MappingKey*)input;
        if (end() > o->end())
            return 1; // go left
        else if (end() < o->end())
            return -1; // go right
        else
            return 0; // overlap
    }

    /* used by btree to compare the start key of input with the end key
     * It return the result of
     *                 *(this) - *(input)
     */
    virtual int compare_start(const BtreeKey* input) const override {
        MappingKey* o = (MappingKey*)input;
        if (end() > o->start())
            return 1; // go left
        else if (end() < o->start())
            return -1; // go right
        else
            return 0; // overlap
    }

    virtual bool preceeds(const BtreeKey* k) const override {
        MappingKey* o = (MappingKey*)k;
        if (end() < o->start()) { return true; }

        return false;
    }

    virtual bool succeeds(const BtreeKey* k) const override {
        MappingKey* o = (MappingKey*)k;
        if (o->end() < start()) { return true; }

        return false;
    }

    virtual sisl::blob get_blob() const override { return {(uint8_t*)m_lbaId_ptr, get_fixed_size()}; }

    virtual void set_blob(const sisl::blob& b) override {
        assert(b.size == get_fixed_size());
        m_lbaId_ptr = (LbaId*)b.bytes;
    }

    virtual void copy_blob(const sisl::blob& b) override {
        assert(b.size == get_fixed_size());
        LbaId* other = (LbaId*)b.bytes;
        set(other->m_lba_start, other->m_n_lba);
    }

    virtual void copy_end_key_blob(const sisl::blob& b) override {
        assert(b.size == get_fixed_size());
        LbaId* other = (LbaId*)b.bytes;
        set(other->end(), 1);
    }

    void set(uint64_t lba_start, uint8_t n_lba) {
        m_lbaId.m_lba_start = lba_start;
        m_lbaId.m_n_lba = n_lba;
        m_lbaId_ptr = &m_lbaId;
    }

    virtual uint32_t get_blob_size() const override { return get_fixed_size(); }

    virtual void set_blob_size(uint32_t size) override { assert(0); }

    virtual string to_string() const override {
        stringstream ss;
        ss << "[" << start() << " - " << end() << "]";
        return ss.str();
    }

    uint64_t get_nlbas(uint64_t end_lba, uint64_t start_lba) { return (end_lba - start_lba + 1); }
    void get_overlap(uint64_t lba_start, uint64_t lba_end, MappingKey& overlap) {
        auto start_lba = std::max(start(), lba_start);
        auto end_lba = std::min(end(), lba_end);
        overlap.set(start_lba, get_nlbas(end_lba, start_lba));
    }

    // returns difference in start lba
    uint64_t get_start_offset(MappingKey& other) { return start() - other.start(); }

    static uint32_t get_fixed_size() { return sizeof(LbaId); }

    friend ostream& operator<<(ostream& os, const MappingKey& k) {
        os << k.to_string();
        return os;
    }

} __attribute__((__packed__));

#define VALUE_ENTRY_VERSION 0x1
struct ValueEntryMeta {
    uint8_t magic = VALUE_ENTRY_VERSION;
    int64_t seqid;
    BlkId blkId;
    uint64_t nlba : NBLKS_BITS;
    uint64_t blk_offset : NBLKS_BITS; // offset based on blk store not based on vol page size
    ValueEntryMeta(uint64_t seqid, const BlkId& blkId, uint8_t blk_offset, uint8_t nlba) :
            seqid(seqid), blkId(blkId), nlba(nlba), blk_offset(blk_offset){};
    ValueEntryMeta() : seqid(0), blkId(0), nlba(0), blk_offset(0){};
} __attribute__((__packed__));

struct ValueEntry {
private:
    ValueEntryMeta m_meta;
    // this allocates 2^NBLKS_BITS size array for checksum on stack, however actual memory used is less on bnode
    // as we call get_blob_size which takes into account actual nlbas to determine exact size of checksum array
    // TODO - can be replaced by thread local buffer in future
    std::array< uint16_t, CS_ARRAY_STACK_SIZE > m_carr;
    ValueEntry* m_ptr;

public:
    ValueEntry() : m_meta(), m_carr() { m_ptr = (ValueEntry*)this; }

    // deep copy
    ValueEntry(int64_t seqid, const BlkId& blkId, uint8_t blk_offset, uint8_t nlba, uint16_t* carr,
               uint64_t vol_page_size) :
            m_meta(seqid, blkId, blk_offset, nlba) {
        for (int i = 0; i < nlba; ++i) {
            m_carr[i] = carr[i];
        }
        m_ptr = (ValueEntry*)this;
#ifndef NDEBUG
        auto actual_nblks = (vol_page_size / HomeBlks::instance()->get_data_pagesz()) * nlba;
        assert(blk_offset + actual_nblks <= get_blkId().get_nblks());
#endif
    }

    ValueEntry(const ValueEntry& ve) { copy_from(ve); }

    ValueEntry(uint8_t* ptr) : m_ptr((ValueEntry*)ptr) {}

    uint32_t get_blob_size() { return sizeof(m_meta) + sizeof(uint16_t) * get_nlba(); }

    sisl::blob get_blob() { return {(uint8_t*)m_ptr, get_blob_size()}; }

    void set_blob(sisl::blob b) { m_ptr = (ValueEntry*)b.bytes; }

    void copy_blob(sisl::blob b) {
        ValueEntry ve(b.bytes);
        copy_from(ve);
    }

    void copy_from(const ValueEntry& ve) {
        m_meta.seqid = ve.get_seqid();
        m_meta.blkId = ve.get_blkId();
        m_meta.blk_offset = ve.get_blk_offset();
        m_meta.nlba = ve.get_nlba();
        for (auto i = 0; i < ve.get_nlba(); i++)
            m_carr[i] = ve.get_checksum_at(i);
        m_ptr = (ValueEntry*)this;
    }

    uint64_t get_blkid_offset(uint64_t lba_offset, uint64_t vol_page_size) {
        return ((vol_page_size / HomeBlks::instance()->get_data_pagesz()) * lba_offset);
    }

    void add_offset(uint8_t lba_offset, uint8_t nlba, uint32_t vol_page_size) {
        // move checksum array elements to start from offset position
        assert(lba_offset < get_nlba());
        memmove((void*)&(m_ptr->m_carr[0]), (void*)(&(m_ptr->m_carr[lba_offset])), sizeof(uint16_t) * nlba);
        m_ptr->m_meta.nlba = nlba;
        uint8_t blk_offset = get_blkid_offset(lba_offset, vol_page_size);
        m_ptr->m_meta.blk_offset += blk_offset;
#ifndef NDEBUG
        auto actual_nblks = (vol_page_size / HomeBlks::instance()->get_data_pagesz()) * nlba;
        assert(blk_offset + actual_nblks <= get_blkId().get_nblks());
#endif
    }

    int64_t get_seqid() const { return m_ptr->m_meta.seqid; }

    BlkId& get_blkId() const { return m_ptr->m_meta.blkId; }

    uint8_t get_blk_offset() const { return (uint8_t)m_ptr->m_meta.blk_offset; }

    uint8_t get_nlba() const { return (uint8_t)m_ptr->m_meta.nlba; }

    uint16_t& get_checksum_at(uint8_t index) const {
        assert(index < get_nlba());
        return m_ptr->m_carr[index];
    }

    int compare(const ValueEntry* other) const {
        if (get_seqid() == other->get_seqid())
            return 0;
        else if (get_seqid() < other->get_seqid())
            return 1; // other is higher
        else
            return -1; // other is lower
    }

    const std::string get_checksums_string() const {
        std::stringstream ss;
        for (auto i = 0u; i < get_nlba(); i++)
            ss << get_checksum_at(i) << ",";
        return ss.str();
    }

    string to_string() const {
        stringstream ss;
        ss << "Seq: " << get_seqid() << ", " << get_blkId() << ", Boff: " << unsigned(get_blk_offset());
        ss << ", v_nlba: " << unsigned(get_nlba());

        if (HomeBlks::instance()->print_checksum()) { ss << ", cs: " << get_checksums_string(); }
        return ss.str();
    }

    friend ostream& operator<<(ostream& os, const ValueEntry& ve) {
        os << ve.to_string();
        return os;
    }
} __attribute__((__packed__));

class MappingValue : public homeds::btree::BtreeValue, public sisl::ObjLifeCounter< MappingValue > {
    Blob_Array< ValueEntry > m_earr;

public:
    // creates empty array
    MappingValue() : ObjLifeCounter(){};

    // creates array with one value entry - on heap - bcopy
    MappingValue(ValueEntry& ve) : ObjLifeCounter() { m_earr.set_element(ve); }

    // performs deep copy from other - on heap
    MappingValue(const MappingValue& other) : ObjLifeCounter() { m_earr.set_elements(other.m_earr); }

    // creates array with  value entrys - on heap -bcopy
    MappingValue(vector< ValueEntry >& elements) : ObjLifeCounter() { m_earr.set_elements(elements); }

    MappingValue(const MappingValue& other, uint16_t offset, uint32_t nlbas, uint32_t page_size) {
        const Blob_Array< ValueEntry >& arr = other.get_array_const();
        assert(arr.get_total_elements() == 1);
        ValueEntry ve;
        arr.get(0, ve, true);
        ve.add_offset(offset, nlbas, page_size);
        m_earr.set_element(ve);
    }

    MappingValue(volume_req* req, const MappingValue& one, uint32_t one_offset, const MappingValue& second,
                 uint32_t second_offset, uint32_t page_size) {
        assert(0);
    }

    virtual sisl::blob get_blob() const override {
        sisl::blob b;
        b.bytes = (uint8_t*)m_earr.get_mem();
        b.size = m_earr.get_size();
        return b;
    }

    uint64_t get_nlbas(uint64_t end_lba, uint64_t start_lba) { return (end_lba - start_lba + 1); }
    void get_overlap_diff_kvs(MappingKey* k1, MappingValue* v1, MappingKey* k2, MappingValue* v2,
                              uint32_t vol_page_size, diff_read_next_t& to_read,
                              std::vector< std::pair< MappingKey, MappingValue > >& overlap_kvs) {
        static MappingKey k;
        static MappingValue v;

        uint64_t start, k1_offset = 0, k2_offset = 0;
        uint64_t nlba = 0, ovr_nlba = 0;

        /* Non-overlapping beginning part */
        if (k1->start() < k2->start()) {
            nlba = k2->start() - k1->start();
            k.set(k1->start(), nlba);
            v = *v1;
            v.add_offset(0, nlba, vol_page_size);
            overlap_kvs.emplace_back(make_pair(k, v));
            k1_offset += nlba;
            start = k1->start() + nlba;
        } else if (k2->start() < k1->start()) {
            nlba = k1->start() - k2->start();
            k.set(k2->start(), nlba);
            v = *v2;
            v.add_offset(0, nlba, vol_page_size);
            overlap_kvs.emplace_back(make_pair(k, v));
            k2_offset += nlba;
            start = k2->start() + nlba;
        } else {
            start = k1->start(); // Same Start - no overlapping part.
        }

        /* Overlapping part */
        if (k1->end() < k2->end()) {
            ovr_nlba = k1->get_n_lba() - k1_offset;
        } else {
            ovr_nlba = k2->get_n_lba() - k2_offset;
        }

        k.set(start, ovr_nlba);

        if (v1->is_new(*v2)) {
            v = *v1;
            v.add_offset(k1_offset, ovr_nlba, vol_page_size);
            k1_offset += ovr_nlba;
        } else {
            v = *v2;
            v.add_offset(k2_offset, ovr_nlba, vol_page_size);
            k2_offset += ovr_nlba;
        }

        overlap_kvs.emplace_back(make_pair(k, v));
        /* Non-overlapping tail part */
        start = start + ovr_nlba;
        if (k1->end() == k2->end()) {
            to_read = READ_BOTH; // Read both
        } else if (k1->end() < start) {
            /* k2 has tail part */
            nlba = get_nlbas(k2->end(), start);
            k2->set(start, nlba);
            v2->add_offset(k2_offset, nlba, vol_page_size);
            to_read = READ_FIRST;
        } else {
            /* k1 has tail part */
            nlba = get_nlbas(k1->end(), start);
            k1->set(start, nlba);
            v1->add_offset(k1_offset, nlba, vol_page_size);
            to_read = READ_SECOND;
        }
    }

    virtual void set_blob(const sisl::blob& b) override { m_earr.set_mem((void*)(b.bytes), b.size); }

    virtual void copy_blob(const sisl::blob& b) override {
        Blob_Array< ValueEntry > other;
        other.set_mem((void*)b.bytes, b.size);
        m_earr.set_elements(other); // deep copy
    }

    virtual uint32_t get_blob_size() const override { return m_earr.get_size(); }

    virtual void set_blob_size(uint32_t size) override { assert(0); }

    virtual uint32_t estimate_size_after_append(const BtreeValue& new_val) override {
        assert(0);
        return 0;
    }

    virtual void append_blob(const BtreeValue& new_val, BtreeValue& existing_val) override { assert(0); }

    virtual string to_string() const override { return m_earr.to_string(); }

    const Blob_Array< ValueEntry >& get_array_const() const { return m_earr; }
    Blob_Array< ValueEntry >& get_array() { return m_earr; }

    uint32_t meta_size() const {
        uint32_t size = 0;
        size = sizeof(ValueEntryMeta) + m_earr.get_meta_size();
        return size;
    }

    bool is_valid() {
        if (m_earr.get_total_elements() == 0) return false;
        return true;
    }

    // add offset to all entries - no copy , in place
    void add_offset(uint8_t lba_offset, uint8_t nlba, uint32_t vol_page_size) {
        auto j = 0u;
        while (j < get_array().get_total_elements()) {
            ValueEntry ve;
            get_array().get(j, ve, false);
            ve.add_offset(lba_offset, nlba, vol_page_size);
            j++;
        }
    }

    /* true if my value is newer than other */
    bool is_new(MappingValue other) {
        /* all mapping value entries have same seqid */
        vector< ValueEntry > my_v_array, other_v_array;

        get_array().get_all(my_v_array, true);
        other.get_array().get_all(other_v_array, true);

        /* If other size is 0, my value is always new */
        if (other_v_array.size() <= 0) { return true; }

        /* If other size is not 0 and my value is 0, my value is old */
        if (my_v_array.size() <= 0) { return false; }

        /* If other seqid is invalid, my value is new */
        if (other_v_array[0].get_seqid() == INVALID_SEQ_ID) { return true; }

        /* If my seqid is invalid and other is not, my value is old */
        if (my_v_array[0].get_seqid() == INVALID_SEQ_ID) { return false; }

        /* If my value is greater than other, my value is new */
        if (my_v_array[0].compare(&other_v_array[0]) > 0) { return true; }

        return false;
    }

    // insert entry to this mapping value, maintaing it sorted by seqid - deep copy
    void add_copy(ValueEntry& ve, MappingValue& out) {
        vector< ValueEntry > v_array;
        get_array().get_all(v_array, true);
        auto i = 0u;
        if (v_array.size() > 0) {
            while (i < v_array.size() && v_array[i].compare(&ve) > 0)
                ++i;
            if (i < v_array.size() && v_array[i].compare(&ve) == 0) {
                /* every sequence ID is invalid until jorunaling comes */
                assert(ve.get_seqid() == INVALID_SEQ_ID);
                ++i;
            }
        }
        v_array.insert(v_array.begin() + i, ve);
        out.get_array().set_elements(v_array);
    }

#if 0    
    void truncate(volume_req* req) {    
        Blob_Array< ValueEntry >& e_varray = get_array();    

        // iterate and remove all entries except latest one    
        for (int i = e_varray.get_total_elements() - 1; i >= 0; i--) {    
            ValueEntry ve;    
            e_varray.get(i, ve, false);    
            uint32_t total = e_varray.get_total_elements();    
            if (req->lastCommited_seqid == INVALID_SEQ_ID ||    
                    ve.get_seqid() < req->lastCommited_seqid) { // eligible for removal    

                LOGTRACE("Free entry:{} nlbas {}", ve.to_string(),    
                        (m_vol_page_size / HomeBlks::instance()->get_data_pagesz()) * e_key->get_n_lba());    
                Free_Blk_Entry fbe(ve.get_blkId(), ve.get_blk_offset(),    
                        (m_vol_page_size / HomeBlks::instance()->get_data_pagesz()) *    
                        e_key->get_n_lba());    
                param->m_req->blkIds_to_free.emplace_back(fbe);    
                e_varray.remove(i);    
            }    
        }    
    }
#endif

    friend ostream& operator<<(ostream& os, const MappingValue& ve) {
        os << ve.to_string();
        return os;
    }
};

typedef std::function< void(Free_Blk_Entry& fbe) > pending_read_blk_cb;
class mapping : public indx_tbl {
    using alloc_blk_callback = std::function< void(struct BlkId blkid, size_t offset_size, size_t size) >;
    using comp_callback = std::function< void(const btree_cp_ptr& bcp) >;
    constexpr static uint64_t lba_query_cnt = 1024ull;

private:
    HomeBlksSafePtr m_hb;
    MappingBtreeDeclType* m_bt;
    alloc_blk_callback m_alloc_blk_cb;
    pending_read_blk_cb m_pending_read_blk_cb;
    uint32_t m_vol_page_size;
    const MappingValue EMPTY_MAPPING_VALUE;
    std::string m_unique_name;
    bool m_fix_state = false;
    uint64_t m_outstanding_io = 0;
    uint64_t m_vol_size = 0;
    match_item_cb_t< MappingKey, MappingValue > m_match_item_cb_get;
    match_item_cb_t< MappingKey, MappingValue > m_match_item_cb_put;
    get_size_needed_cb_t< MappingKey, MappingValue > m_get_size_needed;

    class GetCBParam : public BRangeCBParam {
    public:
        mapping_op_cntx* m_ctx;

        GetCBParam(mapping_op_cntx& cntx) : m_ctx(&cntx) {}
    };

    class UpdateCBParam : public BRangeCBParam {
    public:
        mapping_op_cntx* m_cntx;
        uint64_t m_start_lba;
        MappingValue* m_value;

        UpdateCBParam(mapping_op_cntx& cntx, MappingKey& new_key, MappingValue& new_value) :
                BRangeCBParam(), m_cntx(&cntx), m_start_lba(new_key.start()), m_value(&new_value){};
        MappingValue& get_new_value() { return *m_value; }
    };

public:
    mapping(uint64_t volsize, uint32_t page_size, const std::string& unique_name, trigger_cp_callback trigger_cp_cb,
            pending_read_blk_cb pending_read_cb = nullptr);
    mapping(uint64_t volsize, uint32_t page_size, const std::string& unique_name, btree_super_block btree_sb,
            trigger_cp_callback trigger_cp_cb, pending_read_blk_cb pending_read_cb = nullptr,
            btree_cp_sb* btree_cp_sb = nullptr);
    virtual ~mapping();
    int sweep_alloc_blks(uint64_t start_lba, uint64_t end_lba);
    btree_status_t get(volume_req* req, std::vector< std::pair< MappingKey, MappingValue > >& values);
    btree_status_t get(mapping_op_cntx& cntx, MappingKey& key, BtreeQueryCursor& cur,
                       std::vector< std::pair< MappingKey, MappingValue > >& values);
    /* Note :- we should not write same IO in btree multiple times. When a key is updated , it update the free blk
     * entries in request to its last value. If we write same io multiple times then it could end up freeing the wrong
     * blocks.
     * @cur :- if multiple calls made for the same key then it points to first lba which is not written.
     */
    btree_status_t put(mapping_op_cntx& cntx, MappingKey& key, MappingValue& value, const btree_cp_ptr& cp_id,
                       BtreeQueryCursor& cur);

    void print_tree();
    bool verify_tree();
    /**
     * @brief : Fix a btree by :
     *      1. Create a new btree,
     *      2. Iterating it's leaf node chain,
     *      3. Add every K, V in leaf node into the new btree;
     *      4. Delete in-memory copy of the old btree;
     *
     * @param start_lba : start lba of to recover the btree;
     * @param end_lba   : end lba of to recover the btree
     * @param verify    : if true, verify the new btree after recover by comparing the leaf
     *                    node KVs between the old and new btrees;
     *                    if false, skip verification of the newly created btree;
     *
     * @return : true if btree is succesfully recovered;
     *           false if failed to recover;
     * Note:
     * No need to call old btree destroy() as blocks will be freed automatically;
     */
    bool fix(const btree_cp_ptr& bcp, uint64_t start_lba, uint64_t end_lba, bool verify = false);

    /**
     * @brief : verify that the all the KVs in range [start_lba, end_lba] are the same between old_bt and new_bt
     *
     * @param start_lba : start lba
     * @param end_lba : end lba
     * @param old_bt : the old btree to be compared
     * @param new_bt : the new btree to be compared
     *
     * @return : true if all the KVs are the same between the two btrees;
     *           false if not;
     */
    bool verify_fixed_bt(uint64_t start_lba, uint64_t end_lba, MappingBtreeDeclType* old_bt,
                         MappingBtreeDeclType* new_bt);
    void print_kv(std::vector< std::pair< MappingKey, MappingValue > >& kvs);

    void print_node(uint64_t blkid);

public:
    /* virtual functions required by indx tbl */

    virtual void create_done() override;
    virtual uint64_t get_used_size() override;
    virtual btree_super_block get_btree_sb() override;

    /* It attaches the new CP and prepare for cur cp flush */
    virtual btree_cp_ptr attach_prepare_cp(const btree_cp_ptr& cur_bcp, bool is_last_cp,
                                           bool blkalloc_checkpoint) override;

    virtual void cp_start(const btree_cp_ptr& bcp, cp_comp_callback cb) override;

    virtual void truncate(const btree_cp_ptr& bcp) override;
    virtual void destroy_done() override;
    virtual void update_btree_cp_sb(const btree_cp_ptr& bcp, btree_cp_sb& btree_sb, bool is_blkalloc_cp) override;
    virtual void flush_free_blks(const btree_cp_ptr& bcp, std::shared_ptr< homestore::blkalloc_cp >& ba_cp) override;
    /* it populats the allocated blkids in index req. It might not be the same as in volume req if entry is partially
     * written.
     */
    virtual void update_indx_alloc_blkids(indx_req* ireq) override;
    virtual btree_status_t update_diff_indx_tbl(indx_req* ireq, const btree_cp_ptr& bcp) override;

    virtual btree_status_t update_active_indx_tbl(indx_req* ireq, const btree_cp_ptr& bcp) override;
    virtual btree_status_t recovery_update(logstore_seq_num_t seqnum, journal_hdr* hdr,
                                           const btree_cp_ptr& bcp) override;
    virtual btree_status_t free_user_blkids(blkid_list_ptr free_list, BtreeQueryCursor& cur, int64_t& size) override;
    virtual btree_status_t unmap(blkid_list_ptr free_list, BtreeQueryCursor& cur) override;
    virtual void get_btreequery_cur(const sisl::blob& b, BtreeQueryCursor& cur) override;
    virtual btree_status_t destroy(blkid_list_ptr& free_blkid_list, uint64_t& free_node_cnt) override;
    virtual btree_status_t read_indx(indx_req* req, const read_indx_comp_cb_t& read_cb) override;

public:
    /* static functions */
    static void cp_done(trigger_cp_callback cb);
    static uint64_t get_end_lba(uint64_t start_lba, uint64_t nlba);
    static uint64_t get_nlbas(uint64_t end_lba, uint64_t start_lba);
    static uint64_t get_blkid_offset(uint64_t lba_offset, uint64_t vol_page_size);
    static uint64_t get_next_start_lba(uint64_t start_lba, uint64_t nlba);
    static uint64_t get_nlbas_from_cursor(uint64_t start_lba, BtreeQueryCursor& cur);
    static uint64_t get_next_start_key_from_cursor(BtreeQueryCursor& cur);
    static uint64_t get_end_key_from_cursor(BtreeQueryCursor& cur);

private:
    btree_status_t update_indx_tbl(indx_req* ireq, const btree_cp_ptr& bcp, bool active_btree_update = true);
    btree_status_t get_alloc_blks_cb(std::vector< std::pair< MappingKey, MappingValue > >& match_kv,
                                     std::vector< std::pair< MappingKey, MappingValue > >& result_kv,
                                     BRangeCBParam* cb_param);
    void process_free_blk_callback(free_blk_callback free_cb, MappingValue& mv);
    void mapping_merge_cb(std::vector< std::pair< MappingKey, MappingValue > >& match_kv,
                          std::vector< std::pair< MappingKey, MappingValue > >& replace_kv, BRangeCBParam* cb_param);

    /**
     * Callback called once for each bnode
     * @param match_kv  - list of all match K/V for bnode (based on key.compare/compare_range)
     * @param result_kv - All KV which are passed backed to mapping.get by btree. Btree dosent use this.
     * @param cb_param -  All parameteres provided by mapping.get can be accessed from this
     */
    btree_status_t match_item_cb_get(std::vector< std::pair< MappingKey, MappingValue > >& match_kv,
                                     std::vector< std::pair< MappingKey, MappingValue > >& result_kv,
                                     BRangeCBParam* cb_param, BtreeSearchRange& subrange);
    /* It calculate the offset in a value by looking at start lba */
    uint32_t compute_val_offset(BRangeCBParam* cb_param, uint64_t start_lba);

    uint32_t get_size_needed(std::vector< std::pair< MappingKey, MappingValue > >& match_kv, BRangeCBParam* cb_param);

    /* Callback called onces for each eligible bnode
     * @param match_kv - list of all match K/V for bnode (based on key.compare/compare_range)
     * @param replace_kv - btree replaces all K/V in match_kv with replace_kv
     * @param cb_param - All parameteres provided by mapping.put can be accessed from this
     *
     * We piggyback on put to delete old commited seq Id.
     */
    btree_status_t match_item_cb_put(std::vector< std::pair< MappingKey, MappingValue > >& match_kv,
                                     std::vector< std::pair< MappingKey, MappingValue > >& replace_kv,
                                     BRangeCBParam* cb_param, BtreeSearchRange& subrange);

    /** derieves current range of lba's based on input/sub range
        subrange means current bnodes start/end boundaries
        input_range is original client provided start/end, its always inclusive for mapping layer
        Resulting start/end lba is always inclusive
        **/
    void get_start_end_lba(BtreeSearchRange& subrange, uint64_t& start_lba, uint64_t& end_lba);

    /* result of overlap of k1/k2 is added to replace_kv */
    void compute_and_add_overlap(std::vector< Free_Blk_Entry >& fbe_list, uint64_t s_lba, uint64_t e_lba,
                                 const MappingValue& new_val, uint16_t new_val_offset, MappingValue& e_val,
                                 uint16_t e_val_offset,
                                 std::vector< std::pair< MappingKey, MappingValue > >& replace_kv, uint64_t new_seq_id);

    /* add missing interval to replace kv */
    void add_new_interval(uint64_t s_lba, uint64_t e_lba, const MappingValue& val, uint16_t lba_offset,
                          std::vector< std::pair< MappingKey, MappingValue > >& replace_kv);

#ifndef NDEBUG
    void validate_get_response(uint64_t lba_start, uint32_t n_lba,
                               std::vector< std::pair< MappingKey, MappingValue > >& values,
                               MappingValue* exp_value = nullptr, volume_req* req = nullptr);
#endif
};
} // namespace homestore
