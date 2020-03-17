#pragma once

#include "blkstore/writeBack_cache.hpp"
#include "homeds/btree/ssd_btree.hpp"
#include "homeds/btree/btree.hpp"
#include <blkalloc/blk.h>
#include <csignal>
#include <error/error.h>
#include "homeds/array/blob_array.h"
#include <math.h>
#include <sds_logging/logging.h>
#include <volume/volume.hpp>
#include <utility/obj_life_counter.hpp>
#include "volume/home_blks.hpp"

SDS_LOGGING_DECL(VMOD_VOL_MAPPING)

using namespace homeds::btree;

#define LBA_MASK 0xFFFFFFFFFFFF
#define CS_ARRAY_STACK_SIZE 256 // equals 2^N_LBA_BITS //TODO - put static assert
namespace homestore {

struct LbaId {
    // size of lba start and num of lba can be reduced for future use
    uint64_t m_lba_start : LBA_BITS; // start of lba range
    uint64_t m_n_lba : NBLKS_BITS;   // number of lba's from start(inclusive)

    LbaId() : m_lba_start(0), m_n_lba(0) {}

    LbaId(const LbaId& other) : m_lba_start(other.m_lba_start), m_n_lba(other.m_n_lba) {}

    LbaId(uint64_t lbaId) { LbaId(lbaId & LBA_MASK, lbaId >> LBA_BITS); }

    LbaId(uint64_t lba_start, uint64_t n_lba) : m_lba_start(lba_start), m_n_lba(n_lba) { assert(n_lba < MAX_NUM_LBA); }

    uint64_t end() { return (m_lba_start + m_n_lba - 1); }

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

    virtual homeds::blob get_blob() const override { return {(uint8_t*)m_lbaId_ptr, get_fixed_size()}; }

    virtual void set_blob(const homeds::blob& b) override {
        assert(b.size == get_fixed_size());
        m_lbaId_ptr = (LbaId*)b.bytes;
    }

    virtual void copy_blob(const homeds::blob& b) override {
        assert(b.size == get_fixed_size());
        LbaId* other = (LbaId*)b.bytes;
        set(other->m_lba_start, other->m_n_lba);
    }

    virtual void copy_end_key_blob(const homeds::blob& b) override {
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
        ss << "lba_st = " << start() << ", lba_end = " << (start() + get_n_lba() - 1);
        return ss.str();
    }

    void get_overlap(uint64_t lba_start, uint64_t lba_end, MappingKey& overlap) {
        auto start_lba = std::max(start(), lba_start);
        auto end_lba = std::min(end(), lba_end);
        overlap.set(start_lba, end_lba - start_lba + 1);
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
    uint64_t seqId;
    BlkId blkId;
    uint64_t nlba : NBLKS_BITS;
    uint64_t blk_offset : NBLKS_BITS; // offset based on blk store not based on vol page size
    ValueEntryMeta(uint64_t seqId, const BlkId& blkId, uint8_t blk_offset, uint8_t nlba) :
            seqId(seqId),
            blkId(blkId),
            nlba(nlba),
            blk_offset(blk_offset){};
    ValueEntryMeta() : seqId(0), blkId(0), nlba(0), blk_offset(0){};
} __attribute__((__packed__));

struct ValueEntry {
private:
    ValueEntryMeta m_meta;
    // this allocates 2^NBLKS_BITS size array for checksum on stack, however actual memory used is less on bnode
    // as we call get_blob_size which takes into account actual nblks to determine exact size of checksum array
    // TODO - can be replaced by thread local buffer in future
    std::array< uint16_t, CS_ARRAY_STACK_SIZE > m_carr;
    ValueEntry* m_ptr;

public:
    ValueEntry() : m_meta(), m_carr() { m_ptr = (ValueEntry*)this; }

    // deep copy
    ValueEntry(uint64_t seqId, const BlkId& blkId, uint8_t blk_offset, uint8_t nlba,
               const std::array< uint16_t, CS_ARRAY_STACK_SIZE >& carr) :
            m_meta(seqId, blkId, blk_offset, nlba),
            m_carr(carr) {
        m_ptr = (ValueEntry*)this;
    }

    ValueEntry(const ValueEntry& ve) { copy_from(ve); }

    ValueEntry(uint8_t* ptr) : m_ptr((ValueEntry*)ptr) {}

    uint32_t get_blob_size() { return sizeof(m_meta) + sizeof(uint16_t) * get_nlba(); }

    homeds::blob get_blob() { return {(uint8_t*)m_ptr, get_blob_size()}; }

    void set_blob(homeds::blob b) { m_ptr = (ValueEntry*)b.bytes; }

    void copy_blob(homeds::blob b) {
        ValueEntry ve(b.bytes);
        copy_from(ve);
    }

    void copy_from(const ValueEntry& ve) {
        m_meta.seqId = ve.get_seqId();
        m_meta.blkId = ve.get_blkId();
        m_meta.blk_offset = ve.get_blk_offset();
        m_meta.nlba = ve.get_nlba();
        for (auto i = 0; i < ve.get_nlba(); i++)
            m_carr[i] = ve.get_checksum_at(i);
        m_ptr = (ValueEntry*)this;
    }

    void add_offset(uint8_t lba_offset, uint8_t nlba, uint32_t vol_page_size) {
        // move checksum array elements to start from offset position
        assert(lba_offset < get_nlba());
        memmove((void*)&(m_ptr->m_carr[0]), (void*)(&(m_ptr->m_carr[lba_offset])), sizeof(uint16_t) * nlba);
        m_ptr->m_meta.nlba = nlba;
        uint8_t blk_offset = (vol_page_size / HomeBlks::instance()->get_data_pagesz()) * lba_offset;
        m_ptr->m_meta.blk_offset += blk_offset;
#ifndef NDEBUG
        auto actual_nblks = (vol_page_size / HomeBlks::instance()->get_data_pagesz()) * nlba;
        assert(blk_offset + actual_nblks <= get_blkId().get_nblks());
#endif
    }

    uint64_t get_seqId() const { return m_ptr->m_meta.seqId; }

    BlkId& get_blkId() const { return m_ptr->m_meta.blkId; }

    uint8_t get_blk_offset() const { return (uint8_t)m_ptr->m_meta.blk_offset; }

    uint8_t get_nlba() const { return (uint8_t)m_ptr->m_meta.nlba; }

    void set_nlba(uint8_t nlba) { m_ptr->m_meta.nlba = nlba; }

    uint16_t& get_checksum_at(uint8_t index) const {
        assert(index < get_nlba());
        return m_ptr->m_carr[index];
    }

    int compare(const ValueEntry* other) const {
        if (get_seqId() == other->get_seqId())
            return 0;
        else if (get_seqId() < other->get_seqId())
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
        ss << "Seq: " << get_seqId() << ", " << get_blkId() << ", Boff: " << unsigned(get_blk_offset());
        ss << ", v_nlba: " << unsigned(get_nlba());

        if (HomeBlks::instance()->print_checksum()) {
            ss << ", cs: " << get_checksums_string();
        }
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

    MappingValue(MappingValue& other, uint16_t offset, uint32_t nblks, uint32_t page_size) {
        Blob_Array< ValueEntry >& arr = other.get_array();
        assert(arr.get_total_elements() == 1);
        ValueEntry ve;
        arr.get(0, ve, true);
        ve.add_offset(offset, nblks, page_size);
        m_earr.set_element(ve);
    }

    MappingValue(boost::intrusive_ptr< volume_req > req, const MappingValue& one, uint32_t one_offset,
                 const MappingValue& second, uint32_t second_offset, uint32_t page_size) {
        assert(0);
    }

    virtual homeds::blob get_blob() const override {
        homeds::blob b;
        b.bytes = (uint8_t*)m_earr.get_mem();
        b.size = m_earr.get_size();
        return b;
    }

    virtual void set_blob(const homeds::blob& b) override { m_earr.set_mem((void*)(b.bytes), b.size); }

    virtual void copy_blob(const homeds::blob& b) override {
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

    Blob_Array< ValueEntry >& get_array() { return m_earr; }

    uint32_t meta_size() {
        uint32_t size = 0;
        size = sizeof(ValueEntryMeta) + m_earr.get_meta_size();
        return size;
    }

    bool is_valid() {
        if (m_earr.get_total_elements() == 0)
            return false;
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

    // insert entry to this mapping value, maintaing it sorted by seqId - deep copy
    void add_copy(ValueEntry& ve, MappingValue& out) {
        vector< ValueEntry > v_array;
        get_array().get_all(v_array, true);
        auto i = 0u;
        if (v_array.size() > 0) {
            while (i < v_array.size() && v_array[i].compare(&ve) > 0)
                ++i;
            if (i < v_array.size() && v_array[i].compare(&ve) == 0) {
                /* every sequence ID is invalid until jorunaling comes */
                assert(ve.get_seqId() == INVALID_SEQ_ID);
                ++i;
            }
        }
        v_array.insert(v_array.begin() + i, ve);
        out.get_array().set_elements(v_array);
    }

#if 0    
    void truncate(boost::intrusive_ptr< volume_req > req) {    
        Blob_Array< ValueEntry >& e_varray = get_array();    

        // iterate and remove all entries except latest one    
        for (int i = e_varray.get_total_elements() - 1; i >= 0; i--) {    
            ValueEntry ve;    
            e_varray.get(i, ve, false);    
            uint32_t total = e_varray.get_total_elements();    
            if (req->lastCommited_seqId == INVALID_SEQ_ID ||    
                    ve.get_seqId() < req->lastCommited_seqId) { // eligible for removal    

                LOGTRACE("Free entry:{} nblks {}", ve.to_string(),    
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

class mapping {
    typedef function< void(struct BlkId blkid, size_t offset_size, size_t size) > alloc_blk_callback;
    typedef function< void(boost::intrusive_ptr< volume_req > cookie) > comp_callback;
    typedef std::function< void(Free_Blk_Entry fbe) > free_blk_callback;
    typedef std::function< void(BlkId& bid) > pending_read_blk_cb;
    constexpr static uint64_t lba_query_cnt = 1024ull;

private:
    MappingBtreeDeclType* m_bt;
    alloc_blk_callback m_alloc_blk_cb;
    free_blk_callback m_free_blk_cb;
    pending_read_blk_cb m_pending_read_blk_cb;
    comp_callback m_comp_cb;
    uint32_t m_vol_page_size;
    const MappingValue EMPTY_MAPPING_VALUE;
    std::string m_unique_name;
    bool m_fix_state = false;
    uint64_t m_outstanding_io = 0;

    class GetCBParam : public BRangeQueryCBParam< MappingKey, MappingValue > {
    public:
        boost::intrusive_ptr< volume_req > m_req;

        GetCBParam(boost::intrusive_ptr< volume_req > req) : m_req(req) {}
    };

    class UpdateCBParam : public BRangeUpdateCBParam< MappingKey, MappingValue > {
    public:
        boost::intrusive_ptr< volume_req > m_req;

        UpdateCBParam(boost::intrusive_ptr< volume_req > req, MappingKey& new_key, MappingValue& new_value) :
                BRangeUpdateCBParam(new_key, new_value),
                m_req(req) {}
    };

public:
    void get_alloc_blks_cb(vector< pair< MappingKey, MappingValue > >& match_kv,
                           vector< pair< MappingKey, MappingValue > >& result_kv,
                           BRangeQueryCBParam< MappingKey, MappingValue >* cb_param) {
        uint64_t start_lba = 0, end_lba = 0;
        get_start_end_lba(cb_param, start_lba, end_lba);
        ValueEntry new_ve; // empty

        for (auto i = 0u; i < match_kv.size(); ++i) {
            auto& existing = match_kv[i];
            MappingKey* e_key = &existing.first;
            Blob_Array< ValueEntry > array = (&existing.second)->get_array();
            assert(array.get_total_elements() > 0);

            for (uint32_t j = 0; j < array.get_total_elements(); ++j) {
                ValueEntry ve;
                array.get((uint32_t)j, ve, true);
                MappingKey overlap;
                e_key->get_overlap(start_lba, end_lba, overlap);
                if (i == 0 || i == match_kv.size() - 1) {
                    auto lba_offset = overlap.get_start_offset(*e_key);
                    ve.add_offset(lba_offset, overlap.get_n_lba(), m_vol_page_size);
                } else {
                    assert(!overlap.get_start_offset(*e_key));
                }
                m_alloc_blk_cb(ve.get_blkId(), (ve.get_blk_offset() * HomeBlks::instance()->get_data_pagesz()),
                               (overlap.get_n_lba() * m_vol_page_size));
            }
        }
    }

    ~mapping() { delete m_bt; }

    void destroy() {
        /* XXX: do we need to handle error condition here ?. In the next boot we will automatically recaim these blocks
         */
        auto ret = m_bt->destroy(std::bind(&mapping::process_free_blk_callback, this, std::placeholders::_1), false);
        HS_SUBMOD_ASSERT(LOGMSG, (ret == btree_status_t::success), , "vol", m_unique_name,
                         "Error in destroying mapping btree ret={} ", ret);
    }

    void recovery_cmpltd() { m_bt->recovery_cmpltd(); }

    int sweep_alloc_blks(uint64_t start_lba, uint64_t end_lba) {
        MappingKey start_key(start_lba, 1), end_key(end_lba, 1);
        auto search_range = BtreeSearchRange(start_key, true, end_key, true);
        GetCBParam param(nullptr);
        vector< pair< MappingKey, MappingValue > > result_kv;

        BtreeQueryRequest< MappingKey, MappingValue > qreq(
            search_range, BtreeQueryType::TREE_TRAVERSAL_QUERY, (end_lba - start_lba + 1),
            std::bind(&mapping::get_alloc_blks_cb, this, placeholders::_1, placeholders::_2, placeholders::_3),
            (BRangeQueryCBParam< MappingKey, MappingValue >*)&param);
        if (m_bt->query(qreq, result_kv) != btree_status_t::success) {
            return -1;
        }
        return 0;
    }

    void process_completions(boost::intrusive_ptr< writeback_req > cookie, bool status) {
        if (m_fix_state) {
            // if we are in fix state, we are generating internal put requests for new btree and should not return
            // to volume layer for callback.
            m_outstanding_io--;
            return;
        }

        boost::intrusive_ptr< volume_req > req = boost::static_pointer_cast< volume_req >(cookie);
        if (req->status == no_error) {
            req->status = status ? no_error : btree_write_failed;
        }
        m_comp_cb(req);
    }

    void process_free_blk_callback(MappingValue& mv) {
        Blob_Array< ValueEntry > array = mv.get_array();
        for (uint32_t i = 0; i < array.get_total_elements(); ++i) {
            ValueEntry ve;
            array.get((uint32_t)i, ve, true);
            HS_SUBMOD_LOG(DEBUG, base, , "vol", m_unique_name, "Free Blk: vol_page: {}, data_page: {}, n_lba: {}",
                          m_vol_page_size, HomeBlks::instance()->get_data_pagesz(), ve.get_nlba());
            uint64_t nlba = (m_vol_page_size / HomeBlks::instance()->get_data_pagesz()) * ve.get_nlba();
            Free_Blk_Entry fbe(ve.get_blkId(), ve.get_blk_offset(), nlba);
            m_free_blk_cb(fbe);
        }
    }

    mapping(uint64_t volsize, uint32_t page_size, const std::string& unique_name, comp_callback comp_cb,
            free_blk_callback free_blk_cb, pending_read_blk_cb pending_read_cb = nullptr) :
            m_free_blk_cb(free_blk_cb),
            m_pending_read_blk_cb(pending_read_cb),
            m_comp_cb(comp_cb),
            m_vol_page_size(page_size),
            m_unique_name(unique_name) {
        homeds::btree::BtreeConfig btree_cfg(HomeStoreConfig::atomic_phys_page_size, unique_name.c_str());
        btree_cfg.set_max_objs(volsize / page_size);
        btree_cfg.set_max_key_size(sizeof(uint32_t));
        btree_cfg.set_max_value_size(page_size);

        homeds::btree::btree_device_info bt_dev_info;
        bt_dev_info.blkstore = (void*)HomeBlks::instance()->get_metadata_blkstore();
        bt_dev_info.new_device = false;
        m_bt = MappingBtreeDeclType::create_btree(
            btree_cfg, &bt_dev_info,
            std::bind(&mapping::process_completions, this, std::placeholders::_1, std::placeholders::_2));
    }

    mapping(uint64_t volsize, uint32_t page_size, const std::string& unique_name, btree_super_block& btree_sb,
            comp_callback comp_cb, alloc_blk_callback alloc_blk_cb, free_blk_callback free_blk_cb,
            pending_read_blk_cb pending_read_cb = nullptr) :
            m_alloc_blk_cb(alloc_blk_cb),
            m_free_blk_cb(free_blk_cb),
            m_pending_read_blk_cb(pending_read_cb),
            m_comp_cb(comp_cb),
            m_vol_page_size(page_size),
            m_unique_name(unique_name) {
        homeds::btree::BtreeConfig btree_cfg(HomeStoreConfig::atomic_phys_page_size, unique_name.c_str());
        btree_cfg.set_max_objs(volsize / page_size);
        btree_cfg.set_max_key_size(sizeof(uint32_t));
        btree_cfg.set_max_value_size(page_size);

        homeds::btree::btree_device_info bt_dev_info;
        bt_dev_info.blkstore = HomeBlks::instance()->get_metadata_blkstore();
        bt_dev_info.new_device = false;
        m_bt = MappingBtreeDeclType::create_btree(
            btree_sb, btree_cfg, &bt_dev_info,
            std::bind(&mapping::process_completions, this, std::placeholders::_1, std::placeholders::_2));
    }

    uint64_t get_used_size() { return m_bt->get_used_size(); }
    btree_super_block get_btree_sb() { return (m_bt->get_btree_sb()); }

    error_condition get(boost::intrusive_ptr< volume_req > req, vector< pair< MappingKey, MappingValue > >& values,
                        MappingBtreeDeclType* bt) {
        uint64_t start_lba = req->lba;
        uint64_t num_lba = req->nlbas;
        uint64_t end_lba = start_lba + req->nlbas - 1;
        MappingKey start_key(start_lba, 1);
        MappingKey end_key(end_lba, 1);
        auto search_range = BtreeSearchRange(start_key, true, end_key, true);
        GetCBParam param(req);
        std::vector< pair< MappingKey, MappingValue > > result_kv;

        BtreeQueryRequest< MappingKey, MappingValue > qreq(
            search_range, BtreeQueryType::SWEEP_NON_INTRUSIVE_PAGINATION_QUERY, num_lba,
            std::bind(&mapping::match_item_cb_get, this, placeholders::_1, placeholders::_2, placeholders::_3),
            (BRangeQueryCBParam< MappingKey, MappingValue >*)&param);
        auto ret = bt->query(qreq, result_kv);

        if (ret != btree_status_t::success && ret != btree_status_t::has_more) {
            return btree_read_failed;
        }

        values.insert(values.begin(), result_kv.begin(), result_kv.end());
        return no_error;
    }

    error_condition get(boost::intrusive_ptr< volume_req > req, vector< pair< MappingKey, MappingValue > >& values,
                        bool fill_gaps = true) {
        uint64_t start_lba = req->lba;
        uint64_t num_lba = req->nlbas;
        uint64_t end_lba = start_lba + req->nlbas - 1;
        MappingKey start_key(start_lba, 1);
        MappingKey end_key(end_lba, 1);

        auto search_range = BtreeSearchRange(start_key, true, end_key, true);
        GetCBParam param(req);
        std::vector< pair< MappingKey, MappingValue > > result_kv;

        BtreeQueryRequest< MappingKey, MappingValue > qreq(
            search_range, BtreeQueryType::SWEEP_NON_INTRUSIVE_PAGINATION_QUERY, num_lba,
            std::bind(&mapping::match_item_cb_get, this, placeholders::_1, placeholders::_2, placeholders::_3),
            (BRangeQueryCBParam< MappingKey, MappingValue >*)&param);
        auto ret = m_bt->query(qreq, result_kv);

        if (ret != btree_status_t::success && ret != btree_status_t::has_more) {
            return btree_read_failed;
        }

        if (fill_gaps) {
            // fill the gaps
            auto last_lba = start_lba;
            for (auto i = 0u; i < result_kv.size(); i++) {
                int nl = result_kv[i].first.start() - last_lba;
                while (nl-- > 0) {
                    values.emplace_back(make_pair(MappingKey(last_lba, 1), EMPTY_MAPPING_VALUE));
                    last_lba++;
                }
                values.emplace_back(result_kv[i]);
                last_lba = result_kv[i].first.end() + 1;
            }
            while (last_lba <= end_lba) {
                values.emplace_back(make_pair(MappingKey(last_lba, 1), EMPTY_MAPPING_VALUE));
                last_lba++;
            }
#ifndef NDEBUG
            validate_get_response(start_lba, num_lba, values);
#endif
        } else {
            values.insert(values.begin(), result_kv.begin(), result_kv.end());
        }

        return no_error;
    }

    error_condition put(boost::intrusive_ptr< volume_req > req, MappingKey& key, MappingValue& value,
                        MappingBtreeDeclType* bt) {
        assert(value.get_array().get_total_elements() == 1);
        UpdateCBParam param(req, key, value);
        MappingKey start(key.start(), 1);
        MappingKey end(key.end(), 1);

        auto search_range = BtreeSearchRange(start, true, end, true);
        BtreeUpdateRequest< MappingKey, MappingValue > ureq(
            search_range, bind(&mapping::match_item_cb_put, this, placeholders::_1, placeholders::_2, placeholders::_3),
            bind(&mapping::get_size_needed, this, placeholders::_1, placeholders::_2),
            (BRangeUpdateCBParam< MappingKey, MappingValue >*)&param);
        bt->range_put(key, value, btree_put_type::APPEND_IF_EXISTS_ELSE_INSERT, to_wb_req(req), to_wb_req(req), ureq);

#if 0
        vector<pair<MappingKey, MappingValue>> values;
        auto temp = req->lastCommited_seqId;
        req->lastCommited_seqId = req->seqId;
        get(req, values);
        req->lastCommited_seqId = temp;
        validate_get_response(key.start(), key.get_n_lba(), values, &value, req);
#endif
        return no_error;
    }

    error_condition put(boost::intrusive_ptr< volume_req > req, MappingKey& key, MappingValue& value) {
        return put(req, key, value, m_bt);
    }

    void print_tree() { m_bt->print_tree(); }
    bool verify_tree() { return m_bt->verify_tree(); }

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
    bool fix(uint64_t start_lba, uint64_t end_lba, bool verify = false) {
        if (start_lba >= end_lba) {
            LOGERROR("Wrong input, start_lba: {}, should be smaller than end_lba: {}", start_lba, end_lba);
            return false;
        }

        LOGINFO("Fixing btree, start_lba: {}, end_lba: {}", start_lba, end_lba);

        // create a new btree
        auto btree_cfg = m_bt->get_btree_cfg();
        homeds::btree::btree_device_info bt_dev_info;
        bt_dev_info.blkstore = (void*)HomeBlks::instance()->get_metadata_blkstore();
        bt_dev_info.new_device = false;
        auto new_bt = MappingBtreeDeclType::create_btree(
            btree_cfg, &bt_dev_info,
            std::bind(&mapping::process_completions, this, std::placeholders::_1, std::placeholders::_2));

        m_fix_state = true;
        m_outstanding_io = 0;

        uint64_t num_kv_recovered = 0;
        auto start = start_lba, end = std::min(start_lba + lba_query_cnt, end_lba);
        while (start <= end && end <= end_lba) {
            // get all the KVs from existing btree;
            boost::intrusive_ptr< volume_req > vreq = volume_req::make_request();
            vreq->lba = start;
            vreq->nlbas = end - start + 1;
            vreq->seqId = INVALID_SEQ_ID;
            vreq->lastCommited_seqId = INVALID_SEQ_ID;

            std::vector< std::pair< MappingKey, MappingValue > > kvs;
            auto ret = get(vreq, kvs, false /* fill_gaps */);
            if (ret != no_error) {
                LOGERROR("failed to get KVs from btree");
                return false;
            }

            // put every KV to new btree we have got from old btree;
            for (auto& x : kvs) {
#if 0
                auto ret = new_bt->put(x.first, x.second, btree_put_type::INSERT_ONLY_IF_NOT_EXISTS);
                if (ret != btree_status_t::success) {
                    LOGERROR("failed to put node with k/v: {}/{}, status; {}", x.first.to_string(), x.second.to_string(), ret);
                    return false;
                }
#else
                boost::intrusive_ptr< volume_req > req = volume_req::make_request();
                req->seqId = INVALID_SEQ_ID;
                req->lastCommited_seqId = INVALID_SEQ_ID; // keeping only latest version always
#if 0
                req->lba = x.first.start();
                req->nlbas = x.first.get_n_lba();
                ValueEntry ve;
                x.second.get_array().get(0, ve, false /* copy */);
                req->blkId = ve.get_blkId();
#endif
                // without this line, btree is not trigging process_completions cb to mapping layer;
                req->state = writeback_req_state::WB_REQ_COMPL;
                m_outstanding_io++;

                auto ret = put(req, x.first, x.second, new_bt);
                if (ret != no_error) {
                    LOGERROR("failed to put node with k/v: {}/{}", x.first.to_string(), x.second.to_string());
                    return false;
                }
#endif
                LOGINFO("Successfully inserted K:{}, \n V:{}.", x.first.to_string(), x.second.to_string());
            }

            num_kv_recovered += kvs.size();
            start = end + 1;
            end = std::min(start + lba_query_cnt, end_lba);
        }
        LOGINFO("Successfully recovered num: {} of K,V pairs from corrupted btree.", num_kv_recovered);

        if (verify) {
            auto verify_status = verify_fixed_bt(start_lba, end_lba, m_bt, new_bt);
            if (!verify_status) {
                delete new_bt;
                return false;
            }
        }

        auto old_bt = m_bt;
        m_bt = new_bt;
        delete old_bt;

        while (m_outstanding_io != 0) {
            sleep(2);
        }

        // reset fix state to false
        m_fix_state = false;
        return true;
    }

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
                         MappingBtreeDeclType* new_bt) {
        uint64_t num_kv_verified = 0;
        auto start = start_lba, end = std::min(start_lba + lba_query_cnt, end_lba);
        while (start <= end_lba) {
            assert(start <= end);
            std::vector< std::pair< MappingKey, MappingValue > > kvs_old;
            std::vector< std::pair< MappingKey, MappingValue > > kvs_new;

            // get all the KVs from existing btree;
            boost::intrusive_ptr< volume_req > vreq = volume_req::make_request();
            vreq->lba = start;
            vreq->nlbas = end - start + 1;
            vreq->seqId = INVALID_SEQ_ID;
            vreq->lastCommited_seqId = INVALID_SEQ_ID;

            // now m_bt points to the new btree;
            auto ret_old = get(vreq, kvs_old, old_bt);
            auto ret_new = get(vreq, kvs_new, new_bt);

            if (ret_old != no_error || ret_new != no_error) {
                LOGERROR("btree_fix verify failed, reason: get from btree KVs failed.");
                return false;
            }

            if (kvs_new.size() != kvs_old.size()) {
                LOGERROR("btree_fix verify failed, reason: mismatch total number of KV old: {} new: {}", kvs_old.size(),
                         kvs_new.size());

                LOGINFO("Printing KVs for old and new btree tree for lba range: [{}, {}]", start, end);
                print_kv(kvs_old);
                print_kv(kvs_new);
                return false;
            }

            for (uint64_t i = 0; i < kvs_old.size(); i++) {
                if (kvs_old[i].first.to_string().compare(kvs_new[i].first.to_string()) != 0 ||
                    kvs_old[i].second.to_string().compare(kvs_new[i].second.to_string()) != 0) {
                    LOGERROR("btree_fix verify failed, reason: mismatch KV pair old K: {}, V: {}, new K: {}, V: {}",
                             kvs_old[i].first.to_string(), kvs_new[i].first.to_string(), kvs_old[i].second.to_string(),
                             kvs_new[i].second.to_string());
                    return false;
                }
            }

            num_kv_verified += kvs_new.size();
            start = end + 1;
            end = std::min(start + lba_query_cnt, end_lba);
        }

        LOGINFO("Successfully verified recovered btree, total KV verified: {}", num_kv_verified);
        return true;
    }

    void print_kv(std::vector< std::pair< MappingKey, MappingValue > >& kvs) {
        LOGINFO("Total Elements: {}", kvs.size());
        uint32_t i = 0;
        for (auto& x : kvs) {
            LOGINFO("No. {} : K: {}, V: {}", i++, x.first.to_string(), x.second.to_string());
        }
        LOGINFO("Finished Printing. ");
    }

    void print_node(uint64_t blkid) {
        bnodeid_t bid(blkid);
        m_bt->print_node(bid);
    }

private:
    /**
     * Callback called once for each bnode
     * @param match_kv  - list of all match K/V for bnode (based on key.compare/compare_range)
     * @param result_kv - All KV which are passed backed to mapping.get by btree. Btree dosent use this.
     * @param cb_param -  All parameteres provided by mapping.get can be accessed from this
     */
    void match_item_cb_get(vector< pair< MappingKey, MappingValue > >& match_kv,
                           vector< pair< MappingKey, MappingValue > >& result_kv,
                           BRangeQueryCBParam< MappingKey, MappingValue >* cb_param) {
        uint64_t start_lba = 0, end_lba = 0;
        get_start_end_lba(cb_param, start_lba, end_lba);
        GetCBParam* param = (GetCBParam*)cb_param;

        assert((param->m_req->lastCommited_seqId == INVALID_SEQ_ID) ||
               (param->m_req->lastCommited_seqId <= param->m_req->seqId));

        ValueEntry new_ve; // empty
#ifndef NDEBUG
        stringstream ss;
        ss << "vol_uuid:" << boost::uuids::to_string(param->m_req->vol_uuid);
        ss << ",Lba:" << param->m_req->lba << ",nlbas:" << param->m_req->nlbas << ",seqId:" << param->m_req->seqId
           << ",last_seqId:" << param->m_req->lastCommited_seqId;
        ss << ",is:" << ((MappingKey*)param->get_input_range().get_start_key())->to_string();
        ss << ",ie:" << ((MappingKey*)param->get_input_range().get_end_key())->to_string();
        ss << ",ss:" << ((MappingKey*)param->get_sub_range().get_start_key())->to_string();
        ss << ",se:" << ((MappingKey*)param->get_sub_range().get_end_key())->to_string();
        ss << ",match_kv:";
        for (auto& ptr : match_kv)
            ss << ptr.first.to_string() << "," << ptr.second.to_string();
#endif

        for (auto i = 0u; i < match_kv.size(); i++) {
            auto& existing = match_kv[i];
            MappingKey* e_key = &existing.first;
            Blob_Array< ValueEntry > array = (&existing.second)->get_array();
            for (int j = array.get_total_elements() - 1; j >= 0; j--) {
                // seqId use to filter out KVs with higher seqIds and put only latest seqid entry in result_kv
                ValueEntry ve;
                array.get((uint32_t)j, ve, true);

                if (ve.get_seqId() <= param->m_req->lastCommited_seqId || ve.get_seqId() == INVALID_SEQ_ID) {
                    if (i == 0 || i == match_kv.size() - 1) {

                        MappingKey overlap;
                        e_key->get_overlap(start_lba, end_lba, overlap);

                        auto lba_offset = overlap.get_start_offset(*e_key);
                        ve.add_offset(lba_offset, overlap.get_n_lba(), m_vol_page_size);
                        result_kv.emplace_back(make_pair(overlap, MappingValue(ve)));
                    } else {
                        result_kv.emplace_back(make_pair(MappingKey(*e_key), MappingValue(ve)));
                    }
                    if (m_pending_read_blk_cb) {
                        m_pending_read_blk_cb(ve.get_blkId()); // mark this blk as pending read
                    }
                    break;
                }
                // else {
                //     assert(0);// for now, we are always returning latest write
                // }
            }
        }
#ifndef NDEBUG
        ss << ",result_kv:";
        for (auto& ptr : result_kv)
            ss << ptr.first.to_string() << "," << ptr.second.to_string();
        HS_SUBMOD_LOG(TRACE, base, , "vol", m_unique_name, "Get_CB: {} ", ss.str());
#endif
    }

    /* It calculate the offset in a value by looking at start lba */
    uint32_t compute_val_offset(BRangeUpdateCBParam< MappingKey, MappingValue >* cb_param, uint64_t start_lba) {
        uint64_t input_start_lba = cb_param->get_new_key().start();
        return (start_lba - input_start_lba);
    }

    uint32_t get_size_needed(vector< pair< MappingKey, MappingValue > >& match_kv,
                             BRangeUpdateCBParam< MappingKey, MappingValue >* cb_param) {

        UpdateCBParam* param = (UpdateCBParam*)cb_param;
        MappingValue& new_val = param->get_new_value();
        int overlap_entries = match_kv.size();

        /* In worse case, one value is divided into (2 * overlap_entries + 1). Same meta data of a value (it is fixed
         * size) will be copied to all new entries.
         */
        uint32_t new_size = (overlap_entries + 1) * new_val.meta_size() + new_val.get_blob_size();
        return new_size;
    }

    /* Callback called onces for each eligible bnode
     * @param match_kv - list of all match K/V for bnode (based on key.compare/compare_range)
     * @param replace_kv - btree replaces all K/V in match_kv with replace_kv
     * @param cb_param - All parameteres provided by mapping.put can be accessed from this
     *
     * We piggyback on put to delete old commited seq Id.
     */
    void match_item_cb_put(vector< pair< MappingKey, MappingValue > >& match_kv,
                           vector< pair< MappingKey, MappingValue > >& replace_kv,
                           BRangeUpdateCBParam< MappingKey, MappingValue >* cb_param) {

        uint64_t start_lba = 0, end_lba = 0;
        UpdateCBParam* param = (UpdateCBParam*)cb_param;

        get_start_end_lba(cb_param, start_lba, end_lba);
        auto req = param->m_req;
        MappingValue& new_val = param->get_new_value();

#ifndef NDEBUG
        uint16_t replace_kv_size = req->blkIds_to_free.size();
        stringstream ss;
        ss << "vol_uuid:" << boost::uuids::to_string(param->m_req->vol_uuid);
        ss << ",Lba:" << param->m_req->lba << ",nlbas:" << param->m_req->nlbas << ",seqId:" << param->m_req->seqId
           << ",last_seqId:" << param->m_req->lastCommited_seqId << ",is_mod:" << param->is_state_modifiable();
        ss << ",is:" << ((MappingKey*)param->get_input_range().get_start_key())->to_string();
        ss << ",ie:" << ((MappingKey*)param->get_input_range().get_end_key())->to_string();
        ss << ",ss:" << ((MappingKey*)param->get_sub_range().get_start_key())->to_string();
        ss << ",se:" << ((MappingKey*)param->get_sub_range().get_end_key())->to_string();
        ss << ",match_kv:";
        for (auto& ptr : match_kv)
            ss << ptr.first.to_string() << "," << ptr.second.to_string();
#endif
        /* We don't change BLKID in value. Instead we store offset of lba range that we are storing */
        uint32_t initial_val_offset = compute_val_offset(cb_param, start_lba);
        uint32_t new_val_offset = initial_val_offset;
        for (auto& existing : match_kv) {
            MappingKey* e_key = &existing.first;

            if (e_key->start() > start_lba) {
                /* add missing interval */
                add_new_interval(start_lba, e_key->start() - 1, new_val, new_val_offset, replace_kv);
                new_val_offset += e_key->start() - start_lba;
                start_lba = e_key->start();
            }

            MappingValue* e_value = &existing.second;
            uint32_t existing_val_offset = 0;
            /* enable it when snapshot comes */
#if 0
            /* Truncate the existing value based on seq ID */
            e_value->truncate(req);
#endif

            /* we need to split the existing key/value at the start */
            if (e_key->start() < start_lba) {
                /* It will always be the first entry */
                assert(new_val_offset == initial_val_offset);
                // split existing key at the start and add new interval
                add_new_interval(e_key->start(), start_lba - 1, *e_value, existing_val_offset, replace_kv);
                existing_val_offset += start_lba - e_key->start();
            }

            /* Now both intervals have the same start */
            // compute overlap
            auto end_lba_overlap = e_key->end() < end_lba ? e_key->end() : end_lba;
            compute_and_add_overlap(req, start_lba, end_lba_overlap, new_val, new_val_offset, *e_value,
                                    existing_val_offset, replace_kv);
#ifndef NDEBUG
            ++replace_kv_size;
#endif
            uint32_t nblks = end_lba_overlap - start_lba + 1;
            new_val_offset += nblks;
            existing_val_offset += nblks;
            start_lba += nblks;

            if (e_key->end() > end_lba) {
                assert(start_lba == end_lba + 1);
                // split existing key at the end and add new interval
                add_new_interval(start_lba, e_key->end(), *e_value, existing_val_offset, replace_kv);
            }
        }

        assert(req->blkIds_to_free.size() == replace_kv_size);
        if (start_lba <= end_lba) { // add new range
            add_new_interval(start_lba, end_lba, new_val, new_val_offset, replace_kv);
        }

        // TODO - merge kv which have contigous lba and BlkIds - may be not that useful for performance
#ifndef NDEBUG
        /* sanity check */
        for (auto& pair : replace_kv) {
            Blob_Array< ValueEntry >& array = pair.second.get_array();

            auto i = 0u;
            while (i < array.get_total_elements()) {
                ValueEntry curve;
                array.get(i, curve, false);
                if (i != 0) { // sorted ve check
                    ValueEntry preve;
                    array.get(i - 1, preve, false);
                    assert(preve.compare(&curve) > 0);
                }
                assert(curve.get_nlba() == pair.first.get_n_lba());
                if (same_value_gen) {
                    // same values can be generated for different keys in some test cases
                    ++i;
                    continue;
                }
                // check if replace entries dont overlap free entries
                auto blk_start = curve.get_blkId().get_id() + curve.get_blk_offset();
                auto blk_end =
                    blk_start + (m_vol_page_size / HomeBlks::instance()->get_data_pagesz()) * curve.get_nlba() - 1;
                for (Free_Blk_Entry& fbe : param->m_req->blkIds_to_free) {
                    if (fbe.m_blkId.get_chunk_num() != curve.get_blkId().get_chunk_num()) {
                        continue;
                    }
                    auto fblk_start = fbe.m_blkId.get_id() + fbe.m_blk_offset;
                    auto fblk_end = fblk_start + fbe.m_nblks_to_free - 1;
                    if (blk_end < fblk_start || fblk_end < blk_start) {
                    } // non overlapping
                    else {
                        ss << ",replace_kv:";
                        for (auto& ptr : replace_kv) {
                            ss << ptr.first.to_string() << "," << ptr.second.to_string();
                        }
                        HS_SUBMOD_ASSERT(DEBUG, 0, , "vol", m_unique_name, "Error::Put_CB:,{} ", ss.str());
                    }
                }
                i++;
            }
        }
        ss << ",replace_kv:";
        for (auto& ptr : replace_kv) {
            ss << ptr.first.to_string() << "," << ptr.second.to_string();
        }
        LOGDEBUGMOD(VMOD_VOL_MAPPING, "{}", ss.str());
#endif
    }

    /** derieves current range of lba's based on input/sub range
        subrange means current bnodes start/end boundaries
        input_range is original client provided start/end, its always inclusive for mapping layer
        Resulting start/end lba is always inclusive
        **/
    void get_start_end_lba(BRangeCBParam* param, uint64_t& start_lba, uint64_t& end_lba) {

        // pick higher start of subrange/inputrange
        MappingKey* s_subrange = (MappingKey*)param->get_sub_range().get_start_key();
        assert(s_subrange->start() == s_subrange->end());

        if (param->get_sub_range().is_start_inclusive()) {
            start_lba = s_subrange->start();
        } else {
            start_lba = s_subrange->start() + 1;
        }

        MappingKey* e_subrange = (MappingKey*)param->get_sub_range().get_end_key();
        assert(e_subrange->start() == e_subrange->end());
        if (param->get_sub_range().is_end_inclusive()) {
            end_lba = e_subrange->end();
        } else {
            end_lba = e_subrange->end() - 1;
        }
    }

    /* result of overlap of k1/k2 is added to replace_kv */
    void compute_and_add_overlap(boost::intrusive_ptr< volume_req > req, uint64_t s_lba, uint64_t e_lba,
                                 MappingValue& new_val, uint16_t new_val_offset, MappingValue& e_val,
                                 uint16_t e_val_offset, vector< pair< MappingKey, MappingValue > >& replace_kv) {

        auto nlba = e_lba - s_lba + 1;

        /* This code assumes that there is only one value entry */
        Blob_Array< ValueEntry >& e_varray = e_val.get_array();
        ValueEntry ve;
        e_varray.get(0, ve, false);
        uint16_t blk_offset = (e_val_offset * m_vol_page_size) / HomeBlks::instance()->get_data_pagesz();
        Free_Blk_Entry fbe(ve.get_blkId(), ve.get_blk_offset() + blk_offset,
                           (m_vol_page_size / HomeBlks::instance()->get_data_pagesz()) * nlba);
        req->blkIds_to_free.emplace_back(fbe);

        replace_kv.emplace_back(
            make_pair(MappingKey(s_lba, nlba), MappingValue(new_val, new_val_offset, nlba, m_vol_page_size)));
    }

    /* add missing interval to replace kv */
    void add_new_interval(uint64_t s_lba, uint64_t e_lba, MappingValue& val, uint16_t lba_offset,
                          vector< pair< MappingKey, MappingValue > >& replace_kv) {
        auto nlba = e_lba - s_lba + 1;
        replace_kv.emplace_back(
            make_pair(MappingKey(s_lba, nlba), MappingValue(val, lba_offset, nlba, m_vol_page_size)));
    }

#ifndef NDEBUG

    void validate_get_response(uint64_t lba_start, uint32_t n_lba, vector< pair< MappingKey, MappingValue > >& values,
                               MappingValue* exp_value = nullptr, boost::intrusive_ptr< volume_req > req = nullptr) {
        uint32_t i = 0;
        uint64_t last_slba = lba_start;
        uint8_t last_bid_offset = 0;
        BlkId expBid;
        if (exp_value != nullptr) {
            ValueEntry ve;
            exp_value->get_array().get(0, ve, false);
            expBid = ve.get_blkId();
        }
        while (i < values.size()) {
            if (values[i].first.start() != last_slba) {
                m_bt->print_tree();
                std::this_thread::sleep_for(std::chrono::seconds(5));

                if (req) { // do it again to trace
                    vector< pair< MappingKey, MappingValue > > values;
                    auto temp = req->lastCommited_seqId;
                    req->lastCommited_seqId = req->seqId;
                    MappingKey key(lba_start, n_lba);
                    get(req, values);
                    req->lastCommited_seqId = temp;
                }

                assert(0); // gaps found
            }
            if (exp_value != nullptr) {
                ValueEntry ve;
                assert(values[i].second.get_array().get_total_elements() == 1);
                values[i].second.get_array().get(0, ve, false);

                if (!values[i].second.is_valid() || ve.get_blkId().get_id() != expBid.get_id() ||
                    ve.get_blk_offset() != last_bid_offset) {
                    m_bt->print_tree();
                    std::this_thread::sleep_for(std::chrono::seconds(10));
                    assert(0);
                }
                last_bid_offset +=
                    values[i].first.get_n_lba() * (m_vol_page_size / HomeBlks::instance()->get_data_pagesz());
            }
            last_slba = values[i].first.end() + 1;
            i++;
        }
        assert(last_slba == lba_start + n_lba);
    }

#endif
};
} // namespace homestore
