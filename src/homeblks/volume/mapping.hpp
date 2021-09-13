#pragma once

#include <array>
#include <cmath>
#include <csignal>
#include <cstring>
#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

#include <sds_logging/logging.h>
#include <sisl/utility/obj_life_counter.hpp>

#include "engine/blkalloc/blk.h"
#include "engine/common/error.h"
#include "engine/homeds/array/blob_array.h"
#include "engine/homeds/btree/btree.hpp"
#include "engine/homeds/btree/ssd_btree.hpp"
#include "engine/index/indx_mgr.hpp"
#include "homeblks/home_blks.hpp"

SDS_LOGGING_DECL(volume)

using namespace homeds;
using namespace homeds::btree;

typedef uint64_t lba_t;       // Type refers to both lba in entry and in volume layer
typedef uint32_t lba_count_t; // Type defining number of LBAs represented in volume layer

// Number of lbas in entry addressed at any point will never be more than what a blkid is addressed. In cases user
// IO lba count exceeds, it will be addressed as 2 different entries
typedef blk_count_t lba_entry_count_t;                 // Type refers to num lbas in mapping entry
typedef blk_count_serialized_t lba_count_serialized_t; // Type refers to num lbas when

#define LBA_MASK 0xFFFFFFFFFFFF
constexpr size_t CS_ARRAY_STACK_SIZE{256}; // equals 2^N_LBA_BITS //TODO - put static assert
namespace homestore {
struct volume_req;

enum op_type {
    UPDATE_VAL_ONLY = 0,      // it only update the value
    UPDATE_VAL_AND_FREE_BLKS, // it update the value and also update the free blks
    READ_VAL_WITH_seqid,
    FREE_ALL_USER_BLKID,
    READ_VAL,
    UPDATE_OOB_UNMAP
};

// std::variant
struct mapping_op_cntx {
    op_type op = UPDATE_VAL_ONLY;
    volume_req* vreq;
    sisl::ThreadVector< BlkId >* free_list;
    int64_t seqid = INVALID_SEQ_ID;
    uint64_t free_blk_size = 0;
    bool force = false;
};

struct LbaId {
public:
    LbaId() : m_lba_start{0} {}
    LbaId(const LbaId& other) : m_lba_start{other.m_lba_start}, m_n_lba{other.m_n_lba} {}
    // LbaId(const uint64_t lba_id_integer) { LbaId(lba_id_integer & LBA_MASK, lba_id_integer >> LBA_BITS); }
    LbaId(const lba_t lba_start, const lba_count_t n_lbas) { set(lba_start, n_lbas); }

    void set(const lba_t lba_start, const lba_count_t n_lbas) {
        set_lba_start(lba_start);
        set_nlbas(n_lbas);
    }

    void set_lba_start(const lba_t lba) {
        HS_DEBUG_ASSERT_LE(lba, max_lba_possible());
        m_lba_start = lba;
    }
    [[nodiscard]] lba_t get_lba_start() const { return m_lba_start; }

    void set_nlbas(const lba_count_t nlbas) {
        HS_DEBUG_ASSERT_LE(nlbas, LbaId::max_lba_count_possible());
        HS_DEBUG_ASSERT_LE((m_lba_start + nlbas - 1), LbaId::max_lba_possible());
        m_n_lba = static_cast< lba_count_serialized_t >(nlbas - 1);
    }
    [[nodiscard]] lba_count_t get_nlbas() const { return static_cast< lba_count_t >(m_n_lba) + 1; }

    static constexpr lba_t max_lba_count_possible() { return (1 << NBLKS_BITS); }
    static constexpr lba_t max_lba_possible() { return (1ul << LBA_BITS) - 1; }

    lba_t end() const { return m_lba_start + get_nlbas() - 1; }
    bool is_invalid() const { return m_lba_start == 0; }

private:
    // size of lba start and num of lba can be reduced for future use
    uint64_t m_lba_start : LBA_BITS; // start of lba range
    uint64_t m_n_lba : NBLKS_BITS;   // number of lba's from start(inclusive)
} __attribute__((__packed__));

// MappingKey is fixed size
class MappingKey : public homeds::btree::ExtentBtreeKey, public sisl::ObjLifeCounter< MappingKey > {
    LbaId m_lbaId;

public:
    MappingKey() : ObjLifeCounter() {}

    MappingKey(const MappingKey& other) : ExtentBtreeKey(), ObjLifeCounter(), m_lbaId(other.get_lbaId()) {}

    MappingKey(const lba_t lba_start, const lba_count_t n_lba) : ObjLifeCounter(), m_lbaId{lba_start, n_lba} {}

    const LbaId& get_lbaId() const { return m_lbaId; }
    lba_t start() const { return m_lbaId.get_lba_start(); }
    lba_t end() const { return start() + get_n_lba() - 1; }
    lba_count_t get_n_lba() const { return m_lbaId.get_nlbas(); }

    /* used by btree to compare the end key of input with end key
     * It return the result of
     *                 *(this) - *(input)
     */
    int compare_end(const BtreeKey* input) const override {
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
    int compare_start(const BtreeKey* input) const override {
        MappingKey* o = (MappingKey*)input;
        if (end() > o->start())
            return 1; // go left
        else if (end() < o->start())
            return -1; // go right
        else
            return 0; // overlap
    }

    bool preceeds(const BtreeKey* k) const override {
        MappingKey* o = (MappingKey*)k;
        if (end() < o->start()) { return true; }

        return false;
    }

    bool succeeds(const BtreeKey* k) const override {
        MappingKey* o = (MappingKey*)k;
        if (o->end() < start()) { return true; }

        return false;
    }

    sisl::blob get_blob() const override {
        return {reinterpret_cast< uint8_t* >(const_cast< LbaId* >(&m_lbaId)), get_fixed_size()};
    }

    void set_blob(const sisl::blob& b) override {
        assert(b.size == get_fixed_size());
        const LbaId* const other{reinterpret_cast< const LbaId* >(b.bytes)};
        set(other->get_lba_start(), other->get_nlbas());
    }

    void copy_blob(const sisl::blob& b) override { set_blob(b); }

    void copy_end_key_blob(const sisl::blob& b) override {
        assert(b.size == get_fixed_size());
        const LbaId* const other{reinterpret_cast< const LbaId* >(b.bytes)};
        set(other->end(), 1);
    }

    void set(const lba_t lba_start, const blk_count_t n_lba) { m_lbaId.set(lba_start, n_lba); }

    uint32_t get_blob_size() const override { return get_fixed_size(); }
    void set_blob_size(uint32_t size) override { assert(false); }

    string to_string() const override { return fmt::format("[{}-{}]", start(), end()); }

    lba_count_t get_nlbas(const lba_t end_lba, const lba_t start_lba) const {
        assert((end_lba - start_lba) < BlkId::max_blks_in_op());
        return (end_lba - start_lba + 1);
    }

    void get_overlap(const lba_t lba_start, const lba_t lba_end, MappingKey& overlap) const {
        const auto start_lba = std::max(start(), lba_start);
        const auto end_lba = std::min(end(), lba_end);
        overlap.set(start_lba, get_nlbas(end_lba, start_lba));
    }

    // returns difference in start lba
    lba_t get_start_offset(const MappingKey& other) const { return start() - other.start(); }

    static uint32_t get_fixed_size() { return sizeof(LbaId); }

    friend ostream& operator<<(ostream& os, const MappingKey& k) {
        os << k.to_string();
        return os;
    }

} __attribute__((__packed__));

struct ValueEntry {
    friend class MappingValue;
    friend class Blob_Array;

private:
    seq_id_t m_seqid{0};
    BlkId m_blkid;
    blk_count_serialized_t m_lba_offset{0}; // lba offset within the blkid
    blk_count_serialized_t m_nlbas{0};      // Number of blkids within the view
    csum_t m_carr[0];                       // Array holding the checksums

private:
    ValueEntry() = default;
    ValueEntry(const seq_id_t seqid, const BlkId& blkid, const lba_count_t lba_offset, const lba_count_t nlbas,
               const csum_t* carr) :
            m_seqid{seqid}, m_blkid{blkid} {
        set_lba_offset(lba_offset);
        set_num_lbas(nlbas);
        if (carr && m_blkid.is_valid()) { ::memcpy(&m_carr[0], &carr[0], (nlbas * sizeof(csum_t))); }
    }
    ValueEntry(const ValueEntry& ve) { copy_from(ve); }
    ValueEntry(const ValueEntry& ve, const lba_count_t lba_offset, const lba_count_t nlbas) {
        copy_from_with_offset(ve, lba_offset, nlbas);
    }

public:
    static uint32_t size(const lba_count_t nlbas) { return (sizeof(ValueEntry) + (sizeof(csum_t) * nlbas)); }
    static uint32_t invalid_blkid_size(const lba_count_t nlbas) { return (sizeof(ValueEntry)); }

    [[nodiscard]] uint32_t size() const { return size(get_num_lbas()); }
    [[nodiscard]] uint32_t get_blob_size() const { return size(); }
    [[nodiscard]] sisl::blob get_blob() const { return {(uint8_t*)this, get_blob_size()}; }

    /* Getters and Setters for meta params */
    void set_seq_id(const seq_id_t seq_id) { m_seqid = seq_id; }
    seq_id_t get_seqid() const { return m_seqid; }

    void set_blkid(const BlkId& blkid) { m_blkid = blkid; }
    BlkId get_base_blkid() const { return m_blkid; }

    void set_lba_offset(const lba_count_t offset) {
        HS_DEBUG_ASSERT_LT(offset, BlkId::max_blks_in_op());
        m_lba_offset = static_cast< blk_count_serialized_t >(offset);
    }
    lba_count_t get_lba_offset() const { return static_cast< lba_count_t >(m_lba_offset); }
    blk_count_t get_blk_offset(const uint32_t blks_per_lba) const {
        return static_cast< blk_count_t >(get_lba_offset() * blks_per_lba);
    }

    void set_num_lbas(const lba_count_t nlbas) {
        HS_DEBUG_ASSERT_LE(nlbas, BlkId::max_blks_in_op());
        // HS_DEBUG_ASSERT_EQ(get_blkid().is_valid(), true);
        m_nlbas = static_cast< blk_count_serialized_t >(nlbas - 1);
    }
    lba_count_t get_num_lbas() const { return static_cast< lba_count_t >(m_nlbas) + 1; }
    blk_count_t get_num_blks(const uint32_t blks_per_lba) const {
        return static_cast< blk_count_t >(get_num_lbas() * blks_per_lba);
    }

#if 0
        // this allocates 2^NBLKS_BITS size array for checksum on stack, however actual memory used is less on bnode
        // as we call get_blob_size which takes into account actual nlbas to determine exact size of checksum array
        // TODO - can be replaced by thread local buffer in future
        std::array< csum_t, BlkId::max_blks_in_op() > m_carr;
#endif

    void copy_blob(const sisl::blob& b) {
        const ValueEntry* other = (const ValueEntry*)b.bytes;
        copy_from(*other);
    }

    void add_offset(const lba_count_t lba_offset, const lba_count_t nlbas) {
        // move checksum array elements to start from offset position
        // assert(lba_offset < get_num_lbas());
        HS_DEBUG_ASSERT_LT(get_lba_offset() + lba_offset, BlkId::max_blks_in_op());
        if (m_blkid.is_valid()) { ::memmove((void*)&m_carr[0], (void*)&m_carr[lba_offset], (nlbas * sizeof(csum_t))); }
        set_num_lbas(nlbas);
        set_lba_offset(get_lba_offset() + lba_offset);
    }

    BlkId get_offset_blkid(const uint32_t blks_per_lba) const {
        BlkId ret;
        BlkId base_blkid = get_base_blkid();
        ret.set_blk_num(base_blkid.get_blk_num() + get_blk_offset(blks_per_lba));
        ret.set_nblks(get_num_blks(blks_per_lba));
        ret.set_chunk_num(base_blkid.get_chunk_num());
        return ret;
    }

    csum_t get_checksum_at(const lba_count_t index) const {
        assert(index < get_num_lbas());
        return m_carr[index];
    }

    int compare(const ValueEntry* other) const {
        if (get_seqid() == other->get_seqid()) {
            return 0;
        } else if (get_seqid() < other->get_seqid()) {
            return 1; // other is higher
        } else {
            return -1; // other is lower
        }
    }

    std::string get_checksums_string() const {
        std::string str;
        if (!m_blkid.is_valid()) { return str; }
        for (lba_count_t i{0}; i < get_num_lbas(); ++i) {
            fmt::format_to(std::back_inserter(str), "{},", get_checksum_at(i));
        }
        return str;
    }

    std::string to_string() const {
        std::string str = fmt::format("seq_id={} BaseBlk=[{}] lba_off={} nlbas={}", get_seqid(), get_base_blkid(),
                                      get_lba_offset(), get_num_lbas());
        if (HomeBlks::instance()->print_checksum()) {
            fmt::format_to(std::back_inserter(str), " cs=[{}]", get_checksums_string());
        }
        return str;
    }

    friend ostream& operator<<(ostream& os, const ValueEntry& ve) {
        os << ve.to_string();
        return os;
    }

private:
    void copy_from(const ValueEntry& other) {
        copy_from_with_offset(other, other.get_lba_offset(), other.get_num_lbas());
    }

    void copy_from_with_offset(const ValueEntry& other, const lba_count_t lba_offset, const lba_count_t nlbas) {
        HS_DEBUG_ASSERT_LE(nlbas, BlkId::max_blks_in_op());
        HS_DEBUG_ASSERT_LE(nlbas, other.get_num_lbas());
        HS_DEBUG_ASSERT_LT(lba_offset, other.get_num_lbas());

        m_seqid = other.m_seqid;
        m_blkid = other.m_blkid;
        set_lba_offset(lba_offset);
        set_num_lbas(nlbas);
        if (m_blkid.is_valid()) {
            ::memcpy((void*)&m_carr[0], (void*)&other.m_carr[lba_offset], (nlbas * sizeof(csum_t)));
        }
    }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Waddress-of-packed-member"
    const csum_t* get_checksum_array_const() const { return get_num_lbas() ? &m_carr[0] : nullptr; }
    csum_t* get_checksum_array() { return get_num_lbas() ? &m_carr[0] : nullptr; }
    const csum_t* get_checksum_array_from_const(const lba_count_t n) const {
        return (n < get_num_lbas()) ? &m_carr[n] : nullptr;
    }
#pragma GCC diagnostic pop

} __attribute__((__packed__));

class MappingValue : public homeds::btree::BtreeValue, public sisl::ObjLifeCounter< MappingValue > {
    Blob_Array< ValueEntry > m_earr;

public:
    // creates empty array
    MappingValue() : ObjLifeCounter(){};

    // creates array with one value entry - on heap, does copy. Initializes the value entry with all these params
    MappingValue(const seq_id_t seqid, const BlkId& blkid, const lba_count_t lba_offset, const lba_count_t nlbas,
                 const csum_t* carr) :
            ObjLifeCounter() {
        if (blkid.is_valid()) {
            m_earr.alloc_element(ValueEntry::size(nlbas), seqid, blkid, lba_offset, nlbas, carr);
        } else {
            m_earr.alloc_element(ValueEntry::invalid_blkid_size(nlbas), seqid, blkid, lba_offset, nlbas, carr);
        }
    }

    // Creates one entry but without any offset information.
    MappingValue(const seq_id_t seqid, const BlkId& blkid) : MappingValue(seqid, blkid, 0u, 0u, nullptr) {}

    // Creates one value entry as specified by the ve
    MappingValue(const ValueEntry& ve) :
            MappingValue(ve.get_seqid(), ve.get_base_blkid(), ve.get_lba_offset(), ve.get_num_lbas(),
                         ve.get_checksum_array_const()) {}

    // Creates one value entry as specified by the ve, from specific offline in ve
    MappingValue(const ValueEntry& ve, const lba_count_t offset, const lba_count_t nlbas) :
            MappingValue(ve.get_seqid(), ve.get_base_blkid(), ve.get_lba_offset() + offset, nlbas,
                         ve.get_checksum_array_from_const(offset)) {
        HS_DEBUG_ASSERT_LT(offset, ve.get_num_lbas());
        HS_DEBUG_ASSERT_LE(offset + nlbas, ve.get_num_lbas());
    }

    // performs deep copy from other - on heap
    MappingValue(const MappingValue& other) : ObjLifeCounter() { m_earr.set_elements(other.m_earr); }

    // creates array with  value entrys - on heap -bcopy
    // MappingValue(const std::vector< ValueEntry* >& elements) : ObjLifeCounter() { m_earr.set_elements(elements); }

    // performs deep copy from other - on heap and also set the offset and number of lbas

    MappingValue(volume_req* req, const MappingValue& one, const blk_count_t one_offset, const MappingValue& second,
                 const blk_count_t second_offset) {
        assert(false);
    }

    /******************* Entry Related Section ******************/
    // Extract the specific indexed entry and create a MappingValue out of it
    MappingValue extract(const lba_count_t indx) const {
        const ValueEntry* ve = get_nth_entry(indx);
        return MappingValue{*ve};
    }

    ValueEntry* get_nth_entry(const lba_count_t idx) const { return m_earr.get(idx); }
    ValueEntry* get_latest_entry() const {
        HS_DEBUG_ASSERT_EQ(get_total_entries(), 1, "Number of value entries is expected to be 1");
        return get_nth_entry(0);
    }
    bool is_valid() const { return (m_earr.get_total_elements() != 0); }
    uint32_t get_total_entries() const { return m_earr.get_total_elements(); }

    // ValueEntry get_nth_entry(const lba_count_t idx, bool copy_entry) const { return m_earr.get(idx, copy_entry); }

    /******************* Member access Related Section ******************/
    lba_t get_nlbas(const lba_t end_lba, const lba_t start_lba) const { return (end_lba - start_lba + 1); }

    void get_overlap_diff_kvs(MappingKey* k1, MappingValue* v1, MappingKey* k2, MappingValue* v2,
                              uint32_t vol_page_size, diff_read_next_t& to_read,
                              std::vector< std::pair< MappingKey, MappingValue > >& overlap_kvs) {
        static MappingKey k;
        static MappingValue v;

        lba_t start, k1_offset = 0, k2_offset = 0;
        lba_t nlba = 0, ovr_nlba = 0;

        /* Non-overlapping beginning part */
        if (k1->start() < k2->start()) {
            nlba = k2->start() - k1->start();
            k.set(k1->start(), nlba);
            v = *v1;
            v.add_offset(0, nlba);
            overlap_kvs.emplace_back(make_pair(k, v));
            k1_offset += nlba;
            start = k1->start() + nlba;
        } else if (k2->start() < k1->start()) {
            nlba = k1->start() - k2->start();
            k.set(k2->start(), nlba);
            v = *v2;
            v.add_offset(0, nlba);
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
            v.add_offset(k1_offset, ovr_nlba);
            k1_offset += ovr_nlba;
        } else {
            v = *v2;
            v.add_offset(k2_offset, ovr_nlba);
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
            v2->add_offset(k2_offset, nlba);
            to_read = READ_FIRST;
        } else {
            /* k1 has tail part */
            nlba = get_nlbas(k1->end(), start);
            k1->set(start, nlba);
            v1->add_offset(k1_offset, nlba);
            to_read = READ_SECOND;
        }
    }

    // add offset to all entries - no copy, in place
    void add_offset(const lba_count_t lba_offset, const lba_count_t nlba) {
        for (lba_count_t j{0}; j < m_earr.get_total_elements(); ++j) {
            ValueEntry* ve = get_nth_entry(j);
            ve->add_offset(lba_offset, nlba);
        }
    }

    /* true if my value is newer than other */
    bool is_new(const MappingValue& other) const {
        /* all mapping value entries have same seqid */
        const std::vector< ValueEntry* > my_v_array = m_earr.get_all();
        const std::vector< ValueEntry* > other_v_array = other.m_earr.get_all();

        /* If other size is 0, my value is always new */
        if (other_v_array.size() <= 0) { return true; }

        /* If other size is not 0 and my value is 0, my value is old */
        if (my_v_array.size() <= 0) { return false; }

        /* If other seqid is invalid, my value is new */
        if (other_v_array[0]->get_seqid() == INVALID_SEQ_ID) { return true; }

        /* If my seqid is invalid and other is not, my value is old */
        if (my_v_array[0]->get_seqid() == INVALID_SEQ_ID) { return false; }

        /* If my value is greater than other, my value is new */
        if (my_v_array[0]->compare(other_v_array[0]) > 0) { return true; }

        return false;
    }

    // insert entry to this mapping value, maintaing it sorted by seqid - deep copy
    void add_copy(ValueEntry* ve, MappingValue& out) const {
        std::vector< ValueEntry* > v_array = m_earr.get_all();
        auto i = 0u;
        if (v_array.size() > 0) {
            while (i < v_array.size() && v_array[i]->compare(ve) > 0) {
                ++i;
            }
            if (i < v_array.size() && v_array[i]->compare(ve) == 0) {
                /* every sequence ID is invalid until journaling comes */
                assert(ve->get_seqid() == INVALID_SEQ_ID);
                ++i;
            }
        }
        v_array.insert(v_array.begin() + i, ve);
        out.m_earr.set_elements(v_array);
    }

    /******************* Blob Related Section ******************/
    void set_blob(const sisl::blob& b) override { m_earr.set_mem((void*)(b.bytes), b.size); }
    void copy_blob(const sisl::blob& b) override {
        Blob_Array< ValueEntry > other;
        other.set_mem((void*)b.bytes, b.size);
        m_earr.set_elements(other); // deep copy
    }

    sisl::blob get_blob() const override {
        sisl::blob b;
        b.bytes = (uint8_t*)m_earr.get_mem();
        b.size = m_earr.get_size();
        return b;
    }
    uint32_t get_blob_size() const override { return m_earr.get_size(); }
    void set_blob_size(uint32_t size) override { assert(false); }
    uint32_t estimate_size_after_append(const BtreeValue& new_val) override {
        assert(false);
        return 0;
    }

    void append_blob(const BtreeValue& new_val, BtreeValue& existing_val) override { assert(false); }
    std::string to_string() const override { return m_earr.to_string(); }
    // TODO: Do we really need to add sizeof(ValueEntry)
    uint32_t meta_size() const { return sizeof(ValueEntry) + m_earr.get_meta_size(); }

#if 0
        const Blob_Array< ValueEntry >& get_array_const() const { return m_earr; }
        Blob_Array< ValueEntry >& get_array() { return m_earr; }

        uint32_t meta_size() const { return sizeof(ValueEntryMeta) + m_earr.get_meta_size(); }
#endif

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
                    Free_Blk_Entry fbe(ve.get_blkId(), ve.get_lba_offset(),
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
    lba_count_t m_blks_per_lba;
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
        lba_t m_start_lba;
        MappingValue* m_value;

        UpdateCBParam(mapping_op_cntx& cntx, MappingKey& new_key, MappingValue& new_value) :
                BRangeCBParam(), m_cntx{&cntx}, m_start_lba{new_key.start()}, m_value{&new_value} {};
        MappingValue& get_new_value() { return *m_value; }
    };

public:
    mapping(const uint64_t volsize, const uint32_t page_size, const std::string& unique_name,
            const trigger_cp_callback& trigger_cp_cb, const pending_read_blk_cb& pending_read_cb = nullptr);
    mapping(const uint64_t volsize, uint32_t page_size, const std::string& unique_name,
            const btree_super_block& btree_sb, const trigger_cp_callback& trigger_cp_cb,
            const pending_read_blk_cb& pending_read_cb = nullptr, btree_cp_sb* btree_cp_sb = nullptr);
    virtual ~mapping();
    int sweep_alloc_blks(const lba_t start_lba, const lba_t end_lba);
    btree_status_t get(volume_req* req, std::vector< std::pair< MappingKey, MappingValue > >& values);
    btree_status_t get(MappingKey& key, BtreeQueryCursor& cur,
                       std::vector< std::pair< MappingKey, MappingValue > >& values);
    btree_status_t get(mapping_op_cntx& cntx, MappingKey& key, BtreeQueryCursor& cur,
                       std::vector< std::pair< MappingKey, MappingValue > >& values);
    /* Note :- we should not write same IO in btree multiple times. When a key is updated , it update the free blk
     * entries in request to its last value. If we write same io multiple times then it could end up freeing the
     * wrong blocks.
     * @cur :- if multiple calls made for the same key then it points to first lba which is not written.
     */
    btree_status_t put(mapping_op_cntx& cntx, MappingKey& key, MappingValue& value, const btree_cp_ptr& cp_id,
                       BtreeQueryCursor& cur);
    virtual uint64_t get_btree_node_cnt();

    void print_tree();
    bool verify_tree(bool update_debug_bm);
    nlohmann::json get_status(const int log_level);

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
    bool fix(const btree_cp_ptr& bcp, const lba_t start_lba, const lba_t end_lba, bool verify = false);

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
    bool verify_fixed_bt(const lba_t start_lba, const lba_t end_lba, MappingBtreeDeclType* old_bt,
                         MappingBtreeDeclType* new_bt);
    void print_kv(const std::vector< std::pair< MappingKey, MappingValue > >& kvs) const;

    void print_node(const bnodeid_t& blkid);

    blk_count_t nlbas_to_nblks(const lba_count_t nlbas) const {
        return static_cast< blk_count_t >(nlbas * (m_vol_page_size / HomeBlks::instance()->get_data_pagesz()));
    }

    lba_count_t nblks_to_nlbas(const blk_count_t nblks) const {
        return nblks / (m_vol_page_size / HomeBlks::instance()->get_data_pagesz());
    }

    blk_count_t blks_per_lba() const { return nlbas_to_nblks(1u); }

public:
    /* virtual functions required by indx tbl */

    void create_done() override;
    uint64_t get_used_size() const override;
    btree_super_block get_btree_sb() override;

    /* It attaches the new CP and prepare for cur cp flush */
    btree_cp_ptr attach_prepare_cp(const btree_cp_ptr& cur_bcp, bool is_last_cp, bool blkalloc_checkpoint) override;

    void cp_start(const btree_cp_ptr& bcp, cp_comp_callback cb) override;

    void truncate(const btree_cp_ptr& bcp) override;
    void destroy_done() override;
    void update_btree_cp_sb(const btree_cp_ptr& bcp, btree_cp_sb& btree_sb, bool is_blkalloc_cp) override;
    void flush_free_blks(const btree_cp_ptr& bcp, std::shared_ptr< homestore::blkalloc_cp >& ba_cp) override;
    /* it populats the allocated blkids in index req. It might not be the same as in volume req if entry is
     * partially written.
     */
    void update_indx_alloc_blkids(const indx_req_ptr& ireq) override;
    btree_status_t update_diff_indx_tbl(const indx_req_ptr& ireq, const btree_cp_ptr& bcp) override;

    btree_status_t update_active_indx_tbl(const indx_req_ptr& ireq, const btree_cp_ptr& bcp) override;
    btree_status_t recovery_update(logstore_seq_num_t seqnum, journal_hdr* hdr, const btree_cp_ptr& bcp) override;
    btree_status_t free_user_blkids(blkid_list_ptr free_list, BtreeQueryCursor& cur, int64_t& size) override;
    void get_btreequery_cur(const sisl::blob& b, BtreeQueryCursor& cur) override;
    btree_status_t destroy(blkid_list_ptr& free_blkid_list, uint64_t& free_node_cnt) override;
    btree_status_t read_indx(const indx_req_ptr& ireq, const read_indx_comp_cb_t& read_cb) override;
    btree_status_t update_oob_unmap_active_indx_tbl(blkid_list_ptr free_list, const int64_t seq_id, void* key,
                                                    BtreeQueryCursor& cur, const btree_cp_ptr& bcp, int64_t& size,
                                                    const bool force) override;
    std::string get_cp_flush_status(const btree_cp_ptr& bcp) override;

public:
    /* static functions */
    static lba_t get_end_lba(const lba_t start_lba, const lba_count_t nlba);
    static lba_count_t get_nlbas(const lba_t end_lba, const lba_t start_lba);
    // static uint64_t get_blkid_offset(uint64_t lba_offset, uint64_t vol_page_size);
    static lba_t get_next_start_lba(const lba_t start_lba, const lba_count_t nlba);
    static lba_count_t get_nlbas_from_cursor(const lba_t start_lba, const BtreeQueryCursor& cur);
    static lba_t get_next_start_key_from_cursor(const BtreeQueryCursor& cur);
    static lba_t get_end_key_from_cursor(const BtreeQueryCursor& cur);

private:
    /* It split a key and value.
     * @key :- Split this key into two
     * @value :- split this value as per the key
     * @split_key :- key should be split around split_key
     * @replace_kv :- add the split keys and values in replace_kv
     */
    void split_key_recovery(const MappingKey& key, const MappingValue& val, const MappingKey& split_key,
                            std::vector< std::pair< MappingKey, MappingValue > >& replace_kv);
    btree_status_t update_indx_tbl(const indx_req_ptr& ireq, const btree_cp_ptr& bcp,
                                   const bool active_btree_update = true);
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
    lba_count_t compute_val_offset(BRangeCBParam* cb_param, const lba_t start_lba);

    uint32_t get_size_needed(const std::vector< std::pair< MappingKey, MappingValue > >& match_kv,
                             BRangeCBParam* cb_param) const;

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
    std::pair< lba_t, lba_t > get_start_end_lba(BtreeSearchRange& subrange);

    /* result of overlap of k1/k2 is added to replace_kv */
    void compute_and_add_overlap(std::vector< Free_Blk_Entry >& fbe_list, lba_t s_lba, const lba_t e_lba,
                                 const MappingValue& new_val, lba_count_t new_val_offset, MappingValue& e_val,
                                 const lba_count_t e_val_offset,
                                 std::vector< std::pair< MappingKey, MappingValue > >& replace_kv, int64_t new_seq_id);

    /* add missing interval to replace kv */
    void add_new_interval(const lba_t s_lba, const lba_t e_lba, const MappingValue& val, const lba_count_t lba_offset,
                          std::vector< std::pair< MappingKey, MappingValue > >& replace_kv);
    btree_status_t unmap_recovery_update(logstore_seq_num_t seqnum, journal_hdr* hdr, const btree_cp_ptr& bcp);

#ifndef NDEBUG
    void validate_get_response(const lba_t lba_start, const lba_count_t n_lba,
                               std::vector< std::pair< MappingKey, MappingValue > >& values,
                               MappingValue* exp_value = nullptr, volume_req* req = nullptr);
#endif
};
} // namespace homestore
