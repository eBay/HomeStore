#ifndef _MAPPING_HPP_
#define _MAPPING_HPP_

#include "blkstore/writeBack_cache.hpp"
#include "homeds/btree/ssd_btree.hpp"
#include "homeds/btree/btree.hpp"
#include <blkalloc/blk.h>
#include <csignal>
#include <error/error.h>
#include "homeds/array/interval_array.h"
#include <math.h>
#include <sds_logging/logging.h>
#include <volume/volume.hpp>

using namespace std;
using namespace homeds::btree;

namespace homestore {

/* TODO: it will require some changes to create the btree for correct page size */
#define MAX_INTERVAL_LENGTH_IN_BITS 8
#define Interval_Array_Impl Interval_Array<MappingInterval, 80, 20 >

    // MappingInterval represents single interval inside value interval array
struct MappingInterval : public Interval<MAX_INTERVAL_LENGTH_IN_BITS> {

    struct Value {
        uint16_t m_blkid_offset:MAX_INTERVAL_LENGTH_IN_BITS;
        struct BlkId m_blkid;

        Value() : m_blkid_offset(0), m_blkid(BlkId(0)) {}

        Value(const Value &other) {
            m_blkid_offset = other.m_blkid_offset;
            m_blkid = other.m_blkid;
        }

        Value(uint16_t m_blkid_offset, const BlkId &m_blkid) : m_blkid_offset(m_blkid_offset), m_blkid(m_blkid) {}

        void add(uint64_t offset) {
            this->m_blkid_offset += offset;
        }
    }__attribute__ ((__packed__));

    Value m_value;

    MappingInterval() : MappingInterval(0, 0, Value()) {
    }

    MappingInterval(const MappingInterval &other) :
            MappingInterval(other.m_interval_start, other.m_interval_length,
                            other.m_value) {
    }

    MappingInterval(uint64_t interval_start,
                    uint64_t interval_length,
                    Value other) {
        m_interval_start = interval_start;
        m_interval_length = interval_length;
        m_value.m_blkid_offset = other.m_blkid_offset;
        m_value.m_blkid = other.m_blkid;
    }


    void merge_compare(MappingInterval *&intervalFirst, MappingInterval *&intervalSecond,
                       std::shared_ptr<MappingInterval> &merged_interval,
                       bool &is_intervals_mergable) /*override*/ {
        //DISABLING MERGE AS NOT COMPATIBLE WITH CACHE
        is_intervals_mergable = false;
        merged_interval = nullptr;
    }

    operator std::string() { return to_string(); }

    std::string to_string() {
        std::stringstream ss;
        ss << m_interval_start << "," << m_interval_length << "," << m_value.m_blkid_offset << "--->"
           << m_value.m_blkid.to_string();
        return ss.str();
    };

}__attribute__ ((__packed__));

    // Purpose of lba_block structure is transfer of mapping from mapping layer to volume layer                                
struct Lba_Block : public MappingInterval {
    uint64_t m_actual_lba;
    bool m_blkid_found;

    Lba_Block(const MappingInterval &mapping, uint64_t actual_lba, bool blkid_found) {
        m_interval_start = mapping.m_interval_start;
        m_interval_length = mapping.m_interval_length;
        m_value.m_blkid_offset = mapping.m_value.m_blkid_offset;
        m_value.m_blkid = mapping.m_value.m_blkid;
        m_blkid_found = blkid_found;
        m_actual_lba = actual_lba;
    }

    Lba_Block(uint16_t offset,
              uint16_t num_of_offset,
              uint16_t blkid_offset,
              struct BlkId blkid,
              uint64_t actual_lba,
              bool blkid_found) {
        m_interval_start = offset;
        m_interval_length = num_of_offset;
        m_value.m_blkid_offset = blkid_offset;
        m_value.m_blkid = blkid;
        m_blkid_found = blkid_found;
        m_actual_lba = actual_lba;
    };

}__attribute__ ((__packed__));

constexpr static auto Ki = 1024;
constexpr static auto Mi = Ki * Ki;
constexpr static auto Gi = Ki * Mi;
constexpr static auto MAX_CACHE_SIZE = 2ul * Gi;
constexpr static int MAP_BLOCK_SIZE = (4 * Ki);
constexpr static int LEAST_NO_OF_OBJECTS_IN_NODE = 3;
constexpr static int RECORD_SIZE = sizeof(uint32_t);
constexpr static int KEY_SIZE = sizeof(uint64_t);
constexpr static int VALUE_HEADER_SIZE = sizeof(uint32_t);
constexpr static int VALUE_ENTRY_SIZE = sizeof(struct MappingInterval);
constexpr static int MAX_NO_OF_VALUE_ENTRIES =
        -1 + (MAP_BLOCK_SIZE - LEAST_NO_OF_OBJECTS_IN_NODE * RECORD_SIZE - LEAST_NO_OF_OBJECTS_IN_NODE * KEY_SIZE) /
             (VALUE_HEADER_SIZE + LEAST_NO_OF_OBJECTS_IN_NODE * VALUE_ENTRY_SIZE);
constexpr static int BIT_TO_REPRESENT_MAX_ENTRIES = MAX_INTERVAL_LENGTH_IN_BITS;


class MappingKey : public homeds::btree::BtreeKey {

private:
    //Actual value range for an key is (range_start_offset*MAX_NO_OF_VALUE_ENTRIES,
    // range_start_offset*MAX_NO_OF_VALUE_ENTRIES + MAX_NO_OF_VALUE_ENTRIES -1)
    uint64_t range_start_offset;
    uint64_t *ptr_range_start_offset;
public:
    MappingKey() {
        range_start_offset = 0;
        ptr_range_start_offset = &range_start_offset;
    }

    MappingKey(uint64_t _blob) {
        range_start_offset = _blob;
        ptr_range_start_offset = &range_start_offset;
    }

    explicit MappingKey(const MappingKey& other) = default;
    MappingKey& operator=(const MappingKey& other) = default;

    int compare(const BtreeKey *o) const override {
        MappingKey *key = (MappingKey *) o;
        if (*ptr_range_start_offset < *key->ptr_range_start_offset) {
            return -1;
        } else if (*ptr_range_start_offset > *key->ptr_range_start_offset) {
            return 1;
        } else {
            return 0;
        }
    }

    virtual homeds::blob get_blob() const override {
        homeds::blob b = {(uint8_t *) ptr_range_start_offset, sizeof(range_start_offset)};
        return b;
    }

    virtual void set_blob(const homeds::blob &b) override {
        ptr_range_start_offset = (uint64_t *) b.bytes;
    }

    virtual void copy_blob(const homeds::blob &b) override {
        assert(b.size == sizeof(range_start_offset));
        memcpy(ptr_range_start_offset, b.bytes, b.size);
    }

    virtual uint32_t get_blob_size() const override {
        return (sizeof(range_start_offset));
    }

    virtual void set_blob_size(uint32_t size) override {
    }

    static uint32_t get_fixed_size() {
        return sizeof(range_start_offset);
    }

    uint64_t get_value() {
        return range_start_offset;
    }

    int compare_range(const BtreeSearchRange &range) const override {
        return 0;
    }

    std::string to_string() const override {
        return (std::to_string(*ptr_range_start_offset));
    }
};

class MappingValue : public homeds::btree::BtreeValue {
    Interval_Array_Impl *dyna_arr;
public:
    MappingValue() {
        dyna_arr = new Interval_Array_Impl(5, MAX_NO_OF_VALUE_ENTRIES);
    };

    MappingValue(uint16_t offset, uint64_t no_of_offset, uint16_t block_offset, struct BlkId blockId) :
            homeds::btree::BtreeValue() {
        dyna_arr = new Interval_Array_Impl(5, MAX_NO_OF_VALUE_ENTRIES);
        MappingInterval mappingInterval(offset, no_of_offset, MappingInterval::Value(block_offset, blockId));
        std::vector<std::shared_ptr<MappingInterval> > existingIntervalOverlaps;
        dyna_arr->addInterval(&mappingInterval, existingIntervalOverlaps);
    };

    ~MappingValue() {
        delete dyna_arr;
        dyna_arr = nullptr;
    };

    explicit MappingValue(const MappingValue& other) = default;
    MappingValue& operator=(const MappingValue& other) = default;

    virtual homeds::blob get_blob() const override {
        homeds::blob b;
        b.bytes = (uint8_t *) dyna_arr->get_mem();
        b.size = dyna_arr->get_size();
        return b;
    }

    virtual void set_blob(const homeds::blob &b) override {
        dyna_arr->set_mem((void *) (b.bytes), b.size, MAX_NO_OF_VALUE_ENTRIES);
    }

    virtual void copy_blob(const homeds::blob &b) override {
        delete dyna_arr;
        dyna_arr = new Interval_Array_Impl((void *) b.bytes, b.size, MAX_NO_OF_VALUE_ENTRIES);
    }

    virtual uint32_t get_blob_size() const override {
        return dyna_arr->get_size();
    }

    virtual void set_blob_size(uint32_t size) override {
        assert(0);
    }

    virtual uint32_t estimate_size_after_append(const BtreeValue &new_val) override {
        Interval_Array_Impl *dyna_arr_ptr = ((const MappingValue &) new_val).dyna_arr;
        assert(dyna_arr_ptr->get_no_of_elements_filled() == 1);
        return dyna_arr->estimate_size_after_addOrUpdate(1);
    }

    void get(uint16_t start_offset, uint16_t end_offset,
             std::vector<std::shared_ptr<MappingInterval>> &offsetToBlkIdLst) {
        LOGTRACE("value.get called with :{}:{}", start_offset, end_offset);
        int nblks = end_offset - start_offset + 1;
        uint16_t startIndex=0, endIndex=0;
        MappingInterval *findInterval = new MappingInterval(
                start_offset,
                nblks,
                MappingInterval::Value(0, BlkId(0, 0, 0)));
        dyna_arr->getIntervals(findInterval, offsetToBlkIdLst,startIndex, endIndex);
        delete findInterval;
    }

    void get_all(std::vector<std::shared_ptr<MappingInterval>> &offsetToBlkIdLst) {
        dyna_arr->getAllIntervals(offsetToBlkIdLst);
    }

    std::string to_string() const override {
        return dyna_arr->to_string();
    }

    virtual void append_blob(const BtreeValue &new_val, std::shared_ptr<BtreeValue> &existing_val) override {
        LOGTRACE("Appending->{}", new_val.to_string());
        Interval_Array_Impl *new_dyna_arr_ptr = ((const MappingValue &) new_val).dyna_arr;
        assert(new_dyna_arr_ptr->get_no_of_elements_filled() == 1);
        MappingInterval *newRange = (*new_dyna_arr_ptr)[0];
#ifndef NDEBUG
        uint64_t nblks_before = count_nblks();
#endif
        std::vector<std::shared_ptr<MappingInterval> > existingIntervalOverlaps;
        dyna_arr->addInterval(newRange, existingIntervalOverlaps);

        MappingValue *existingValue = (MappingValue *) existing_val.get();
        for (std::shared_ptr<MappingInterval> ptr : existingIntervalOverlaps) {
            existingValue->dyna_arr->addOrUpdate(ptr.get());
        }

#ifndef NDEBUG
        validate_sanity_value_array(nblks_before);
#endif

    }

#ifndef NDEBUG

    uint64_t count_nblks() {
        uint64_t nblks = 0;
        for (uint32_t i = 0; i < dyna_arr->get_no_of_elements_filled(); i++) {
            nblks += (*dyna_arr)[i]->m_interval_length;
        }
        return nblks;
    }

    void validate_sanity_value_array(uint64_t nblks_before) {
        uint64_t nblks_after = count_nblks();
        if (nblks_after < nblks_before) {
            LOGERROR("Lost entry:{} -> {} :: {}", nblks_before, nblks_after, dyna_arr->to_string());
            assert(0);
        }

        int i = 0;
        std::map<int, bool> mapOfWords;
        int prevsOffset = -1;
        int preveOffset = -1;
        //validate if keys are in ascending orde
        while (i < (int) dyna_arr->get_no_of_elements_filled()) {
            MappingInterval *currentInterval = (*dyna_arr)[i];
            uint16_t soffset = currentInterval->m_interval_start;
            uint16_t eoffset = currentInterval->m_interval_start + currentInterval->m_interval_length - 1;
            std::pair<std::map<int, bool>::iterator, bool> result;
            result = mapOfWords.insert(std::make_pair(soffset, true));
            if (result.second == false) {
                //check uniqueness and sorted
                LOGERROR("Duplicate entry:{} -> {}", soffset, dyna_arr->to_string());
                assert(0);
            }
            if (soffset < prevsOffset) {
                LOGERROR("Not Sorted-> {},{} -> {}", prevsOffset, soffset, dyna_arr->to_string());
                assert(0);
            }
            if (soffset <= preveOffset) {
                LOGERROR("Overlapping-> {},{} -> {}", prevsOffset, soffset, dyna_arr->to_string());
                assert(0);
            }
            if (eoffset >= 145) {
                LOGERROR("Overflow-> {}-> {}", eoffset, dyna_arr->to_string());
                assert(0);
            }
            prevsOffset = soffset;
            preveOffset = eoffset;
            i++;
        }
    }

#endif
};


class mapping {
typedef std::function<void(struct BlkId blkid)> free_blk_callback;
typedef std::function<void(boost::intrusive_ptr<volume_req> cookie)> comp_callback;
private:
    MappingBtreeDeclType *m_bt;

    free_blk_callback free_blk_cb;
    comp_callback comp_cb;

public:
    MappingBtreeDeclType* get_bt_handle() const {
        return m_bt;
    }
    void process_completions(boost::intrusive_ptr<writeback_req> cookie, std::error_condition status);

    mapping(uint64_t volsize, uint32_t page_size, comp_callback comp_cb) : comp_cb(comp_cb) {
        assert(BIT_TO_REPRESENT_MAX_ENTRIES > log2(MAX_NO_OF_VALUE_ENTRIES));
        homeds::btree::BtreeConfig btree_cfg;
        btree_cfg.set_max_objs(volsize / (MAX_NO_OF_VALUE_ENTRIES * MAP_BLOCK_SIZE));
        btree_cfg.set_max_key_size(sizeof(uint32_t));
        btree_cfg.set_max_value_size(MAX_NO_OF_VALUE_ENTRIES * sizeof(MappingInterval));

        homeds::btree::btree_device_info bt_dev_info;
        bt_dev_info.blkstore = (void *)HomeBlks::instance()->get_metadata_blkstore();
        bt_dev_info.new_device = false;
        m_bt = MappingBtreeDeclType::create_btree(btree_cfg, &bt_dev_info,
                std::bind(&mapping::process_completions, this,
                    std::placeholders::_1, std::placeholders::_2));
    }

    mapping(uint64_t volsize, uint32_t page_size, btree_super_block &btree_sb, comp_callback comp_cb) : comp_cb(comp_cb) {
        assert(BIT_TO_REPRESENT_MAX_ENTRIES > log2(MAX_NO_OF_VALUE_ENTRIES));
        homeds::btree::BtreeConfig btree_cfg;
        btree_cfg.set_max_objs(volsize / (MAX_NO_OF_VALUE_ENTRIES * MAP_BLOCK_SIZE));
        btree_cfg.set_max_key_size(sizeof(uint32_t));
        btree_cfg.set_max_value_size(MAX_NO_OF_VALUE_ENTRIES * sizeof(MappingInterval));

        homeds::btree::btree_device_info bt_dev_info;
        bt_dev_info.blkstore = HomeBlks::instance()->get_metadata_blkstore();
        bt_dev_info.new_device = false;
        m_bt = MappingBtreeDeclType::create_btree(btree_sb, btree_cfg, &bt_dev_info,
                std::bind(&mapping::process_completions, this,
                    std::placeholders::_1, std::placeholders::_2));
    }

    btree_super_block get_btree_sb() {
        return(m_bt->get_btree_sb());
    }
#ifndef NDEBUG
    void enable_split_merge_crash_simulation() {
        m_bt->simulate_merge_crash=true;
        m_bt->simulate_split_crash=true;
    }
#endif

    void add_lba(MappingInterval &offBlk, bool found, uint64_t actual_lba,
            std::vector<std::shared_ptr<Lba_Block>> &mappingList) {
        mappingList.push_back(std::make_shared<Lba_Block>(offBlk, actual_lba, found));
    }

    void add_dummy_for_missing_mappings(uint64_t start_lba, uint64_t end_lba,
            std::vector<std::shared_ptr<Lba_Block>> &mappingList);

    void print_tree() {
        m_bt->print_tree();
    }

    std::error_condition get(uint64_t start_lba, uint32_t nblks, std::vector<std::shared_ptr<Lba_Block>> &mappingList);

#ifndef NDEBUG
    void validate_get_response(uint64_t start_lba, uint32_t num_lbas, std::vector<std::shared_ptr<Lba_Block>> &mappingList);
#endif

    std::error_condition put(boost::intrusive_ptr<volume_req> req, uint64_t lba_uint, uint32_t nblks, struct BlkId blkid);
};

}

#endif
