#include "homeds/btree/ssd_btree.hpp"
#include "homeds/btree/btree.hpp"
#include <blkalloc/blk.h>
#include <csignal>
#include <error/error.h>
#include <homeds/array/elastic_array.h>
#include <math.h>
#include <sds_logging/logging.h>

using namespace std;
using namespace homestore;
using namespace homeds::btree;

#define MappingBtreeDeclType     homeds::btree::Btree<homeds::btree::SSD_BTREE, MappingKey, MappingValue, \
                                    homeds::btree::BTREE_NODETYPE_VAR_VALUE, homeds::btree::BTREE_NODETYPE_VAR_VALUE, 4096u>
#define Elastic_Array_Impl Elastic_Array<struct value_internal_offset_to_blkid_type, 80, 20 >
// MAKE SURE BIT_TO_REPRESENT_MAX_ENTRIES IS SET CORRECTLY BELOW based on estimated MAX_NO_OF_VALUE_ENTRIES
#define BIT_TO_REPRESENT_MAX_ENTRIES_DECLARE 16;

struct value_internal_offset_to_blkid_type {
    uint16_t m_offset:BIT_TO_REPRESENT_MAX_ENTRIES_DECLARE;
    struct BlkId m_blkid;

    value_internal_offset_to_blkid_type(uint64_t offset, struct BlkId blkid) : m_offset(offset), m_blkid(blkid) {}

    bool operator<(struct value_internal_offset_to_blkid_type &other) {
        if (m_offset < other.m_offset)return true;
        else return false;
    }

    bool operator>(struct value_internal_offset_to_blkid_type &other) {
        if (m_offset > other.m_offset)return true;
        else return false;
    }

    bool operator==(struct value_internal_offset_to_blkid_type &other) {
        if (m_offset == other.m_offset)return true;
        else return false;
    }

    std::string to_string() {
        std::stringstream ss;
        ss << m_offset << ":" << m_blkid.to_string();
        return ss.str();
    };

    operator std::string() { return to_string(); }
}__attribute__ ((__packed__));

constexpr static auto Ki = 1024;
constexpr static auto Mi = Ki * Ki;
constexpr static auto Gi = Ki * Mi;
constexpr static auto MAX_CACHE_SIZE = 2ul * Gi;
//TODO - templatize mapping and block size should come from template
constexpr static int MAP_BLOCK_SIZE = (4 * Ki);
constexpr static int LEAST_NO_OF_OBJECTS_IN_NODE = 3;
constexpr static int RECORD_SIZE = sizeof(uint32_t);
constexpr static int KEY_SIZE = sizeof(uint64_t);
constexpr static int VALUE_HEADER_SIZE = sizeof(uint32_t);
constexpr static int VALUE_ENTRY_SIZE = sizeof(struct value_internal_offset_to_blkid_type);
constexpr static int MAX_NO_OF_VALUE_ENTRIES =
        -1 + (MAP_BLOCK_SIZE - LEAST_NO_OF_OBJECTS_IN_NODE * RECORD_SIZE - LEAST_NO_OF_OBJECTS_IN_NODE * KEY_SIZE) /
             (VALUE_HEADER_SIZE + LEAST_NO_OF_OBJECTS_IN_NODE * VALUE_ENTRY_SIZE);
constexpr static int BIT_TO_REPRESENT_MAX_ENTRIES = BIT_TO_REPRESENT_MAX_ENTRIES_DECLARE;


struct lba_BlkId_mapping {
    uint64_t lba;
    BlkId blkId;
    bool blkid_found;

    lba_BlkId_mapping() : lba(0), blkId(0), blkid_found(false) {};

    lba_BlkId_mapping(uint64_t lba, BlkId blkId, bool blkid_found) : lba(lba), blkId(blkId),
                                                                     blkid_found(blkid_found) {};
};


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

    std::string to_string() const {
        return (std::to_string(*ptr_range_start_offset));
    }
};

class MappingValue : public homeds::btree::BtreeValue {
    Elastic_Array_Impl *dyna_arr;
public:
    MappingValue() {
        dyna_arr = new Elastic_Array_Impl(0, MAX_NO_OF_VALUE_ENTRIES);
    };

    MappingValue(uint16_t offset, struct BlkId _val) :
            homeds::btree::BtreeValue() {
        dyna_arr = new Elastic_Array_Impl(5, MAX_NO_OF_VALUE_ENTRIES);
        value_internal_offset_to_blkid_type offset_blkid(offset, _val);
        dyna_arr->addOrUpdate(&offset_blkid);
    };

    ~MappingValue() {
        delete dyna_arr;
        dyna_arr = NULL;
    };

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
        dyna_arr = new Elastic_Array_Impl((void *) b.bytes, b.size, MAX_NO_OF_VALUE_ENTRIES);
    }

    virtual void append_blob(const BtreeValue &new_val) override {
        // TODO - also check if all entries are not contigious, as it hsould had been merged already

        /* Scenarios for auto-merge 
            1) new_val offset/blockid/nblks does not overlap any existing offset/blockid/nblks
                - Just do shift_insert
            2) superposes exacly one (as whole)
                - Just do update(in place)
            3) Forms contigous with exactly one range (as whole)
                - Just do update(in place) with combined nblks
            4) Forms contigous with two or more ranges ( as whole)
                - update lowest offset with combined nblks
                - remove_shift all other ranges in one go (defien new method remove(i,j)
            5) Overlaps partially with one range 
                - make range with partial overlapping part and new_val
                - update existing range with non-overlaping part(in place)
                - shift_insert new range
            6) Overlaps partially with two or more ranges
                - make range with 2 partial overlapping parts and new_val
                - update 2 existing ranges with non-overlaping parts(in place)
                - remove_shift all in between ranges in one go (defien new method remove(i,j)
                - shift_insert new range
        */

        Elastic_Array_Impl *new_dyna_arr_ptr = ((const MappingValue &) new_val).dyna_arr;
        assert(new_dyna_arr_ptr->get_no_of_elements_filled() == 1);
        value_internal_offset_to_blkid_type *newRange = (*new_dyna_arr_ptr)[0];

        //all s/e offset and blockid are inclusive
        uint16_t new_sOffset = newRange->m_offset;
        uint8_t blocks_to_add = newRange->m_blkid.get_nblks();
        uint16_t new_eOffset = newRange->m_offset + blocks_to_add - 1;
        uint64_t new_sblockId = newRange->m_blkid.get_id();
        uint64_t new_eblockId = newRange->m_blkid.get_id() + newRange->m_blkid.get_nblks() - 1;
        uint16_t new_chunk_num = newRange->m_blkid.get_chunk_num();


        // find start index
        uint16_t startIndex = 0;
        uint16_t endIndex = 0;
        bool is_start_partially_overlapping = false;
        bool is_end_partially_overlapping = false;
        bool is_left_merged = false;
        bool is_right_merged = false;
        bool is_left_partial_overlap = false;
        bool is_right_partial_overlap = false;
        value_internal_offset_to_blkid_type startLeadingNonOverlappingPart(0, BlkId(0));
        value_internal_offset_to_blkid_type endTrailingNonOverlappingPart(0, BlkId(0));
        value_internal_offset_to_blkid_type *currentRange = nullptr;

        //find start 
        while (startIndex < dyna_arr->get_no_of_elements_filled()) {
            currentRange = (*dyna_arr)[startIndex];
            //all s/e offset and blockid are inclusive
            uint16_t curr_sOffset = currentRange->m_offset;
            uint16_t curr_eOffset = currentRange->m_offset + currentRange->m_blkid.get_nblks() - 1;
            uint64_t curr_sblockId = currentRange->m_blkid.get_id();
            uint16_t curr_chunk_num = currentRange->m_blkid.get_chunk_num();

            if (new_sOffset < curr_sOffset) {
                break; // start did not overlap
            } else if (new_sOffset >= curr_sOffset && new_sOffset <= curr_eOffset) {
                if (new_sOffset > curr_sOffset) {
                    assert(0);//TODO remove this
                    //start did partially overlap
                    is_left_partial_overlap = true;
                    is_start_partially_overlapping = true;
                    startLeadingNonOverlappingPart.m_offset = curr_eOffset;
                    startLeadingNonOverlappingPart.m_blkid = BlkId(curr_sblockId, (new_sOffset - curr_sOffset),
                                                                   curr_chunk_num);
                }
                break;
            }
            startIndex++;
        }

        endIndex = startIndex;

        //find end 
        while (endIndex < dyna_arr->get_no_of_elements_filled()) {
            currentRange = (*dyna_arr)[endIndex];
            //all s/e offset and blockid are inclusive
            uint16_t curr_sOffset = currentRange->m_offset;
            uint16_t curr_eOffset = currentRange->m_offset + currentRange->m_blkid.get_nblks() - 1;
            uint64_t curr_sblockId = currentRange->m_blkid.get_id();
            uint16_t curr_chunk_num = currentRange->m_blkid.get_chunk_num();

            if (new_eOffset < curr_sOffset) {
                break; // end did not overlap
            } else if (new_eOffset >= curr_sOffset && new_sOffset <= curr_eOffset) {
                if (new_eOffset < curr_eOffset) {
                    assert(0);//TODO remove this
                    //end did partially overlap
                    is_right_partial_overlap = true;
                    is_end_partially_overlapping = true;
                    endTrailingNonOverlappingPart.m_offset = new_eOffset + 1;
                    endTrailingNonOverlappingPart.m_blkid = BlkId(curr_sblockId + (new_eOffset - curr_sOffset),
                                                                  (curr_eOffset - new_eOffset),
                                                                  curr_chunk_num);
                }
                break;
            }
            endIndex++;
        }
        assert(startIndex == endIndex);//TODO- remove this later

        if (!is_start_partially_overlapping && startIndex > 0) {
            // check if left side is mergable
            currentRange = (*dyna_arr)[startIndex - 1];
            uint16_t curr_sOffset = currentRange->m_offset;
            uint16_t curr_eOffset = currentRange->m_offset + currentRange->m_blkid.get_nblks() - 1;
            uint64_t curr_sblockId = currentRange->m_blkid.get_id();
            uint64_t curr_eblockId = curr_sblockId + currentRange->m_blkid.get_nblks() - 1;
            uint16_t curr_chunk_num = currentRange->m_blkid.get_chunk_num();

            if (curr_eOffset + 1 == new_sOffset && curr_eblockId + 1 == new_sblockId &&
                curr_chunk_num == new_chunk_num) {
                //contigious
                is_left_merged = true;
                newRange->m_offset = curr_sOffset;
                newRange->m_blkid.set_id(curr_sblockId);
                newRange->m_blkid.set_nblks(newRange->m_blkid.get_nblks() + currentRange->m_blkid.get_nblks());
            }
        }
        if (!is_end_partially_overlapping && endIndex < dyna_arr->get_no_of_elements_filled() - 1) {
            // check if right side is mergable
            currentRange = (*dyna_arr)[endIndex];
            uint16_t curr_sOffset = currentRange->m_offset;
            uint64_t curr_sblockId = currentRange->m_blkid.get_id();
            uint16_t curr_chunk_num = currentRange->m_blkid.get_chunk_num();

            if (curr_sOffset - 1 == new_eOffset && curr_sblockId - 1 == new_eblockId &&
                curr_chunk_num == new_chunk_num) {
                //contigious
                is_right_merged = true;
                newRange->m_blkid.set_nblks(newRange->m_blkid.get_nblks() + currentRange->m_blkid.get_nblks());
            }
        }

        std::vector<value_internal_offset_to_blkid_type *> listToAdd;
        if (is_start_partially_overlapping) {
            listToAdd.push_back(&startLeadingNonOverlappingPart);
        }

        listToAdd.push_back(newRange);

        if (is_end_partially_overlapping) {
            listToAdd.push_back(&endTrailingNonOverlappingPart);
        }

        //TODO-reduce so many remove shift and insert shift so as all can be done in one go
        if ((is_left_merged || is_right_merged || is_left_partial_overlap || is_right_partial_overlap)) {
            if(is_left_merged) startIndex--;
            if(is_left_merged && !is_right_merged) endIndex--;
            
#ifndef NDEBUG
            sanity_check_nblks_add_up(startIndex, endIndex, blocks_to_add, listToAdd);
#endif
            if (endIndex == dyna_arr->get_no_of_elements_filled()) 
                endIndex--;
            assert(startIndex<=endIndex);
            dyna_arr->remove_shift(startIndex, endIndex);
        }
        for (auto value : listToAdd) {
            dyna_arr->insert_shift(startIndex, value);
            startIndex++;
        }

#ifndef NDEBUG
        validate_sanity();
#endif
    }

#ifndef NDEBUG
    void sanity_check_nblks_add_up(uint16_t startIndex, uint16_t endIndex, int blksToAdd,
                                   std::vector<value_internal_offset_to_blkid_type *> &listToAdd) {
        int nblks = blksToAdd;
        while (startIndex <= endIndex) {
            nblks += (*dyna_arr)[startIndex]->m_blkid.m_nblks;
            startIndex++;
        }
        int nblks2 = 0;
        for (value_internal_offset_to_blkid_type *value : listToAdd) {
            nblks2 += value->m_blkid.m_nblks;
        }
        if (nblks != nblks2) {
            LOGDEBUG("Nblks beeing added/removed is invalid: added-{}, removed-{} -> {}", nblks2, nblks,
                     this->to_string());
            assert(0);
        }
    }

    void validate_sanity() {
        int i = 0;
        std::map<int, bool> mapOfWords;
        uint16_t prevOffset = 0;
        //validate if keys are in ascending orde
        while (i < (int) dyna_arr->get_no_of_elements_filled()) {
            value_internal_offset_to_blkid_type *currentRange = (*dyna_arr)[i];
            uint16_t offset = currentRange->m_offset;
            std::pair<std::map<int, bool>::iterator, bool> result;
            result = mapOfWords.insert(std::make_pair(offset, true));
            if (result.second == false) {
                //check uniqueness and sorted
                LOGDEBUG("Duplicate entry:{} -> {}", offset, this->to_string());
                assert(0);
            }
            if (offset < prevOffset) {
                LOGDEBUG("Not Sorted-> {},{} -> {}", prevOffset, offset, this->to_string());
                assert(0);
            }
            prevOffset = offset;
            i++;
        }
    }
#endif

    virtual uint32_t get_blob_size() const override {
        return dyna_arr->get_size();
    }

    virtual void set_blob_size(uint32_t size) override {
        assert(0);
    }

    virtual uint32_t estimate_size_after_append(const BtreeValue &new_val) override {
        Elastic_Array_Impl *dyna_arr_ptr = ((const MappingValue &) new_val).dyna_arr;
        assert(dyna_arr_ptr->get_no_of_elements_filled() == 1);
        return dyna_arr->estimate_size_after_addOrUpdate(1);
    }

    void get(uint16_t start_offset, uint32_t nblks,
             std::vector<value_internal_offset_to_blkid_type> &offsetToBlkIdLst) {
        if (dyna_arr->get_no_of_elements_filled() == 0)return;
        value_internal_offset_to_blkid_type start_element(start_offset, BlkId(0, nblks, 0)), end_element(
                start_offset + nblks,
                BlkId(0, nblks, 0));
        int st = dyna_arr->binary_search(&start_element);
        uint32_t end_offset = start_offset + nblks - 1;//inclusive

        if (st < 0) {
            st = (-st - 1);//insertion point
            if (st > 0)st--;//consider one more on left as could be partial overlap
        }
        uint32_t start = (uint32_t) st;

        //find ranges which partially or fully covers requires offset/nblks
        while (start < dyna_arr->get_no_of_elements_filled()) {
            uint16_t curr_soffset = (*dyna_arr)[start]->m_offset;
            uint64_t curr_nblks = (*dyna_arr)[start]->m_blkid.m_nblks;
            uint16_t curr_eoffset = curr_soffset + curr_nblks - 1;//inclusive

            if (curr_eoffset < start_offset) {
                start++;//no overlap at all
                continue;
            } else if (curr_soffset > end_offset) {
                break;//need no more
            }
            offsetToBlkIdLst.push_back(*(*dyna_arr)[start]);
            start++;
        }
    }

    std::string to_string() const {
        return dyna_arr->get_string_representation();
    }
};

class mapping {
    typedef std::function<void(struct BlkId blkid)> free_blk_callback;
private:
    MappingBtreeDeclType *m_bt;

    free_blk_callback free_blk_cb;
public:
    mapping(uint32_t volsize, free_blk_callback cb, DeviceManager *mgr) : free_blk_cb(cb) {
        assert(BIT_TO_REPRESENT_MAX_ENTRIES > log2(MAX_NO_OF_VALUE_ENTRIES));
        homeds::btree::BtreeConfig btree_cfg;
        btree_cfg.set_max_objs(volsize / (MAX_NO_OF_VALUE_ENTRIES * MAP_BLOCK_SIZE));
        btree_cfg.set_max_key_size(sizeof(uint32_t));
        btree_cfg.set_max_value_size(MAX_NO_OF_VALUE_ENTRIES * sizeof(value_internal_offset_to_blkid_type));

        // Create a global cache entry
        homestore::Cache<BlkId> *glob_cache = new homestore::Cache<homestore::BlkId>(MAX_CACHE_SIZE, MAP_BLOCK_SIZE);
        assert(glob_cache);

        homeds::btree::btree_device_info bt_dev_info;
        bt_dev_info.new_device = true;
        bt_dev_info.dev_mgr = mgr;
        bt_dev_info.size = 512 * Mi;
        bt_dev_info.cache = glob_cache;
        bt_dev_info.vb = nullptr;
        m_bt = MappingBtreeDeclType::create_btree(btree_cfg, &bt_dev_info);
    }

    void add_lba(uint64_t lba, uint64_t id, uint8_t nblks, uint16_t chunk_num, bool found,
                 std::vector<struct lba_BlkId_mapping> &mappingList) {
        //TODO - MEMORY LEAK-  put *mapping in shared/unique ptr to prevent memory leak
        lba_BlkId_mapping *mapping = new struct lba_BlkId_mapping(lba, BlkId(id, nblks, chunk_num), found);
        mappingList.push_back(*mapping);
    }

    void add_dummy_for_missing_mappings(uint64_t start_lba, uint64_t end_lba,
                                        std::vector<struct lba_BlkId_mapping> &mappingList) {
        while (start_lba <= end_lba) {
            add_lba(start_lba, 0, 0, 0, false, mappingList);
            start_lba++;
        }
    }

    std::error_condition get(uint64_t lba, uint32_t nblks_uint,
                             std::vector<struct lba_BlkId_mapping> &mappingList) {
        std::error_condition error = no_error;
        bool atleast_one_lba_found = false;
        bool atleast_one_lba_not_found = false;

        uint64_t start_lba = lba;
        uint64_t end_lba = lba + nblks_uint - 1;//inclusive
        int nblks = (int) nblks_uint;
        //iterate till all blocks are readed
        while (nblks != 0) {
            int range_offset = lba / MAX_NO_OF_VALUE_ENTRIES; // key for btree
            uint64_t start_lba_for_range = range_offset * MAX_NO_OF_VALUE_ENTRIES; // start actual lba for this range
            uint64_t end_lba_for_range =
                    ((range_offset + 1) * MAX_NO_OF_VALUE_ENTRIES) - 1; // end actual lba for this range
            // offset inside the current lba range, this would always be zeor except for first window
            uint16_t value_internal_offset = lba - start_lba_for_range;

            //look up key/value from btree
            MappingKey key(range_offset);
            MappingValue value;
            bool ret = m_bt->get(key, &value);

            //find all matching values 
            std::vector<value_internal_offset_to_blkid_type> valueOffsetToBlkIdLst;
            if (ret) {
                value.get(value_internal_offset, nblks, valueOffsetToBlkIdLst);
            }
            uint64_t last_lba = lba;
            if (!ret || valueOffsetToBlkIdLst.size() == 0) {
                m_bt->print_tree();
                assert(0);//REMOVE THIS ASSERT

                // if key/value not found or values is empty
                uint64_t start_lba = lba, end_lba = lba + nblks - 1;
                if (end_lba >= end_lba_for_range)
                    end_lba = end_lba_for_range - 1;
                add_dummy_for_missing_mappings(start_lba, end_lba, mappingList);

                atleast_one_lba_not_found = true;
                last_lba = end_lba + 1;
            } else {
                atleast_one_lba_found = true;

                int i = 0;

                // iterate all values found and fill in the gaps
                while (i < (int) valueOffsetToBlkIdLst.size()) {
                    uint64_t actual_lba = start_lba_for_range + valueOffsetToBlkIdLst[i].m_offset;
                    if (i == 0 && lba > actual_lba) {
                        // this happens for 1 time only at left partial overlap
                        int diff = lba - actual_lba;
                        int blocks_to_consider = valueOffsetToBlkIdLst[i].m_blkid.m_nblks - diff;
                        if (lba + blocks_to_consider - 1 > end_lba) {
                            blocks_to_consider = end_lba - lba + 1;
                        }
                        add_lba(lba, valueOffsetToBlkIdLst[i].m_blkid.m_id + diff, blocks_to_consider,
                                valueOffsetToBlkIdLst[i].m_blkid.m_chunk_num, true, mappingList);
                        last_lba = lba + blocks_to_consider;
                        i++;
                        continue;
                    }
                    if (last_lba < actual_lba) {
                        atleast_one_lba_not_found = true;
                        add_dummy_for_missing_mappings(lba, actual_lba - 1, mappingList);
                    }
                    //request needs only partial of end range - takes care of right partial overlap
                    uint64_t blocks_to_consider = valueOffsetToBlkIdLst[i].m_blkid.m_nblks;
                    if (actual_lba + blocks_to_consider - 1 > end_lba) {
                        blocks_to_consider = end_lba - lba + 1;
                    }
                    add_lba(actual_lba, valueOffsetToBlkIdLst[i].m_blkid.m_id, blocks_to_consider,
                            valueOffsetToBlkIdLst[i].m_blkid.m_chunk_num, true, mappingList);
                    last_lba = actual_lba + blocks_to_consider;
                    i++;

                }
            }
            if ((int) (last_lba - lba) > nblks)
                nblks = 0;
            else
                nblks -= (last_lba - lba);
            lba = last_lba;
        }

        if (!atleast_one_lba_found) {
            mappingList.empty();
            error = homestore::make_error_condition(
                    homestore_error::lba_not_exist);
        } else if (atleast_one_lba_not_found) {
            error = homestore::make_error_condition(
                    homestore_error::partial_lba_not_exist);
        }
        return error;
    }


    std::error_condition put(uint64_t lba, uint32_t nblks, struct BlkId blkid) {
        //MappingValue value;
        uint64_t last_blkid = blkid.get_id();

        //iterate till all blocks are written
        while (nblks != 0) {
            uint64_t range_offset = lba / MAX_NO_OF_VALUE_ENTRIES; // key for btree
            uint64_t start_lba_for_range = range_offset * MAX_NO_OF_VALUE_ENTRIES; // start actual lba for this range
            uint64_t end_lba_for_range =
                    ((range_offset + 1) * MAX_NO_OF_VALUE_ENTRIES) - 1; // end actual lba for this range
            // offset inside the current lba range, this would always be zeor except for first window
            uint16_t value_internal_offset = lba - start_lba_for_range;
            assert(value_internal_offset <= MAX_NO_OF_VALUE_ENTRIES);
            MappingKey key(range_offset);
            BlkId blk;
            blk.m_chunk_num = blkid.m_chunk_num;
            blk.m_nblks = blkid.m_nblks > (end_lba_for_range - lba + 1) ? (end_lba_for_range - lba + 1) : blkid.m_nblks;
            blk.m_id = last_blkid;
            MappingValue value(value_internal_offset, blkid);

            m_bt->put(key, value,
                      homeds::btree::APPEND_IF_EXISTS_ELSE_INSERT);

            lba = end_lba_for_range + 1;
            nblks -= blk.m_nblks;
            last_blkid += blk.m_nblks;
        }
        return homestore::no_error;
    }
};
