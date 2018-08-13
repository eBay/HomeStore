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
#define Elastic_Array_Impl Elastic_Array<struct Offset_BlkId, 80, 20 >
// MAKE SURE BIT_TO_REPRESENT_MAX_ENTRIES IS SET CORRECTLY BELOW based on estimated MAX_NO_OF_VALUE_ENTRIES
#define BIT_TO_REPRESENT_MAX_ENTRIES_DECLARE 16;

struct Offset_BlkId {
    uint16_t m_offset:BIT_TO_REPRESENT_MAX_ENTRIES_DECLARE;
    struct BlkId m_blkid;

    Offset_BlkId(uint64_t offset, struct BlkId blkid) : m_offset(offset), m_blkid(blkid) {}

    bool operator<(struct Offset_BlkId &other) {
        if (m_offset < other.m_offset)return true;
        else return false;
    }

    bool operator>(struct Offset_BlkId &other) {
        if (m_offset > other.m_offset)return true;
        else return false;
    }

    bool operator==(struct Offset_BlkId &other) {
        if (m_offset == other.m_offset)return true;
        else return false;
    }

    std::string to_string() {
        std::stringstream ss;
        ss << m_offset << "--->" << m_blkid.to_string();
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
constexpr static int VALUE_ENTRY_SIZE = sizeof(struct Offset_BlkId);
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
        Offset_BlkId offset_blkid(offset, _val);
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

        LOGTRACE("Appending->{}", new_val.to_string());
        bool is_disjoint_interval = true;
        bool is_right_overlap = false;
        bool is_eclipsing_multiple_intervals = false;
        uint16_t startIndex = 0;//point where to delete ranges from.(inclusive). Also the insertion point for newrange
        uint16_t endIndex = 0;// point where to delet range to. (inclusive)

        Elastic_Array_Impl *new_dyna_arr_ptr = ((const MappingValue &) new_val).dyna_arr;
        assert(new_dyna_arr_ptr->get_no_of_elements_filled() == 1);
        Offset_BlkId *newRange = (*new_dyna_arr_ptr)[0];

        //all s/e offset and blockid are inclusive
        uint16_t new_sOffset = newRange->m_offset;
        uint8_t blocks_to_add = newRange->m_blkid.get_nblks();
        uint16_t new_eOffset = newRange->m_offset + blocks_to_add - 1;
        uint64_t new_sblockId = newRange->m_blkid.get_id();
        uint64_t new_eblockId = newRange->m_blkid.get_id() + newRange->m_blkid.get_nblks() - 1;
        uint16_t new_chunk_num = newRange->m_blkid.get_chunk_num();

        Offset_BlkId *startLeadingNonOverlappingPart = nullptr;
        Offset_BlkId *endTrailingNonOverlappingPart = nullptr;
        Offset_BlkId *currentRange = nullptr;

        //loop to find index of left overlap (partial or full)
        while (startIndex < dyna_arr->get_no_of_elements_filled()) {
            currentRange = (*dyna_arr)[startIndex];
            //all s/e offset and blockid are inclusive
            uint16_t curr_sOffset = currentRange->m_offset;
            uint16_t curr_eOffset = currentRange->m_offset + currentRange->m_blkid.get_nblks() - 1;
            uint64_t curr_sblockId = currentRange->m_blkid.get_id();
            uint16_t curr_chunk_num = currentRange->m_blkid.get_chunk_num();

            if (new_sOffset < curr_sOffset) {
                break;
            } else if (new_sOffset >= curr_sOffset && new_sOffset <= curr_eOffset) {
                //start did overlap (partially or fully)
                is_disjoint_interval = false;
                if (new_sOffset > curr_sOffset) {
                    //partial overlap
                    startLeadingNonOverlappingPart = new
                            Offset_BlkId(curr_sOffset,
                                         BlkId(curr_sblockId,
                                               (new_sOffset -
                                                curr_sOffset),
                                               curr_chunk_num));
                }
                break;
            }
            startIndex++;
        }
        // At this point, if there is overlap, startIndex will point to it. If not, it will point to insertion index
        endIndex = startIndex;
        LOGTRACE("Post left overlap phase:{} -> {}", startIndex, endIndex);

        //loop to find index of right overlap (partial or full)
        while (endIndex < dyna_arr->get_no_of_elements_filled()) {
            currentRange = (*dyna_arr)[endIndex];
            //all s/e offset and blockid are inclusive
            uint16_t curr_sOffset = currentRange->m_offset;
            uint16_t curr_eOffset = currentRange->m_offset + currentRange->m_blkid.get_nblks() - 1;
            uint64_t curr_sblockId = currentRange->m_blkid.get_id();
            uint16_t curr_chunk_num = currentRange->m_blkid.get_chunk_num();

            if (new_eOffset < curr_sOffset) {
                break; // end did not overlap
            } else if (new_eOffset >= curr_sOffset && new_eOffset <= curr_eOffset) {
                //start did overlap (partially or fully)
                is_disjoint_interval = false;
                is_right_overlap = true;
                if (new_eOffset < curr_eOffset) {
                    //partial overlap
                    endTrailingNonOverlappingPart = new
                            Offset_BlkId(new_eOffset + 1,
                                         BlkId(curr_sblockId +
                                               (new_eOffset -
                                                curr_sOffset + 1),
                                               (curr_eOffset -
                                                new_eOffset),
                                               curr_chunk_num));
                }
                break;
            }
            is_eclipsing_multiple_intervals = true;
            endIndex++;
        }
        if (!is_right_overlap && endIndex > startIndex) {
            endIndex--;
        }
        LOGTRACE("Post right overlap phase:{} -> {}", startIndex, endIndex);
        // At this point, if there is overlap, endIndex will point to it. If not, it will point to  insertion index -1 or startIndex

        //check if left mergable or not
        if (startIndex > 0) {
            currentRange = (*dyna_arr)[startIndex - 1];
            uint16_t curr_sOffset = currentRange->m_offset;
            uint16_t curr_eOffset = currentRange->m_offset + currentRange->m_blkid.get_nblks() - 1;
            uint64_t curr_sblockId = currentRange->m_blkid.get_id();
            uint64_t curr_eblockId = curr_sblockId + currentRange->m_blkid.get_nblks() - 1;
            uint16_t curr_chunk_num = currentRange->m_blkid.get_chunk_num();

            if (curr_eOffset + 1 == new_sOffset && curr_eblockId + 1 == new_sblockId &&
                curr_chunk_num == new_chunk_num) {
                //contigious

                if (is_disjoint_interval && startIndex == endIndex) {
                    //did not overlap and start/end points to same entry
                    // we need to keep start and end at same position
                    // eg interval existing is 5-15, 20-27 and new interval comes as 16-17
                    // in this case start and end were pointingto 20-27 and we realized lef merge is needed
                    // so we point start and end  to 5-15
                    endIndex--;
                }
                startIndex--;
                is_disjoint_interval = false;
                newRange->m_offset = curr_sOffset;
                newRange->m_blkid.set_id(curr_sblockId);
                newRange->m_blkid.set_nblks(newRange->m_blkid.get_nblks() + currentRange->m_blkid.get_nblks());
            }
        }
        LOGTRACE("Post left merge phase:{} -> {}", startIndex, endIndex);
        //check if right mergable or not
        if (endIndex < dyna_arr->get_no_of_elements_filled() - 1) {
            currentRange = (*dyna_arr)[endIndex + 1];
            uint16_t curr_sOffset = currentRange->m_offset;
            uint64_t curr_sblockId = currentRange->m_blkid.get_id();
            uint16_t curr_chunk_num = currentRange->m_blkid.get_chunk_num();

            if (curr_sOffset - 1 == new_eOffset && curr_sblockId - 1 == new_eblockId &&
                curr_chunk_num == new_chunk_num) {
                //contigious
                endIndex++;
                is_disjoint_interval = false;
                newRange->m_blkid.set_nblks(newRange->m_blkid.get_nblks() + currentRange->m_blkid.get_nblks());
            }
        }
        LOGTRACE("Post right merge phase:{} -> {}", startIndex, endIndex);
        LOGTRACE("Is disjoint?:{} ", is_disjoint_interval);
        LOGTRACE("Prior to append:{}", dyna_arr->get_string_representation());
        //TODO-reduce so many remove shift and insert shift , insetad use in place updates partially
        assert(startIndex <= endIndex);

#ifndef NDEBUG
        uint64_t nblks_before = count_nblks();
#endif

        if (!is_disjoint_interval) {
            // either merger or overlap happened

            //when righ end of new range crosses over all existing ranges
            if (endIndex == dyna_arr->get_no_of_elements_filled()) endIndex--;

            dyna_arr->remove_shift(startIndex, endIndex);
        } else {
            if (is_eclipsing_multiple_intervals) {
                dyna_arr->remove_shift(startIndex, endIndex);
            }
        }

        // Not adding required elements
        std::vector<Offset_BlkId *> listToAdd;
        if (startLeadingNonOverlappingPart != nullptr) {
            listToAdd.push_back(startLeadingNonOverlappingPart);
        }
        listToAdd.push_back(newRange);
        if (endTrailingNonOverlappingPart != nullptr) {
            listToAdd.push_back(endTrailingNonOverlappingPart);
        }
        uint16_t index = startIndex;
        for (auto value : listToAdd) {
            dyna_arr->insert_shift(index, value);
            index++;
        }

#ifndef NDEBUG
        validate_sanity_value_array(nblks_before);
#endif
        delete startLeadingNonOverlappingPart;
        delete endTrailingNonOverlappingPart;
    }

#ifndef NDEBUG

    uint64_t count_nblks() {
        uint64_t nblks = 0;
        for (uint32_t i = 0; i < dyna_arr->get_no_of_elements_filled(); i++) {
            nblks += (*dyna_arr)[i]->m_blkid.m_nblks;
        }
        return nblks;
    }

    // TODO - also check if all entries are not contigious, as it hsould had been merged already
    void validate_sanity_value_array(uint64_t nblks_before) {
        uint64_t nblks_after = count_nblks();
        if (nblks_after < nblks_before) {
            LOGDEBUG("Lost entry:{} -> {} :: {}", nblks_before, nblks_after, this->to_string());
            assert(0);
        }

        int i = 0;
        std::map<int, bool> mapOfWords;
        int prevsOffset = -1;
        int preveOffset = -1;
        //validate if keys are in ascending orde
        while (i < (int) dyna_arr->get_no_of_elements_filled()) {
            Offset_BlkId *currentRange = (*dyna_arr)[i];
            uint16_t soffset = currentRange->m_offset;
            uint16_t eoffset = currentRange->m_offset + currentRange->m_blkid.m_nblks - 1;
            std::pair<std::map<int, bool>::iterator, bool> result;
            result = mapOfWords.insert(std::make_pair(soffset, true));
            if (result.second == false) {
                //check uniqueness and sorted
                LOGDEBUG("Duplicate entry:{} -> {}", soffset, this->to_string());
                assert(0);
            }
            if (soffset < prevsOffset) {
                LOGDEBUG("Not Sorted-> {},{} -> {}", prevsOffset, soffset, this->to_string());
                assert(0);
            }
            if (soffset <= preveOffset) {
                LOGDEBUG("Overlapping-> {},{} -> {}", prevsOffset, soffset, this->to_string());
                assert(0);
            }
            if(eoffset>=MAX_NO_OF_VALUE_ENTRIES){
                LOGDEBUG("Overflow-> {}-> {}", soffset, this->to_string());
                assert(0);
            }
            prevsOffset = soffset;
            preveOffset = eoffset;
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

    void get(uint16_t start_offset, uint16_t end_offset,
             std::vector<Offset_BlkId *> &offsetToBlkIdLst) {
        LOGINFO("value.get called with :{}:{}",start_offset,end_offset);
        if (dyna_arr->get_no_of_elements_filled() == 0)return;
        Offset_BlkId start_element(start_offset, BlkId(0, 0, 0));
        int st = dyna_arr->binary_search(&start_element);

        if (st < 0) {
            st = (-st - 1);//insertion point
            if (st > 0)st--;//consider one more on left as could be partial overlap
        }
        uint32_t start = (uint32_t) st;

        //TODO - Memory leak -fix , use unique/shared ptr
        Offset_BlkId *currentRange = nullptr;

        //find ranges which partially or fully covers requires offset/nblks
        while (start < dyna_arr->get_no_of_elements_filled()) {
            uint64_t curr_soffset = (*dyna_arr)[start]->m_offset;
            uint64_t curr_nblks = (*dyna_arr)[start]->m_blkid.m_nblks;
            uint64_t curr_eoffset = curr_soffset + curr_nblks - 1;//inclusive
            uint64_t curr_sblockId = (*dyna_arr)[start]->m_blkid.m_id;
            uint64_t curr_chunk_num = (*dyna_arr)[start]->m_blkid.m_chunk_num;

            if (curr_eoffset < start_offset) {
                start++;//this range is not required
                continue;
            } else if (curr_soffset > end_offset) {
                break;//dont need any more ranges
            }

            currentRange = new
                    Offset_BlkId(curr_soffset,
                                 BlkId(curr_sblockId,
                                       curr_nblks,
                                       curr_chunk_num));
            if (start_offset >= curr_soffset && start_offset <= curr_eoffset) {
                //its an overlap
                if (start_offset > curr_soffset) {
                    //partial overlap with non-required starting blocks
                    currentRange->m_offset = start_offset;
                    currentRange->m_blkid.set(curr_sblockId + (start_offset - curr_soffset),
                                              (curr_eoffset - start_offset)+1, curr_chunk_num);
                }
            }
            if (end_offset >= curr_soffset && end_offset <= curr_eoffset) {
                if (end_offset < curr_eoffset) {
                    //partial overlap with non-required trailing blocks
                    currentRange->m_blkid.m_nblks -= (curr_eoffset - end_offset);
                }
            }
            //push current_Range
            assert(currentRange->m_blkid.m_nblks>0);
            offsetToBlkIdLst.push_back(currentRange);
            start++;
        }
        LOGINFO("value.get finished with :{}:{}",start_offset,end_offset);
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
        btree_cfg.set_max_value_size(MAX_NO_OF_VALUE_ENTRIES * sizeof(Offset_BlkId));

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
        m_bt->print_tree();
        assert(0);//REMOVE LATER
        while (start_lba <= end_lba) {
            add_lba(start_lba, 0, 0, 0, false, mappingList);
            start_lba++;
        }
    }

    void print_tree() {
        m_bt->print_tree();
    }

    void get(uint64_t start_lba, uint32_t nblks,
             std::vector<struct lba_BlkId_mapping> &mappingList) {
        LOGINFO("mapping.get called with :{}:{}",start_lba,nblks);
        uint64_t curr_lba = start_lba;
        uint64_t end_lba = start_lba + nblks - 1;//inclusive

        while (curr_lba <= end_lba) {
            int range_offset = curr_lba / MAX_NO_OF_VALUE_ENTRIES; // key for btree
            uint64_t start_lba_for_range = range_offset * MAX_NO_OF_VALUE_ENTRIES; // start actual lba for this range
            uint64_t end_lba_for_range =
                    ((range_offset + 1) * MAX_NO_OF_VALUE_ENTRIES) - 1; // end actual lba for this range

            // offset inside the current lba range, this would always be zeor except for first window
            uint16_t start_offset = curr_lba - start_lba_for_range;
            uint16_t end_offset =  MAX_NO_OF_VALUE_ENTRIES - 1;

            if (end_lba < end_lba_for_range) {
                //we dont need all ranges in this key
                end_offset -= (end_lba_for_range - end_lba);
            }
            //look up key/value from btree
            MappingKey key(range_offset);
            MappingValue value;
            bool ret = m_bt->get(key, &value);

            //find all matching values 
            std::vector<Offset_BlkId *> valueOffsetToBlkIdLst;
            if (ret) {
                value.get(start_offset, end_offset, valueOffsetToBlkIdLst);
            }
            if (!ret || valueOffsetToBlkIdLst.size() == 0) {
                //either key not found or no values found for this range
                m_bt->print_tree();
                assert(0);//REMOVE THIS ASSERT
            }

            int i = 0;
            // iterate all values found and fill in the gaps
            while (i < (int) valueOffsetToBlkIdLst.size()) {
                uint64_t curr_range_start_lba = start_lba_for_range + valueOffsetToBlkIdLst[i]->m_offset;
                uint64_t curr_range_end_lba = curr_range_start_lba + valueOffsetToBlkIdLst[i]->m_blkid.m_nblks - 1;
                assert(curr_range_start_lba >= curr_lba && curr_range_start_lba >= start_lba);

                //fill the gaps
                if (curr_lba < curr_range_start_lba) {
                    add_dummy_for_missing_mappings(curr_lba, curr_range_start_lba - curr_lba, mappingList);
                }
                //add the range found
                add_lba(curr_range_start_lba, valueOffsetToBlkIdLst[i]->m_blkid.m_id,
                        valueOffsetToBlkIdLst[i]->m_blkid.m_nblks,
                        valueOffsetToBlkIdLst[i]->m_blkid.m_chunk_num, true, mappingList);

                curr_lba = curr_range_end_lba + 1;
                i++;
            }
            if (curr_lba < end_lba_for_range && curr_lba < end_lba) {
                //gather remaining lba's which are not found
                if (end_lba < end_lba_for_range) end_lba_for_range = end_lba;
                add_dummy_for_missing_mappings(curr_lba, end_lba_for_range - curr_lba + 1, mappingList);
                curr_lba = end_lba_for_range + 1;
            }
        }
        LOGINFO("mapping.get finished with :{}:{}",start_lba,nblks);
#ifndef NDEBUG
        validate_get_response(start_lba,nblks,mappingList);
#endif
    }

#ifndef NDEBUG
    void validate_get_response(uint64_t start_lba, uint32_t nblks,
             std::vector<struct lba_BlkId_mapping> &mappingList) {

        uint32_t fetch_no_blockes=0;
        uint32_t i=0;
        uint64_t last_slba = start_lba;
        while(i<mappingList.size()){
            uint64_t curr_slba = mappingList[i].lba;
            uint64_t curr_elba = curr_slba+mappingList[i].blkId.m_nblks-1;
            fetch_no_blockes+=mappingList[i].blkId.m_nblks;
            if(curr_slba !=  last_slba){
                //gaps found
                assert(0);
            }
            last_slba = curr_elba+1;
            i++;
        }
        assert(fetch_no_blockes==nblks);
    }
    
#endif

    std::error_condition put(uint64_t lba_uint, uint32_t nblks, struct BlkId blkid) {
        uint64_t last_blkid = blkid.get_id();// lba which is to be put next
        uint64_t lba = lba_uint;
        int total_blocks = nblks;
        //iterate till all blocks are put
        while (total_blocks != 0) {
            uint64_t range_offset = lba / MAX_NO_OF_VALUE_ENTRIES; // key for btree
            uint64_t start_lba_for_range = range_offset * MAX_NO_OF_VALUE_ENTRIES; // start actual lba for this range
            uint64_t end_lba_for_range =
                    ((range_offset + 1) * MAX_NO_OF_VALUE_ENTRIES) - 1; // end actual lba for this range
            // offset inside the current lba range, this would always be zeor except for first window
            uint16_t value_internal_offset = lba - start_lba_for_range;
            assert(value_internal_offset < MAX_NO_OF_VALUE_ENTRIES);
            MappingKey key(range_offset);
            BlkId blk;
            blk.m_chunk_num = blkid.m_chunk_num;
            //see if we have reached almost end of nblks needed.
            blk.m_nblks = (uint64_t) total_blocks > (end_lba_for_range - lba + 1) ? (end_lba_for_range - lba + 1)
                                                                                  : total_blocks;
            blk.m_id = last_blkid;
            assert(value_internal_offset+ blk.m_nblks-1 <MAX_NO_OF_VALUE_ENTRIES);
            MappingValue value(value_internal_offset, blk);

            m_bt->put(key, value,
                      homeds::btree::APPEND_IF_EXISTS_ELSE_INSERT);

            lba = end_lba_for_range + 1;
            assert(blk.m_nblks>0);
            total_blocks -= blk.m_nblks;
            last_blkid += blk.m_nblks;
            assert(total_blocks >= 0);
        }
        return homestore::no_error;
    }
};
