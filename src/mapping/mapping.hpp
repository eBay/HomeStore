#include "homeds/btree/ssd_btree.hpp"
#include "homeds/btree/btree.hpp"
#include <blkalloc/blk.h>
#include <csignal>
#include <error/error.h>
#include <homeds/array/sorted_dynamic_array.h>

using namespace std;
using namespace homestore;
using namespace homeds::btree;

#define Sorted_Dynamic_Array_Impl Sorted_Dynamic_Array<struct value_internal_offset_to_blkid_type, 80, 20>

class MappingKey : public homeds::btree::BtreeKey {
private:
    //Actual value range for an key is (range_start_offset*KEY_RANGE, range_start_offset*KEY_RANGE + KEY_RANGE -1)
    uint64_t range_start_offset; // TODO - compress further if we dont need such big lba numbers
    uint64_t *ptr_range_start_offset;
public:
    MappingKey() {}

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


struct value_internal_offset_to_blkid_type {
    uint16_t m_offset; // TODO - further compress, we just need 10 bits to represent 1024 entries
    struct BlkId m_blkid;

    value_internal_offset_to_blkid_type(uint64_t offset, struct BlkId blkid) : m_offset(offset), m_blkid(blkid) {}

    bool operator<(struct lba_blkid &other) {
        if (m_offset < other.m_offset)return true;
        else return false;
    }

    bool operator>(struct m_lba_blkid &other) {
        if (m_offset > other.m_offset)return true;
        else return false;
    }

    bool operator==(struct m_lba_blkid &other) {
        if (m_offset == other.m_offset)return true;
        else return false;
    }

    std::string to_string() {
        std::stringstream ss;
        ss << m_offset << ":" << m_blkid.to_string();
        return ss.str();
    };
};

class MappingValue : public homeds::btree::BtreeValue {
    Sorted_Dynamic_Array_Impl *dyna_arr;
public:
    MappingValue() {
        dyna_arr = new Sorted_Dynamic_Array_Impl(3);
    };

    MappingValue(uint16_t offset, struct BlkId _val) :
            homeds::btree::BtreeValue() {
        dyna_arr = new Sorted_Dynamic_Array_Impl(3);
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
        dyna_arr->set_mem((void *) (b.bytes), b.size);
    }

    virtual void copy_blob(const homeds::blob &b) override {
        delete dyna_arr;
        dyna_arr = new Sorted_Dynamic_Array_Impl((void *) b.bytes, b.size);
    }

    virtual void append_blob(const BtreeValue &new_val) override {
        //TODO - yet to implement value auto-merge
        assert(((const MappingValue &) new_val).dyna_arr->get_no_of_elements_filled() == 1);
        dyna_arr->addOrUpdate(((const MappingValue &) new_val).*dyna_arr[0]);
    }

    virtual uint32_t get_blob_size() const override {
        return dyna_arr->get_size();
    }

    virtual void set_blob_size(uint32_t size) override {
        assert(0);
    }

    void get(uint16_t offset, uint32_t nblks,
             std::vector<value_internal_offset_to_blkid_type> &offsetToBlkIdLst) {
        if (dyna_arr->get_no_of_elements_filled() == 0)return;
        value_internal_offset_to_blkid_type start_element(offset, BlkId(0)), end_element(offset + nblks, BlkId(0));

        int start = dyna_arr->binary_search(&start_element);

        //TODO - could be faster to do linear scan from start instead of bs on end
        int end = dyna_arr->binary_search(&end_element);

        if (start < 0)start = -start + 1;
        if (start == dyna_arr->get_no_of_elements_filled())start--;
        if (end < 0)end = -end + 1;
        if (end == dyna_arr->get_no_of_elements_filled())end--;
        while (start <= end) {
            offsetToBlkIdLst.push_back(dyna_arr->[start]);
            start++;
        }
    }

    std::string to_string() const {
        return dyna_arr->get_string_representation();
    }
};

#define MappingBtreeDeclType     homeds::btree::Btree<homeds::btree::SSD_BTREE, MappingKey, MappingValue, \
                                    homeds::btree::BTREE_NODETYPE_VAR_VALUE, homeds::btree::BTREE_NODETYPE_VAR_VALUE, 4096u>
#define KEY_RANGE    1000
constexpr auto MAP_BLOCK_SIZE = (4 * 1024ul);

namespace homestore {
    struct lba_BlkId_mapping {
        uint64_t lba;
        BlkId blkId;
        bool blkid_found;

        lba_BlkId_mapping() : lba(0), blkId(0), blkid_found(false) {};

        lba_BlkId_mapping(uint64_t lba, BlkId blkId, bool blkid_found) : lba(lba), blkId(blkId),
                                                                         blkid_found(blkid_found) {};
    };
}

class mapping {
    typedef std::function<void(struct BlkId blkid)> free_blk_callback;
private:
    MappingBtreeDeclType *m_bt;

    constexpr static auto Ki = 1024;
    constexpr static auto Mi = Ki * Ki;
    constexpr static auto Gi = Ki * Mi;
    constexpr static auto MAX_CACHE_SIZE = 2ul * Gi;

    free_blk_callback free_blk_cb;
public:
    mapping(uint32_t volsize, free_blk_callback cb, DeviceManager *mgr) : free_blk_cb(cb) {

        homeds::btree::BtreeConfig btree_cfg;
        btree_cfg.set_max_objs(volsize / (KEY_RANGE * MAP_BLOCK_SIZE));
        btree_cfg.set_max_key_size(sizeof(uint32_t));
        btree_cfg.set_max_value_size(KEY_RANGE * sizeof(value_internal_offset_to_blkid_type));

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

    void add_lba(uint64_t lba, BlkId blkId, bool found,
                 std::vector<struct homestore::lba_BlkId_mapping> &mappingList) {
        homestore::lba_BlkId_mapping *mapping = new struct homestore::lba_BlkId_mapping(lba, blkId, found);
        mappingList.push_back(*mapping);
    }

    void add_dummy_for_missing_mappings(uint64_t start_lba, uint64_t end_lba,
                                        std::vector<struct homestore::lba_BlkId_mapping> &mappingList) {
        while (start_lba <= end_lba) {
            add_lba(start_lba, BlkId(0), false, mappingList);
            start_lba++;
        }
    }

    std::error_condition get(uint64_t lba, uint32_t nblks,
                             std::vector<struct homestore::lba_BlkId_mapping> &mappingList) {
        std::error_condition error = no_error;
        bool atleast_one_lba_found = false;
        bool atleast_one_lba_not_found = false;

        //iterate till all blocks are readed
        while (nblks != 0) {
            int range_offset = lba / KEY_RANGE; // key for btree
            uint64_t start_lba_for_range = range_offset * KEY_RANGE; // start actual lba for this range
            uint64_t end_lba_for_range = ((range_offset + 1) * KEY_RANGE) - 1; // end actual lba for this range
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
                // if key/value not found or values is empty
                uint64_t start_lba = lba, end_lba = lba + end_lba_for_range;
                add_dummy_for_missing_mappings(start_lba, end_lba, mappingList);

                atleast_one_lba_not_found = true;
                last_lba = end_lba_for_range + 1;
            } else {
                atleast_one_lba_found = true;

                int i = 0;

                // iterate all values found and fill in the gaps
                while (i < valueOffsetToBlkIdLst.size()) {
                    uint64_t actual_lba = start_lba_for_range + valueOffsetToBlkIdLst[i].m_offset;
                    if (last_lba < actual_lba) {
                        add_dummy_for_missing_mappings(lba, actual_lba - 1, mappingList);
                    }
                    add_lba(actual_lba, valueOffsetToBlkIdLst[i].m_blkid, true, mappingList);
                    last_lba = actual_lba + valueOffsetToBlkIdLst[i].m_blkid.m_nblks + 1;
                }
            }

            lba = last_lba;
            nblks -= (KEY_RANGE - value_internal_offset);
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
        MappingValue value;
        uint64_t last_blkid = blkid.get_id();

        //iterate till all blocks are written
        while (nblks != 0) {
            int range_offset = lba / KEY_RANGE; // key for btree
            uint64_t start_lba_for_range = range_offset * KEY_RANGE; // start actual lba for this range
            uint64_t end_lba_for_range = ((range_offset + 1) * KEY_RANGE) - 1; // end actual lba for this range
            // offset inside the current lba range, this would always be zeor except for first window
            uint16_t value_internal_offset = lba - start_lba_for_range;

            MappingKey key(range_offset);
            BlkId blk;
            blk.m_chunk_num = blkid.m_chunk_num;
            blk.m_nblks = blkid.m_nblks > (end_lba_for_range - lba) ? (end_lba_for_range - lba) : blkid.m_nblks;
            blk.m_id = last_blkid;
            MappingValue value(value_internal_offset, blkid);

            m_bt->put(key, value,
                      homeds::btree::APPEND_IF_EXISTS_ELSE_INSERT);

            nblks -= blk.m_nblks;
            last_blkid += blk.m_nblks;
        }
        return homestore::no_error;
    }
};
