#include "homeds/btree/ssd_btree.hpp"
#include "homeds/btree/btree.hpp"
#include <blkalloc/blk.h>
#include <csignal>
#include <error/error.h>

using namespace std;
using namespace homestore;
using namespace homeds::btree;

class MappingKey : public homeds::btree::BtreeKey {
private:
	uint64_t blob;
	uint64_t *ptr_blob;
public:
	MappingKey(){}
	MappingKey(uint64_t _blob) {
		blob = _blob;
		ptr_blob = &blob;
	}
	int compare(const BtreeKey *o) const override {
		MappingKey *key = (MappingKey *)o;
		if (*ptr_blob < *key->ptr_blob) {
			return -1;
		} else if (*ptr_blob > *key->ptr_blob) {
			return 1;
		} else {
			return 0;
		}
	}
	virtual homeds::blob get_blob() const override {
		homeds::blob b = {(uint8_t *) ptr_blob, sizeof(blob)};
		return b;
	}
	virtual void set_blob(const homeds::blob &b) override {
		ptr_blob = (uint64_t *)b.bytes;
	}
	virtual void copy_blob(const homeds::blob &b) override {
		memcpy(ptr_blob, b.bytes, b.size);
	}
	virtual uint32_t get_blob_size() const override {
		return (sizeof(*ptr_blob));
	}
	virtual void set_blob_size(uint32_t size) override {
	}
	static uint32_t get_fixed_size() {
		return sizeof(blob);
	}
	uint64_t get_value() {
		return blob;
	}
	int compare_range(const BtreeSearchRange &range) const override {
		return 0;
	}
	std::string to_string() const  {
		return (std::to_string(*ptr_blob));
	}
};

class MappingValue : public homeds::btree::BtreeValue {
	struct BlkId val;
	struct BlkId *pVal;
public:
	MappingValue() {
		pVal = &val;
	};
	MappingValue(struct BlkId _val) : homeds::btree::BtreeValue() {
		val = _val;
		pVal = &val;
	};
	virtual homeds::blob get_blob() const override {
		homeds::blob b;
		b.bytes = (uint8_t *)pVal; b.size = sizeof(pVal);
		return b;
	}
	virtual void set_blob(const homeds::blob &b) override {
		pVal = (struct BlkId *) b.bytes;
	}
	virtual void copy_blob(const homeds::blob &b) override {
		memcpy(pVal, b.bytes, b.size);
	}
	virtual void append_blob(const BtreeValue &new_val) override {
		memcpy(pVal, ((const MappingValue &)new_val).pVal, sizeof(val));
	}
	virtual uint32_t get_blob_size() const override {
		return sizeof(*pVal);
	}
	virtual void set_blob_size(uint32_t size) override {
		assert(size == sizeof(*pVal));
	}
	static uint32_t get_fixed_size() {
		return sizeof(val);
	}
	struct BlkId get_val() {
		return val;
	}
	struct BlkId *get_pVal() {
		return pVal;
	}
	std::string to_string() const  {
		return (std::to_string(pVal->m_id));
	}
};

#define MappingBtreeDeclType     homeds::btree::Btree<homeds::btree::SSD_BTREE, MappingKey, MappingValue, \
                                    homeds::btree::BTREE_NODETYPE_SIMPLE, homeds::btree::BTREE_NODETYPE_SIMPLE, 4096u>
#define KEY_RANGE	1
constexpr auto MAP_BLOCK_SIZE = (4 * 1024ul);

namespace homestore {
	struct lba_BlkId_mapping {
		uint64_t lba;
		BlkId blkId;
		bool blkid_found;
		lba_BlkId_mapping():lba(0),blkId(0),blkid_found(false){};
	};
}

class mapping {
	typedef std::function< void (struct BlkId blkid) > free_blk_callback;
private:
	MappingBtreeDeclType *m_bt;

	constexpr static auto Ki = 1024;
	constexpr static auto Mi = Ki * Ki;
	constexpr static auto Gi = Ki * Mi;
	constexpr static auto MAX_CACHE_SIZE = 2ul * Gi;

  free_blk_callback free_blk_cb;
public:
  mapping(uint32_t volsize, free_blk_callback cb, DeviceManager *mgr) :  free_blk_cb(cb) {

		homeds::btree::BtreeConfig btree_cfg;
		btree_cfg.set_max_objs(volsize/(KEY_RANGE*MAP_BLOCK_SIZE));
		btree_cfg.set_max_key_size(sizeof(MappingKey));
		btree_cfg.set_max_value_size(sizeof(MappingValue));
        
		//TODO: we want to initialize btree_device_info only in case of SSD tree

		// Create a global cache entry
		homestore::Cache< BlkId > *glob_cache = new homestore::Cache< homestore::BlkId >(MAX_CACHE_SIZE, MAP_BLOCK_SIZE);
		assert(glob_cache);


		homeds::btree::btree_device_info bt_dev_info;
		bt_dev_info.new_device = true;
		bt_dev_info.dev_mgr = mgr;
		bt_dev_info.size= 512 * Mi;
		bt_dev_info.cache = glob_cache;
		bt_dev_info.vb = nullptr;
        m_bt = MappingBtreeDeclType::create_btree(btree_cfg, &bt_dev_info);
	}

	MappingKey get_key(uint32_t lba) {
		MappingKey key(lba/KEY_RANGE);
		return key;
	}

	MappingValue get_value(struct BlkId blkid) {
		MappingValue value(blkid);
		return value;
	}

	std::error_condition put(uint64_t lba, uint32_t nblks, struct BlkId blkid) {
		MappingValue value;

		/* TODO: It is very naive way of doing it and will definitely impact
		 * the performance. We have a new design and will implement it with
		 * snapshot.
		 */
		for (uint32_t i = 0; i < nblks; ++i) {
			blkid.set_nblks(1);
			/* TODO: don't need to call remove explicitly once
			 * varsize btree is plugged in.
			 */
			bool ret = m_bt->remove(get_key(lba), &value);
			if (ret) {
				/* free this block */
				free_blk_cb(value.get_val());
			}
			m_bt->put(get_key(lba), get_value(blkid), 
				homeds::btree::INSERT_ONLY_IF_NOT_EXISTS);
			++lba;
			blkid.set_id(blkid.get_id() + 1);
		}
		return homestore::no_error;
	}

	std::error_condition get(uint64_t lba, uint32_t nblks,
							 std::vector<struct homestore::lba_BlkId_mapping> &mappingList) {
		std::error_condition error = no_error;
		bool atleast_one_lba_found = false;
		bool atleast_one_lba_not_found = false;
		uint64_t key;

		while (nblks != 0) {
			homestore::lba_BlkId_mapping* mapping = new struct homestore::lba_BlkId_mapping();
			mapping->lba = lba;
			MappingValue value;

			key = get_key(lba).get_value();
			bool ret = m_bt->get(get_key(lba), &value);
			if (!ret) {
				mappingList.push_back(*mapping);
				lba++;
				nblks--;
				atleast_one_lba_not_found = true;
				continue;
			}
			atleast_one_lba_found = true;
			mapping->blkId = value.get_val();
			mapping->blkid_found = true;

			uint32_t maxBlkRead = KEY_RANGE - (lba - (key * KEY_RANGE));

			if (maxBlkRead >= nblks) {
				mapping->blkId.set_nblks(nblks);
				mapping->blkId.set_id(mapping->blkId.get_id() + lba - (key * KEY_RANGE));
				mappingList.push_back(*mapping);
				nblks = 0;
			} else {
				mapping->blkId.set_nblks(maxBlkRead);
				mapping->blkId.set_id(mapping->blkId.get_id() + lba - (key * KEY_RANGE));
				mappingList.push_back(*mapping);
				nblks = nblks - maxBlkRead;
				lba = lba + maxBlkRead;
			}
		}

		if(!atleast_one_lba_found){
			mappingList.empty();
			error = homestore::make_error_condition(
					homestore_error::lba_not_exist);
		}else if(atleast_one_lba_not_found){
			error = homestore::make_error_condition(
					homestore_error::partial_lba_not_exist);
		}
		return error;
	}
};
