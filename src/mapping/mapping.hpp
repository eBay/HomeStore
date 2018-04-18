#include "homeds/btree/mem_btree.hpp"
#include "homeds/btree/btree.hpp"
#include <blkalloc/blk.h>
#include <csignal>

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

#define MappingBtreeDeclType     homeds::btree::Btree<homeds::btree::MEM_BTREE, MappingKey, MappingValue, \
                                    homeds::btree::BTREE_NODETYPE_SIMPLE, homeds::btree::BTREE_NODETYPE_SIMPLE>
#define KEY_RANGE	1
#define BLOCK_SIZE	8192

class mapping {
private:
	MappingBtreeDeclType *m_bt;
public:
	mapping(uint32_t volsize) {
		homeds::btree::BtreeConfig btree_cfg;
		btree_cfg.set_max_objs(volsize/(KEY_RANGE*BLOCK_SIZE));
		btree_cfg.set_max_key_size(sizeof(MappingKey));
		btree_cfg.set_max_value_size(sizeof(MappingValue));
		m_bt = MappingBtreeDeclType::create_btree(btree_cfg, NULL); 
	}

	MappingKey get_key(uint32_t lba) {
		MappingKey key(lba/KEY_RANGE);
		return key;
	}

	MappingValue get_value(struct BlkId blkid) {
		MappingValue value(blkid);
		return value;
	}

	uint32_t put(uint64_t lba, uint32_t nblks, struct BlkId blkid) {
		MappingValue value;
		struct BlkId *temp_blkid;


		m_bt->put(get_key(lba), get_value(blkid), homeds::btree::INSERT_ONLY_IF_NOT_EXISTS);
#ifdef DEBUG
//		m_bt->get(get_key(lba), &value);
//		temp_blkid = value.get_pVal();
//		assert(temp_blkid->m_chunk_num == blkid.m_chunk_num);
#endif
		
		return 0;
	}
		
	uint32_t get(uint64_t lba, uint32_t nblks, 
			std::vector<struct homestore::BlkId> &blkIdList) {

		uint64_t key;

		while (nblks != 0) {
			MappingValue value;
			
			key = get_key(lba).get_value();
			bool ret = m_bt->get(get_key(lba), &value);
			assert(ret);
			struct BlkId blkid = value.get_val();
			uint32_t maxBlkRead = KEY_RANGE - (lba - (key * KEY_RANGE));
	
			if (maxBlkRead >= nblks) {
				blkid.set_nblks(nblks);
				blkid.set_id(blkid.get_id() + lba - (key * KEY_RANGE));
				blkIdList.push_back(blkid);
				nblks = 0;
			} else {
				blkid.set_nblks(maxBlkRead);
				blkid.set_id(blkid.get_id() + lba - (key * KEY_RANGE));
				blkIdList.push_back(blkid);
				nblks = nblks - maxBlkRead;
				lba = lba + maxBlkRead;
			}
		}
		return 0;
	}
};
