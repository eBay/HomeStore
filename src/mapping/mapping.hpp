#include "omds/btree/mem_btree.hpp"
#include "omds/btree/btree.hpp"
#include <blkalloc/blk.h>

using namespace std;
using namespace omstore;
using namespace omds::btree;

class MappingKey : public omds::btree::BtreeKey {
private:
	uint32_t blob;
	uint32_t *ptr_blob;
public:
	MappingKey(){}
	MappingKey(uint32_t _blob) {
		blob = _blob;
		ptr_blob = &blob;
	}
	int compare(const BtreeKey *o) const override {
		MappingKey *key = (MappingKey *)o;
		if (*ptr_blob < key->blob) {
			return -1;
		} else if (*ptr_blob > key->blob) {
			return 1;
		} else {
			return 0;
		}
	}
	virtual omds::blob get_blob() const override {
		omds::blob b = {(uint8_t *) ptr_blob, sizeof(blob)};
		return b;
	}
	virtual void set_blob(const omds::blob &b) override {
		ptr_blob = (uint32_t *)b.bytes;
	}
	virtual void copy_blob(const omds::blob &b) override {
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
	uint32_t get_value() {
		return blob;
	}
};

class MappingValue : public omds::btree::BtreeValue {
	struct BlkId val;
	struct BlkId *pVal;
public:
	MappingValue() {};
	MappingValue(struct BlkId _val) : omds::btree::BtreeValue() {
		val = _val;
		pVal = &val;
	};
	virtual omds::blob get_blob() const override {
		omds::blob b;
		b.bytes = (uint8_t *)pVal; b.size = sizeof(pVal);
		return b;
	}
	virtual void set_blob(const omds::blob &b) override {
		pVal = (struct BlkId *) b.bytes;
	}
	virtual void copy_blob(const omds::blob &b) override {
		memcpy(pVal, b.bytes, b.size);
	}
	virtual void append_blob(const BtreeValue &new_val) override {
		memcpy(pVal, ((const MappingValue &)new_val).pVal, sizeof(pVal));
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
};

#define MappingBtreeDeclType     omds::btree::Btree<omds::btree::MEM_BTREE, MappingKey, MappingValue, \
                                    omds::btree::BTREE_NODETYPE_SIMPLE, omds::btree::BTREE_NODETYPE_SIMPLE>
#define KEY_RANGE	1000
#define BLOCK_SIZE	8192

class mapping {
private:
	MappingBtreeDeclType *m_bt;
public:
	mapping(uint32_t volsize) {
		omds::btree::BtreeConfig btree_cfg;
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

	uint32_t put(uint32_t lba, uint32_t nblks, struct BlkId blkid) {
		m_bt->put(get_key(lba), get_value(blkid), omds::btree::INSERT_ONLY_IF_NOT_EXISTS);
		return 0;
	}
		
	uint32_t get(uint32_t lba, uint32_t nblks, 
			std::vector<struct omstore::BlkId> &blkIdList) {

		uint32_t key;

		while (nblks != 0) {
			MappingValue value;
			
			key = get_key(lba).get_value;
			m_bt->get(get_key(lba), &value);
			struct BlkId blkid = value.get_val();
			uint32_t maxBlkRead = KEY_RANGE - (lba - key);
	
			if (maxBlkRead >= nblks) {
				blkid.set_nblks(nblks);
				blkid.set_id(blkid.get_id() + lba - key);
				blkIdList.push_back(blkid);
				nblks = 0;
			} else {
				blkid.set_nblks(maxBlkRead);
				blkid.set_id(blkid.get_id() + lba - key);
				blkIdList.push_back(blkid);
				nblks = nblks - maxBlkRead;
				lba = lba + maxBlkRead;
			}
		}
		return 0;
	}
};
