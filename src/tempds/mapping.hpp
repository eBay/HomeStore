#include "omds/btree/btree.hpp"
#include <blkalloc/blk.h>
#include "omds/arrayBtree/arrayBtree.hpp"

using namespace std;
using namespace omstore;
using namespace omds::btree;

struct valueBlob : public intervalBtree::baseClassBlob {
        /* TODO: rishabh, we can compact it more */
        struct BlkId id;
        uint64_t lba;
        uint16_t nblks; 
        /* TODO:rishabh, need to add more values for the snaphot */
       
        valueBlob(struct BlkId id, uint64_t lba, uint16_t nblks):id(id), lba(lba), nblks(nblks) {};
        baseClassBlob& operator|=(struct baseClassBlob& otherBaseObj) {
                /* TODO: rishabh :- 
                 * for now value would be overwritten. It changes
                 * when snapshots come. We need to OR with
                 * then exsiting values for snapshots
                 */     
                struct valueBlob &other = get_valueBlob_class(otherBaseObj);
                int offset = value.lba - lba; 
                id.set_id(val.get_id() + offset);
                return (*this);
        }      

        struct valueBlob &get_valueBlob_class(struct baseClassBlob& other) {
                return other; 
        }      
       
        baseClassBlob& operator=(struct baseClassBlob& otherBaseObj) {
                struct valueBlob &other = get_valueBlob_class(otherBaseObj);
                assert(id.lo() == other.id.lo() && id.hi() == other.id.hi());
                int offset = other.lba - lba; 
                /* TODO: if we are overwriting any value, then we should call block store
                 * to free the blkid. 
                 */     
                id.set_id(id.get_id() + offset);
                /* TODO: rishabh :- 
                 * copy the other values also when snaphot comes. 
                 */     
                return (*this);
        }      

        bool operator==(struct baseClassBlob& otherBaseObj) {
                struct valueBlob &other = get_valueBlob_class(otherBaseObj);
                if (id == other.id) {
                        return true;
                } else {
                        return false;
                }
        }

        uint64_t hi(struct valueBlob &blob) const {
                return (blob.lba + nblks - 1);
        }
        uint64_t lo(struct valueBlob &blob) const {
                return blob.lba;
        }
        void modify_lo(int lo) {
                nblks += (lba - lo);
                id.set_id(id.get_id() + lo - lba);
                id.set_nblks(nblks);
        }

        void modify_hi(int hi) {
                nblks += (hi - (lba + nblks - 1));
                id.set_nblks(nblks);
                /* value remain same */
                assert(nblks > 0);
        }
        static bool compareBlob(struct valueBlob &i, struct valueBlob &j) {
                return (i.lba < j.lba);
        }
};

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
        intervalBtree::intervalBtree<struct valueBlob> val_btree;
public:
        MappingValue():val_btree(1) {
        };
        MappingValue(uint64_t lba, uint16_t nblks, struct BlkId _val) :
                                omds::btree::BtreeValue(), val_btree(1) {
                valueBlob node_blob(_val, lba, nblks);
                val_btree.insert_blob(node_blob);
        };
        virtual omds::blob get_blob() const override {
                omds::blob b = {(uint8_t *)val_btree.get_mem(), val_btree.get_size()};
                return b;
        }
        virtual void set_blob(const omds::blob &b) override {
                val_btree.set_mem((void *)(b.bytes), b.size);
        }
        virtual void copy_blob(const omds::blob &b) override {
                /* TODO: we shoudn't do copy.it will change in
                 * future once we have the get_Callback.
                 */
                val_btree = intervalBtree(b.size, b.bytes);
        }
        virtual void append_blob(const BtreeValue &new_val) override {
                assert(((const MappingValue &)new_val).val_btree.get_size() == 1);

                val_btree.insert_blob(((const MappingValue &)new_val).val_btree.get_root_blob());
        }
        virtual uint32_t get_blob_size() const override {
                return val_btree.get_size();
        }
        virtual void set_blob_size(uint32_t size) override {
        }
        /* TODO: will change it to get_callback() */
        int get(uint64_t lba, uint32_t nblks,
                        std::vector<valueBlob> &blkIdList) {
                uint32_t total_blks = val_btree.read(lba, lba+nblks-1, blkIdList);
                assert(total_blks == nblks);
                assert(std::is_sorted(blkIdList.begin(), blkIdList.end(), valueBlob::compareBlob));
        }
};

#define MappingBtreeDeclType     omds::btree::Btree<omds::btree::MEM_BTREE, MappingKey, MappingValue, \
                                    omds::btree::BTREE_NODETYPE_SIMPLE, omds::btree::BTREE_NODETYPE_SIMPLE>
#define KEY_RANGE       1
#define BLOCK_SIZE      8192

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
        MappingValue get_value(struct BlkId blkid, uint64_t lba, uint16_t nblks) {
                MappingValue value(lba, nblks, blkid);
                return value;
        }

        uint32_t put(uint32_t lba, uint32_t nblks, struct BlkId blkid) {
                MappingValue value;
                struct BlkId *temp_blkid;
        //      printf("caliing mapping put\n");
                m_bt->put(get_key(lba), get_value(blkid, lba, blkid.get_nblks()),
                                                        omds::btree::APPEND_IF_EXISTS_ELSE_INSERT);
        //      printf ("temp chunk num %d, %d\n", temp_blkid->m_chunk_num, blkid.m_chunk_num);
                assert(temp_blkid->m_chunk_num == blkid.m_chunk_num);
//              std::cout << std::to_string(temp_blkid.m_chunk_num);
//              std::cout << std::to_string(blkid.m_chunk_num);
                return 0;
        }

        uint32_t get(uint32_t lba, uint32_t nblks,
                        std::vector<struct valueBlob> &blkIdList) {

                uint32_t key;

                while (nblks != 0) {
                        MappingValue value;

                        key = get_key(lba).get_value();
                        m_bt->get(get_key(lba), &value);
                        uint32_t maxBlkRead = KEY_RANGE - (lba - key);

                        if (maxBlkRead >= nblks) {
                                value.get(lba, nblks, blkIdList);
                                nblks = 0;
                        } else {
				value.get(lba, maxBlkRead, blkIdList);
                                nblks = nblks - maxBlkRead;
                                lba = lba + maxBlkRead;
                        }
                }
                return 0;
        }
};
