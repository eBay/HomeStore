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

using namespace std;
using namespace homeds::btree;
#define LBA_BITS 56
#define N_LBA_BITS 8
#define LBA_MASK 0xFFFFFFFFFFFF
#define CS_ARRAY_STACK_SIZE 256 //equals 2^N_LBA_BITS //TODO - put static assert
namespace homestore {

    struct LbaId {
        //size of lba start and num of lba can be reduced for future use
        uint64_t m_lba_start:LBA_BITS;//start of lba range
        uint16_t m_n_lba:N_LBA_BITS;// number of lba's from start(inclusive)

        LbaId() : m_lba_start(0), m_n_lba(0) {}

        LbaId(uint64_t lbaId) { LbaId(lbaId & LBA_MASK, lbaId >> LBA_BITS); }

        LbaId(uint64_t lba_start, uint16_t n_lba) : m_lba_start(lba_start), m_n_lba(n_lba) {}

    }__attribute__ ((__packed__));

    //MappingKey is fixed size
    class MappingKey : public homeds::btree::BtreeKey {
        LbaId m_lbaId;
        LbaId *m_lbaId_ptr;
    public:
        MappingKey() : m_lbaId_ptr(&m_lbaId) {}

        MappingKey(const MappingKey &other) : BtreeKey(), m_lbaId(other.get_lbaId()), m_lbaId_ptr(&m_lbaId) {}

        MappingKey(uint64_t lba_start, uint16_t n_lba) : m_lbaId(lba_start, n_lba), m_lbaId_ptr(&m_lbaId) {}

        LbaId get_lbaId() const { return *m_lbaId_ptr; }

        uint64_t start() const { return m_lbaId_ptr->m_lba_start; }

        uint64_t end() const { return start() + get_n_lba() - 1; }

        uint16_t get_n_lba() const { return m_lbaId_ptr->m_n_lba; }

        // used by btree to ensure inserted keys are sorted
        virtual int compare(const BtreeKey *input) const override {
            MappingKey *o = (MappingKey *) input;
            if (o->end() < start()) return 1;// no overlap - go left
            else if (end() < o->start()) return -1;// no overlap - go right
            else return 0;//overlap
        }

        // used by btree range queries to find overlaps with existing keys in inner/leaf nodes
        virtual int compare_range(const BtreeSearchRange &input) const override {
            //check if any overlap in lba range - return 0 if the case
            MappingKey *o_start = (MappingKey *) input.get_start_key();
            MappingKey *o_end = (MappingKey *) input.get_end_key();
            if (o_end->end() < start()) return 1;//no overlap - go left
            else if (end() < o_start->start()) return -1; // no overlap- go right
            else return 0; //overlap
        }

        virtual homeds::blob get_blob() const override { return {(uint8_t *) m_lbaId_ptr, get_fixed_size()}; }

        virtual void set_blob(const homeds::blob &b) override {
            assert(b.size == get_fixed_size());
            m_lbaId_ptr = (LbaId *) b.bytes;
        }

        virtual void copy_blob(const homeds::blob &b) override {
            assert(b.size == get_fixed_size());
            LbaId *other = (LbaId *) b.bytes;
            set(other->m_lba_start, other->m_n_lba);
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
            ss << "lba_st=" << start() << ",nlba=" << get_n_lba();
            return ss.str();
        }

        void get_overlap(MappingKey &other, MappingKey &overlap) {
            auto start_lba = std::max(start(), other.start());
            auto end_lba = std::min(end(), other.end());
            overlap.set(start_lba, end_lba - start_lba + 1);
        }

        //returns difference in start lba
        uint64_t get_start_offset(MappingKey &other) { return start() - other.start(); }

        static uint32_t get_fixed_size() { return sizeof(LbaId); }

        friend ostream &operator<<(ostream &os, const MappingKey &k) {
            os << k.to_string();
            return os;
        }

    }__attribute__ ((__packed__));

    struct ValueEntry {
    private:
        uint64_t m_seqId;
        BlkId m_blkId;
        uint64_t m_blk_offset:NBLKS_BITS;//offset based on blk store not based on vol page size

        //this allocates 2^NBLKS_BITS size array for checksum on stack, however actual memory used is less on bnode
        //as we call get_blob_size which takes into account actual nblks to determine exact size of checksum array
        //TODO - can be replaced by thread local buffer in future
        std::array<uint16_t, CS_ARRAY_STACK_SIZE> m_carr;

        ValueEntry *m_ptr;

    public:
        ValueEntry() : m_seqId(0), m_blkId(0), m_blk_offset(0), m_carr() { m_ptr = (ValueEntry *) &m_seqId; }

        //deep copy
        ValueEntry(uint64_t seqId, const BlkId &blkId, uint8_t blk_offset,
                   const array<uint16_t, CS_ARRAY_STACK_SIZE> &carr)
                : m_seqId(seqId), m_blkId(blkId), m_blk_offset(blk_offset),
                  m_carr(carr) { m_ptr = (ValueEntry *) &m_seqId; }

        ValueEntry(const ValueEntry &ve) {
            copy_from(ve);
        }

        ValueEntry(uint8_t *ptr) : m_ptr((ValueEntry *) ptr) {}

        uint32_t get_blob_size() {
            return sizeof(uint64_t) + sizeof(BlkId) + sizeof(uint8_t) + sizeof(uint16_t) * get_actual_nblks();
        }

        homeds::blob get_blob() { return {(uint8_t *) m_ptr, get_blob_size()}; }

        void set_blob(homeds::blob b) {
            m_ptr = (ValueEntry *) b.bytes;
            assert(b.size == get_blob_size());
        }

        void copy_blob(homeds::blob b) {
            ValueEntry ve(b.bytes);
            copy_from(ve);
        }

        void copy_from(const ValueEntry &ve) {
            m_seqId = ve.get_seqId();
            m_blkId = ve.get_blkId();
            m_blk_offset = ve.get_blk_offset();
            for (auto i = 0; i < ve.get_actual_nblks(); i++) {
                m_carr[i] = ve.get_checksum_at(i);
            }
            m_ptr = (ValueEntry *) &m_seqId;
        }

        //TODO- blk offset should not be used for checksum array, instead use nlba/lbaoffset
        void add_offset(uint8_t lba_offset, uint8_t nlba, uint32_t vol_page_size, uint32_t blkalloc_page_size) {
            assert(get_actual_nblks() - lba_offset > 0);
            //move checksum array elements to start from offset position
            memmove((void *) &(m_ptr->m_carr[0]), (void *) (&(m_ptr->m_carr[lba_offset])),
                    sizeof(uint16_t) * (get_actual_nblks() - lba_offset));
            uint8_t blk_offset = (vol_page_size / blkalloc_page_size)*lba_offset;
            m_ptr->m_blk_offset += blk_offset;
            //TODO - use nlba to trip checksum array
#ifndef NDEBUG
            auto nblks = nlba * vol_page_size / blkalloc_page_size;
            assert(blk_offset + nblks <= get_blkId().get_nblks());
            assert(blk_offset < get_blkId().get_nblks());
#endif
        }

        uint8_t get_actual_nblks() const { return get_blkId().get_nblks() - get_blk_offset(); }

        uint64_t get_seqId() const { return m_ptr->m_seqId; }

        BlkId &get_blkId() const { return m_ptr->m_blkId; }

        uint8_t get_blk_offset() const { return (uint8_t) m_ptr->m_blk_offset; }

        uint16_t &get_checksum_at(uint8_t index) const {
            assert(index < get_actual_nblks());
            return m_ptr->m_carr[index];
        }

        const std::string get_checksums_string() const {
            std::stringstream ss;
            for (auto i = 0u; i < get_actual_nblks(); i++) {
                ss << get_checksum_at(i) << ",";
            }
            return ss.str();
        }

        friend ostream &operator<<(ostream &os, const ValueEntry &ve) {
            os << "Seq=" << ve.get_seqId() << ","
               << ve.get_blkId() << ",Boff=" << unsigned(ve.get_blk_offset())
               << ",CSArr=" << ve.get_checksums_string();
            return os;
        }
    }__attribute__ ((__packed__));

    class MappingValue : public homeds::btree::BtreeValue {
        Blob_Array <ValueEntry> m_earr;
    public:
        //creates empty array
        MappingValue() {};

        //creates array with one value entry - on heap - bcopy
        MappingValue(ValueEntry &ve) { m_earr.set_element(ve); }

        //performs deep copy from other - on heap
        MappingValue(const MappingValue &other) { m_earr.set_elements(other.m_earr); }

        //creates array with  value entrys - on heap -bcopy
        MappingValue(vector<ValueEntry> &elements) { m_earr.set_elements(elements); }

        virtual homeds::blob get_blob() const override {
            homeds::blob b;
            b.bytes = (uint8_t *) m_earr.get_mem();
            b.size = m_earr.get_size();
            return b;
        }

        virtual void set_blob(const homeds::blob &b) override {
            m_earr.set_mem((void *) (b.bytes), b.size);
        }

        virtual void copy_blob(const homeds::blob &b) override {
            Blob_Array <ValueEntry> other;
            other.set_mem((void *) b.bytes, b.size);
            m_earr.set_elements(other);//deep copy
        }

        virtual uint32_t get_blob_size() const override { return m_earr.get_size(); }

        virtual void set_blob_size(uint32_t size) override { assert(0); }

        virtual uint32_t estimate_size_after_append(const BtreeValue &new_val) override { assert(0); return 0; }

        virtual void append_blob(const BtreeValue &new_val, BtreeValue &existing_val) override { assert(0); }

        virtual string to_string() const override { return m_earr.to_string(); }

        Blob_Array <ValueEntry> &get_array() { return m_earr; }

        bool is_valid() {
            if (m_earr.get_total_elements() == 0) return false;
            return true;
        }

        //return deep copied MappingValue and add offset to all entries in copy
        void
        add_offset(uint8_t lba_offset, uint8_t nlba, uint32_t vol_page_size, uint32_t blkalloc_page_size,
                   MappingValue &out) {
            vector<ValueEntry> v_array;
            auto j = 0u;
            while (j < get_array().get_total_elements()) {
                ValueEntry ve;
                get_array().get(j, ve, true);
                ve.add_offset(lba_offset, nlba, vol_page_size, blkalloc_page_size);
                v_array.emplace_back(ve);
                j++;
            }
            out.get_array().set_elements(v_array);
        }

        //append entry to this mapping value, it return new Mapping Value - deep copy
        void add(ValueEntry &ve, MappingValue &out) {
            vector<ValueEntry> v_array;
            get_array().get_all(v_array, true);
            v_array.emplace_back(ve);
            out.get_array().set_elements(v_array);
        }
    };

    class mapping {
        typedef function<void(struct BlkId blkid)> free_blk_callback;
        typedef function<void(boost::intrusive_ptr<volume_req> cookie)> comp_callback;
    private:
        MappingBtreeDeclType *m_bt;
        free_blk_callback free_blk_cb;
        comp_callback comp_cb;
        uint32_t m_vol_page_size;
        uint32_t m_blkalloc_page_size;
        const MappingValue EMPTY_MAPPING_VALUE;
    public:
        MappingBtreeDeclType* get_bt_handle() const {
            return m_bt;
        }
        void process_completions(boost::intrusive_ptr<writeback_req> cookie,
                                 error_condition status) {
            boost::intrusive_ptr<volume_req> req =
                    boost::static_pointer_cast<volume_req>(cookie);
            if (req->status == no_error) {
                req->status = status;
            }

            comp_cb(req);
        }

        mapping(uint64_t volsize, uint32_t page_size, comp_callback comp_cb) : comp_cb(comp_cb) {
            homeds::btree::BtreeConfig btree_cfg;
            btree_cfg.set_max_objs(volsize / page_size);
            btree_cfg.set_max_key_size(sizeof(uint32_t));
            btree_cfg.set_max_value_size(page_size);

            homeds::btree::btree_device_info bt_dev_info;
            bt_dev_info.blkstore = (void *)HomeBlks::instance()->get_metadata_blkstore();
            bt_dev_info.new_device = false;
            m_bt = MappingBtreeDeclType::create_btree(btree_cfg, &bt_dev_info,
                                                      std::bind(&mapping::process_completions, this,
                                                                std::placeholders::_1, std::placeholders::_2));
        }

        mapping(uint64_t volsize, uint32_t page_size, btree_super_block &btree_sb, comp_callback comp_cb) : comp_cb(comp_cb) {
            homeds::btree::BtreeConfig btree_cfg;
            btree_cfg.set_max_objs(volsize / page_size);
            btree_cfg.set_max_key_size(sizeof(uint32_t));
            btree_cfg.set_max_value_size(page_size);

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
        
        error_condition get(boost::intrusive_ptr<volume_req> req, MappingKey &key,
                            vector<pair<MappingKey, MappingValue>> &values) {
            MappingKey start_key(key.start(), 1);
            MappingKey end_key(key.end(), 1);
            auto search_range = BtreeSearchRange(start_key, true, end_key, true);
            GetCBParam param(req);
            vector<pair<MappingKey, MappingValue>> result_kv;
            BtreeQueryRequest<MappingKey, MappingValue>
                    qreq(search_range,
                         BtreeQueryType::SWEEP_NON_INTRUSIVE_PAGINATION_QUERY,
                         key.get_n_lba(),
                         std::bind(&mapping::match_item_cb_get, this,
                                   placeholders::_1, placeholders::_2,
                                   placeholders::_3),
                         (BRangeQueryCBParam<MappingKey, MappingValue> *) &param);
            m_bt->query(qreq, result_kv);

            //fill the gaps
            auto last_lba = key.start();
            for (auto i = 0u; i < result_kv.size(); i++) {
                int nl = result_kv[i].first.start() - last_lba;
                while (nl-- > 0) {
                    values.emplace_back(make_pair(MappingKey(last_lba, 1), EMPTY_MAPPING_VALUE));
                    last_lba++;
                }
                values.emplace_back(result_kv[i]);
                last_lba = result_kv[i].first.end() + 1;
            }
            while (last_lba <= key.end()) {
                values.emplace_back(make_pair(MappingKey(last_lba, 1), EMPTY_MAPPING_VALUE));
                last_lba++;
            }

#ifndef NDEBUG
            validate_get_response(key.start(), key.get_n_lba(), values);
#endif
            return no_error;
        }

        error_condition put(boost::intrusive_ptr<volume_req> req,
                            MappingKey &key, MappingValue &value) {
            LOGINFO("Mapping.PUT called {} {}", key.to_string(), value.to_string());
            assert(value.get_array().get_total_elements() == 1);
            UpdateCBParam param(req, key, value);
            MappingKey start(key.start(), 1);
            MappingKey end(key.end(), 1);

            auto search_range = BtreeSearchRange(start, true, end, true);
            BtreeUpdateRequest<MappingKey, MappingValue>
                    ureq(search_range,
                         bind(&mapping::match_item_cb_put, this,
                              placeholders::_1, placeholders::_2,
                              placeholders::_3),
                         (BRangeUpdateCBParam<MappingKey, MappingValue> *) &param);
            m_bt->range_put(key, value, PutType::APPEND_IF_EXISTS_ELSE_INSERT,
                            boost::static_pointer_cast<writeback_req>(req),
                            boost::static_pointer_cast<writeback_req>(req),
                            ureq);

            return no_error;
        }

        void print_tree() {
            m_bt->print_tree();
        }

    private:
        /**
         * Callback called once for each bnode
         * @param match_kv  - list of all match K/V for bnode (based on key.compare/compare_range)
         * @param result_kv - All KV which are passed backed to mapping.get by btree. Btree dosent use this.
         * @param cb_param -  All parameteres provided by mapping.get can be accessed from this
         */
        void match_item_cb_get(vector<pair<MappingKey, MappingValue>> &match_kv,
                               vector<pair<MappingKey, MappingValue>> &result_kv,
                               BRangeQueryCBParam<MappingKey, MappingValue> *cb_param) {
            uint64_t start_lba = 0, end_lba = 0;
            get_start_end_lba(cb_param, start_lba, end_lba);
            MappingKey eff_range(start_lba, end_lba - start_lba + 1);
            GetCBParam *param = (GetCBParam *) cb_param;
            assert(param->m_req->lastCommited_seqId <= param->m_req->seqId);
            ValueEntry new_ve;//empty

            for (auto i = 0u; i < match_kv.size(); i++) {
                auto &existing = match_kv[i];
                MappingKey *e_key = &existing.first;
                Blob_Array <ValueEntry> array = (&existing.second)->get_array();
                assert(array.get_total_elements() > 0);

                for (int i = array.get_total_elements() - 1; i >= 0; i--) {
                    // seqId use to filter out KVs with higher seqIds and put only latest seqid entry in result_kv
                    ValueEntry ve;
                    array.get((uint32_t) i, ve, true);
                    if (ve.get_seqId() <= param->m_req->lastCommited_seqId) {
                        if (i == 0) {
                            MappingKey overlap;
                            e_key->get_overlap(eff_range, overlap);

                            auto lba_offset = overlap.get_start_offset(*e_key);
                            if (lba_offset != 0) //partial overlap for first entry
                                ve.add_offset(lba_offset, overlap.get_n_lba(), m_vol_page_size, m_blkalloc_page_size);

                            result_kv.emplace_back(make_pair(overlap, MappingValue(ve)));
                        } else
                            result_kv.emplace_back(make_pair(MappingKey(*e_key), MappingValue(ve)));
                        break;
                    }
                }
            }
        }

        /**
         * Callback called onces for each eligible bnode
         * @param match_kv - list of all match K/V for bnode (based on key.compare/compare_range)
         * @param replace_kv - btree replaces all K/V in match_kv with replace_kv
         * @param cb_param - All parameteres provided by mapping.put can be accessed from this
         * 
         * We piggyback on put to delete old commited seq Id.
         */
        void match_item_cb_put(vector<pair<MappingKey, MappingValue>> &match_kv,
                               vector<pair<MappingKey, MappingValue>> &replace_kv,
                               BRangeUpdateCBParam<MappingKey, MappingValue> *cb_param) {

            uint64_t start_lba = 0, end_lba = 0;
            get_start_end_lba(cb_param, start_lba, end_lba);

            UpdateCBParam *param = (UpdateCBParam *) cb_param;
            assert(param->m_req->lastCommited_seqId <= param->m_req->seqId);

#ifndef NDEBUG
            stringstream ss;
            ss << "Lba:"<<param->m_req->lba << ",nlbas:" << param->m_req->nlbas
               << ",seqId:" << param->m_req->seqId << ",is_mod:" <<param->is_state_modifiable();
            ss << ",is:"<<((MappingKey*)param->get_input_range().get_start_key())->to_string();
            ss << ",ie:"<<((MappingKey*)param->get_input_range().get_end_key())->to_string();
            ss << ",ss:"<<((MappingKey*)param->get_sub_range().get_start_key())->to_string();
            ss << ",se:"<<((MappingKey*)param->get_sub_range().get_end_key())->to_string();
            ss << ",match_kv:" ;
            for(auto &ptr : match_kv) ss << ptr.first.to_string() << "==>" << ptr.second.to_string();
#endif
            ValueEntry new_ve;
            param->get_new_value().get_array().get(0, new_ve, false);

            MappingKey *s_in_range = (MappingKey *) param->get_input_range().get_start_key();
            auto last_lba = start_lba;
            for (auto i = 0u; i < match_kv.size(); i++) {
                auto &existing = match_kv[i];
                MappingKey *e_key = &existing.first;
                MappingValue *e_value = &existing.second;
                Blob_Array <ValueEntry> &array = e_value->get_array();

                if (e_key->start() > last_lba) //gap found 
                    add_missing_interval(last_lba, e_key->start() - 1, new_ve,
                                         last_lba - s_in_range->start(), replace_kv);
                auto j = 0u;
                while (j < array.get_total_elements()) {
                    //iterate array and remove elements<lastcommitedid, but still maintain one latest value entry
                    ValueEntry ve;
                    array.get(j, ve, false);
                    if (ve.get_seqId() < param->m_req->lastCommited_seqId) {
                        if(param->is_state_modifiable()) {
                            Free_Blk_Entry fbe(ve.get_blkId(), ve.get_blk_offset(), e_key->get_n_lba());
                            param->m_req->blkIds_to_free.emplace_back(fbe);
                        }
                        array.remove(j);
                    } else break;
                }

                add_overlaps(e_key, e_value, &(param->get_new_key()), &(param->get_new_value()), replace_kv);
                last_lba = e_key->end() + 1;
            }
            if (end_lba >= last_lba)//gap found 
                add_missing_interval(last_lba, end_lba, new_ve, last_lba - s_in_range->start(), replace_kv);
            // TODO merge entries - when neighbours lba/blk are consecutive and have only 1 value entry each

#ifndef NDEBUG
            ss << ", replace_kv:";
            for(auto &ptr : replace_kv) ss << ptr.first.to_string() << "==>" << ptr.second.to_string();
            if(param->is_state_modifiable())
             LOGINFO("Put CB completed: {} ", ss.str());
#endif
        }

        /** derieves current range of lba's based on input/sub range
            subrange means current bnodes start/end boundaries
            input_range is original client provided start/end, its always inclusive for mapping layer 
            Resulting start/end lba is always inclusive
            **/
        void get_start_end_lba(BRangeCBParam *param, uint64_t &start_lba, uint64_t &end_lba) {

            //pick higher start of subrange/inputrange
            MappingKey *s_subrange = (MappingKey *) param->get_sub_range().get_start_key();
            MappingKey *s_in_range = (MappingKey *) param->get_input_range().get_start_key();

            if (param->get_sub_range().is_start_inclusive())
                start_lba = max(s_subrange->end(), s_in_range->start());
            else
                start_lba = max(s_subrange->end() + 1, s_in_range->start());

            //pick lower end of subrange/inputrange
            MappingKey *e_subrange = (MappingKey *) param->get_sub_range().get_end_key();//end is always inclusive
            MappingKey *e_in_range = (MappingKey *) param->get_input_range().get_end_key();//inclusive

            if (param->get_sub_range().is_end_inclusive())
                end_lba = min(e_subrange->end(), e_in_range->end());
            else
                end_lba = min(e_subrange->end() - 1, e_in_range->end());

        }

        /** result of overlap of k1/k2 is added to replace_kv **/
        void add_overlaps(MappingKey *k1, MappingValue *v1, MappingKey *k2, MappingValue *v2,
                          vector<pair<MappingKey, MappingValue>> &replace_kv) {
            assert(v2->get_array().get_total_elements() == 1);

            auto start = k1->start();
            auto end = k1->end();
            if (k2->start() > start ) { //non overlaping start
                if(v1->get_array().get_total_elements() > 0)
                    replace_kv.emplace_back(make_pair(MappingKey(start, k2->start() - start), MappingValue(*v1)));
                start = k2->start();
            }
            if (k2->end() < k1->end()) { // non overlaping end
                auto lba_offset = k2->end() - k1->start();
                MappingKey key(k2->end() + 1, k1->end() - k2->end());
                if(v1->get_array().get_total_elements() > 0) {
                    MappingValue value;
                    v1->add_offset(lba_offset, key.get_n_lba(), m_vol_page_size, m_blkalloc_page_size, value);
                    replace_kv.emplace_back(make_pair(key, value));
                }
                end = k2->end();
            }
            assert(start >= k2->start() && start >= k1->start());
            assert(end <= k2->end() && end <= k1->end());

            //get entris from both v1/v2 and offset is needed for both of them
            MappingKey key3(start, end - start + 1);
            auto k1_offset = start - k1->start();
            auto k2_offset = start - k2->start();
            MappingValue temp_mv;
            if (v1->get_array().get_total_elements() > 0)
                v1->add_offset(k1_offset, k1->get_n_lba() - k1_offset, m_vol_page_size, m_blkalloc_page_size, temp_mv);
            ValueEntry new_ve;
            v2->get_array().get(0, new_ve, true);
            new_ve.add_offset(k2_offset, k2->get_n_lba() - k2_offset, m_vol_page_size, m_blkalloc_page_size);
            MappingValue value3;
            temp_mv.add(new_ve, value3);
            replace_kv.emplace_back(make_pair(key3, value3));

        }

        /**add missing interval to replace kv**/
        void add_missing_interval(uint64_t s_lba, uint64_t e_lba, ValueEntry &ve, uint16_t lba_offset,
                                  vector<pair<MappingKey, MappingValue>> &replace_kv) {
            ValueEntry gap_entry(ve);
            auto nlba = e_lba - s_lba + 1;
            gap_entry.add_offset(lba_offset, nlba, m_vol_page_size, m_blkalloc_page_size);
            replace_kv.emplace_back(make_pair(MappingKey(s_lba, nlba), MappingValue(gap_entry)));
        }

        class GetCBParam : public BRangeQueryCBParam<MappingKey, MappingValue> {
        public:
            boost::intrusive_ptr<volume_req> m_req;

            GetCBParam(boost::intrusive_ptr<volume_req> req)
                    : m_req(req) {}
        };

        class UpdateCBParam : public BRangeUpdateCBParam<MappingKey, MappingValue> {
        public:
            boost::intrusive_ptr<volume_req> m_req;

            UpdateCBParam(boost::intrusive_ptr<volume_req> req, MappingKey &new_key, MappingValue &new_value) :
                    BRangeUpdateCBParam(new_key, new_value), m_req(req) {}
        };

#ifndef NDEBUG
        void validate_get_response(uint64_t lba_start, uint32_t n_lba,
                                   vector<pair<MappingKey, MappingValue>> &values) {
            uint32_t fetch_no_lbas = 0;
            uint32_t i = 0;
            uint64_t last_slba = lba_start;
            std::stringstream ss;
            while (i < values.size()) {
                uint64_t curr_slba = values[i].first.start();
                uint64_t curr_elba = values[i].first.end();
                fetch_no_lbas += values[i].first.get_n_lba();
                if (curr_slba != last_slba) {
                    //gaps found
                    assert(0);
                }

                if (values[i].second.is_valid()) {
                    ValueEntry ve;
                    values[i].second.get_array().get(0, ve, false);

                    ss << "Start:" << values[i].first.start() << ",nlba:" << values[i].first.get_n_lba()
                       << ",BlkId:" << ve.get_blkId() << " && ";
                } else {
                    ss << "Invalid ";
                }
                last_slba = curr_elba + 1;
                i++;
            }
            assert(fetch_no_lbas == n_lba);
        }

#endif

    };
}

