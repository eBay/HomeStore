#include "mapping.hpp"

namespace homestore {

    class mapping {
        typedef std::function<void(struct BlkId blkid)> free_blk_callback;
        typedef std::function<void(boost::intrusive_ptr<volume_req> cookie)> comp_callback;
    private:
        MappingBtreeDeclType *m_bt;

        free_blk_callback free_blk_cb;
        comp_callback comp_cb;

    public:
        void process_completions(boost::intrusive_ptr<writeback_req> cookie,
                                 std::error_condition status) {
            boost::intrusive_ptr<volume_req> req =
                    boost::static_pointer_cast<volume_req>(cookie);

            if (req->status == no_error) {
                req->status = status;
            }
            if (req->num_mapping_update.fetch_sub(1, std::memory_order_release) == 1) {
                comp_cb(req);
            }
        }

        mapping(uint32_t volsize, free_blk_callback free_cb, comp_callback comp_cb,
                DeviceManager *mgr, Cache<BlkId> *cache) : free_blk_cb(free_cb), comp_cb(comp_cb) {
            assert(BIT_TO_REPRESENT_MAX_ENTRIES > log2(MAX_NO_OF_VALUE_ENTRIES));
            homeds::btree::BtreeConfig btree_cfg;
            btree_cfg.set_max_objs(volsize / (MAX_NO_OF_VALUE_ENTRIES * MAP_BLOCK_SIZE));
            btree_cfg.set_max_key_size(sizeof(uint32_t));
            btree_cfg.set_max_value_size(MAX_NO_OF_VALUE_ENTRIES * sizeof(MappingInterval));

            homeds::btree::btree_device_info bt_dev_info;
            bt_dev_info.new_device = true;
            bt_dev_info.dev_mgr = mgr;
            bt_dev_info.size = 512 * Mi;
            bt_dev_info.cache = cache;
            bt_dev_info.vb = nullptr;
            m_bt = MappingBtreeDeclType::create_btree(btree_cfg, &bt_dev_info,
                                                      std::bind(&mapping::process_completions, this,
                                                                std::placeholders::_1, std::placeholders::_2));
        }

        void add_lba(MappingInterval &offBlk, bool found, uint64_t actual_lba,
                     std::vector<std::shared_ptr<Lba_Block>> &mappingList) {
            mappingList.push_back(std::make_shared<Lba_Block>(offBlk, actual_lba, found));
        }

        void add_dummy_for_missing_mappings(uint64_t start_lba, uint64_t end_lba,
                                            std::vector<std::shared_ptr<Lba_Block>> &mappingList) {
            while (start_lba <= end_lba) {
                mappingList.push_back(std::make_shared<Lba_Block>(0, 1, 0, BlkId(0, 1, 0), start_lba, false));
                start_lba++;
            }
        }

        void print_tree() {
            m_bt->print_tree();
        }

        std::error_condition get(uint64_t start_lba, uint32_t nblks,
                                 std::vector<std::shared_ptr<Lba_Block>> &mappingList) {
            LOGTRACE("mapping.get called with :{}:{}", start_lba, nblks);
            std::error_condition error = no_error;
            bool atleast_one_lba_found = false;
            bool atleast_one_lba_not_found = false;

            uint64_t curr_lba = start_lba;
            uint64_t end_lba = start_lba + nblks - 1;//inclusive

            while (curr_lba <= end_lba) {
                int range_offset = curr_lba / MAX_NO_OF_VALUE_ENTRIES; // key for btree
                uint64_t start_lba_for_range =
                        range_offset * MAX_NO_OF_VALUE_ENTRIES; // start actual lba for this range
                uint64_t end_lba_for_range =
                        ((range_offset + 1) * MAX_NO_OF_VALUE_ENTRIES) - 1; // end actual lba for this range

                // offset inside the current lba range, this would always be zero except for first window
                uint16_t start_offset = curr_lba - start_lba_for_range;
                uint16_t end_offset = MAX_NO_OF_VALUE_ENTRIES - 1;

                if (end_lba < end_lba_for_range) {
                    //we dont need all ranges in this key
                    end_offset -= (end_lba_for_range - end_lba);
                }
                //look up key/value from btree
                MappingKey key(range_offset);
                MappingValue value;
                bool ret = m_bt->get(key, &value);

                //find all matching values 
                std::vector<std::shared_ptr<MappingInterval> > valueOffsetToBlkIdLst;
                if (ret) {
                    value.get(start_offset, end_offset, valueOffsetToBlkIdLst);
                }

                int i = 0;
                // iterate all values found and fill in the gaps
                while (i < (int) valueOffsetToBlkIdLst.size()) {
                    uint64_t curr_range_start_lba = start_lba_for_range + valueOffsetToBlkIdLst[i]->m_interval_start;
                    uint64_t curr_range_end_lba =
                            curr_range_start_lba + valueOffsetToBlkIdLst[i]->m_interval_length - 1;
                    assert(curr_range_start_lba >= curr_lba && curr_range_start_lba >= start_lba);

                    //fill the gaps
                    if (curr_lba < curr_range_start_lba) {
                        add_dummy_for_missing_mappings(curr_lba, curr_range_start_lba - 1, mappingList);
                        atleast_one_lba_not_found = true;
                    }
                    //add the range found
                    mappingList.push_back(std::make_shared<Lba_Block>(*(valueOffsetToBlkIdLst[i].get()),
                                                                      curr_range_start_lba, true));
                    atleast_one_lba_found = true;

                    curr_lba = curr_range_end_lba + 1;
                    i++;
                }
                if (curr_lba <= end_lba_for_range && curr_lba <= end_lba) {
                    //gather remaining lba's which are not found
                    if (end_lba < end_lba_for_range) end_lba_for_range = end_lba;
                    add_dummy_for_missing_mappings(curr_lba, end_lba_for_range, mappingList);
                    atleast_one_lba_not_found = true;
                    curr_lba = end_lba_for_range + 1;
                }
            }
#ifndef NDEBUG
            validate_get_response(start_lba, nblks, mappingList);
#endif
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

#ifndef NDEBUG

        void validate_get_response(uint64_t start_lba, uint32_t num_lbas,
                                   std::vector<std::shared_ptr<Lba_Block>> &mappingList) {

            uint32_t fetch_no_lbas = 0;
            uint32_t i = 0;
            uint64_t last_slba = start_lba;
            while (i < mappingList.size()) {
                uint64_t curr_slba = mappingList[i]->m_actual_lba;
                uint64_t curr_elba = curr_slba + mappingList[i]->m_interval_length - 1;
                fetch_no_lbas += mappingList[i]->m_interval_length;
                if (curr_slba != last_slba) {
                    //gaps found
                    assert(0);
                }
                last_slba = curr_elba + 1;
                i++;
            }
            assert(fetch_no_lbas == num_lbas);
        }

#endif

        std::error_condition put(boost::intrusive_ptr<volume_req> req,
                                 uint64_t lba_uint, uint32_t nblks, struct BlkId blkid) {
            LOGTRACE("mapping.put called with :{}:{}:{}", lba_uint, nblks, blkid.to_string());

            uint64_t lba = lba_uint;
            uint16_t block_offset = 0;
            int total_blocks = nblks;

            //iterate till all blocks are put
            req->num_mapping_update++;
            while (total_blocks != 0) {
                uint64_t range_offset = lba / MAX_NO_OF_VALUE_ENTRIES; // key for btree
                uint64_t start_lba_for_range =
                        range_offset * MAX_NO_OF_VALUE_ENTRIES; // start actual lba for this range
                uint64_t end_lba_for_range =
                        ((range_offset + 1) * MAX_NO_OF_VALUE_ENTRIES) - 1; // end actual lba for this range
                // offset inside the current lba range, this would always be zeor except for first window
                uint16_t value_internal_offset = lba - start_lba_for_range;
                assert(value_internal_offset < MAX_NO_OF_VALUE_ENTRIES);
                MappingKey key(range_offset);
                //see if we have reached almost end of nblks needed.
                uint64_t no_of_offset =
                        (uint64_t) total_blocks > (end_lba_for_range - lba + 1) ? (end_lba_for_range - lba + 1)
                                                                                : total_blocks;
                assert(value_internal_offset + no_of_offset - 1 < MAX_NO_OF_VALUE_ENTRIES);

                MappingValue value(value_internal_offset, no_of_offset, block_offset, blkid);

                req->num_mapping_update++;

                std::shared_ptr<BtreeValue> existing_val = static_pointer_cast<BtreeValue>(
                        std::make_shared<MappingValue>());
                m_bt->put(key, value,
                          homeds::btree::APPEND_IF_EXISTS_ELSE_INSERT, boost::static_pointer_cast<writeback_req>(req),
                          boost::static_pointer_cast<writeback_req>(req), existing_val);

                //find blks to free
                MappingValue *mappingValue = (MappingValue *) existing_val.get();
                std::vector<std::shared_ptr<MappingInterval>> offsetToBlkIdLst;
                mappingValue->get_all(offsetToBlkIdLst);
                for (std::shared_ptr<MappingInterval> offBlkId :offsetToBlkIdLst) {
                    std::shared_ptr<Free_Blk_Entry> fbe =
                            std::make_shared<Free_Blk_Entry>(
                                    offBlkId->m_value.m_blkid,
                                    (uint16_t) offBlkId->m_value.m_blkid_offset,
                                    (uint16_t) offBlkId->m_interval_length);
                    assert(offBlkId->m_value.m_blkid_offset + offBlkId->m_interval_length <=
                           offBlkId->m_value.m_blkid.get_nblks());
                    req->blkids_to_free_due_to_overwrite.push_back(fbe);
                }

                lba = end_lba_for_range + 1;
                assert(no_of_offset > 0);
                total_blocks -= no_of_offset;
                block_offset += no_of_offset;
                assert(total_blocks >= 0);
            }
            if (req->num_mapping_update.fetch_sub(1, std::memory_order_release) == 1) {
                comp_cb(req);
            }

            return homestore::no_error;
        }
    };
}
