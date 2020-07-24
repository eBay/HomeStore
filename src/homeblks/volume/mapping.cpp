#include <cstring>
#include "mapping.hpp"
#include "volume.hpp"

using namespace homestore;

uint64_t mapping::get_end_lba(uint64_t start_lba, uint64_t nlba) { return (start_lba + nlba - 1); }
uint64_t mapping::get_nlbas(uint64_t end_lba, uint64_t start_lba) {
    assert(end_lba >= start_lba);
    return (end_lba - start_lba + 1);
}
uint64_t mapping::get_blkid_offset(uint64_t lba_offset, uint64_t vol_page_size) {
    return ((vol_page_size / HomeBlks::instance()->get_data_pagesz()) * lba_offset);
}

uint64_t mapping::get_next_start_lba(uint64_t start_lba, uint64_t nlba) { return (start_lba + nlba); }

uint64_t mapping::get_nlbas_from_cursor(uint64_t start_lba, BtreeQueryCursor& cur) {
    auto mapping_key = (MappingKey*)(cur.m_last_key.get());
    if (!mapping_key->end()) { return 0; }
    return get_nlbas(mapping_key->end(), start_lba);
}

uint64_t mapping::get_end_key_from_cursor(BtreeQueryCursor& cur) {
    auto mapping_key = (MappingKey*)(cur.m_last_key.get());
    assert(mapping_key->start() == mapping_key->end());
    return (mapping_key->end());
}

uint64_t mapping::get_next_start_key_from_cursor(BtreeQueryCursor& cur) {
    auto mapping_key = (MappingKey*)(cur.m_last_key.get());
    assert(mapping_key->start() == mapping_key->end());
    return (mapping_key->end() + 1);
}

mapping::mapping(uint64_t volsize, uint32_t page_size, const std::string& unique_name,
                 trigger_cp_callback trigger_cp_cb, pending_read_blk_cb pending_read_cb) :
        m_pending_read_blk_cb(pending_read_cb), m_vol_page_size(page_size), m_unique_name(unique_name) {
    m_vol_size = volsize;
    m_hb = HomeBlks::safe_instance();
    homeds::btree::BtreeConfig btree_cfg(HS_STATIC_CONFIG(disk_attr.atomic_phys_page_size), unique_name.c_str());
    btree_cfg.set_max_objs(volsize / page_size);
    btree_cfg.set_max_key_size(sizeof(uint32_t));
    btree_cfg.set_max_value_size(page_size);
    btree_cfg.blkstore = (void*)m_hb->get_index_blkstore();
    btree_cfg.trigger_cp_cb = trigger_cp_cb;

    m_bt = MappingBtreeDeclType::create_btree(btree_cfg);
}

mapping::mapping(uint64_t volsize, uint32_t page_size, const std::string& unique_name, btree_super_block btree_sb,
                 trigger_cp_callback trigger_cp_cb, pending_read_blk_cb pending_read_cb,
                 btree_cp_superblock* btree_cp_sb) :
        m_pending_read_blk_cb(pending_read_cb), m_vol_page_size(page_size), m_unique_name(unique_name) {
    m_vol_size = volsize;
    m_hb = HomeBlks::safe_instance();
    homeds::btree::BtreeConfig btree_cfg(HS_STATIC_CONFIG(disk_attr.atomic_phys_page_size), unique_name.c_str());
    btree_cfg.set_max_objs(volsize / page_size);
    btree_cfg.set_max_key_size(sizeof(uint32_t));
    btree_cfg.set_max_value_size(page_size);
    btree_cfg.blkstore = (void*)m_hb->get_index_blkstore();
    btree_cfg.trigger_cp_cb = trigger_cp_cb;

    m_bt = MappingBtreeDeclType::create_btree(btree_sb, btree_cfg, btree_cp_sb);
}

mapping::~mapping() { delete m_bt; }

btree_status_t mapping::get(volume_req* req, std::vector< std::pair< MappingKey, MappingValue > >& values,
                            bool fill_gaps) {
    mapping_op_cntx cntx;
    cntx.op = READ_VAL_WITH_SEQID;
    cntx.u.vreq = req;
    MappingKey key(req->lba(), req->nlbas());
    BtreeQueryCursor cur;
    return (get(cntx, key, cur, values, fill_gaps));
}

btree_status_t mapping::get(mapping_op_cntx& cntx, MappingKey& key, BtreeQueryCursor& cur,
                            std::vector< std::pair< MappingKey, MappingValue > >& values, bool fill_gaps) {
    uint64_t start_lba;
    if (cur.m_last_key != nullptr) { // last key will be null for first read or if no read happened in the last read
        start_lba = get_next_start_key_from_cursor(cur);
    } else {
        start_lba = key.start();
    }

    uint64_t end_lba;
    if (cntx.op == FREE_ALL_USER_BLKID) {
        assert(!fill_gaps);
        end_lba = m_vol_size / m_vol_page_size;
    } else {
        end_lba = key.end();
    }
    auto start_key = MappingKey(start_lba, 1);
    auto end_key = MappingKey(end_lba, 1);
    auto search_range = BtreeSearchRange(start_key, true, end_key, true); // it doesn't accept the extent key
    GetCBParam param(cntx);
    std::vector< pair< MappingKey, MappingValue > > result_kv;

    BtreeQueryRequest< MappingKey, MappingValue > qreq(
        search_range, BtreeQueryType::SWEEP_NON_INTRUSIVE_PAGINATION_QUERY, get_nlbas(end_lba, start_lba),
        bind(&mapping::match_item_cb_get, this, placeholders::_1, placeholders::_2, placeholders::_3),
        (BRangeQueryCBParam< MappingKey, MappingValue >*)&param);
    auto ret = m_bt->query(qreq, result_kv);

    /* TODO : we should store the pointer inside cb_param */
    cntx = param.m_ctx;

    /* Note : btree returns the last key it read. */
    if (ret != btree_status_t::success) {
        assert(ret == btree_status_t::resource_full || ret == btree_status_t::fast_path_not_possible);
        if (qreq.cursor().m_last_key) {
            /* partial read happened */
            end_lba = get_end_key_from_cursor(qreq.cursor());
            assert(get_end_key_from_cursor(qreq.cursor()) == result_kv.back().first.end());
        } else {
            /* it means no read has happened */
            assert(result_kv.size() == 0);
            end_lba = UINT64_MAX; // end lba is invalid
        }
    }

    cur = std::move(qreq.cursor());
    if (fill_gaps && end_lba != UINT64_MAX) {
        // fill the gaps
        auto last_lba = start_lba;
        for (auto i = 0u; i < result_kv.size(); i++) {
            int nl = result_kv[i].first.start() - last_lba;
            while (nl-- > 0) {
                values.emplace_back(make_pair(MappingKey(last_lba, 1), EMPTY_MAPPING_VALUE));
                last_lba++;
            }
            values.emplace_back(result_kv[i]);
            last_lba = result_kv[i].first.end() + 1;
        }
        while (last_lba <= end_lba) {
            values.emplace_back(make_pair(MappingKey(last_lba, 1), EMPTY_MAPPING_VALUE));
            last_lba++;
        }
#ifndef NDEBUG
        validate_get_response(start_lba, get_nlbas(end_lba, start_lba), values);
#endif
    } else {
        values.insert(values.begin(), result_kv.begin(), result_kv.end());
    }
    return ret;
}

/* Note :- we should not write same IO in btree multiple times. When a key is updated , it update the free blk
 * entries in request to its last value. If we write same io multiple times then it could end up freeing the wrong
 * blocks.
 * @cur :-  points to first lba which is not written.
 */
btree_status_t mapping::put(mapping_op_cntx& cntx, MappingKey& key, MappingValue& value, const btree_cp_id_ptr& cp_id,
                            BtreeQueryCursor& cur) {
    assert(value.get_array().get_total_elements() == 1);

    /* value is stored in updateCBParam and actual range is also stored in cb param. range stored in here
     * is not same as search range. search range is taken from the cur and range here is taken from
     * the actual key.
     */
    UpdateCBParam param(cntx, key, value);
    uint64_t start_lba;
    if (cur.m_last_key != nullptr) { // last key will be null for first read or if no read happened in the last read
        start_lba = get_next_start_key_from_cursor(cur);
    } else {
        start_lba = key.start();
    }
    MappingKey start(start_lba, 1);
    MappingKey end(key.end(), 1);

    auto search_range = BtreeSearchRange(start, true, end, true); // range key is store here
    BtreeUpdateRequest< MappingKey, MappingValue > ureq(
        search_range, bind(&mapping::match_item_cb_put, this, placeholders::_1, placeholders::_2, placeholders::_3),
        bind(&mapping::get_size_needed, this, placeholders::_1, placeholders::_2),
        (BRangeUpdateCBParam< MappingKey, MappingValue >*)&param);
    auto ret = m_bt->range_put(key, value, btree_put_type::APPEND_IF_EXISTS_ELSE_INSERT, ureq, cp_id);

    assert(ret == btree_status_t::success || ret == btree_status_t::fast_path_not_possible ||
           ret == btree_status_t::resource_full || ret == btree_status_t::cp_id_mismatch);

    /* update start_lba to which this range is updated. It is helpful in cases of partial writes. */
    uint64_t next_start_lba = ((MappingKey*)(ureq.get_input_range().get_start_key()))->start();
    next_start_lba = ureq.get_input_range().is_start_inclusive() ? next_start_lba : next_start_lba + 1;

    if (next_start_lba != start_lba) { // don't update cursor if nothing is written
        assert(next_start_lba > start_lba);
        cur.m_last_key = std::make_unique< MappingKey >(MappingKey(next_start_lba - 1, 1)); // cursor always points to
                                                                                            // the last updated key
    }

    if (ret != btree_status_t::success) {
        /* In range update, it can be written paritally. Find the first key in this range which is not updated */
        return ret;
    }
    assert(next_start_lba == key.end() + 1);
#if 0
    vector< pair< MappingKey, MappingValue > > values;
    uint64_t temp;
    if (req) {
        auto temp = req->lastCommited_seqId;
        req->lastCommited_seqId = req->seqId;
    }
    get(req, values);
    if (req) { req->lastCommited_seqId = temp; }
    validate_get_response(key.start(), key.get_n_lba(), values, &value, req);
#endif
    return btree_status_t::success;
}

void mapping::print_tree() { m_bt->print_tree(); }
bool mapping::verify_tree() { return m_bt->verify_tree(); }

/**
 * @brief : Fix a btree by :
 *      1. Create a new btree,
 *      2. Iterating it's leaf node chain,
 *      3. Add every K, V in leaf node into the new btree;
 *      4. Delete in-memory copy of the old btree;
 *
 * @param start_lba : start lba of to recover the btree;
 * @param end_lba   : end lba of to recover the btree
 * @param verify    : if true, verify the new btree after recover by comparing the leaf
 *                    node KVs between the old and new btrees;
 *                    if false, skip verification of the newly created btree;
 *
 * @return : true if btree is succesfully recovered;
 *           false if failed to recover;
 * Note:
 * No need to call old btree destroy() as blocks will be freed automatically;
 */
bool mapping::fix(const btree_cp_id_ptr& cp_id, uint64_t start_lba, uint64_t end_lba, bool verify) {
#if 0
    if (start_lba >= end_lba) {
        LOGERROR("Wrong input, start_lba: {}, should be smaller than end_lba: {}", start_lba, end_lba);
        return false;
    }

    LOGINFO("Fixing btree, start_lba: {}, end_lba: {}", start_lba, end_lba);
    /* TODO : enable it later */
    // create a new btree
    auto btree_cfg = m_bt->get_btree_cfg();
    auto new_bt = MappingBtreeDeclType::create_btree(btree_cfg);

    m_fix_state = true;
    m_outstanding_io = 0;

    uint64_t num_kv_recovered = 0;
    auto start = start_lba, end = std::min(start_lba + lba_query_cnt, end_lba);
    while (start <= end && end <= end_lba) {
        // get all the KVs from existing btree;
        volume_req* vreq = volume_req::make_request();
        vreq->lba = start;
        vreq->nlbas = num_lba(end, start);
        vreq->seqId = INVALID_SEQ_ID;
        vreq->lastCommited_seqId = INVALID_SEQ_ID;

        std::vector< std::pair< MappingKey, MappingValue > > kvs;
        auto ret = get(vreq, kvs, false /* fill_gaps */);
        if (ret != no_error) {
            LOGERROR("failed to get KVs from btree");
            return false;
        }

        // put every KV to new btree we have got from old btree;
        for (auto& x : kvs) {
            auto ret = put(nullptr, x.first, x.second, cp_id, new_bt);
            if (ret != btree_status_t::success) {
                LOGERROR("failed to put node with k/v: {}/{}", x.first.to_string(), x.second.to_string());
                return false;
            }
            LOGINFO("Successfully inserted K:{}, \n V:{}.", x.first.to_string(), x.second.to_string());
        }

        num_kv_recovered += kvs.size();
        start = end + 1;
        end = std::min(start + lba_query_cnt, end_lba);
    }
    LOGINFO("Successfully recovered num: {} of K,V pairs from corrupted btree.", num_kv_recovered);

    if (verify) {
        auto verify_status = verify_fixed_bt(start_lba, end_lba, m_bt, new_bt);
        if (!verify_status) {
            delete new_bt;
            return false;
        }
    }

    auto old_bt = m_bt;
    m_bt = new_bt;
    delete old_bt;

    while (m_outstanding_io != 0) {
        sleep(2);
    }

    // reset fix state to false
    m_fix_state = false;
#endif
    return true;
}

/**
 * @brief : verify that the all the KVs in range [start_lba, end_lba] are the same between old_bt and new_bt
 *
 * @param start_lba : start lba
 * @param end_lba : end lba
 * @param old_bt : the old btree to be compared
 * @param new_bt : the new btree to be compared
 *
 * @return : true if all the KVs are the same between the two btrees;
 *           false if not;
 */
bool mapping::verify_fixed_bt(uint64_t start_lba, uint64_t end_lba, MappingBtreeDeclType* old_bt,
                              MappingBtreeDeclType* new_bt) {
#if 0
    uint64_t num_kv_verified = 0;
    auto start = start_lba, end = std::min(start_lba + lba_query_cnt, end_lba);
    while (start <= end_lba) {
        assert(start <= end);
        std::vector< std::pair< MappingKey, MappingValue > > kvs_old;
        std::vector< std::pair< MappingKey, MappingValue > > kvs_new;

        // now m_bt points to the new btree;
        auto ret_old = get(nullptr, kvs_old, old_bt);
        auto ret_new = get(nullptr, kvs_new, new_bt);

        if (ret_old != no_error || ret_new != no_error) {
            LOGERROR("btree_fix verify failed, reason: get from btree KVs failed.");
            return false;
        }

        if (kvs_new.size() != kvs_old.size()) {
            LOGERROR("btree_fix verify failed, reason: mismatch total number of KV old: {} new: {}", kvs_old.size(),
                     kvs_new.size());

            LOGINFO("Printing KVs for old and new btree tree for lba range: [{}, {}]", start, end);
            print_kv(kvs_old);
            print_kv(kvs_new);
            return false;
        }

        for (uint64_t i = 0; i < kvs_old.size(); i++) {
            if (kvs_old[i].first.to_string().compare(kvs_new[i].first.to_string()) != 0 ||
                kvs_old[i].second.to_string().compare(kvs_new[i].second.to_string()) != 0) {
                LOGERROR("btree_fix verify failed, reason: mismatch KV pair old K: {}, V: {}, new K: {}, V: {}",
                         kvs_old[i].first.to_string(), kvs_new[i].first.to_string(), kvs_old[i].second.to_string(),
                         kvs_new[i].second.to_string());
                return false;
            }
        }
        num_kv_verified += kvs_new.size();
        start = end + 1;
        end = std::min(start + lba_query_cnt, end_lba);
    }

    LOGINFO("Successfully verified recovered btree, total KV verified: {}", num_kv_verified);
#endif
    return true;
}

void mapping::print_kv(std::vector< std::pair< MappingKey, MappingValue > >& kvs) {
    LOGINFO("Total Elements: {}", kvs.size());
    uint32_t i = 0;
    for (auto& x : kvs) {
        LOGINFO("No. {} : K: {}, V: {}", i++, x.first.to_string(), x.second.to_string());
    }
    LOGINFO("Finished Printing. ");
}

void mapping::print_node(uint64_t blkid) { m_bt->print_node(blkid); }

/**
 * Callback called once for each bnode
 * @param match_kv  - list of all match K/V for bnode (based on key.compare/compare_range)
 * @param result_kv - All KV which are passed backed to mapping.get by btree. Btree dosent use this.
 * @param cb_param -  All parameteres provided by mapping.get can be accessed from this
 */
btree_status_t mapping::match_item_cb_get(std::vector< std::pair< MappingKey, MappingValue > >& match_kv,
                                          std::vector< std::pair< MappingKey, MappingValue > >& result_kv,
                                          BRangeQueryCBParam< MappingKey, MappingValue >* cb_param) {
    uint64_t start_lba = 0, end_lba = 0;
    get_start_end_lba(cb_param, start_lba, end_lba);
    GetCBParam* param = (GetCBParam*)cb_param;

    ValueEntry new_ve; // empty
#ifndef NDEBUG
    stringstream ss;
    /* For map load test vol instance is null */
    ss << ",is:" << ((MappingKey*)param->get_input_range().get_start_key())->to_string();
    ss << ",ie:" << ((MappingKey*)param->get_input_range().get_end_key())->to_string();
    ss << ",ss:" << ((MappingKey*)param->get_sub_range().get_start_key())->to_string();
    ss << ",se:" << ((MappingKey*)param->get_sub_range().get_end_key())->to_string();
    ss << ",match_kv:";
    for (auto& ptr : match_kv) {
        ss << ptr.first.to_string() << "," << ptr.second.to_string();
    }
#endif

    for (auto i = 0u; i < match_kv.size(); i++) {
        auto& existing = match_kv[i];
        MappingKey* e_key = &existing.first;
        Blob_Array< ValueEntry > array = (&existing.second)->get_array();
        std::vector< Free_Blk_Entry > fbe_list;
        MappingKey overlap;
        e_key->get_overlap(start_lba, end_lba, overlap);
        auto lba_offset = overlap.get_start_offset(*e_key);

        for (int j = array.get_total_elements() - 1; j >= 0; j--) {
            // seqId use to filter out KVs with higher seqIds and put only latest seqid entry in result_kv
            ValueEntry ve;
            array.get((uint32_t)j, ve, true);

            ve.add_offset(lba_offset, overlap.get_n_lba(), m_vol_page_size);
            if (param->m_ctx.op == READ_VAL_WITH_SEQID) {
                if (ve.get_seqId() == INVALID_SEQ_ID || ve.get_seqId() <= param->m_ctx.seqId) {
                    result_kv.emplace_back(make_pair(overlap, MappingValue(ve)));
                    if (m_pending_read_blk_cb && param->m_ctx.u.vreq) {
                        Free_Blk_Entry fbe(ve.get_blkId());
                        m_pending_read_blk_cb(fbe); // mark this blk as pending read
                    }
                    break;
                }
            } else if (param->m_ctx.op == FREE_ALL_USER_BLKID) {
                /* free all the blkids */
                HS_SUBMOD_LOG(DEBUG, volume, , "vol", m_unique_name, "Free Blk: vol_page: {}, data_page: {}, n_lba: {}",
                              m_vol_page_size, HomeBlks::instance()->get_data_pagesz(), ve.get_nlba());
                uint64_t nblks = (m_vol_page_size / HomeBlks::instance()->get_data_pagesz()) * ve.get_nlba();
                Free_Blk_Entry fbe(ve.get_blkId(), ve.get_blk_offset(), nblks);
                fbe_list.push_back(fbe);
            } else {
                assert(0);
            }
        }

        if (param->m_ctx.op == FREE_ALL_USER_BLKID && fbe_list.size() > 0) {
            uint64_t size = IndxMgr::free_blk(nullptr, param->m_ctx.u.free_list, fbe_list, false);
            assert(size != 0);
            if (size > 0) {
                param->m_ctx.free_blk_size += size;
                ValueEntry ve; // create a default value
                /* TODO : we should only add last key */
                result_kv.emplace_back(make_pair(overlap, MappingValue(ve)));
            } else {
                return btree_status_t::resource_full;
            }
        }
    }
#ifndef NDEBUG
    ss << ",result_kv:";
    for (auto& ptr : result_kv) {
        ss << ptr.first.to_string() << "," << ptr.second.to_string();
    }
    if (param->m_ctx.u.vreq) {
        HS_SUBMOD_LOG(TRACE, volume, param->m_ctx.u.vreq, "vol", m_unique_name, "Get_CB: {} ", ss.str());
    } else {
        HS_SUBMOD_LOG(TRACE, volume, , "vol", m_unique_name, "Get_CB: {} ", ss.str());
    }
#endif
    return btree_status_t::success;
}

/* It calculate the offset in a value by looking at start lba */
uint32_t mapping::compute_val_offset(BRangeUpdateCBParam< MappingKey, MappingValue >* cb_param, uint64_t start_lba) {
    uint64_t input_start_lba = ((UpdateCBParam*)cb_param)->m_start_lba;
    return (start_lba - input_start_lba);
}

uint32_t mapping::get_size_needed(std::vector< std::pair< MappingKey, MappingValue > >& match_kv,
                                  BRangeUpdateCBParam< MappingKey, MappingValue >* cb_param) {

    UpdateCBParam* param = (UpdateCBParam*)cb_param;
    MappingValue& new_val = param->get_new_value();
    int overlap_entries = match_kv.size();

    /* In worse case, one value is divided into (2 * overlap_entries + 1). Same meta data of a value (it is
     * fixed size) will be copied to all new entries.
     */
    uint32_t new_size = (overlap_entries + 1) * new_val.meta_size() + new_val.get_blob_size();
    return new_size;
}

/* Callback called onces for each eligible bnode
 * @param match_kv - list of all match K/V for bnode (based on key.compare/compare_range)
 * @param replace_kv - btree replaces all K/V in match_kv with replace_kv
 * @param cb_param - All parameteres provided by mapping.put can be accessed from this
 *
 * We piggyback on put to delete old commited seq Id.
 */
btree_status_t mapping::match_item_cb_put(std::vector< std::pair< MappingKey, MappingValue > >& match_kv,
                                          std::vector< std::pair< MappingKey, MappingValue > >& replace_kv,
                                          BRangeUpdateCBParam< MappingKey, MappingValue >* cb_param) {

    uint64_t start_lba = 0, end_lba = 0;
    UpdateCBParam* param = (UpdateCBParam*)cb_param;
    std::vector< Free_Blk_Entry > fbe_list;

    get_start_end_lba(cb_param, start_lba, end_lba);
    auto cntx = param->m_cntx;
    struct volume_req* req = nullptr;
    if (cntx.op == op_type::UPDATE_VAL_AND_FREE_BLKS) { req = cntx.u.vreq; }
    MappingValue& new_val = param->get_new_value();
    /* get sequence ID of this value */
    Blob_Array< ValueEntry >& new_varray = new_val.get_array();
    ValueEntry new_ve;
    new_varray.get(0, new_ve, false);
    uint64_t new_seq_id = new_ve.get_seqId();

#ifndef NDEBUG
    stringstream ss;
    if (req) {
        ss << "Lba:" << req->lba() << ",nlbas:" << req->nlbas() << ",seqId:" << req->seqId
           << ",last_seqId:" << req->lastCommited_seqId << ",is_mod:" << param->is_state_modifiable();
    }
    ss << ",is:" << ((MappingKey*)param->get_input_range().get_start_key())->to_string();
    ss << ",ie:" << ((MappingKey*)param->get_input_range().get_end_key())->to_string();
    ss << ",ss:" << ((MappingKey*)param->get_sub_range().get_start_key())->to_string();
    ss << ",se:" << ((MappingKey*)param->get_sub_range().get_end_key())->to_string();
    ss << ",match_kv:";
    for (auto& ptr : match_kv) {
        ss << ptr.first.to_string() << "," << ptr.second.to_string();
    }
#endif
    /* We don't change BLKID in value. Instead we store offset of lba range that we are storing */
    uint32_t initial_val_offset = compute_val_offset(cb_param, start_lba);
    uint32_t new_val_offset = initial_val_offset;

    for (auto& existing : match_kv) {
        MappingKey* e_key = &existing.first;
        MappingValue* e_value = &existing.second;
        uint32_t existing_val_offset = 0;

        Blob_Array< ValueEntry >& e_varray = e_value->get_array();
        ValueEntry ve;
        e_varray.get(0, ve, false);
        uint64_t seq_id = ve.get_seqId();
        if (new_seq_id <= seq_id) {
            /* it is the latest entry, we should not override it */
            replace_kv.emplace_back(existing.first, existing.second);
            auto nlbas = ve.get_nlba();
            if (cntx.op == op_type::UPDATE_VAL_AND_FREE_BLKS) {
                Blob_Array< ValueEntry >& new_varray = new_val.get_array();
                ValueEntry ve;
                new_varray.get(0, ve, false);
                /* free new blkid. it is overridden */
                Free_Blk_Entry fbe(ve.get_blkId(), new_val_offset,
                                   (m_vol_page_size / HomeBlks::instance()->get_data_pagesz()) * nlbas);
                fbe_list.push_back(fbe);
            }
            start_lba += nlbas;
            new_val_offset += nlbas;
            continue;
        }

        if (e_key->start() > start_lba) {
            /* add missing interval */
            add_new_interval(start_lba, e_key->start() - 1, new_val, new_val_offset, replace_kv);
            new_val_offset += e_key->start() - start_lba;
            start_lba = e_key->start();
        }

        /* enable it when snapshot comes */
#if 0
        /* Truncate the existing value based on seq ID */
        e_value->truncate(req);
#endif
        /* we need to split the existing key/value at the start */
        if (e_key->start() < start_lba) {
            /* It will always be the first entry */
            assert(new_val_offset == initial_val_offset);
            // split existing key at the start and add new interval
            add_new_interval(e_key->start(), start_lba - 1, *e_value, existing_val_offset, replace_kv);
            existing_val_offset += start_lba - e_key->start();
        }

        /* Now both intervals have the same start */
        // compute overlap
        auto end_lba_overlap = e_key->end() < end_lba ? e_key->end() : end_lba;
        compute_and_add_overlap(cntx.op, fbe_list, start_lba, end_lba_overlap, new_val, new_val_offset, *e_value,
                                existing_val_offset, replace_kv);
        uint32_t nlbas = get_nlbas(end_lba_overlap, start_lba);
        new_val_offset += nlbas;
        existing_val_offset += nlbas;
        start_lba += nlbas;

        if (e_key->end() > end_lba) {
            assert(start_lba == end_lba + 1);
            // split existing key at the end and add new interval
            add_new_interval(start_lba, e_key->end(), *e_value, existing_val_offset, replace_kv);
        }
    }

    if (start_lba <= end_lba) { // add new range
        add_new_interval(start_lba, end_lba, new_val, new_val_offset, replace_kv);
    }

    btree_status_t ret = btree_status_t::success;
    if (cntx.op == op_type::UPDATE_VAL_AND_FREE_BLKS) {
        req->indx_push_fbe(fbe_list);
    } else {
        /* add trim code */
    }

// TODO - merge kv which have contigous lba and BlkIds - may be not that useful for performance
#ifndef NDEBUG
    /* sanity check */
    for (auto& pair : replace_kv) {
        Blob_Array< ValueEntry >& array = pair.second.get_array();

        auto i = 0u;
        while (i < array.get_total_elements()) {
            ValueEntry curve;
            array.get(i, curve, false);
            if (i != 0) { // sorted ve check
                ValueEntry preve;
                array.get(i - 1, preve, false);
                assert(preve.compare(&curve) > 0);
            }
            assert(curve.get_nlba() == pair.first.get_n_lba());
            if (same_value_gen) {
                // same values can be generated for different keys in some test cases
                ++i;
                continue;
            }
            if (!req) {
                ++i;
                continue;
            }
#if 0
            // check if replace entries dont overlap free entries
            auto blk_start = curve.get_blkId().get_id() + curve.get_blk_offset();
            auto blk_end =
                blk_start + (m_vol_page_size / HomeBlks::instance()->get_data_pagesz()) * curve.get_nlba() - 1;
            req->init_fbe_iterator();
            while (auto fbe = req->get_next_fbe()) {
                if (fbe->m_blkId.get_chunk_num() != curve.get_blkId().get_chunk_num()) { continue; }
                auto fblk_start = fbe->m_blkId.get_id() + fbe->m_blk_offset;
                auto fblk_end = fblk_start + fbe->m_nblks_to_free - 1;
                if (blk_end < fblk_start || fblk_end < blk_start) {
                } // non overlapping
                else {
                    ss << ",replace_kv:";
                    for (auto& ptr : replace_kv) {
                        ss << ptr.first.to_string() << "," << ptr.second.to_string();
                    }
                    HS_SUBMOD_ASSERT(DEBUG, 0, , "vol", m_unique_name, "Error::Put_CB:,{} ", ss.str());
                }
            }
#endif
            i++;
        }
    }
    ss << ",replace_kv:";
    for (auto& ptr : replace_kv) {
        ss << ptr.first.to_string() << "," << ptr.second.to_string();
    }
    if (req) {
        HS_SUBMOD_LOG(TRACE, volume, req, "vol", m_unique_name, "{}", ss.str());
    } else {
        HS_SUBMOD_LOG(TRACE, volume, , "vol", m_unique_name, "{}", ss.str());
    }
#endif
    return ret;
}

/* derieves current range of lba's based on input/sub range
 * subrange means current bnodes start/end boundaries
 * input_range is original client provided start/end, its always inclusive for mapping layer
 * Resulting start/end lba is always inclusive
 */
void mapping::get_start_end_lba(BRangeCBParam * param, uint64_t & start_lba, uint64_t & end_lba) {

    // pick higher start of subrange/inputrange
    MappingKey* s_subrange = (MappingKey*)param->get_sub_range().get_start_key();
    assert(s_subrange->start() == s_subrange->end());

    if (param->get_sub_range().is_start_inclusive()) {
        start_lba = s_subrange->start();
    } else {
        start_lba = s_subrange->start() + 1;
    }

    MappingKey* e_subrange = (MappingKey*)param->get_sub_range().get_end_key();
    assert(e_subrange->start() == e_subrange->end());
    if (param->get_sub_range().is_end_inclusive()) {
        end_lba = e_subrange->end();
    } else {
        end_lba = e_subrange->end() - 1;
    }
}

/* add missing interval to replace kv */
void mapping::add_new_interval(uint64_t s_lba, uint64_t e_lba, MappingValue& val, uint16_t lba_offset,
                               std::vector< std::pair< MappingKey, MappingValue > >& replace_kv) {
    auto nlba = get_nlbas(e_lba, s_lba);
    replace_kv.emplace_back(make_pair(MappingKey(s_lba, nlba), MappingValue(val, lba_offset, nlba, m_vol_page_size)));
}

/* result of overlap of k1/k2 is added to replace_kv */
void mapping::compute_and_add_overlap(op_type update_op, std::vector< Free_Blk_Entry > fbe_list, uint64_t s_lba,
                                      uint64_t e_lba, MappingValue & new_val, uint16_t new_val_offset,
                                      MappingValue & e_val, uint16_t e_val_offset,
                                      std::vector< std::pair< MappingKey, MappingValue > > & replace_kv) {

    auto nlba = get_nlbas(e_lba, s_lba);

    /* This code assumes that there is only one value entry */
    Blob_Array< ValueEntry >& e_varray = e_val.get_array();
    ValueEntry ve;
    e_varray.get(0, ve, false);
    uint16_t blk_offset = (e_val_offset * m_vol_page_size) / HomeBlks::instance()->get_data_pagesz();
    if (update_op == op_type::UPDATE_VAL_AND_FREE_BLKS) {
        Free_Blk_Entry fbe(ve.get_blkId(), ve.get_blk_offset() + blk_offset,
                           (m_vol_page_size / HomeBlks::instance()->get_data_pagesz()) * nlba);
        fbe_list.push_back(fbe);
    }

    replace_kv.emplace_back(
        make_pair(MappingKey(s_lba, nlba), MappingValue(new_val, new_val_offset, nlba, m_vol_page_size)));
}


#ifndef NDEBUG
void mapping::validate_get_response(uint64_t lba_start, uint32_t n_lba,
                                    std::vector< std::pair< MappingKey, MappingValue > >& values,
                                    MappingValue* exp_value, volume_req* req) {
    uint32_t i = 0;
    uint64_t last_slba = lba_start;
    uint8_t last_bid_offset = 0;
    BlkId expBid;
    if (exp_value != nullptr) {
        ValueEntry ve;
        exp_value->get_array().get(0, ve, false);
        expBid = ve.get_blkId();
    }
    while (i < values.size()) {
        if (values[i].first.start() != last_slba) {
            m_bt->print_tree();
            std::this_thread::sleep_for(std::chrono::seconds(5));

            if (req) { // do it again to trace
                std::vector< std::pair< MappingKey, MappingValue > > values;
                auto temp = req->lastCommited_seqId;
                req->lastCommited_seqId = req->seqId;
                MappingKey key(lba_start, n_lba);
                get(req, values);
                req->lastCommited_seqId = temp;
            }

            assert(0); // gaps found
        }
        if (exp_value != nullptr) {
            ValueEntry ve;
            assert(values[i].second.get_array().get_total_elements() == 1);
            values[i].second.get_array().get(0, ve, false);

            if (!values[i].second.is_valid() || ve.get_blkId().get_id() != expBid.get_id() ||
                ve.get_blk_offset() != last_bid_offset) {
                m_bt->print_tree();
                std::this_thread::sleep_for(std::chrono::seconds(10));
                assert(0);
            }
            last_bid_offset += values[i].first.get_n_lba() * (m_vol_page_size / m_hb->get_data_pagesz());
        }
        last_slba = values[i].first.end() + 1;
        i++;
    }
    assert(last_slba == lba_start + n_lba);
}
#endif

void mapping::create_done() { m_bt->create_done(); }
uint64_t mapping::get_used_size() { return m_bt->get_used_size(); }
btree_super_block mapping::get_btree_sb() { return (m_bt->get_btree_sb()); }

btree_cp_id_ptr mapping::attach_prepare_cp(const btree_cp_id_ptr& cur_cp_id, bool is_last_cp,
                                           bool blkalloc_checkpoint) {
    return (m_bt->attach_prepare_cp(cur_cp_id, is_last_cp, blkalloc_checkpoint));
}

void mapping::cp_start(const btree_cp_id_ptr& cp_id, cp_comp_callback cb) { m_bt->cp_start(cp_id, cb); }

void mapping::truncate(const btree_cp_id_ptr& cp_id) { m_bt->truncate(cp_id); }

void mapping::cp_done(trigger_cp_callback cb) { MappingBtreeDeclType::cp_done(cb); }

void mapping::destroy_done() { m_bt->destroy_done(); }
void mapping::flush_free_blks(const btree_cp_id_ptr& btree_id,
                              std::shared_ptr< homestore::blkalloc_cp_id >& blkalloc_id) {
    m_bt->flush_free_blks(btree_id, blkalloc_id);
}
void mapping::update_btree_cp_sb(const btree_cp_id_ptr& cp_id, btree_cp_superblock& btree_sb, bool blkalloc_cp) {
    m_bt->update_btree_cp_sb(cp_id, btree_sb, blkalloc_cp);
}

btree_status_t mapping::update_diff_indx_tbl(indx_req* ireq, const btree_cp_id_ptr& btree_id) {
    return (update_indx_tbl(ireq, btree_id, false));
}

btree_status_t mapping::update_active_indx_tbl(indx_req* ireq, const btree_cp_id_ptr& btree_id) {
    return (update_indx_tbl(ireq, btree_id, true));
}

/* it populats the allocated blkids in index req. It might not be the same as in volume req if entry is partially
 * written.
 */
void mapping::update_indx_alloc_blkids(indx_req* ireq) {
    uint32_t total_lbas = 0;
    auto vreq = static_cast< volume_req* >(ireq);
    /* XXX: Can this assert be hit. it means nothing is written to active btree */
    assert(vreq->active_btree_cur.m_last_key);
    auto end_lba = get_end_key_from_cursor(vreq->active_btree_cur);
    auto lbas_written = get_nlbas(end_lba, vreq->lba());
    for (uint32_t i = 0; i < vreq->alloc_blkid_list.size(); ++i) {
        auto blkid = vreq->alloc_blkid_list[i];
        uint32_t page_size = vreq->vol()->get_page_size();
        uint32_t nlbas = blkid.data_size(HomeBlks::instance()->get_data_pagesz()) / page_size;
        if (total_lbas + nlbas >= lbas_written) {
            /* it is written only upto this blkid */
            auto size_written = (lbas_written - total_lbas) * vreq->vol()->get_page_size();
            auto blkid_written =
                blkid.get_blkid_at(0 /* offset */, size_written, HomeBlks::instance()->get_data_pagesz());
            vreq->push_indx_alloc_blkid(blkid_written);
            break;
        }
        total_lbas += nlbas;
        vreq->push_indx_alloc_blkid(blkid);
    }
}

btree_status_t mapping::update_indx_tbl(indx_req* ireq, const btree_cp_id_ptr& btree_id, bool active_btree_update) {
    auto vreq = static_cast< volume_req* >(ireq);
    uint64_t start_lba = vreq->lba();
    int csum_indx = 0;
    uint64_t next_start_lba = start_lba;
    uint64_t end_lba;
    auto btree_cur_ptr = (active_btree_update ? &vreq->active_btree_cur : &vreq->diff_btree_cur);

    /* we will start from the same place where it is left last time */
    if (active_btree_update) {
        end_lba = get_end_lba(start_lba, vreq->nlbas());
    } else {
        /* we don't write more then what is written in active btree. */
        /* XXX: Can this assert be hit. it means nothing is written to active btree */
        assert(vreq->active_btree_cur.m_last_key);
        end_lba = get_end_key_from_cursor(vreq->active_btree_cur);
        assert(end_lba >= start_lba);
    }
    if (btree_cur_ptr->m_last_key) { next_start_lba = get_next_start_key_from_cursor(*btree_cur_ptr); }
    assert(end_lba <= get_end_lba(start_lba, vreq->nlbas()));

    btree_status_t ret = btree_status_t::success;

    for (uint32_t i = 0; i < vreq->alloc_blkid_list.size(); ++i) {
        auto blkid = vreq->alloc_blkid_list[i];
        uint32_t nlbas = blkid.data_size(HomeBlks::instance()->get_data_pagesz()) / m_vol_page_size;

        if (start_lba < next_start_lba) {
            if (get_end_lba(start_lba, nlbas) < next_start_lba) {
                start_lba += nlbas;
                csum_indx += nlbas;
                /* skip this write as it is already written */
                continue;
            }

            /* For partially written range , it will be taken care automically by cursor */
        }

        if (get_end_lba(start_lba, nlbas) > end_lba) {
            /* we don't write more then what is updated in active btree */
            nlbas = get_nlbas(end_lba, start_lba);
        }
        MappingKey key(start_lba, nlbas);
        ValueEntry ve(vreq->seqId, blkid, 0 /* blk offset */, nlbas, &vreq->csum_list[csum_indx]);
        MappingValue value(ve);

        /* if snapshot is disabled then cntx would be different. XXX : do we need to suppprt snapshot disable */
        mapping_op_cntx cntx;
        if (active_btree_update && 0) {
            cntx.op = UPDATE_VAL_ONLY;
        } else {
            cntx.op = UPDATE_VAL_AND_FREE_BLKS;
            cntx.u.vreq = vreq;
        }

        ret = put(cntx, key, value, btree_id, *btree_cur_ptr);

        start_lba += nlbas;
        csum_indx += nlbas;
        if (ret != btree_status_t::success || start_lba > end_lba) { break; }
        assert(start_lba == (get_end_key_from_cursor(*btree_cur_ptr) + 1));
    }

    assert(ret != btree_status_t::success || (start_lba == (end_lba + 1)));
    return ret;
}

btree_status_t mapping::recovery_update(logstore_seq_num_t seqnum, journal_hdr* hdr, const btree_cp_id_ptr& btree_id) {
    /* get all the values from journal entry */
    auto key = (journal_key*)indx_journal_entry::get_key(hdr).first;
    assert(indx_journal_entry::get_key(hdr).second == sizeof(journal_key));
    uint64_t lba = key->lba;
    BlkId* bid = indx_journal_entry::get_alloc_bid_list(hdr).first;
    uint32_t nbid = indx_journal_entry::get_alloc_bid_list(hdr).second;
    uint16_t* csum = (uint16_t*)indx_journal_entry::get_val(hdr).first;
    uint32_t ncsum = indx_journal_entry::get_val(hdr).second / sizeof(uint16_t);
    assert(ncsum == key->nlbas);

    /* uodate btree */
    uint32_t csum_indx = 0;
    btree_status_t ret = btree_status_t::success;
    for (uint32_t i = 0; i < nbid; ++i) {
        uint32_t nlbas = bid[i].data_size(HomeBlks::instance()->get_data_pagesz()) / m_vol_page_size;
        MappingKey key(lba, nlbas);
        ValueEntry ve(seqnum, bid[i], 0, nlbas, &csum[csum_indx]);
        MappingValue value(ve);
        uint64_t next_start_lba;
        mapping_op_cntx cntx;
        cntx.op = UPDATE_VAL_ONLY;
        BtreeQueryCursor cur;
        ret = put(cntx, key, value, btree_id, cur);
        assert(ret == btree_status_t::success);
        lba += nlbas;
        csum_indx += nlbas;
    }
    assert(lba == key->lba + key->nlbas);
    return ret;
}

btree_status_t mapping::free_user_blkids(blkid_list_ptr free_list, BtreeQueryCursor& cur, int64_t& size) {
    uint64_t start_lba = 0;
    if (cur.m_last_key) { start_lba = get_next_start_key_from_cursor(cur); }
    mapping_op_cntx cntx;
    cntx.op = FREE_ALL_USER_BLKID;
    cntx.u.free_list = free_list.get();

    MappingKey key(start_lba, 1);
    std::vector< std::pair< MappingKey, MappingValue > > values;
    auto ret = get(cntx, key, cur, values, false);
    size = cntx.free_blk_size;
    return ret;
}

btree_status_t mapping::unmap(blkid_list_ptr free_list, BtreeQueryCursor& cur) { return btree_status_t::success; }

void mapping::get_btreequery_cur(const sisl::blob& b, BtreeQueryCursor& cur) {
    cur.m_last_key = std::make_unique< MappingKey >(MappingKey());
    cur.m_last_key->set_blob(b);
};

btree_status_t mapping::destroy(blkid_list_ptr& free_blkid_list, uint64_t& free_node_cnt) {
    auto ret = btree_status_t::success;
    HS_SUBMOD_ASSERT(LOGMSG, (ret == btree_status_t::success), , "vol", m_unique_name,
                     "Error in destroying mapping btree ret={} ", ret);
    ret = m_bt->destroy(free_blkid_list, free_node_cnt);
    assert(ret == btree_status_t::success);
    return btree_status_t::success;
}
