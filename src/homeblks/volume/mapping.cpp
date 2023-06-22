/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 *********************************************************************************/
#include <chrono>
#include <cstring>
#include <thread>

#include <fmt/format.h>
#include "mapping.hpp"
#include "volume.hpp"

using namespace homestore;

lba_t mapping::get_end_lba(const lba_t start_lba, const lba_count_t nlba) { return (start_lba + nlba - 1); }

lba_count_t mapping::get_nlbas(const lba_t end_lba, const lba_t start_lba) {
    HS_REL_ASSERT_GE(end_lba, start_lba);
    return (end_lba - start_lba + 1);
}

#if 0
uint64_t mapping::get_blkid_offset(uint64_t lba_offset, uint64_t vol_page_size) {
    return ((vol_page_size / HomeBlks::instance()->get_data_pagesz()) * lba_offset);
}
#endif

lba_t mapping::get_next_start_lba(const lba_t start_lba, const lba_count_t nlba) { return (start_lba + nlba); }

lba_count_t mapping::get_nlbas_from_cursor(const lba_t start_lba, const BtreeQueryCursor& cur) {
    const auto mapping_key = (MappingKey*)(cur.m_last_key.get());
    if (mapping_key) { return get_nlbas(mapping_key->end(), start_lba); }
    return 0;
}

lba_t mapping::get_end_key_from_cursor(const BtreeQueryCursor& cur) {
    const auto mapping_key = (MappingKey*)(cur.m_last_key.get());
    return (mapping_key->end());
}

lba_t mapping::get_next_start_key_from_cursor(const BtreeQueryCursor& cur) {
    const auto mapping_key = (MappingKey*)(cur.m_last_key.get());
    return (mapping_key->end() + 1);
}

mapping::mapping(const uint64_t volsize, const uint32_t page_size, const std::string& unique_name,
                 const trigger_cp_callback& trigger_cp_cb, const pending_read_blk_cb& pending_read_cb) :
        m_pending_read_blk_cb{pending_read_cb},
        m_vol_page_size{page_size},
        m_unique_name{unique_name},
        m_vol_size{volsize} {
    m_hb = HomeBlks::safe_instance();
    m_blks_per_lba = page_size / m_hb->get_data_pagesz();
    m_match_item_cb_put = bind_this(mapping::match_item_cb_put, 4);
    m_match_item_cb_get = bind_this(mapping::match_item_cb_get, 4);
    m_get_size_needed = bind_this(mapping::get_size_needed, 2);

    // create btree
    // TO DO: Might need to differentiate based on data or fast type
    homeds::btree::BtreeConfig btree_cfg(m_hb->get_index_blkstore()->get_vdev()->get_atomic_page_size(),
                                         unique_name.c_str());
    btree_cfg.set_max_objs(volsize / page_size);
    btree_cfg.set_max_key_size(sizeof(uint32_t));
    btree_cfg.set_max_value_size(page_size);
    btree_cfg.blkstore = (void*)m_hb->get_index_blkstore();
    btree_cfg.trigger_cp_cb = trigger_cp_cb;

    m_bt = MappingBtreeDeclType::create_btree(btree_cfg);
    if (!m_bt) { throw homestore::homestore_exception("btree creation failed", homestore_error::no_space_avail); }

    m_sobject = m_hb->sobject_mgr()->create_object("mapping", m_unique_name,
                                                   std::bind(&mapping::get_status, this, std::placeholders::_1));
}

mapping::mapping(const uint64_t volsize, const uint32_t page_size, const std::string& unique_name,
                 const btree_super_block& btree_sb, const trigger_cp_callback& trigger_cp_cb,
                 const pending_read_blk_cb& pending_read_cb, btree_cp_sb* btree_cp_sb) :
        m_pending_read_blk_cb{pending_read_cb},
        m_vol_page_size{page_size},
        m_unique_name{unique_name},
        m_vol_size{volsize} {
    m_hb = HomeBlks::safe_instance();
    m_blks_per_lba = page_size / m_hb->get_data_pagesz();
    m_match_item_cb_put = bind_this(mapping::match_item_cb_put, 4);
    m_match_item_cb_get = bind_this(mapping::match_item_cb_get, 4);
    m_get_size_needed = bind_this(mapping::get_size_needed, 2);

    // create btree
    // TO DO: Might need to differentiate based on data or fast type
    homeds::btree::BtreeConfig btree_cfg(m_hb->get_index_blkstore()->get_vdev()->get_atomic_page_size(),
                                         unique_name.c_str());
    btree_cfg.set_max_objs(volsize / page_size);
    btree_cfg.set_max_key_size(sizeof(uint32_t));
    btree_cfg.set_max_value_size(page_size);
    btree_cfg.blkstore = (void*)m_hb->get_index_blkstore();
    btree_cfg.trigger_cp_cb = trigger_cp_cb;

    m_bt = MappingBtreeDeclType::create_btree(btree_sb, btree_cfg, btree_cp_sb,
                                              std::bind(&mapping::split_key_recovery, this, placeholders::_1,
                                                        placeholders::_2, placeholders::_3, placeholders::_4));
    m_sobject = m_hb->sobject_mgr()->create_object("mapping", m_unique_name,
                                                   std::bind(&mapping::get_status, this, std::placeholders::_1));
}

mapping::~mapping() { delete m_bt; }

void mapping::split_key_recovery(const MappingKey& key, const MappingValue& val, const MappingKey& split_key,
                                 std::vector< std::pair< MappingKey, MappingValue > >& replace_kv) {
    HS_REL_ASSERT_EQ(split_key.start(), split_key.end());
    HS_REL_ASSERT_LE(key.start(), split_key.start());
    HS_REL_ASSERT_GT(key.end(), split_key.end());
    auto start_lba = key.start();
    auto end_lba = split_key.end();
    uint16_t offset = 0;

    /* split it into two */
    add_new_interval(start_lba, end_lba, val, offset, replace_kv);

    offset += get_nlbas(end_lba, start_lba);
    start_lba = end_lba + 1;
    end_lba = key.end();

    add_new_interval(start_lba, end_lba, val, offset, replace_kv);
}

std::string mapping::get_cp_flush_status(const btree_cp_ptr& bcp) { return (m_bt->get_cp_flush_status(bcp)); }

btree_status_t mapping::read_indx(const indx_req_ptr& ireq, const read_indx_comp_cb_t& read_cb) {
    auto vreq = static_cast< volume_req* >(ireq.get());
    std::vector< std::pair< MappingKey, MappingValue > > values;

    auto ret = get(vreq, vreq->result_kv);

    if (!vreq->first_read_indx_call) {
        /* it should not be incremented multiple times */
        vreq->first_read_indx_call = true;
        vreq->outstanding_io_cnt.increment(1); // it will be decremented in read_cb
    }

    // don't expect to see "has_more" return value in read path;
    HS_DBG_ASSERT_NE(ret, btree_status_t::has_more);

    if (ret == btree_status_t::success) {
        // otherwise send callbacks to client for each K/V;
        read_cb(ireq, no_error);
    } else if (ret == btree_status_t::fast_path_not_possible) {
        // in slow path, return to caller to trigger slow path;
    } else {
        // callback to volume for this read failure;
        // could be here for both fast and slow path;
        auto hs_ret = (ret == btree_status_t::crc_mismatch) ? homestore_error::btree_crc_mismatch
                                                            : homestore_error::btree_read_failed;

        read_cb(ireq, hs_ret);
    }

    return ret;
}

btree_status_t mapping::get(volume_req* req, std::vector< std::pair< MappingKey, MappingValue > >& values) {
    mapping_op_cntx cntx;
    cntx.op = READ_VAL_WITH_seqid;
    cntx.vreq = req;
    MappingKey key(req->lba(), req->nlbas());
    return (get(cntx, key, req->read_cur, values));
}

btree_status_t mapping::get(MappingKey& key, BtreeQueryCursor& cur,
                            std::vector< std::pair< MappingKey, MappingValue > >& values) {
    mapping_op_cntx cntx;
    cntx.op = READ_VAL_WITH_seqid;
    cntx.vreq = nullptr;
    return (get(cntx, key, cur, values));
}

btree_status_t mapping::get(mapping_op_cntx& cntx, MappingKey& key, BtreeQueryCursor& cur,
                            std::vector< std::pair< MappingKey, MappingValue > >& result_kv) {
    /* initialize the search range */
    lba_t end_lba = (cntx.op == FREE_ALL_USER_BLKID) ? m_vol_size / m_vol_page_size : key.end();

    HS_SUBMOD_LOG(DEBUG, volume, , "vol", m_unique_name, "GET : lba_range[{}-{}]", key.start(), end_lba);
    const auto start_key = MappingKey(key.start(), 1);
    const auto end_key = MappingKey(end_lba, 1);
    auto search_range = BtreeSearchRange(start_key, true, end_key, true, &cur); // it doesn't accept the extent key

    /* create query */
    GetCBParam param(cntx);
    BtreeQueryRequest< MappingKey, MappingValue > qreq(search_range,
                                                       BtreeQueryType::SWEEP_NON_INTRUSIVE_PAGINATION_QUERY, UINT32_MAX,
                                                       m_match_item_cb_get, dynamic_cast< BRangeCBParam* >(&param));

    /* run query */
    auto ret = m_bt->query(qreq, result_kv);

    if (ret != btree_status_t::success) {
        HS_SUBMOD_LOG(INFO, volume, , "vol", m_unique_name, "GET : start_lba {} end lba {} ret {}", key.start(),
                      end_lba, ret);
    }
#ifndef NDEBUG
    for (uint32_t i = 0; i < result_kv.size(); ++i) {
        HS_SUBMOD_LOG(DEBUG, volume, , "vol", m_unique_name, "GET : start_lba {} end lba {} value {}",
                      result_kv[i].first.start(), result_kv[i].first.end(), result_kv[i].second.to_string());
    }
#endif

    HS_SUBMOD_LOG(DEBUG, volume, , "vol", m_unique_name, "GET complete : end key from cursor {}", end_lba);
    return ret;
}

/* Note :- we should not write same IO in btree multiple times. When a key is updated , it update the free blk
 * entries in request to its last value. If we write same io multiple times then it could end up freeing the wrong
 * blocks.
 * @cur :-  points to first lba which is not written.
 */
btree_status_t mapping::put(mapping_op_cntx& cntx, MappingKey& key, MappingValue& value, const btree_cp_ptr& bcp,
                            BtreeQueryCursor& cur) {
    HS_DBG_ASSERT_EQ(value.get_total_entries(), 1);

    HS_SUBMOD_LOG(DEBUG, volume, , "vol", m_unique_name, "PUT : start_lba {} end lba {} value {}", key.start(),
                  key.end(), value.to_string());
    /* create search range */
    // last key will be null for first read or if no read happened in the last
    lba_t start_lba = (cur.m_last_key != nullptr) ? get_next_start_key_from_cursor(cur) : key.start();
    lba_t end_lba = key.end();
    const MappingKey start(start_lba, 1);
    const MappingKey end(key.end(), 1);
    auto search_range = BtreeSearchRange(start, true, end, true, &cur); // range key is store here

    /* create update req */
    UpdateCBParam param(cntx, key, value);
    BtreeUpdateRequest< MappingKey, MappingValue > ureq(search_range, m_match_item_cb_put, m_get_size_needed,
                                                        (BRangeCBParam*)&param);

    /* start range put */
    auto ret = m_bt->range_put(btree_put_type::APPEND_IF_EXISTS_ELSE_INSERT, ureq, bcp);

    if (cur.m_last_key != nullptr) {
        HS_REL_ASSERT_GE(get_next_start_key_from_cursor(cur), start_lba);
        HS_REL_ASSERT_LE(get_next_start_key_from_cursor(cur), (end_lba + 1));
    }
    /* we should not get resource full error */
    if (ret != btree_status_t::success) {
        HS_SUBMOD_LOG(INFO, volume, , "vol", m_unique_name, "PUT : start_lba {} end lba {} ret {}", key.start(),
                      end_lba, ret);
    }

    /* In range update, it can be written paritally. Find the first key in this range which is not updated */
    return ret;
#if 0
    vector< pair< MappingKey, MappingValue > > values;
    uint64_t temp;
    if (req) {
        auto temp = req->lastCommited_seqid;
        req->lastCommited_seqid = req->seqid;
    }
    get(req, values);
    if (req) { req->lastCommited_seqid = temp; }
    validate_get_response(key.start(), key.get_n_lba(), values, &value, req);
#endif
}

uint64_t mapping::get_btree_node_cnt() { return m_bt->get_btree_node_cnt(); }
void mapping::print_tree() { m_bt->print_tree(); }
bool mapping::verify_tree(bool update_debug_bm) { return m_bt->verify_tree(update_debug_bm); }

sisl::status_response mapping::get_status(const sisl::status_request& request) { return m_bt->get_status(request); }

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
bool mapping::fix(const btree_cp_ptr& bcp, const lba_t start_lba, const lba_t end_lba, bool verify) {
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
        vreq->seqid = INVALID_SEQ_ID;
        vreq->lastCommited_seqid = INVALID_SEQ_ID;

        std::vector< std::pair< MappingKey, MappingValue > > kvs;
        auto ret = get(vreq, kvs, false /* fill_gaps */);
        if (ret != no_error) {
            LOGERROR("failed to get KVs from btree");
            delete new_bt;
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
        std::this_thread::sleep_for(std::chrono::seconds{2});
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
bool mapping::verify_fixed_bt(const lba_t start_lba, const lba_t end_lba, MappingBtreeDeclType* old_bt,
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

void mapping::print_kv(const std::vector< std::pair< MappingKey, MappingValue > >& kvs) const {
    LOGINFO("Total Elements: {}", kvs.size());
    uint32_t i{0};
    for (const auto& x : kvs) {
        LOGINFO("No. {} : K: {}, V: {}", i++, x.first.to_string(), x.second.to_string());
    }
    LOGINFO("Finished Printing. ");
}

void mapping::print_node(const bnodeid_t& blkid) { m_bt->print_node(blkid); }

/**
 * Callback called once for each bnode
 * @param match_kv  - list of all match K/V for bnode (based on key.compare/compare_range)
 * @param result_kv - All KV which are passed backed to mapping.get by btree. Btree dosent use this.
 * @param cb_param -  All parameteres provided by mapping.get can be accessed from this
 */
btree_status_t mapping::match_item_cb_get(std::vector< std::pair< MappingKey, MappingValue > >& match_kv,
                                          std::vector< std::pair< MappingKey, MappingValue > >& result_kv,
                                          BRangeCBParam* cb_param, BtreeSearchRange& subrange) {
    GetCBParam* param = (GetCBParam*)cb_param;

#ifndef NDEBUG
    auto str = fmt::format("ss={},se={},match_kv=[", ((MappingKey*)subrange.get_start_key())->to_string(),
                           ((MappingKey*)subrange.get_end_key())->to_string());
    for (const auto& [mk, mv] : match_kv) {
        fmt::format_to(std::back_inserter(str), "[{}],[{}]", mk.to_string(), mv.to_string());
    }
    fmt::format_to(std::back_inserter(str), "]");
#endif

    auto [start_lba, end_lba] = get_start_end_lba(subrange);
    for (const auto& [e_key, e_val] : match_kv) {
        std::vector< Free_Blk_Entry > fbe_list;
        MappingKey overlap;
        e_key.get_overlap(start_lba, end_lba, overlap);
        auto lba_offset = overlap.get_start_offset(e_key);

        for (int j = e_val.get_total_entries() - 1; j >= 0; j--) {
            // seqid use to filter out KVs with higher seqids and put only latest seqid entry in result_kv
            MappingValue new_val = e_val.extract(j);
            ValueEntry* ve = new_val.get_nth_entry((uint32_t)j);
            ve->add_offset(lba_offset, overlap.get_n_lba());

            if (param->m_ctx->op == READ_VAL_WITH_seqid) {
                if (param->m_ctx->seqid == INVALID_SEQ_ID || ve->get_seqid() <= param->m_ctx->seqid) {
                    result_kv.emplace_back(make_pair(overlap, new_val));
                    if (m_pending_read_blk_cb && param->m_ctx->vreq && ve->get_base_blkid().is_valid()) {
                        Free_Blk_Entry fbe(ve->get_base_blkid());
                        m_pending_read_blk_cb(fbe); // mark this blk as pending read
                    }
                    break;
                }
            } else if (param->m_ctx->op == FREE_ALL_USER_BLKID) {
                /* free all the blkids */
                HS_SUBMOD_LOG(DEBUG, volume, , "vol", m_unique_name,
                              "Free Blk: blks_per_lba, n_lba: {} start lba {} end lba {} lba offset {}", m_blks_per_lba,
                              ve->get_num_lbas(), overlap.start(), overlap.end(), lba_offset);
                if (ve->get_base_blkid().is_valid()) {
                    const Free_Blk_Entry fbe(ve->get_base_blkid(), ve->get_blk_offset(m_blks_per_lba),
                                             ve->get_num_blks(m_blks_per_lba));
                    fbe_list.push_back(fbe);
                }
            } else {
                assert(false);
            }
        }

        if (param->m_ctx->op == FREE_ALL_USER_BLKID && fbe_list.size() > 0) {
            uint64_t size = IndxMgr::free_blk(nullptr, param->m_ctx->free_list, fbe_list, false);
            HS_SUBMOD_LOG(DEBUG, volume, , "vol", m_unique_name, "size : {}", size);
            if (size > 0) {
                param->m_ctx->free_blk_size += size;
                /* TODO : we should only add last key */
                result_kv.emplace_back(make_pair(overlap, MappingValue(0, BlkId{}))); // Create default value
            } else {
                LOGINFO("failing because of resource_full error");
                return btree_status_t::resource_full;
            }
        }
    }
#ifndef NDEBUG
    fmt::format_to(std::back_inserter(str), ",result_kv:[");
    for (const auto& [mk, mv] : result_kv) {
        fmt::format_to(std::back_inserter(str), "[{}],[{}]", mk.to_string(), mv.to_string());
    }
    fmt::format_to(std::back_inserter(str), "]");

    if (param->m_ctx->vreq) {
        HS_SUBMOD_LOG(TRACE, volume, param->m_ctx->vreq, "vol", m_unique_name, "Get_CB: {} ", str);
    } else {
        HS_SUBMOD_LOG(TRACE, volume, , "vol", m_unique_name, "Get_CB: {} ", str);
    }
#endif
    return btree_status_t::success;
}

/* It calculate the offset in a value by looking at start lba */
lba_count_t mapping::compute_val_offset(BRangeCBParam* cb_param, const lba_t start_lba) {
    const lba_t input_start_lba = ((UpdateCBParam*)cb_param)->m_start_lba;
    return (start_lba - input_start_lba);
}

uint32_t mapping::get_size_needed(const std::vector< std::pair< MappingKey, MappingValue > >& match_kv,
                                  BRangeCBParam* cb_param) const {
    UpdateCBParam* param = (UpdateCBParam*)cb_param;
    const MappingValue& new_val = param->get_new_value();
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
                                          BRangeCBParam* cb_param, BtreeSearchRange& subrange) {
    UpdateCBParam* param = (UpdateCBParam*)cb_param;
    std::vector< Free_Blk_Entry > fbe_list;

    auto cntx = param->m_cntx;
    struct volume_req* req{nullptr};
    if (cntx->op == op_type::UPDATE_VAL_AND_FREE_BLKS) { req = cntx->vreq; }
    const MappingValue& new_val = param->get_new_value();

    /* get sequence ID of this value */
    const ValueEntry* new_ve = new_val.get_latest_entry();
    const seq_id_t new_seq_id = new_ve->get_seqid();

#ifndef NDEBUG
    std::string str;
    if (req) {
        fmt::format_to(std::back_inserter(str), "Lba={},nlbas={},seqid={},last_seqid={} ", req->lba(), req->nlbas(),
                       req->seqid, req->lastCommited_seqid);
    }
    fmt::format_to(std::back_inserter(str), "ss={},se={},match_kv:[",
                   ((MappingKey*)subrange.get_start_key())->to_string(),
                   ((MappingKey*)subrange.get_end_key())->to_string());
    for (const auto& [mk, mv] : match_kv) {
        fmt::format_to(std::back_inserter(str), "[{}],[{}]", mk.to_string(), mv.to_string());
    }
    fmt::format_to(std::back_inserter(str), "]");
#endif

    /* We don't change BLKID in value. Instead we store offset of lba range that we are storing */
    auto [start_lba, end_lba] = get_start_end_lba(subrange);
    const lba_count_t initial_val_offset = compute_val_offset(cb_param, start_lba);
    lba_count_t new_val_offset = initial_val_offset;

    for (auto& existing : match_kv) {
        MappingKey* e_key = &existing.first;
        MappingValue* e_value = &existing.second;
        lba_count_t existing_val_offset = 0;

        if (e_key->start() > start_lba) {
            /* add missing interval */
            if (new_ve->get_base_blkid().is_valid()) { // not a unmap operation
                add_new_interval(start_lba, e_key->start() - 1, new_val, new_val_offset, replace_kv);
            }
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
            HS_REL_ASSERT_EQ(new_val_offset, initial_val_offset);
            // split existing key at the start and add new interval
            add_new_interval(e_key->start(), start_lba - 1, *e_value, existing_val_offset, replace_kv);
            existing_val_offset += start_lba - e_key->start();
        }

        /* Now both intervals have the same start */
        // compute overlap
        auto end_lba_overlap = e_key->end() < end_lba ? e_key->end() : end_lba;
        compute_and_add_overlap(fbe_list, start_lba, end_lba_overlap, new_val, new_val_offset, *e_value,
                                existing_val_offset, replace_kv, new_seq_id);
        const lba_count_t nlbas = get_nlbas(end_lba_overlap, start_lba);
        new_val_offset += nlbas;
        existing_val_offset += nlbas;
        start_lba += nlbas;

        if (e_key->end() > end_lba) {
            HS_DBG_ASSERT_EQ(start_lba, (end_lba + 1));
            // split existing key at the end and add new interval
            add_new_interval(start_lba, e_key->end(), *e_value, existing_val_offset, replace_kv);
        }
    }

    if (start_lba <= end_lba && new_ve->get_base_blkid().is_valid()) { // add new range
        add_new_interval(start_lba, end_lba, new_val, new_val_offset, replace_kv);
    }

    btree_status_t ret = btree_status_t::success;
    if (cntx->op == op_type::UPDATE_VAL_AND_FREE_BLKS) {
        req->indx_push_fbe(fbe_list);
    } else if (cntx->op == op_type::UPDATE_OOB_UNMAP) {
        if (fbe_list.size() > 0) {
            uint64_t size = IndxMgr::free_blk(nullptr, cntx->free_list, fbe_list, cntx->force);
            cntx->free_blk_size += size;
            if (size == 0) { ret = btree_status_t::resource_full; }
        }
    }

    // TODO - merge kv which have contigous lba and BlkIds - may be not that useful for performance
#ifndef NDEBUG
    /* sanity check */
    for (const auto& [mk, mv] : replace_kv) {
        lba_count_t i = 0u;
        while (i < mv.get_total_entries()) {
            const ValueEntry* cur_ve = mv.get_nth_entry(i);
            if (i != 0) { // sorted ve check
                const ValueEntry* prev_ve = mv.get_nth_entry(i - 1);
                HS_DBG_ASSERT_GT(prev_ve->compare(cur_ve), 0);
            }
            HS_DBG_ASSERT_EQ(cur_ve->get_num_lbas(), mk.get_n_lba());
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
            auto blk_start = curve.get_blkId().get_blk_num() + curve.get_blk_offset();
            auto blk_end =
                blk_start + (m_vol_page_size / HomeBlks::instance()->get_data_pagesz()) * curve.get_nlba() - 1;
            req->init_fbe_iterator();
            while (auto fbe = req->get_next_fbe()) {
                if (fbe->m_blkId.get_chunk_num() != curve.get_blkId().get_chunk_num()) { continue; }
                auto fblk_start = fbe->m_blkId.get_blk_num() + fbe->m_blk_offset;
                auto fblk_end = fblk_start + fbe->m_nblks_to_free - 1;
                if (blk_end < fblk_start || fblk_end < blk_start) {
                } // non overlapping
                else {
                    ss << ",replace_kv:";
                    for (auto& ptr : replace_kv) {
                        ss << ptr.first.to_string() << "," << ptr.second.to_string();
                    }
                    VOL_DBG_ASSERT(0, , "vol", m_unique_name, "Error::Put_CB:,{} ", ss.str());
                }
            }
#endif
            ++i;
        }
    }

    fmt::format_to(std::back_inserter(str), ", replace_kv:[");
    for (const auto& [mk, mv] : replace_kv) {
        fmt::format_to(std::back_inserter(str), "[{}],[{}]", mk.to_string(), mv.to_string());
    }
    fmt::format_to(std::back_inserter(str), "]");
    if (req) {
        HS_SUBMOD_LOG(TRACE, volume, req, "vol", m_unique_name, "{}", str);
    } else {
        HS_SUBMOD_LOG(TRACE, volume, , "vol", m_unique_name, "{}", str);
    }
#endif
    return ret;
}

/* derieves current range of lba's based on input/sub range
 * subrange means current bnodes start/end boundaries
 * input_range is original client provided start/end, its always inclusive for mapping layer
 * Resulting start/end lba is always inclusive
 */
std::pair< lba_t, lba_t > mapping::get_start_end_lba(BtreeSearchRange& subrange) {
    lba_t start_lba, end_lba;

    MappingKey* s_subrange = (MappingKey*)subrange.get_start_key();
    HS_DBG_ASSERT_EQ(s_subrange->start(), s_subrange->end());
    start_lba = s_subrange->start();
    if (!subrange.is_start_inclusive()) { start_lba = s_subrange->start() + 1; }

    MappingKey* e_subrange = (MappingKey*)subrange.get_end_key();
    HS_DBG_ASSERT_EQ(e_subrange->start(), e_subrange->end());
    end_lba = e_subrange->end();
    if (!subrange.is_end_inclusive()) { end_lba = e_subrange->end() - 1; }

    return std::make_pair<>(start_lba, end_lba);
}

/* add missing interval to replace kv */
void mapping::add_new_interval(const lba_t s_lba, const lba_t e_lba, const MappingValue& val,
                               const lba_count_t lba_offset,
                               std::vector< std::pair< MappingKey, MappingValue > >& replace_kv) {
    HS_DBG_ASSERT_LE(lba_offset, BlkId::max_blks_in_op());
    const auto nlba = get_nlbas(e_lba, s_lba);
    replace_kv.emplace_back(
        std::make_pair(MappingKey(s_lba, nlba), MappingValue(*val.get_latest_entry(), lba_offset, nlba)));
}

/* result of overlap of k1/k2 is added to replace_kv */
void mapping::compute_and_add_overlap(std::vector< Free_Blk_Entry >& fbe_list, lba_t s_lba, const lba_t e_lba,
                                      const MappingValue& new_val, lba_count_t new_lba_offset, MappingValue& e_val,
                                      const lba_count_t e_lba_offset,
                                      std::vector< std::pair< MappingKey, MappingValue > >& replace_kv,
                                      const seq_id_t new_seq_id) {
    auto nlba = get_nlbas(e_lba, s_lba);

    /* This code assumes that there is only one value entry */
    const ValueEntry* e_ve = e_val.get_latest_entry();
    const seq_id_t e_seq_id = e_ve->get_seqid();

    if (new_seq_id > e_seq_id) {
        /* override */
        if (e_ve->get_base_blkid().is_valid()) {
            Free_Blk_Entry fbe(e_ve->get_base_blkid(), nlbas_to_nblks(e_ve->get_lba_offset() + e_lba_offset),
                               nlbas_to_nblks(nlba));
            fbe_list.push_back(fbe);
        }
        auto& [mk, mv] = replace_kv.back();
        if (replace_kv.size() > 0 && (mv.get_latest_entry()->get_seqid() == new_seq_id)) {
            s_lba = mk.start();
            nlba += mk.get_n_lba();
            new_lba_offset = mv.get_latest_entry()->get_lba_offset();
            replace_kv.pop_back();
        }
        replace_kv.emplace_back(
            std::make_pair(MappingKey(s_lba, nlba), MappingValue(*new_val.get_latest_entry(), new_lba_offset, nlba)));
    } else {
        /* don't override. free new blks */
        const ValueEntry* new_ve = new_val.get_latest_entry();
        if (new_ve->get_base_blkid().is_valid()) {
            fbe_list.emplace_back(new_ve->get_base_blkid(), nlbas_to_nblks(new_ve->get_lba_offset() + new_lba_offset),
                                  nlbas_to_nblks(nlba));
        }
        replace_kv.emplace_back(
            std::make_pair(MappingKey(s_lba, nlba), MappingValue(*e_val.get_latest_entry(), e_lba_offset, nlba)));
    }
}

#ifndef NDEBUG
void mapping::validate_get_response(const lba_t lba_start, const lba_count_t n_lba,
                                    std::vector< std::pair< MappingKey, MappingValue > >& values,
                                    MappingValue* exp_value, volume_req* req) {
    lba_t last_slba = lba_start;
    lba_count_t last_lba_offset = 0;
    BlkId expBid;
    if (exp_value != nullptr) {
        const ValueEntry* ve = exp_value->get_latest_entry();
        expBid = ve->get_base_blkid();
    }

    for (const auto& [mk, mv] : values) {
        if (mk.start() != last_slba) {
            m_bt->print_tree();
            std::this_thread::sleep_for(std::chrono::seconds(5));

            if (req) { // do it again to trace
                std::vector< std::pair< MappingKey, MappingValue > > values;
                auto temp = req->lastCommited_seqid;
                req->lastCommited_seqid = req->seqid;
                MappingKey key(lba_start, n_lba);
                get(req, values);
                req->lastCommited_seqid = temp;
            }
            assert(false); // gaps found
        }

        if (exp_value != nullptr) {
            HS_DBG_ASSERT_EQ(mv.get_total_entries(), 1);
            const ValueEntry* ve = mv.get_latest_entry();

            if (!mv.is_valid() || ve->get_base_blkid().get_blk_num() != expBid.get_blk_num() ||
                ve->get_lba_offset() != last_lba_offset) {
                m_bt->print_tree();
                std::this_thread::sleep_for(std::chrono::seconds(10));
                assert(false);
            }
            last_lba_offset += mk.get_n_lba();
        }
        last_slba = mk.end() + 1;
    }
    HS_DBG_ASSERT_EQ(last_slba, lba_start + n_lba);
}
#endif

void mapping::create_done() { m_bt->create_done(); }
uint64_t mapping::get_used_size() const { return m_bt->get_used_size(); }
btree_super_block mapping::get_btree_sb() { return (m_bt->get_btree_sb()); }

btree_cp_ptr mapping::attach_prepare_cp(const btree_cp_ptr& cur_bcp, bool is_last_cp, bool blkalloc_checkpoint) {
    return (m_bt->attach_prepare_cp(cur_bcp, is_last_cp, blkalloc_checkpoint));
}

void mapping::cp_start(const btree_cp_ptr& bcp, cp_comp_callback cb) { m_bt->cp_start(bcp, cb); }

void mapping::truncate(const btree_cp_ptr& bcp) { m_bt->truncate(bcp); }

void mapping::destroy_done() { m_bt->destroy_done(); }

void mapping::flush_free_blks(const btree_cp_ptr& bcp, std::shared_ptr< homestore::blkalloc_cp >& ba_cp) {
    m_bt->flush_free_blks(bcp, ba_cp);
}
void mapping::update_btree_cp_sb(const btree_cp_ptr& bcp, btree_cp_sb& btree_sb, bool is_blkalloc_cp) {
    m_bt->update_btree_cp_sb(bcp, btree_sb, is_blkalloc_cp);
}

btree_status_t mapping::update_diff_indx_tbl(const indx_req_ptr& ireq, const btree_cp_ptr& bcp) {
    return (update_indx_tbl(ireq, bcp, false));
}

btree_status_t mapping::update_active_indx_tbl(const indx_req_ptr& ireq, const btree_cp_ptr& bcp) {
    return (update_indx_tbl(ireq, bcp, true));
}

/* it populats the allocated blkids in index req. It might not be the same as in volume req if entry is partially
 * written.
 */
void mapping::update_indx_alloc_blkids(const indx_req_ptr& ireq) {
    lba_count_t total_lbas = 0;
    auto vreq = static_cast< volume_req* >(ireq.get());

    if (!vreq->active_btree_cur.m_last_key) { return; }
    const auto end_lba = get_end_key_from_cursor(vreq->active_btree_cur);
    const auto lbas_written = get_nlbas(end_lba, vreq->lba());
    const auto page_size = vreq->vol()->get_page_size();

    for (const auto& blkid : vreq->alloc_blkid_list) {
        const lba_count_t nlbas = nblks_to_nlbas(blkid.get_nblks());
        if (total_lbas + nlbas >= lbas_written) {
            /* it is written only upto this blkid */
            const auto size_written = (lbas_written - total_lbas) * vreq->vol()->get_page_size();
            const auto blkid_written =
                blkid.get_blkid_at(0 /* offset */, size_written, HomeBlks::instance()->get_data_pagesz());
            vreq->push_indx_alloc_blkid(blkid_written);
            break;
        }
        total_lbas += nlbas;
        vreq->push_indx_alloc_blkid(blkid);
    }
}

btree_status_t mapping::update_indx_tbl(const indx_req_ptr& ireq, const btree_cp_ptr& bcp,
                                        const bool active_btree_update) {
    auto vreq = static_cast< volume_req* >(ireq.get());
    lba_t start_lba = vreq->lba();
    lba_count_t csum_indx{0};
    lba_t next_start_lba = start_lba;
    lba_t end_lba;
    auto btree_cur_ptr = (active_btree_update ? &vreq->active_btree_cur : &vreq->diff_btree_cur);

    if (active_btree_update) {
        end_lba = get_end_lba(start_lba, vreq->nlbas());
    } else {
        /* we don't write more then what is written in active btree. */
        /* XXX: Can this assert be hit. it means nothing is written to active btree */
        assert(vreq->active_btree_cur.m_last_key);
        end_lba = get_end_key_from_cursor(vreq->active_btree_cur);
        HS_DBG_ASSERT_GE(end_lba, start_lba);
    }

    /* we will start from the same place where it is left last time */
    if (btree_cur_ptr->m_last_key) { next_start_lba = get_next_start_key_from_cursor(*btree_cur_ptr); }
    HS_DBG_ASSERT_LE(end_lba, get_end_lba(start_lba, vreq->nlbas()));

    btree_status_t ret = btree_status_t::success;

    if (vreq->is_unmap()) {
        lba_count_t nlbas_cur = get_nlbas(end_lba, next_start_lba);
        const lba_count_t nlbas_entry = (nlbas_cur > BlkId::max_blks_in_op()) ? BlkId::max_blks_in_op() : nlbas_cur;
        MappingKey key{next_start_lba, nlbas_entry};
        MappingValue value{vreq->seqid, BlkId{}, 0u, nlbas_entry, nullptr /* csum ptr */};

        mapping_op_cntx cntx;
        cntx.op = UPDATE_VAL_AND_FREE_BLKS;
        cntx.vreq = vreq;
        ret = put(cntx, key, value, bcp, *btree_cur_ptr);
        return ret;
    }

    for (const auto& blkid : vreq->alloc_blkid_list) {
        lba_count_t nlbas = nblks_to_nlbas(blkid.get_nblks());

        if (start_lba < next_start_lba) {
            if (get_end_lba(start_lba, nlbas) < next_start_lba) {
                start_lba += nlbas;
                csum_indx += nlbas;
                /* skip this write as it is already written */
                continue;
            }

            /* For partially written range , it will be taken care automically by cursor */
        }

        /* we don't write more then what is updated in active btree */
        if (get_end_lba(start_lba, nlbas) > end_lba) { nlbas = get_nlbas(end_lba, start_lba); }

        MappingKey key{start_lba, nlbas};
        MappingValue value{vreq->seqid, blkid, 0u, nlbas, &vreq->csum_list[csum_indx]};

        /* if snapshot is disabled then cntx would be different. XXX : do we need to suppprt snapshot disable */
        mapping_op_cntx cntx;
        if (active_btree_update && 0) {
            cntx.op = UPDATE_VAL_ONLY;
        } else {
            cntx.op = UPDATE_VAL_AND_FREE_BLKS;
            cntx.vreq = vreq;
        }

        ret = put(cntx, key, value, bcp, *btree_cur_ptr);

        start_lba += nlbas;
        csum_indx += nlbas;
        if (ret != btree_status_t::success || start_lba > end_lba) { break; }
        HS_DBG_ASSERT_EQ(start_lba, (get_end_key_from_cursor(*btree_cur_ptr) + 1));
    }

    HS_DBG_ASSERT((ret != btree_status_t::success || (start_lba == (end_lba + 1))), "ret {} start_lba {} end_lba {}",
                  ret, start_lba, end_lba);
    return ret;
}

btree_status_t mapping::recovery_update(const logstore_seq_num_t seqnum, journal_hdr* hdr, const btree_cp_ptr& bcp) {

    BlkId* bid = indx_journal_entry::get_alloc_bid_list(hdr).first;
    uint32_t nbid = indx_journal_entry::get_alloc_bid_list(hdr).second;
    if (!nbid) {
        // it is unmap
        auto ret = unmap_recovery_update(seqnum, hdr, bcp);
        return ret;
    }

    /* get all the values from journal entry */
    const auto key = (journal_key*)indx_journal_entry::get_key(hdr).first;
    HS_REL_ASSERT_EQ(indx_journal_entry::get_key(hdr).second, sizeof(journal_key));

    lba_t lba = key->lba;
    csum_t* csum = (csum_t*)indx_journal_entry::get_val(hdr).first;
    lba_count_t ncsum = indx_journal_entry::get_val(hdr).second / sizeof(csum_t);
    HS_REL_ASSERT_EQ(ncsum, key->num_lbas());

    /* update btree */
    uint32_t csum_indx = 0;
    btree_status_t ret = btree_status_t::success;
    for (uint32_t i = 0; i < nbid; ++i) {
        lba_count_t nlbas = 0;
        if (bid[i].is_valid()) {
            nlbas = nblks_to_nlbas(bid[i].get_nblks());
        } else {
            nlbas = key->num_lbas();
        }
        MappingKey key{lba, nlbas};
        MappingValue value{seqnum, bid[i], 0, nlbas, &csum[csum_indx]};

        mapping_op_cntx cntx;
        cntx.op = UPDATE_VAL_ONLY;

        BtreeQueryCursor cur;
        ret = put(cntx, key, value, bcp, cur);
        HS_REL_ASSERT_EQ(ret, btree_status_t::success);
        lba += nlbas;
        csum_indx += nlbas;
    }
    HS_REL_ASSERT_EQ(lba, key->lba + key->num_lbas());
    return ret;
}

btree_status_t mapping::unmap_recovery_update(const logstore_seq_num_t seqnum, journal_hdr* hdr,
                                              const btree_cp_ptr& bcp) {
    const auto j_key = (journal_key*)indx_journal_entry::get_key(hdr).first;
    HS_REL_ASSERT_EQ(indx_journal_entry::get_key(hdr).second, sizeof(journal_key));
    lba_t lba = j_key->lba;
    lba_count_t nlbas = j_key->num_lbas();
    MappingKey key{lba, nlbas};
    BlkId bid;
    HS_DBG_ASSERT(!bid.is_valid(), "blkid is valid");
    MappingValue value{seqnum, bid, 0, nlbas, nullptr};
    mapping_op_cntx cntx;
    cntx.op = UPDATE_VAL_ONLY;
    BtreeQueryCursor cur;
    auto ret = put(cntx, key, value, bcp, cur);
    HS_REL_ASSERT_EQ(ret, btree_status_t::success);
    return ret;
}

btree_status_t mapping::free_user_blkids(blkid_list_ptr free_list, BtreeQueryCursor& cur, int64_t& size) {
    const lba_t start_lba{0};
    mapping_op_cntx cntx;
    cntx.op = FREE_ALL_USER_BLKID;
    cntx.free_list = free_list.get();

    MappingKey key(start_lba, 1);
    std::vector< std::pair< MappingKey, MappingValue > > values;
    auto ret = get(cntx, key, cur, values);
    size = cntx.free_blk_size;
    return ret;
}

void mapping::get_btreequery_cur(const sisl::blob& b, BtreeQueryCursor& cur) {
    if (b.size == 0) { return; }
    cur.m_last_key = std::make_unique< MappingKey >(MappingKey());
    cur.m_last_key->set_blob(b);
};

btree_status_t mapping::destroy(blkid_list_ptr& free_blkid_list, uint64_t& free_node_cnt) {
    auto ret = btree_status_t::success;
    ret = m_bt->destroy(free_blkid_list, free_node_cnt);
    VOL_LOG_ASSERT_CMP(ret, ==, btree_status_t::success, , "Error in destroying mapping btree");
    return ret;
}

btree_status_t mapping::update_oob_unmap_active_indx_tbl(blkid_list_ptr free_list, const seq_id_t seq_id, void* key,
                                                         BtreeQueryCursor& cur, const btree_cp_ptr& bcp, int64_t& size,
                                                         const bool force) {
    journal_key* j_key = (journal_key*)key;
    lba_count_t nlbas_rem;
    lba_t next_start_lba;
    const lba_t start_lba = j_key->lba;
    const lba_t end_lba = get_end_lba(start_lba, j_key->user_io_nlbas);

    btree_status_t ret = btree_status_t::success;

    mapping_op_cntx cntx;
    cntx.op = UPDATE_OOB_UNMAP;
    cntx.free_list = free_list.get();
    cntx.force = force;

    next_start_lba = (cur.m_last_key) ? get_next_start_key_from_cursor(cur) : j_key->lba;
    const uint32_t max_iterations{static_cast< uint32_t >(HS_DYNAMIC_CONFIG(generic.max_unmap_iterations))};
    uint32_t num_iterations = 0;
    nlbas_rem = get_nlbas(end_lba, next_start_lba);
    while (nlbas_rem > 0) {
        const lba_count_t nlbas_cur = (nlbas_rem > BlkId::max_blks_in_op()) ? BlkId::max_blks_in_op() : nlbas_rem;
        MappingKey key{next_start_lba, nlbas_cur};
        MappingValue value{seq_id, BlkId{}, 0u, nlbas_cur, nullptr /* csum ptr */};

        ret = put(cntx, key, value, bcp, cur);
        if (ret != btree_status_t::success) {
            HS_SUBMOD_LOG(INFO, volume, , "vol", m_unique_name, "PUT : start_lba {} end lba {} ret {}", key.start(),
                          end_lba, ret);
            break;
        }
        next_start_lba = (cur.m_last_key) ? get_next_start_key_from_cursor(cur) : j_key->lba;
        nlbas_rem -= nlbas_cur;
        ++num_iterations;
        if (nlbas_rem > 0 && num_iterations == max_iterations && !force) {
            ret = btree_status_t::resource_full;
            break;
        }
    }
    size += cntx.free_blk_size;
    return ret;
}
