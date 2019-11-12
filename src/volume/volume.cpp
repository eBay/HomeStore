
//
// Created by Kadayam, Hari on 06/11/17.
//

#include "home_blks.hpp"
#include <mapping/mapping.hpp>
#include <fstream>
#include <atomic>
#include <fds/utils.hpp>

using namespace std;
using namespace homestore;

#ifndef NDEBUG
/* only for testing */
bool vol_test_enable = false;
#endif

SDS_LOGGING_DECL(volume)

namespace homestore {
void intrusive_ptr_add_ref(homestore::BlkBuffer* buf) {
    intrusive_ptr_add_ref((homestore::WriteBackCacheBuffer< BlkId >*)buf);
}

void intrusive_ptr_release(homestore::BlkBuffer* buf) {
    intrusive_ptr_release((homestore::WriteBackCacheBuffer< BlkId >*)buf);
}
} // namespace homestore

VolInterface* VolInterface::_instance = nullptr;
homestore::BlkStore< homestore::VdevVarSizeBlkAllocatorPolicy >* Volume::m_data_blkstore = nullptr;

Volume::Volume(const vol_params& params) :
        m_comp_cb(params.io_comp_cb),
        m_metrics(params.vol_name),
        m_vol_name(params.vol_name) {
    m_state = vol_state::UNINITED;
    m_map = new mapping(params.size, params.page_size, params.vol_name,
                        std::bind(&Volume::process_metadata_completions, this, std::placeholders::_1),
                        std::bind(&Volume::process_free_blk_callback, this, std::placeholders::_1),
                        std::bind(&Volume::pending_read_blk_cb, this, std::placeholders::_1));

    m_sb = new vol_mem_sb();
    auto ret = posix_memalign((void**)&(m_sb->ondisk_sb), HomeStoreConfig::align_size, VOL_SB_SIZE);
    assert(!ret);
    assert(m_sb != nullptr);

    m_sb->ondisk_sb->btree_sb = m_map->get_btree_sb();
    m_sb->ondisk_sb->state = vol_state::ONLINE;
    m_sb->ondisk_sb->page_size = params.page_size;
    m_sb->ondisk_sb->size = params.size;
    m_sb->ondisk_sb->uuid = params.uuid;
    memcpy(m_sb->ondisk_sb->vol_name, params.vol_name, VOL_NAME_SIZE);

    /* Create home journal instance per volume - Journal has same id as volume*/
    m_volume_journal = new VolumeJournal(boost::uuids::to_string(m_sb->ondisk_sb->uuid));

    HomeBlks::instance()->vol_sb_init(m_sb);

    seq_Id = 3;
    alloc_single_block_in_mem();

    m_data_blkstore = HomeBlks::instance()->get_data_blkstore();
    m_state = vol_state::ONLINE;
    m_read_blk_tracker = std::make_unique< Blk_Read_Tracker >(
        params.vol_name, std::bind(&Volume::process_free_blk_callback, this, std::placeholders::_1));
}

Volume::Volume(vol_mem_sb* sb) : m_sb(sb), m_metrics(sb->ondisk_sb->vol_name), m_vol_name(sb->ondisk_sb->vol_name) {
    m_state = vol_state::UNINITED;
    if (m_sb->ondisk_sb->state == vol_state::FAILED) {
        m_map = new mapping(m_sb->ondisk_sb->size, m_sb->ondisk_sb->page_size, m_sb->ondisk_sb->vol_name,
                            std::bind(&Volume::process_metadata_completions, this, std::placeholders::_1),
                            std::bind(&Volume::process_free_blk_callback, this, std::placeholders::_1),
                            std::bind(&Volume::pending_read_blk_cb, this, std::placeholders::_1));
        m_sb->ondisk_sb->btree_sb = m_map->get_btree_sb();
        m_sb->ondisk_sb->state = vol_state::DEGRADED;

        /* Create home journal instance per volume */
        m_volume_journal = new VolumeJournal(boost::uuids::to_string(m_sb->ondisk_sb->uuid));

        LOGINFO("reinitialized the volume {} because vdev is in failed state. It state will be degraded"
                "until it is resync",
                sb->ondisk_sb->vol_name);
        HomeBlks::instance()->vol_sb_write(m_sb);
    } else {
        m_map = new mapping(m_sb->ondisk_sb->size, m_sb->ondisk_sb->page_size, m_sb->ondisk_sb->vol_name,
                            m_sb->ondisk_sb->btree_sb,
                            std::bind(&Volume::process_metadata_completions, this, std::placeholders::_1),
                            std::bind(&Volume::alloc_blk_callback, this, std::placeholders::_1, std::placeholders::_2,
                                      std::placeholders::_3),
                            std::bind(&Volume::process_free_blk_callback, this, std::placeholders::_1),
                            std::bind(&Volume::pending_read_blk_cb, this, std::placeholders::_1));
        /* Create home journal instance per volume */
        m_volume_journal = new VolumeJournal(boost::uuids::to_string(m_sb->ondisk_sb->uuid));
    }
    assert(m_sb->ondisk_sb->state == OFFLINE || m_sb->ondisk_sb->state == DEGRADED || m_sb->ondisk_sb->state == ONLINE);
    seq_Id = 3;
    m_state = vol_state::MOUNTING;
    alloc_single_block_in_mem();

    m_data_blkstore = HomeBlks::instance()->get_data_blkstore();
    m_read_blk_tracker = std::make_unique< Blk_Read_Tracker >(
        sb->ondisk_sb->vol_name, std::bind(&Volume::process_free_blk_callback, this, std::placeholders::_1));
}

/* it should be called during recovery */
void Volume::recovery_start() { vol_scan_alloc_blks(); }

uint64_t Volume::get_metadata_used_size() { return m_map->get_used_size(); }

#ifdef _PRERELEASE
void Volume::set_error_flip() {
    FlipClient* fc = HomeStoreFlip::client_instance();
    FlipFrequency freq;
    FlipCondition cond1;
    freq.set_count(2000000000);
    freq.set_percent(1);

    /* error flips */
    freq.set_percent(1);
    fc->inject_noreturn_flip("vol_vchild_error", {}, freq);
    fc->inject_retval_flip("delay_us_and_inject_error_on_completion", {}, freq, 20);
    fc->inject_noreturn_flip("varsize_blkalloc_no_blks", {}, freq);
}

void Volume::set_io_flip() {
    FlipClient* fc = HomeStoreFlip::client_instance();
    FlipFrequency freq;
    FlipCondition cond1;
    freq.set_count(2000000000);
    freq.set_percent(2);

    /* io flips */
    fc->inject_retval_flip("vol_delay_read_us", {}, freq, 20);

    fc->inject_retval_flip("cache_insert_race", {}, freq, 20);
    fc->inject_retval_flip("io_write_iocb_empty_flip", {}, freq, 20);
    fc->inject_retval_flip("io_read_iocb_empty_flip", {}, freq, 20);

    fc->create_condition("nuber of blks in a write", flip::Operator::EQUAL, 8, &cond1);
    fc->inject_retval_flip("blkalloc_split_blk", {cond1}, freq, 4);
}
#endif

//
// No need to do it in multi-threading since blkstore.free_blk is in-mem operation.
//
void Volume::process_free_blk_callback(Free_Blk_Entry fbe) {
    VOL_LOG(DEBUG, volume, , "Freeing blks cb - bid: {}, offset: {}, nblks: {}, get_pagesz: {}",
            fbe.m_blkId.to_string(), fbe.blk_offset(), fbe.blks_to_free(), get_page_size());

    uint64_t size = HomeBlks::instance()->get_data_pagesz() * fbe.m_nblks_to_free;
    m_data_blkstore->free_blk(fbe.m_blkId, HomeBlks::instance()->get_data_pagesz() * fbe.m_blk_offset,
                              HomeBlks::instance()->get_data_pagesz() * fbe.m_nblks_to_free);
    m_used_size.fetch_sub(size, std::memory_order_relaxed);
}

/* when read happens on mapping btree, under read lock we mark blk so it does not get removed by concurrent writes */
void Volume::pending_read_blk_cb(BlkId& bid) { m_read_blk_tracker->insert(bid); }

#ifndef NDEBUG
void Volume::verify_pending_blks() { assert(m_read_blk_tracker->get_size() == 0); }
#endif

/* convertes kvs to free blk entries*/
void Volume::get_free_blk_entries(std::vector< std::pair< MappingKey, MappingValue > >& kvs,
                                  std::vector< Free_Blk_Entry >& fbes) {
    auto it = kvs.begin();
    while (it != kvs.end()) {
        std::pair< MappingKey, MappingValue >& kv = *it;
        if (!kv.second.is_valid()) {
            ++it;
            continue;
        }
        ValueEntry ve;
        (kv.second.get_array()).get(0, ve, false);
        uint8_t blk_offset = 0, nblks = 0;
        blk_offset = ve.get_blk_offset();
        nblks = (m_sb->ondisk_sb->size / HomeBlks::instance()->get_data_pagesz()) * ve.get_nlba();
        fbes.push_back(Free_Blk_Entry(ve.get_blkId(), blk_offset, nblks));
        ++it;
    }
}

/* Removes blkid from free blk entries*/
bool Volume::remove_free_blk_entry(std::vector< Free_Blk_Entry >& fbes, std::pair< MappingKey, MappingValue >& kv) {
    ValueEntry ve;
    (kv.second.get_array()).get(0, ve, false);
    auto bid = ve.get_blkId();
    auto it = fbes.begin();
    while (it != fbes.end()) {
        Free_Blk_Entry& fbe = *it;
        if (BlkId::compare(fbe.m_blkId, bid) == 0 && ve.get_blk_offset() == fbe.m_blk_offset) {
            fbes.erase(it);
            return true;
        }
        ++it;
    }
    return false;
}

boost::uuids::uuid Volume::get_uuid() { return (get_sb()->ondisk_sb->uuid); }

vol_state Volume::get_state() { return m_state; }

void Volume::set_state(vol_state state, bool persist) {
    LOGINFO("volume state changed from {} to {}", m_state, state);
    m_state = state;
    if (persist) {
        m_sb->lock();
        m_sb->ondisk_sb->state = state;
        m_sb->unlock();
        HomeBlks::instance()->vol_sb_write(get_sb());
    }
}

void Volume::attach_completion_cb(const io_comp_callback& cb) { m_comp_cb = cb; }

void Volume::blk_recovery_process_completions(bool success) {
    VOL_LOG(INFO, volume, , "block recovery of volume completed with {}", (success ? "success" : "failure"));
    assert(m_state == vol_state::MOUNTING);
    m_state = m_sb->ondisk_sb->state;
    m_map->recovery_cmpltd();
    HomeBlks::instance()->vol_scan_cmpltd(shared_from_this(), m_sb->ondisk_sb->state, success);
}

/* TODO: This part of the code should be moved to mapping layer. Ideally
 * we only need to have a callback for a blkid, offset and end  from the mapping layer
 */
void Volume::alloc_blk_callback(struct BlkId bid, size_t offset_size, size_t size) {
    assert(m_state == vol_state::MOUNTING);
    BlkId free_bid(bid.get_blkid_at(offset_size, size, HomeBlks::instance()->get_data_pagesz()));
    m_data_blkstore->alloc_blk(free_bid);
    m_used_size.fetch_add(size, std::memory_order_relaxed);
}

void Volume::vol_scan_alloc_blks() {
    std::vector< ThreadPool::TaskFuture< void > > task_result;
    task_result.push_back(submit_job([this]() { this->get_allocated_blks(); }));
    return;
}

Volume::~Volume() {
    if (get_state() != DESTROYING) {
        VOL_LOG(INFO, , , "Shutting volume");
        delete m_map;
        delete m_volume_journal;
        delete (m_sb);
    } else {
        VOL_LOG(INFO, , , "Destroying volume");
        //
        // 1. Traverse mapping btree in post order:
        //    1.a for leaf node, get key/value and call m_data_blkstore.free_blk to free the block;
        //    1.b for non-leaf node, call btree_store_t::free_node which is in Btree::free();
        // 2. Delete in-memory m_map and m_data_blkstore;
        // 3. Clean on-disk volume super block related data
        //
        // destroy is a sync call.
        VOL_LOG(INFO, , , "Vol destroy frees {} used blks", m_used_size.load());
        m_map->destroy();

        // all blks should have been freed
        VOL_ASSERT_CMP(LOGMSG, m_used_size.load(), ==, 0, , "All blks expected to be freed");

        HomeBlks::instance()->vol_sb_remove(get_sb());
        delete m_map;
        delete m_volume_journal;
        delete (m_sb);
        auto system_cap = HomeBlks::instance()->get_system_capacity();
        VOL_LOG(INFO, volume, , "volume is destroyed. New system capacity is {}", system_cap.to_string());
    }
}

void Volume::process_metadata_completions(const volume_req_ptr& vreq) {
    assert(!vreq->is_read);
    assert(!vreq->isSyncCall);

#ifndef NDEBUG
    vreq->done = true;
#endif

    COUNTER_DECREMENT(m_metrics, volume_outstanding_metadata_write_count, 1);
    auto& parent_req = vreq->parent_req;
    assert(parent_req != nullptr);

    VOL_LOG(TRACE, volume, parent_req, "metadata_complete: status={}", vreq->err.message());
    HISTOGRAM_OBSERVE(m_metrics, volume_map_write_latency, get_elapsed_time_us(vreq->op_start_time));

#ifdef _PRERELEASE
    if (parent_req->outstanding_io_cnt.get() > 2 && homestore_flip->test_flip("vol_vchild_error")) {
        vreq->err = homestore_error::flip_comp_error;
    }
#endif
    check_and_complete_req(parent_req, vreq->err, true /* call_completion_cb */, &(vreq->blkIds_to_free));
#ifndef NDEBUG
    {
        std::unique_lock< std::mutex > mtx(m_req_mtx);
        auto it = m_req_map.find(vreq->reqId);
        assert(it != m_req_map.end());
        m_req_map.erase(it);
    }
#endif
}

void Volume::process_vol_data_completions(const boost::intrusive_ptr< blkstore_req< BlkBuffer > >& bs_req) {
    volume_req::cast(bs_req)->vol_instance->process_data_completions(bs_req);
}

volume_req_ptr Volume::create_vol_req(Volume* vol, const vol_interface_req_ptr& hb_req) {
    volume_req_ptr vreq = volume_req::make_request();
    vreq->parent_req = hb_req;
    vreq->is_read = hb_req->is_read;
    vreq->vol_instance = vol->shared_from_this();

    hb_req->outstanding_io_cnt.increment(1);
    hb_req->outstanding_data_io_cnt.increment(1);
    return vreq;
}

vol_interface_req_ptr Volume::create_vol_hb_req() { return vol_hb_req::make_instance(); }

void Volume::process_journal_completions(vol_hb_req* vhb_req, uint64_t log_id) {
    auto child_reqs = vhb_req->child_reqs;
    auto itr = child_reqs.begin();
    while (itr != child_reqs.end()) {
        auto vreq = *itr;
        MappingKey key(vreq->lba, vreq->nlbas);
        std::array< uint16_t, CS_ARRAY_STACK_SIZE > carr;
        uint64_t offset = 0;
        for (int i = 0; i < vreq->nlbas; i++) {
            carr[i] = crc16_t10dif(init_crc_16, vreq->bbuf->at_offset(offset).bytes, get_page_size());
            offset += get_page_size();
        }
        vreq->op_start_time = Clock::now();
        ValueEntry ve(log_id, vreq->bid, 0, vreq->nlbas, carr);
        MappingValue value(ve);
#ifndef NDEBUG
        vreq->vol_uuid = m_sb->ondisk_sb->uuid;
        VOL_LOG(DEBUG, volume, vreq->parent_req, "Mapping.PUT, vol_uuid:{}, Key:{}, Value:{}",
                boost::uuids::to_string(vreq->vol_uuid), key.to_string(), value.to_string());
#endif
        COUNTER_DECREMENT(m_metrics, volume_outstanding_data_write_count, 1);
        COUNTER_INCREMENT(m_metrics, volume_outstanding_metadata_write_count, 1);
        m_map->put(vreq, key, value);
        ++itr;
    }
}

void Volume::set_journal_key_value(VolumeJournalKey& jkey, VolumeJournalValue& jval, vol_hb_req* vhb_req) {
    // Set key
    std::string vol_id_str = boost::lexical_cast< std::string >(get_uuid());
    const char* volId = vol_id_str.c_str();
    uint64_t lsn = 0; // TODO - to set plsn here which comes all the way from client DM
    jkey.set(lsn, volId);

    // Set value
    std::vector< Lba_Blk_Entry > lbes;
    auto itr = vhb_req->child_reqs.begin();
    while (itr != vhb_req->child_reqs.end()) {
        auto creq = *itr;
        lbes.push_back(Lba_Blk_Entry(creq->lba, creq->nlbas, creq->bid));
        ++itr;
    }
    jval.set(lbes);
}

void Volume::process_data_completions(const boost::intrusive_ptr< blkstore_req< BlkBuffer > >& bs_req) {
    auto vreq = volume_req::cast(bs_req);
    auto& parent_req = vreq->parent_req;

    assert(parent_req != nullptr);
    assert(!vreq->isSyncCall);

    VOL_LOG(TRACE, volume, parent_req, "data op complete: status={}", vreq->err.message());

    std::vector< Free_Blk_Entry > fbes;
    if (vreq->is_read) {
        fbes.push_back(Free_Blk_Entry(vreq->bid, vreq->read_buf_offset, vreq->read_size));
        // for write flow, we havent marked anything till meta completion, so nothing to do
    }

#ifdef _PRERELEASE
    if (parent_req->outstanding_io_cnt.get() > 2 && homestore_flip->test_flip("vol_vchild_error")) {
        vreq->err = homestore_error::flip_comp_error;
    }
#endif
    // Shortcut to error completion
    if (vreq->err) {
        if (!vreq->is_read) {
            COUNTER_DECREMENT(m_metrics, volume_outstanding_data_write_count, 1);
        } else {
            COUNTER_DECREMENT(m_metrics, volume_outstanding_data_read_count, 1);
        }
#ifndef NDEBUG
        {
            std::unique_lock< std::mutex > mtx(m_req_mtx);
            auto it = m_req_map.find(vreq->reqId);
            assert(it != m_req_map.end());
            m_req_map.erase(it);
        }
#endif
        check_and_complete_req(parent_req, vreq->err, true /* call_completion_cb */, &fbes /* empty for write flow*/);
        return;
    }

    HISTOGRAM_OBSERVE_IF_ELSE(m_metrics, vreq->is_read, volume_data_read_latency, volume_data_write_latency,
                              get_elapsed_time_us(vreq->op_start_time));
    if (!vreq->is_read) {
        assert(vreq->nlbas < 256 && vreq->bid.get_nblks() < 256);
        if (vreq->parent_req->outstanding_data_io_cnt.decrement_testz(1)) {
            // all data io finished, time to write to journal
            // get all child requests from request context
            auto vhb_req = vol_hb_req::cast(parent_req);
            VolumeJournalKey jkey;
            VolumeJournalValue jvalue;
            set_journal_key_value(jkey, jvalue, vhb_req);

            uint64_t log_id;
            m_volume_journal->append_sync(jkey, jvalue, log_id); // sync write to journal

            // TODO - in future append is going to be async and process_journal_compl will be invoked
            // when data is persisted on drive (group commit)
            process_journal_completions(vhb_req, log_id);
        }
    } else {
        std::array< uint16_t, CS_ARRAY_STACK_SIZE > carr;
        uint64_t offset = 0;
        for (int i = 0; i < vreq->nlbas; i++) {
            carr[i] =
                crc16_t10dif(init_crc_16, vreq->bbuf->at_offset(vreq->read_buf_offset + offset).bytes, get_page_size());
            offset += get_page_size();

            VOL_RELEASE_ASSERT_CMP(vreq->checksum[i], ==, carr[i], vreq->parent_req,
                                   "Checksum mismatch and blks from cache {}",
                                   vreq->is_blk_from_cache(vreq->read_buf_offset + offset));
        }
        COUNTER_DECREMENT(m_metrics, volume_outstanding_data_read_count, 1);
        check_and_complete_req(parent_req, no_error, true /* call_completion_cb */, &fbes);
#ifndef NDEBUG
        {
            std::unique_lock< std::mutex > mtx(m_req_mtx);
            auto it = m_req_map.find(vreq->reqId);
            assert(it != m_req_map.end());
            m_req_map.erase(it);
        }
#endif
    }
}

std::error_condition Volume::write(uint64_t lba, uint8_t* buf, uint32_t nlbas, const vol_interface_req_ptr& hb_req) {
    assert(m_sb->ondisk_sb->page_size % HomeBlks::instance()->get_data_pagesz() == 0);
    assert((m_sb->ondisk_sb->page_size * nlbas) <= VOL_MAX_IO_SIZE);

    // TODO: @hkadayam Remove the init() call and fix the tests to always use fresh vol_interface_req on every call
    hb_req->init();
    hb_req->io_start_time = Clock::now();
    hb_req->is_read = false;
    // An outside cover to ensure that all vol reqs are issued before any one vol request completion triggering
    // vol_interface_req completion.
    hb_req->outstanding_io_cnt.set(1);

    // buf will be freed automatically when ref count drops to zero
    boost::intrusive_ptr< homeds::MemVector > mvec(new homeds::MemVector());
    mvec->set(buf, m_sb->ondisk_sb->page_size * nlbas, 0);

    if (is_offline()) {
        check_and_complete_req(hb_req, std::make_error_condition(std::errc::no_such_device), false, nullptr);
        return std::make_error_condition(std::errc::no_such_device);
    }

    std::vector< BlkId > bid;
    blk_alloc_hints hints;
    hints.desired_temp = 0;
    hints.dev_id_hint = -1;
    hints.multiplier = (m_sb->ondisk_sb->page_size / HomeBlks::instance()->get_data_pagesz());

    VOL_LOG(TRACE, volume, hb_req, "write: lba={}, nlbas={}, buf={}", lba, nlbas, (void*)buf);
    try {
        BlkAllocStatus status = m_data_blkstore->alloc_blk(nlbas * m_sb->ondisk_sb->page_size, hints, bid);
        if (status != BLK_ALLOC_SUCCESS) {
            LOGERROR("failing IO as it is out of disk space");
            check_and_complete_req(hb_req, std::make_error_condition(std::errc::no_space_on_device), false);
            return std::errc::no_space_on_device;
        }
        assert(status == BLK_ALLOC_SUCCESS);
        HISTOGRAM_OBSERVE(m_metrics, volume_blkalloc_latency, get_elapsed_time_ns(hb_req->io_start_time));
        COUNTER_INCREMENT(m_metrics, volume_write_count, 1);
    } catch (const std::exception& e) {
        VOL_LOG_ASSERT(0, hb_req, "Exception: {}", e.what())
        check_and_complete_req(hb_req, std::make_error_condition(std::errc::device_or_resource_busy), false);
        return hb_req->err;
    }

    m_used_size.fetch_add(nlbas * m_sb->ondisk_sb->page_size, std::memory_order_relaxed);

    uint32_t offset = 0;
    uint32_t lbas_snt = 0;
    uint32_t i = 0;

    Clock::time_point data_io_start_time = Clock::now();
    auto sid = seq_Id.fetch_add(1, memory_order_seq_cst);
    auto vhb_req = vol_hb_req::cast(hb_req);

    /* Create child requests */
    for (i = 0; i < bid.size(); ++i) {
        volume_req_ptr vreq = Volume::create_vol_req(this, hb_req);
        vreq->bid = bid[i];
        vreq->lba = lba + lbas_snt;
        // TODO - actual seqId/lastCommit seq id should be from vol interface req
        vreq->seqId = INVALID_SEQ_ID;           // GET_IO_SEQ_ID(sid);
        vreq->lastCommited_seqId = vreq->seqId; // keeping only latest version always
        vreq->op_start_time = data_io_start_time;
        vreq->reqId = ++m_req_id;

        assert((bid[i].data_size(HomeBlks::instance()->get_data_pagesz()) % m_sb->ondisk_sb->page_size) == 0);
        vreq->nlbas = bid[i].data_size(HomeBlks::instance()->get_data_pagesz()) / m_sb->ondisk_sb->page_size;

        vhb_req->child_reqs.push_back(vreq);

        VOL_LOG(TRACE, volume, vreq->parent_req, "alloc_blk: bid: {}, offset: {}, nblks: {}", bid[i].to_string(),
                bid[i].data_size(HomeBlks::instance()->get_data_pagesz()), vreq->nlbas);
        COUNTER_INCREMENT(m_metrics, volume_outstanding_data_write_count, 1);

#ifndef NDEBUG
        {
            std::unique_lock< std::mutex > mtx(m_req_mtx);
            m_req_map.emplace(std::make_pair(vreq->reqId, vreq));
        }
#endif
        lbas_snt += vreq->nlbas;
    }
    try {
        /* Issue child requests */
        for (i = 0; i < vhb_req->child_reqs.size(); ++i) {
            volume_req_ptr vreq = vhb_req->child_reqs[i];
            std::deque< writeback_req_ptr > req_q;

            boost::intrusive_ptr< BlkBuffer > bbuf = m_data_blkstore->write(
                vreq->bid, mvec, offset, boost::static_pointer_cast< blkstore_req< BlkBuffer > >(vreq), req_q);

            offset += bid[i].data_size(HomeBlks::instance()->get_data_pagesz());
        }

        HISTOGRAM_OBSERVE(m_metrics, volume_pieces_per_write, bid.size());
        check_and_complete_req(hb_req, no_error, true /* call_completion_cb */);
        assert(lbas_snt == nlbas);
    } catch (const std::exception& e) {
        VOL_LOG_ASSERT(0, hb_req, "Exception: {}", e.what())
        check_and_complete_req(hb_req, std::make_error_condition(std::errc::io_error), false);
        return hb_req->err;
    }

    auto wr_size = m_sb->ondisk_sb->page_size * nlbas;
    HISTOGRAM_OBSERVE(m_metrics, volume_write_size_distribution, wr_size);
    COUNTER_INCREMENT(m_metrics, volume_write_size_total, wr_size);

    return no_error;
}

/* This methods check if we can complete the req and if we can do so. This is the exit point of all async volume
 * read/write operations. All read/writes must call this if it is sync or async.
 *
 * If all ios for request is completed or any one io is errored out, it will call completion if its an async completion
 *
 * Parameters are:
 * 1) hb_req: Request which is to be checked and completed
 * 2) Error: Any IO error condition. Note if there is an error, the request is immediately completed.
 * 3) call_completion_cb: Should we call the inbuilt completion as part of the complete_io
 */
void Volume::check_and_complete_req(const vol_interface_req_ptr& hb_req, const std::error_condition& err,
                                    bool call_completion, std::vector< Free_Blk_Entry >* fbes) {
    // If there is error and request is not completed yet, we need to complete it now.
    VOL_LOG(TRACE, volume, hb_req, "complete_io: status={}, call_completion={}, outstanding_io_cnt={}", err.message(),
            call_completion, hb_req->outstanding_io_cnt.get());

    m_read_blk_tracker->safe_remove_blks(hb_req->is_read, fbes, err);

    if (err) {
        if (hb_req->set_error(err)) {
            // Was not completed earlier, so complete the io
            COUNTER_INCREMENT_IF_ELSE(m_metrics, hb_req->is_read, volume_write_error_count, volume_read_error_count, 1);
            uint64_t cnt = m_err_cnt.fetch_add(1, std::memory_order_relaxed);
            VOL_LOG(ERROR, , hb_req, "Vol operation error {}", err.message());
        } else {
            VOL_LOG(WARN, , hb_req, "Receiving completion on already completed request id={}", hb_req->request_id);
        }
    }

    if (hb_req->outstanding_io_cnt.decrement_testz(1)) {
        HISTOGRAM_OBSERVE_IF_ELSE(m_metrics, hb_req->is_read, volume_read_latency, volume_write_latency,
                                  get_elapsed_time_us(hb_req->io_start_time));
        if (get_elapsed_time_ms(hb_req->io_start_time) > 5000) {
            VOL_LOG(WARN, , hb_req, "vol req took time {}", get_elapsed_time_ms(hb_req->io_start_time));
        }
        if (call_completion) {
            // Clear child requests before returning completion.
            // This ensure release of cyclic dependancy between child_reqs and parent_req intrusive ptrs.
            auto vhb_req = vol_hb_req::cast(hb_req);
            vhb_req->child_reqs.clear();
#ifdef _PRERELEASE
            if (auto flip_ret = homestore_flip->get_test_flip< int >("vol_comp_delay_us")) {
                LOGINFO("delaying completion in volume");
                usleep(flip_ret.get());
            }
#endif
            VOL_LOG(TRACE, volume, hb_req, "IO DONE");
            m_comp_cb(hb_req);
        }
    }
}

void Volume::print_tree() { m_map->print_tree(); }

void Volume::print_node(uint64_t blkid) { m_map->print_node(blkid); }

#if 0
std::error_condition Volume::read_metadata(const vol_req_ptr& vreq) {
    MappingKey                                           key(vreq->lba, vreq->nlbas);
    std::vector< std::pair< MappingKey, MappingValue > > kvs;

#ifndef NDEBUG
    vreq->vol_uuid = m_sb->ondisk_sb->uuid;
    VOL_LOG(DEBUG, volume, vreq->parent_req, "Mapping.GET vol_uuid:{} ,key:{} last_seqId: {}",
        boost::uuids::to_string(vreq->vol_uuid), key.to_string(), vreq->lastCommited_seqId);
#endif

    auto err = m_map->get(vreq, key, kvs);
    if (err) {
        if (err != homestore_error::lba_not_exist) {
            COUNTER_INCREMENT(m_metrics, volume_read_error_count, 1);
        }
        check_and_complete_req(hb_req, err, false /* call_completion_cb */);
        return err;
    }
    HISTOGRAM_OBSERVE(m_metrics, volume_map_read_latency, get_elapsed_time_us(vreq->parant_req->io_start_time));

    return no_error;
}
#endif

std::error_condition Volume::read(uint64_t lba, int nlbas, const vol_interface_req_ptr& hb_req, bool sync) {

    std::vector< Free_Blk_Entry > fbes; // used to clean up in case of error(for async) and in case of sync call

    try {
        VOL_LOG(TRACE, volume, hb_req, "read: lba={}, nlbas={}, sync={}", lba, nlbas, sync);
        hb_req->init();
        hb_req->io_start_time = Clock::now();
        hb_req->is_read = true;

        // seqId shoudl be passed from vol interface req and passed to mapping layer
        auto sid = seq_Id.fetch_add(1, memory_order_seq_cst);

        volume_req_ptr vreq = Volume::create_vol_req(this, hb_req);
        vreq->request_id = hb_req->request_id;
        vreq->lba = lba;
        vreq->nlbas = nlbas;
        vreq->seqId = INVALID_SEQ_ID;           // GET_IO_SEQ_ID(sid);
        vreq->lastCommited_seqId = vreq->seqId; // read only latest value

        std::vector< std::pair< MappingKey, MappingValue > > kvs;

#ifndef NDEBUG
        vreq->vol_uuid = m_sb->ondisk_sb->uuid;
        VOL_LOG(DEBUG, volume, vreq->parent_req, "Mapping.GET vol_uuid:{}, last_seqId: {}",
                boost::uuids::to_string(vreq->vol_uuid), vreq->lastCommited_seqId);
#endif

        if (is_offline()) {
            check_and_complete_req(hb_req, std::make_error_condition(std::errc::no_such_device), false, nullptr);
            return std::make_error_condition(std::errc::no_such_device);
        }
        COUNTER_INCREMENT(m_metrics, volume_read_count, 1);
        COUNTER_INCREMENT(m_metrics, volume_outstanding_metadata_read_count, 1);
        auto err = m_map->get(vreq, kvs);
        COUNTER_DECREMENT(m_metrics, volume_outstanding_metadata_read_count, 1);

        get_free_blk_entries(kvs, fbes);

        if (err) {
            if (err != homestore_error::lba_not_exist) { COUNTER_INCREMENT(m_metrics, volume_read_error_count, 1); }
            check_and_complete_req(hb_req, err, false /* call_completion_cb */, &fbes);
            return err;
        }
        HISTOGRAM_OBSERVE(m_metrics, volume_map_read_latency, get_elapsed_time_us(hb_req->io_start_time));
        Clock::time_point data_io_start_time = Clock::now();

        hb_req->read_buf_list.reserve(kvs.size());
#ifndef NDEBUG
        auto cur_lba = lba;
#endif
        for (auto& kv : kvs) {
            if (!(kv.second.is_valid())) {
                hb_req->read_buf_list.emplace_back(m_sb->ondisk_sb->get_page_size(), 0, m_only_in_mem_buff);
#ifndef NDEBUG
                cur_lba++;
#endif
            } else {
                volume_req_ptr child_vreq = Volume::create_vol_req(this, hb_req);
                child_vreq->lba = kv.first.start();
                child_vreq->nlbas = kv.first.get_n_lba();
                child_vreq->is_read = true;
                child_vreq->isSyncCall = sync;
                child_vreq->op_start_time = data_io_start_time;
                child_vreq->reqId = ++m_req_id;

                assert(kv.second.get_array().get_total_elements() == 1);
                ValueEntry ve;
                (kv.second.get_array()).get(0, ve, false);

                /* Get checksum also */
                for (auto i = 0ul; i < kv.first.get_n_lba(); i++) {
                    child_vreq->checksum[i] = ve.get_checksum_at(i);
                }

                auto sz = get_page_size() * kv.first.get_n_lba();
                auto offset = HomeBlks::instance()->get_data_pagesz() * ve.get_blk_offset();
                child_vreq->read_buf_offset = offset;
                child_vreq->bid = ve.get_blkId();
                child_vreq->read_size = sz;
                COUNTER_INCREMENT(m_metrics, volume_outstanding_data_read_count, 1);
#ifndef NDEBUG
                {
                    if (!sync) {
                        std::unique_lock< std::mutex > mtx(m_req_mtx);
                        m_req_map.emplace(std::make_pair(child_vreq->reqId, child_vreq));
                    }
                }
#endif
                boost::intrusive_ptr< BlkBuffer > bbuf = m_data_blkstore->read(
                    ve.get_blkId(), offset, sz, boost::static_pointer_cast< blkstore_req< BlkBuffer > >(child_vreq));

                // TODO: @hkadayam There is a potential for race of read_buf_list getting emplaced after completion
                hb_req->read_buf_list.emplace_back(sz, offset, bbuf);
                if (sync) {
                    COUNTER_DECREMENT(m_metrics, volume_outstanding_data_read_count, 1);
                    std::array< uint16_t, CS_ARRAY_STACK_SIZE > carr;
                    uint64_t offset = 0;
                    for (int i = 0; i < child_vreq->nlbas; i++) {
                        carr[i] = crc16_t10dif(init_crc_16,
                                               child_vreq->bbuf->at_offset(child_vreq->read_buf_offset + offset).bytes,
                                               get_page_size());
                        offset += get_page_size();
                        VOL_RELEASE_ASSERT_CMP(child_vreq->checksum[i], ==, carr[i], child_vreq->parent_req,
                                               "Checksum mismatch");
                    }
                } else { // for async call, clean up is done in process completion
                    remove_free_blk_entry(fbes, kv);
                }
            }
        }
        auto rd_size = m_sb->ondisk_sb->page_size * nlbas;
        HISTOGRAM_OBSERVE(m_metrics, volume_read_size_distribution, rd_size);
        COUNTER_INCREMENT(m_metrics, volume_read_size_total, rd_size);

#ifndef NDEBUG
        if (sync)
            assert(fbes.size() == kvs.size());
        else
            assert(fbes.size() == 0);
#endif
        // Atleast 1 metadata io is completed.
        check_and_complete_req(hb_req, no_error, !sync /* call_completion_cb */, &fbes);
    } catch (const std::exception& e) {
        VOL_LOG_ASSERT(0, hb_req, "Exception: {}", e.what())
        check_and_complete_req(hb_req, std::make_error_condition(std::errc::device_or_resource_busy), false, &fbes);
        return hb_req->err;
    }
    return no_error;
}

/* Just create single block in memory, not on physical device and not in cache */
void Volume::alloc_single_block_in_mem() {
    BlkId out_blkid(0);
    // Create an object for the buffer
    m_only_in_mem_buff = BlkBuffer::make_object();
    m_only_in_mem_buff->set_key(out_blkid);

    // Create a new block of memory for the blocks requested and set the memvec pointer to that
    uint8_t* ptr;
    uint32_t size = m_sb->ondisk_sb->page_size;
    ptr = (uint8_t*)malloc(size);
    if (ptr == nullptr) { throw std::bad_alloc(); }
    memset(ptr, 0, size);

    boost::intrusive_ptr< homeds::MemVector > mvec(new homeds::MemVector());
    mvec->set(ptr, size, 0);
    m_only_in_mem_buff->set_memvec(mvec, 0, size);
}

//
// Say we have t threads in pool
// round = 0;
// T1: Range Query [64MB*0, 64MB*1),
// T2: Range Query [64MB*1 ~ 64MB*2),
// ...
// Tt: Range Query [64MB*(t-1) ~ 64MB*t]
//
// When T[i] finishes, it should do Range Query to :
// [64MB*(0+round), 64MB*(1+round)];
//
// When last thread in previous round finishes (need a in-memory bitmap to indicate
// whether this is the last thread completing its task in current round):
// round++;
//
// Repeat until "Range Query" returns false (nothing more left to query);
//
void Volume::get_allocated_blks() {

    mapping* mp = get_mapping_handle();

    uint64_t max_lba = get_last_lba() + 1;

    uint64_t start_lba = 0, end_lba = 0;

    std::vector< ThreadPool::TaskFuture< void > > v;

    bool success = true;
    while (end_lba < max_lba) {
        // if high watermark is hit, wait for a while so that we do not consuming too
        // much memory pushing new tasks. This is helpful when volume size is extreamly large.
        if (get_thread_pool().high_watermark()) {
            std::this_thread::yield();
            continue;
        }

        start_lba = end_lba;
        end_lba = std::min((unsigned long long)max_lba, end_lba + NUM_BLKS_PER_THREAD_TO_QUERY);

        v.push_back(submit_job([this, start_lba, end_lba, mp]() {
            if (mp->sweep_alloc_blks(start_lba, end_lba)) { this->set_recovery_error(); }
        }));
    }

    for (auto& x : v) {
        x.get();
    }

    // return completed with success to the caller
    blk_recovery_process_completions(!m_recovery_error);
}

void Volume::set_recovery_error() {
    /* XXX: does it need to be atomic variable. Don't think so as we can only set it to false in thread pool */
    m_recovery_error = true;
}

bool Volume::is_offline() { return (m_state == DESTROYING || m_state == FAILED || m_state == OFFLINE); }
