
//
// Created by Kadayam, Hari on 06/11/17.
//

#include <homeblks/home_blks.hpp>
#include "mapping.hpp"
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
std::atomic< uint64_t > Volume::home_blks_ref_cnt = 0;

namespace homestore {
void intrusive_ptr_add_ref(homestore::BlkBuffer* buf) { intrusive_ptr_add_ref((homestore::CacheBuffer< BlkId >*)buf); }

void intrusive_ptr_release(homestore::BlkBuffer* buf) { intrusive_ptr_release((homestore::CacheBuffer< BlkId >*)buf); }
} // namespace homestore

#ifdef _PRERELEASE
void Volume::set_error_flip() {
    FlipClient* fc = HomeStoreFlip::client_instance();
    FlipFrequency freq;
    FlipCondition cond1;

    FlipCondition null_cond;
    fc->create_condition("", flip::Operator::DONT_CARE, (int)1, &null_cond);

    freq.set_count(2000000000);
    freq.set_percent(1);

    /* error flips */
    freq.set_percent(1);
    //    fc->inject_retval_flip("delay_us_and_inject_error_on_completion", { null_cond }, freq, 20);
    fc->inject_noreturn_flip("varsize_blkalloc_no_blks", {null_cond}, freq);
}

void Volume::set_io_flip() {
    FlipClient* fc = HomeStoreFlip::client_instance();
    FlipFrequency freq;
    FlipCondition cond1;
    freq.set_count(2000000000);
    freq.set_percent(5);

    FlipCondition null_cond;
    fc->create_condition("", flip::Operator::DONT_CARE, (int)1, &null_cond);

    /* io flips */
    fc->inject_retval_flip("vol_delay_read_us", {null_cond}, freq, 20);

    fc->inject_retval_flip("cache_insert_race", {null_cond}, freq, 20);
    fc->inject_retval_flip("io_write_iocb_empty_flip", {null_cond}, freq, 20);
    fc->inject_retval_flip("io_read_iocb_empty_flip", {null_cond}, freq, 20);

    fc->inject_retval_flip("blkalloc_split_blk", {null_cond}, freq, 4);
}
#endif

Volume::Volume(const vol_params& params) :
        m_params(params), m_metrics(boost::uuids::to_string(params.uuid).c_str()), m_comp_cb(params.io_comp_cb) {
    m_state = vol_state::UNINITED;
    m_hb = HomeBlks::safe_instance();
    seq_Id = 3;
    m_read_blk_tracker = std::make_unique< Blk_Read_Tracker >(
        params.vol_name, params.uuid, std::bind(&Volume::process_free_blk_callback, this, std::placeholders::_1));
}

Volume::Volume(vol_sb_hdr& sb) : m_metrics(sb.vol_name) {
    /* TODO : add recovery code */
    /* Take care of vdev error and init cnt */
}

void Volume::init() {
    m_indx_mgr =
        new IndxMgr(shared_from_this(), m_params,
                    std::bind(&Volume::process_indx_completions, this, std::placeholders::_1, std::placeholders::_2),
                    std::bind(&Volume::process_free_blk_callback, this, std::placeholders::_1),
                    std::bind(&Volume::pending_read_blk_cb, this, std::placeholders::_1, std::placeholders::_2));
    vol_sb_hdr* sb;
    auto ret = posix_memalign((void**)&(sb), HS_STATIC_CONFIG(disk_attr.align_size), sizeof(vol_sb_hdr));
    assert(!ret);
    m_sb = new (sb) vol_sb_hdr(m_params.page_size, m_params.size, (char*)m_params.vol_name, m_params.uuid,
                               m_indx_mgr->get_active_sb());
    assert(sb != nullptr);
    alloc_single_block_in_mem();
    assert(get_page_size() % HomeBlks::instance()->get_data_pagesz() == 0);
    set_state(vol_state::ONLINE, true);
}

void Volume::destroy(indxmgr_stop_cb cb) {
    /* we don't allow shutdown and destroy in parallel */
    ++home_blks_ref_cnt;
    if (m_hb->is_shutdown()) {
        auto cnt = home_blks_ref_cnt.fetch_sub(1);
        if (cnt == 1) { m_hb->do_volume_shutdown(true); }
    }

    ++vol_ref_cnt;
    auto prev_state = set_state(vol_state::DESTROYING);
    if (prev_state == vol_state::DESTROYING) {
        auto cnt = home_blks_ref_cnt.fetch_sub(1);
        if (cnt == 1) { m_hb->do_volume_shutdown(true); }
        return;
    }

    m_destroy_done_cb = cb;
    auto cnt = vol_ref_cnt.fetch_sub(1);
    if (cnt == 1) { destroy_internal(); }
}

void Volume::destroy_internal() {
    m_indx_mgr->destroy(([this](bool success) {
        if (success) {
            LOGINFO("volume destroyed");
            remove_sb();
            m_indx_mgr->destroy_done();
        }
        m_destroy_done_cb(success);
        auto cnt = home_blks_ref_cnt.fetch_sub(1);
        if (cnt == 1) { m_hb->do_volume_shutdown(true); }
    }));
}

void Volume::shutdown(indxmgr_stop_cb cb) { IndxMgr::shutdown(cb); }

Volume::~Volume() {
    free(m_sb);
    free(m_indx_mgr);
}

std::error_condition Volume::write(const vol_interface_req_ptr& hb_req) {

    auto vreq = volume_req::cast(hb_req);
    std::vector< BlkId > bid;

    COUNTER_INCREMENT(m_metrics, volume_outstanding_data_write_count, 1);

    /* Sanity checks */
    ++home_blks_ref_cnt;
    ++vol_ref_cnt;
    // sync write is not supported
    assert(!vreq->sync);
    if (is_offline()) {
        check_and_complete_req(vreq, std::make_error_condition(std::errc::no_such_device));
        return std::make_error_condition(std::errc::no_such_device);
    }

    /* Allocate blkid */
    if (alloc_blk(vreq, bid) != no_error) {
        check_and_complete_req(vreq, std::make_error_condition(std::errc::device_or_resource_busy));
        return vreq->err;
    }

    /* Note: If we crash before we write this entry to a journal then there is a chance
     * of leaking these allocated blocks.
     */
    uint32_t offset = 0;
    uint32_t start_lba = vreq->lba;
    try {
        for (uint32_t i = 0; i < bid.size(); ++i) {
            /* Create child requests */
            int nlba = bid[i].data_size(HomeBlks::instance()->get_data_pagesz()) / get_page_size();
            auto vc_req = create_vol_child_req(bid[i], vreq, start_lba, nlba);
            start_lba += nlba;

            /* Issue child request */
            /* store blkid which is used later to create journal entry */
            vreq->push_blkid(bid[i]);
            boost::intrusive_ptr< BlkBuffer > bbuf = m_hb->get_data_blkstore()->write(
                vc_req->bid, vreq->mvec, offset, boost::static_pointer_cast< blkstore_req< BlkBuffer > >(vc_req),
                false);

            offset += bid[i].data_size(m_hb->get_data_pagesz());
        }
        assert((start_lba - vreq->lba) == vreq->nlbas);

        /* compute checksum and store it in a request */
        for (uint32_t i = 0; i < vreq->nlbas; ++i) {
            homeds::blob outb;
            vreq->mvec->get(&outb, i * get_page_size());
            vreq->push_csum(crc16_t10dif(init_crc_16, outb.bytes, get_page_size()));
        }

        /* complete the request */
        check_and_complete_req(vreq, no_error);
    } catch (const std::exception& e) {
        VOL_LOG_ASSERT(0, vreq, "Exception: {}", e.what())
        check_and_complete_req(vreq, std::make_error_condition(std::errc::io_error));
        return vreq->err;
    }

    return no_error;
}

std::error_condition Volume::read(const vol_interface_req_ptr& hb_req) {

    auto vreq = volume_req::cast(hb_req);

    THIS_VOL_LOG(TRACE, volume, vreq, "read: lba={}, nlbas={}, sync={}", vreq->lba, vreq->nlbas, vreq->sync);
    COUNTER_INCREMENT(m_metrics, volume_read_count, 1);
    COUNTER_INCREMENT(m_metrics, volume_outstanding_data_read_count, 1);

    try {
        /* add sanity checks */
        ++home_blks_ref_cnt;
        ++vol_ref_cnt;
        if (is_offline()) {
            check_and_complete_req(vreq, std::make_error_condition(std::errc::no_such_device));
            return std::make_error_condition(std::errc::no_such_device);
        }

        /* read indx */
        std::vector< std::pair< MappingKey, MappingValue > > kvs;
        auto err = read_indx(vreq, kvs);
        if (err != no_error) {
            check_and_complete_req(vreq, err);
            return err;
        }

        /* create child req and read buffers */
        vreq->read_buf_list.reserve(kvs.size());
        for (auto& kv : kvs) {
            if (!(kv.second.is_valid())) {
                vreq->read_buf_list.emplace_back(get_page_size(), 0, m_only_in_mem_buff);
                auto blob = m_only_in_mem_buff->at_offset(0);
                vreq->push_csum(crc16_t10dif(init_crc_16, blob.bytes, get_page_size()));
            } else {
                ValueEntry ve;
                (kv.second.get_array()).get(0, ve, false);
                assert(kv.second.get_array().get_total_elements() == 1);

                volume_child_req_ptr vc_req =
                    Volume::create_vol_child_req(ve.get_blkId(), vreq, kv.first.start(), kv.first.get_n_lba());

                /* store csum read so that we can verify it later after data is read */
                for (auto i = 0ul; i < kv.first.get_n_lba(); i++) {
                    vreq->push_csum(ve.get_checksum_at(i));
                }

                /* Read data */
                auto sz = get_page_size() * kv.first.get_n_lba();
                auto offset = m_hb->get_data_pagesz() * ve.get_blk_offset();
                boost::intrusive_ptr< BlkBuffer > bbuf = m_hb->get_data_blkstore()->read(
                    ve.get_blkId(), offset, sz, boost::static_pointer_cast< blkstore_req< BlkBuffer > >(vc_req));

                // TODO: @hkadayam There is a potential for race of read_buf_list getting emplaced after completion
                /* Add buffer to read_buf_list. User read data from read buf list */
                vreq->read_buf_list.emplace_back(sz, offset, bbuf);
            }
        }

        // Atleast 1 metadata io is completed.
        check_and_complete_req(vreq, no_error);
    } catch (const std::exception& e) {
        VOL_LOG_ASSERT(0, vreq, "Exception: {}", e.what())
        check_and_complete_req(vreq, std::make_error_condition(std::errc::device_or_resource_busy));
        return vreq->err;
    }
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
 */
void Volume::check_and_complete_req(volume_req_ptr& vreq, const std::error_condition& err) {

    // If there is error and request is not completed yet, we need to complete it now.
    THIS_VOL_LOG(TRACE, volume, vreq, "complete_io: status={}, outstanding_io_cnt={}, read {}, indx update {}",
                 err.message(), vreq->outstanding_io_cnt.get(), vreq->is_read, vreq->update_indx);

    if (err) {
        if (vreq->set_error(err)) {
            // Was not completed earlier, so complete the io
            COUNTER_INCREMENT_IF_ELSE(m_metrics, vreq->is_read, volume_write_error_count, volume_read_error_count, 1);
            uint64_t cnt = m_err_cnt.fetch_add(1, std::memory_order_relaxed);
            THIS_VOL_LOG(ERROR, , vreq, "Vol operation error {}", err.message());
            m_read_blk_tracker->safe_remove_blks(vreq);
            if (!vreq->sync) { m_comp_cb(boost::static_pointer_cast< vol_interface_req >(vreq)); }
        } else {
            THIS_VOL_LOG(WARN, , vreq, "Receiving completion on already completed request id={}", vreq->request_id);
        }
    }

    if (!vreq->outstanding_io_cnt.decrement_testz(1)) { return; }

    /* It is single threaded beyond this point */

    if (vreq->err != no_error) {
        try_shutdown_destroy();
        return;
    }

    /* Verify cheksum for read and update indx for write */
    if (vreq->is_read) {
        /* verify checksum for read */
        verify_csum(vreq);
    } else if (!vreq->update_indx) {
        /* update indx mgr */
        vreq->update_indx = true;
        vreq->outstanding_io_cnt.increment(1);
        vreq->indx_start_time = Clock::now();
        m_indx_mgr->update_indx(vreq);
        return;
    }

    m_read_blk_tracker->safe_remove_blks(vreq);

    /* update counters */
    auto size = get_page_size() * vreq->nlbas;
    HISTOGRAM_OBSERVE_IF_ELSE(m_metrics, vreq->is_read, volume_read_latency, volume_write_latency,
                              get_elapsed_time_us(vreq->io_start_time));
    if (vreq->is_read) {
        COUNTER_DECREMENT(m_metrics, volume_outstanding_data_read_count, 1);
        COUNTER_INCREMENT(m_metrics, volume_read_size_total, size);
    } else {
        COUNTER_DECREMENT(m_metrics, volume_outstanding_data_write_count, 1);
        COUNTER_INCREMENT(m_metrics, volume_write_size_total, size);
    }
    HISTOGRAM_OBSERVE_IF_ELSE(m_metrics, vreq->is_read, volume_read_size_distribution, volume_write_size_distribution,
                              size);
    HISTOGRAM_OBSERVE_IF_ELSE(m_metrics, vreq->is_read, volume_pieces_per_write, volume_pieces_per_read,
                              vreq->vc_req_cnt);

    if (get_elapsed_time_ms(vreq->io_start_time) > 5000) {
        THIS_VOL_LOG(WARN, , vreq, "vol req took time {}", get_elapsed_time_ms(vreq->io_start_time));
    }

    if (!vreq->sync) {
#ifdef _PRERELEASE
        if (auto flip_ret = homestore_flip->get_test_flip< int >("vol_comp_delay_us")) {
            LOGINFO("delaying completion in volume");
            usleep(flip_ret.get());
        }
#endif
        THIS_VOL_LOG(TRACE, volume, vreq, "IO DONE");
        m_comp_cb(boost::static_pointer_cast< vol_interface_req >(vreq));
    }
    try_shutdown_destroy();
}

void Volume::try_shutdown_destroy() {
    auto homeblks_io_cnt = home_blks_ref_cnt.fetch_sub(1);
    auto vol_io_cnt = vol_ref_cnt.fetch_sub(1);
    if (homeblks_io_cnt == 1 && m_hb->is_shutdown()) { m_hb->do_volume_shutdown(true); }
    if (vol_io_cnt == 1 && m_state == vol_state::DESTROYING) { destroy_internal(); }
}

//
// No need to do it in multi-threading since blkstore.free_blk is in-mem operation.
//
void Volume::process_free_blk_callback(Free_Blk_Entry fbe) {
    THIS_VOL_LOG(DEBUG, volume, , "Freeing blks cb - bid: {}, offset: {}, nblks: {}, get_pagesz: {}",
                 fbe.m_blkId.to_string(), fbe.blk_offset(), fbe.blks_to_free(), get_page_size());

    uint64_t size = m_hb->get_data_pagesz() * fbe.m_nblks_to_free;
    m_hb->get_data_blkstore()->free_blk(fbe.m_blkId, m_hb->get_data_pagesz() * fbe.m_blk_offset,
                                        m_hb->get_data_pagesz() * fbe.m_nblks_to_free);
}

/* when read happens on mapping btree, under read lock we mark blk so it does not get removed by concurrent writes */
void Volume::pending_read_blk_cb(volume_req_ptr vreq, BlkId& bid) {
    m_read_blk_tracker->insert(bid);
    Free_Blk_Entry fbe(bid, 0, 0);
    vreq->push_fbe(fbe);
}

void Volume::process_indx_completions(volume_req_ptr& vreq, std::error_condition err) {
    assert(!vreq->is_read);
    assert(!vreq->sync);

    COUNTER_DECREMENT(m_metrics, volume_outstanding_metadata_write_count, 1);

    THIS_VOL_LOG(TRACE, volume, vreq, "metadata_complete: status={}", vreq->err.message());
    HISTOGRAM_OBSERVE(m_metrics, volume_map_write_latency, get_elapsed_time_us(vreq->indx_start_time));

    check_and_complete_req(vreq, err);
}

void Volume::process_vol_data_completions(const boost::intrusive_ptr< blkstore_req< BlkBuffer > >& bs_req) {
    volume_child_req::cast(bs_req)->parent_req->vol_instance->process_data_completions(bs_req);
}

void Volume::process_data_completions(const boost::intrusive_ptr< blkstore_req< BlkBuffer > >& bs_req) {
    auto vc_req = volume_child_req::cast(bs_req);
    auto& vreq = vc_req->parent_req;

    assert(vreq != nullptr);
    assert(!vreq->sync);

    THIS_VOL_LOG(TRACE, volume, vreq, "data op complete: status={}", vreq->err.message());

#ifdef _PRERELEASE
    if (vreq->outstanding_io_cnt.get() > 2 && homestore_flip->test_flip("vol_vchild_error")) {
        vreq->err = homestore_error::flip_comp_error;
    }
#endif

    HISTOGRAM_OBSERVE_IF_ELSE(m_metrics, vreq->is_read, volume_data_read_latency, volume_data_write_latency,
                              get_elapsed_time_us(vc_req->op_start_time));
    check_and_complete_req(vreq, vc_req->err);
    return;
}

void Volume::attach_completion_cb(const io_comp_callback& cb) { m_comp_cb = cb; }

void Volume::verify_csum(volume_req_ptr& vreq) {
    uint64_t offset = 0;
    uint32_t csum_indx = 0;

    for (auto& info : vreq->read_buf_list) {
        auto offset = info.offset;
        auto size = info.size;
        auto buf = info.buf;
        while (size != 0) {
            homeds::blob b = VolInterface::get_instance()->at_offset(buf, offset);
            for (uint32_t size_read = 0; size_read < b.size && size != 0; size_read += get_page_size()) {
                uint16_t csum = crc16_t10dif(init_crc_16, b.bytes + size_read, get_page_size());

                size -= get_page_size();
                offset += get_page_size();

                VOL_RELEASE_ASSERT_CMP(vreq->csum_list[csum_indx++], ==, csum, vreq, "Checksum mismatch");
            }
        }
    }
}

std::error_condition Volume::read_indx(volume_req_ptr& vreq,
                                       std::vector< std::pair< MappingKey, MappingValue > >& kvs) {
    /* get list of key values */
    COUNTER_INCREMENT(m_metrics, volume_outstanding_metadata_read_count, 1);
    auto err = m_indx_mgr->get_active_indx()->get(vreq, kvs);
    COUNTER_DECREMENT(m_metrics, volume_outstanding_metadata_read_count, 1);
    HISTOGRAM_OBSERVE(m_metrics, volume_map_read_latency, get_elapsed_time_us(vreq->io_start_time));
    if (err) {
        if (err != homestore_error::lba_not_exist) { COUNTER_INCREMENT(m_metrics, volume_read_error_count, 1); }
        return err;
    }
    return no_error;
}

vol_interface_req_ptr Volume::create_volume_req(std::shared_ptr< Volume >& vol, void* buf, uint64_t lba, uint32_t nlbas,
                                                bool read, bool sync) {
    return volume_req::make_instance(vol, buf, lba, nlbas, read, sync);
}

/* It is not lock protected. It should be called only by thread for a vreq */
volume_child_req_ptr Volume::create_vol_child_req(BlkId& bid, const volume_req_ptr& vreq, uint32_t start_lba,
                                                  int nlba) {
    volume_child_req_ptr vc_req = volume_child_req::make_request();
    vc_req->parent_req = vreq;
    vc_req->is_read = vreq->is_read;
    vc_req->bid = bid;
    vc_req->lba = start_lba;
    vc_req->op_start_time = Clock::now();
    ;
    vc_req->reqId = ++m_req_id;
    vc_req->sync = vreq->sync;

    assert((bid.data_size(HomeBlks::instance()->get_data_pagesz()) % get_page_size()) == 0);
    vc_req->nlbas = nlba;

    assert(vc_req->nlbas > 0);

    if (!vreq->sync) { vreq->outstanding_io_cnt.increment(1); }
    ++vreq->vc_req_cnt;
    THIS_VOL_LOG(TRACE, volume, vc_req->parent_req, "alloc_blk: bid: {}, offset: {}, nblks: {}", bid.to_string(),
                 bid.data_size(HomeBlks::instance()->get_data_pagesz()), vc_req->nlbas);
    return vc_req;
}

void Volume::print_tree() { m_indx_mgr->get_active_indx()->print_tree(); }
bool Volume::verify_tree() { return (m_indx_mgr->get_active_indx()->verify_tree()); }
void Volume::print_node(uint64_t blkid) { m_indx_mgr->get_active_indx()->print_node(blkid); }

std::error_condition Volume::alloc_blk(volume_req_ptr& vreq, std::vector< BlkId >& bid) {
    blk_alloc_hints hints;
    hints.desired_temp = 0;
    hints.dev_id_hint = -1;
    hints.multiplier = (get_page_size() / m_hb->get_data_pagesz());

    THIS_VOL_LOG(TRACE, volume, vreq, "write: lba={}, nlbas={}", vreq->lba, vreq->nlbas);
    try {
        BlkAllocStatus status = m_hb->get_data_blkstore()->alloc_blk(vreq->nlbas * get_page_size(), hints, bid);
        if (status != BLK_ALLOC_SUCCESS) {
            LOGERROR("failing IO as it is out of disk space");
            check_and_complete_req(vreq, std::make_error_condition(std::errc::no_space_on_device));
            return std::errc::no_space_on_device;
        }
        assert(status == BLK_ALLOC_SUCCESS);
        HISTOGRAM_OBSERVE(m_metrics, volume_blkalloc_latency, get_elapsed_time_ns(vreq->io_start_time));
        COUNTER_INCREMENT(m_metrics, volume_write_count, 1);
    } catch (const std::exception& e) {
        VOL_LOG_ASSERT(0, vreq, "Exception: {}", e.what());
        return std::errc::device_or_resource_busy;
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
    uint32_t size = get_page_size();
    ptr = (uint8_t*)malloc(size);
    if (ptr == nullptr) { throw std::bad_alloc(); }
    memset(ptr, 0, size);

    boost::intrusive_ptr< homeds::MemVector > mvec(new homeds::MemVector());
    mvec->set(ptr, size, 0);
    m_only_in_mem_buff->set_memvec(mvec, 0, size);
}

bool Volume::fix_mapping_btree(bool verify) {
#if 0
        /* TODO: move it to indx mgr */
//    auto ret = m_map->fix(0, get_last_lba(), verify);
    
    // update new btree sb;
    if (ret) {
        m_sb->ondisk_sb->btree_sb = m_map->get_btree_sb();
        m_hb->vol_sb_write(m_sb.get());
    }
#endif
    return false;
}

vol_cp_id_ptr Volume::attach_prepare_volume_cp_id(vol_cp_id_ptr cur_id, indx_cp_id* home_blks_id) {
    return (m_indx_mgr->attach_prepare_vol_cp(cur_id, home_blks_id));
}

#ifndef NDEBUG
void Volume::verify_pending_blks() { assert(m_read_blk_tracker->get_size() == 0); }
#endif

vol_state Volume::set_state(vol_state state, bool persist) {
    LOGINFO("volume state changed from {} to {}", m_state, state);
    auto prev_state = m_state.exchange(state);
    if (prev_state == state) { return prev_state; }
    if (persist) { write_sb(); }
    return prev_state;
}

bool Volume::is_offline() {
    auto state = get_state();
    return (state == vol_state::DESTROYING || state == vol_state::FAILED || state == vol_state::OFFLINE ||
            m_hb->is_shutdown());
}

void Volume::write_sb() {
    std::unique_lock< std::mutex > lk(m_sb_lock);

    /* update mutable params */
    m_sb->state = m_state;

    /* TODO write super block */
}

void Volume::remove_sb() { /* TODO: remove super block */
}

mapping* Volume::get_mapping_handle() { return (m_indx_mgr->get_active_indx()); }
