
//
// Created by Kadayam, Hari on 06/11/17.
//

/* volume file */
#include <homeblks/home_blks.hpp>
#include "volume.hpp"
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
REGISTER_METABLK_SUBSYSTEM(volume, "VOLUME", Volume::meta_blk_found_cb, nullptr)

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
        m_params(params),
        m_metrics(params.vol_name),
        m_comp_cb(params.io_comp_cb),
        m_indx_mgr_destroy_started(false) {

    /* this counter is decremented later when this volume become part of a cp. until then shutdown is
     * not allowed.
     */
    m_hb = HomeBlks::safe_instance();
    ++home_blks_ref_cnt;
    if (m_hb->is_shutdown()) {
        auto cnt = home_blks_ref_cnt.fetch_sub(1);
        if (cnt == 1) { m_hb->do_volume_shutdown(true); }
        throw std::runtime_error("shutdown in progress");
    }
    m_state = vol_state::UNINITED;
}

Volume::Volume(meta_blk* mblk_cookie, sisl::byte_view sb_buf) :
        m_metrics(((vol_sb_hdr*)sb_buf.bytes())->vol_name),
        m_indx_mgr_destroy_started(false),
        m_sb_cookie(mblk_cookie) {
    m_sb_buf = sb_buf;
    auto sb = (vol_sb_hdr*)m_sb_buf.bytes();
    m_state = sb->state;

    m_hb = HomeBlks::safe_instance();
}

void Volume::init() {
    auto sb = (vol_sb_hdr*)m_sb_buf.bytes();
    if (!sb) {

        /* populate superblock */
        uint32_t align = 0;
        if (meta_blk_mgr->is_aligned_buf_needed(sizeof(vol_sb_hdr))) { align = HS_STATIC_CONFIG(disk_attr.align_size); }
        sisl::byte_view b(sizeof(vol_sb_hdr), align);
        m_sb_buf = b;
        sb = (vol_sb_hdr*)m_sb_buf.bytes();
        sb->page_size = m_params.page_size;
        sb->size = m_params.size;
        memcpy((char*)sb->vol_name, (const char*)m_params.vol_name, VOL_NAME_SIZE);
        sb->uuid = m_params.uuid;

        /* create indx tbl */
        m_indx_mgr = SnapMgr::make_SnapMgr(
            m_params.uuid, std::string(m_params.vol_name),
            std::bind(&Volume::process_indx_completions, this, std::placeholders::_1, std::placeholders::_2),
            std::bind(&Volume::process_read_indx_completions, this, std::placeholders::_1, std::placeholders::_2),
            std::bind(&Volume::create_indx_tbl, this), false);

        /* populate indx mgr super block */
        sb->indx_mgr_sb = m_indx_mgr->get_static_sb();

        set_state(vol_state::ONLINE, true);
        seq_Id = m_indx_mgr->get_max_psn_found_in_recovery();
        /* it is called after superblock is persisted by volume */
        m_indx_mgr->indx_init();

        SnapMgr::trigger_indx_cp_with_cb(([this](bool success) {
            /* Now it is safe to do shutdown as this volume has become a part of CP */
            auto cnt = home_blks_ref_cnt.fetch_sub(1);
            if (cnt == 1 && m_hb->is_shutdown()) { m_hb->do_volume_shutdown(true); }
        }));
    } else {
        /* recovery */
        auto indx_mgr_sb = sb->indx_mgr_sb;
        m_indx_mgr = SnapMgr::make_SnapMgr(
            get_uuid(), std::string(get_name()),
            std::bind(&Volume::process_indx_completions, this, std::placeholders::_1, std::placeholders::_2),
            std::bind(&Volume::process_read_indx_completions, this, std::placeholders::_1, std::placeholders::_2),
            std::bind(&Volume::create_indx_tbl, this),
            std::bind(&Volume::recover_indx_tbl, this, std::placeholders::_1, std::placeholders::_2), indx_mgr_sb);
    }
    alloc_single_block_in_mem();
    HS_ASSERT_CMP(RELEASE, get_page_size() % HomeBlks::instance()->get_data_pagesz(), ==, 0);
}

void Volume::meta_blk_found_cb(meta_blk* mblk, sisl::byte_view buf, size_t size) {
    HS_ASSERT_CMP(RELEASE, sizeof(vol_sb_hdr), ==, size);

    auto new_vol = Volume::make_volume(mblk, buf);
    /* add this volume in home blks */
    HomeBlks::safe_instance()->create_volume(new_vol);
}

/* This function can be called multiple times. Underline functions should be idempotent */
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
        shutdown_if_needed();
        return;
    }

    m_destroy_done_cb = cb;
    auto cnt = vol_ref_cnt.fetch_sub(1);
    if (cnt == 1) { destroy_internal(); }
}

/* This function can be called multiple times. Underline functions should be idempotent */
void Volume::destroy_internal() {
    auto prev_state = m_indx_mgr_destroy_started.exchange(true);
    if (prev_state) {
        /* destroy is already triggered. so ignore this request */
        return;
    }
    m_indx_mgr->destroy(([this](bool success) {
        HS_RELEASE_ASSERT_NE(get_state(), vol_state::DESTROYED, "Volume {} is already in destroyed state",
                             m_params.vol_name);
        if (success) {
            THIS_VOL_LOG(INFO, base, , "volume destroyed");
            remove_sb();
            set_state(vol_state::DESTROYED, false);
            m_indx_mgr->destroy_done();
        }
        auto vol_ptr = shared_from_this();
        m_destroy_done_cb(success);
        m_destroy_done_cb = nullptr;
        auto cnt = home_blks_ref_cnt.fetch_sub(1);
        if (cnt == 1 && m_hb->is_shutdown()) { m_hb->do_volume_shutdown(true); };
    }));
}

/* It is called only once */
void Volume::shutdown(const indxmgr_stop_cb& cb) { SnapMgr::shutdown(cb); }

Volume::~Volume() {}

indx_tbl* Volume::create_indx_tbl() {
    auto tbl =
        new mapping(get_size(), get_page_size(), get_name(), SnapMgr::trigger_indx_cp, SnapMgr::add_read_tracker);
    return static_cast< indx_tbl* >(tbl);
}

indx_tbl* Volume::recover_indx_tbl(btree_super_block& sb, btree_cp_superblock& cp_info) {
    auto tbl = new mapping(get_size(), get_page_size(), get_name(), sb, SnapMgr::trigger_indx_cp,
                           SnapMgr::add_read_tracker, &cp_info);
    return static_cast< indx_tbl* >(tbl);
}

std::error_condition Volume::write(const vol_interface_req_ptr& iface_req) {
    std::vector< BlkId > bid;
    std::error_condition ret = no_error;
    uint32_t offset = 0;
    uint32_t start_lba = 0;

    auto vreq = volume_req::make(iface_req);
    THIS_VOL_LOG(TRACE, volume, vreq, "write: lba={}, nlbas={}", vreq->lba(), vreq->nlbas());
    COUNTER_INCREMENT(m_metrics, volume_outstanding_data_write_count, 1);

    /* Sanity checks */
    ++home_blks_ref_cnt;
    ++vol_ref_cnt;

    // sync write is not supported
    VOL_DEBUG_ASSERT_CMP(vreq->is_sync(), ==, false, vreq, "sync not supported");
    if (is_offline()) {
        ret = std::make_error_condition(std::errc::no_such_device);
        goto done;
    }

    /* Allocate blkid */
    if ((ret = alloc_blk(vreq, bid)) != no_error) { goto done; }

    /* Note: If we crash before we write this entry to a journal then there is a chance
     * of leaking these allocated blocks.
     */
    offset = 0;
    start_lba = vreq->lba();
    try {
        vreq->state = volume_req_state::data_io;

        for (uint32_t i = 0; i < bid.size(); ++i) {
            if (bid[i].get_nblks() == 0) {
                /* It should not happen. But it happened once so adding a safe check in case it happens again */
                VOL_LOG_ASSERT(0, vreq, "{}", bid[i].to_string());
                continue;
            }

            /* Create child requests */
            int nlbas = bid[i].data_size(HomeBlks::instance()->get_data_pagesz()) / get_page_size();
            auto vc_req = create_vol_child_req(bid[i], vreq, start_lba, nlbas);
            start_lba += nlbas;

            /* Issue child request */
            /* store blkid which is used later to create journal entry */
            vreq->push_blkid(bid[i]);
            boost::intrusive_ptr< BlkBuffer > bbuf = m_hb->get_data_blkstore()->write(
                vc_req->bid, vreq->mvec, offset, boost::static_pointer_cast< blkstore_req< BlkBuffer > >(vc_req),
                false);

            offset += bid[i].data_size(m_hb->get_data_pagesz());
        }
        VOL_DEBUG_ASSERT_CMP((start_lba - vreq->lba()), ==, vreq->nlbas(), vreq, "lba don't match");

        /* compute checksum and store it in a request */
        for (uint32_t i = 0; i < vreq->nlbas(); ++i) {
            sisl::blob outb;
            vreq->mvec->get(&outb, i * get_page_size());
            vreq->push_csum(crc16_t10dif(init_crc_16, outb.bytes, get_page_size()));
        }

        /* complete the request */
        ret = no_error;
    } catch (const std::exception& e) {
        VOL_LOG_ASSERT(0, vreq, "Exception: {}", e.what())
        ret = std::make_error_condition(std::errc::io_error);
    }

done:
    check_and_complete_req(vreq, ret);
    return ret;
}

std::error_condition Volume::read(const vol_interface_req_ptr& iface_req) {
    std::error_condition ret = no_error;

    auto vreq = volume_req::make(iface_req);
    THIS_VOL_LOG(TRACE, volume, vreq, "read: lba={}, nlbas={}, sync={}", vreq->lba(), vreq->nlbas(), vreq->is_sync());
    COUNTER_INCREMENT(m_metrics, volume_read_count, 1);
    COUNTER_INCREMENT(m_metrics, volume_outstanding_data_read_count, 1);

    ++home_blks_ref_cnt;
    ++vol_ref_cnt;
    if (is_offline()) {
        ret = std::make_error_condition(std::errc::no_such_device);
        goto done;
    }

    try {
        /* add sanity checks */
        vreq->state = volume_req_state::data_io;
        /* read indx */
        COUNTER_INCREMENT(m_metrics, volume_outstanding_metadata_read_count, 1);
        m_indx_mgr->read_indx(boost::static_pointer_cast< indx_req >(vreq));
    } catch (const std::exception& e) {
        VOL_LOG_ASSERT(0, vreq, "Exception: {}", e.what())
        ret = std::make_error_condition(std::errc::device_or_resource_busy);
    }

done:
    check_and_complete_req(vreq, ret);
    return ret;
}

std::error_condition Volume::unmap(const vol_interface_req_ptr& iface_req) {
    std::error_condition ret = no_error;

    auto vreq = volume_req::make(iface_req);
    THIS_VOL_LOG(TRACE, volume, vreq, "unmap: lba={}, nlbas={}", vreq->lba(), vreq->nlbas());

    /* Sanity checks */
    ++home_blks_ref_cnt;
    ++vol_ref_cnt;

    if (is_offline()) {
        ret = std::make_error_condition(std::errc::no_such_device);
        goto done;
    }

    try {
        THIS_VOL_LOG(TRACE, volume, vreq, "unmap: not yet supported");

        vreq->state = volume_req_state::data_io;
        BlkId bid_invalid{BlkId::invalid_internal_id()};

        /* store blkid which is used later to create journal entry */
        vreq->push_blkid(bid_invalid);

        /* complete the request */
        ret = no_error;
    } catch (const std::exception& e) {
        VOL_LOG_ASSERT(0, vreq, "Exception: {}", e.what())
        ret = std::make_error_condition(std::errc::io_error);
    }

done:
    check_and_complete_req(vreq, ret);
    return ret;
}

/* This methods check if we can complete the req and if we can do so. This is the exit point of all async volume
 * read/write operations. All read/writes must call this if it is sync or async.
 *
 * If all ios for request is completed or any one io is errored out, it will call completion if its an async
 * completion
 *
 * Parameters are:
 * 1) hb_req: Request which is to be checked and completed
 * 2) Error: Any IO error condition. Note if there is an error, the request is immediately completed.
 */
bool Volume::check_and_complete_req(const volume_req_ptr& vreq, const std::error_condition& err) {
    bool completed = false;
    uint64_t size = 0;

    // If there is error and request is not completed yet, we need to complete it now.
    THIS_VOL_LOG(TRACE, volume, vreq, "complete_io: status={}, outstanding_io_cnt={}, read={}, state={}", err.message(),
                 vreq->outstanding_io_cnt.get(), vreq->is_read_op(), vreq->state);

    if (err) {
        if (vreq->iface_req->set_error(err)) {
            // Was not completed earlier, so complete the io
            COUNTER_INCREMENT_IF_ELSE(m_metrics, vreq->is_read_op(), volume_write_error_count, volume_read_error_count,
                                      1);
            uint64_t cnt = m_err_cnt.fetch_add(1, std::memory_order_relaxed);
            THIS_VOL_LOG(ERROR, , vreq, "Vol operation error {}", err.message());
            completed = true;
            /* outstanding io cnt is not decremented. So it never going to do another completion callback if other
             * child requests are completed successfully
             */
        } else {
            THIS_VOL_LOG(WARN, , vreq, "Receiving completion on already completed request id={}", vreq->request_id);
        }
    } else if (vreq->state == volume_req_state::data_io) {
        if (vreq->outstanding_io_cnt.decrement_testz(1)) {
            if (vreq->is_read_op()) {
                /* verify checksum for read */
                verify_csum(vreq);
                completed = true;
            } else {
                vreq->state = volume_req_state::journal_io;
                vreq->indx_start_time = Clock::now();
                m_indx_mgr->update_indx(boost::static_pointer_cast< indx_req >(vreq));
            }
        }
    } else if (vreq->state == volume_req_state::journal_io) {
        completed = true;
    }

    if (completed) {
        vreq->state = volume_req_state::completed;

        /* update counters */
        size = get_page_size() * vreq->nlbas();
        auto latency_us = get_elapsed_time_us(vreq->io_start_time);
        if (vreq->is_read_op()) {
            COUNTER_DECREMENT(m_metrics, volume_outstanding_data_read_count, 1);
            COUNTER_INCREMENT(m_metrics, volume_read_size_total, size);
            HISTOGRAM_OBSERVE(m_metrics, volume_read_size_distribution, size);
            HISTOGRAM_OBSERVE(m_metrics, volume_pieces_per_read, vreq->vc_req_cnt);
            HISTOGRAM_OBSERVE(m_metrics, volume_read_latency, latency_us);
        } else {
            COUNTER_DECREMENT(m_metrics, volume_outstanding_data_write_count, 1);
            COUNTER_INCREMENT(m_metrics, volume_write_size_total, size);
            HISTOGRAM_OBSERVE(m_metrics, volume_write_size_distribution, size);
            HISTOGRAM_OBSERVE(m_metrics, volume_pieces_per_write, vreq->vc_req_cnt);
            HISTOGRAM_OBSERVE(m_metrics, volume_write_latency, latency_us);
        }

        if (latency_us > 5000000) { THIS_VOL_LOG(WARN, , vreq, "vol req took time {} us", latency_us); }

        if (!vreq->is_sync()) {
#ifdef _PRERELEASE
            if (auto flip_ret = homestore_flip->get_test_flip< int >("vol_comp_delay_us")) {
                LOGINFO("delaying completion in volume for {} us", flip_ret.get());
                usleep(flip_ret.get());
            }
#endif
            THIS_VOL_LOG(TRACE, volume, vreq, "IO DONE");
            interface_req_done(vreq->iface_req);
        }

        shutdown_if_needed();
    }
    return completed;
}

void Volume::shutdown_if_needed() {
    auto homeblks_io_cnt = home_blks_ref_cnt.fetch_sub(1);
    auto vol_io_cnt = vol_ref_cnt.fetch_sub(1);
    if (homeblks_io_cnt == 1 && m_hb->is_shutdown()) { m_hb->do_volume_shutdown(true); }
    if (vol_io_cnt == 1 && m_state == vol_state::DESTROYING) { destroy_internal(); }
}

void Volume::process_indx_completions(const indx_req_ptr& ireq, std::error_condition err) {
    auto vreq = boost::static_pointer_cast< volume_req >(ireq);
    VOL_DEBUG_ASSERT_CMP(vreq->is_read_op(), !=, true, vreq, "read operation not allowed");
    VOL_DEBUG_ASSERT_CMP(vreq->is_sync(), !=, true, vreq, "sync op not allowed");

    COUNTER_DECREMENT(m_metrics, volume_outstanding_metadata_write_count, 1);

    THIS_VOL_LOG(TRACE, volume, vreq, "metadata_complete: status={}", vreq->err().message());
    HISTOGRAM_OBSERVE(m_metrics, volume_map_write_latency, get_elapsed_time_us(vreq->indx_start_time));

    check_and_complete_req(vreq, err);
}

void Volume::process_vol_data_completions(const boost::intrusive_ptr< blkstore_req< BlkBuffer > >& bs_req) {
    volume_child_req::cast(bs_req)->parent_req->vol()->process_data_completions(bs_req);
}

void Volume::process_data_completions(const boost::intrusive_ptr< blkstore_req< BlkBuffer > >& bs_req) {
    auto vc_req = volume_child_req::cast(bs_req);
    auto& vreq = vc_req->parent_req;

    assert(vreq != nullptr);
    VOL_DEBUG_ASSERT_CMP(vreq->is_sync(), ==, false, vreq, "sync op not allowed");

    THIS_VOL_LOG(TRACE, volume, vreq, "data op complete: status={}", vreq->err().message());

#ifdef _PRERELEASE
    if (vreq->outstanding_io_cnt.get() > 2 && homestore_flip->test_flip("vol_vchild_error")) {
        vreq->iface_req->err = homestore_error::flip_comp_error;
    }
#endif

    HISTOGRAM_OBSERVE_IF_ELSE(m_metrics, vreq->is_read_op(), volume_data_read_latency, volume_data_write_latency,
                              get_elapsed_time_us(vc_req->op_start_time));

    Free_Blk_Entry fbe(vc_req->bid);
    IndxMgr::remove_read_tracker(fbe); // entry is added into read tracker by mapping when key value is
                                       // read under the lock
    check_and_complete_req(vreq, vc_req->err);
    return;
}

void Volume::attach_completion_cb(const io_comp_callback& cb) { m_comp_cb = cb; }

void Volume::verify_csum(const volume_req_ptr& vreq) {
    uint64_t offset = 0;
    uint32_t csum_indx = 0;

    for (auto& info : vreq->read_buf()) {
        auto offset = info.offset;
        auto size = info.size;
        auto buf = info.buf;
        while (size != 0) {
            sisl::blob b = VolInterface::get_instance()->at_offset(buf, offset);
            for (uint32_t size_read = 0; size_read < b.size && size != 0; size_read += get_page_size()) {
                uint16_t csum = crc16_t10dif(init_crc_16, b.bytes + size_read, get_page_size());

                size -= get_page_size();
                offset += get_page_size();

                VOL_RELEASE_ASSERT_CMP(vreq->csum_list[csum_indx++], ==, csum, vreq, "Checksum mismatch");
            }
        }
    }
}

mapping* Volume::get_active_indx() {
    auto indx_tbl = m_indx_mgr->get_active_indx();
    return (static_cast< mapping* >(indx_tbl));
}

void Volume::process_read_indx_completions(const boost::intrusive_ptr< indx_req >& ireq, std::error_condition err) {
    auto ret = no_error;
    auto vreq = boost::static_pointer_cast< volume_req >(ireq);

    // if there is error or nothing to read anymore, complete this req;
    if (err != no_error) {
        vreq->state = volume_req_state::data_io;
        ret = err;
        goto read_done;
    }

    try {
        /* we populate the entire LBA range asked even if it is not populated by the user */
        uint64_t next_start_lba = vreq->lba();
        for (uint32_t i = 0; i < vreq->result_kv.size(); ++i) {
            /* create child req and read buffers */
            MappingKey* mk = &(vreq->result_kv[i].first);
            MappingValue* mv = &(vreq->result_kv[i].second);
            uint64_t start_lba = mk->start();
            uint64_t end_lba = mk->end();
            VOL_RELEASE_ASSERT_CMP(next_start_lba, <=, start_lba, vreq, "mismatch start lba and next start lba");
            VOL_RELEASE_ASSERT_CMP(mapping::get_end_lba(vreq->lba(), vreq->nlbas()), >=, end_lba, vreq,
                                   "mismatch end lba and end lba in req");
            /* check if there are any holes in the beginning or in the middle */
            while (next_start_lba < start_lba) {
                vreq->read_buf().emplace_back(get_page_size(), 0, m_only_in_mem_buff);
                auto blob = m_only_in_mem_buff->at_offset(0);
                vreq->push_csum(crc16_t10dif(init_crc_16, blob.bytes, get_page_size()));
                ++next_start_lba;
            }
            next_start_lba = end_lba + 1;

            ValueEntry ve;
            (mv->get_array()).get(0, ve, false);
            VOL_DEBUG_ASSERT_CMP(mv->get_array().get_total_elements(), ==, 1, vreq,
                                 "array number of elements not valid");

            volume_child_req_ptr vc_req =
                Volume::create_vol_child_req(ve.get_blkId(), vreq, mk->start(), mk->get_n_lba());

            /* store csum read so that we can verify it later after data is read */
            for (auto i = 0ul; i < mk->get_n_lba(); i++) {
                vreq->push_csum(ve.get_checksum_at(i));
            }

            /* Read data */
            auto sz = get_page_size() * mk->get_n_lba();
            auto offset = m_hb->get_data_pagesz() * ve.get_blk_offset();
            boost::intrusive_ptr< BlkBuffer > bbuf = m_hb->get_data_blkstore()->read(
                ve.get_blkId(), offset, sz, boost::static_pointer_cast< blkstore_req< BlkBuffer > >(vc_req));

            // TODO: @hkadayam There is a potential for race of read_buf_list getting emplaced after completion
            /* Add buffer to read_buf_list. User read data from read buf list */
            vreq->read_buf().emplace_back(sz, offset, bbuf);
        }

        /* check if there are any holes at the end */
        while (next_start_lba <= mapping::get_end_lba(vreq->lba(), vreq->nlbas())) {
            vreq->read_buf().emplace_back(get_page_size(), 0, m_only_in_mem_buff);
            auto blob = m_only_in_mem_buff->at_offset(0);
            vreq->push_csum(crc16_t10dif(init_crc_16, blob.bytes, get_page_size()));
            ++next_start_lba;
        }
        VOL_RELEASE_ASSERT_CMP(next_start_lba, ==, mapping::get_end_lba(vreq->lba(), vreq->nlbas()) + 1, vreq,
                               "mismatch start lba and next start lba");
    } catch (const std::exception& e) {
        VOL_LOG_ASSERT(0, vreq, "Exception: {}", e.what())
        ret = std::make_error_condition(std::errc::device_or_resource_busy);
    }

    COUNTER_DECREMENT(m_metrics, volume_outstanding_metadata_read_count, 1);
    HISTOGRAM_OBSERVE(m_metrics, volume_map_read_latency, get_elapsed_time_us(vreq->io_start_time));
read_done:
    check_and_complete_req(vreq, ret);
    return;
}

/* It is not lock protected. It should be called only by thread for a vreq */
volume_child_req_ptr Volume::create_vol_child_req(BlkId& bid, const volume_req_ptr& vreq, uint32_t start_lba,
                                                  int nlbas) {
    volume_child_req_ptr vc_req = volume_child_req::make_request();
    vc_req->parent_req = vreq;
    vc_req->is_read = vreq->is_read_op();
    vc_req->bid = bid;
    vc_req->lba = start_lba;
    vc_req->op_start_time = Clock::now();
    vc_req->reqId = ++m_req_id;
    vc_req->sync = vreq->is_sync();
    vc_req->part_of_batch = vreq->iface_req->part_of_batch;

    assert((bid.data_size(HomeBlks::instance()->get_data_pagesz()) % get_page_size()) == 0);
    vc_req->nlbas = nlbas;

    VOL_DEBUG_ASSERT_CMP(vc_req->nlbas, >, 0, vreq, "nlbas are zero");

    if (!vreq->is_sync()) { vreq->outstanding_io_cnt.increment(1); }
    ++vreq->vc_req_cnt;
    THIS_VOL_LOG(TRACE, volume, vc_req->parent_req, "Blks to io: bid: {}, offset: {}, nlbas: {}", bid.to_string(),
                 bid.data_size(HomeBlks::instance()->get_data_pagesz()), vc_req->nlbas);
    return vc_req;
}

void Volume::print_tree() { get_active_indx()->print_tree(); }
bool Volume::verify_tree() { return (get_active_indx()->verify_tree()); }
void Volume::print_node(uint64_t blkid) { get_active_indx()->print_node(blkid); }

std::error_condition Volume::alloc_blk(const volume_req_ptr& vreq, std::vector< BlkId >& bid) {
    blk_alloc_hints hints;
    hints.desired_temp = 0;
    hints.dev_id_hint = -1;
    hints.multiplier = (get_page_size() / m_hb->get_data_pagesz());

    try {
        BlkAllocStatus status = m_hb->get_data_blkstore()->alloc_blk(vreq->nlbas() * get_page_size(), hints, bid);
        if (status != BLK_ALLOC_SUCCESS) {
            LOGERROR("failing IO as it is out of disk space");
            return std::errc::no_space_on_device;
        }
        VOL_LOG_ASSERT((status == BLK_ALLOC_SUCCESS), vreq, "blk alloc status not valid");
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

    // Create a new block of memory for the blocks requested and set the memvec
    // pointer to that
    uint8_t* ptr;
    uint32_t size = get_page_size();
    ptr = iomanager.iobuf_alloc(HS_STATIC_CONFIG(disk_attr.align_size), size);
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

void Volume::interface_req_done(const vol_interface_req_ptr& iface_req) {
    if (std::holds_alternative< io_batch_comp_callback >(m_comp_cb)) {
        m_completed_reqs->push_back(iface_req);
        if (m_completed_reqs->size() == 1) {
            // Also add this volume to global list to batch multiple volume
            // responses in the protocol layer
            if (HomeBlks::s_io_completed_volumes == nullptr) {
                HomeBlks::s_io_completed_volumes = sisl::VectorPool< std::shared_ptr< Volume > >::alloc();
            }
            HomeBlks::s_io_completed_volumes->push_back(shared_from_this());
        }
        THIS_VOL_LOG(TRACE, volume, iface_req, "Added to completed req, its size now = {}", m_completed_reqs->size());
    } else if (std::holds_alternative< io_single_comp_callback >(m_comp_cb)) {
        (std::get< io_single_comp_callback >(m_comp_cb))(iface_req);
    } else {
        VOL_ASSERT(DEBUG, 0, , "invalid operation");
    }
}

size_t Volume::call_batch_completion_cbs() {
    auto count = 0u;
    if (std::holds_alternative< io_batch_comp_callback >(m_comp_cb)) {
        count = m_completed_reqs->size();
        if (count) {
            auto comp_reqs = m_completed_reqs->swap();
            (std::get< io_batch_comp_callback >(m_comp_cb))(*comp_reqs);
            m_completed_reqs->drop(comp_reqs);
        }
    }
    return count;
}

indx_cp_ptr Volume::attach_prepare_volume_cp(const indx_cp_ptr& icp, hs_cp* cur_hcp, hs_cp* new_hcp) {
    return (m_indx_mgr->attach_prepare_indx_cp(icp, cur_hcp, new_hcp));
}

vol_state Volume::set_state(vol_state state, bool persist) {
    THIS_VOL_LOG(INFO, base, , "volume state changed from {} to {}", m_state, state);
    auto prev_state = m_state.exchange(state);
    if (prev_state == state) { return prev_state; }
    if (persist) {
        VOL_ASSERT(DEBUG, (state == vol_state::DESTROYING || state == vol_state::ONLINE || state == vol_state::OFFLINE),
                   , "state is {}", state);
        write_sb();
    }
    return prev_state;
}

bool Volume::is_offline() {
    auto state = get_state();
    return (state == vol_state::DESTROYING || state == vol_state::FAILED || state == vol_state::OFFLINE ||
            m_hb->is_shutdown());
}

void Volume::write_sb() {
    std::unique_lock< std::mutex > lk(m_sb_lock);
    auto sb = (vol_sb_hdr*)m_sb_buf.bytes();
    /* update mutable params */
    sb->state = m_state;

    if (!m_sb_cookie) {
        // first time insert
        MetaBlkMgr::instance()->add_sub_sb("VOLUME", (void*)m_sb_buf.bytes(), sizeof(vol_sb_hdr), m_sb_cookie);
    } else {
        MetaBlkMgr::instance()->update_sub_sb("VOLUME", (void*)m_sb_buf.bytes(), sizeof(vol_sb_hdr), m_sb_cookie);
    }
}

void Volume::remove_sb() {
    // remove sb from MetaBlkMgr
    MetaBlkMgr::instance()->remove_sub_sb(m_sb_cookie);
}

void Volume::migrate_sb() {
    // auto inst = MetaBlkMgr::instance();
    // inst->add_sub_sb(meta_sub_type::VOLUME, (void*)(m_sb->ondisk_sb),
    // sizeof(vol_ondisk_sb), &(m_sb->cookie));
}

void Volume::recovery_start_phase1() { m_indx_mgr->recovery_start_phase1(); }
void Volume::recovery_start_phase2() {
    m_indx_mgr->recovery_start_phase2();
    seq_Id = m_indx_mgr->get_max_psn_found_in_recovery();
}
