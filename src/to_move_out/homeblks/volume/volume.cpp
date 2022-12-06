﻿
//
// Created by Kadayam, Hari on 06/11/17.
//

/* volume file */
#include <atomic>
#include <cassert>
#include <chrono>
#include <fstream>
#include <iterator>
#include <thread>

#include <sisl/fds/buffer.hpp>

#include "engine/common/homestore_flip.hpp"
#include "homeblks/home_blks.hpp"

#include "volume.hpp"

using namespace homestore;

SISL_LOGGING_DECL(volume)
SISL_LOGGING_DECL(vol_io_wd)

sisl::atomic_counter< uint64_t > Volume::home_blks_ref_cnt{0};

VolumeIOWatchDog::VolumeIOWatchDog() {
    m_wd_on = HB_DYNAMIC_CONFIG(volume.io_watchdog_timer_on);

    if (m_wd_on) {
        m_timer_hdl = iomanager.schedule_global_timer(
            HB_DYNAMIC_CONFIG(volume.io_watchdog_timer_sec) * 1000ul * 1000ul * 1000ul, true, nullptr,
            iomgr::thread_regex::all_worker, [this](void* cookie) { io_timer(); });
    }

    LOGINFO("volume io watchdog turned {}.", m_wd_on ? "ON" : "OFF");
}

VolumeIOWatchDog::~VolumeIOWatchDog() { m_outstanding_ios.clear(); }

void VolumeIOWatchDog::add_io(const volume_child_req_ptr& vc_req) {
    {
        std::unique_lock< std::mutex > lk(m_mtx);
        vc_req->unique_id = ++m_unique_id;

        const auto result = m_outstanding_ios.insert_or_assign(vc_req->unique_id, vc_req);
        HS_LOG(TRACE, vol_io_wd, "add_io: {}, {}", vc_req->unique_id, vc_req->to_string());
        HS_REL_ASSERT_EQ(result.second, true, "expecting to insert instead of update");
    }
}

void VolumeIOWatchDog::complete_io(const volume_child_req_ptr& vc_req) {
    {
        std::unique_lock< std::mutex > lk(m_mtx);
        const auto result = m_outstanding_ios.erase(vc_req->unique_id);
        HS_LOG(TRACE, vol_io_wd, "complete_io: {}, {}", vc_req->unique_id, vc_req->to_string());
        HS_REL_ASSERT_EQ(result, 1, "expecting to erase 1 element");
    }
}

bool VolumeIOWatchDog::is_on() { return m_wd_on; }

void VolumeIOWatchDog::io_timer() {
    {
        std::unique_lock< std::mutex > lk(m_mtx);
        std::vector< volume_child_req_ptr > timeout_reqs;
        // the 1st io iteratred in map will be the oldeset one, because we add io
        // to map when vol_child_req is being created, e.g. op_start_time is from oldeset to latest;
        for (const auto& io : m_outstanding_ios) {
            const auto this_io_dur_us = get_elapsed_time_us(io.second->op_start_time);
            if (this_io_dur_us >= HB_DYNAMIC_CONFIG(volume.io_timeout_limit_sec) * 1000ul * 1000ul) {
                // coolect all timeout requests
                timeout_reqs.push_back(io.second);
            } else {
                // no need to search for newer requests stored in the map;
                break;
            }
        }

        if (timeout_reqs.size()) {
            LOGCRITICAL("Total num timeout requests: {}, the oldest io req that timeout duration is: {},  vc_req: {}",
                        timeout_reqs.size(), get_elapsed_time_us(timeout_reqs[0]->op_start_time),
                        timeout_reqs[0]->to_string());

            HS_REL_ASSERT(false, "Volume IO watchdog timeout! timeout_limit: {}, watchdog_timer: {}",
                          HB_DYNAMIC_CONFIG(volume.io_timeout_limit_sec),
                          HB_DYNAMIC_CONFIG(volume.io_watchdog_timer_sec));
        } else {
            HS_PERIODIC_LOG(DEBUG, vol_io_wd, "io_timer passed {}, no timee out IO found. Total outstanding_io_cnt: {}",
                            ++m_wd_pass_cnt, m_outstanding_ios.size());
        }
    }
}

#ifdef _PRERELEASE
void Volume::set_error_flip() {
    FlipClient* fc = HomeStoreFlip::client_instance();
    FlipFrequency freq;

    FlipCondition null_cond;
    fc->create_condition("", flip::Operator::DONT_CARE, (int)1, &null_cond);

    freq.set_count(20);
    freq.set_percent(10);

    /* error flips */
    fc->inject_retval_flip("vol_vchild_error", {null_cond}, freq, 20);
    fc->inject_noreturn_flip("varsize_blkalloc_no_blks", {null_cond}, freq);
}

void Volume::set_io_flip() {
    FlipClient* fc = HomeStoreFlip::client_instance();
    FlipFrequency freq;
    FlipCondition cond1;
    freq.set_count(2000000000);
    freq.set_percent(2);

    FlipCondition null_cond;
    fc->create_condition("", flip::Operator::DONT_CARE, (int)1, &null_cond);

    /* io flips */
    fc->inject_retval_flip("vol_delay_read_us", {null_cond}, freq, 20);

    fc->inject_retval_flip("cache_insert_race", {null_cond}, freq, 20);

    freq.set_count(10);
    freq.set_percent(10);
    fc->inject_noreturn_flip("simulate_slow_dirty_buffer", {null_cond}, freq);
    fc->inject_retval_flip("io_write_iocb_empty_flip", {null_cond}, freq, 20);
    fc->inject_retval_flip("io_read_iocb_empty_flip", {null_cond}, freq, 20);
    fc->inject_retval_flip("read_write_resubmit_io", {null_cond}, freq, 1);
    fc->inject_retval_flip("read_sync_resubmit_io", {null_cond}, freq, 1);
    fc->inject_retval_flip("write_sync_resubmit_io", {null_cond}, freq, 1);

#if 0
    // Uncomment this line once the memory leak issue is fixed
    FlipCondition vdev_type_cond1;
    fc->create_condition< std::string >("vdev_type", flip::Operator::EQUAL, std::string("data"), &vdev_type_cond1);
    fc->inject_delay_flip("simulate_vdev_delay", {vdev_type_cond1, null_cond}, freq, 500);

    FlipCondition vdev_type_cond2;
    fc->create_condition< std::string >("vdev_type", flip::Operator::EQUAL, std::string("index"), &vdev_type_cond2);
    fc->inject_delay_flip("simulate_vdev_delay", {vdev_type_cond2, null_cond}, freq, 500);
#endif
}
#endif

Volume::Volume(const vol_params& params) :
        m_params(params),
        m_metrics(params.vol_name, this),
        m_comp_cb(params.io_comp_cb),
        m_indx_mgr_destroy_started(false) {

    /* this counter is decremented later when this volume become part of a cp. until then shutdown is
     * not allowed.
     */
    m_hb = HomeBlks::safe_instance();
    home_blks_ref_cnt.increment(1);
    if (m_hb->is_shutdown()) {
        if (home_blks_ref_cnt.decrement_testz(1)) { m_hb->do_volume_shutdown(true); }
        throw std::runtime_error("shutdown in progress");
    }
    m_state = vol_state::UNINITED;
}

Volume::Volume(meta_blk* mblk_cookie, sisl::byte_view sb_buf) :
        m_metrics(((vol_sb_hdr*)sb_buf.bytes())->vol_name, this),
        m_indx_mgr_destroy_started(false),
        m_sb_cookie(mblk_cookie) {
    // TO DO: Might need to address alignment based on data or fast type
    m_sb_buf = hs_utils::extract_byte_array(sb_buf, true, MetaBlkMgrSI()->get_align_size());
    auto sb = (vol_sb_hdr*)m_sb_buf->bytes;
    m_state = sb->state;

    THIS_VOL_LOG(INFO, volume, , "Found volume: {}", sb->to_string());
    HS_REL_ASSERT_LE(sb->version, vol_sb_version, "version mismatch");
    HS_REL_ASSERT_EQ(sb->magic, vol_sb_magic, "magic mismatch");
    m_hb = HomeBlks::safe_instance();
}

void Volume::init() {
    bool init = false;
    vol_sb_hdr* sb{nullptr};
    m_max_vol_io_size = HS_STATIC_CONFIG(engine.max_vol_io_size);

    /* add this volume in home blks */
    if (m_sb_buf == nullptr) {
        init = true;
        // allocate stream for this volume
        if (is_data_drive_hdd()) { m_stream_info = m_hb->get_data_blkstore()->get_vdev()->alloc_stream(m_params.size); }

        m_sb_buf =
            hs_utils::make_byte_array(sizeof(vol_sb_hdr) + (m_stream_info.num_streams * sizeof(vdev_stream_id_t)),
                                      MetaBlkMgrSI()->is_aligned_buf_needed(sizeof(vol_sb_hdr)), sisl::buftag::metablk,
                                      MetaBlkMgrSI()->get_align_size());

        /* populate superblock */
        sb = new (m_sb_buf->bytes)
            vol_sb_hdr(m_params.page_size, m_params.size, m_params.vol_name, m_params.uuid, m_stream_info.num_streams);

        /* create indx tbl */
        m_indx_mgr = SnapMgr::make_SnapMgr(
            m_params.uuid, std::string(m_params.vol_name),
            std::bind(&Volume::process_indx_completions, this, std::placeholders::_1, std::placeholders::_2),
            std::bind(&Volume::process_read_indx_completions, this, std::placeholders::_1, std::placeholders::_2),
            std::bind(&Volume::create_indx_tbl, this), false);

        sb->indx_sb = m_indx_mgr->get_immutable_sb();
        vdev_stream_id_t* const id = (vdev_stream_id_t*)(m_sb_buf->bytes + sizeof(vol_sb_hdr));
        for (uint32_t i{0}; i < sb->num_streams; ++i) {
            id[i] = m_stream_info.stream_id[i];
        }

        set_state(vol_state::ONLINE, true);
        m_seq_id = m_indx_mgr->get_max_seqid_found_in_recovery();
        /* it is called after superblock is persisted by volume */
        m_indx_mgr->indx_init();

    } else {
        /* recovery */
        sb = (vol_sb_hdr*)m_sb_buf->bytes;
        if (sb->version == vol_sb_version_1_2) {
            // upgrade it to the new version
            sb->version = vol_sb_version;
            sb->num_streams = 0;
            write_sb();
        }
        auto indx_sb = sb->indx_sb;
        m_indx_mgr = SnapMgr::make_SnapMgr(
            get_uuid(), std::string(get_name()),
            std::bind(&Volume::process_indx_completions, this, std::placeholders::_1, std::placeholders::_2),
            std::bind(&Volume::process_read_indx_completions, this, std::placeholders::_1, std::placeholders::_2),
            std::bind(&Volume::create_indx_tbl, this),
            std::bind(&Volume::recover_indx_tbl, this, std::placeholders::_1, std::placeholders::_2), indx_sb);

        // reserve stream if it is hard drive
        if (is_data_drive_hdd()) {
            m_stream_info = m_hb->get_data_blkstore()->get_vdev()->reserve_stream(
                (vdev_stream_id_t*)(m_sb_buf->bytes + sizeof(vol_sb_hdr)), sb->num_streams);
        }
    }
    alloc_single_block_in_mem();
    m_blks_per_lba = get_page_size() / m_hb->get_data_pagesz();
    HS_REL_ASSERT_EQ(get_page_size() % m_hb->get_data_pagesz(), 0);
    m_hb->create_volume(shared_from_this());

    if (init) {
        SnapMgr::trigger_indx_cp_with_cb(([this](bool success) {
            /* Now it is safe to do shutdown as this volume has become a part of CP */
            if (home_blks_ref_cnt.decrement_testz(1) && m_hb->is_shutdown()) { m_hb->do_volume_shutdown(true); }
        }));
    }
}

void Volume::meta_blk_found_cb(meta_blk* mblk, sisl::byte_view buf, size_t size) {
    HS_REL_ASSERT_GE(size, sizeof(vol_sb_hdr));
    Volume::make_volume(mblk, buf);
}

void Volume::destroy(indxmgr_stop_cb cb) {
    /* we don't allow shutdown and destroy in parallel */
    home_blks_ref_cnt.increment();
    if (m_hb->is_shutdown()) {
        if (home_blks_ref_cnt.decrement_testz(1)) { m_hb->do_volume_shutdown(true); }
    }

    m_vol_ref_cnt.increment(1);
    if (!m_hb->is_recovery_mode() || get_state() != vol_state::START_INDX_TREE_DESTROYING) {
        auto prev_state = set_state(vol_state::DESTROYING);
        HS_REL_ASSERT_NE(prev_state, vol_state::START_INDX_TREE_DESTROYING, "prev state {}", prev_state);
        if (!m_hb->is_recovery_mode() && prev_state == vol_state::DESTROYING) {
            shutdown_if_needed();
            return;
        }
    }
    m_destroy_done_cb = cb;
    if (m_vol_ref_cnt.decrement_testz(1)) { destroy_internal(); }
}

/* This function can be called multiple times. Underline functions should be idempotent */
void Volume::destroy_internal() {
    auto prev_state = m_indx_mgr_destroy_started.exchange(true);
    if (prev_state) {
        /* destroy is already triggered. so ignore this request */
        return;
    }

    m_indx_mgr->destroy(([this](bool success) {
        HS_REL_ASSERT_NE(get_state(), vol_state::DESTROYED, "Volume {} is already in destroyed state",
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
        m_hb->get_data_blkstore()->get_vdev()->free_stream(m_stream_info);
        if (home_blks_ref_cnt.decrement_testz(1) && m_hb->is_shutdown()) { m_hb->do_volume_shutdown(true); };
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

indx_tbl* Volume::recover_indx_tbl(btree_super_block& sb, btree_cp_sb& cp_info) {
    auto tbl = new mapping(get_size(), get_page_size(), get_name(), sb, SnapMgr::trigger_indx_cp,
                           SnapMgr::add_read_tracker, &cp_info);
    return static_cast< indx_tbl* >(tbl);
}

std::error_condition Volume::write(const vol_interface_req_ptr& iface_req) {
    static thread_local std::vector< BlkId > bid{};
    std::error_condition ret{no_error};

    HS_REL_ASSERT_LE(get_io_size(iface_req->nlbas), m_max_vol_io_size, "IO size exceeds max_vol_io_size supported");

    auto vreq = volume_req::make(iface_req);
    THIS_VOL_LOG(TRACE, volume, vreq, "write: lba={}, nlbas={}, cache={}", vreq->lba(), vreq->nlbas(),
                 vreq->use_cache());
    COUNTER_INCREMENT(m_metrics, volume_outstanding_data_write_count, 1);

    // Sanity checks
    home_blks_ref_cnt.increment();
    m_vol_ref_cnt.increment();

    // sync write is not supported
    VOL_DBG_ASSERT_CMP(vreq->is_sync(), ==, false, vreq, "sync not supported");

    if (is_offline()) {
        ret = std::make_error_condition(std::errc::resource_unavailable_try_again);
        goto done;
    }

    // Allocate blkid
    bid.clear();
    if ((ret = alloc_blk(vreq, bid)) != no_error) { goto done; }

    // Note: If we crash before we write this entry to a journal then there is a chance
    // of leaking these allocated blocks.

    try {
        IoVecTransversal write_transversal{};
        uint64_t data_offset{0};
        uint64_t start_lba{vreq->lba()};

        for (size_t i{0}; i < bid.size(); ++i) {
            if (bid[i].get_nblks() == 0) {
                // It should not happen. But it happened once so adding a safe check in case it happens again
                VOL_LOG_ASSERT(0, vreq, "{}", bid[i].to_string());
                continue;
            }

            // Create child requests
            const uint64_t data_size{bid[i].data_size(m_hb->get_data_pagesz())};
            const lba_count_t nlbas{static_cast< lba_count_t >(data_size / get_page_size())};
            auto vc_req = create_vol_child_req(bid[i], vreq, start_lba, nlbas);
            start_lba += nlbas;

            // Issue child request
            // store blkid which is used later to create journal entry
            vreq->push_blkid(bid[i]);
            if (vreq->use_cache()) {
                // managed memory write
                const auto& mem_vec{std::get< volume_req::MemVecData >(vreq->data)};
                boost::intrusive_ptr< BlkBuffer > bbuf = m_hb->get_data_blkstore()->write(
                    vc_req->bid, mem_vec, data_offset, boost::static_pointer_cast< blkstore_req< BlkBuffer > >(vc_req),
                    true /* use cache */);

                // update checksums which must be done in page size increments
                sisl::blob outb{};
                uint64_t checksum_offset{data_offset};
                for (uint32_t count{0}; count < nlbas; ++count, checksum_offset += get_page_size()) {
                    mem_vec->get(&outb, checksum_offset);
                    vreq->push_csum(
                        crc16_t10dif(init_crc_16, static_cast< unsigned char* >(outb.bytes), get_page_size()));
                }
            } else {
                // scatter/gather write
                const auto& iovecs{std::get< volume_req::IoVecData >(vreq->data)};
                const auto write_iovecs{get_next_iovecs(write_transversal, iovecs, data_size)};

                // TO DO: Add option to insert into cache if write cache option true

                // write data
                m_hb->get_data_blkstore()->write(vc_req->bid, write_iovecs,
                                                 boost::static_pointer_cast< blkstore_req< BlkBuffer > >(vc_req));

                // update checksums which must be done in page size increments
                auto iovec_itr{std::cbegin(write_iovecs)};
                const uint8_t* buffer{static_cast< uint8_t* >(iovec_itr->iov_base)};
                size_t iovec_remaining{iovec_itr->iov_len};
                for (uint32_t count{0}; count < nlbas; ++count) {
                    auto csum{init_crc_16};
                    uint32_t csum_remaining{static_cast< uint32_t >(get_page_size())};
                    while (csum_remaining > 0) {
                        if (iovec_remaining == 0) {
                            ++iovec_itr;
                            assert(iovec_itr != std::cend(write_iovecs));
                            buffer = static_cast< uint8_t* >(iovec_itr->iov_base);
                            assert(buffer != nullptr);
                            iovec_remaining = iovec_itr->iov_len;
                        }
                        const uint32_t len{std::min< uint32_t >(iovec_remaining, csum_remaining)};
                        csum = crc16_t10dif(csum, buffer, len);
                        csum_remaining -= len;
                        iovec_remaining -= len;
                        buffer += len;
                    }
                    vreq->push_csum(csum);
                }
            }

            data_offset += data_size;
        }
        VOL_DBG_ASSERT_CMP((start_lba - vreq->lba()), ==, vreq->nlbas(), vreq, "lba don't match");

        // complete the request
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
    THIS_VOL_LOG(TRACE, volume, vreq, "read: lba={}, nlbas={}, sync={}, cache={}", vreq->lba(), vreq->nlbas(),
                 vreq->is_sync(), vreq->use_cache());
    COUNTER_INCREMENT(m_metrics, volume_read_count, 1);
    COUNTER_INCREMENT(m_metrics, volume_outstanding_data_read_count, 1);

    home_blks_ref_cnt.increment();
    m_vol_ref_cnt.increment();
    if (is_offline()) {
        ret = std::make_error_condition(std::errc::resource_unavailable_try_again);
        goto done;
    }

    try {
        /* add sanity checks */
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

    COUNTER_INCREMENT(m_metrics, volume_unmap_count, 1);

    /* Sanity checks */
    home_blks_ref_cnt.increment();
    m_vol_ref_cnt.increment();

    if (is_offline()) {
        ret = std::make_error_condition(std::errc::resource_unavailable_try_again);
        goto done;
    }

    if (vreq->nlbas() > BlkId::max_blks_in_op()) {
        THIS_VOL_LOG(ERROR, volume, vreq, "unmap: lba={}, nlbas={} invalid argument, nlbas should not exceed: {} ",
                     vreq->lba(), vreq->nlbas(), BlkId::max_blks_in_op());
        ret = std::make_error_condition(std::errc::invalid_argument);
        goto done;
    }

    try {
        THIS_VOL_LOG(TRACE, volume, vreq, "unmap: not yet supported");

        BlkId bid_invalid;

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
        if (err == homestore_error::btree_crc_mismatch) {
            // only expecting receiving crc mismatch in this state;
            LOGERROR("crc mismatch received: outstanding_io_cnt={}, read={}, state={}", vreq->outstanding_io_cnt.get(),
                     vreq->is_read_op(), vreq->state);

            fault_containment();
        }

        if (vreq->err() == std::errc::no_space_on_device) {
            uint64_t used_size_p = (get_used_size().used_data_size * 100) / get_size();
            VOL_REL_ASSERT_CMP(used_size_p, <, HS_DYNAMIC_CONFIG(resource_limits.vol_threshhold_used_size_p), vreq,
                               "this homestore instance is either over subscribed or there is data leak");
        }
        if (vreq->iface_req->set_error(err)) {
            // Was not completed earlier, so complete the io
            COUNTER_INCREMENT_IF_ELSE(m_metrics, vreq->is_read_op(), volume_write_error_count, volume_read_error_count,
                                      1);
            uint64_t cnt = m_err_cnt.fetch_add(1, std::memory_order_relaxed);
            HS_LOG_EVERY_N(ERROR, base, 50, "Vol {} operation error {}", get_name(), err.message());
            /* we wait for all outstanding child req to be completed before we do completion upcall */
        } else {
            THIS_VOL_LOG(WARN, , vreq, "Receiving completion on already completed request id={}", vreq->request_id);
        }
    }

    if (vreq->state == volume_req_state::data_io) {
        if (vreq->outstanding_io_cnt.decrement_testz(1)) {
            if (vreq->iface_req->get_status()) {
                completed = true;
            } else if (vreq->is_read_op()) {
                /* verify checksum for read */
                verify_csum(vreq);
                completed = true;
            } else {
                // set seq id before we write to btree/journal;
                vreq->set_seq_id();
                vreq->state = volume_req_state::journal_io;
                vreq->indx_start_time = Clock::now();
                auto ireq = boost::static_pointer_cast< indx_req >(vreq);
                (vreq->is_unmap()) ? m_indx_mgr->unmap(ireq) : m_indx_mgr->update_indx(ireq);
                COUNTER_INCREMENT(m_metrics, volume_outstanding_metadata_write_count, 1);
            }
        }
    } else if (vreq->state == volume_req_state::journal_io) {
        completed = true;
    }

    if (completed) {
        VOL_DBG_ASSERT_CMP(vreq->state, !=, volume_req_state::completed, vreq, "state should not be completed");
        vreq->state = volume_req_state::completed;

        /* update counters */
        size = get_page_size() * vreq->nlbas();
        const auto latency_us = get_elapsed_time_us(vreq->io_start_time);
        if (vreq->is_read_op()) {
            COUNTER_DECREMENT(m_metrics, volume_outstanding_data_read_count, 1);
            COUNTER_INCREMENT(m_metrics, volume_read_size_total, size);
            HISTOGRAM_OBSERVE(m_metrics, volume_read_size_distribution, size);
            HISTOGRAM_OBSERVE(m_metrics, volume_pieces_per_read, vreq->vc_req_cnt);
            HISTOGRAM_OBSERVE(m_metrics, volume_read_latency, latency_us);
        } else if (vreq->is_write()) {
            COUNTER_DECREMENT(m_metrics, volume_outstanding_data_write_count, 1);
            COUNTER_INCREMENT(m_metrics, volume_write_size_total, size);
            HISTOGRAM_OBSERVE(m_metrics, volume_write_size_distribution, size);
            HISTOGRAM_OBSERVE(m_metrics, volume_pieces_per_write, vreq->vc_req_cnt);
            HISTOGRAM_OBSERVE(m_metrics, volume_write_latency, latency_us);
        } else if (vreq->is_unmap()) {
            HISTOGRAM_OBSERVE(m_metrics, volume_unmap_latency, latency_us);
            COUNTER_INCREMENT(m_metrics, volume_unmap_size_total, size);
            HISTOGRAM_OBSERVE(m_metrics, volume_unmap_size_distribution, size);
        }

        if (latency_us > 5000000) { THIS_VOL_LOG(WARN, , vreq, "vol req took time {} us", latency_us); }

        if (!vreq->is_sync()) {
#ifdef _PRERELEASE
            if (auto flip_ret = homestore_flip->get_test_flip< int >("vol_comp_delay_us")) {
                LOGINFO("delaying completion in volume for {} us", flip_ret.get());
                std::this_thread::sleep_for(std::chrono::microseconds{flip_ret.get()});
            }
#endif
            THIS_VOL_LOG(TRACE, volume, vreq, "IO DONE");
            interface_req_done(vreq->iface_req);
        }
        shutdown_if_needed();
    }

    return completed;
}

void Volume::inc_ref_cnt() {
    m_vol_ref_cnt.increment();
    home_blks_ref_cnt.increment();
}

void Volume::shutdown_if_needed() {
    if (m_vol_ref_cnt.decrement_testz(1) && m_state.load(std::memory_order_acquire) == vol_state::DESTROYING) {
        destroy_internal();
    }
    if (home_blks_ref_cnt.decrement_testz(1) && m_hb->is_shutdown()) { m_hb->do_volume_shutdown(true); }
}

void Volume::process_indx_completions(const indx_req_ptr& ireq, std::error_condition err) {
    auto vreq = boost::static_pointer_cast< volume_req >(ireq);
    VOL_DBG_ASSERT_CMP(vreq->is_read_op(), !=, true, vreq, "read operation not allowed");
    VOL_DBG_ASSERT_CMP(vreq->is_sync(), !=, true, vreq, "sync op not allowed");

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
    VOL_DBG_ASSERT_CMP(vreq->is_sync(), ==, false, vreq, "sync op not allowed");

    THIS_VOL_LOG(TRACE, volume, vreq, "data op complete: status={}", vreq->err().message());

#ifdef _PRERELEASE
    if (vreq->outstanding_io_cnt.get() > 2 && homestore_flip->test_flip("vol_vchild_error")) {
        vreq->iface_req->err = homestore_error::flip_comp_error;
    }
#endif

    // mark complete in watchdog
    if (m_hb->get_vol_io_wd()->is_on()) { m_hb->get_vol_io_wd()->complete_io(vc_req); }

    HISTOGRAM_OBSERVE_IF_ELSE(m_metrics, vreq->is_read_op(), volume_data_read_latency, volume_data_write_latency,
                              get_elapsed_time_us(vc_req->op_start_time));

    Free_Blk_Entry fbe(vc_req->bid);
    IndxMgr::remove_read_tracker(fbe); // entry is added into read tracker by mapping when key value is
                                       // read under the lock
    check_and_complete_req(vreq, vc_req->err);
    return;
}

void Volume::attach_completion_cb(const io_comp_callback& cb) { m_comp_cb = cb; }

void Volume::fault_containment() {
    m_hb->move_to_restricted_state();
    VOL_REL_ASSERT(0, , "hit checksum mismatch");
#if 0
    // set state to offline
    set_state(vol_state::OFFLINE);

    // send state_change_callback to AM
    m_hb->vol_state_change(shared_from_this(), vol_state::OFFLINE);
#endif

    // I/O completion cb will be suppressed automatcially since after state change cb, scst connection should be donwn;
}

void Volume::verify_csum(const volume_req_ptr& vreq) {
    uint32_t csum_indx = 0;
    if (vreq->use_cache()) {
        for (const auto& info : vreq->read_buf()) {
            auto offset = info.offset;
            auto size = info.size;
            auto buf = info.buf;
            while (size != 0) {
                const sisl::blob b = VolInterface::get_instance()->at_offset(buf, offset);
                for (uint32_t size_read{0}; size_read < b.size && size != 0; size_read += get_page_size()) {
                    const uint16_t csum = crc16_t10dif(init_crc_16, b.bytes + size_read, get_page_size());

                    size -= get_page_size();
                    offset += get_page_size();
                    bool crc_mismatch = (vreq->csum_list[csum_indx] != csum);
#ifdef _PRERELEASE
                    crc_mismatch |= homestore_flip->test_flip("vol_crc_mismatch");
#endif
                    if (crc_mismatch) {
                        THIS_VOL_LOG(ERROR, volume, vreq, "crc mismatch at offset: {}, vreq->crc: {}, csum: {}", offset,
                                     vreq->csum_list[csum_indx], csum);
                        fault_containment();
                    }
                    ++csum_indx;
                }
            }
        }
    } else {
        const std::vector< iovec >& iovecs{std::get< volume_req::IoVecData >(vreq->data)};
        for (const auto& iov : iovecs) {
            const uint64_t size{static_cast< uint64_t >(iov.iov_len)};
            for (uint32_t size_read{0}; size_read < size; size_read += get_page_size()) {
                const uint16_t csum =
                    crc16_t10dif(init_crc_16, static_cast< uint8_t* >(iov.iov_base) + size_read, get_page_size());
                bool crc_mismatch = (vreq->csum_list[csum_indx] != csum);
#ifdef _PRERELEASE
                crc_mismatch |= homestore_flip->test_flip("vol_crc_mismatch");
#endif
                if (crc_mismatch) {
                    THIS_VOL_LOG(ERROR, volume, vreq, "crc mismatch at offset: {}, vreq->crc: {}, csum: {}", size_read,
                                 vreq->csum_list[csum_indx], csum);
                    fault_containment();
                }
                ++csum_indx;
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
        ret = err;
        goto read_done;
    }

    try {
        IoVecTransversal read_transversal{};
        auto insertIntoIovecs{[&vreq, this](std::vector< iovec >& iovecs, const uint8_t* const data,
                                            const uint64_t size) {
            uint64_t source_offset{0};
            uint64_t data_remaining{size};
            for (auto& read_iovec : iovecs) {
                assert(read_iovec.iov_base != nullptr);
                const uint64_t data_length{data_remaining > read_iovec.iov_len ? read_iovec.iov_len : data_remaining};
                ::memcpy(read_iovec.iov_base, static_cast< const void* >(data + source_offset), data_length);
                source_offset += data_length;
                data_remaining -= data_length;
                if (data_remaining == static_cast< uint64_t >(0)) break;
            }
            assert(data_remaining == static_cast< uint64_t >(0));
            VOL_REL_ASSERT_CMP(data_remaining, ==, static_cast< uint64_t >(0), vreq,
                               "Insufficient iovec storage space");
        }};

        // we populate the entire LBA range asked even if it is not populated by the user
        lba_t next_start_lba = vreq->lba();
        for (const auto& [mk, mv] : vreq->result_kv) {
            /* create child req and read buffers */
            const lba_t start_lba = mk.start();
            const lba_t end_lba = mk.end();
            VOL_REL_ASSERT_CMP(next_start_lba, <=, start_lba, vreq, "mismatch start lba and next start lba");
            VOL_REL_ASSERT_CMP(mapping::get_end_lba(vreq->lba(), vreq->nlbas()), >=, end_lba, vreq,
                               "mismatch end lba and end lba in req");

            // check if there are any holes in the beginning or in the middle
            const ValueEntry* ve = mv.get_latest_entry();
            BlkId base_blkid = ve->get_base_blkid();
            if (!base_blkid.is_valid()) { continue; } // It is trimmed.

            while (next_start_lba < start_lba) {
                const auto blob{m_only_in_mem_buff->at_offset(0)};
                COUNTER_INCREMENT(m_metrics, volume_read_on_hole, get_page_size());
                if (vreq->use_cache()) {
                    vreq->read_buf().emplace_back(get_page_size(), 0, m_only_in_mem_buff);
                } else {
                    // scatter/gather read
                    auto& iovecs{std::get< volume_req::IoVecData >(vreq->data)};
                    auto read_iovecs{get_next_iovecs(read_transversal, iovecs, get_page_size())};
                    insertIntoIovecs(read_iovecs, blob.bytes, get_page_size());
                }
                vreq->push_csum(crc16_t10dif(init_crc_16, blob.bytes, get_page_size()));
                ++next_start_lba;
            }
            next_start_lba = end_lba + 1;

            volume_child_req_ptr vc_req = Volume::create_vol_child_req(base_blkid, vreq, mk.start(), mk.get_n_lba());

            // store csum read so that we can verify it later after data is read
            for (csum_t i{0}; i < mk.get_n_lba(); ++i) {
                vreq->push_csum(ve->get_checksum_at(i));
            }

            // Read data
            const auto sz{get_page_size() * mk.get_n_lba()};
            if (!vreq->use_cache()) {
                // scatter/gather read
                const BlkId read_blkid{ve->get_offset_blkid(m_blks_per_lba)};
                auto& iovecs{std::get< volume_req::IoVecData >(vreq->data)};
                auto read_iovecs{get_next_iovecs(read_transversal, iovecs, sz)};

                vc_req->blkId = read_blkid;
#ifndef NDEBUG
                vc_req->read_iovs = read_iovecs;
#endif

                // TO DO: Add option to read from cache if read cache option true

                // read from disk
                m_hb->get_data_blkstore()->read(read_blkid, read_iovecs, sz,
                                                boost::static_pointer_cast< blkstore_req< BlkBuffer > >(vc_req));
            } else {
                const auto blk_offset{get_page_size() * ve->get_lba_offset()};
                boost::intrusive_ptr< BlkBuffer > bbuf = m_hb->get_data_blkstore()->read(
                    base_blkid, blk_offset, sz, boost::static_pointer_cast< blkstore_req< BlkBuffer > >(vc_req));
                vreq->read_buf().emplace_back(sz, blk_offset, std::move(bbuf));
            }
        }

        // check if there are any holes at the end
        const lba_t req_end_lba = mapping::get_end_lba(vreq->lba(), vreq->nlbas());
        while (next_start_lba <= req_end_lba) {
            COUNTER_INCREMENT(m_metrics, volume_read_on_hole, get_page_size());
            const auto blob{m_only_in_mem_buff->at_offset(0)};
            if (vreq->use_cache()) {
                vreq->read_buf().emplace_back(get_page_size(), 0, m_only_in_mem_buff);
            } else {
                // scatter/gather read
                auto& iovecs{std::get< volume_req::IoVecData >(vreq->data)};
                auto read_iovecs{get_next_iovecs(read_transversal, iovecs, get_page_size())};
                insertIntoIovecs(read_iovecs, blob.bytes, get_page_size());
            }
            vreq->push_csum(crc16_t10dif(init_crc_16, blob.bytes, get_page_size()));
            ++next_start_lba;
        }
        // This will never be false, so why check - commenting out
        // VOL_REL_ASSERT_CMP(next_start_lba, ==, mapping::get_end_lba(vreq->lba(), vreq->nlbas()) + 1, vreq,
        //                       "mismatch start lba and next start lba");
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
volume_child_req_ptr Volume::create_vol_child_req(const BlkId& bid, const volume_req_ptr& vreq,
                                                  const uint64_t start_lba, const lba_count_t nlbas) {
    volume_child_req_ptr vc_req = volume_child_req::make_request();
    vc_req->parent_req = vreq;
    vc_req->is_read = vreq->is_read_op();
    vc_req->bid = bid;
    vc_req->lba = start_lba;
    vc_req->op_start_time = Clock::now();
    vc_req->isSyncCall = vreq->is_sync();
    vc_req->use_cache = vreq->use_cache();
    vc_req->part_of_batch = vreq->iface_req->part_of_batch;
    vc_req->request_id = vreq->request_id;

    assert((bid.data_size(HomeBlks::instance()->get_data_pagesz()) % get_page_size()) == 0);
    vc_req->nlbas = nlbas;

    VOL_DBG_ASSERT_CMP(vc_req->nlbas, >, 0, vreq, "nlbas are zero");

    if (!vreq->is_sync()) { vreq->outstanding_io_cnt.increment(1); }
    ++vreq->vc_req_cnt;
    THIS_VOL_LOG(TRACE, volume, vc_req->parent_req, "Blks to io: bid: {}, offset: {}, nlbas: {}", bid.to_string(),
                 bid.data_size(HomeBlks::instance()->get_data_pagesz()), vc_req->nlbas);

    // add to watch dog
    if (m_hb->get_vol_io_wd()->is_on()) { m_hb->get_vol_io_wd()->add_io(vc_req); }

    return vc_req;
}

void Volume::print_tree() { get_active_indx()->print_tree(); }
bool Volume::verify_tree(bool update_debug_bm) { return (get_active_indx()->verify_tree(update_debug_bm)); }

nlohmann::json Volume::get_status(const int log_level) {
    nlohmann::json j;
    auto active_indx_json = get_active_indx()->get_status(log_level);
    if (!active_indx_json.empty()) { j.update(active_indx_json); }
    return j;
}

void Volume::populate_debug_bm() {
    unsigned int i{0};
    unsigned int batch{BlkId::max_blks_in_op()};
    uint64_t max_lba{get_last_lba()};
    BtreeQueryCursor cur;
    while (i <= max_lba) {
        std::vector< std::pair< MappingKey, MappingValue > > kvs;
        LOGDEBUG("Reading -> lba:{},nlbas:{}", i, batch);
        MappingKey key(i, batch);
        get_active_indx()->get(key, cur, kvs);

        // Update the debug bitmap
        for (auto& kv : kvs) {
            if (!kv.second.is_valid()) { continue; }
            ValueEntry* ve = kv.second.get_nth_entry(0);
            const BlkId blkid{ve->get_offset_blkid(m_blks_per_lba)};
            if (!blkid.is_valid()) { continue; }
            THIS_VOL_LOG(TRACE, volume, , "Debug bitmap populate {}", blkid.to_string());
            m_hb->get_data_blkstore()->update_debug_bm(blkid);
        }
        i += batch;
    }
}

void Volume::print_node(uint64_t blkid) { get_active_indx()->print_node(blkid); }

std::error_condition Volume::alloc_blk(const volume_req_ptr& vreq, std::vector< BlkId >& bid) {
    blk_alloc_hints hints;
    hints.desired_temp = 0;
    hints.dev_id_hint = -1;
    hints.multiplier = m_blks_per_lba;
    hints.max_blks_per_entry = HS_STATIC_CONFIG(engine.max_blks_in_blkentry);
    hints.stream_info = (uintptr_t)&m_stream_info;
#ifdef _PRERELEASE
    hints.error_simulate = true;
#endif

    try {
        BlkAllocStatus status = m_hb->get_data_blkstore()->alloc_blk(get_io_size(vreq->nlbas()), hints, bid);
        if (status != BlkAllocStatus::SUCCESS) {
            LOGERROR("failing IO as it is out of disk space");
            return std::errc::no_space_on_device;
        }
        VOL_LOG_ASSERT((status == BlkAllocStatus::SUCCESS), vreq, "blk alloc status not valid");
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
    ptr = hs_utils::iobuf_alloc(size, sisl::buftag::common, m_hb->get_data_blkstore()->get_vdev()->get_align_size());
    memset(ptr, 0, size);

    boost::intrusive_ptr< homeds::MemVector > mvec{new homeds::MemVector{}};
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

            /* we increment the ref count so that volume/homeblks doesn't shutdown before completion callback is done.
             */
            home_blks_ref_cnt.increment();
            m_vol_ref_cnt.increment();
        }
        THIS_VOL_LOG(TRACE, volume, iface_req, "Added to completed req, its size now = {}", m_completed_reqs->size());
    } else if (std::holds_alternative< io_single_comp_callback >(m_comp_cb)) {
        (std::get< io_single_comp_callback >(m_comp_cb))(iface_req);
    } else {
        VOL_DBG_ASSERT(0, , "invalid operation");
    }
}

size_t Volume::call_batch_completion_cbs() {
    auto count = 0u;
    if (std::holds_alternative< io_batch_comp_callback >(m_comp_cb)) {
        count = m_completed_reqs->size();
        assert(count > 0);
        if (count) {
            auto comp_reqs = m_completed_reqs->swap();
            THIS_VOL_LOG(TRACE, volume, , "Calling batch completion for {} reqs", comp_reqs->size());
            (std::get< io_batch_comp_callback >(m_comp_cb))(*comp_reqs);
            m_completed_reqs->drop(comp_reqs);
            shutdown_if_needed();
        }
    }
    return count;
}

indx_cp_ptr Volume::attach_prepare_volume_cp(const indx_cp_ptr& icp, hs_cp* cur_hcp, hs_cp* new_hcp) {
    return (m_indx_mgr->attach_prepare_indx_cp(icp, cur_hcp, new_hcp));
}

vol_state Volume::set_state(vol_state state, bool persist) {
    THIS_VOL_LOG(INFO, base, , "volume state changed from {} to {}", m_state, state);
    auto prev_state = m_state.exchange(state, std::memory_order_acquire);
    if (prev_state == state) { return prev_state; }

    if (persist) { write_sb(); }

    return prev_state;
}

bool Volume::is_offline() const {
    const auto state = get_state();
    return (state != vol_state::ONLINE || m_hb->is_shutdown());
}

bool Volume::is_destroying() const {
    const auto state = get_state();
    return (state == vol_state::DESTROYING || state == vol_state::START_INDX_TREE_DESTROYING ||
            state == vol_state::DESTROYED);
}

bool Volume::is_online() const {
    const auto state = get_state();
    return (state == vol_state::ONLINE);
}

void Volume::write_sb() {
    std::unique_lock< std::mutex > lk(m_sb_lock);
    auto sb = (vol_sb_hdr*)m_sb_buf->bytes;
    /* update mutable params */
    sb->state = m_state.load(std::memory_order_release);

    if (!m_sb_cookie) {
        // first time insert
        MetaBlkMgrSI()->add_sub_sb("VOLUME", (void*)m_sb_buf->bytes, m_sb_buf->size, m_sb_cookie);
    } else {
        MetaBlkMgrSI()->update_sub_sb((void*)m_sb_buf->bytes, m_sb_buf->size, m_sb_cookie);
    }
}

void Volume::remove_sb() {
    // remove sb from MetaBlkMgr
    const auto ret{MetaBlkMgrSI()->remove_sub_sb(m_sb_cookie)};
    if (ret != no_error) { HS_REL_ASSERT(false, "failed to remove subsystem with status: {}", ret.message()); }
}

void Volume::migrate_sb() {
    // auto inst = MetaBlkMgrSI();
    // inst->add_sub_sb(meta_sub_type::VOLUME, (void*)(m_sb->ondisk_sb),
    // sizeof(vol_ondisk_sb), &(m_sb->cookie));
}

void Volume::recovery_start_phase1() { m_indx_mgr->recovery(); }
void Volume::recovery_start_phase2() {
    m_indx_mgr->recovery();
    m_seq_id = m_indx_mgr->get_max_seqid_found_in_recovery();
}

std::vector< iovec > Volume::get_next_iovecs(IoVecTransversal& iovec_transversal,
                                             const std::vector< iovec >& data_iovecs, const uint64_t size) {
    // scatter/gather read
    std::vector< iovec > iovecs{};
    if (size == 0) return iovecs;

    iovecs.reserve(2);
    iovecs.emplace_back();
    auto iov_ptr{std::rbegin(iovecs)};

    uint64_t data_consumed{0};
    while (iovec_transversal.iovecs_index < data_iovecs.size()) {
        auto& iov{data_iovecs[iovec_transversal.iovecs_index]};
        if (iovec_transversal.current_iovecs_offset < iov.iov_len) {
            iov_ptr->iov_base = static_cast< uint8_t* >(iov.iov_base) + iovec_transversal.current_iovecs_offset;
            const uint64_t remaining{static_cast< uint64_t >(iov.iov_len - iovec_transversal.current_iovecs_offset)};
            if (data_consumed + remaining > size) {
                iov_ptr->iov_len = size - data_consumed;
                iovec_transversal.current_iovecs_offset += iov_ptr->iov_len;
            } else {
                // consume iovec
                iov_ptr->iov_len = remaining;
                iovec_transversal.current_iovecs_offset = 0;
                ++iovec_transversal.iovecs_index;
            }
            data_consumed += iov_ptr->iov_len;
        }

        if (data_consumed == size) {
            break;
        } else {
            // prepare next iovec
            iovecs.emplace_back();
            iov_ptr = std::rbegin(iovecs);
        }
    }
    assert(data_consumed == size);
    if (data_consumed != size) { throw std::runtime_error("Insufficient data iovecs"); }
    return iovecs;
}

// Note: Metrics scrapping can happen at any point after volume instance is created and registered with metrics farm;
void VolumeMetrics::on_gather() {
    // is_online makes sure in first-time-boot indx mgr is created before metrics can go ahead to get used size
    // through indx mgr;
    if (m_volume->is_online() && m_volume->is_recovery_done()) {
        cap_attrs size{m_volume->get_used_size()};
        GAUGE_UPDATE(*this, volume_data_used_size, size.used_data_size);
        GAUGE_UPDATE(*this, volume_index_used_size, size.used_index_size);
        GAUGE_UPDATE(*this, volume_state, static_cast< int64_t >(m_volume->get_state()));
    } else {
        HS_LOG_EVERY_N(
            WARN, base, 50,
            "gathering metrics before volume is ready: state: {}, recovery_done: {}, can not serve this request!",
            m_volume->is_online() ? "Online" : "Offline", m_volume->is_recovery_done());
    }
}
