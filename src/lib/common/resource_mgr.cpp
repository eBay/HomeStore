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
#include <homestore/homestore.hpp>
#include <homestore/logstore_service.hpp>
#include <homestore/replication_service.hpp>
#include <iomgr/iomgr_flip.hpp>
#include "resource_mgr.hpp"
#include "homestore_assert.hpp"
#include "replication/repl_dev/raft_repl_dev.h"

namespace homestore {
ResourceMgr& resource_mgr() { return hs()->resource_mgr(); }

void ResourceMgr::start(uint64_t total_cap) {
    m_total_cap = total_cap;
    start_timer();
}
void ResourceMgr::stop() {
    LOGINFO("Cancel resource manager timer.");
    iomanager.cancel_timer(m_res_audit_timer_hdl);
    m_res_audit_timer_hdl = iomgr::null_timer_handle;
}
//
// 1. Conceptually in rare case(not poosible for NuObject, possibly true for NuBlox2.0) truncate itself can't garunteen
//    the space is freed up upto satisfy resource manager. e.g. multiple log stores on this same descriptor and one
//    logstore lagging really behind and not able to truncate much space. Doing multiple truncation won't help in this
//    case.
// 2. And any write on any other descriptor will trigger a high_watermark_check, and if it were to trigger critial
//    alert on this vdev, truncation will be made immediately on all descriptors;
// 3. If still no space can be freed, there is nothing we can't here to back pressure to above layer by rejecting log
//    writes on this descriptor;
//
void ResourceMgr::trigger_truncate() {
    if (hs()->has_repl_data_service()) {
        // first make sure all repl dev's unlyding raft log store make corresponding reservation during
        // truncate -- set the safe truncate boundary for each raft log store;
        hs()->repl_service().iterate_repl_devs([](cshared< ReplDev >& rd) {
            // lock is already taken by repl service layer;
            std::dynamic_pointer_cast< RaftReplDev >(rd)->truncate(
                HS_DYNAMIC_CONFIG(resource_limits.raft_logstore_reserve_threshold));
        });

        // next do device truncate which go through all logdevs and truncate them;
        hs()->logstore_service().device_truncate();
    }

    // TODO: add device_truncate callback to audit how much space was freed per each LogDev and add related
    // metrics;
}

void ResourceMgr::start_timer() {
    auto const res_mgr_timer_ms = HS_DYNAMIC_CONFIG(resource_limits.resource_audit_timer_ms);
    LOGINFO("resource audit timer is set to {} usec", res_mgr_timer_ms);

    m_res_audit_timer_hdl = iomanager.schedule_global_timer(
        res_mgr_timer_ms * 1000 * 1000, true /* recurring */, nullptr /* cookie */, iomgr::reactor_regex::all_worker,
        [this](void*) {
            // all resource timely audit routine should arrive here;
            this->trigger_truncate();
        },
        true /* wait_to_schedule */);
}

/* monitor dirty buffer count */
void ResourceMgr::inc_dirty_buf_size(const uint32_t size) {
    HS_REL_ASSERT_GT(size, 0);
    const auto dirty_buf_cnt = m_hs_dirty_buf_cnt.fetch_add(size, std::memory_order_relaxed);
    COUNTER_INCREMENT(m_metrics, dirty_buf_cnt, size);
    if (m_dirty_buf_exceed_cb && ((dirty_buf_cnt + size) > get_dirty_buf_limit())) {
        m_dirty_buf_exceed_cb(dirty_buf_cnt + size, false /* critical */);
    }
}

void ResourceMgr::dec_dirty_buf_size(const uint32_t size) {
    HS_REL_ASSERT_GT(size, 0);
    const int64_t dirty_buf_cnt = m_hs_dirty_buf_cnt.fetch_sub(size, std::memory_order_relaxed);
    COUNTER_DECREMENT(m_metrics, dirty_buf_cnt, size);
    HS_REL_ASSERT_GE(dirty_buf_cnt, size);
}

void ResourceMgr::register_dirty_buf_exceed_cb(exceed_limit_cb_t cb) { m_dirty_buf_exceed_cb = std::move(cb); }

/* monitor free blk cnt */
void ResourceMgr::inc_free_blk(int size) {
    // trigger hs cp when either one of the limit is reached
    auto cnt = m_hs_fb_cnt.fetch_add(1, std::memory_order_relaxed);
    auto sz = m_hs_fb_size.fetch_add(size, std::memory_order_relaxed);
    COUNTER_INCREMENT(m_metrics, free_blk_size_in_cp, size);
    COUNTER_INCREMENT(m_metrics, free_blk_cnt_in_cp, 1);
}

void ResourceMgr::dec_free_blk(int size) {
    auto dirty_fb_cnt = m_hs_fb_cnt.fetch_sub(1, std::memory_order_relaxed);
    HS_REL_ASSERT_GE(dirty_fb_cnt, 0);
    auto dirty_fb_size = m_hs_fb_size.fetch_sub(size, std::memory_order_relaxed);
    HS_REL_ASSERT_GE(dirty_fb_size, 0);
    COUNTER_DECREMENT(m_metrics, free_blk_size_in_cp, size);
    COUNTER_DECREMENT(m_metrics, free_blk_cnt_in_cp, 1);
}

void ResourceMgr::register_free_blks_exceed_cb(exceed_limit_cb_t cb) { m_free_blks_exceed_cb = std::move(cb); }

bool ResourceMgr::can_add_free_blk(int cnt) const {
    if ((cur_free_blk_cnt() + cnt) > get_free_blk_cnt_limit() || (cur_free_blk_size()) > get_free_blk_size_limit()) {
        return false;
    } else {
        return true;
    }
}

int64_t ResourceMgr::cur_free_blk_cnt() const { return m_hs_fb_cnt.load(std::memory_order_relaxed); }
int64_t ResourceMgr::get_free_blk_cnt_limit() const { return ((HS_DYNAMIC_CONFIG(resource_limits.free_blk_cnt))); }
int64_t ResourceMgr::cur_free_blk_size() const { return m_hs_fb_size.load(std::memory_order_relaxed); }
int64_t ResourceMgr::get_free_blk_size_limit() const {
    return ((m_total_cap * HS_DYNAMIC_CONFIG(resource_limits.free_blk_size_percent)) / 100);
}

/* monitor memory used to store seqid --> data mapping during recovery */
void ResourceMgr::inc_mem_used_in_recovery(int size) {
    m_memory_used_in_recovery.fetch_add(size, std::memory_order_relaxed);
}
void ResourceMgr::dec_mem_used_in_recovery(int size) {
    m_memory_used_in_recovery.fetch_sub(size, std::memory_order_relaxed);
}

bool ResourceMgr::can_add_mem_in_recovery(int size) const {
    if (cur_mem_used_in_recovery() + size > get_mem_used_in_recovery_limit()) {
        return false;
    } else {
        return true;
    }
}

int64_t ResourceMgr::cur_mem_used_in_recovery() const {
    return (m_memory_used_in_recovery.load(std::memory_order_relaxed));
}

int64_t ResourceMgr::get_mem_used_in_recovery_limit() const {
    return ((HS_DYNAMIC_CONFIG(resource_limits.memory_in_recovery_precent) * HS_STATIC_CONFIG(input.app_mem_size)) /
            100);
}

/* get cache size */
uint64_t ResourceMgr::get_cache_size() const {
    return ((HS_STATIC_CONFIG(input.io_mem_size()) * HS_DYNAMIC_CONFIG(resource_limits.cache_size_percent)) / 100);
}

bool ResourceMgr::check_journal_descriptor_size(const uint64_t used_size) const {
    return (used_size >= get_journal_descriptor_size_limit());
}

/* monitor journal vdev size */
bool ResourceMgr::check_journal_vdev_size(const uint64_t used_size, const uint64_t total_size) {
    if (m_journal_vdev_exceed_cb) {
        const uint32_t used_pct = (100 * used_size / total_size);
        if (used_pct >= get_journal_vdev_size_limit()) {
            m_journal_vdev_exceed_cb(used_size, used_pct >= get_journal_vdev_size_critical_limit() /* is_critical */);
            HS_LOG_EVERY_N(WARN, base, 50, "high watermark hit, used percentage: {}, high watermark percentage: {}",
                           used_pct, get_journal_vdev_size_limit());
            return true;
        }
    }
    return false;
}

void ResourceMgr::register_journal_vdev_exceed_cb(exceed_limit_cb_t cb) { m_journal_vdev_exceed_cb = std::move(cb); }

uint32_t ResourceMgr::get_journal_descriptor_size_limit() const {
    return HS_DYNAMIC_CONFIG(resource_limits.journal_descriptor_size_threshold_mb) * 1024 * 1024;
}

uint32_t ResourceMgr::get_journal_vdev_size_critical_limit() const {
    return HS_DYNAMIC_CONFIG(resource_limits.journal_vdev_size_percent_critical);
}

uint32_t ResourceMgr::get_journal_vdev_size_limit() const {
    return HS_DYNAMIC_CONFIG(resource_limits.journal_vdev_size_percent);
}

/* monitor chunk size */
void ResourceMgr::check_chunk_free_size_and_trigger_cp(uint64_t free_size, uint64_t alloc_size) {}

uint32_t ResourceMgr::get_dirty_buf_qd() const { return m_flush_dirty_buf_q_depth; }

void ResourceMgr::increase_dirty_buf_qd() {
    auto qd = m_flush_dirty_buf_q_depth.load();
    if (qd < max_qd_multiplier * HS_DYNAMIC_CONFIG(generic.cache_max_throttle_cnt)) {
        auto const nd = m_flush_dirty_buf_q_depth.fetch_add(2 * qd) + (2 * qd);
        HS_PERIODIC_LOG(INFO, base, "q depth increased to {}", nd);
    }
}

void ResourceMgr::reset_dirty_buf_qd() {
    m_flush_dirty_buf_q_depth = HS_DYNAMIC_CONFIG(generic.cache_max_throttle_cnt);
}

int64_t ResourceMgr::get_dirty_buf_limit() const {
    return int64_cast((HS_DYNAMIC_CONFIG(resource_limits.dirty_buf_percent) * HS_STATIC_CONFIG(input.io_mem_size())) /
                      100);
}
} // namespace homestore
