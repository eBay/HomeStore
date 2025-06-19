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
#pragma once
#include <atomic>
#include <sisl/metrics/metrics.hpp>
#include "homestore_config.hpp"

namespace homestore {
class RsrcMgrMetrics : public sisl::MetricsGroup {
public:
    explicit RsrcMgrMetrics() : sisl::MetricsGroup("resource_mgr", "resource_mgr") {
        REGISTER_COUNTER(dirty_buf_cnt, "Total wb cache dirty buffer cnt", sisl::_publish_as::publish_as_gauge);
        REGISTER_COUNTER(free_blk_size_in_cp, "Total free blks size accumulated in a cp",
                         sisl::_publish_as::publish_as_gauge);
        REGISTER_COUNTER(free_blk_cnt_in_cp, "Total free blks cnt accumulated in a cp",
                         sisl::_publish_as::publish_as_gauge);
        REGISTER_COUNTER(alloc_blk_cnt_in_cp, "Total alloc blks cnt accumulated in a cp",
                         sisl::_publish_as::publish_as_gauge);
        register_me_to_farm();
    }

    RsrcMgrMetrics(const RsrcMgrMetrics&) = delete;
    RsrcMgrMetrics(RsrcMgrMetrics&&) noexcept = delete;
    RsrcMgrMetrics& operator=(const RsrcMgrMetrics&) = delete;
    RsrcMgrMetrics& operator=(const RsrcMgrMetrics&&) noexcept = delete;
    ~RsrcMgrMetrics() { deregister_me_from_farm(); }
};

typedef std::function< void(int64_t /* dirty_buf_cnt */, bool /* critical */) > exceed_limit_cb_t;
const uint32_t max_qd_multiplier = 32;

class ResourceMgr {
public:
    void start(uint64_t total_cap);
    void stop();

    /* monitor dirty buffer count */
    void inc_dirty_buf_size(const uint32_t size);
    void dec_dirty_buf_size(const uint32_t size);
    void register_dirty_buf_exceed_cb(exceed_limit_cb_t cb);

    /* monitor free blk cnt */
    void inc_free_blk(int size);

    void dec_free_blk(int size);
    void register_free_blks_exceed_cb(exceed_limit_cb_t cb);

    bool can_add_free_blk(int cnt) const;

    int64_t cur_free_blk_cnt() const;
    int64_t get_free_blk_cnt_limit() const;
    int64_t cur_free_blk_size() const;
    int64_t get_free_blk_size_limit() const;

    /* monitor memory used to store seqid --> data mapping during recovery */
    void inc_mem_used_in_recovery(int size);
    void dec_mem_used_in_recovery(int size);

    bool can_add_mem_in_recovery(int size) const;
    int64_t cur_mem_used_in_recovery() const;
    int64_t get_mem_used_in_recovery_limit() const;

    /* get cache size */
    uint64_t get_cache_size() const;

    /**
     * @brief Checks if the journal virtual device (vdev) size is within the specified limits.
     *
     * This function compares the used size of the journal vdev with the total size of the vdev
     * and returns true if the used size is within the limits, and false otherwise.
     *
     * If it exceeds the limit, it will call the callback function registered with register_journal_vdev_exceed_cb().
     *
     * @param used_size The used size of the journal vdev.
     * @param total_size The total size of the journal vdev.
     * @return true if the used size is exceeding the limits, false if not exceeding limit or caller didn't registered
     * any callback (caller not interested).
     */
    bool check_journal_vdev_size(const uint64_t used_size, const uint64_t total_size);

    /**
     * @brief Checks if the given used size is within the acceptable range for the journal descriptor.
     *
     * This function checks if the used size of the journal descriptor is within the acceptable range.
     * The acceptable range is determined by the implementation of the resource manager.
     *
     * @param used_size The used size of the journal descriptor.
     * @return true if the used size is exceeding the acceptable range, false otherwise.
     */
    bool check_journal_descriptor_size(const uint64_t used_size) const;

    /**
     * Registers a callback function to be called when the journal virtual device exceeds its limit.
     *
     * @param cb The callback function to be registered.
     */
    void register_journal_vdev_exceed_cb(exceed_limit_cb_t cb);

    uint32_t get_journal_vdev_size_limit() const;
    uint32_t get_journal_vdev_size_critical_limit() const;
    uint32_t get_journal_descriptor_size_limit() const;

    /* monitor chunk size */
    void check_chunk_free_size_and_trigger_cp(uint64_t free_size, uint64_t alloc_size);

    uint32_t get_dirty_buf_qd() const;

    void increase_dirty_buf_qd();

    void reset_dirty_buf_qd();

    /**
     * Triggers the truncation process.
     * This function is responsible for initiating the truncation process.
     */
    void trigger_truncate();

private:
    int64_t get_dirty_buf_limit() const;

    /**
     * Starts resource manager resource audit timer.
     */
    void start_timer();

private:
    std::atomic< int64_t > m_hs_dirty_buf_cnt;
    std::atomic< int64_t > m_hs_fb_cnt;  // free count
    std::atomic< int64_t > m_hs_fb_size; // free size
    std::atomic< int64_t > m_hs_ab_cnt;  // alloc count
    std::atomic< int64_t > m_memory_used_in_recovery;
    std::atomic< uint32_t > m_flush_dirty_buf_q_depth{64};
    std::atomic< bool > m_is_stopped_{false};
    uint64_t m_total_cap;

    // TODO: make it event_cb
    exceed_limit_cb_t m_dirty_buf_exceed_cb;
    exceed_limit_cb_t m_free_blks_exceed_cb;
    exceed_limit_cb_t m_journal_vdev_exceed_cb;
    RsrcMgrMetrics m_metrics;

    iomgr::timer_handle_t m_res_audit_timer_hdl{iomgr::null_timer_handle};
};

extern ResourceMgr& resource_mgr();
} // namespace homestore
