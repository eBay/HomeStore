#pragma once
#include <atomic>
#include <sisl/metrics/metrics.hpp>
#include "homestore_config.hpp"

namespace homestore {
class RsrcMgrMetrics : public sisl::MetricsGroup {
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

typedef std::function< void(int64_t) > exceed_limit_cb_t;

class ResourceMgr {
public:
    static ResourceMgr& instance() {
        static ResourceMgr s_rmgr;
        return s_rmgr;
    }

    void set_total_cap(uint64_t total_cap) { m_total_cap = total_cap; }

    /* monitor dirty buffer count */
    void inc_dirty_buf_cnt(const uint32_t size) {
        HS_REL_ASSERT_GT(size, 0);
        const auto dirty_buf_cnt = m_hs_dirty_buf_cnt.fetch_add(size, std::memory_order_relaxed);
        COUNTER_INCREMENT(m_metrics, dirty_buf_cnt, size);
        if (m_dirty_buf_exceed_cb && ((dirty_buf_cnt + size) > get_dirty_buf_limit())) {
            m_dirty_buf_exceed_cb(dirty_buf_cnt + size);
        }
    }

    void dec_dirty_buf_cnt(const uint32_t size) {
        HS_REL_ASSERT_GT(size, 0);
        const int64_t dirty_buf_cnt = m_hs_dirty_buf_cnt.fetch_sub(size, std::memory_order_relaxed);
        COUNTER_DECREMENT(m_metrics, dirty_buf_cnt, size);
        HS_REL_ASSERT_GE(dirty_buf_cnt, size);
    }

    void register_dirty_buf_exceed_cb(exceed_limit_cb_t cb) { m_dirty_buf_exceed_cb = std::move(cb); }

    /* monitor free blk cnt */
    void inc_free_blk(int size) {
        // trigger hs cp when either one of the limit is reached
        auto cnt = m_hs_fb_cnt.fetch_add(1, std::memory_order_relaxed);
        auto sz = m_hs_fb_size.fetch_add(size, std::memory_order_relaxed);
        COUNTER_INCREMENT(m_metrics, free_blk_size_in_cp, size);
        COUNTER_INCREMENT(m_metrics, free_blk_cnt_in_cp, 1);

        if (m_dirty_buf_exceed_cb && (cnt > get_free_blk_cnt_limit() || sz > get_free_blk_size_limit())) {
            m_dirty_buf_exceed_cb(cnt);
        }
    }

    void dec_free_blk(int size) {
        auto dirty_fb_cnt = m_hs_fb_cnt.fetch_sub(1, std::memory_order_relaxed);
        HS_REL_ASSERT_GE(dirty_fb_cnt, 0);
        auto dirty_fb_size = m_hs_fb_size.fetch_sub(size, std::memory_order_relaxed);
        HS_REL_ASSERT_GE(dirty_fb_size, 0);
        COUNTER_DECREMENT(m_metrics, free_blk_size_in_cp, size);
        COUNTER_DECREMENT(m_metrics, free_blk_cnt_in_cp, 1);
    }

    void register_free_blks_exceed_cb(exceed_limit_cb_t cb) { m_free_blks_exceed_cb = std::move(cb); }

    bool can_add_free_blk(int cnt) const {
        if ((cur_free_blk_cnt() + cnt) > get_free_blk_cnt_limit() ||
            (cur_free_blk_size()) > get_free_blk_size_limit()) {
            return false;
        } else {
            return true;
        }
    }

    int64_t cur_free_blk_cnt() const { return m_hs_fb_cnt.load(std::memory_order_relaxed); }
    int64_t get_free_blk_cnt_limit() const { return ((HS_DYNAMIC_CONFIG(resource_limits.free_blk_cnt))); }
    int64_t cur_free_blk_size() const { return m_hs_fb_size.load(std::memory_order_relaxed); }
    int64_t get_free_blk_size_limit() const {
        return ((m_total_cap * HS_DYNAMIC_CONFIG(resource_limits.free_blk_size_percent)) / 100);
    }

    /* monitor memory used to store seqid --> data mapping during recovery */
    void inc_mem_used_in_recovery(int size) { m_memory_used_in_recovery.fetch_add(size, std::memory_order_relaxed); }
    void dec_mem_used_in_recovery(int size) { m_memory_used_in_recovery.fetch_sub(size, std::memory_order_relaxed); }

    bool can_add_mem_in_recovery(int size) const {
        if (cur_mem_used_in_recovery() + size > get_mem_used_in_recovery_limit()) {
            return false;
        } else {
            return true;
        }
    }

    int64_t cur_mem_used_in_recovery() const { return (m_memory_used_in_recovery.load(std::memory_order_relaxed)); }

    int64_t get_mem_used_in_recovery_limit() const {
        return ((HS_DYNAMIC_CONFIG(resource_limits.memory_in_recovery_precent) * HS_STATIC_CONFIG(input.app_mem_size)) /
                100);
    }

    /* get cache size */
    uint64_t get_cache_size() const {
        return ((HS_STATIC_CONFIG(input.app_mem_size) * HS_DYNAMIC_CONFIG(resource_limits.cache_size_percent)) / 100);
    }

    /* monitor journal size */
    bool check_journal_size(const uint64_t used_size, const uint64_t total_size) {
        if (m_journal_exceed_cb) {
            const uint32_t used_pct = (100 * used_size / total_size);
            if (used_pct >= HS_DYNAMIC_CONFIG(resource_limits.journal_size_percent)) {
                m_journal_exceed_cb(used_size);
                HS_LOG_EVERY_N(WARN, device, 50,
                               "high watermark hit, used percentage: {}, high watermark percentage: {}", used_pct,
                               HS_DYNAMIC_CONFIG(resource_limits.journal_size_percent));
                return true;
            }
        }
        return false;
    }
    void register_journal_exceed_cb(exceed_limit_cb_t cb) { m_journal_exceed_cb = std::move(cb); }

    uint32_t get_journal_size_limit() const { return HS_DYNAMIC_CONFIG(resource_limits.journal_size_percent); }

    /* monitor chunk size */
    void check_chunk_free_size_and_trigger_cp(uint64_t free_size, uint64_t alloc_size);

private:
    int64_t get_dirty_buf_limit() const {
        return (int64_t)((HS_DYNAMIC_CONFIG(resource_limits.dirty_buf_percent) * HS_STATIC_CONFIG(input.app_mem_size) /
                          100));
    }

    std::atomic< int64_t > m_hs_dirty_buf_cnt;
    std::atomic< int64_t > m_hs_fb_cnt;  // free count
    std::atomic< int64_t > m_hs_fb_size; // free size
    std::atomic< int64_t > m_hs_ab_cnt;  // alloc count
    std::atomic< int64_t > m_memory_used_in_recovery;
    uint64_t m_total_cap;
    exceed_limit_cb_t m_dirty_buf_exceed_cb;
    exceed_limit_cb_t m_free_blks_exceed_cb;
    exceed_limit_cb_t m_journal_exceed_cb;
    RsrcMgrMetrics m_metrics;
};

static ResourceMgr& ResourceMgrSI() { return ResourceMgr::instance(); }
} // namespace homestore
