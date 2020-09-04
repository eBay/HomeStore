#pragma once
#include <cassert>
#include "indx_mgr.hpp"

namespace homestore {
class ResourceMgr {
public:
    static void set_total_cap(uint64_t total_cap) { m_total_cap = total_cap; }
    /* monitor dirty buffer count */
    static void inc_dirty_buf_cnt() {
        auto dirty_buf_cnt = m_hs_dirty_buf_cnt.fetch_add(1, std::memory_order_relaxed);
        if (dirty_buf_cnt > get_dirty_buf_limit()) { IndxMgr::trigger_indx_cp(); };
    }
    static void dec_dirty_buf_cnt() {
        int64_t dirty_buf_cnt = m_hs_dirty_buf_cnt.fetch_sub(1, std::memory_order_relaxed);
        HS_ASSERT_CMP(RELEASE, dirty_buf_cnt, >=, 0);
    }

    /* monitor free blk cnt */
    static void inc_free_blk(int size) {
        if (m_hs_fb_cnt.fetch_add(1, std::memory_order_relaxed) > get_free_blk_cnt_limit()) {
            IndxMgr::trigger_hs_cp();
        }
        if (m_hs_fb_size.fetch_add(size, std::memory_order_relaxed) > get_free_blk_size_limit()) {
            IndxMgr::trigger_hs_cp();
        }
    }
    static void dec_free_blk(int size) {
        auto dirty_fb_cnt = m_hs_fb_cnt.fetch_sub(1, std::memory_order_relaxed);
        HS_ASSERT_CMP(RELEASE, dirty_fb_cnt, >=, 0);
        auto dirty_fb_size = m_hs_fb_size.fetch_sub(size, std::memory_order_relaxed);
        HS_ASSERT_CMP(RELEASE, dirty_fb_size, >=, 0);
    }
    static bool can_add_free_blk(int cnt) {
        if ((cur_free_blk_cnt() + cnt) > get_free_blk_cnt_limit() ||
            (cur_free_blk_size()) > get_free_blk_size_limit()) {
            return false;
        } else {
            return true;
        }
    }
    static int64_t cur_free_blk_cnt() { return m_hs_fb_cnt.load(std::memory_order_relaxed); }
    static int64_t get_free_blk_cnt_limit() { return ((HS_DYNAMIC_CONFIG(resource_limits.free_blk_cnt))); }
    static int64_t cur_free_blk_size() { return m_hs_fb_size.load(std::memory_order_relaxed); }
    static int64_t get_free_blk_size_limit() {
        return ((m_total_cap * HS_DYNAMIC_CONFIG(resource_limits.free_blk_size)) / 100);
    }

    /* monitor memory used to store seqid --> data mapping during recovery */
    static void inc_mem_used_in_recovery(int size) {
        m_memory_used_in_recovery.fetch_add(size, std::memory_order_relaxed);
    }
    static void dec_mem_used_in_recovery(int size) {
        m_memory_used_in_recovery.fetch_sub(size, std::memory_order_relaxed);
    }
    static bool can_add_mem_in_recovery(int size) {
        if (cur_mem_used_in_recovery() + size > get_mem_used_in_recovery_limit()) {
            return false;
        } else {
            return true;
        }
    }
    static int64_t cur_mem_used_in_recovery() { return (m_memory_used_in_recovery.load(std::memory_order_relaxed)); }
    static int64_t get_mem_used_in_recovery_limit() {
        return ((HS_DYNAMIC_CONFIG(resource_limits.memory_in_recovery_precent) * HS_STATIC_CONFIG(input.app_mem_size)) /
                100);
    }

    /* get cache size */
    static uint64_t get_cache_size() {
        return ((HS_STATIC_CONFIG(input.app_mem_size) * HS_DYNAMIC_CONFIG(resource_limits.cache_size_percent)) / 100);
    }

    /* monitor journal size */
    static void check_journal_size_and_trigger_cp(uint64_t used_size, uint64_t total_size) {
        uint32_t used_per = (100 * used_size / total_size);
        if (used_per >= HS_DYNAMIC_CONFIG(resource_limits.journal_size_percent)) { IndxMgr::trigger_hs_cp(); }
    }

    static uint32_t get_journal_size_limit() { return HS_DYNAMIC_CONFIG(resource_limits.journal_size_percent); }
    /* monitor chunk size */
    static void check_chunk_free_size_and_trigger_cp(uint64_t free_size, uint64_t alloc_size);

private:
    static int64_t get_dirty_buf_limit() {
        return (int64_t)(
            (HS_DYNAMIC_CONFIG(resource_limits.dirty_buf_percent) * HS_STATIC_CONFIG(input.app_mem_size) / 100) /
            HS_STATIC_CONFIG(disk_attr.atomic_phys_page_size));
    }

    static std::atomic< int64_t > m_hs_dirty_buf_cnt;
    static std::atomic< int64_t > m_hs_fb_cnt;
    static std::atomic< int64_t > m_hs_fb_size;
    static std::atomic< int64_t > m_memory_used_in_recovery;
    static uint64_t m_total_cap;
};
} // namespace homestore
