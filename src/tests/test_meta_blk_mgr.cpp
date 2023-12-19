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
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <vector>
#include <iomgr/io_environment.hpp>
#include <sisl/logging/logging.h>
#include <sisl/options/options.h>
#include <sisl/flip/flip_client.hpp>
#include <gtest/gtest.h>

#include <homestore/homestore.hpp>
#include <homestore/meta_service.hpp>
#include "meta/meta_sb.hpp"
#include "common/homestore_config.hpp"
#include "common/homestore_assert.hpp"
#include "common/homestore_flip.hpp"
#include "test_common/bits_generator.hpp"
#include "test_common/homestore_test_common.hpp"

using namespace homestore;

RCU_REGISTER_INIT
SISL_LOGGING_INIT(HOMESTORE_LOG_MODS)
std::vector< std::string > test_common::HSTestHelper::s_dev_names;

SISL_OPTIONS_ENABLE(logging, test_meta_blk_mgr, iomgr, test_common_setup)

SISL_LOGGING_DECL(test_meta_blk_mgr)

struct Param {
    uint64_t num_io;
    uint64_t run_time;
    uint32_t per_write;
    uint32_t per_update;
    uint32_t per_remove;
    bool fixed_wrt_sz_enabled;
    uint32_t fixed_wrt_sz;
    uint32_t min_wrt_sz;
    uint32_t max_wrt_sz;
    bool always_do_overflow;
    bool is_bitmap;
};

static Param gp;

static const std::string META_FILE_PREFIX{"/tmp/test_meta_blk_mgr_"};
static constexpr uint32_t dma_address_boundary{512}; // Mininum size the dma/writes to be aligned with
static constexpr uint64_t Ki{1024};
static constexpr uint64_t Mi{Ki * Ki};
static constexpr uint64_t Gi{Ki * Mi};

struct sb_info_t {
    void* cookie;
    std::string str;
};

class VMetaBlkMgrTest : public ::testing::Test {
public:
    enum class meta_op_type : uint8_t { write = 1, update = 2, remove = 3, read = 4 };

    std::string mtype;
    Clock::time_point m_start_time;
    std::vector< meta_sub_type > actual_cb_order;
    std::vector< meta_sub_type > actual_on_complete_cb_order;
    std::vector< void* > cookies;

    VMetaBlkMgrTest() = default;
    VMetaBlkMgrTest(const VMetaBlkMgrTest&) = delete;
    VMetaBlkMgrTest& operator=(const VMetaBlkMgrTest&) = delete;
    VMetaBlkMgrTest(VMetaBlkMgrTest&&) noexcept = delete;
    VMetaBlkMgrTest& operator=(VMetaBlkMgrTest&) noexcept = delete;

    virtual ~VMetaBlkMgrTest() override = default;

protected:
    void SetUp() override {
        test_common::HSTestHelper::start_homestore("test_meta_blk_mgr", {{HS_SERVICE::META, {.size_pct = 85.0}}});
    }

    void TearDown() override{};

public:
    [[nodiscard]] uint64_t get_elapsed_time(const Clock::time_point& start) {
        const std::chrono::seconds sec{std::chrono::duration_cast< std::chrono::seconds >(Clock::now() - start)};
        return sec.count();
    }

    bool keep_running() {
        HS_DBG_ASSERT(m_mbm->total_size() >= m_mbm->used_size(), "total size:{} less than used size: {}",
                      m_mbm->total_size(), m_mbm->used_size());
        const auto free_size = m_mbm->total_size() - m_mbm->used_size();
        if (free_size < gp.max_wrt_sz) { return false; }
        if ((get_elapsed_time(m_start_time) >= gp.run_time) || (io_cnt() >= gp.num_io)) { return false; }
        return true;
    }

    void restart_homestore() {
        test_common::HSTestHelper::start_homestore("test_meta_blk_mgr", {{HS_SERVICE::META, {.size_pct = 85.0}}},
                                                   nullptr /* before_svc_start_cb */, true /* restart */);
    }

    uint64_t io_cnt() const { return m_update_cnt + m_wrt_cnt + m_rm_cnt; }

    void gen_rand_buf(uint8_t* s, const uint32_t len) {
        if (gp.is_bitmap) {
            BitsGenerator::gen_random_bits(len, s);
        } else {
            constexpr std::array< char, 62 > alphanum{
                '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K',
                'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};
            std::random_device rd;
            std::default_random_engine re{rd()};
            std::uniform_int_distribution< size_t > alphanum_rand{0, alphanum.size() - 1};
            for (size_t i{0}; i < len - 1; ++i) {
                s[i] = alphanum[alphanum_rand(re)];
            }
            s[len - 1] = 0;
        }
    }

    // size between 512 ~ 8192, 512 aligned;
    uint32_t rand_size(const bool overflow, const bool aligned = true) {
        static thread_local std::random_device rd;
        static thread_local std::default_random_engine re{rd()};
        if (overflow) {
            std::uniform_int_distribution< long unsigned > dist{gp.min_wrt_sz, gp.max_wrt_sz};
            return aligned ? sisl::round_up(dist(re), dma_address_boundary) : dist(re);
        } else {
            std::uniform_int_distribution< long unsigned > dist{64, m_mbm->meta_blk_context_sz()};
            return dist(re);
        }
    }

    uint64_t total_size_written(const void* cookie) { return m_mbm->meta_size(cookie); }

    void do_write_to_full() {
        static constexpr uint64_t blkstore_overhead = 4 * 1024ul * 1024ul; // 4MB
        ssize_t free_size = uint64_cast(m_mbm->total_size() - m_mbm->used_size() - blkstore_overhead);

        HS_REL_ASSERT_GT(free_size, 0);
        HS_REL_ASSERT_EQ(uint64_cast(free_size), m_mbm->available_blks() * m_mbm->block_size() - blkstore_overhead);

        uint64_t size_written{0};
        while (free_size > 0) {
            if (free_size >= gp.max_wrt_sz) {
                size_written = do_sb_write(do_overflow());
            } else {
                size_written = do_sb_write(false, m_mbm->meta_blk_context_sz());
                HS_REL_ASSERT_EQ(size_written, m_mbm->block_size());
            }

            // size_written should be at least one page;
            HS_REL_ASSERT_GE(size_written, m_mbm->block_size());

            free_size -= size_written;

            HS_REL_ASSERT_EQ(uint64_cast(free_size), m_mbm->available_blks() * m_mbm->block_size() - blkstore_overhead);
        }

        HS_REL_ASSERT_EQ(free_size, 0);
    }

    uint64_t do_sb_write(const bool overflow, size_t sz_to_wrt = 0) {
        ++m_wrt_cnt;
        if (!sz_to_wrt) { sz_to_wrt = rand_size(overflow); }
        int64_t ret_size_written{0};
        uint8_t* buf = iomanager.iobuf_alloc(512, sz_to_wrt);
        gen_rand_buf(buf, sz_to_wrt);

        void* cookie{nullptr};
        m_mbm->add_sub_sb(mtype, buf, sz_to_wrt, cookie);
        HS_DBG_ASSERT_NE(cookie, nullptr);

        // LOGINFO("buf written: size: {}, data: {}", sz_to_wrt, (char*)buf);
        meta_blk* mblk = s_cast< meta_blk* >(cookie);
        // verify context_sz

        if (mblk->hdr.h.compressed == false) {
            if (overflow) {
                HS_DBG_ASSERT_GE(sz_to_wrt, m_mbm->block_size());
                HS_DBG_ASSERT(mblk->hdr.h.ovf_bid.is_valid(), "Expected valid ovf meta blkid");
            } else {
                HS_DBG_ASSERT_LE(sz_to_wrt, m_mbm->meta_blk_context_sz());
                HS_DBG_ASSERT(!mblk->hdr.h.ovf_bid.is_valid(), "Expected invalid ovf meta blkid");
            }

            // verify context_sz
            HS_DBG_ASSERT(mblk->hdr.h.context_sz == sz_to_wrt, "context_sz mismatch: {}/{}",
                          uint64_cast(mblk->hdr.h.context_sz), sz_to_wrt);
        }

        {
            // save cookie;
            std::unique_lock< std::mutex > lg{m_mtx};
            const auto bid = mblk->hdr.h.bid.to_integer();
            HS_DBG_ASSERT(m_write_sbs.find(bid) == m_write_sbs.end(), "cookie already in the map.");

            // save to cache
            m_write_sbs[bid].cookie = cookie;
            m_write_sbs[bid].str = std::string(r_cast< const char* >(buf), sz_to_wrt);

            ret_size_written = total_size_written(cookie);
            m_total_wrt_sz += ret_size_written;
            HS_DBG_ASSERT(m_total_wrt_sz == m_mbm->used_size(), "Used size mismatch: {}/{}", m_total_wrt_sz,
                          m_mbm->used_size());
        }

        static bool done_read{false};
        if (!done_read) {
            done_read = true;
            m_mbm->read_sub_sb(mtype);
            const auto read_buf_str = m_cb_blks[mblk->hdr.h.bid.to_integer()];
            const std::string write_buf_str{r_cast< char* >(buf), sz_to_wrt};
            const auto ret = read_buf_str.compare(write_buf_str);
            if (mblk->hdr.h.compressed == false) {
                HS_DBG_ASSERT(ret == 0, "Context data mismatch: Saved: {}, read: {}.", write_buf_str, read_buf_str);
            }
        }

        iomanager.iobuf_free(buf);

        return ret_size_written;
    }

    void do_sb_remove() {
        void* cookie{nullptr};
        size_t sz{0};
        std::map< uint64_t, sb_info_t >::iterator it;
        {
            static thread_local std::random_device rd;
            static thread_local std::default_random_engine re{rd()};
            std::unique_lock< std::mutex > lg{m_mtx};
            std::uniform_int_distribution< size_t > advance_random{0, m_write_sbs.size() - 1};
            ++m_rm_cnt;
            sz = m_write_sbs.size();
            it = m_write_sbs.begin();
            std::advance(it, advance_random(re));

            cookie = it->second.cookie;
            m_total_wrt_sz -= total_size_written(cookie);
        }

        const auto ret = m_mbm->remove_sub_sb(cookie);
        if (ret != no_error) { HS_REL_ASSERT(false, "failed to remove subsystem with status: {}", ret.message()); }

        {
            std::unique_lock< std::mutex > lg{m_mtx};
            m_write_sbs.erase(it);
            HS_REL_ASSERT_EQ(sz, m_write_sbs.size() + 1); // release assert to make compiler happy on sz;

            HS_DBG_ASSERT(m_total_wrt_sz == m_mbm->used_size(), "Used size mismatch: {}/{}", m_total_wrt_sz,
                          m_mbm->used_size());
        }
    }

    void do_single_sb_read() {
        meta_blk* mblk{nullptr};
        std::string str;
        {
            std::unique_lock< std::mutex > lg{m_mtx};
            const auto it = m_write_sbs.begin();

            HS_DBG_ASSERT_EQ(it != m_write_sbs.end(), true);
            str = it->second.str;
            mblk = s_cast< meta_blk* >(it->second.cookie);
        }

        // read output will be sent via callback which also holds mutex;
        m_mbm->read_sub_sb(mblk->hdr.h.type);

        {
            std::unique_lock< std::mutex > lg{m_mtx};
            const auto read_buf_str = m_cb_blks[mblk->hdr.h.bid.to_integer()];
            const std::string write_buf_str{str};
            const auto ret = read_buf_str.compare(write_buf_str);
            HS_DBG_ASSERT(ret == 0, "Context data mismatch: Saved: {}, read: {}.", write_buf_str, read_buf_str);
        }
    }

    void do_sb_update(const bool aligned_buf_size, uint64_t size_to_update = 0) {
        ++m_update_cnt;
        uint8_t* buf{nullptr};
        auto overflow = do_overflow();
        if (!aligned_buf_size) { overflow = true; } // for unaligned buf size, let's generate overflow buf size;
        auto sz_to_wrt = (size_to_update ? size_to_update : rand_size(overflow, aligned_buf_size));
        void* cookie{nullptr};
        bool unaligned_addr{false};
        uint32_t unaligned_shift{0};
        {
            static thread_local std::random_device rd;
            static thread_local std::default_random_engine re{rd()};
            std::unique_lock< std::mutex > lg{m_mtx};
            std::uniform_int_distribution< size_t > advance_random{0, m_write_sbs.size() - 1};
            auto it = m_write_sbs.begin();
            std::advance(it, advance_random(re));
            if (aligned_buf_size) {
                buf = iomanager.iobuf_alloc(512, sz_to_wrt);
            } else {
                // do unaligned write
                buf = new uint8_t[sz_to_wrt];
                // simulate some unaligned sz and unaligned buffer address
                if (((r_cast< std::uintptr_t >(buf) & s_cast< std::uintptr_t >(dma_address_boundary - 1)) == 0x00) &&
                    !do_aligned()) {
                    unaligned_addr = true;
                    std::uniform_int_distribution< long unsigned > dist{1, dma_address_boundary - 1};
                    unaligned_shift = dist(re);
                    HS_DBG_ASSERT_GT(sz_to_wrt, unaligned_shift);
                    buf += unaligned_shift; // simulate unaligned address
                    sz_to_wrt -= unaligned_shift;
                }
            }

            gen_rand_buf(buf, sz_to_wrt);

            cookie = it->second.cookie;
            m_write_sbs.erase(it);

            // update is in-place, the metablk is re-used, ovf-blk is freed then re-allocated
            // so it is okay to decreaase at this point, then add it back after update completes
            m_total_wrt_sz -= total_size_written(cookie);
        }

        m_mbm->update_sub_sb(buf, sz_to_wrt, cookie);

        {
            std::unique_lock< std::mutex > lg{m_mtx};
            const auto bid = s_cast< const meta_blk* >(cookie)->hdr.h.bid.to_integer();
            HS_DBG_ASSERT(m_write_sbs.find(bid) == m_write_sbs.end(), "cookie already in the map.");
            m_write_sbs[bid].cookie = cookie;
            m_write_sbs[bid].str = std::string{r_cast< const char* >(buf), sz_to_wrt};

            // verify context_sz
            const meta_blk* mblk = s_cast< const meta_blk* >(cookie);
            if (mblk->hdr.h.compressed == false) {
                HS_DBG_ASSERT(mblk->hdr.h.context_sz == sz_to_wrt, "context_sz mismatch: {}/{}",
                              uint64_cast(mblk->hdr.h.context_sz), sz_to_wrt);
            }

            // update total size, add size of metablk back
            m_total_wrt_sz += total_size_written(cookie);
            HS_DBG_ASSERT(m_total_wrt_sz == m_mbm->used_size(), "Used size mismatch: {}/{}", m_total_wrt_sz,
                          m_mbm->used_size());
        }

        if (aligned_buf_size) {
            iomanager.iobuf_free(buf);
        } else {
            if (unaligned_addr) {
                delete[](buf - unaligned_shift);
            } else {
                delete[] buf;
            }
        }
    }

    // compare m_cb_blks with m_write_sbs;
    void verify_cb_blks() {
        std::unique_lock< std::mutex > lg{m_mtx};
        HS_DBG_ASSERT_EQ(m_cb_blks.size(), m_write_sbs.size());

        for (auto it{std::cbegin(m_write_sbs)}; it != std::cend(m_write_sbs); ++it) {
            const auto bid = it->first;
            auto it_cb = m_cb_blks.find(bid);

            HS_DBG_ASSERT(it_cb != std::cend(m_cb_blks), "Saved bid during write not found in recover callback.");

            // the saved buf should be equal to the buf received in the recover callback;
            const int ret = it->second.str.compare(it_cb->second);
            HS_DBG_ASSERT(ret == 0, "Context data mismatch: Saved: {}, callback: {}.", it->second.str, it_cb->second);
        }
    }

    //
    // 1. do a write, make sure compression is triggered.
    // 2. update same meta blk, with data that exceeds compression ratio and thus back off compression.
    //
    void write_compression_backoff() {
        HS_SETTINGS_FACTORY().modifiable_settings([](auto& s) {
            s.metablk.compress_ratio_limit = 100; // this will allow every compression attempt;
            HS_SETTINGS_FACTORY().save();
        });

        LOGINFO("compression ratio limit changed to: {}", HS_DYNAMIC_CONFIG(metablk.compress_ratio_limit));

        do_sb_write(true /* do_overflow */, 5 * Mi);

        HS_SETTINGS_FACTORY().modifiable_settings([](auto& s) {
            s.metablk.compress_ratio_limit = 0; // this will disallow every compression attempt;
            HS_SETTINGS_FACTORY().save();
        });

        LOGINFO("compression ratio limit changed to: {}", HS_DYNAMIC_CONFIG(metablk.compress_ratio_limit));

        // since we only wrote 1 metablk, it will always pick up the same one;
        do_sb_update(true /* aligned */, 5 * Mi);
    }

    void do_rand_load() {
        while (keep_running()) {
            switch (get_op()) {
            case meta_op_type::write: {
                do_sb_write(do_overflow());
            } break;
            case meta_op_type::remove:
                do_sb_remove();
                break;
            case meta_op_type::update:
                do_sb_update(do_aligned());
                break;
            default:
                break;
            }
        }
    }

    bool do_overflow() const {
        static thread_local std::random_device rd;
        static thread_local std::default_random_engine re{rd()};
        if (gp.always_do_overflow) {
            return true;
        } else {
            std::uniform_int_distribution< uint8_t > overflow_rand{0, 1};
            return (overflow_rand(re) == s_cast< uint8_t >(1));
        }
    }

    bool do_aligned() const {
        static thread_local std::random_device rd;
        static thread_local std::default_random_engine re{rd()};
        std::uniform_int_distribution< uint8_t > aligned_rand{0, 1};
        return (aligned_rand(re) == s_cast< uint8_t >(1));
    }

    void recover() {
        // TODO: This scan_blks and recover should be replaced with actual TestHelper::start_homestore with restart
        // on. That way, we don't need to simulate all these calls here
        // do recover and callbacks will be triggered;
        m_cb_blks.clear();
        hs()->cp_mgr().shutdown();
        hs()->cp_mgr().start(false /* first_time_boot */);
        m_mbm->recover(false);
    }

    void recover_with_on_complete() {
        // TODO: This scan_blks and recover should be replaced with actual TestHelper::start_homestore with restart
        // on. That way, we don't need to simulate all these calls here
        // do recover and callbacks will be triggered;
        m_cb_blks.clear();
        hs()->cp_mgr().shutdown();
        hs()->cp_mgr().start(false /* first_time_boot */);
        m_mbm->recover(true);
    }

    void validate() {
        // verify received blks via callbaks are all good;
        verify_cb_blks();
    }

    void scan_blks() { m_mbm->scan_meta_blks(); }

    meta_op_type get_op() {
        static thread_local bool keep_remove{false};
        // if we hit some high watermark, remove the sbs until hit some low watermark;
        if (100 * m_mbm->used_size() / m_mbm->total_size() > 80) {
            keep_remove = true;
            return meta_op_type::remove;
        }

        if (keep_remove) {
            if (100 * m_mbm->used_size() / m_mbm->total_size() > 20) {
                return meta_op_type::remove;
            } else {
                // let's start over the test;
                reset_counters();
                // there is some overhead by MetaBlkMgr, such as meta ssb;
                m_total_wrt_sz = m_mbm->used_size();
                keep_remove = false;
            }
        }

        if (do_write()) {
            return meta_op_type::write;
        } else if (do_update()) {
            return meta_op_type::update;
        } else {
            return meta_op_type::remove;
        }
    }

    uint64_t total_op_cnt() const { return m_update_cnt + m_wrt_cnt + m_rm_cnt; }

    uint32_t write_ratio() const {
        if (m_wrt_cnt == 0) return 0;
        return (100 * m_wrt_cnt) / total_op_cnt();
    }

    uint32_t update_ratio() const {
        if (m_update_cnt == 0) return 0;
        return (100 * m_update_cnt) / total_op_cnt();
    }

    bool do_update() const {
        if (update_ratio() < gp.per_update) { return true; }
        return false;
    }

    bool do_write() const {
        if (write_ratio() < gp.per_write) { return true; }
        return false;
    }

    void shutdown() {
        {
            std::unique_lock< std::mutex > lk(m_mtx);
            reset_counters();
            m_write_sbs.clear();
            m_cb_blks.clear();
        }
        test_common::HSTestHelper::shutdown_homestore();
    }

    void reset_counters() {
        m_wrt_cnt = 0;
        m_update_cnt = 0;
        m_rm_cnt = 0;
        m_total_wrt_sz = 0;
    }

    void register_client() {
        m_mbm = &(meta_service());
        m_total_wrt_sz = m_mbm->used_size();

        HS_REL_ASSERT_EQ(m_mbm->total_size() - m_total_wrt_sz, m_mbm->available_blks() * m_mbm->block_size());

        m_mbm->deregister_handler(mtype);
        m_mbm->register_handler(
            mtype,
            [this](meta_blk* mblk, sisl::byte_view buf, size_t size) {
                if (mblk) {
                    std::unique_lock< std::mutex > lg{m_mtx};
                    m_cb_blks[mblk->hdr.h.bid.to_integer()] = std::string{r_cast< const char* >(buf.bytes()), size};
                }
            },
            [this](bool success) { HS_DBG_ASSERT_EQ(success, true); });
    }

    void register_client_inlcuding_dependencies() {
        m_mbm = &(meta_service());
        m_total_wrt_sz = m_mbm->used_size();

        HS_REL_ASSERT_EQ(m_mbm->total_size() - m_total_wrt_sz, m_mbm->available_blks() * m_mbm->block_size());

        m_mbm->deregister_handler(mtype);

        /*
            we have a DAG to simulate dependencies like this:
                       A
                      / \
                     B   C
                    / \   \
                   D   E   F
        */

        // register with dependencies
        m_mbm->register_handler(
            "A",
            [this](meta_blk* mblk, sisl::byte_view buf, size_t size) {
                meta_sub_type subType(mblk->hdr.h.type);
                actual_cb_order.push_back(subType);
            },
            [this](bool success) { actual_on_complete_cb_order.push_back("A"); }, false,
            std::optional< meta_subtype_vec_t >({"B", "C"}));

        m_mbm->register_handler(
            "B",
            [this](meta_blk* mblk, sisl::byte_view buf, size_t size) {
                meta_sub_type subType(mblk->hdr.h.type);
                actual_cb_order.push_back(subType);
            },
            [this](bool success) { actual_on_complete_cb_order.push_back("B"); }, false,
            std::optional< meta_subtype_vec_t >({"D", "E"}));

        m_mbm->register_handler(
            "C",
            [this](meta_blk* mblk, sisl::byte_view buf, size_t size) {
                meta_sub_type subType(mblk->hdr.h.type);
                actual_cb_order.push_back(subType);
            },
            [this](bool success) { actual_on_complete_cb_order.push_back("C"); }, false,
            std::optional< meta_subtype_vec_t >({"F"}));

        m_mbm->register_handler(
            "D",
            [this](meta_blk* mblk, sisl::byte_view buf, size_t size) {
                meta_sub_type subType(mblk->hdr.h.type);
                actual_cb_order.push_back(subType);
            },
            [this](bool success) { actual_on_complete_cb_order.push_back("D"); }, false);
        m_mbm->register_handler(
            "E",
            [this](meta_blk* mblk, sisl::byte_view buf, size_t size) {
                meta_sub_type subType(mblk->hdr.h.type);
                actual_cb_order.push_back(subType);
            },
            [this](bool success) { actual_on_complete_cb_order.push_back("E"); }, false);
        m_mbm->register_handler(
            "F",
            [this](meta_blk* mblk, sisl::byte_view buf, size_t size) {
                meta_sub_type subType(mblk->hdr.h.type);
                actual_cb_order.push_back(subType);
            },
            [this](bool success) { actual_on_complete_cb_order.push_back("F"); }, false);
    }

    void deregister_client_inlcuding_dependencies() {
        m_mbm->deregister_handler("A");
        m_mbm->deregister_handler("B");
        m_mbm->deregister_handler("C");
        m_mbm->deregister_handler("D");
        m_mbm->deregister_handler("E");
        m_mbm->deregister_handler("F");
        m_mbm->register_handler(
            mtype,
            [this](meta_blk* mblk, sisl::byte_view buf, size_t size) {
                if (mblk) {
                    std::unique_lock< std::mutex > lg{m_mtx};
                    m_cb_blks[mblk->hdr.h.bid.to_integer()] = std::string{r_cast< const char* >(buf.bytes()), size};
                }
            },
            [this](bool success) { HS_DBG_ASSERT_EQ(success, true); });
    }

#ifdef _PRERELEASE
    void set_flip_point(const std::string flip_name) {
        flip::FlipCondition null_cond;
        flip::FlipFrequency freq;
        freq.set_count(1);
        freq.set_percent(100);
        m_fc.inject_noreturn_flip(flip_name, {null_cond}, freq);
        LOGDEBUG("Flip {} set", flip_name);
    }
#endif

    uint64_t m_wrt_cnt{0};
    uint64_t m_update_cnt{0};
    uint64_t m_rm_cnt{0};
    uint64_t m_total_wrt_sz{0};
    MetaBlkService* m_mbm{nullptr};
    std::map< uint64_t, sb_info_t > m_write_sbs; // during write, save blkid to buf map;
    std::map< uint64_t, std::string > m_cb_blks; // during recover, save blkid to buf map;
    std::mutex m_mtx;
#ifdef _PRERELEASE
    flip::FlipClient m_fc{HomeStoreFlip::instance()};
#endif
};

static constexpr uint64_t MIN_DRIVE_SIZE{2147483648}; // 2 GB

TEST_F(VMetaBlkMgrTest, min_drive_size_test) {
    mtype = "Test_Min_Drive_Size";
    this->register_client();

    EXPECT_GT(this->do_sb_write(false), uint64_cast(0));

    this->do_single_sb_read();

    this->shutdown();
}

TEST_F(VMetaBlkMgrTest, write_to_full_test) {
    mtype = "Test_Write_to_Full";
    reset_counters();
    m_start_time = Clock::now();
    this->register_client();

    this->do_write_to_full();

    this->shutdown();
}

TEST_F(VMetaBlkMgrTest, single_read_test) {
    mtype = "Test_Read";
    reset_counters();
    m_start_time = Clock::now();
    this->register_client();

    EXPECT_GT(this->do_sb_write(false), uint64_cast(0));

    this->do_single_sb_read();

    this->shutdown();
}

TEST_F(VMetaBlkMgrTest, random_dependency_test) {
    reset_counters();
    m_start_time = Clock::now();
    this->register_client_inlcuding_dependencies();

    // add sub super block out of order
    uint8_t* buf = iomanager.iobuf_alloc(512, 1);
    void* cookie{nullptr};
    for (int i = 0; i < 10; i++) {
        m_mbm->add_sub_sb("E", buf, 1, cookie);
        cookies.push_back(cookie);
        m_mbm->add_sub_sb("B", buf, 1, cookie);
        cookies.push_back(cookie);
        m_mbm->add_sub_sb("A", buf, 1, cookie);
        cookies.push_back(cookie);
        m_mbm->add_sub_sb("F", buf, 1, cookie);
        cookies.push_back(cookie);
        m_mbm->add_sub_sb("C", buf, 1, cookie);
        cookies.push_back(cookie);
        m_mbm->add_sub_sb("D", buf, 1, cookie);
        cookies.push_back(cookie);
    }

    iomanager.iobuf_free(buf);

    // simulate reboot case that MetaBlkMgr will scan the disk for all the metablks that were written;
    this->scan_blks();

    this->recover_with_on_complete();

    std::unordered_map< meta_sub_type, int > actual_first_cb_order_map;
    std::unordered_map< meta_sub_type, int > actual_last_cb_order_map;

    // verify the order of callback
    for (long unsigned int i = 0; i < actual_cb_order.size(); i++) {
        meta_sub_type subType = actual_cb_order[i];
        actual_last_cb_order_map[subType] = i;
        if (actual_first_cb_order_map.find(subType) == actual_first_cb_order_map.end()) {
            actual_first_cb_order_map[subType] = i;
        }
    }

    EXPECT_TRUE(actual_last_cb_order_map["B"] < actual_first_cb_order_map["A"]);
    EXPECT_TRUE(actual_last_cb_order_map["C"] < actual_first_cb_order_map["A"]);
    EXPECT_TRUE(actual_last_cb_order_map["D"] < actual_first_cb_order_map["B"]);
    EXPECT_TRUE(actual_last_cb_order_map["E"] < actual_first_cb_order_map["B"]);
    EXPECT_TRUE(actual_last_cb_order_map["F"] < actual_first_cb_order_map["C"]);

    actual_first_cb_order_map.clear();

    for (long unsigned int i = 0; i < actual_on_complete_cb_order.size(); i++) {
        actual_first_cb_order_map[actual_on_complete_cb_order[i]] = i;
    }
    EXPECT_TRUE(actual_first_cb_order_map["B"] < actual_first_cb_order_map["A"]);
    EXPECT_TRUE(actual_first_cb_order_map["C"] < actual_first_cb_order_map["A"]);
    EXPECT_TRUE(actual_first_cb_order_map["D"] < actual_first_cb_order_map["B"]);
    EXPECT_TRUE(actual_first_cb_order_map["E"] < actual_first_cb_order_map["B"]);
    EXPECT_TRUE(actual_first_cb_order_map["F"] < actual_first_cb_order_map["C"]);

    this->deregister_client_inlcuding_dependencies();

    this->shutdown();
}

TEST_F(VMetaBlkMgrTest, recovery_test) {
    mtype = "Test_MetaService_recovery";
    reset_counters();
    m_start_time = Clock::now();
    this->register_client();

    // since we are using overflow metablk with 64K metadata, which will cause consume anther 2 metablks
    auto max_write_times = m_mbm->available_blks() * m_mbm->block_size() / (64 * Ki + 8 * Ki);
    // write 1/2 of the available blks;
    for (uint64_t i = 0; i < max_write_times / 2; i++) {
        EXPECT_GT(this->do_sb_write(true, uint64_cast(64 * Ki)), uint64_cast(0));
    }

    // restart homestore
    this->restart_homestore();
    // write another 1/2 of the available blks to make sure we can write after recovery
    // during the write, HS metablk service will check the allocated metablk is unique
    reset_counters();
    this->register_client();
    for (uint64_t i = 0; i < (max_write_times / 2); i++) {
        EXPECT_GT(this->do_sb_write(true, uint64_cast(64 * Ki)), uint64_cast(0));
    }
    this->shutdown();
}

// 1. randome write, update, remove;
// 2. recovery test and verify callback context data matches;
TEST_F(VMetaBlkMgrTest, random_load_test) {
    mtype = "Test_Rand_Load";
    reset_counters();
    m_start_time = Clock::now();
    register_client();

    this->do_rand_load();

    // simulate reboot case that MetaBlkMgr will scan the disk for all the metablks that were written;
    this->scan_blks();

    this->recover();

    this->validate();

    this->shutdown();
}

#ifdef _PRERELEASE // release build doens't have flip point
//
// 1. Turn on flip to simulate fix is not there;
// 2. Write compressed then uncompressed to reproduce the issue which ends up writing bad data (hdr size mismatch)
// to disk, Change dynamic setting to skip hdr size check, because we've introduced bad data.
// 3. Do a recover, verify no crash or assert should happen (need the code change to recover a bad data during
// scan_meta_blks) and data can be fixed during recovery and send back to consumer;
// 4. After recovery everything should be fine;
//
TEST_F(VMetaBlkMgrTest, RecoveryFromBadData) {
    mtype = "Test_Recovery_from_bad_data";
    reset_counters();
    m_start_time = Clock::now();
    this->register_client();

    set_flip_point("without_compress_init");
    //
    // 1. write compressed metablk
    // 2. do an update on the metablk with compression ratio not meet limit, so backoff compression.
    // 3. bad data (with size mismatch) will be written which is expected;
    //
    this->write_compression_backoff();

    HS_SETTINGS_FACTORY().modifiable_settings([](auto& s) {
        s.metablk.skip_header_size_check =
            1; // this will skip hdr size mismatch check during recovery, because we know bad data is written;
        HS_SETTINGS_FACTORY().save();
    });

    LOGINFO("skip_header_size_check changed to: {}", m_mbm->get_skip_hdr_check());

    //
    // Then do a recovery, the data read from disk should be uncompressed and match the size we saved in its metablk
    // header. If size mismatch, it will hit assert failure;
    //

    // simulate reboot case that MetaBlkMgr will scan the disk for all the metablks that were written;
    this->scan_blks();

    this->recover();

    this->validate();

    // up to this point, we can not use the cached meta blk to keep doing update because the mblk in memory copy
    // inside metablkstore are all freed;

    this->shutdown();
}
#endif

TEST_F(VMetaBlkMgrTest, CompressionBackoff) {
    mtype = "Test_Compression_Backoff";
    reset_counters();
    m_start_time = Clock::now();
    this->register_client();

    //
    // 1. write compressed metablk
    // 2. do an update on the metablk with compression ratio not meet limit, so backoff compression.
    //
    this->write_compression_backoff();

    //
    // Then do a recovery, the data read from disk should be uncompressed and match the size we saved in its metablk
    // header. If size mismatch, it will hit assert failure;
    //

    // simulate reboot case that MetaBlkMgr will scan the disk for all the metablks that were written;
    this->scan_blks();

    this->recover();

    this->validate();

    this->shutdown();
}

SISL_OPTION_GROUP(
    test_meta_blk_mgr,
    (fixed_write_size_enabled, "", "fixed_write_size_enabled", "fixed write size enabled 0 or 1",
     ::cxxopts::value< uint32_t >()->default_value("0"), "flag"),
    (fixed_write_size, "", "fixed_write_size", "fixed write size", ::cxxopts::value< uint32_t >()->default_value("512"),
     "number"),
    (run_time, "", "run_time", "running time in seconds", ::cxxopts::value< uint64_t >()->default_value("30"),
     "number"),
    (min_write_size, "", "min_write_size", "minimum write size", ::cxxopts::value< uint32_t >()->default_value("4096"),
     "number"),
    (max_write_size, "", "max_write_size", "maximum write size",
     ::cxxopts::value< uint32_t >()->default_value("524288"), "number"),
    (num_io, "", "num_io", "number of io", ::cxxopts::value< uint64_t >()->default_value("300"), "number"),
    (overflow, "", "overflow", "always do overflow", ::cxxopts::value< uint32_t >()->default_value("0"), "number"),
    (per_update, "", "per_update", "update percentage", ::cxxopts::value< uint32_t >()->default_value("20"), "number"),
    (per_write, "", "per_write", "write percentage", ::cxxopts::value< uint32_t >()->default_value("60"), "number"),
    (per_remove, "", "per_remove", "remove percentage", ::cxxopts::value< uint32_t >()->default_value("20"), "number"),
    (bitmap, "", "bitmap", "bitmap test", ::cxxopts::value< bool >()->default_value("false"), "true or false"));

int main(int argc, char* argv[]) {
    ::testing::GTEST_FLAG(filter) = "*random*:VMetaBlkMgrTest.recovery_test";
    ::testing::InitGoogleTest(&argc, argv);
    SISL_OPTIONS_LOAD(argc, argv, logging, test_meta_blk_mgr, iomgr, test_common_setup);
    sisl::logging::SetLogger("test_meta_blk_mgr");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    gp.num_io = SISL_OPTIONS["num_io"].as< uint64_t >();
    gp.run_time = SISL_OPTIONS["run_time"].as< uint64_t >();
    gp.per_update = SISL_OPTIONS["per_update"].as< uint32_t >();
    gp.per_write = SISL_OPTIONS["per_write"].as< uint32_t >();
    gp.fixed_wrt_sz_enabled = SISL_OPTIONS["fixed_write_size_enabled"].as< uint32_t >();
    gp.fixed_wrt_sz = SISL_OPTIONS["fixed_write_size"].as< uint32_t >();
    gp.min_wrt_sz = SISL_OPTIONS["min_write_size"].as< uint32_t >();
    gp.max_wrt_sz = SISL_OPTIONS["max_write_size"].as< uint32_t >();
    gp.always_do_overflow = SISL_OPTIONS["overflow"].as< uint32_t >();
    gp.is_bitmap = SISL_OPTIONS["bitmap"].as< bool >();

    if ((gp.per_update == 0) || (gp.per_write == 0) || (gp.per_update + gp.per_write + gp.per_remove != 100)) {
        gp.per_update = 20;
        gp.per_write = 60;
        gp.per_remove = 20;
    }

    if ((gp.max_wrt_sz < gp.min_wrt_sz) || (gp.min_wrt_sz < 4096)) {
        gp.min_wrt_sz = 4096;
        gp.max_wrt_sz = 65536;
        LOGINFO("Invalid input for min/max wrt sz: defaulting to {}/{}", gp.min_wrt_sz, gp.max_wrt_sz);
    }

    LOGINFO("Testing with run_time: {}, num_io: {}, overflow: {}, write/update/remove percentage: {}/{}/{}, "
            "min/max io "
            "size: {}/{}",
            gp.run_time, gp.num_io, gp.always_do_overflow, gp.per_write, gp.per_update, gp.per_remove, gp.min_wrt_sz,
            gp.max_wrt_sz);
    return RUN_ALL_TESTS();
}
