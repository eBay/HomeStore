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
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <random>

#ifdef __linux__
#include <fcntl.h>
#include <isa-l/crc.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timeb.h>
#include <unistd.h>
#include <errno.h>

#endif

#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <sisl/fds/atomic_status_counter.hpp>
#include <sisl/fds/bitset.hpp>
#include <sisl/fds/buffer.hpp>
#include <iomgr/aio_drive_interface.hpp>
#include <iomgr/io_environment.hpp>
#include <iomgr/http_server.hpp>
#include <iomgr/spdk_drive_interface.hpp>
#include <sisl/logging/logging.h>
#include <sisl/options/options.h>
#include <sisl/utility/thread_buffer.hpp>

#include <gtest/gtest.h>

#include "api/meta_interface.hpp"
#include "api/vol_interface.hpp"
#include "engine/common/homestore_flip.hpp"
#include "engine/common/homestore_header.hpp"
#include "engine/common/mod_test_iface.hpp"
#include "engine/blkstore/blkbuffer.hpp"
#include "engine/homestore_base.hpp"
#include "test_common/homestore_test_common.hpp"

using namespace homestore;
#ifdef _PRERELEASE
using namespace flip;
#endif

RCU_REGISTER_INIT

/************************** GLOBAL VARIABLES ***********************/

static constexpr uint32_t MAX_DEVICES{2};
static constexpr uint64_t HOMEBLKS_SB_FLAGS_SHUTDOWN{0x01};
static const std::string VOL_PREFIX{"test_files/vol"};

namespace homestore {
extern bool vol_test_run;
}
constexpr uint64_t Ki{1024};
constexpr uint64_t Mi{Ki * Ki};
constexpr uint64_t Gi{Ki * Mi};
namespace fs = std::filesystem;

using log_level = spdlog::level::level_enum;
SISL_LOGGING_INIT(HOMESTORE_LOG_MODS)

ENUM(load_type_t, uint8_t, random = 0, same = 1, sequential = 2);
ENUM(verify_type_t, uint8_t, csum = 0, data = 1, header = 2, null = 3);

ENUM(vol_cd_state_t, uint8_t, UNINITED = 0, CREATED = 1, DELETED = 2);

struct vol_file_hdr {
    vol_cd_state_t state;
    boost::uuids::uuid uuid;
};

#define VOL_FILE_HDR_SZ sizeof(struct vol_file_hdr)

#define VOL_HDR_ONLY_FILE_SIZE 4096
static_assert(VOL_HDR_ONLY_FILE_SIZE >= VOL_FILE_HDR_SZ);

struct TestCfg {
    TestCfg() = default;
    TestCfg(const TestCfg&) = delete;
    TestCfg(TestCfg&&) noexcept = delete;
    TestCfg& operator=(const TestCfg&) = default;
    TestCfg& operator=(TestCfg&&) noexcept = delete;

    std::array< std::string, 4 > default_names{"test_files/vol_file1", "test_files/vol_file2", "test_files/vol_file3",
                                               "test_files/vol_file4"};
    std::vector< std::string > dev_names;
    std::vector< std::string > mod_list;
    uint64_t max_vols{50};
    uint64_t max_num_writes{100000};
    uint64_t run_time{60};
    uint64_t num_threads{8};
    uint64_t unmap_frequency{100};

    uint64_t max_io_size{1 * Mi};
    uint64_t max_outstanding_ios{32};
    uint64_t max_disk_capacity{20 * Gi};
    uint64_t app_mem_size_in_gb{1};

    uint32_t atomic_phys_page_size{512};
    uint32_t vol_page_size{4096};
    uint32_t phy_page_size{4096};
    uint32_t mem_btree_page_size{4096};
    uint32_t io_size{4096};

    bool can_delete_volume{false};
    bool read_enable{true};
    bool unmap_enable{false};
    bool oob_unmap_enable{false};
    bool enable_crash_handler{true};
    bool read_verify{false};
    bool remove_file_on_shutdown{true};
    bool remove_file_on_start{false};
    bool verify_only{false};
    bool pre_init_verify{true};
    bool is_abort{false};
    bool vol_create_del{false};
    bool overlapping_allowed{false};
    bool expect_vol_offline{false};

    verify_type_t verify_type{verify_type_t::csum};
    load_type_t load_type{load_type_t::random};
    uint32_t nblks{100};
    uint32_t flip_set{0};                 // TODO: change this to enum
    io_flag io_flags{io_flag::DIRECT_IO}; // 2: READ_ONLY 1: DIRECT_IO, 0: BUFFERED_IO;

    homestore::vol_state expected_vol_state{homestore::vol_state::ONLINE}; // TODO: Move to separate job config section
    bool init{true};
    bool expected_init_fail{false};
    bool precreate_volume{true};
    bool expect_io_error{false};
    uint32_t p_volume_size{60};
    bool is_spdk{false};
    bool read_cache{false};
    bool write_cache{false};
    bool read_iovec{false};
    bool write_iovec{false};
    bool batch_completion{false};
    bool create_del_with_io{false};
    bool delete_with_io;
    uint32_t emulate_hdd_cnt{0};
    uint32_t emulate_hdd_stream_cnt{0};
    uint32_t create_del_ops_cnt;
    uint32_t create_del_ops_interval;
    uint32_t p_vol_files_space;
    std::string flip_name;
    std::string vol_copy_file_path;

    bool verify_csum() { return verify_type == verify_type_t::csum; }
    bool verify_data() { return verify_type == verify_type_t::data; }
    bool verify_hdr() { return verify_type == verify_type_t::header; }
    bool verify_type_set() { return verify_type != verify_type_t::null; }
    bool create_vol_file() {
        // return true for all verify types for now, as we rely on vol file hdr for all recovery cases;
        return true;
    }
};

struct TestOutput {
    TestOutput() = default;
    TestOutput(const TestOutput&) = delete;
    TestOutput(TestOutput&&) noexcept = delete;
    TestOutput& operator=(const TestOutput&) = delete;
    TestOutput& operator=(TestOutput&&) noexcept = delete;

    std::atomic< uint64_t > data_match_cnt{0};
    std::atomic< uint64_t > csum_match_cnt{0};
    std::atomic< uint64_t > hdr_only_match_cnt{0};

    std::atomic< uint64_t > write_cnt{0};
    std::atomic< uint64_t > read_cnt{0};
    std::atomic< uint64_t > unmap_cnt{0};
    std::atomic< uint64_t > read_err_cnt{0};
    std::atomic< uint64_t > vol_create_cnt{0};
    std::atomic< uint64_t > vol_del_cnt{0};
    std::atomic< uint64_t > vol_mounted_cnt{0};
    std::atomic< uint64_t > vol_indx{0};

    void print(const char* const work_type, const bool metrics_dump = false) const {
        uint64_t v;
        fmt::memory_buffer buf{};
        if ((v = write_cnt.load())) {
            fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"write_cnt={} "}, fmt::make_format_args(v));
        }
        if ((v = read_cnt.load())) {
            fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"read_cnt={} "}, fmt::make_format_args(v));
        }
        if ((v = unmap_cnt.load())) {
            fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"unmap_cnt={} "}, fmt::make_format_args(v));
        }
        if ((v = read_err_cnt.load())) {
            fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"read_err_cnt={} "}, fmt::make_format_args(v));
        }
        if ((v = data_match_cnt.load())) {
            fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"data_match_cnt={} "}, fmt::make_format_args(v));
        }
        if ((v = csum_match_cnt.load())) {
            fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"csum_match_cnt={} "}, fmt::make_format_args(v));
        }
        if ((v = hdr_only_match_cnt.load())) {
            fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"hdr_only_match_cnt={} "}, fmt::make_format_args(v));
        }
        if ((v = vol_create_cnt.load())) {
            fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"vol_create_cnt={} "}, fmt::make_format_args(v));
        }
        if ((v = vol_del_cnt.load())) {
            fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"vol_del_cnt={} "}, fmt::make_format_args(v));
        }
        if ((v = vol_mounted_cnt.load())) {
            fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"vol_mounted_cnt={} "}, fmt::make_format_args(v));
        }
        if ((v = vol_indx.load())) {
            fmt::vformat_to(fmt::appender{buf}, fmt::string_view{"vol_indx={} "}, fmt::make_format_args(v));
        }

        LOGINFO("{} Output: [{}]", work_type, buf.data());
        if (metrics_dump) LOGINFO("Metrics: {}", sisl::MetricsFarm::getInstance().get_result_in_json().dump(2));
    }
};

class VolTest;
struct io_req_t;
ENUM(wait_type, uint8_t, no_wait = 0, for_execution = 1, for_completion = 2);

class TestJob {
    static thread_local bool is_this_thread_running_io;

public:
    enum class job_status_t { not_started = 0, running = 1, stopped = 2, completed = 3 };

    TestJob(VolTest* test) : m_voltest(test), m_start_time(Clock::now()) {
        m_timer_hdl = iomanager.schedule_global_timer(5 * 1000ul * 1000ul * 1000ul, true, nullptr,
                                                      iomgr::thread_regex::all_worker,
                                                      [this](void* cookie) { try_run_one_iteration(); });
    }

    TestJob(VolTest* test, uint32_t interval_ops_sec, bool run_in_worker_thread) :
            m_voltest(test), m_start_time(Clock::now()), m_interval_ops_sec(interval_ops_sec) {
        m_timer_hdl = iomanager.schedule_global_timer(interval_ops_sec * 1000ul * 1000ul * 1000ul, true, nullptr,
                                                      run_in_worker_thread ? iomgr::thread_regex::all_worker
                                                                           : iomgr::thread_regex::all_user,
                                                      [this](void* cookie) { try_run_one_iteration(); });
    }

    virtual ~TestJob() = default;
    TestJob(const TestJob&) = delete;
    TestJob(TestJob&&) noexcept = delete;
    TestJob& operator=(const TestJob&) = delete;
    TestJob& operator=(TestJob&&) noexcept = delete;

    virtual void run_one_iteration() = 0;
    virtual void on_one_iteration_completed(const boost::intrusive_ptr< io_req_t >& req) = 0;
    virtual bool time_to_stop() const = 0;
    virtual bool is_job_done() const = 0;
    virtual bool is_async_job() const = 0;
    virtual std::string job_name() const = 0;

    virtual void start_in_this_thread() {
        m_status_threads_executing.xchng_status(job_status_t::not_started, job_status_t::running);
        if (m_status_threads_executing.get_status() != job_status_t::running) { return; }
        for (uint32_t i{0}; i < mod_tests.size(); ++i) {
            mod_tests[i]->run_start();
        }
        try_run_one_iteration();
        if (time_to_stop()) { notify_completions(); }
    }

    virtual void try_run_one_iteration() {
        if (get_elapsed_time_sec(m_start_time) < m_interval_ops_sec) { return; }
        if (!time_to_stop() && !is_this_thread_running_io &&
            m_status_threads_executing.increment_if_status(job_status_t::running)) {
            is_this_thread_running_io = true;
            for (uint32_t i{0}; i < mod_tests.size(); ++i) {
                mod_tests[i]->try_run_one_iteration();
            }
            run_one_iteration();
            VolInterface::get_instance()->submit_io_batch();
            is_this_thread_running_io = false;
            m_status_threads_executing.decrement_testz_and_test_status(job_status_t::stopped);
        }
        if (time_to_stop()) { notify_completions(); }
    }

    void notify_completions() {
        std::unique_lock< std::mutex > lk{m_mutex};
        LOGDEBUG("notifying completions");
        if (is_job_done()) {
            m_status_threads_executing.set_status(job_status_t::completed);
            m_notify_job_done = true;
        } else {
            m_status_threads_executing.set_status(job_status_t::stopped);
        }

        for (uint32_t i{0}; i < mod_tests.size(); ++i) {
            mod_tests[i]->try_run_last_iteration();
        }
        m_execution_cv.notify_all();
        if (m_notify_job_done) m_completion_cv.notify_all();
    }

    virtual void wait_for_execution() {
        std::unique_lock< std::mutex > lk{m_mutex};
        if (!m_notify_job_done) {
            m_execution_cv.wait(lk, [this] {
                const auto status{m_status_threads_executing.get_status()};
                LOGINFO("status {}", status);
                bool cv_status = (((status == job_status_t::stopped) || (status == job_status_t::completed)) &&
                                  (m_status_threads_executing.count() == 0));
                if (cv_status && m_timer_hdl != iomgr::null_timer_handle) {
                    iomanager.cancel_timer(m_timer_hdl, false /* wait */);
                    m_timer_hdl = iomgr::null_timer_handle;
                }
                return cv_status;
            });
        }
        LOGINFO("Job {} is done executing", job_name());
    }

    virtual void wait_for_completion() {
        std::unique_lock< std::mutex > lk{m_mutex};
        if (!m_notify_job_done) {
            m_completion_cv.wait(lk, [this] {
                const bool cv_status{((m_status_threads_executing.get_status() == job_status_t::completed) &&
                                      (m_status_threads_executing.count() == 0))};
                if (cv_status && m_timer_hdl != iomgr::null_timer_handle) {
                    iomanager.cancel_timer(m_timer_hdl);
                    m_timer_hdl = iomgr::null_timer_handle;
                }
                return cv_status;
            });
        }
        LOGINFO("Job {} is completed", job_name());
    }

protected:
    VolTest* m_voltest;
    std::mutex m_mutex;
    std::condition_variable m_execution_cv;
    std::condition_variable m_completion_cv;
    Clock::time_point m_start_time;
    bool m_notify_job_done{false};
    // std::atomic< job_status_t > m_status = job_status_t::not_started;
    // std::atomic< int32_t > m_threads_executing = 0;
    sisl::atomic_status_counter< job_status_t, job_status_t::not_started > m_status_threads_executing;
    iomgr::timer_handle_t m_timer_hdl{iomgr::null_timer_handle};
    uint32_t m_interval_ops_sec = 0;
};

template <>
struct fmt::formatter< TestJob::job_status_t > : formatter< string_view > {
    // parse is inherited from formatter<string_view>.
    template < typename FormatContext >
    auto format(TestJob::job_status_t c, FormatContext& ctx) const {
        string_view name = "unknown";
        switch (c) {
        case TestJob::job_status_t::not_started:
            name = "not started";
            break;
        case TestJob::job_status_t::running:
            name = "running";
            break;
        case TestJob::job_status_t::stopped:
            name = "stopped";
            break;
        case TestJob::job_status_t::completed:
            name = "completed";
            break;
        }
        return formatter< string_view >::format(name, ctx);
    }
};
thread_local bool TestJob::is_this_thread_running_io{false};

struct vol_info_t {
    VolumePtr vol;
    boost::uuids::uuid uuid;
    int fd;

    std::mutex vol_mutex;
    std::unique_ptr< sisl::Bitset > m_pending_lbas_bm;
    std::unique_ptr< sisl::Bitset > m_hole_lbas_bm;

    uint64_t max_vol_blks;
    uint64_t cur_checkpoint;
    std::atomic< uint64_t > start_lba{0};
    std::atomic< uint64_t > start_large_lba{0};
    size_t vol_idx{0};
    sisl::atomic_counter< uint64_t > ref_cnt;
    std::atomic< bool > vol_destroyed{false};

    vol_info_t() = default;
    vol_info_t(const vol_info_t&) = delete;
    vol_info_t(vol_info_t&&) noexcept = delete;
    vol_info_t& operator=(const vol_info_t&) = delete;
    vol_info_t& operator=(vol_info_t&&) noexcept = delete;
    ~vol_info_t() = default;

    void mark_lbas_busy(const uint64_t start_lba, const uint32_t nlbas) {
        m_pending_lbas_bm->set_bits(start_lba, nlbas);
    }

    void mark_lbas_free(const uint64_t start_lba, const uint32_t nlbas) {
        m_pending_lbas_bm->reset_bits(start_lba, nlbas);
    }

    bool is_lbas_free(const uint64_t start_lba, const uint32_t nlbas) {
        return m_pending_lbas_bm->is_bits_reset(start_lba, nlbas);
    }

    void invalidate_lbas(const uint64_t start_lba, const uint32_t nlbas) { m_hole_lbas_bm->set_bits(start_lba, nlbas); }
    void validate_lbas(const uint64_t start_lba, const uint32_t nlbas) { m_hole_lbas_bm->reset_bits(start_lba, nlbas); }
    auto get_next_valid_lbas(const uint64_t start_lba, const uint32_t min_nlbas, const uint32_t max_nlbas) {
        const auto bb{m_hole_lbas_bm->get_next_contiguous_n_reset_bits(start_lba, std::nullopt, min_nlbas, max_nlbas)};
        return std::make_pair<>(bb.start_bit, bb.nbits);
    }
};

struct io_req_t : public vol_interface_req {
    uint64_t original_size;
    uint64_t original_offset;
    uint64_t verify_size;
    uint64_t verify_offset;
    int fd;
    uint8_t* buffer{nullptr};
    uint8_t* validate_buffer{nullptr};
    Op_type op_type;
    uint64_t cur_vol;
    std::shared_ptr< vol_info_t > vol_info;
    bool done{false};

    io_req_t(const std::shared_ptr< vol_info_t >& vinfo, const Op_type op, std::vector< iovec >&& iovecs,
             const uint64_t lba, const uint32_t nlbas, const bool is_csum, const bool cache = false,
             const bool sync = false) :
            vol_interface_req{std::move(iovecs), lba, nlbas, sync, cache},
            buffer{nullptr},
            op_type{op},
            vol_info{vinfo} {
        init(lba, nlbas, is_csum);
        const auto req_ptr{static_cast< vol_interface_req* >(this)};
        if (op == Op_type::WRITE || op == Op_type::UNMAP) {
            // make copy of buffer so validation works properly
            if (is_csum) {
                uint8_t* validate_ptr{validate_buffer};
                const uint64_t pg_size{VolInterface::get_instance()->get_page_size(vinfo->vol)};
                for (const auto& iov : req_ptr->iovecs) {
                    HS_REL_ASSERT_EQ(iov.iov_len % pg_size, 0);
                    populate_csum_buf(reinterpret_cast< uint16_t* >(validate_ptr),
                                      static_cast< const uint8_t* >(iov.iov_base), iov.iov_len, vinfo.get());
                    validate_ptr += (iov.iov_len / pg_size) * sizeof(uint16_t);
                }
            } else {
                uint8_t* validate_ptr{validate_buffer};
                for (const auto& iov : req_ptr->iovecs) {
                    ::memcpy(static_cast< void* >(validate_ptr), static_cast< const void* >(iov.iov_base), iov.iov_len);
                    validate_ptr += iov.iov_len;
                }
            }
        }
    }

    io_req_t(const std::shared_ptr< vol_info_t >& vinfo, const Op_type op, uint8_t* const buf, const uint64_t lba,
             const uint32_t nlbas, const bool is_csum, const bool cache = false, const bool sync = false) :
            vol_interface_req{buf, lba, nlbas, sync, cache},

            buffer{buf},
            op_type{op},
            vol_info{vinfo} {
        init(lba, nlbas, is_csum);

        if (op == Op_type::WRITE) {
            // make copy of buffer so validation works properly
            if (is_csum) {
                populate_csum_buf(reinterpret_cast< uint16_t* >(validate_buffer), buffer, original_size, vinfo.get());
            } else {
                ::memcpy(static_cast< void* >(validate_buffer), static_cast< const void* >(buffer), verify_size);
            }
        }
    }

    bool is_read() const { return op_type == Op_type::READ; }
    bool is_write() const { return op_type == Op_type::WRITE; }
    bool is_unmap() const { return op_type == Op_type::UNMAP; }

    virtual ~io_req_t() override {
        if (validate_buffer) {
            iomanager.iobuf_free(validate_buffer);
        } else {
            // right now we only have unmap that doesn't create validate_buffer;
            HS_REL_ASSERT_EQ(op_type, Op_type::UNMAP);
        }

        const auto req_ptr{static_cast< vol_interface_req* >(this)};
        if (use_cache()) { return; }
        for (auto& iov : req_ptr->iovecs) {
            if (iov.iov_base) {
                iomanager.iobuf_free(static_cast< uint8_t* >(iov.iov_base));
            } else {
                // remove this assert if there is other op that could also have null iovs;
                HS_REL_ASSERT_EQ(op_type, Op_type::UNMAP, "unexpected op_type: {}, other than unmap", op_type);
            }
        }
    }

    io_req_t(const io_req_t&) = delete;
    io_req_t(io_req_t&&) noexcept = delete;
    io_req_t& operator=(const io_req_t&) = delete;
    io_req_t& operator=(io_req_t&&) noexcept = delete;

private:
    void init(const uint64_t lba, const uint32_t nlbas, const bool is_csum) {
        const uint64_t page_size{VolInterface::get_instance()->get_page_size(vol_info->vol)};
        original_size = nlbas * page_size;
        original_offset = lba * page_size;
        verify_size = is_csum ? nlbas * sizeof(uint16_t) : original_size;
        verify_offset = is_csum ? lba * sizeof(uint16_t) : original_offset;
        fd = vol_info->fd;
        cur_vol = vol_info->vol_idx;

        if (op_type != Op_type::UNMAP) {
            validate_buffer = iomanager.iobuf_alloc(512, verify_size);
            HS_REL_ASSERT_NOTNULL(validate_buffer);
        }
    }

    // compute checksum and store in a buf which will be used for verification
    void populate_csum_buf(uint16_t* const csum_buf, const uint8_t* const buf, const uint64_t size,
                           const vol_info_t* const vinfo) {
        if (!buf) return;
        const uint64_t pg_size{VolInterface::get_instance()->get_page_size(vinfo->vol)};
        size_t checksum_num{0};
        for (uint64_t buf_offset{0}; buf_offset < size; buf_offset += pg_size, ++checksum_num) {
            const uint16_t csum1{crc16_t10dif(init_crc_16, buf + buf_offset, pg_size)};
            *(csum_buf + checksum_num) = csum1;
        }
    }
};

TestCfg tcfg;          // Config for each VolTest
const TestCfg g_cfg{}; // Config for global for all tests
const std::string access_mgr_mtype{"ACCESS_MGR"};

class IOTestJob;
/**************** Common class created for all tests ***************/
class VolTest : public ::testing::Test {
    friend class TestJob;
    friend class VolCreateDeleteJob;
    friend class IOTestJob;
    friend class VolVerifyJob;

protected:
    std::atomic< size_t > outstanding_ios;
    TestOutput output;

    std::vector< std::shared_ptr< vol_info_t > > m_vol_info;

    // std::condition_variable m_cv;
    std::condition_variable m_init_done_cv;
    bool m_init_done{false};
    std::mutex m_mutex;
    void* init_buf{nullptr};

    // uint64_t cur_vol;
    // Clock::time_point startTime;
    std::vector< dev_info > m_device_info;
    uint64_t max_vol_size;
    uint64_t max_vol_size_csum;
    std::shared_ptr< IOTestJob > m_io_job;

    // bool verify_done;
    // bool move_verify_to_done;
    // bool vol_create_del_test;

    Clock::time_point print_startTime;

    // std::atomic< bool > io_stalled = false;
    // bool expected_init_fail = false;

    static boost::uuids::uuid m_am_uuid; // simulate am system uuid
    static bool m_am_sb_received;        // used in recovery mode;
    static bool m_am_sb_written;         // track whether am sb is written or not
public:
    static thread_local uint32_t _n_completed_this_thread;

    VolTest() : m_vol_info(g_cfg.max_vols), m_device_info{} {
        tcfg = g_cfg; // Reset the config from global config

        // cur_vol = 0;
        max_vol_size = 0;
        max_vol_size_csum = 0;
        // verify_done = false;
        // vol_create_del_test = false;
        // move_verify_to_done = false;
        print_startTime = Clock::now();

        // outstanding_ios = 0;
    }

    virtual ~VolTest() override {
        if (init_buf) { iomanager.iobuf_free(static_cast< uint8_t* >(init_buf)); }
    }

    VolTest(const VolTest&) = delete;
    VolTest(VolTest&&) noexcept = delete;
    VolTest& operator=(const VolTest&) = delete;
    VolTest& operator=(VolTest&&) noexcept = delete;

    virtual void SetUp() override{};
    virtual void TearDown() override{};

    void remove_files() {
        /* no need to delete the user created file/disk */
        if (tcfg.dev_names.size() == 0) {
            for (const auto& n : tcfg.default_names) {
                const fs::path fpath{n};
                if (fs::exists(fpath) && fs::is_regular_file(fpath)) { fs::remove(fpath); }
            }
        }

        for (uint32_t i{0}; i < tcfg.max_vols; ++i) {
            const fs::path fpath{VOL_PREFIX + std::to_string(i)};
            if (fs::exists(fpath) && fs::is_regular_file(fpath)) { fs::remove(fpath); }
        }
    }

    static void am_meta_blk_comp_cb(bool success) {
        HS_REL_ASSERT_EQ(success, true);
        // it is possible that abort (intentional test) can happen before am got chance to be written;
        if (!tcfg.init && m_am_sb_written) {
            // should have received am sb callback from MetaBlkStore;
            HS_REL_ASSERT_EQ(m_am_sb_received, true);
        }
    }

    static void am_meta_blk_found_cb([[maybe_unused]] meta_blk* const mblk, const sisl::byte_view& buf,
                                     const size_t size) {
        // should be called only once in recovery mode;
        HS_REL_ASSERT_EQ(m_am_sb_received, false);
        m_am_sb_received = true;
        const std::string str{reinterpret_cast< const char* >(buf.bytes()), size};
        HS_REL_ASSERT_EQ(str.compare(boost::uuids::to_string(m_am_uuid)), 0);
    }

    uint64_t get_dev_info(std::vector< dev_info >& device_info) {
        uint64_t max_capacity{0};

        if (tcfg.dev_names.size() != 0) {
            for (uint32_t i{0}; i < tcfg.dev_names.size(); ++i) {
                const fs::path fpath{tcfg.dev_names[i]};
                /* we use this capacity to calculate volume size */
                max_capacity += tcfg.max_disk_capacity;
                // device_info.emplace_back(fs::canonical(fpath).string(), HSDevType::Data);
                device_info.emplace_back(tcfg.dev_names[i], HSDevType::Data);
            }
        } else {
            /* create files */
            for (uint32_t i{0}; i < MAX_DEVICES; ++i) {
                const fs::path fpath{tcfg.default_names[i]};
                if (tcfg.init) {
                    std::ofstream ofs{fpath.string(), std::ios::binary | std::ios::out};
                    fs::resize_file(fpath, tcfg.max_disk_capacity);
                }

                device_info.emplace_back(fs::canonical(fpath).string(), HSDevType::Data);
                max_capacity += tcfg.max_disk_capacity;
            }
        }

        uint32_t hdd_cnt = tcfg.emulate_hdd_cnt;
        for (auto& dinfo : device_info) {

            auto data_attrs = iomgr::drive_attributes();
            data_attrs.phys_page_size = tcfg.phy_page_size;
            data_attrs.align_size = 512;
            data_attrs.atomic_phys_page_size = tcfg.atomic_phys_page_size;

            if (hdd_cnt != 0) {
                iomgr::DriveInterface::emulate_drive_type(dinfo.dev_names,
                                                          tcfg.dev_names.empty() ? iomgr::drive_type::file_on_hdd
                                                                                 : iomgr::drive_type::block_hdd);
                data_attrs.align_size = 2 * data_attrs.align_size;
                data_attrs.phys_page_size = 2 * tcfg.phy_page_size;
                data_attrs.atomic_phys_page_size = 2 * tcfg.atomic_phys_page_size;
                data_attrs.num_streams = tcfg.emulate_hdd_stream_cnt;
                --hdd_cnt;
            }
            iomgr::DriveInterface::emulate_drive_attributes(dinfo.dev_names, data_attrs);
        }

        return max_capacity;
    }

    void start_homestore(const bool force_reinit = true, const bool wait_for_init_done = true) {
        uint64_t max_capacity = 0;

        /* start homestore */
        /* create files */
#if 0
        struct stat st;
        if (stat("test_files", &st) == -1) { mkdir("test_files", 0700); }
#endif

        if (tcfg.remove_file_on_start) {
            // clean all files under test_files/ dir
            const fs::path fpath{"test_files"};
            if (fs::is_directory(fpath)) {
                auto nfiles = fs::remove_all(fs::canonical(fpath));
                LOGINFO("Removed {} files in dir: {}", nfiles, fpath.string());
            } else {
                LOGINFO("{} is not a directory", fpath.string());
            }
        }

        fs::create_directory("test_files");
        fs::permissions("test_files", fs::perms::owner_all);

        ioenvironment.with_iomgr(tcfg.num_threads, tcfg.is_spdk);

        get_dev_info(m_device_info);
        init_params params;
        params.data_open_flags = tcfg.io_flags;
        params.fast_open_flags = tcfg.io_flags;
        params.min_virtual_page_size = tcfg.vol_page_size;
        params.app_mem_size = tcfg.app_mem_size_in_gb * 1024 * 1024 * 1024ul;

        params.data_devices = m_device_info;

#ifdef _PRERELEASE
        params.force_reinit = force_reinit;
#endif
        if (std::getenv(HTTP_SVC_ENV_VAR_STRING.c_str())) {
            params.start_http = false; // do not start http server;
        }
        params.init_done_cb = bind_this(VolTest::init_done_cb, 2);
        params.vol_mounted_cb = bind_this(VolTest::vol_mounted_cb, 2);
        params.vol_state_change_cb = bind_this(VolTest::vol_state_change_cb, 3);
        params.vol_found_cb = bind_this(VolTest::vol_found_cb, 1);
        params.end_of_batch_cb = bind_this(VolTest::process_end_of_batch, 1);

        boost::uuids::string_generator gen;
        m_am_uuid = gen("01970496-0262-11e9-8eb2-f2801f1b9fd1");

        for (uint32_t i{0}; i < mod_tests.size(); ++i) {
            mod_tests[i]->try_init_iteration();
        }
        if (SISL_OPTIONS.count("http_port")) {
            test_common::set_fixed_http_port(SISL_OPTIONS["http_port"].as< uint32_t >());
        } else {
            test_common::set_random_http_port();
        }
        VolInterface::init(params);

        if (wait_for_init_done) { wait_homestore_init_done(); }
        ioenvironment.get_http_server()->start();

        if (tcfg.init) {
            void* cookie{nullptr};
            MetaBlkMgrSI()->add_sub_sb(access_mgr_mtype, (void*)(boost::uuids::to_string(m_am_uuid).c_str()),
                                       boost::uuids::to_string(m_am_uuid).size(), cookie);
            m_am_sb_written = true;
        }
    }

    bool fix_vol_mapping_btree() {
        /* fix all volumes mapping btrees */
        for (uint64_t i{0}; i < tcfg.max_vols; ++i) {
            auto vol_ptr{m_vol_info[i]->vol};
            const auto ret{VolInterface::get_instance()->fix_tree(vol_ptr, true /* verify */)};
            if (ret == false) {
                LOGERROR("fix_tree of vol: {} failed!", VolInterface::get_instance()->get_name(vol_ptr));
                return false;
            }
        }
        return true;
    }

    void move_vol_to_offline() {
        /* move all volumes to offline */
        for (uint64_t i{0}; i < tcfg.max_vols; ++i) {
            VolInterface::get_instance()->vol_state_change(m_vol_info[i]->vol, homestore::vol_state::OFFLINE);
        }
    }

    void move_vol_to_online() {
        /* move all volumes to online */
        for (uint64_t i{0}; i < tcfg.max_vols; ++i) {
            VolInterface::get_instance()->vol_state_change(m_vol_info[i]->vol, homestore::vol_state::ONLINE);
        }
    }

    bool vol_found_cb(const boost::uuids::uuid uuid) {
        HS_REL_ASSERT_EQ(tcfg.init, false);
        return (is_valid_vol_file(uuid));
    }

    void vol_mounted_cb(const VolumePtr& vol_obj, const vol_state state) {
        HS_REL_ASSERT_EQ(tcfg.init, false);
        const auto cnt{output.vol_mounted_cnt.fetch_add(1, std::memory_order_relaxed)};
        vol_init(vol_obj);

        VolInterface* const viface{VolInterface::get_instance()};
        if (tcfg.batch_completion) {
            viface->attach_vol_completion_cb(vol_obj, bind_this(VolTest::process_multi_completions, 1));
            viface->attach_end_of_batch_cb(bind_this(VolTest::process_end_of_batch, 1));
        } else {
            viface->attach_vol_completion_cb(vol_obj, bind_this(VolTest::process_single_completion, 1));
        }
        HS_REL_ASSERT_EQ(state, tcfg.expected_vol_state);
        if (tcfg.expected_vol_state == homestore::vol_state::DEGRADED ||
            tcfg.expected_vol_state == homestore::vol_state::OFFLINE) {
            VolInterface::get_instance()->vol_state_change(vol_obj, vol_state::ONLINE);
        }
    }

    void vol_init(const VolumePtr& vol_obj) {
        const std::string file_name{VolInterface::get_instance()->get_name(vol_obj)};
        const int indx{get_vol_indx(file_name)};

        std::shared_ptr< vol_info_t > info{std::make_shared< vol_info_t >()};
        info->vol = vol_obj;
        info->uuid = VolInterface::get_instance()->get_uuid(vol_obj);
        if (tcfg.create_vol_file()) { info->fd = open(file_name.c_str(), O_RDWR); }
        info->max_vol_blks =
            VolInterface::get_instance()->get_size(vol_obj) / VolInterface::get_instance()->get_page_size(vol_obj);

        info->m_pending_lbas_bm = std::make_unique< sisl::Bitset >(info->max_vol_blks);
        info->m_hole_lbas_bm = std::make_unique< sisl::Bitset >(info->max_vol_blks);
        info->invalidate_lbas(0, info->max_vol_blks); // Punch hole for all.
        info->cur_checkpoint = 0;
        info->ref_cnt.increment(1);

        m_vol_info[indx] = info;
    }

    void vol_state_change_cb(const VolumePtr& vol, const vol_state old_state, const vol_state new_state) {
        HS_REL_ASSERT_EQ(new_state, homestore::vol_state::FAILED);
    }

    /* Note: It assumes that create volume is not happening in parallel */
    bool create_volume(const int indx) {
        if ((m_vol_info.size() != 0) && m_vol_info[indx]) {
            if (m_vol_info[indx]->ref_cnt.get()) {
                // this volume is still active;
                return false;
            } else {
                // remove volume has been issued on this volume;
                const auto vol = VolInterface::get_instance()->lookup_volume(m_vol_info[indx]->uuid);
                if (vol) {
                    // async deletion of this volume is still in progress;
                    // otherwise, vol will not be found by homeblks;
                    const auto state = VolInterface::get_instance()->get_state(vol);
                    HS_REL_ASSERT_EQ(state == vol_state::DESTROYING || state == vol_state::START_INDX_TREE_DESTROYING ||
                                         state == vol_state::DESTROYED,
                                     true, "unexpected vol state: {}", state);
                    return false;
                }

                // volume has already been removed, we can safely fall through to create another volume on same index;
            }
        }

        /* Create a volume */
        vol_params params;
        params.page_size = tcfg.vol_page_size;
        params.size = max_vol_size;
        params.io_comp_cb = tcfg.batch_completion ? io_comp_callback(bind_this(VolTest::process_multi_completions, 1))
                                                  : io_comp_callback(bind_this(VolTest::process_single_completion, 1));
        params.uuid = boost::uuids::random_generator()();
        const std::string name{VOL_PREFIX + std::to_string(indx)};
        ::strcpy(params.vol_name, name.c_str());
        /* check if same volume exist or not */

        auto vol_obj{VolInterface::get_instance()->create_volume(params)};
        if (vol_obj == nullptr) {
            LOGINFO("creation failed");
            return false;
        }
        HS_REL_ASSERT_EQ(VolInterface::get_instance()->lookup_volume(params.uuid), vol_obj);

        if (tcfg.create_vol_file()) {
            // check remaining space on root fs;
            std::error_code ec;
            uint64_t free_space{0};
            const fs::space_info si = fs::space(fs::current_path(), ec);
            if (ec.value()) {
                HS_REL_ASSERT(false, "Error getting space for dir={}, error={}", name, ec.message());
            } else {
                // Don't use more than 30% of free space of root fs;
                free_space = static_cast< uint64_t >(std::min(si.free, si.available) * tcfg.p_vol_files_space / 100);
            }

            uint64_t offset_to_seek{0};
            if (tcfg.verify_csum()) {
                offset_to_seek = max_vol_size_csum + VOL_FILE_HDR_SZ;
            } else if (tcfg.verify_data()) {
                offset_to_seek = max_vol_size + VOL_FILE_HDR_SZ;
            } else {
                // we still create vol file with small size for just vol hdr for recovery relies on vol hdr to count
                // mounted vols;
                HS_REL_ASSERT(tcfg.verify_hdr() || !tcfg.verify_type_set(), "Unrecognized verify_type: {} ",
                              tcfg.verify_type);
                offset_to_seek = VOL_HDR_ONLY_FILE_SIZE;
            }

            HS_REL_ASSERT_GT(free_space, offset_to_seek);

            // create file for verification
            auto vol_file_path = fs::current_path().string() + "/" + name;
            if (fs::exists(vol_file_path) == false) {
                // only create file and initialize it when file is not there;
                std::ofstream ofs{name, std::ios::binary | std::ios::out | std::ios::trunc};
                ofs.seekp(offset_to_seek);
                ofs.write("", 1);
                ofs.close();
            }

            auto fd = open(name.c_str(), O_RDWR);
            init_vol_files(fd, params.uuid);
            close(fd);
        }

        LOGINFO("Created volume {} of size: {}", name, tcfg.verify_csum() ? max_vol_size_csum : max_vol_size);
        ++output.vol_create_cnt;

        /* open a corresponding file */
        vol_init(vol_obj);
        return true;
    }

    void init_done_cb(const std::error_condition err, const out_params& params) {
        /* create volume */
        if (err) {
            HS_REL_ASSERT_EQ(tcfg.expected_init_fail, true);
            {
                std::unique_lock< std::mutex > lk{m_mutex};
                m_init_done = true;
            }
            m_init_done_cv.notify_all();
            return;
        }

        /* Don't populate the whole disks. Only 60 % of it */
        const auto max_capacity{VolInterface::get_instance()->get_system_capacity().initial_total_size};
        if (tcfg.max_vols) {
            max_vol_size = (tcfg.p_volume_size * max_capacity) / (100 * tcfg.max_vols);
            max_vol_size_csum = (sizeof(uint16_t) * max_vol_size) / tcfg.vol_page_size;
        }

        if (tcfg.init) {
            HS_REL_ASSERT_EQ(params.first_time_boot, true);
        } else {
            HS_REL_ASSERT_EQ(output.vol_mounted_cnt, get_mounted_vols());
            HS_REL_ASSERT_EQ(params.first_time_boot, false);
        }

        tcfg.max_io_size = params.max_io_size;
        if (SISL_OPTIONS.count("max_io_size")) { tcfg.max_io_size = SISL_OPTIONS["max_io_size"].as< uint64_t >(); }

        HS_REL_ASSERT_LE(tcfg.io_size, tcfg.max_io_size, "io_size {} should not exceed max_io_size {}", tcfg.io_size,
                         tcfg.max_io_size);

        const uint64_t init_buf_size{tcfg.verify_csum() ? tcfg.vol_page_size : tcfg.max_io_size};

        init_buf = iomanager.iobuf_alloc(512 /* alignment */, init_buf_size);
        std::memset(static_cast< void* >(init_buf), 0, init_buf_size);
        HS_REL_ASSERT_EQ(tcfg.expected_init_fail, false);
        if (tcfg.init) {
            if (tcfg.precreate_volume) {
                for (uint64_t i{0}; i < tcfg.max_vols; ++i) {
                    create_volume(i);
                }
            }
            // verify_done = true;
            // startTime = Clock::now();
        }

        /* TODO :- Rishabh: remove it */

        outstanding_ios = 0;

        {
            std::unique_lock< std::mutex > lk{m_mutex};
            m_init_done = true;
        }
        /* notify who is waiting for init to be completed */
        m_init_done_cv.notify_all();

#ifdef _PRERELEASE
        if (tcfg.flip_set == 1) {
            VolInterface::get_instance()->set_io_flip();
        } else if (tcfg.flip_set == 2) {
            tcfg.expect_io_error = true;
            VolInterface::get_instance()->set_io_flip();
            VolInterface::get_instance()->set_error_flip();
        }
#endif
        return;
    }

    void shutdown() {
        LOGINFO("shutting down homeblks");

        {
            std::unique_lock< std::mutex > lk(m_mutex);
            m_vol_info.clear();
        }

        VolInterface::shutdown(false /* force */);
        ioenvironment.get_http_server()->stop();

        LOGINFO("stopping iomgr");
        iomanager.stop();
    }

    void start_job(TestJob* const job, const wait_type wait_type = wait_type::for_completion) {
        iomanager.run_on(iomgr::thread_regex::all_worker,
                         [job, this](iomgr::io_thread_addr_t a) { job->start_in_this_thread(); });
        if (wait_type == wait_type::for_execution) {
            job->wait_for_execution();
        } else if (wait_type == wait_type::for_completion) {
            job->wait_for_completion();
        }
    }

    std::shared_ptr< IOTestJob > start_io_job(const wait_type wait_type = wait_type::for_execution,
                                              const load_type_t load_type = tcfg.load_type);

    void wait_homestore_init_done() {
        std::unique_lock< std::mutex > lk{m_mutex};
        m_init_done_cv.wait(lk, [this]() { return m_init_done; });
    }

    //
    // pick up an existing volume issue an destroy then create same volume with same uuid before destroy volume
    // finishes;
    //
    void delete_and_create_same_uuid_vol() {
        HS_REL_ASSERT_GT(m_vol_info.size(), 0, "Expecting at least one volumee");
        auto vinfo = m_vol_info[0];
        const auto uuid = VolInterface::get_instance()->get_uuid(vinfo->vol);

        VolInterface::get_instance()->remove_volume(uuid);

        /* Create a volume */
        vol_params params;
        params.page_size = tcfg.vol_page_size;
        params.size = max_vol_size;
        params.io_comp_cb = tcfg.batch_completion ? io_comp_callback(bind_this(VolTest::process_multi_completions, 1))
                                                  : io_comp_callback(bind_this(VolTest::process_single_completion, 1));
        params.uuid = uuid; /* use same uuid that is pending on destroying */
        const std::string name{VOL_PREFIX + std::to_string(0)};
        ::strcpy(params.vol_name, name.c_str());

        /* check if same volume exist or not */
        const auto vol_obj = VolInterface::get_instance()->create_volume(params);
        if (vol_obj == nullptr) {
            LOGINFO("Create vol with same uuid: {} failed as expected!", boost::lexical_cast< std::string >(uuid));
        } else {
            // trigger assert failure to fail the test;
            HS_REL_ASSERT(
                false, "Expecting vol_obj to be null when creating vol with same uuid that is pending on destroying.");
        }
    }

    void delete_volumes() {
        const uint64_t tot_cap{VolInterface::get_instance()->get_system_capacity().initial_total_data_meta_size};
        uint64_t used_cap{VolInterface::get_instance()->get_system_capacity().used_total_size};
        HS_REL_ASSERT_LE(used_cap, tot_cap);
        for (uint64_t i{0}; i < m_vol_info.size(); ++i) {
            delete_volume(i);
        }
        used_cap = VolInterface::get_instance()->get_system_capacity().used_total_size;
        if (used_cap != 0) {
            // assert(false);
        }
    }

private:
    void init_vol_file_hdr(const int fd) {
        /* set first bit to 0 */
        vol_file_hdr hdr;
        hdr.state = vol_cd_state_t::DELETED;
        auto buf = iomanager.iobuf_alloc(512, sizeof(vol_file_hdr));
        *reinterpret_cast< vol_file_hdr* >(buf) = hdr;
        const auto ret{pwrite(fd, buf, sizeof(vol_file_hdr), 0)};
        HS_REL_ASSERT_EQ(static_cast< uint64_t >(ret), sizeof(vol_file_hdr));
        iomanager.iobuf_free(buf);
    }

    void set_vol_file_hdr(const int fd, const boost::uuids::uuid uuid) {
        /* set first bit to 1 */
        vol_file_hdr hdr;
        hdr.state = vol_cd_state_t::CREATED;
        hdr.uuid = uuid;
        auto* const buf{iomanager.iobuf_alloc(512, sizeof(vol_file_hdr))};
        *reinterpret_cast< vol_file_hdr* >(buf) = hdr;
        const auto ret{::pwrite(fd, buf, sizeof(vol_file_hdr), 0)};
        HS_REL_ASSERT_EQ(static_cast< uint64_t >(ret), sizeof(vol_file_hdr));
        iomanager.iobuf_free(buf);
    }

    bool is_valid_vol_file(const boost::uuids::uuid& uuid) {
        auto buf = iomanager.iobuf_alloc(512, sizeof(vol_file_hdr));
        bool found = false;
        for (uint32_t i = 0; i < tcfg.max_vols; ++i) {
            const std::string name = VOL_PREFIX + std::to_string(i);
            auto fd = open(name.c_str(), O_RDWR);
            const auto ret{pread(fd, buf, sizeof(vol_file_hdr), 0)};
            close(fd);
            vol_file_hdr hdr = *reinterpret_cast< vol_file_hdr* >(buf);
            if (hdr.state == vol_cd_state_t::DELETED) {
                if (hdr.uuid == uuid) {
                    LOGINFO("Bypassing deleted file hdr vol:{} with SAME uuid: {}", name, hdr.uuid);
                }
                continue;
            }

            if (hdr.uuid == uuid) {
                found = true;
                break;
            }
        }

        iomanager.iobuf_free(buf);
        return found;
    }

    uint64_t get_mounted_vols() {
        auto buf = iomanager.iobuf_alloc(512 /* alignment */, sizeof(vol_file_hdr));
        uint64_t mounted_vols = 0;
        for (uint32_t i = 0; i < tcfg.max_vols; ++i) {
            const std::string name = VOL_PREFIX + std::to_string(i);
            auto fd = open(name.c_str(), O_RDWR);

            if (fd < 0) {
                // there is assert if mounted vols counter doesn't match;
                LOGINFO(
                    "Error opening fd: {}, error: {}, possible volume: {} is not yet created if this is intentional "
                    "crash test.",
                    fd, errno, name);
                continue;
            }

            std::memset(buf, 0, sizeof(vol_file_hdr));

            // read file content if file exists;
            const auto ret{pread(fd, buf, sizeof(vol_file_hdr), 0)};
            close(fd);
            vol_file_hdr hdr = *reinterpret_cast< vol_file_hdr* >(buf);
            if (hdr.state == vol_cd_state_t::DELETED) {
                LOGINFO("Found deleted vol:{}, uuid: {} ", name, hdr.uuid);
                continue;
            } else if (hdr.state == vol_cd_state_t::CREATED) {
                LOGINFO("Found mounted vol:{}, uuid: {} ", name, hdr.uuid);
                ++mounted_vols;
            } else {
                // we will not come here in existing case, but it is a possible path that program do
                // intentional/random abort after file creation before init file hdr;
                //
                // This volume will be discarded by vol_gtest if it has been created insternally by homestore which is a
                // fine case;
                LOGINFO(
                    "Found uninitialized vol: {} on disk and ignoring it, this is because the file is created but not "
                    "inited yet. ",
                    name);
            }
        }

        iomanager.iobuf_free(buf);
        return mounted_vols;
    }

    void write_vol_file(const int fd, void* const buf, const uint64_t write_size, const off_t offset) {
        const auto ret(::pwrite(fd, buf, write_size, offset + VOL_FILE_HDR_SZ));
        HS_REL_ASSERT_EQ(static_cast< uint64_t >(ret), write_size);
    }

    void read_vol_file(const int fd, void* const buf, const uint64_t read_size, const off_t offset) {
        const auto ret(::pread(fd, buf, read_size, offset + VOL_FILE_HDR_SZ));
        HS_REL_ASSERT_EQ(static_cast< uint64_t >(ret), read_size);
    }

    int get_vol_indx(const std::string& file_name) {
        const std::string str{file_name.substr(VOL_PREFIX.size())};
        return (std::stoi(str));
    }

    void init_vol_files(const int fd, const boost::uuids::uuid uuid) {
        if (tcfg.verify_csum() || tcfg.verify_data()) {
            // 1. we only write vol file content for csum and data verify;
            // 2. skip for hdr and null verify type;
            //
            // for csum, write csum (sizeof(uint64_t)) for every 4k data;
            // initialize the file only for non-header case;
            uint8_t* init_csum_buf{nullptr};
            const uint32_t num_csums_write{1024};
            const auto crc_zero =
                crc16_t10dif(init_crc_16, static_cast< const uint8_t* >(init_buf), tcfg.vol_page_size);

            if (tcfg.verify_csum()) {
                init_csum_buf = iomanager.iobuf_alloc(512, num_csums_write * sizeof(uint16_t));
                for (size_t i = 0; i < num_csums_write; ++i) {
                    *(reinterpret_cast< uint16_t* >(init_csum_buf) + i) = crc_zero;
                }
            }
            const uint64_t offset_increment{tcfg.verify_csum() ? (sizeof(uint16_t) * num_csums_write)
                                                               : tcfg.max_io_size};

            const uint64_t max_offset{tcfg.verify_csum() ? max_vol_size_csum : max_vol_size};

            for (uint64_t offset{0}; offset < max_offset; offset += offset_increment) {
                uint64_t write_size;
                if (offset + offset_increment > max_offset) {
                    write_size = max_offset - offset;
                } else {
                    write_size = offset_increment;
                }

                write_vol_file(fd, static_cast< void* >(tcfg.verify_csum() ? init_csum_buf : init_buf), write_size,
                               static_cast< off_t >(offset));
            }

            if (init_csum_buf) { iomanager.iobuf_free(init_csum_buf); }
        }

        // we write header in the last, so if it crashes before header written, vol will be discarded;
        set_vol_file_hdr(fd, uuid);
    }

    static thread_local std::list< vol_interface_req_ptr > completed_reqs_this_thread;

    void process_multi_completions(const std::vector< vol_interface_req_ptr >& reqs) {
        LOGTRACE("Multi completions for {} reqs", reqs.size());
        for (auto& vol_req : reqs) {
            LOGTRACE("vol req id = {} is completed", vol_req->request_id);
            ASSERT_EQ(vol_req->vol_instance.get(), reqs[0]->vol_instance.get());
            completed_reqs_this_thread.push_back(vol_req);
        }
        LOGTRACE("Got {} completions for volume {} in one event", reqs.size(),
                 VolInterface::get_instance()->get_name(reqs[0]->vol_instance));
    }

    void process_single_completion(const vol_interface_req_ptr& vol_req) {
        LOGTRACE("vol req id = {} is completed", vol_req->request_id);
        completed_reqs_this_thread.push_back(vol_req);
        process_end_of_batch(1);
    }

    void process_end_of_batch(const int ncompletions) {
        LOGTRACE("Got total {} callbacks across multiple volumes in one event, num_jobs_completed_this_thread={}",
                 ncompletions, completed_reqs_this_thread.size());

        // First iteration goes thru all jobs and call their on_completion method
        for (auto& vol_req : completed_reqs_this_thread) {
            TestJob* const job{static_cast< TestJob* >(vol_req->cookie)};
            job->on_one_iteration_completed(boost::static_pointer_cast< io_req_t >(vol_req));
        }

        // Second iteration gives the job a chance to refill the work if it is not time to stop
        HS_REL_ASSERT_EQ(completed_reqs_this_thread.empty(), false);
        while (!completed_reqs_this_thread.empty()) {
            auto vol_req{std::move(completed_reqs_this_thread.front())};
            completed_reqs_this_thread.pop_front();

            TestJob* const job{static_cast< TestJob* >(vol_req->cookie)};
            job->try_run_one_iteration();
        }

        VolInterface::get_instance()->submit_io_batch();
    }

    bool delete_volume(const int vol_indx) {
        // std::move will release the ref_count in VolTest::vol and pass to HomeBlks::remove_volume
        boost::uuids::uuid uuid;
        auto vinfo{m_vol_info[vol_indx]};
        if (!vinfo) { return false; }
        auto& vol{vinfo->vol};
        bool expected{false};
        bool desired{true};
        if (vinfo->vol_destroyed.compare_exchange_strong(expected, desired)) {
            if (!tcfg.expect_io_error) {
                HS_REL_ASSERT_EQ(VolInterface::get_instance()->get_state(vol), vol_state::ONLINE);
            }
            uuid = VolInterface::get_instance()->get_uuid(vinfo->vol);
            /* initialize file hdr */
            if (tcfg.create_vol_file()) { init_vol_file_hdr(vinfo->fd); }
            VolInterface::get_instance()->remove_volume(uuid);
            vinfo->ref_cnt.decrement_testz(1);
            ++output.vol_del_cnt;
        }
        return true;
    }

    void shutdown_force(const bool timeout) {
        std::unique_lock< std::mutex > lk{m_mutex};
        bool force{false};
        // release the ref_count to volumes;
        if (!timeout) {
            remove_journal_files();
            m_vol_info.clear();
            force = true;
        }
        VolInterface::shutdown(force);
        ioenvironment.get_http_server()->stop();
    }

    void remove_journal_files() {
        // Remove journal folders
        for (size_t i{0}; i < m_vol_info.size(); ++i) {
            const fs::path name{boost::lexical_cast< std::string >(m_vol_info[i]->uuid)};
            if (fs::exists(name) && fs::is_directory(name)) {
                fs::remove_all(name);
                LOGINFO("Removed journal dir: {}", name);
            }
        }
    }

public:
    //
    // read crc from test_files/vol[1...x]
    // read data on vol file and caculate its crc and make sure they match;
    //
    void reverse_verify_vol(const std::string& vol_copy_file_path) {
        const auto fname = fs::path(vol_copy_file_path).filename().string();
        const auto vol_uuid = fname.substr(0, fname.find("_p_"));
        const std::string crc_file_name{VOL_PREFIX + std::to_string(0)};
        auto crc_fd = open(crc_file_name.c_str(), O_RDONLY);
        auto fd = open(vol_copy_file_path.c_str(), O_RDONLY);

        lseek(crc_fd, VOL_FILE_HDR_SZ, SEEK_SET);
        ssize_t nbytes = 0;
        off_t crc_off = 0;
        const auto read_buf = iomanager.iobuf_alloc(512 /* alignment */, tcfg.vol_page_size);
        std::memset(read_buf, 0, tcfg.vol_page_size);
        const auto zero_crc = crc16_t10dif(init_crc_16, read_buf, tcfg.vol_page_size);
        uint16_t crc1 = 0;

        // let crc_fd's file offset advance automatcially;
        while ((nbytes = read(crc_fd, &crc1, sizeof(uint16_t))) != 0) {
            if (nbytes == -1) {
                HS_REL_ASSERT(true, "read errno: {}, message: {}", errno, std::strerror(errno));
            } else {
                if (nbytes != sizeof(uint16_t)) {
                    // we reached end of file;
                    // vol file was written one byte of null at the end of the file;
                    LOGINFO("Reached end of vol file storing crc.");
                    break;
                }

                if (crc1 != zero_crc) {
                    std::memset(read_buf, 0, tcfg.vol_page_size);
                    [[maybe_unused]] const auto ret =
                        pread(fd, read_buf, tcfg.vol_page_size, crc_off * tcfg.vol_page_size);
                    const auto crc2 = crc16_t10dif(init_crc_16, read_buf, tcfg.vol_page_size);
                    HS_REL_ASSERT_EQ(crc1, crc2, "crc mismatch: origin crc: {}, copy vol crc: {}, offset: {}, len: {}",
                                     crc1, crc2, crc_off, tcfg.vol_page_size);
                }
                // fall through for crc equal to m_crc_zero
            }

            // move to next page crc;
            ++crc_off;
        }
        // end of file

        iomanager.iobuf_free(read_buf);
        close(crc_fd);
        close(fd);
        LOGINFO("Successfully reverse verified crc.");
    }

    //
    // vol data is copied to "vol_copy_file_path",
    // 1. read data out, calculate crc and compare it with vol file saved under test_files/vol[1...x]
    // 2. this is only valid when --verify_type is set to 0, which is default value;
    //
    void verify_vol(const std::string& vol_copy_file_path) {
        // vol_copy_file_path: the file dumped with copied volume data
        // crc_file_name: the file stored with crc when volume is being written in io job;
        const auto fname = fs::path(vol_copy_file_path).filename().string();
        const auto vol_uuid = fname.substr(0, fname.find("_p_"));
        const std::string crc_file_name{VOL_PREFIX + std::to_string(0)};
        auto crc_fd = open(crc_file_name.c_str(), O_RDONLY);
        vol_file_hdr hdr;
        [[maybe_unused]] const auto rd_sz = pread(crc_fd, (char*)&hdr, VOL_FILE_HDR_SZ, 0 /* offset*/);

        // 1. verify uuid does match;
        HS_DBG_ASSERT_EQ(vol_uuid, boost::uuids::to_string(hdr.uuid));

        // 2. read vol_copy_rf (sparse file) and compare with vol_file (dense file);
        //    make sure everything written in vol_copy is also written in vol_file;
        auto fd = open(vol_copy_file_path.c_str(), O_RDONLY);

        uint64_t total_bytes = 0ull;
        // std::vector< uint16_t > crc_vec;
        off_t hole, data, pos;
        auto buf = iomanager.iobuf_alloc(512 /* alignment */, tcfg.vol_page_size);
        std::memset(buf, 0, tcfg.vol_page_size);

        // read until end of the file;
        for (hole = 0;; data = hole) {
            if ((data = lseek(fd, hole, SEEK_DATA)) == -1) {
                if (errno == ENXIO) {
                    LOGINFO("no more data on seek + data.");
                    break;
                }
                HS_REL_ASSERT(false, "Unexpected error: {}, msg: {}", errno, std::strerror(errno));
            }

            if ((hole = lseek(fd, data, SEEK_HOLE)) == -1) {
                if (errno == ENXIO) {
                    LOGINFO("no more data on seek + data.");
                    break;
                }
                HS_REL_ASSERT(false, "Unexpected error: {}, msg: {}", errno, std::strerror(errno));
            }

            HS_DBG_ASSERT_EQ(data % tcfg.vol_page_size, 0, "Unexpected data offset: {}", data);
            HS_DBG_ASSERT_EQ(hole % tcfg.vol_page_size, 0, "Unexpected hole offset: {}", hole);

            const auto data_len = hole - data;
            LOGINFO("Found data lba: {}, len: {}", data / tcfg.vol_page_size, data_len);
            total_bytes += data_len;

            // read page by page to cross compare crc with the crc saved on disk;
            for (pos = data; pos < hole;) {
                // io size should be times of 4KB;
                std::memset(buf, 0, tcfg.vol_page_size);
                [[maybe_unused]] const auto ret = pread(fd, buf, tcfg.vol_page_size, pos);
                // calculate crc
                const auto crc1 = crc16_t10dif(init_crc_16, buf, tcfg.vol_page_size);
                uint16_t crc2 = 0;
                [[maybe_unused]] const auto ret2 = pread(
                    crc_fd, &crc2, sizeof(uint16_t), VOL_FILE_HDR_SZ + (pos / tcfg.vol_page_size) * sizeof(uint16_t));
                HS_REL_ASSERT_EQ(crc1, crc2, "crc mismatch: copy vol crc: {}, origin crc: {}, offset: {}, len: {}",
                                 crc1, crc2, pos, tcfg.vol_page_size);
                pos += tcfg.vol_page_size;
            }

            HS_DBG_ASSERT_EQ(pos, hole, "pos: {}, hole: {}", pos, hole);
        }

        LOGINFO(
            "Successfully verficed copied volume's name: {}, crc matches with crc file saved on disk, total bytes: {}",
            vol_uuid, total_bytes);

        iomanager.iobuf_free(buf);
        close(fd);
        close(crc_fd);
    }

    void force_reinit(const std::vector< dev_info >& data_devices, const io_flag data_oflags,
                      const io_flag fast_oflags) {
        ioenvironment.with_iomgr(1);
        VolInterface::get_instance()->zero_boot_sbs(data_devices);
        iomanager.stop();
    }
};

bool VolTest::m_am_sb_received{false};
bool VolTest::m_am_sb_written{false};
boost::uuids::uuid VolTest::m_am_uuid{};

class VolCreateDeleteJob : public TestJob {
public:
    // create and delete operation can'be done in worker thread, as it will trigger sync io;
    VolCreateDeleteJob(VolTest* test) : TestJob(test, tcfg.create_del_ops_interval, false /* run_in_worker_thread */) {}
    virtual ~VolCreateDeleteJob() override = default;
    VolCreateDeleteJob(const VolCreateDeleteJob&) = delete;
    VolCreateDeleteJob(VolCreateDeleteJob&&) noexcept = delete;
    VolCreateDeleteJob& operator=(const VolCreateDeleteJob&) = delete;
    VolCreateDeleteJob& operator=(VolCreateDeleteJob&&) noexcept = delete;

    void run_one_iteration() override {
        static thread_local std::random_device rd{};
        static thread_local std::default_random_engine engine{rd()};
        static thread_local std::uniform_int_distribution< uint64_t > dist{0, RAND_MAX};
        if (tcfg.create_del_with_io && m_voltest->create_volume(dist(engine) % tcfg.max_vols)) { ++m_op_cnt; }
        if (m_voltest->delete_volume(dist(engine) % tcfg.max_vols)) { ++m_op_cnt; }
    }

    void on_one_iteration_completed(const boost::intrusive_ptr< io_req_t >& req) override {}

    bool time_to_stop() const override {
        return ((m_op_cnt > tcfg.create_del_ops_cnt) || (get_elapsed_time_sec(m_start_time) > tcfg.run_time));
    }

    virtual bool is_job_done() const override { return true; }
    bool is_async_job() const override { return false; };

    std::string job_name() const { return "VolCreateDeleteJob"; }

private:
    uint32_t m_op_cnt{0};
};

class IOTestJob : public TestJob {
public:
    IOTestJob(VolTest* const test, const load_type_t type = tcfg.load_type) : TestJob{test}, m_load_type{type} {}
    virtual ~IOTestJob() override = default;
    IOTestJob(const IOTestJob&) = delete;
    IOTestJob(IOTestJob&&) noexcept = delete;
    IOTestJob& operator=(const IOTestJob&) = delete;
    IOTestJob& operator=(IOTestJob&&) noexcept = delete;

    virtual void run_one_iteration() override {
        static thread_local uint64_t num_rw_without_unmap{tcfg.unmap_frequency};
        uint64_t cnt{0};
        HS_REL_ASSERT_GE(tcfg.max_outstanding_ios, tcfg.num_threads);
        while ((cnt++ < 1) && (m_outstanding_ios < tcfg.max_outstanding_ios)) {
            write_io();
            if (tcfg.read_enable) { read_io(); }
            if ((++num_rw_without_unmap >= tcfg.unmap_frequency) && (tcfg.unmap_enable)) {
                unmap_io();
                num_rw_without_unmap = 0;
            }
        }
    }

    void on_one_iteration_completed(const boost::intrusive_ptr< io_req_t >& req) override {
        static thread_local std::random_device rd{};
        static thread_local std::default_random_engine engine{rd()};
        static thread_local std::uniform_int_distribution< uint64_t > dist{0, RAND_MAX};

        if (req->err != no_error) {
            assert((req->err == std::errc::resource_unavailable_try_again) || tcfg.expect_io_error);
        } else {
            if (req->is_read() && (tcfg.verify_type_set())) {
                /* read from the file and verify it */
                if (!tcfg.verify_hdr()) {
                    /* no need to read from the file to verify hdr */
                    m_voltest->read_vol_file(req->vol_info->fd, req->validate_buffer, req->verify_size,
                                             req->verify_offset);
                }
                verify(req);
            } else if (!req->is_read() && (tcfg.verify_type_set())) {
                /* write to a file */
                if (!tcfg.verify_hdr()) {
                    /* no need to write to a file to verify hdr */
                    m_voltest->write_vol_file(req->vol_info->fd, req->validate_buffer, req->verify_size,
                                              req->verify_offset);
                }
                if (tcfg.read_verify) {
                    auto& vol{req->vol_info->vol};
                    if (vol) {
                        const auto read_req{read_vol_internal(req->vol_info, vol, req->lba, req->nlbas, true)};
                        if (!tcfg.verify_hdr()) {
                            /* no need to read from the file to verify hdr */
                            m_voltest->read_vol_file(read_req->fd, read_req->validate_buffer, read_req->verify_size,
                                                     read_req->verify_offset);
                        }
                        verify(read_req);
                    }
                }
            }
        }

        if (tcfg.is_abort) {
            if ((get_elapsed_time_sec(m_start_time) > tcfg.run_time) &&
                (get_elapsed_time_sec(m_start_time) > (dist(engine) % tcfg.run_time))) {
                std::raise(SIGKILL);
            }
        }

        {
            std::unique_lock< std::mutex > lk{req->vol_info->vol_mutex};
            req->vol_info->mark_lbas_free(req->lba, req->nlbas);
        }

        --m_outstanding_ios;
        static Clock::time_point print_startTime{Clock::now()};
        const auto elapsed_time{get_elapsed_time_ms(print_startTime)};
        static uint64_t print_time{120000};
        if (elapsed_time > print_time) {
            print_startTime = Clock::now();
            m_voltest->output.print("volume completion");
        }

        req->vol_info->ref_cnt.decrement_testz(1);
    }

    bool time_to_stop() const override {
        return (!tcfg.is_abort &&
                ((m_voltest->output.write_cnt >= tcfg.max_num_writes) ||
                 (get_elapsed_time_sec(m_start_time) > tcfg.run_time)));
    }

    virtual bool is_job_done() const override { return (m_outstanding_ios == 0); }
    bool is_async_job() const override { return true; }
    std::string job_name() const { return "IOJob"; }

protected:
    load_type_t m_load_type;
    std::atomic< uint64_t > m_cur_vol{0};
    std::atomic< uint64_t > m_outstanding_ios{0};
    typedef std::function< bool(const uint32_t, const uint64_t, const uint32_t) > IoFuncType;

    struct io_lba_range_t {
        io_lba_range_t() {}
        io_lba_range_t(bool valid, uint64_t vidx, uint64_t l, uint32_t n) :
                valid_io{valid}, vol_idx{vidx}, lba{l}, num_lbas{n} {}
        bool valid_io{false};
        uint64_t vol_idx{0};
        uint64_t lba{0};
        uint32_t num_lbas{0};
    };
    typedef std::function< io_lba_range_t(void) > LbaGeneratorType;

    io_lba_range_t same_lbas() { return io_lba_range_t{true, 0u, 1u, tcfg.nblks}; }

    std::shared_ptr< vol_info_t > pick_vol_round_robin(io_lba_range_t& r) {
        r.vol_idx = ++m_cur_vol % tcfg.max_vols;
        const auto vol_info{m_voltest->m_vol_info[r.vol_idx]};

        // make sure this volume is still active by checking ref_cnt;
        // if the volume is in destroying state, it is likely the vol_info can be destroyed by other threads
        return (vol_info && vol_info->vol && !(VolInterface::get_instance()->is_destroying(vol_info->vol))) ? vol_info
                                                                                                            : nullptr;
    }

    io_lba_range_t seq_lbas() {
        io_lba_range_t ret;
        const auto vinfo{pick_vol_round_robin(ret)};
        if (vinfo == nullptr) { return ret; }

        ret.num_lbas = tcfg.io_size / VolInterface::get_instance()->get_page_size(vinfo->vol);
        ret.lba = (vinfo->start_lba.fetch_add(ret.num_lbas, std::memory_order_acquire)) %
            (vinfo->max_vol_blks - ret.num_lbas);
        ret.valid_io = true;
        return ret;
    }

    enum class lbas_choice_t : uint8_t { dont_care, atleast_one_valid, all_valid };
    enum class lba_validate_t : uint8_t { dont_care, validate, invalidate };

    io_lba_range_t do_get_rand_lbas(const lbas_choice_t lba_choice, const lba_validate_t validate_choice,
                                    const bool overlapping_allowed) {
        static thread_local std::random_device rd{};
        static thread_local std::default_random_engine engine{rd()};

        io_lba_range_t ret;
        const auto vinfo{pick_vol_round_robin(ret)};
        if (vinfo == nullptr) { return ret; }

        const uint32_t max_blks{
            static_cast< uint32_t >(tcfg.max_io_size / VolInterface::get_instance()->get_page_size(vinfo->vol))};
        // lba: [0, max_vol_blks - max_blks)
        std::uniform_int_distribution< uint64_t > lba_random{0, vinfo->max_vol_blks - max_blks - 1};
        // nlbas: [1, max_blks]
        std::uniform_int_distribution< uint32_t > nlbas_random{1, max_blks};

        // we won't be writing more then 128 blocks in one io
        uint32_t attempt{1};
        while (attempt <= 2u) {
            // can not support concurrent overlapping writes if whole data need to be verified
            std::unique_lock< std::mutex > lk{vinfo->vol_mutex};
            if (lba_choice == lbas_choice_t::dont_care) {
                ret.lba = lba_random(engine);
                ret.num_lbas = nlbas_random(engine);
            } else {
                const auto start_lba{(attempt++ == 1u) ? lba_random(engine) : 0};
                std::tie(ret.lba, ret.num_lbas) = vinfo->get_next_valid_lbas(
                    start_lba, 1u, (lba_choice == lbas_choice_t::all_valid) ? nlbas_random(engine) : 1u);
                if ((lba_choice == lbas_choice_t::atleast_one_valid) && (ret.num_lbas)) {
                    ret.num_lbas = nlbas_random(engine);
                    std::uniform_int_distribution< uint32_t > pivot_random{0, ret.num_lbas - 1};
                    const auto pivot{pivot_random(engine)};
                    ret.lba = (ret.lba < pivot) ? 0 : ret.lba - pivot;
                    if ((ret.lba + ret.num_lbas) > vinfo->max_vol_blks) {
                        ret.num_lbas = vinfo->max_vol_blks - ret.lba;
                    }
                }
            }

            // check if someone is already doing writes/reads
            if (!overlapping_allowed && (ret.num_lbas && vinfo->is_lbas_free(ret.lba, ret.num_lbas))) {
                vinfo->mark_lbas_busy(ret.lba, ret.num_lbas);
                if (validate_choice == lba_validate_t::validate) {
                    vinfo->validate_lbas(ret.lba, ret.num_lbas);
                } else if (validate_choice == lba_validate_t::invalidate) {
                    vinfo->invalidate_lbas(ret.lba, ret.num_lbas);
                }
                ret.valid_io = true;
                break;
            } else if (ret.num_lbas && overlapping_allowed) {
                ret.valid_io = true;
                break;
            }
        }

        return ret;
    }

    io_lba_range_t readable_rand_lbas() {
        return do_get_rand_lbas(lbas_choice_t::atleast_one_valid, lba_validate_t::dont_care, tcfg.overlapping_allowed);
    }
    io_lba_range_t writeable_rand_lbas() {
        return do_get_rand_lbas(lbas_choice_t::dont_care, lba_validate_t::validate, tcfg.overlapping_allowed);
    }
    io_lba_range_t unmappable_rand_lbas() {
        return do_get_rand_lbas(lbas_choice_t::atleast_one_valid, lba_validate_t::invalidate, tcfg.overlapping_allowed);
    }

    io_lba_range_t large_unmappable_rand_lbas() {
        static thread_local std::random_device rd{};
        static thread_local std::default_random_engine engine{rd()};
        io_lba_range_t ret;

        // select volume
        const auto vinfo{pick_vol_round_robin(ret)};

        // select lba
        std::uniform_int_distribution< uint64_t > lba_random{0, vinfo->max_vol_blks - 512};
        ret.lba = lba_random(engine);

        // select nlbas
        std::uniform_int_distribution< uint32_t > nlbas_random{512, (uint32_t)(vinfo->max_vol_blks - ret.lba)};
        ret.num_lbas = nlbas_random(engine);
        ret.valid_io = true;
        return ret;
    }

    bool write_io() {
        bool ret{false};
        const IoFuncType write_function{bind_this(IOTestJob::write_vol, 3)};
        switch (m_load_type) {
        case load_type_t::random:
            ret = run_io(bind_this(IOTestJob::writeable_rand_lbas, 0), write_function);
            break;
        case load_type_t::same:
            ret = run_io(bind_this(IOTestJob::same_lbas, 0), write_function);
            break;
        case load_type_t::sequential:
            ret = run_io(bind_this(IOTestJob::seq_lbas, 0), write_function);
            break;
        }
        return ret;
    }

    bool read_io() {
        const IoFuncType read_function{bind_this(IOTestJob::read_vol, 3)};
        bool ret{false};
        switch (m_load_type) {
        case load_type_t::random:
            ret = run_io(bind_this(IOTestJob::readable_rand_lbas, 0), read_function);
            break;
        case load_type_t::same:
            ret = run_io(bind_this(IOTestJob::same_lbas, 0), read_function);
            break;
        case load_type_t::sequential:
            assert(false);
            break;
        }
        return ret;
    }

    bool unmap_io() {
        const IoFuncType unmap_function{bind_this(IOTestJob::unmap_vol, 3)};
        bool ret{false};
        switch (m_load_type) {
        case load_type_t::random:
            ret = run_io(bind_this(IOTestJob::unmappable_rand_lbas, 0), unmap_function);
            if (ret && tcfg.oob_unmap_enable) {
                ret = run_io(bind_this(IOTestJob::large_unmappable_rand_lbas, 0), unmap_function);
            }
            break;
        case load_type_t::same:
            assert(false);
            break;
        case load_type_t::sequential:
            assert(false);
            break;
        }
        return ret;
    }

    bool run_io(const LbaGeneratorType& lba_generator, const IoFuncType& io_function) {
        if (!tcfg.max_vols) { return false; }
        const auto gen_lba{lba_generator()};
        return (gen_lba.valid_io) ? io_function(gen_lba.vol_idx, gen_lba.lba, gen_lba.num_lbas) : false;
    }

    bool write_vol(const uint32_t cur, const uint64_t lba, const uint32_t nlbas) {
        const auto vinfo{m_voltest->m_vol_info[cur]};
        const auto vol{vinfo->vol};
        if (vol == nullptr) { return false; }

        const uint64_t page_size{VolInterface::get_instance()->get_page_size(vol)};
        const uint64_t size{nlbas * page_size};
        boost::intrusive_ptr< io_req_t > vreq{};
        if (tcfg.write_cache) {
            uint8_t* const wbuf{iomanager.iobuf_alloc(512, size)};
            HS_REL_ASSERT_NOTNULL(wbuf);

            populate_buf(wbuf, size, lba, vinfo.get());

            vreq = boost::intrusive_ptr< io_req_t >(
                new io_req_t(vinfo, Op_type::WRITE, wbuf, lba, nlbas, tcfg.verify_csum(), tcfg.write_cache));
        } else {
            static bool send_iovec{true};
            std::vector< iovec > iovecs{};
            if (send_iovec) {
                for (uint32_t lba_num{0}; lba_num < nlbas; ++lba_num) {
                    uint8_t* const wbuf{iomanager.iobuf_alloc(512, page_size)};
                    HS_REL_ASSERT_NOTNULL(wbuf);
                    iovec iov{static_cast< void* >(wbuf), static_cast< size_t >(page_size)};
                    iovecs.emplace_back(std::move(iov));

                    populate_buf(wbuf, page_size, lba + lba_num, vinfo.get());
                }

                vreq = boost::intrusive_ptr< io_req_t >(new io_req_t(vinfo, Op_type::WRITE, std::move(iovecs), lba,
                                                                     nlbas, tcfg.verify_csum(), tcfg.write_cache));
            } else {
                uint8_t* const wbuf{iomanager.iobuf_alloc(512, size)};
                populate_buf(wbuf, size, lba, vinfo.get());
                HS_REL_ASSERT_NOTNULL(wbuf);

                vreq = boost::intrusive_ptr< io_req_t >{
                    new io_req_t(vinfo, Op_type::WRITE, wbuf, lba, nlbas, tcfg.verify_csum(), tcfg.write_cache)};
            }
            send_iovec = !send_iovec;
        }
        vreq->cookie = static_cast< void* >(this);

        ++m_voltest->output.write_cnt;
        ++m_outstanding_ios;
        vinfo->ref_cnt.increment(1);
        const auto ret_io{VolInterface::get_instance()->write(vol, vreq)};
        LOGDEBUG("Wrote lba: {}, nlbas: {} outstanding_ios={}, iovec(s)={}, cache={}", lba, nlbas,
                 m_outstanding_ios.load(), (tcfg.write_iovec != 0 ? true : false),
                 (tcfg.write_cache != 0 ? true : false));
        if (ret_io != no_error) { return false; }
        return true;
    }

    void populate_buf(uint8_t* const buf, const uint64_t size, const uint64_t lba, const vol_info_t* const vinfo) {
        static thread_local std::random_device rd{};
        static thread_local std::default_random_engine engine{rd()};
        static thread_local std::uniform_int_distribution< uint64_t > generator{};

        uint64_t current_lba{lba};
        for (uint64_t write_sz{0}; write_sz < size; write_sz += sizeof(uint64_t)) {
            uint64_t* const write_buf{reinterpret_cast< uint64_t* >(buf + write_sz)};
            if (!(write_sz % tcfg.vol_page_size)) {
                *write_buf = current_lba;
                if (vinfo->vol == nullptr) { return; }
                if (!((write_sz % VolInterface::get_instance()->get_page_size(vinfo->vol)))) { ++current_lba; }
            } else {
                *write_buf = generator(engine);
            }
        }
    }

    bool read_vol(const uint32_t cur, const uint64_t lba, const uint32_t nlbas) {
        const auto vinfo{m_voltest->m_vol_info[cur]};
        const auto vol{vinfo->vol};
        if (vol == nullptr) { return false; }
        if (read_vol_internal(vinfo, vol, lba, nlbas, false)) { return true; }
        return false;
    }

    boost::intrusive_ptr< io_req_t > read_vol_internal(std::shared_ptr< vol_info_t > vinfo, VolumePtr vol,
                                                       const uint64_t lba, const uint32_t nlbas,
                                                       const bool sync = false) {
        const uint64_t page_size{VolInterface::get_instance()->get_page_size(vol)};
        boost::intrusive_ptr< io_req_t > vreq{};
        if (tcfg.read_cache) {
            vreq = boost::intrusive_ptr< io_req_t >{
                new io_req_t{vinfo, Op_type::READ, nullptr, lba, nlbas, tcfg.verify_csum(), tcfg.read_cache, sync}};
        } else {
            static bool send_iovec{true};
            if (send_iovec) {
                std::vector< iovec > iovecs{};
                for (uint32_t lba_num{0}; lba_num < nlbas; ++lba_num) {
                    uint8_t* const rbuf{iomanager.iobuf_alloc(512, page_size)};
                    std::memset(static_cast< void* >(rbuf), 0, page_size);

                    HS_REL_ASSERT_NOTNULL(rbuf);
                    iovec iov{static_cast< void* >(rbuf), static_cast< size_t >(page_size)};
                    iovecs.emplace_back(std::move(iov));
                }

                vreq = boost::intrusive_ptr< io_req_t >{new io_req_t{vinfo, Op_type::READ, std::move(iovecs), lba,
                                                                     nlbas, tcfg.verify_csum(), tcfg.read_cache, sync}};
            } else {
                uint8_t* const rbuf{iomanager.iobuf_alloc(512, nlbas * page_size)};
                std::memset(static_cast< void* >(rbuf), 0, nlbas * page_size);
                vreq = boost::intrusive_ptr< io_req_t >{
                    new io_req_t{vinfo, Op_type::READ, rbuf, lba, nlbas, tcfg.verify_csum(), tcfg.read_cache, sync}};
            }
            send_iovec = !send_iovec;
        }
        vreq->cookie = static_cast< void* >(this);

        ++m_voltest->output.read_cnt;
        ++m_outstanding_ios;
        vinfo->ref_cnt.increment(1);
        const auto ret_io{VolInterface::get_instance()->read(vol, vreq)};
        LOGDEBUG("Read lba: {}, nlbas: {} outstanding_ios={}, iovec(s)={}, cache={}", lba, nlbas,
                 m_outstanding_ios.load(), (tcfg.read_iovec != 0 ? true : false),
                 (tcfg.read_cache != 0 ? true : false));
        if (sync) {
            --m_outstanding_ios;
            vinfo->ref_cnt.decrement(1);
        }
        if (ret_io != no_error) { return nullptr; }
        return vreq;
    }

    bool unmap_vol(const uint32_t cur, const uint64_t lba, const uint32_t nlbas) {
        const auto vinfo{m_voltest->m_vol_info[cur]};
        const auto vol{vinfo->vol};
        if (vol == nullptr) { return false; }

        const auto vreq{boost::intrusive_ptr< io_req_t >{
            new io_req_t(vinfo, Op_type::UNMAP, nullptr, lba, nlbas, tcfg.verify_csum())}};

        vreq->cookie = static_cast< void* >(this);

        ++m_voltest->output.unmap_cnt;
        ++m_outstanding_ios;
        vinfo->ref_cnt.increment(1);
        const auto ret_io{VolInterface::get_instance()->unmap(vol, vreq)};
        LOGDEBUG("Unmapped lba: {}, nlbas: {} outstanding_ios={}, cache={}", lba, nlbas, m_outstanding_ios.load(),
                 (tcfg.write_cache != 0 ? true : false));
        if (ret_io != no_error) { return false; }

        return true;
    }

    bool verify(const boost::intrusive_ptr< io_req_t >& req, const bool can_panic = true) const {
        const auto& vol_req{static_cast< vol_interface_req_ptr >(req)};

        const auto verify_buffer{[this, &req, &can_panic](const uint8_t* const validate_buffer,
                                                          const uint8_t* const data_buffer, const uint64_t data_size,
                                                          const uint64_t total_size_read) {
            bool error{false};
            if (tcfg.verify_csum()) {
                const uint16_t csum1{*reinterpret_cast< const uint16_t* >(validate_buffer)};
                const uint16_t csum2{crc16_t10dif(init_crc_16, data_buffer, data_size)};
                error = (csum1 != csum2);
                if (error) {
                    LOGINFO("checksum mismatch operation {} volume {} lba {} csum1 {} csum2 {}",
                            (req->op_type == Op_type::READ ? "read" : "write"), req->cur_vol, req->lba, csum1, csum2);
                } else {
                    ++m_voltest->output.csum_match_cnt;
                }
            } else if (tcfg.verify_data()) {
                error = ::memcmp(static_cast< const void* >(data_buffer), static_cast< const void* >(validate_buffer),
                                 data_size) != 0;
                if (!error) { ++m_voltest->output.data_match_cnt; }
            } else {
                // we will only verify the header. We write lba number in the header
                const uint64_t validate_lba{req->lba + total_size_read / data_size};
                const uint64_t data_lba{*reinterpret_cast< const uint64_t* >(data_buffer)};
                if ((data_lba == 0) || (validate_lba == data_lba)) {
                    // const auto ret{pwrite(req->fd, data_buffer, data_size, total_size_read +
                    // req->original_offset)}; assert(static_cast<uint64_t>(ret) == data_size);
                } else {
                    LOGINFO("header mismatch operation {} volume {} lba {} header1 {} header2 {}",
                            (req->op_type == Op_type::READ ? "read" : "write"), req->cur_vol, req->lba, validate_lba,
                            data_lba);
                    error = true;
                }

                if (!error) { ++m_voltest->output.hdr_only_match_cnt; }
            }

            if (error) {
                if (can_panic) {
                    if (!tcfg.verify_csum()) {
                        // verify the data
                        error = std::memcmp(static_cast< const void* >(data_buffer),
                                            static_cast< const void* >(validate_buffer), data_size) != 0;
                        if (error) {
                            LOGINFO("data mismatch lba read {}", *reinterpret_cast< const uint64_t* >(data_buffer));
                        }
                    }

                    LOGINFO("mismatch found lba {} nlbas {} total_size_read {}", req->lba, req->nlbas, total_size_read);
#ifndef NDEBUG
                    VolInterface::get_instance()->verify_tree(req->vol_info->vol);
                    VolInterface::get_instance()->print_tree(req->vol_info->vol);
#endif
                    LOGINFO("lba {} {}", req->lba, req->nlbas);
                    // verify is done io is done completion thread which is SPDK thread and can't do sleep
                    // std::this_thread::sleep_for(std::chrono::seconds{30});
                    HS_REL_ASSERT(0, "");
                }
                // need to return false
                return false;
            }

            return true;
        }};

        uint64_t total_size_read{0};
        uint64_t total_size_read_csum{0};
        const uint32_t size_read{tcfg.vol_page_size};
        if (tcfg.read_cache) {
            for (auto& info : vol_req->read_buf_list) {
                uint32_t offset{static_cast< uint32_t >(info.offset)};
                uint64_t size{info.size};
                HS_REL_ASSERT_EQ(size % size_read, 0);
                const auto buf{info.buf};
                while (size != 0) {
                    const sisl::blob b{VolInterface::get_instance()->at_offset(buf, offset)};
                    const uint8_t* const validate_buffer{req->validate_buffer +
                                                         (tcfg.verify_csum() ? total_size_read_csum : total_size_read)};
                    if (!verify_buffer(validate_buffer, b.bytes, size_read, total_size_read)) return false;
                    size -= size_read;
                    offset += size_read;
                    total_size_read += size_read;
                    total_size_read_csum += sizeof(uint16_t);
                }
            }
        } else {
            for (const auto& iov : vol_req->iovecs) {
                uint64_t size{static_cast< uint64_t >(iov.iov_len)};
                uint32_t offset{0};
                HS_REL_ASSERT_EQ(size % size_read, 0);
                while (size != 0) {
                    const uint8_t* const buffer{static_cast< uint8_t* >(iov.iov_base) + offset};
                    const uint8_t* const validate_buffer{req->validate_buffer +
                                                         (tcfg.verify_csum() ? total_size_read_csum : total_size_read)};
                    if (!verify_buffer(validate_buffer, buffer, size_read, total_size_read)) return false;
                    size -= size_read;
                    offset += size_read;
                    total_size_read += size_read;
                    total_size_read_csum += sizeof(uint16_t);
                }
            }
        }
        tcfg.verify_csum() ? (HS_REL_ASSERT_EQ(total_size_read_csum, req->verify_size))
                           : (HS_REL_ASSERT_EQ(total_size_read, req->original_size));
        return true;
    }
};

class VolVerifyJob : public IOTestJob {
public:
    VolVerifyJob(VolTest* test) : IOTestJob(test, load_type_t::sequential) {
        m_start_time = Clock::now();
        LOGINFO("verifying vols");
    }
    virtual ~VolVerifyJob() override = default;
    VolVerifyJob(const VolVerifyJob&) = delete;
    VolVerifyJob(VolVerifyJob&&) noexcept = delete;
    VolVerifyJob& operator=(const VolVerifyJob&) = delete;
    VolVerifyJob& operator=(VolVerifyJob&&) noexcept = delete;

    void run_one_iteration() override {
        for (uint32_t cur{0}; cur < tcfg.max_vols; ++cur) {
            if (!vol_info(cur)) { continue; }
            const uint64_t max_blks{
                (tcfg.max_io_size / VolInterface::get_instance()->get_page_size(vol_info(cur)->vol))};
            for (uint64_t lba{vol_info(cur)->cur_checkpoint}; lba < vol_info(cur)->max_vol_blks;) {
                uint64_t io_size{0};
                if (lba + max_blks > vol_info(cur)->max_vol_blks) {
                    io_size = vol_info(cur)->max_vol_blks - lba;
                } else {
                    io_size = max_blks;
                }
                read_vol(cur, lba, io_size);
                vol_info(cur)->cur_checkpoint = lba + io_size;
                if (m_outstanding_ios > tcfg.max_outstanding_ios) { return; }
                lba = lba + io_size;
            }
        }
        m_is_job_done = true;
    }

    bool time_to_stop() const override { return m_is_job_done; }
    bool is_job_done() const override { return (m_outstanding_ios == 0); }
    bool is_async_job() const override { return true; };
    std::string job_name() const override { return "VerifyJob"; }

private:
    std::shared_ptr< vol_info_t >& vol_info(const uint32_t nth) { return m_voltest->m_vol_info[nth]; }
    bool m_is_job_done{false};
};

std::shared_ptr< IOTestJob > VolTest::start_io_job(const wait_type wait_type, const load_type_t load_type) {
    m_io_job = std::make_shared< IOTestJob >(this, load_type);
    this->start_job(m_io_job.get(), wait_type);
    return m_io_job;
}

thread_local std::list< vol_interface_req_ptr > VolTest::completed_reqs_this_thread{};

/************************** Test cases ****************************/

/*********** Below Tests does IO and exit with clean shutdown *************/

/*!
    @test   lifecycle_test
    @brief  It initialize the homestore, create volume, delete volume and shutdown the system
 */
TEST_F(VolTest, lifecycle_test) {
    this->start_homestore();
    this->start_io_job();
    output.print("lifecycle_test");
#ifdef _PRERELEASE
    FlipClient fc(HomeStoreFlip::instance());
    FlipFrequency freq;
    freq.set_count(10);
    freq.set_percent(100);

    fc.inject_retval_flip("vol_comp_delay_us", {}, freq, 100);
#endif
    this->delete_volumes();

    LOGINFO("All volumes are deleted, do a shutdown of homestore");
    this->shutdown();

    LOGINFO("Shutdown of homestore is completed, removing files");
    if (tcfg.remove_file_on_shutdown) { this->remove_files(); }
}

/// @brief : create vol with same uuid that is pending on destroy
///
/// @param VolTest
/// @param del_create_same_uuid_vol
TEST_F(VolTest, del_and_create_same_uuid_vol) {
    this->start_homestore();
    this->start_io_job();
    output.print("del_and_create_same_uuid_vol");

    this->delete_and_create_same_uuid_vol();

    LOGINFO("All volumes are deleted, do a shutdown of homestore");
    this->shutdown();

    LOGINFO("Shutdown of homestore is completed, removing files");
    if (tcfg.remove_file_on_shutdown) { this->remove_files(); }
}

/*
 * NOTE: This test case only works when fault_containment goes into offline, instead of assert fail;
 * */
TEST_F(VolTest, vol_crc_mismatch_test) {
#ifdef _PRERELEASE
    FlipClient* const fc{HomeStoreFlip::client_instance()};
    FlipFrequency freq;
    FlipCondition null_cond;
    fc->create_condition("", flip::Operator::DONT_CARE, (int)1, &null_cond);
    freq.set_count(20);
    freq.set_percent(100);
    fc->inject_noreturn_flip("vol_crc_mismatch", {null_cond}, freq);
#endif
    this->start_homestore();
    this->start_io_job();
    tcfg.expect_vol_offline = true;
    output.print("vol_crc_mismatch_test");

    this->delete_volumes();

    LOGINFO("All volumes are deleted, do a shutdown of homestore");
    this->shutdown();

    LOGINFO("Shutdown of homestore is completed, removing files");
    if (tcfg.remove_file_on_shutdown) { this->remove_files(); }
    tcfg.expect_vol_offline = false;
}

/*!
    @test   init_io_test
    @brief  It initialize the homestore, create volume and
            shutdown the system
 */
TEST_F(VolTest, init_io_test) {
    this->start_homestore();

#ifdef _PRERELEASE
    FlipClient fc{HomeStoreFlip::instance()};
    FlipFrequency freq;
    freq.set_count(10);
    freq.set_percent(100);

    fc.inject_retval_flip(tcfg.flip_name, {}, freq, 100);
#endif

    std::unique_ptr< VolCreateDeleteJob > cdjob;
    if (tcfg.create_del_with_io || tcfg.delete_with_io) {
        cdjob = std::make_unique< VolCreateDeleteJob >(this);
        this->start_job(cdjob.get(), wait_type::no_wait);
    }

    this->start_io_job();
    output.print("init_io_test");

    if (tcfg.create_del_with_io || tcfg.delete_with_io) { cdjob->wait_for_completion(); }

    this->shutdown();
    if (tcfg.remove_file_on_shutdown) { this->remove_files(); }
}

/*!
    @test   recovery_io_test
    @brief  Tests which does recovery. End up with a clean shutdown
 */
TEST_F(VolTest, recovery_io_test) {
    tcfg.init = false;
    this->start_homestore(false /* force_reinit */);

    LOGINFO("recovery verify started");
    std::unique_ptr< VolVerifyJob > verify_job;
    if (tcfg.pre_init_verify || tcfg.verify_only) {
        verify_job = std::make_unique< VolVerifyJob >(this);
        this->start_job(verify_job.get(), wait_type::for_completion);
        LOGINFO("recovery verify done");
    } else {
        LOGINFO("bypassing recovery verify");
    }

    std::unique_ptr< VolCreateDeleteJob > cdjob;
    if (tcfg.create_del_with_io || tcfg.delete_with_io) {
        cdjob = std::make_unique< VolCreateDeleteJob >(this);
        this->start_job(cdjob.get(), wait_type::no_wait);
    }

    this->start_io_job();
    output.print("recovery_io_test");

    if (tcfg.create_del_with_io || tcfg.delete_with_io) { cdjob->wait_for_completion(); }

    if (tcfg.can_delete_volume) { this->delete_volumes(); }
    this->shutdown();
    if (tcfg.remove_file_on_shutdown) { this->remove_files(); }
}

/*!
    @test   recovery_boot_test
    @brief  Tests which does recovery. End up with a clean shutdown
    This test doesn't do any io to volume;
 */
TEST_F(VolTest, recovery_boot_test) {
    const auto start_time(Clock::now());
    tcfg.init = false;
    this->start_homestore(false /* force_reinit */);

    LOGINFO("recovery verify started");
    std::unique_ptr< VolVerifyJob > verify_job;
    if (tcfg.pre_init_verify || tcfg.verify_only) {
        verify_job = std::make_unique< VolVerifyJob >(this);
        this->start_job(verify_job.get(), wait_type::for_completion);
        LOGINFO("recovery verify done");
    } else {
        LOGINFO("bypassing recovery verify");
    }

    while ((get_elapsed_time_sec(start_time) < tcfg.run_time)) {
        std::this_thread::sleep_for(std::chrono::seconds{2});
    }

    if (tcfg.can_delete_volume) { this->delete_volumes(); }
    this->shutdown();
    if (tcfg.remove_file_on_shutdown) { this->remove_files(); }
}

/*!
    @test   recovery_boot_btree_node_pagination_test
    @brief  Tests which does recovery. End up with a clean shutdown
    This test doesn't do any io to volume;
 */
TEST_F(VolTest, recovery_boot_btree_node_pagination_test) {
    const auto start_time(Clock::now());
    tcfg.init = false;
    this->start_homestore(false /* force_reinit */);

    LOGINFO("recovery verify started");
    std::unique_ptr< VolVerifyJob > verify_job;
    if (tcfg.pre_init_verify || tcfg.verify_only) {
        verify_job = std::make_unique< VolVerifyJob >(this);
        this->start_job(verify_job.get(), wait_type::for_completion);
        LOGINFO("recovery verify done");
    } else {
        LOGINFO("bypassing recovery verify");
    }

    LOGINFO("Starting btree leaf node pagination.");

    sisl::status_request status_req;
    status_req.obj_type = "btree_node";
    status_req.obj_name = "btree_node_test_files/vol0";

    const auto sobject_mgr = HomeStoreBase::safe_instance()->sobject_mgr();
    while (true) {
        const auto status_resp = sobject_mgr->get_status(status_req);
        if (status_resp.json.contains("error")) {
            HS_DBG_ASSERT(false, "get_status returned error: {}", status_resp.json.dump(2));
        } else {
            LOGINFO("get_status return successfully: {}", status_resp.json.dump(2));
        }

        if (status_resp.json["has_more"] == "true") {
            status_req.next_cursor = status_resp.json["next_cursor"].get< std::string >();
            LOGINFO("more leaf nodes to get, next_cursor: {}", status_req.next_cursor);
        } else {
            LOGINFO("no more leaf node. ");
            break;
        }
    }

    if (tcfg.can_delete_volume) { this->delete_volumes(); }
    this->shutdown();
    if (tcfg.remove_file_on_shutdown) { this->remove_files(); }
}

/*!
    @test   recovery_boot_copy_vol_test
    @brief  Tests which does recovery. End up with a clean shutdown
    This test doesn't do any io to volume;
 */
TEST_F(VolTest, recovery_boot_copy_vol_test) {
    const auto start_time(Clock::now());
    tcfg.init = false;
    this->start_homestore(false /* force_reinit */);

    LOGINFO("recovery verify started");
    std::unique_ptr< VolVerifyJob > verify_job;
    if (tcfg.pre_init_verify || tcfg.verify_only) {
        verify_job = std::make_unique< VolVerifyJob >(this);
        this->start_job(verify_job.get(), wait_type::for_completion);
        LOGINFO("recovery verify done");
    } else {
        LOGINFO("bypassing recovery verify");
    }

    LOGINFO("Starting to verify dumpped files with saved vol file with crc checksum");

    HS_REL_ASSERT_EQ(m_vol_info.empty(), false);

    // use real vol uuid and faked partition info
    const auto file_path =
        "./test_files/" + boost::uuids::to_string(m_vol_info[0]->uuid) + "_p_" + "137_sds_tess86_01_am02";

    // copy vol
    VolInterface::get_instance()->copy_vol(m_vol_info[0]->uuid, file_path);

    // verify copied vol;
    // make sure everything we wrote to vol file matches the crc we saved on crc_vol_file;
    verify_vol(file_path);
    // make sure everything we wrote on crc_vol_file also matches the data we wrote on copied vol file,
    // it is required to make sure the copied file doesn't miss anything data;
    reverse_verify_vol(file_path);

    if (tcfg.can_delete_volume) { this->delete_volumes(); }
    this->shutdown();
    if (tcfg.remove_file_on_shutdown) { this->remove_files(); }
}

#ifdef _PRERELEASE
/*
 * @test    hs_force_reinit_test only works in PRERELEASE mode;
 * @brief   This test cases works with force_reinit field in input_params which is only valid in PRERELEASE mode;
 * if not in PRERELEASE mode, assert for first_time_boot will fail in init_done_cb
 * */
TEST_F(VolTest, hs_force_reinit_test) {
    output.print("hs_force_reinit_test");

    tcfg.init = true; // so that we can assert first time boot in init_done_cb

    // 1. set input params with force_reinit;
    // 2. boot homestore which should be first-time-boot
    this->start_homestore();

    // 3. verify it is first time boot which is done in init_done_cb

    if (tcfg.can_delete_volume) { this->delete_volumes(); }
    this->shutdown();
    if (tcfg.remove_file_on_shutdown) { this->remove_files(); }
}
#endif

#if 0
/*!
    @test   hs_force_reinit_test works as always (not depend on force_reinit field)
    @brief  Tests force reinit to boot as first time boot;
    This test case is supposed to be called after init_io_test.
    It can also be run standalone.
    The expected result is it will always boot as first time boot;
 */
TEST_F(VolTest, hs_force_reinit_test) {
    output.print("hs_force_reinit_test");

    // 1. first calling init_done to zero sb on physical device_boot_fail
    std::vector< dev_info > tmp_data_dev_info, tmp_fast_dev_info;
    get_dev_info(tmp_dev_info);
    HS_REL_ASSERT_GT(tmp_dev_info.size(), 0);

    this->force_reinit(tmp_dev_info, homestore::io_flag::DIRECT_IO,
                       tmp_fast_dev_info, homestore::io_flag::DIRECT_IO);

    // 2. boot homestore which should be first-time-boot
    this->start_homestore();

    // 3. verify it is first time boot which is done in init_done_cb;

    if (tcfg.can_delete_volume) { this->delete_volumes(); }
    this->shutdown();
    if (tcfg.remove_file_on_shutdown) { this->remove_files(); }
}
#endif

/*!
    @test   vol_create_del_test
    @brief  Below tests delete volumes. Should exit with clean shutdown.
 */
TEST_F(VolTest, vol_create_del_test) {
    tcfg.precreate_volume = false;
    this->start_homestore();

    auto cdjob{std::make_unique< VolCreateDeleteJob >(this)};
    this->start_job(cdjob.get(), wait_type::for_completion);
    output.print("vol_create_del_test");
    this->shutdown();
    if (tcfg.remove_file_on_shutdown) { this->remove_files(); }
}

/************ Below tests check the workflows ***********/

TEST_F(VolTest, one_disk_fail_test) {
#ifdef _PRERELEASE
    FlipClient fc{HomeStoreFlip::instance()};
    FlipFrequency freq;
    FlipCondition cond1;
    FlipCondition cond2;
    freq.set_count(100);
    freq.set_percent(100);
    fc.create_condition("setting error on file1", flip::Operator::EQUAL, tcfg.default_names[0], &cond1);
    fc.inject_noreturn_flip("device_boot_fail", {cond1}, freq);
#endif
    tcfg.init = false;
    tcfg.expected_init_fail = true;
    this->start_homestore();
    this->start_io_job();

    output.print("one_disk_fail_test");
    this->shutdown();
    if (tcfg.remove_file_on_shutdown) { this->remove_files(); }
}

TEST_F(VolTest, vol_offline_test) {
    tcfg.expected_vol_state = vol_state::OFFLINE;
    this->start_homestore();

    tcfg.expect_io_error = true;
    auto job = this->start_io_job(wait_type::no_wait);
    this->move_vol_to_offline();
    job->wait_for_completion();
    this->shutdown();
}

/**
 * @brief :
 * Test Procedure:
 * 1. start homesotre and do I/Os;
 * 2. wait I/O completed
 * 3. move all volumes to offline state;
 * 4. inject flip point for read btree node to return failure.
 * 5. start btree fix and it should return failure as expected, instead of core dump or crash;
 * 6. delete volumes and shotdown homesotre;
 *
 * @param VolTest
 * @param btree_fix_read_failure_test
 */
TEST_F(VolTest, btree_fix_read_failure_test) {
    this->start_homestore();
    this->start_io_job(wait_type::for_completion);
    output.print("btree_fix_read_failure_test");

    this->move_vol_to_offline();
#ifdef _PRERELEASE
    FlipClient* const fc{homestore::HomeStoreFlip::client_instance()};
    FlipFrequency freq;
    freq.set_count(2000000000);
    freq.set_percent(1);

    FlipCondition null_cond;
    fc->create_condition("", flip::Operator::DONT_CARE, (int)1, &null_cond);

    fc->inject_noreturn_flip("btree_read_fail", {null_cond}, freq);
#endif
    auto ret = this->fix_vol_mapping_btree();
    EXPECT_EQ(ret, false);

    this->delete_volumes();
    this->shutdown();
    if (tcfg.remove_file_on_shutdown) { this->remove_files(); }
}

/**
 * @brief :
 * Test Procedure :
 * 1. Start homestore and do customized IO based on input parameter
 * 2. wait I/O completed
 * 3. move all volumes to offline state;
 * 4. start btree fix (with verify set to true) on every volume and expect it to be successfully completed.
 * 5. verify KVs between newly created btree and old btree should also return successfully;
 * 6. delete volumes and shotdown homestore;
 *
 * @param VolTest
 * @param btree_fix_test
 */
TEST_F(VolTest, btree_fix_test) {
    this->start_homestore();
    this->start_io_job(wait_type::for_completion);
    output.print("btree_fix_test");

    this->move_vol_to_offline();
    auto ret = this->fix_vol_mapping_btree();
    EXPECT_EQ(ret, true);

    this->delete_volumes();
    this->shutdown();
    if (tcfg.remove_file_on_shutdown) { this->remove_files(); }
}

/**
 * @brief :
 * Test Procedure :
 * 1. Start homestore and do customerized IO based on input parameter
 * 2. wait I/O completed
 * 3. move all volumes to offline state;
 * 4. start btree fix (with verify set to true) on every volume and expect it to be successfully completed.
 * 5. verify KVs between newly created btree and old btree should also return successfully;
 * 6. move volume back online.
 * 7. start I/O on volumes and wait I/O completed
 * 8. delete all volumes and shutdown homestore and exit;
 *
 * @param VolTest
 * @param btree_fix_test
 */
TEST_F(VolTest, btree_fix_rerun_io_test) {
    this->start_homestore();
    this->start_io_job(wait_type::for_completion);
    output.print("btree_fix_rerun_io_test");

    this->move_vol_to_offline();
    auto ret = this->fix_vol_mapping_btree();
    EXPECT_EQ(ret, true);

    output.write_cnt = 0;
    output.read_cnt = 0;
    output.unmap_cnt = 0;
    this->move_vol_to_online();
    this->start_io_job(wait_type::for_execution);
    output.print("btree_fix_rerun_io_test");

    if (tcfg.can_delete_volume) { this->delete_volumes(); }
    this->shutdown();
    if (tcfg.remove_file_on_shutdown) { this->remove_files(); }
}

std::vector< module_test* > mod_tests;
void indx_mgr_test_main();
void meta_mod_test_main();
void vdev_mod_test_main();
std::vector< std::function< void() > > mod_init_funcs;

/************************* CLI options ***************************/

SISL_OPTION_GROUP(
    test_volume,
    (run_time, "", "run_time", "run time for io", ::cxxopts::value< uint32_t >()->default_value("30"), "seconds"),
    (load_type, "", "load_type", "load_type", ::cxxopts::value< uint32_t >()->default_value("0"),
     "random_write_read:0, same_write_read:1, seq_write:2"),
    (nblks, "", "nblks", "nblks", ::cxxopts::value< uint32_t >()->default_value("100"),
     "number of blks to write when load_type is same"),
    (overlapping_allowed, "", "overlapping_allowed", "overlapping_allowed",
     ::cxxopts::value< bool >()->default_value("false"), "true or false"),
    (num_threads, "", "num_threads", "num_threads - default 2 for spdk and 8 for non-spdk",
     ::cxxopts::value< uint32_t >()->default_value("8"), "number"),
    (read_enable, "", "read_enable", "read enable 0 or 1", ::cxxopts::value< uint32_t >()->default_value("1"), "flag"),
    (unmap_enable, "", "unmap_enable", "unmap enable 0 or 1", ::cxxopts::value< uint32_t >()->default_value("0"),
     "flag"),
    (oob_unmap_enable, "", "oob_unmap_enable", "out-of-band unmap enable 0 or 1",
     ::cxxopts::value< uint32_t >()->default_value("0"), "flag"),
    (max_disk_capacity, "", "max_disk_capacity", "max disk capacity",
     ::cxxopts::value< uint64_t >()->default_value("10"), "GB"),
    (max_volume, "", "max_volume", "max volume", ::cxxopts::value< uint64_t >()->default_value("50"), "number"),
    (max_num_writes, "", "max_num_writes", "max num of writes", ::cxxopts::value< uint64_t >()->default_value("100000"),
     "number"),
    (verify_type, "", "verify_type", "verify type", ::cxxopts::value< uint32_t >()->default_value("0"),
     "csum:0, data:1, header:2, null:3"),
    (read_verify, "", "read_verify", "read verification for each write",
     ::cxxopts::value< uint64_t >()->default_value("0"), "0 or 1"),
    (enable_crash_handler, "", "enable_crash_handler", "enable crash handler 0 or 1",
     ::cxxopts::value< uint32_t >()->default_value("1"), "flag"),
    (remove_file_on_shutdown, "", "remove_file_on_shutdown", "remove file at the end of test 0 or 1",
     ::cxxopts::value< uint32_t >()->default_value("1"), "flag"), // remove file on shutdown
    (remove_file_on_start, "", "remove_file_on_start", "remove file at the start of test 0 or 1",
     ::cxxopts::value< uint32_t >()->default_value("0"),
     "flag"), // by default (0) we keep the file on disk unless the test specifically ask to remove, some tests rely on
              // previously generated vol files to run;
    (expected_vol_state, "", "expected_vol_state", "volume state expected during boot",
     ::cxxopts::value< uint32_t >()->default_value("0"), "flag"),
    (verify_only, "", "verify_only", "verify only boot", ::cxxopts::value< uint32_t >()->default_value("0"), "flag"),
    (pre_init_verify, "", "pre_init_verify", "pre_init_verify", ::cxxopts::value< bool >()->default_value("true"),
     "validate data before starting io"),
    (abort, "", "abort", "abort", ::cxxopts::value< uint32_t >()->default_value("0"), "flag"),
    (flip, "", "flip", "flip", ::cxxopts::value< uint32_t >()->default_value("0"), "flag"),
    (flip_name, "", "flip_name", "list of flips", ::cxxopts::value< std::string >()->default_value(""), "flip_name"),
    (delete_volume, "", "delete_volume", "delete_volume", ::cxxopts::value< uint32_t >()->default_value("0"), "flag"),
    (atomic_phys_page_size, "", "atomic_phys_page_size", "atomic_phys_page_size",
     ::cxxopts::value< uint32_t >()->default_value("4096"), "atomic_phys_page_size"),
    (vol_page_size, "", "vol_page_size", "vol_page_size", ::cxxopts::value< uint32_t >()->default_value("4096"),
     "vol_page_size"),
    (device_list, "", "device_list", "List of device paths", ::cxxopts::value< std::vector< std::string > >(),
     "path [...]"),
    (mod_list, "", "mod_list", "List of modules to be enbaled for test",
     ::cxxopts::value< std::vector< std::string > >(), "mod [...]"),
    (phy_page_size, "", "phy_page_size", "phy_page_size", ::cxxopts::value< uint32_t >()->default_value("4096"),
     "phy_page_size"),
    (io_flags, "", "io_flags", "io_flags", ::cxxopts::value< uint32_t >()->default_value("1"), "0 or 1"),
    (mem_btree_page_size, "", "mem_btree_page_size", "mem_btree_page_size",
     ::cxxopts::value< uint32_t >()->default_value("8192"), "mem_btree_page_size"),
    (expect_io_error, "", "expect_io_error", "expect_io_error", ::cxxopts::value< uint32_t >()->default_value("0"),
     "0 or 1"),
    (p_volume_size, "", "p_volume_size", "percentage of volume size that should take from maximum disk capacity",
     ::cxxopts::value< uint32_t >()->default_value("60"), "0 to 200"),
    (write_cache, "", "write_cache", "write cache", ::cxxopts::value< uint32_t >()->default_value("0"), "flag"),
    (read_cache, "", "read_cache", "read cache", ::cxxopts::value< uint32_t >()->default_value("0"), "flag"),
    (write_iovec, "", "write_iovec", "write iovec(s)", ::cxxopts::value< uint32_t >()->default_value("0"), "flag"),
    (read_iovec, "", "read_iovec", "read iovec(s)", ::cxxopts::value< uint32_t >()->default_value("0"), "flag"),
    (batch_completion, "", "batch_completion", "batch completion", ::cxxopts::value< bool >()->default_value("false"),
     "true or false"),
    (spdk, "", "spdk", "spdk", ::cxxopts::value< bool >()->default_value("false"), "true or false"),
    (vol_create_del, "", "vol_create_del", "vol_create_del", ::cxxopts::value< bool >()->default_value("false"),
     "true or false"),
    (create_del_with_io, "", "create_del_with_io", "create_del_with_io",
     ::cxxopts::value< bool >()->default_value("false"), "true or false"),
    (delete_with_io, "", "delete_with_io", "delete_with_io", ::cxxopts::value< bool >()->default_value("false"),
     "true or false"),
    (create_del_ops_cnt, "", "create_del_ops_cnt", "create_del_ops_cnt",
     ::cxxopts::value< uint32_t >()->default_value("100"), "number of ops"),
    (create_del_ops_interval, "", "create_del_ops_interval", "create_del_ops_interval",
     ::cxxopts::value< uint32_t >()->default_value("10"), "interval between create del in seconds"),
    (emulate_hdd_cnt, "", "emulate_hdd_cnt", "emulate_hdd_cnt", ::cxxopts::value< uint32_t >()->default_value("0"),
     "number of files or drives to be emulated as hdd"),
    (http_port, "", "http_port", "http_port", ::cxxopts::value< uint32_t >()->default_value("5000"),
     "http server port"),
    (emulate_hdd_stream_cnt, "", "emulate_hdd_stream_cnt", "emulate_hdd_stream_cnt",
     ::cxxopts::value< uint32_t >()->default_value("20"), "number of streams for each emulated hdd"),
    (p_vol_files_space, "", "p_vol_files_space",
     "percentage of volume verficiation files of available free space on hosting file system",
     ::cxxopts::value< uint32_t >()->default_value("30"), "0 to 100"),
    (app_mem_size_in_gb, "", "app_mem_size_in_gb", "cache size in gb",
     ::cxxopts::value< uint32_t >()->default_value("1"), "1 to 5"),
    (max_io_size, "", "max_io_size", "max io size", ::cxxopts::value< uint64_t >()->default_value("4096"),
     "max_io_size"),
    (io_size, "", "io_size", "io size in KB", ::cxxopts::value< uint32_t >()->default_value("4"), "io_size"),
    (vol_copy_file_path, "", "vol_copy_file_path", "file path for copied volume",
     ::cxxopts::value< std::string >()->default_value(""), "path [...]"),
    (unmap_frequency, "", "unmap_frequency", "do unmap for every N",
     ::cxxopts::value< uint64_t >()->default_value("100"), "unmap_frequency"))

#define ENABLED_OPTIONS logging, test_volume, iomgr, test_indx_mgr, test_meta_mod, test_vdev_mod, config

SISL_OPTIONS_ENABLE(ENABLED_OPTIONS)

/************************** MAIN ********************************/

/* We can run this target either by using default options which run the normal io tests or by setting different
 * options. Format is
 *   1. ./test_volume
 *   2. ./test_volume --gtest_filter=*recovery* --run_time=120 --num_threads=16 --max_disk_capacity=10
 * --max_volume=50 Above command run all tests having a recovery keyword for 120 seconds with 16 threads , 10g
 * disk capacity and 50 volumes
 *
 *   * Sequential 64KB write work load, read is disabled
 *   3. ./test_volume --load_type=2 --read_enable=0  --io_size=64 --max_volume=1 --p_volume_size=20   // <<< if want to
 * only create one volume with specific size, use needs to specify p_volume_size;
 */
int main(int argc, char* argv[]) {
    ::testing::GTEST_FLAG(filter) = "*lifecycle_test*";
    ::testing::InitGoogleTest(&argc, argv);
    SISL_OPTIONS_LOAD(argc, argv, ENABLED_OPTIONS)
    sisl::logging::SetLogger("test_volume");
    spdlog::set_pattern("[%D %T.%f] [%^%L%$] [%t] %v");
    homestore::vol_test_run = true;

    TestCfg& gcfg{const_cast< TestCfg& >(g_cfg)};
    gcfg.run_time = SISL_OPTIONS["run_time"].as< uint32_t >();
    gcfg.num_threads = SISL_OPTIONS["num_threads"].as< uint32_t >();
    gcfg.read_enable = SISL_OPTIONS["read_enable"].as< uint32_t >();
    gcfg.unmap_enable = SISL_OPTIONS["unmap_enable"].as< uint32_t >();
    gcfg.oob_unmap_enable = SISL_OPTIONS["oob_unmap_enable"].as< uint32_t >();
    gcfg.unmap_frequency = SISL_OPTIONS["unmap_frequency"].as< uint64_t >();
    gcfg.max_disk_capacity = ((SISL_OPTIONS["max_disk_capacity"].as< uint64_t >()) * (1ul << 30));
    gcfg.max_vols = SISL_OPTIONS["max_volume"].as< uint64_t >();
    gcfg.max_num_writes = SISL_OPTIONS["max_num_writes"].as< uint64_t >();
    gcfg.enable_crash_handler = SISL_OPTIONS["enable_crash_handler"].as< uint32_t >();
    gcfg.verify_type = static_cast< verify_type_t >(SISL_OPTIONS["verify_type"].as< uint32_t >());
    gcfg.pre_init_verify = SISL_OPTIONS["pre_init_verify"].as< bool >();
    gcfg.read_verify = SISL_OPTIONS["read_verify"].as< uint64_t >() ? true : false;
    gcfg.load_type = static_cast< load_type_t >(SISL_OPTIONS["load_type"].as< uint32_t >());
    gcfg.remove_file_on_shutdown = SISL_OPTIONS["remove_file_on_shutdown"].as< uint32_t >();
    gcfg.remove_file_on_start = SISL_OPTIONS["remove_file_on_start"].as< uint32_t >();
    gcfg.expected_vol_state = static_cast< homestore::vol_state >(SISL_OPTIONS["expected_vol_state"].as< uint32_t >());
    gcfg.verify_only = SISL_OPTIONS["verify_only"].as< uint32_t >();
    gcfg.is_abort = SISL_OPTIONS["abort"].as< uint32_t >();
    gcfg.flip_set = SISL_OPTIONS["flip"].as< uint32_t >();
    gcfg.can_delete_volume = SISL_OPTIONS["delete_volume"].as< uint32_t >() ? true : false;
    gcfg.atomic_phys_page_size = SISL_OPTIONS["atomic_phys_page_size"].as< uint32_t >();
    gcfg.vol_page_size = SISL_OPTIONS["vol_page_size"].as< uint32_t >();
    gcfg.phy_page_size = SISL_OPTIONS["phy_page_size"].as< uint32_t >();
    gcfg.mem_btree_page_size = SISL_OPTIONS["mem_btree_page_size"].as< uint32_t >();
    gcfg.io_flags = static_cast< io_flag >(SISL_OPTIONS["io_flags"].as< uint32_t >());
    gcfg.expect_io_error = SISL_OPTIONS["expect_io_error"].as< uint32_t >() ? true : false;
    gcfg.p_volume_size = SISL_OPTIONS["p_volume_size"].as< uint32_t >();
    gcfg.is_spdk = SISL_OPTIONS["spdk"].as< bool >();
    gcfg.read_cache = SISL_OPTIONS["read_cache"].as< uint32_t >() != 0 ? true : false;
    gcfg.write_cache = SISL_OPTIONS["write_cache"].as< uint32_t >() != 0 ? true : false;
    gcfg.read_iovec = SISL_OPTIONS["read_iovec"].as< uint32_t >() != 0 ? true : false;
    gcfg.write_iovec = SISL_OPTIONS["write_iovec"].as< uint32_t >() != 0 ? true : false;
    gcfg.batch_completion = SISL_OPTIONS["batch_completion"].as< bool >();
    gcfg.vol_create_del = SISL_OPTIONS["vol_create_del"].as< bool >();
    gcfg.create_del_with_io = SISL_OPTIONS["create_del_with_io"].as< bool >();
    gcfg.delete_with_io = SISL_OPTIONS["delete_with_io"].as< bool >();
    gcfg.create_del_ops_cnt = SISL_OPTIONS["create_del_ops_cnt"].as< uint32_t >();
    gcfg.create_del_ops_interval = SISL_OPTIONS["create_del_ops_interval"].as< uint32_t >();
    gcfg.flip_name = SISL_OPTIONS["flip_name"].as< std::string >();
    gcfg.overlapping_allowed = SISL_OPTIONS["overlapping_allowed"].as< bool >();
    gcfg.emulate_hdd_cnt = SISL_OPTIONS["emulate_hdd_cnt"].as< uint32_t >();
    gcfg.emulate_hdd_stream_cnt = SISL_OPTIONS["emulate_hdd_stream_cnt"].as< uint32_t >();
    gcfg.p_vol_files_space = SISL_OPTIONS["p_vol_files_space"].as< uint32_t >();
    gcfg.app_mem_size_in_gb = SISL_OPTIONS["app_mem_size_in_gb"].as< uint32_t >();
    gcfg.vol_copy_file_path = SISL_OPTIONS["vol_copy_file_path"].as< std::string >();
    const auto io_size_in_kb = SISL_OPTIONS["io_size"].as< uint32_t >();
    gcfg.io_size = io_size_in_kb * 1024;

    HS_REL_ASSERT(io_size_in_kb && (io_size_in_kb % 4 == 0),
                  "input io_size (in KB): {} should not be zero and be 4 aligned.", io_size_in_kb);

    if (SISL_OPTIONS.count("device_list")) {
        gcfg.dev_names = SISL_OPTIONS["device_list"].as< std::vector< std::string > >();
        std::string dev_list_str;
        for (const auto& d : gcfg.dev_names) {
            dev_list_str += d;
        }
        LOGINFO("Taking input dev_list: {}", dev_list_str);
    }

    if (SISL_OPTIONS.count("mod_list")) {
        // currently we should only have use-case for one module enabled concurrently,
        // but this framework allows user to enable multiple;
        gcfg.mod_list = SISL_OPTIONS["mod_list"].as< std::vector< std::string > >();
        for (size_t i{0}; i < gcfg.mod_list.size(); ++i) {
            if (gcfg.mod_list[i] == "meta") {
                mod_init_funcs.push_back(meta_mod_test_main);
            } else if (gcfg.mod_list[i] == "index") {
                mod_init_funcs.push_back(indx_mgr_test_main);
            } else if (gcfg.mod_list[i] == "vdev") {
                mod_init_funcs.push_back(vdev_mod_test_main);
            } else {
                LOGERROR("Unsported mod_list: {}, supported list: [ index | meta | vdev ]", gcfg.mod_list[i]);
                return 1;
            }
        }

        // log a warning messaeg if more than one module enabled is really what user wants.
        if (mod_init_funcs.size() > 1) { LOGWARN("User want more than one module enabled for testing!"); }
    }

    if ((gcfg.load_type == load_type_t::sequential) || (gcfg.load_type == load_type_t::same)) {
        gcfg.verify_type = verify_type_t::null;
        if (gcfg.load_type == load_type_t::same) { gcfg.nblks = SISL_OPTIONS["nblks"].as< uint32_t >(); }
    }

    if (gcfg.overlapping_allowed) { gcfg.verify_type = verify_type_t::header; }

    if (gcfg.enable_crash_handler) { sisl::logging::install_crash_handler(); }

    // TODO: Remove this once we found the root cause of the problem.
    sisl::logging::SetModuleLogLevel("transient", spdlog::level::debug);

    /* if --spdk is not set, check env variable if user want to run spdk */
    if (!gcfg.is_spdk && std::getenv(SPDK_ENV_VAR_STRING.c_str())) { gcfg.is_spdk = true; }

    if (gcfg.is_spdk) {
        gcfg.read_iovec = true;
        gcfg.write_iovec = true;
        gcfg.batch_completion = false;
    }

    if (gcfg.is_spdk && gcfg.num_threads > 2) {
        gcfg.num_threads = 2;
    } /* default to 2 to avoid high cpu usage with spdk */

    LOGINFO("Testing with vol_gtest with gcfg spdk: {}, nthreads: {}", gcfg.is_spdk, gcfg.num_threads);

    for (size_t i{0}; i < mod_init_funcs.size(); ++i) {
        mod_init_funcs[i]();
    }

    MetaBlkMgrSI()->register_handler(access_mgr_mtype, VolTest::am_meta_blk_found_cb, VolTest::am_meta_blk_comp_cb,
                                     true);

    const auto ret{RUN_ALL_TESTS()};
    return ret;
}
