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
/*
 * Homestore testing binaries shared common definitions, apis and data structures
 *
 */

#pragma once
#include <sisl/logging/logging.h>
#include <sisl/options/options.h>
#include <sisl/settings/settings.hpp>
#include <iomgr/io_environment.hpp>
#include <iomgr/iomgr_flip.hpp>
#include <homestore/homestore.hpp>
#include <homestore/index_service.hpp>
#include <homestore/replication_service.hpp>
#include <homestore/checkpoint/cp_mgr.hpp>
#include <device/hs_super_blk.h>
#include <iomgr/iomgr_config_generated.h>
#include <common/homestore_assert.hpp>
#include <iomgr/http_server.hpp>

#ifdef _PRERELEASE
#include "common/crash_simulator.hpp"
#endif

const std::string SPDK_ENV_VAR_STRING{"USER_WANT_SPDK"};
const std::string HTTP_SVC_ENV_VAR_STRING{"USER_WANT_HTTP_OFF"};
const std::string CP_WATCHDOG_TIMER_SEC{"USER_SET_CP_WD_TMR_SEC"};          // used in nightly test;
const std::string FLIP_SLOW_PATH_EVERY_NTH{"USER_SET_SLOW_PATH_EVERY_NTH"}; // used in nightly test;
const std::string BLKSTORE_FORMAT_OFF{"USER_WANT_BLKSTORE_FORMAT_OFF"};     // used for debug purpose;
const std::string USER_WANT_DIRECT_IO{"USER_WANT_DIRECT_IO"};               // used for HDD direct io mode;

SISL_OPTION_GROUP(
    test_common_setup,
    (num_threads, "", "num_threads", "number of threads", ::cxxopts::value< uint32_t >()->default_value("2"), "number"),
    (num_fibers, "", "num_fibers", "number of fibers per thread", ::cxxopts::value< uint32_t >()->default_value("2"),
     "number"),
    (num_devs, "", "num_devs", "number of devices to create", ::cxxopts::value< uint32_t >()->default_value("3"),
     "number"),
    (dev_size_mb, "", "dev_size_mb", "size of each device in MB", ::cxxopts::value< uint64_t >()->default_value("2048"),
     "number"),
    (device_list, "", "device_list", "Device List instead of default created",
     ::cxxopts::value< std::vector< std::string > >(), "path [...]"),
    (http_port, "", "http_port", "http port (0 for no http, -1 for random, rest specific value)",
     ::cxxopts::value< int >()->default_value("-1"), "number"),
    (num_io, "", "num_io", "number of IO operations", ::cxxopts::value< uint64_t >()->default_value("300"), "number"),
    (qdepth, "", "qdepth", "Max outstanding operations", ::cxxopts::value< uint32_t >()->default_value("8"), "number"),
    (spdk, "", "spdk", "spdk", ::cxxopts::value< bool >()->default_value("false"), "true or false"),
    (flip_list, "", "flip_list", "btree flip list", ::cxxopts::value< std::vector< std::string > >(), "flips [...]"),
    (use_file, "", "use_file", "use file instead of real drive", ::cxxopts::value< bool >()->default_value("false"),
     "true or false"),
    (enable_crash, "", "enable_crash", "enable crash", ::cxxopts::value< bool >()->default_value("0"), ""));

SETTINGS_INIT(iomgrcfg::IomgrSettings, iomgr_config);

using namespace homestore;

namespace test_common {

class test_http_server {
public:
    void get_prometheus_metrics(const Pistache::Rest::Request&, Pistache::Http::ResponseWriter response) {
        response.send(Pistache::Http::Code::Ok,
                      sisl::MetricsFarm::getInstance().report(sisl::ReportFormat::kTextFormat));
    }

    void start() {
        auto http_server_ptr = ioenvironment.get_http_server();

        std::vector< iomgr::http_route > routes = {
            {Pistache::Http::Method::Get, "/metrics",
             Pistache::Rest::Routes::bind(&test_http_server::get_prometheus_metrics, this), iomgr::url_t::safe}};
        try {
            http_server_ptr->setup_routes(routes);
            LOGINFO("Started http server ");
        } catch (std::runtime_error const& e) { LOGERROR("setup routes failed, {}", e.what()) }

        // start the server
        http_server_ptr->start();
    }

    void stop() {
        auto http_server_ptr = ioenvironment.get_http_server();
        http_server_ptr->stop();
    }
};

// Fix a port for http server
inline static void set_fixed_http_port(uint32_t http_port) {
    SETTINGS_FACTORY(iomgr_config).modifiable_settings([http_port](auto& s) { s.io_env->http_port = http_port; });
    SETTINGS_FACTORY(iomgr_config).save();
    LOGINFO("http port = {}", http_port);
}

// generate random port for http server
inline static uint32_t generate_random_http_port() {
    static std::random_device dev;
    static std::mt19937 rng(dev());
    std::uniform_int_distribution< std::mt19937::result_type > dist(1001u, 99999u);
    const uint32_t http_port = dist(rng);
    LOGINFO("random port generated = {}", http_port);
    return http_port;
}

struct Runner {
    uint64_t total_tasks_{0};
    uint32_t qdepth_{8};
    std::atomic< uint64_t > issued_tasks_{0};
    std::atomic< uint64_t > completed_tasks_{0};
    std::function< void(void) > task_;
    folly::Promise< folly::Unit > comp_promise_;

    Runner(uint64_t num_tasks, uint32_t qd = 8) : total_tasks_{num_tasks}, qdepth_{qd} {
        if (total_tasks_ < (uint64_t)qdepth_) { total_tasks_ = qdepth_; }
    }
    Runner() : Runner{SISL_OPTIONS["num_io"].as< uint64_t >(), SISL_OPTIONS["qdepth"].as< uint32_t >()} {}
    Runner(const Runner&) = delete;
    Runner& operator=(const Runner&) = delete;

    void set_num_tasks(uint64_t num_tasks) { total_tasks_ = std::max((uint64_t)qdepth_, num_tasks); }
    void set_task(std::function< void(void) > f) {
        issued_tasks_.store(0);
        completed_tasks_.store(0);
        comp_promise_ = folly::Promise< folly::Unit >{};
        task_ = std::move(f);
    }

    folly::Future< folly::Unit > execute() {
        for (uint32_t i{0}; i < qdepth_; ++i) {
            run_task();
        }
        return comp_promise_.getFuture();
    }

    void next_task() {
        auto ctasks = completed_tasks_.fetch_add(1);
        if ((issued_tasks_.load() < total_tasks_)) {
            run_task();
        } else if ((ctasks + 1) == total_tasks_) {
            comp_promise_.setValue();
        }
    }

    void run_task() {
        ++issued_tasks_;
        iomanager.run_on_forget(iomgr::reactor_regex::random_worker, task_);
    }
};

struct Waiter {
    std::atomic< uint64_t > expected_comp{0};
    std::atomic< uint64_t > actual_comp{0};
    folly::Promise< folly::Unit > comp_promise;

    Waiter(uint64_t num_op) : expected_comp{num_op} {}
    Waiter() : Waiter{SISL_OPTIONS["num_io"].as< uint64_t >()} {}
    Waiter(const Waiter&) = delete;
    Waiter& operator=(const Waiter&) = delete;

    folly::Future< folly::Unit > start(std::function< void(void) > f) {
        f();
        return comp_promise.getFuture();
    }

    void one_complete() {
        if ((actual_comp.fetch_add(1) + 1) >= expected_comp.load()) { comp_promise.setValue(); }
    }
};

class HSTestHelper {
    friend class HSReplTestHelper;

public:
    struct test_params {
        float size_pct{0};
        blk_allocator_type_t blkalloc_type{blk_allocator_type_t::varsize};
        uint32_t blk_size{0};
        shared< ChunkSelector > custom_chunk_selector{nullptr};
        shared< ChunkSelector > index_chunk_selector{nullptr};
        IndexServiceCallbacks* index_svc_cbs{nullptr};
        shared< ReplApplication > repl_app{nullptr};
        chunk_num_t num_chunks{1};
        uint64_t chunk_size{32 * 1024 * 1024}; // Chunk size in MB.
        uint64_t min_chunk_size{0};
        vdev_size_type_t vdev_size_type{vdev_size_type_t::VDEV_SIZE_STATIC};
    };

    struct test_token {
        std::string name_;
        std::map< uint32_t, test_params > svc_params_;
        hs_before_services_starting_cb_t cb_{nullptr};
        std::vector< homestore::dev_info > devs_;

        test_params& params(uint32_t svc) { return svc_params_[svc]; }
        hs_before_services_starting_cb_t& cb() { return cb_; }
    };

    virtual void start_homestore(const std::string& test_name, std::map< uint32_t, test_params >&& svc_params,
                                 hs_before_services_starting_cb_t cb = nullptr,
                                 std::vector< homestore::dev_info > devs = {}, bool init_device = true) {
        m_token =
            test_token{.name_ = test_name, .svc_params_ = std::move(svc_params), .cb_ = cb, .devs_ = std::move(devs)};
        do_start_homestore(false /* fake_restart */, init_device);
    }

    virtual void restart_homestore(uint32_t shutdown_delay_sec = 5) {
        do_start_homestore(true /* fake_restart*/, false /* init_device */, shutdown_delay_sec);
    }

    virtual void start_homestore() {
        do_start_homestore(true /* fake_restart*/, false /* init_device */, 1 /* shutdown_delay_sec */);
    }

    virtual void shutdown_homestore(bool cleanup = true) {
        if (homestore::HomeStore::safe_instance() == nullptr) {
            /* Already shutdown */
            return;
        }

        homestore::HomeStore::instance()->shutdown();
        iomanager.stop(); // Stop iomanager first in case any fiber is still referencing homestore resources
        homestore::HomeStore::reset_instance();

        if (cleanup) {
            remove_files(m_generated_devs);
            m_generated_devs.clear();
        }
    }

    void change_start_cb(hs_before_services_starting_cb_t cb) { m_token.cb() = cb; }
    void change_device_list(std::vector< homestore::dev_info > devs) { m_token.devs_ = std::move(devs); }
    test_params& params(uint32_t svc) { return m_token.svc_params_[svc]; }

#ifdef _PRERELEASE
    void wait_for_crash_recovery(bool check_will_crash = false) {
        if (check_will_crash && !homestore::HomeStore::instance()->crash_simulator().will_crash()) { return; }
        LOGDEBUG("Waiting for m_crash_recovered future");
        m_crash_recovered.getFuture().get();
        m_crash_recovered = folly::Promise< folly::Unit >();
        homestore::HomeStore::instance()->crash_simulator().set_will_crash(false);
    }
#endif

    void set_min_chunk_size(uint64_t chunk_size) {
#ifdef _PRERELEASE
        LOGINFO("Set minimum chunk size {}", chunk_size);
        flip::FlipClient* fc = iomgr_flip::client_instance();

        flip::FlipFrequency freq;
        freq.set_count(2000000);
        freq.set_percent(100);

        flip::FlipCondition dont_care_cond;
        fc->create_condition("", flip::Operator::DONT_CARE, (int)1, &dont_care_cond);
        fc->inject_retval_flip< long >("set_minimum_chunk_size", {dont_care_cond}, freq, chunk_size);
#endif
    }

#ifdef _PRERELEASE
    void set_basic_flip(const std::string flip_name, uint32_t count = 1, uint32_t percent = 100) {
        flip::FlipCondition null_cond;
        flip::FlipFrequency freq;
        freq.set_count(count);
        freq.set_percent(percent);
        m_fc.inject_noreturn_flip(flip_name, {null_cond}, freq);
        LOGDEBUG("Flip {} set", flip_name);
    }

    void set_delay_flip(const std::string flip_name, uint64_t delay_usec, uint32_t count = 1, uint32_t percent = 100) {
        flip::FlipCondition null_cond;
        flip::FlipFrequency freq;
        freq.set_count(count);
        freq.set_percent(percent);
        m_fc.inject_delay_flip(flip_name, {null_cond}, freq, delay_usec);
        LOGDEBUG("Flip {} set", flip_name);
    }

    void remove_flip(const std::string flip_name) {
        m_fc.remove_flip(flip_name);
        LOGDEBUG("Flip {} removed", flip_name);
    }
#endif

    static void fill_data_buf(uint8_t* buf, uint64_t size, uint64_t pattern = 0) {
        uint64_t* ptr = r_cast< uint64_t* >(buf);
        for (uint64_t i = 0ul; i < size / sizeof(uint64_t); ++i) {
            *(ptr + i) = (pattern == 0) ? i : pattern;
        }
    }

    static void validate_data_buf(uint8_t const* buf, uint64_t size, uint64_t pattern = 0) {
        uint64_t const* ptr = r_cast< uint64_t const* >(buf);
        for (uint64_t i = 0ul; i < size / sizeof(uint64_t); ++i) {
            HS_REL_ASSERT_EQ(ptr[i], ((pattern == 0) ? i : pattern), "data_buf mismatch at offset={}", i);
        }
    }

    static sisl::sg_list create_sgs(uint64_t io_size, uint32_t max_size_per_iov,
                                    std::optional< uint64_t > fill_data_pattern = std::nullopt) {
        auto blk_size = SISL_OPTIONS["block_size"].as< uint32_t >();
        HS_REL_ASSERT_EQ(io_size % blk_size, 0, "io_size should be a multiple of blk_size");
        HS_REL_ASSERT_EQ(max_size_per_iov % blk_size, 0, "max_size_per_iov should be a multiple of blk_size");

        uint32_t const nblks = io_size / blk_size;
        uint32_t const max_iov_nblks = std::min(nblks, max_size_per_iov / blk_size);

        static std::random_device s_rd{};
        static std::default_random_engine s_re{s_rd()};
        static std::uniform_int_distribution< uint32_t > iov_nblks_generator{1u, max_iov_nblks};

        sisl::sg_list sgs;
        sgs.size = 0;
        uint32_t remain_nblks = nblks;
        while (remain_nblks != 0) {
            uint32_t iov_nblks = iov_nblks_generator(s_re);
            uint32_t iov_len = blk_size * std::min(iov_nblks, remain_nblks);
            sgs.iovs.emplace_back(iovec{.iov_base = iomanager.iobuf_alloc(512, iov_len), .iov_len = iov_len});
            sgs.size += iov_nblks * blk_size;
            remain_nblks -= iov_nblks;

            if (fill_data_pattern) {
                fill_data_buf(uintptr_cast(sgs.iovs.back().iov_base), sgs.iovs.back().iov_len, *fill_data_pattern);
            }
        }

        return sgs;
    }

    static bool compare(const sisl::sg_list& sg1, const sisl::sg_list& sg2) {
        if ((sg2.size != sg1.size)) {
            LOGINFO("sg_list of sg1 size: {} mismatch with sg2 size: {}, ", sg1.size, sg2.size);
            return false;
        }

        if (sg2.iovs.size() != sg1.iovs.size()) {
            LOGINFO("sg_list num of iovs mismatch: sg1: {}, sg2: {}", sg1.iovs.size(), sg2.iovs.size());
            return false;
        }

        const auto num_iovs = sg2.iovs.size();
        for (auto i = 0ul; i < num_iovs; ++i) {
            if (sg2.iovs[i].iov_len != sg1.iovs[i].iov_len) {
                LOGINFO("iov_len of iov[{}] mismatch, sg1: {}, sg2: {}", i, sg1.iovs[i].iov_len, sg2.iovs[i].iov_len);
                return false;
            }
            auto ret = std::memcmp(sg2.iovs[i].iov_base, sg1.iovs[i].iov_base, sg1.iovs[i].iov_len);
            if (ret != 0) {
                LOGINFO("memcmp return false for iovs[{}] between sg1 and sg2.", i);
                return false;
            }
        }

        return true;
    }

    static void free(sisl::sg_list& sg) {
        for (auto x : sg.iovs) {
            iomanager.iobuf_free(s_cast< uint8_t* >(x.iov_base));
            x.iov_base = nullptr;
            x.iov_len = 0;
        }

        sg.size = 0;
    }

    static void trigger_cp(bool wait) {
        auto fut = homestore::hs()->cp_mgr().trigger_cp_flush(true /* force */);
        auto on_complete = [&](auto success) {
            HS_REL_ASSERT_EQ(success, true, "CP Flush failed");
            LOGDEBUG("CP Flush completed");
        };

        if (wait) {
            on_complete(std::move(fut).get());
        } else {
            std::move(fut).thenValue(on_complete);
        }
    }

    test_http_server* get_http_server() {
        return m_http_server.get();
    }

    void set_app_mem_size(uint64_t app_mem_size) { m_app_mem_size = app_mem_size; }

private:
    void do_start_homestore(bool fake_restart = false, bool init_device = true, uint32_t shutdown_delay_sec = 5) {
        auto const ndevices = SISL_OPTIONS["num_devs"].as< uint32_t >();
        auto const dev_size = SISL_OPTIONS["dev_size_mb"].as< uint64_t >() * 1024 * 1024;
        auto num_threads = SISL_OPTIONS["num_threads"].as< uint32_t >();
        auto num_fibers = SISL_OPTIONS["num_fibers"].as< uint32_t >();
        auto is_spdk = SISL_OPTIONS["spdk"].as< bool >();

        auto use_file = SISL_OPTIONS["use_file"].as< bool >();

        if (use_file && SISL_OPTIONS.count("device_list")) {
            LOGWARN("Ignoring device_list as use_file is set to true");
        }

        if (fake_restart) {
            // Fake restart, device list is unchanged.
            shutdown_homestore(false);
            std::this_thread::sleep_for(std::chrono::seconds{shutdown_delay_sec});
        } else if (SISL_OPTIONS.count("device_list") && !use_file) {
            // User has provided explicit device list, use that and initialize them
            auto const devs = SISL_OPTIONS["device_list"].as< std::vector< std::string > >();
            for (const auto& name : devs) {
                // iomgr::DriveInterface::emulate_drive_type(name, iomgr::drive_type::block_hdd);
                m_token.devs_.emplace_back(name,
                                           m_token.devs_.empty()
                                               ? homestore::HSDevType::Fast
                                               : homestore::HSDevType::Data); // First device is fast device
            }

            LOGINFO("Taking input dev_list: {}",
                    std::accumulate(m_token.devs_.begin(), m_token.devs_.end(), std::string(""),
                                    [](const std::string& s, const homestore::dev_info& dinfo) {
                                        return s.empty() ? dinfo.dev_name : s + "," + dinfo.dev_name;
                                    }));

            if (init_device) { init_raw_devices(m_token.devs_); }
        } else {
            for (uint32_t i{0}; i < ndevices; ++i) {
                m_generated_devs.emplace_back(std::string{"/tmp/" + m_token.name_ + "_" + std::to_string(i + 1)});
            }
            if (init_device) {
                LOGINFO("creating {} device files with each of size {} ", ndevices, homestore::in_bytes(dev_size));
                init_files(m_generated_devs, dev_size);
            }
            for (auto const& fname : m_generated_devs) {
                m_token.devs_.emplace_back(std::filesystem::canonical(fname).string(),
                                           m_token.devs_.empty()
                                               ? homestore::HSDevType::Fast
                                               : homestore::HSDevType::Data); // First device is fast device
            }
        }

        if (is_spdk) {
            LOGINFO("Spdk with more than 2 threads will cause overburden test systems, changing nthreads to 2");
            num_threads = 2;
        }

        LOGINFO("Starting iomgr with {} threads, spdk: {}", num_threads, is_spdk);
        ioenvironment.with_iomgr(
            iomgr::iomgr_params{.num_threads = num_threads, .is_spdk = is_spdk, .num_fibers = 1 + num_fibers});

        auto const http_port = SISL_OPTIONS["http_port"].as< int >();
        if (http_port != 0) {
            set_fixed_http_port((http_port == -1) ? generate_random_http_port() : uint32_cast(http_port));
            ioenvironment.with_http_server();
        }

        const uint64_t app_mem_size = (m_app_mem_size == 0) ? (((ndevices * dev_size) * 15) / 100) : m_app_mem_size;
        LOGINFO("Initialize and start HomeStore with app_mem_size = {}", homestore::in_bytes(app_mem_size));

        using namespace homestore;
        auto hsi = HomeStore::instance();
        for (auto& [svc, tp] : m_token.svc_params_) {
            if (svc == HS_SERVICE::DATA) {
                hsi->with_data_service(tp.custom_chunk_selector);
            } else if (svc == HS_SERVICE::INDEX) {
                hsi->with_index_service(std::unique_ptr< IndexServiceCallbacks >(tp.index_svc_cbs),
                                        tp.index_chunk_selector);
            } else if ((svc == HS_SERVICE::LOG)) {
                hsi->with_log_service();
            } else if (svc == HS_SERVICE::REPLICATION) {
                hsi->with_repl_data_service(tp.repl_app, tp.custom_chunk_selector);
            }
        }
#ifdef _PRERELEASE
        hsi->with_crash_simulator([this](void) mutable {
            LOGWARN("CrashSimulator::crash() is called - restarting homestore");
            this->restart_homestore();
            m_crash_recovered.setValue();
        });
#endif

        bool need_format =
            hsi->start(hs_input_params{.devices = m_token.devs_, .app_mem_size = app_mem_size}, m_token.cb_);

        // We need to set the min chunk size before homestore format
        if (m_token.svc_params_.contains(HS_SERVICE::LOG) && m_token.svc_params_[HS_SERVICE::LOG].min_chunk_size != 0) {
            set_min_chunk_size(m_token.svc_params_[HS_SERVICE::LOG].min_chunk_size);
        }

        if (need_format) {
            auto svc_params = m_token.svc_params_;
            hsi->format_and_start(
                {{HS_SERVICE::META,
                  {.dev_type = homestore::HSDevType::Fast, .size_pct = svc_params[HS_SERVICE::META].size_pct}},
                 {HS_SERVICE::LOG,
                  {.dev_type = homestore::HSDevType::Fast,
                   .size_pct = svc_params[HS_SERVICE::LOG].size_pct,
                   .chunk_size = svc_params[HS_SERVICE::LOG].chunk_size,
                   .vdev_size_type = svc_params[HS_SERVICE::LOG].vdev_size_type}},
                 {HS_SERVICE::DATA,
                  {.size_pct = svc_params[HS_SERVICE::DATA].size_pct,
                   .num_chunks = svc_params[HS_SERVICE::DATA].num_chunks,
                   .alloc_type = svc_params[HS_SERVICE::DATA].blkalloc_type,
                   .chunk_sel_type = svc_params[HS_SERVICE::DATA].custom_chunk_selector
                       ? chunk_selector_type_t::CUSTOM
                       : chunk_selector_type_t::ROUND_ROBIN}},
                 {HS_SERVICE::INDEX,
                  {.dev_type = homestore::HSDevType::Fast,
                   .size_pct = svc_params[HS_SERVICE::INDEX].size_pct,
                   .chunk_sel_type = svc_params[HS_SERVICE::INDEX].custom_chunk_selector
                       ? chunk_selector_type_t::CUSTOM
                       : chunk_selector_type_t::ROUND_ROBIN}},
                 {HS_SERVICE::REPLICATION,
                  {.size_pct = svc_params[HS_SERVICE::REPLICATION].size_pct,
                   .alloc_type = svc_params[HS_SERVICE::REPLICATION].blkalloc_type,
                   .chunk_sel_type = svc_params[HS_SERVICE::REPLICATION].custom_chunk_selector
                       ? chunk_selector_type_t::CUSTOM
                       : chunk_selector_type_t::ROUND_ROBIN}}});
        }
    }

    void remove_files(const std::vector< std::string >& file_paths) {
        for (const auto& fpath : file_paths) {
            if (std::filesystem::exists(fpath)) { std::filesystem::remove(fpath); }
        }
    }

    void init_files(const std::vector< std::string >& file_paths, uint64_t dev_size) {
        remove_files(file_paths);
        for (const auto& fpath : file_paths) {
            std::ofstream ofs{fpath, std::ios::binary | std::ios::out | std::ios::trunc};
            std::filesystem::resize_file(fpath, dev_size);
        }
    }

    void init_raw_devices(const std::vector< homestore::dev_info >& devs) {
        auto const zero_size = hs_super_blk::first_block_size() * 1024;
        std::vector< int > zeros(zero_size, 0);
        for (auto const& dinfo : devs) {
            if (!std::filesystem::exists(dinfo.dev_name)) {
                HS_REL_ASSERT(false, "Device {} does not exist", dinfo.dev_name);
            }

            auto fd = ::open(dinfo.dev_name.c_str(), O_RDWR, 0640);
            HS_REL_ASSERT(fd != -1, "Failed to open device");

            auto const write_sz =
                pwrite(fd, zeros.data(), zero_size /* size */, hs_super_blk::first_block_offset() /* offset */);
            HS_REL_ASSERT(write_sz == zero_size, "Failed to write to device");
            LOGINFO("Successfully zeroed the 1st {} bytes of device {}", zero_size, dinfo.dev_name);
            ::close(fd);
        }
    }

protected:
    test_token m_token;
    std::vector< std::string > m_generated_devs;
    std::unique_ptr< test_http_server > m_http_server;
    uint64_t m_app_mem_size{0};
#ifdef _PRERELEASE
    flip::FlipClient m_fc{iomgr_flip::instance()};
    folly::Promise< folly::Unit > m_crash_recovered;
#endif
};
} // namespace test_common
