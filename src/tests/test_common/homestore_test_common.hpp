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
#include <iomgr/iomgr_config_generated.h>
#include <common/homestore_assert.hpp>

const std::string SPDK_ENV_VAR_STRING{"USER_WANT_SPDK"};
const std::string HTTP_SVC_ENV_VAR_STRING{"USER_WANT_HTTP_OFF"};
const std::string CP_WATCHDOG_TIMER_SEC{"USER_SET_CP_WD_TMR_SEC"};          // used in nightly test;
const std::string FLIP_SLOW_PATH_EVERY_NTH{"USER_SET_SLOW_PATH_EVERY_NTH"}; // used in nightly test;
const std::string BLKSTORE_FORMAT_OFF{"USER_WANT_BLKSTORE_FORMAT_OFF"};     // used for debug purpose;
const std::string USER_WANT_DIRECT_IO{"USER_WANT_DIRECT_IO"};               // used for HDD direct io mode;

SISL_OPTION_GROUP(test_common_setup,
                  (num_threads, "", "num_threads", "number of threads",
                   ::cxxopts::value< uint32_t >()->default_value("2"), "number"),
                  (num_fibers, "", "num_fibers", "number of fibers per thread",
                   ::cxxopts::value< uint32_t >()->default_value("2"), "number"),
                  (num_devs, "", "num_devs", "number of devices to create",
                   ::cxxopts::value< uint32_t >()->default_value("2"), "number"),
                  (dev_size_mb, "", "dev_size_mb", "size of each device in MB",
                   ::cxxopts::value< uint64_t >()->default_value("1024"), "number"),
                  (device_list, "", "device_list", "Device List instead of default created",
                   ::cxxopts::value< std::vector< std::string > >(), "path [...]"),
                  (http_port, "", "http_port", "http port (0 for no http, -1 for random, rest specific value)",
                   ::cxxopts::value< int >()->default_value("-1"), "number"),
                  (num_io, "", "num_io", "number of IO operations",
                   ::cxxopts::value< uint64_t >()->default_value("300"), "number"),
                  (spdk, "", "spdk", "spdk", ::cxxopts::value< bool >()->default_value("false"), "true or false"));

SETTINGS_INIT(iomgrcfg::IomgrSettings, iomgr_config);

using namespace homestore;

namespace test_common {

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
    Runner() : Runner{SISL_OPTIONS["num_io"].as< uint64_t >()} {}
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
private:
    static void remove_files(const std::vector< std::string >& file_paths) {
        for (const auto& fpath : file_paths) {
            if (std::filesystem::exists(fpath)) { std::filesystem::remove(fpath); }
        }
    }

    static void init_files(const std::vector< std::string >& file_paths, uint64_t dev_size) {
        remove_files(file_paths);
        for (const auto& fpath : file_paths) {
            std::ofstream ofs{fpath, std::ios::binary | std::ios::out | std::ios::trunc};
            std::filesystem::resize_file(fpath, dev_size);
        }
    }

    static std::vector< std::string > s_dev_names;

public:
    struct test_params {
        float size_pct{0};
        blk_allocator_type_t blkalloc_type{blk_allocator_type_t::varsize};
        uint32_t blk_size{0};
        shared< ChunkSelector > custom_chunk_selector{nullptr};
        IndexServiceCallbacks* index_svc_cbs{nullptr};
        shared< ReplApplication > repl_app{nullptr};
        chunk_num_t num_chunks{1};
        uint64_t chunk_size{32 * 1024 * 1024}; // Chunk size in MB.
        uint64_t min_chunk_size{0};
        vdev_size_type_t vdev_size_type{vdev_size_type_t::VDEV_SIZE_STATIC};
    };

    static void start_homestore(const std::string& test_name, std::map< uint32_t, test_params >&& svc_params,
                                hs_before_services_starting_cb_t cb = nullptr, bool fake_restart = false,
                                bool init_device = true, uint32_t shutdown_delay_sec = 5) {
        auto const ndevices = SISL_OPTIONS["num_devs"].as< uint32_t >();
        auto const dev_size = SISL_OPTIONS["dev_size_mb"].as< uint64_t >() * 1024 * 1024;
        auto num_threads = SISL_OPTIONS["num_threads"].as< uint32_t >();
        auto num_fibers = SISL_OPTIONS["num_fibers"].as< uint32_t >();
        auto is_spdk = SISL_OPTIONS["spdk"].as< bool >();

        if (fake_restart) {
            shutdown_homestore(false);
            sisl::GrpcAsyncClientWorker::shutdown_all();
            std::this_thread::sleep_for(std::chrono::seconds{shutdown_delay_sec});
        }

        std::vector< homestore::dev_info > device_info;
        if (SISL_OPTIONS.count("device_list")) {
            s_dev_names = SISL_OPTIONS["device_list"].as< std::vector< std::string > >();
            LOGINFO("Taking input dev_list: {}",
                    std::accumulate(
                        s_dev_names.begin(), s_dev_names.end(), std::string(""),
                        [](const std::string& ss, const std::string& s) { return ss.empty() ? s : ss + "," + s; }));

            for (const auto& name : s_dev_names) {
                device_info.emplace_back(name, homestore::HSDevType::Data);
            }
        } else {
            /* create files */
            LOGINFO("creating {} device files with each of size {} ", ndevices, homestore::in_bytes(dev_size));
            for (uint32_t i{0}; i < ndevices; ++i) {
                s_dev_names.emplace_back(std::string{"/tmp/" + test_name + "_" + std::to_string(i + 1)});
            }

            if (!fake_restart && init_device) { init_files(s_dev_names, dev_size); }
            for (const auto& fname : s_dev_names) {
                device_info.emplace_back(std::filesystem::canonical(fname).string(), homestore::HSDevType::Data);
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

        const uint64_t app_mem_size = ((ndevices * dev_size) * 15) / 100;
        LOGINFO("Initialize and start HomeStore with app_mem_size = {}", homestore::in_bytes(app_mem_size));

        using namespace homestore;
        auto hsi = HomeStore::instance();
        for (auto& [svc, tp] : svc_params) {
            if (svc == HS_SERVICE::DATA) {
                hsi->with_data_service(tp.custom_chunk_selector);
            } else if (svc == HS_SERVICE::INDEX) {
                hsi->with_index_service(std::unique_ptr< IndexServiceCallbacks >(tp.index_svc_cbs));
            } else if ((svc == HS_SERVICE::LOG)) {
                hsi->with_log_service();
            } else if (svc == HS_SERVICE::REPLICATION) {
                hsi->with_repl_data_service(tp.repl_app, tp.custom_chunk_selector);
            }
        }
        bool need_format =
            hsi->start(hs_input_params{.devices = device_info, .app_mem_size = app_mem_size}, std::move(cb));

        // We need to set the min chunk size before homestore format
        if (svc_params[HS_SERVICE::LOG].min_chunk_size != 0) {
            set_min_chunk_size(svc_params[HS_SERVICE::LOG].min_chunk_size);
        }

        if (need_format) {
            hsi->format_and_start({{HS_SERVICE::META, {.size_pct = svc_params[HS_SERVICE::META].size_pct}},
                                   {HS_SERVICE::LOG,
                                    {.size_pct = svc_params[HS_SERVICE::LOG].size_pct,
                                     .chunk_size = svc_params[HS_SERVICE::LOG].chunk_size,
                                     .vdev_size_type = svc_params[HS_SERVICE::LOG].vdev_size_type}},
                                   {HS_SERVICE::DATA,
                                    {.size_pct = svc_params[HS_SERVICE::DATA].size_pct,
                                     .num_chunks = svc_params[HS_SERVICE::DATA].num_chunks,
                                     .alloc_type = svc_params[HS_SERVICE::DATA].blkalloc_type,
                                     .chunk_sel_type = svc_params[HS_SERVICE::DATA].custom_chunk_selector
                                         ? chunk_selector_type_t::CUSTOM
                                         : chunk_selector_type_t::ROUND_ROBIN}},
                                   {HS_SERVICE::INDEX, {.size_pct = svc_params[HS_SERVICE::INDEX].size_pct}},
                                   {HS_SERVICE::REPLICATION,
                                    {.size_pct = svc_params[HS_SERVICE::REPLICATION].size_pct,
                                     .alloc_type = svc_params[HS_SERVICE::REPLICATION].blkalloc_type,
                                     .chunk_sel_type = svc_params[HS_SERVICE::REPLICATION].custom_chunk_selector
                                         ? chunk_selector_type_t::CUSTOM
                                         : chunk_selector_type_t::ROUND_ROBIN}}});
        }
    }

    static void shutdown_homestore(bool cleanup = true) {
        homestore::HomeStore::instance()->shutdown();
        homestore::HomeStore::reset_instance();
        iomanager.stop();

        if (cleanup) { remove_files(s_dev_names); }
        s_dev_names.clear();
    }

    static void set_min_chunk_size(uint64_t chunk_size) {
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
            LOGINFO("CP Flush completed");
        };

        if (wait) {
            on_complete(std::move(fut).get());
        } else {
            std::move(fut).thenValue(on_complete);
        }
    }
};
}; // namespace test_common
