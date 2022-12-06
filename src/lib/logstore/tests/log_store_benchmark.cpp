#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <vector>

#include <api/vol_interface.hpp>
#include <benchmark/benchmark.h>
#include <iomgr/aio_drive_interface.hpp>
#include <iomgr/io_environment.hpp>
#include <sisl/logging/logging.h>
#include <sisl/options/options.h>

#include "engine/common/homestore_header.hpp"

#include "../log_store.hpp"

using namespace homestore;
SISL_LOGGING_INIT(HOMESTORE_LOG_MODS)

static constexpr size_t ITERATIONS{100000};
static constexpr size_t THREADS{64};

typedef std::function< void(logstore_seq_num_t) > test_log_store_comp_cb_t;

class SampleLogStoreClient {
public:
    friend class SampleDB;
    SampleLogStoreClient(std::shared_ptr< HomeLogStore > store, const logstore_family_id_t family_idx,
                         const uint64_t nentries, const test_log_store_comp_cb_t& cb) :
            m_comp_cb{cb}, m_nentries{nentries}, m_family{family_idx}, m_store_id{store->get_store_id()} {
        init(store);
        generate_rand_data(nentries);
    }

    explicit SampleLogStoreClient(const uint64_t nentries, const logstore_family_id_t family_idx,
                                  const test_log_store_comp_cb_t& cb) :
            SampleLogStoreClient(HomeLogStoreMgrSI().create_new_log_store(family_idx, false /* append_mode */),
                                 family_idx, nentries, cb) {}

    SampleLogStoreClient(const SampleLogStoreClient&) = delete;
    SampleLogStoreClient& operator=(const SampleLogStoreClient&) = delete;
    SampleLogStoreClient(SampleLogStoreClient&&) noexcept = delete;
    SampleLogStoreClient& operator=(SampleLogStoreClient&&) noexcept = delete;
    ~SampleLogStoreClient() = default;

    void init(std::shared_ptr< HomeLogStore > store) {
        m_log_store = store;
        m_log_store->register_log_found_cb(bind_this(SampleLogStoreClient::on_log_found, 3));
        m_nth_entry.store(0);
    }

    [[nodiscard]] bool append() {
        const auto ind{m_nth_entry.fetch_add(1, std::memory_order_acq_rel)};
        if (ind >= m_nentries) { return false; }
        DLOGDEBUG("Appending log entry for ind {}", ind);
        [[maybe_unused]] const auto seq_num{m_log_store->append_async(
            sisl::io_blob(reinterpret_cast< uint8_t* >(m_data[ind].data()), static_cast< uint32_t >(m_data[ind].size()),
                          false),
            nullptr,
            [this](logstore_seq_num_t seq_num, sisl::io_blob& iob, bool success, void* ctx) { m_comp_cb(seq_num); })};
        return true;
    }

    void read(const logstore_seq_num_t lsn) { [[maybe_unused]] const auto b{m_log_store->read_sync(lsn)}; }

    void on_log_found(const logstore_seq_num_t lsn, const log_buffer buf, void* const ctx) {
        // LOGDEBUG("Recovered lsn {}:{} with log data of size {}", m_log_store->get_store_id(), lsn, buf.size())
    }

private:
    void generate_rand_data(const uint64_t nentries) {
        static thread_local std::random_device rd{};
        static thread_local std::default_random_engine re{rd()};
        std::uniform_int_distribution< uint32_t > data_size{0, max_data_size - 1};

        static unsigned char ch{0};
        m_data.reserve(nentries);

        for (uint64_t i{0}; i < nentries; ++i) {
            const auto sz{data_size(re)};
            m_data.emplace_back(std::string(sz, ++ch));
        }
    }

public:
    static uint32_t max_data_size;

private:
    test_log_store_comp_cb_t m_comp_cb;
    uint64_t m_nentries = 0;
    std::shared_ptr< HomeLogStore > m_log_store;
    std::atomic< uint64_t > m_nth_entry = 0;
    std::vector< std::string > m_data;
    logstore_family_id_t m_family;
    logstore_id_t m_store_id;
};

class SampleDB {
public:
    SampleDB(const SampleDB&) = delete;
    SampleDB& operator=(const SampleDB&) = delete;
    SampleDB(SampleDB&&) noexcept = delete;
    SampleDB& operator=(SampleDB&&) noexcept = delete;
    ~SampleDB() = default;

    static SampleDB& instance() {
        static SampleDB inst;
        return inst;
    }

    void start_homestore(const std::string& devname, const uint32_t nthreads, const uint32_t n_log_stores,
                         const uint32_t n_entries, const uint32_t qdepth, const bool restart = false) {
        if (restart) { shutdown(); }

        std::vector< dev_info > device_info;
        // these should be static so that they stay in scope in the lambda in case function ends before lambda completes
        static std::mutex start_mutex;
        static std::condition_variable cv;
        static bool inited;

        inited = false;
        m_q_depth = qdepth;
        const std::filesystem::path fpath{devname};
        LOGINFO("opening {} device of size {} ", fpath.string());
        device_info.emplace_back(std::filesystem::canonical(fpath).string(), HSDevType::Data);

        LOGINFO("Starting iomgr with {} threads", nthreads);
        ioenvironment.with_iomgr(nthreads);

        if (restart) {
            for (uint32_t i{0}; i < n_log_stores; ++i) {
                SampleLogStoreClient* client = m_log_store_clients[i].get();
                HomeLogStoreMgrSI().open_log_store(
                    client->m_family, client->m_store_id, false /* append_mode */,
                    [i, this](std::shared_ptr< HomeLogStore > log_store) { m_log_store_clients[i]->init(log_store); });
            }
        }

        constexpr uint64_t app_mem_size{static_cast< uint64_t >(2) * 1024 * 1024 * 1024};
        LOGINFO("Initialize and start HomeBlks with memory size = {}", app_mem_size);

        boost::uuids::string_generator gen;
        init_params params;
        params.data_open_flags = homestore::io_flag::DIRECT_IO;
        params.min_virtual_page_size = 4096;
        params.app_mem_size = app_mem_size;
        params.data_devices = device_info;
        params.init_done_cb = [&tl_start_mutex = start_mutex, &tl_cv = cv,
                               &tl_inited = inited](std::error_condition err, const out_params& params) {
            LOGINFO("HomeBlks Init completed");
            {
                std::unique_lock< std::mutex > lk{tl_start_mutex};
                tl_inited = true;
            }
            tl_cv.notify_one();
        };
        params.vol_mounted_cb = [](const VolumePtr& vol_obj, vol_state state) {};
        params.vol_state_change_cb = [](const VolumePtr& vol, vol_state old_state, vol_state new_state) {};
        params.vol_found_cb = [](boost::uuids::uuid uuid) -> bool { return true; };
        VolInterface::init(params, restart);

        {
            std::unique_lock< std::mutex > lk{start_mutex};
            cv.wait(lk, [] { return inited; });
        }

        if (!restart) {
            for (uint32_t i{0}; i < n_log_stores; ++i) {
                auto family_idx =
                    ((i % 2) == 0) ? HomeLogStoreMgr::DATA_LOG_FAMILY_IDX : HomeLogStoreMgr::CTRL_LOG_FAMILY_IDX;
                m_log_store_clients.push_back(std::make_unique< SampleLogStoreClient >(
                    n_entries, family_idx, bind_this(SampleDB::on_log_append_completion, 1)));
            }
        }
    }

    void shutdown() {
        VolInterface::shutdown();

        // m_log_store_clients.clear();
        iomanager.stop();
    }

    void kickstart_io() {
        m_done = false;
        for (auto& sc : m_log_store_clients) {
            sc->m_nth_entry.store(0);
        }
        iomanager.run_on(iomgr::thread_regex::all_io, [this](io_thread_addr_t addr) { initial_io(); });
    }

    void initial_io() {
        for (decltype(m_q_depth) i{0}; i < m_q_depth; ++i) {
            issue_io();
        }
    }

    void issue_io() {
        m_outstanding.fetch_add(1, std::memory_order_acq_rel);

        // TODO: Pick a log store later, right now use only 1st
        if (!m_log_store_clients[0]->append()) {
            DLOGDEBUG("Notify that append has reached limit outstanding = {}", m_outstanding.load());
            bool notify{false};
            {
                std::unique_lock< std::mutex > lk{m_pending_mtx};
                notify = m_done = (m_outstanding.fetch_sub(1, std::memory_order_acq_rel) == 1);
            }
            if (notify) {
                DLOGDEBUG("Notify that append has completed, outstanding = {}", m_outstanding.load());
                m_pending_cv.notify_all();
            }
        }
    }

    void on_log_append_completion(const logstore_seq_num_t lsn) {
        const auto outstanding{m_outstanding.fetch_sub(1, std::memory_order_acq_rel)};
        if (outstanding < static_cast< int >(m_q_depth)) { issue_io(); }
    }

    void wait_for_appends() {
        {
            std::unique_lock< std::mutex > lk{m_pending_mtx};
            m_pending_cv.wait(lk, [&] { return (m_done); });
        }
        DLOGDEBUG("All appends completed and waiting is done, outstanding = {}", m_outstanding.load());
    }

private:
    SampleDB() = default;

    std::function< void() > m_on_schedule_io_cb;
    std::vector< std::unique_ptr< SampleLogStoreClient > > m_log_store_clients;

    std::atomic< int32_t > m_outstanding{0};
    uint32_t m_q_depth{0};
    bool m_done{false};
    std::mutex m_pending_mtx;
    std::condition_variable m_pending_cv;
};

#define sample_db SampleDB::instance()

static void test_append(benchmark::State& state) {
    [[maybe_unused]] uint64_t counter{0};
    for ([[maybe_unused]] auto current_state : state) { // Loops upto iteration count
        sample_db.kickstart_io();
        sample_db.wait_for_appends();
    }
}

static void setup() {
    sample_db.start_homestore(SISL_OPTIONS["dev_name"].as< std::string >(),   // devname
                              SISL_OPTIONS["num_threads"].as< uint32_t >(),   // num threads
                              SISL_OPTIONS["num_logstores"].as< uint32_t >(), // num log stores
                              SISL_OPTIONS["num_entries"].as< uint64_t >(),   // num entries
                              SISL_OPTIONS["qdepth"].as< uint32_t >(),        // qdepth
                              false                                           // restart
    );
}
static void teardown() { sample_db.shutdown(); }

SISL_OPTIONS_ENABLE(logging, log_store_benchmark)
SISL_OPTION_GROUP(log_store_benchmark,
                  (num_threads, "", "num_threads", "number of threads",
                   ::cxxopts::value< uint32_t >()->default_value("2"), "number"),
                  (dev_name, "", "dev_name", "name of homeblks device",
                   ::cxxopts::value< std::string >()->default_value("/tmp/hb_dev1"), "string"),
                  (num_logstores, "", "num_logstores", "number of log stores",
                   ::cxxopts::value< uint32_t >()->default_value("1"), "number"),
                  (num_entries, "", "num_entries", "number of log records",
                   ::cxxopts::value< uint64_t >()->default_value("10000"), "number"),
                  (qdepth, "", "qdepth", "qdepth per thread", ::cxxopts::value< uint32_t >()->default_value("32"),
                   "number"),
                  (max_record_size, "", "max_record_size", "max record size",
                   ::cxxopts::value< uint32_t >()->default_value("1024"), "number"));

// BENCHMARK(test_append)->Iterations(10)->Threads(SISL_OPTIONS["num_threads"].as< uint32_t >());
BENCHMARK(test_append)->Iterations(1);

uint32_t SampleLogStoreClient::max_data_size{1024};
int main(int argc, char** argv) {
    SISL_OPTIONS_LOAD(argc, argv, logging, log_store_benchmark)
    sisl::logging::SetLogger("log_store_benchmark");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    SampleLogStoreClient::max_data_size = SISL_OPTIONS["max_record_size"].as< uint32_t >();
    setup();
    ::benchmark::Initialize(&argc, argv);
    ::benchmark::RunSpecifiedBenchmarks();
    std::cout << "Metrics: " << sisl::MetricsFarm::getInstance().get_result_in_json()["LogStores"].dump(4) << "\n";
    teardown();

    malloc_stats();
    // malloc_info(0, stdout);
}
