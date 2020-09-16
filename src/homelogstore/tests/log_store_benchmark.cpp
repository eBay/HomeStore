#include <benchmark/benchmark.h>
#include <sds_logging/logging.h>
#include <sds_options/options.h>
#include "../log_store.hpp"
#include <iomgr/iomgr.hpp>
#include <iomgr/aio_drive_interface.hpp>
#include <api/vol_interface.hpp>
#include <string>
#include <malloc.h>
#include "engine/common/homestore_header.hpp"

using namespace homestore;
THREAD_BUFFER_INIT;
SDS_LOGGING_INIT(HOMESTORE_LOG_MODS)

#define ITERATIONS 100000
#define THREADS 64

typedef std::function< void(logstore_seq_num_t) > test_log_store_comp_cb_t;

class SampleLogStoreClient {
public:
    friend class SampleDB;
    SampleLogStoreClient(std::shared_ptr< HomeLogStore > store, uint64_t nentries, const test_log_store_comp_cb_t& cb) :
            m_comp_cb(cb),
            m_nentries(nentries) {
        init(store);
        generate_rand_data(nentries);
    }

    explicit SampleLogStoreClient(uint64_t nentries, const test_log_store_comp_cb_t& cb) :
            SampleLogStoreClient(home_log_store_mgr.create_new_log_store(), nentries, cb) {}

    void init(std::shared_ptr< HomeLogStore > store) {
        m_log_store = store;
        m_log_store->register_log_found_cb(std::bind(&SampleLogStoreClient::on_log_found, this, std::placeholders::_1,
                                                     std::placeholders::_2, std::placeholders::_3));
        m_nth_entry.store(0);
    }

    bool append() {
        auto ind = m_nth_entry.fetch_add(1, std::memory_order_acq_rel);
        if (ind >= m_nentries) { return false; }
        DLOGDEBUG("Appending log entry for ind {}", ind);
        m_log_store->append_async(
            sisl::io_blob((uint8_t*)m_data[ind].data(), (uint32_t)m_data[ind].size(), false), nullptr,
            [this](logstore_seq_num_t seq_num, sisl::io_blob& iob, bool success, void* ctx) { m_comp_cb(seq_num); });
        return true;
    }

    void read(logstore_seq_num_t lsn) { auto b = m_log_store->read_sync(lsn); }

    void on_log_found(logstore_seq_num_t lsn, log_buffer buf, void* ctx) {
        // LOGDEBUG("Recovered lsn {}:{} with log data of size {}", m_log_store->get_store_id(), lsn, buf.size())
    }

private:
    void generate_rand_data(uint64_t nentries) {
        static unsigned char ch = 0;
        m_data.reserve(nentries);

        for (auto i = 0u; i < nentries; ++i) {
            auto sz = rand() % max_data_size;
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
};

class SampleDB {
public:
    static SampleDB& instance() {
        static SampleDB inst;
        return inst;
    }

    void start_homestore(const std::string& devname, uint32_t nthreads, uint32_t n_log_stores, uint32_t n_entries,
                         uint32_t qdepth, bool restart = false) {
        if (restart) { shutdown(); }

        std::vector< dev_info > device_info;
        std::mutex start_mutex;
        std::condition_variable cv;
        bool inited = false;

        m_q_depth = qdepth;
        LOGINFO("opening {} device of size {} ", devname);
        device_info.push_back({devname});

        LOGINFO("Starting iomgr with {} threads", nthreads);
        iomanager.start(nthreads);

        if (restart) {
            for (auto i = 0u; i < n_log_stores; ++i) {
                home_log_store_mgr.open_log_store(i, [i, this](std::shared_ptr< HomeLogStore > log_store) {
                    m_log_store_clients[i]->init(log_store);
                });
            }
        }

        uint64_t app_mem_size = 2ul * 1024 * 1024 * 1024;
        LOGINFO("Initialize and start HomeBlks with memory size = {}", app_mem_size);

        boost::uuids::string_generator gen;
        init_params params;
        params.open_flags = homestore::io_flag::DIRECT_IO;
        params.min_virtual_page_size = 4096;
        params.app_mem_size = app_mem_size;
        params.disk_init = !restart;
        params.devices = device_info;
        params.init_done_cb = [&](std::error_condition err, const out_params& params) {
            LOGINFO("HomeBlks Init completed");
            {
                std::unique_lock< std::mutex > lk(start_mutex);
                inited = true;
            }
            cv.notify_all();
        };
        params.vol_mounted_cb = [](const VolumePtr& vol_obj, vol_state state) {};
        params.vol_state_change_cb = [](const VolumePtr& vol, vol_state old_state, vol_state new_state) {};
        params.vol_found_cb = [](boost::uuids::uuid uuid) -> bool { return true; };
        params.system_uuid = gen("01970496-0262-11e9-8eb2-f2801f1b9fd1");
        VolInterface::init(params, restart);

        std::unique_lock< std::mutex > lk(start_mutex);
        cv.wait(lk, [&] { return inited; });

        if (!restart) {
            for (auto i = 0u; i < n_log_stores; ++i) {
                m_log_store_clients.push_back(std::make_unique< SampleLogStoreClient >(
                    n_entries, std::bind(&SampleDB::on_log_append_completion, this, std::placeholders::_1)));
            }
        }
    }

    void shutdown() {
        VolInterface::get_instance()->shutdown();

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
        for (auto i = 0u; i < m_q_depth; ++i) {
            issue_io();
        }
    }

    void issue_io() {
        m_outstanding.fetch_add(1, std::memory_order_acq_rel);

        // TODO: Pick a log store later, right now use only 1st
        if (!m_log_store_clients[0]->append()) {
            DLOGDEBUG("Notify that append has reached limit outstanding = {}", m_outstanding.load());
            bool notify = false;
            {
                std::unique_lock< std::mutex > lk(m_pending_mtx);
                notify = m_done = (m_outstanding.fetch_sub(1, std::memory_order_acq_rel) == 1);
            }
            if (notify) {
                DLOGDEBUG("Notify that append has completed, outstanding = {}", m_outstanding.load());
                m_pending_cv.notify_all();
            }
        }
    }

    void on_log_append_completion(logstore_seq_num_t lsn) {
        auto outstanding = m_outstanding.fetch_sub(1, std::memory_order_acq_rel);
        if (outstanding < (int)m_q_depth) { issue_io(); }
    }

    void wait_for_appends() {
        {
            std::unique_lock< std::mutex > lk(m_pending_mtx);
            m_pending_cv.wait(lk, [&] { return (m_done); });
        }
        DLOGDEBUG("All appends completed and waiting is done, outstanding = {}", m_outstanding.load());
    }

private:
    std::function< void() > m_on_schedule_io_cb;
    std::vector< std::unique_ptr< SampleLogStoreClient > > m_log_store_clients;

    std::atomic< int32_t > m_outstanding = 0;
    uint32_t m_q_depth = 0;
    bool m_done = false;
    std::mutex m_pending_mtx;
    std::condition_variable m_pending_cv;
};

#define sample_db SampleDB::instance()

void test_append(benchmark::State& state) {
    uint64_t counter = 0U;
    for (auto _ : state) { // Loops upto iteration count
        sample_db.kickstart_io();
        sample_db.wait_for_appends();
    }
}

void setup() {
    sample_db.start_homestore(SDS_OPTIONS["dev_name"].as< std::string >(),   // devname
                              SDS_OPTIONS["num_threads"].as< uint32_t >(),   // num threads
                              SDS_OPTIONS["num_logstores"].as< uint32_t >(), // num log stores
                              SDS_OPTIONS["num_entries"].as< uint64_t >(),   // num entries
                              SDS_OPTIONS["qdepth"].as< uint32_t >(),        // qdepth
                              false                                          // restart
    );
}
void teardown() { sample_db.shutdown(); }

SDS_OPTIONS_ENABLE(logging, log_store_benchmark)
SDS_OPTION_GROUP(log_store_benchmark,
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
                  ::cxxopts::value< uint32_t >()->default_value("1024"), "number"),
                 (hb_stats_port, "", "hb_stats_port", "Stats port for HTTP service",
                  cxxopts::value< int32_t >()->default_value("5000"), "port"));

// BENCHMARK(test_append)->Iterations(10)->Threads(SDS_OPTIONS["num_threads"].as< uint32_t >());
BENCHMARK(test_append)->Iterations(1);

uint32_t SampleLogStoreClient::max_data_size = 1024;
int main(int argc, char** argv) {
    SDS_OPTIONS_LOAD(argc, argv, logging, log_store_benchmark)
    sds_logging::SetLogger("log_store_benchmark");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    SampleLogStoreClient::max_data_size = SDS_OPTIONS["max_record_size"].as< uint32_t >();
    setup();
    ::benchmark::Initialize(&argc, argv);
    ::benchmark::RunSpecifiedBenchmarks();
    std::cout << "Metrics: " << sisl::MetricsFarm::getInstance().get_result_in_json()["LogStores"].dump(4) << "\n";
    teardown();

    malloc_stats();
    // malloc_info(0, stdout);
}