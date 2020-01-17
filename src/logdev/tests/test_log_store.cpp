#include <gtest/gtest.h>
#include "../log_store.hpp"
#include <sds_logging/logging.h>
#include <sds_options/options.h>
#include <iomgr/iomgr.hpp>
#include <iomgr/aio_drive_interface.hpp>
#include <algorithm> // std::shuffle
#include <random>    // std::default_random_engine
#include <chrono>    // std::chrono::system_clock

using namespace homestore;
THREAD_BUFFER_INIT;
SDS_LOGGING_INIT(test_log_store, btree_structures, btree_nodes, btree_generics, cache, device, httpserver_lmod, iomgr,
                 varsize_blk_alloc, VMOD_VOL_MAPPING, volume, logdev, flip)

struct test_log_data {
    uint32_t size;
    uint8_t data[0];
};

typedef std::function< void(logstore_seq_num_t) > test_log_store_comp_cb_t;

class TestLogStoreClient {
public:
    explicit TestLogStoreClient(const test_log_store_comp_cb_t& cb) {
        m_comp_cb = cb;
        m_log_store = home_log_store_mgr.create_new_log_store();
    }

    void insert_next_batch(uint32_t batch_size) {
        auto cur_lsn = m_cur_lsn.fetch_add(batch_size);
        insert(cur_lsn, batch_size, false);
    }

    void insert(logstore_seq_num_t start_lsn, int64_t nparallel_count, bool wait_for_completion = true) {
        std::vector< logstore_seq_num_t > lsns;
        lsns.reserve(nparallel_count);

        // Shuffle ids within the range for count
        for (auto lsn = start_lsn; lsn < start_lsn + nparallel_count; ++lsn) {
            lsns.push_back(lsn);
        }
        uint32_t seed = std::chrono::system_clock::now().time_since_epoch().count();
        std::shuffle(lsns.begin(), lsns.end(), std::default_random_engine(seed));

        for (auto lsn : lsns) {
            auto sz = rand() % max_data_size;

            // Generate buffer of randome size and fill with specific data
            auto raw_buf = (uint8_t*)malloc(sizeof(test_log_data) + sz);
            test_log_data* d = new (raw_buf) test_log_data();
            d->size = sz;
            for (auto i = 0u; i < sz; ++i) {
                // Get printable ascii character range
                d->data[i] = ((lsn % 94) + 33);
            }

            m_log_store->write_async(lsn, {(uint8_t*)d, d->size}, nullptr,
                                     [d, this](logstore_seq_num_t seq_num, bool success, void* ctx) {
                                         LOGINFO("Completed write of lsn {} ", seq_num);
                                         free(d);
                                         m_comp_cb(seq_num);
                                     });
        }
    }

    void read(logstore_seq_num_t lsn) {
        EXPECT_GT(lsn, m_truncated_upto_lsn);
        // m_log_store->read(id);
    }

    void truncate(logstore_seq_num_t lsn) {
        m_log_store->truncate(lsn);
        m_truncated_upto_lsn = lsn;
    }

private:
    std::shared_ptr< HomeLogStore > m_log_store;
    std::atomic< logstore_seq_num_t > m_truncated_upto_lsn = 0;
    std::atomic< logstore_seq_num_t > m_cur_lsn = 0;
    test_log_store_comp_cb_t m_comp_cb;

    static constexpr uint32_t max_data_size = 1024;
};

struct LogStoreTest : public testing::Test {
public:
    static void start_homestore(uint32_t ndevices, uint64_t dev_size, uint32_t nthreads) {
        std::vector< dev_info > device_info;
        std::mutex start_mutex;
        std::condition_variable cv;
        bool inited = false;

        LOGINFO("creating {} device files with each of size {} ", ndevices, dev_size);
        for (uint32_t i = 0; i < ndevices; i++) {
            std::string fpath = "/tmp/" + std::to_string(i + 1);
            std::ofstream ofs(fpath.c_str(), std::ios::binary | std::ios::out);
            ofs.seekp(dev_size - 1);
            ofs.write("", 1);
            ofs.close();
            device_info.push_back({fpath});
        }

        LOGINFO("Starting iomgr with {} threads", nthreads);
        iomanager.start(1 /* total interfaces */, nthreads);
        iomanager.add_drive_interface(
            std::dynamic_pointer_cast< iomgr::DriveInterface >(std::make_shared< iomgr::AioDriveInterface >()),
            true /* is_default */);

        uint64_t cache_size = ((ndevices * dev_size) * 10) / 100;
        LOGINFO("Initialize and start HomeBlks with cache_size = {}", cache_size);

        boost::uuids::string_generator gen;
        init_params params;
        params.flag = homestore::io_flag::DIRECT_IO;
        params.min_virtual_page_size = 4096;
        params.cache_size = cache_size;
        params.disk_init = true;
        params.devices = device_info;
        params.is_file = true;
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
        VolInterface::init(params);

        std::unique_lock< std::mutex > lk(start_mutex);
        cv.wait(lk, [&] { return inited; });
    }

    void init(uint32_t n_log_stores, uint64_t n_total_records) {
        m_ev_fd = eventfd(0, EFD_NONBLOCK);
        m_ev_fdinfo = iomanager.add_fd(m_ev_fd,
                                       std::bind(&LogStoreTest::process_event, this, std::placeholders::_1,
                                                 std::placeholders::_2, std::placeholders::_3),
                                       EPOLLIN, 9, nullptr);
        m_pending_issued_records = std::lround(n_total_records / batch_size) * batch_size;
        m_pending_comp_records = 0;

        // Create multiple log stores
        for (auto i = 0u; i < n_log_stores; ++i) {
            m_log_store_clients.push_back(std::make_unique< TestLogStoreClient >(
                std::bind(&LogStoreTest::on_insert_completion, this, std::placeholders::_1)));
        }
    }

    void shutdown() { iomanager.remove_fd(this->m_ev_fdinfo); }
    void process_event(int fd, void* cookie, int event) {
        uint64_t temp;
        [[maybe_unused]] auto rsize = read(this->m_ev_fd, &temp, sizeof(uint64_t));
        do_insert();
    }

    void kickstart_inserts() {
        uint64_t temp = 1;
        [[maybe_unused]] auto wsize = write(this->m_ev_fd, &temp, sizeof(uint64_t));
    }

    void do_insert() {
        // Randomly pick a store client and write journal entry batch.
        while (m_pending_issued_records.fetch_sub(batch_size) > 0) {
            m_pending_comp_records.fetch_add(batch_size);
            m_log_store_clients[rand() % m_log_store_clients.size()]->insert_next_batch(batch_size);
        }
    }

    void on_insert_completion(logstore_seq_num_t lsn) {
        if ((m_pending_comp_records.fetch_sub(1) == 0) && (m_pending_issued_records == 0)) {
            m_pending_cv.notify_all();
        }
    }

    void wait_for_inserts() {
        {
            std::unique_lock< std::mutex > lk(m_pending_mtx);
            m_pending_cv.wait(lk, [&] { return (m_pending_issued_records <= 0) && (m_pending_comp_records <= 0); });
        }
    }

protected:
    std::vector< std::unique_ptr< TestLogStoreClient > > m_log_store_clients;
    int m_ev_fd;
    iomgr::fd_info* m_ev_fdinfo;

    std::atomic< int64_t > m_pending_issued_records = 0;
    std::atomic< int64_t > m_pending_comp_records = 0;
    std::mutex m_pending_mtx;
    std::condition_variable m_pending_cv;

    static constexpr uint32_t batch_size = 10;
};

TEST_F(LogStoreTest, RandomInsertThenTruncate) {
    LogStoreTest::start_homestore(SDS_OPTIONS["num_devs"].as< uint32_t >(),
                                  SDS_OPTIONS["dev_size_mb"].as< uint64_t >() * 1024 * 1024,
                                  SDS_OPTIONS["num_threads"].as< uint32_t >());
    this->init(SDS_OPTIONS["num_logstores"].as< uint32_t >(), SDS_OPTIONS["num_records"].as< uint32_t >());
    this->kickstart_inserts();
    this->wait_for_inserts();
}

SDS_OPTIONS_ENABLE(logging, test_log_store)
SDS_OPTION_GROUP(test_log_store,
                 (num_threads, "", "num_threads", "number of threads",
                  ::cxxopts::value< uint32_t >()->default_value("2"), "number"),
                 (num_devs, "", "num_devs", "number of devices to create",
                  ::cxxopts::value< uint32_t >()->default_value("2"), "number"),
                 (dev_size_mb, "", "dev_size_mb", "size of each device in MB",
                  ::cxxopts::value< uint64_t >()->default_value("5120"), "number"),
                 (dev_names, "", "dev_names", "Device List instead of default created",
                  ::cxxopts::value< std::string >(), "/dev/nvme5n1,/dev/nvme5n2"),
                 (num_logstores, "", "num_logstores", "number of log stores",
                  ::cxxopts::value< uint32_t >()->default_value("4"), "number"),
                 (num_records, "", "num_records", "number of record to test",
                  ::cxxopts::value< uint32_t >()->default_value("10000"), "number"));

#if 0
void parse() {
    if (SDS_OPTIONS.count("log_mods")) {
        std::regex re("[\\s,]+");
        auto s = SDS_OPTIONS["log_mods"].as< std::string >();
        std::sregex_token_iterator it(s.begin(), s.end(), re, -1);
        std::sregex_token_iterator reg_end;
        for (; it != reg_end; ++it) {
            auto mod_stream = std::istringstream(it->str());
            std::string module_name, module_level;
            getline(mod_stream, module_name, ':');
            auto sym = "module_level_" + module_name;
            if (auto mod_level = (spdlog::level::level_enum*)dlsym(RTLD_DEFAULT, sym.c_str()); nullptr != mod_level) {
                if (getline(mod_stream, module_level, ':')) {
                    *mod_level = (spdlog::level::level_enum)strtol(module_level.data(), nullptr, 0);
                } else {
                    *mod_level = lvl;
                }
                glob_enabled_mods.push_back(module_name);
            } else {
                LOGWARN("Could not load module logger: {}\n{}", module_name, dlerror());
            }
        }
        LOGINFO("Enabled modules:\t{}",
                std::accumulate(glob_enabled_mods.begin(), glob_enabled_mods.end(), std::string("")));
    }
}
#endif

int main(int argc, char* argv[]) {
    srand(time(0));
    testing::InitGoogleTest(&argc, argv);
    SDS_OPTIONS_LOAD(argc, argv, logging, test_log_store);
    sds_logging::SetLogger("test_log_store");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    return RUN_ALL_TESTS();

#if 0
    home_log_store_mgr.start(true);
    auto ls = home_log_store_mgr.create_new_log_store();

    std::atomic< int64_t > pending_count = 0;
    std::mutex _mtx;
    std::condition_variable _cv;
    std::vector< std::string > s;
    s.reserve(200);

    for (auto i = 0; i < 195; i++) {
        ++pending_count;
        s.push_back(std::to_string(i));
        ls->write_async(i, {(uint8_t*)s.back().c_str(), (uint32_t)s.back().size() + 1}, nullptr,
                        [&pending_count, &_cv](logstore_seq_num_t seq_num, bool success, void* ctx) {
                            LOGINFO("Completed write of seq_num {} ", seq_num);
                            if (--pending_count == 0) { _cv.notify_all(); }
                        });
    }

    {
        std::unique_lock< std::mutex > lk(_mtx);
        _cv.wait(lk, [&] { return (pending_count == 0); });
    }
#endif
}