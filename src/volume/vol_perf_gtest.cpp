#include <gtest/gtest.h>
#include <iomgr/iomgr.hpp>
#include <sds_logging/logging.h>
#include <sds_options/options.h>
#include <metrics/metrics.hpp>
#include <main/vol_interface.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <fstream>
#include <iostream>
#include <string>
#include <homeds/bitmap/bitset.hpp>
#include <atomic>
#include <string>
#include <utility/thread_buffer.hpp>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
extern "C" {
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timeb.h>
}

using namespace homestore;

THREAD_BUFFER_INIT;

/************************** GLOBAL VARIABLES ***********************/

uint64_t preload_writes = 100000000; // with 4k write it is 400 G insertion

uint64_t max_disk_capacity;
#define MAX_DEVICES 2
std::vector< std::string > dev_names;
std::string names[4] = {"/tmp/perf_file1", "/tmp/perf_file2", "/tmp/perf_file3", "/tmp/perf_file4"};

uint64_t max_vols = 1;
uint64_t run_time;
uint64_t num_threads;
uint64_t queue_depth;
uint32_t read_p;
uint32_t io_size;
bool is_file = false;
bool ref_cnt = false;
constexpr auto Ki = 1024ull;
constexpr auto Mi = Ki * Ki;
constexpr auto Gi = Ki * Mi;
constexpr uint64_t max_io_size = 1 * Mi;
uint64_t max_outstanding_ios;
uint64_t match_cnt = 0;
uint64_t cache_size = 0;
std::atomic< uint64_t > write_cnt(0);
std::atomic< uint64_t > read_cnt(0);
std::atomic< uint64_t > read_err_cnt(0);
std::atomic< size_t > outstanding_ios(0);
bool disk_init = true;
using log_level = spdlog::level::level_enum;
SDS_LOGGING_INIT(HOMESTORE_LOG_MODS)

/**************** Common class created for all tests ***************/

class test_ep : public iomgr::EndPoint {
public:
    test_ep(std::shared_ptr< iomgr::ioMgr > iomgr) : iomgr::EndPoint(iomgr) {}
    void init_local() override {}
    void shutdown_local() override {}
    void print_perf() override {}
};

uint64_t req_cnt = 0;
uint64_t req_free_cnt = 0;
class IOTest : public ::testing::Test {
    struct req : vol_interface_req {
        ssize_t size;
        off_t offset;
        uint64_t lba;
        uint32_t nblks;
        int fd;
        bool is_read;
        uint64_t cur_vol;
        req() { req_cnt++; }
        virtual ~req() { req_free_cnt++; }
    };

protected:
    std::shared_ptr< iomgr::ioMgr > iomgr_obj;
    bool init;
    std::vector< VolumePtr > vol;
    std::vector< homeds::Bitset* > m_vol_bm;
    std::vector< uint64_t > max_vol_blks;
    std::atomic< uint64_t > vol_cnt;
    test_ep* ep;
    int ev_fd;
    std::condition_variable m_cv;
    std::mutex m_mutex;
    uint64_t cur_vol;
    Clock::time_point start_time;
    Clock::time_point end_time;
    std::vector< dev_info > device_info;
    uint64_t max_vol_size;
    std::atomic< int > rdy_state;
    bool is_abort;
    bool preload_done;
    Clock::time_point print_startTime;

public:
    IOTest() : vol(max_vols), m_vol_bm(max_vols), max_vol_blks(max_vols), device_info(0), is_abort(false) {
        vol_cnt = 0;
        cur_vol = 0;
        max_vol_size = 0;
        print_startTime = Clock::now();
        preload_done = false;
    }

    void print() {}

    void remove_files() {
        remove("/tmp/perf_file1");
        remove("/tmp/perf_file2");
        remove("/tmp/perf_file3");
        remove("tmp/perf_file4");
    }

    void start_homestore() {
        /* start homestore */
        for (uint32_t i = 0; i < dev_names.size(); i++) {
            dev_info temp_info;
            temp_info.dev_names = dev_names[i];
            device_info.push_back(temp_info);
        }
        /* Don't populate the whole disks. Only 80 % of it */
        max_vol_size = (80 * max_disk_capacity) / (100 * max_vols);

        iomgr_obj = std::make_shared< iomgr::ioMgr >(2, num_threads);
        init_params params;
        params.flag = homestore::io_flag::DIRECT_IO;
        params.min_virtual_page_size = 4096;
        params.cache_size = cache_size * 1024 * 1024 * 1024ul;
        params.disk_init = init;
        params.devices = device_info;
        params.is_file = is_file ? true : false;
        params.iomgr = iomgr_obj;
        params.init_done_cb = std::bind(&IOTest::init_done_cb, this, std::placeholders::_1, std::placeholders::_2);
        params.vol_mounted_cb = std::bind(&IOTest::vol_mounted_cb, this, std::placeholders::_1, std::placeholders::_2);
        params.vol_state_change_cb = std::bind(&IOTest::vol_state_change_cb, this, std::placeholders::_1,
                                               std::placeholders::_2, std::placeholders::_3);
        params.vol_found_cb = std::bind(&IOTest::vol_found_cb, this, std::placeholders::_1);
        boost::uuids::string_generator gen;
        params.system_uuid = gen("01970496-0262-11e9-8eb2-f2801f1b9fd1");
        VolInterface::init(params);
    }

    bool vol_found_cb(boost::uuids::uuid uuid) {
        assert(!init);
        return true;
    }

    void vol_mounted_cb(const VolumePtr& vol_obj, vol_state state) {
        assert(!init);
        int cnt = vol_cnt.fetch_add(1, std::memory_order_relaxed);
        vol_init(cnt, vol_obj);
        auto cb = [this](boost::intrusive_ptr< vol_interface_req > vol_req) { process_completions(vol_req); };
        VolInterface::get_instance()->attach_vol_completion_cb(vol_obj, cb);
    }

    void vol_init(int cnt, const VolumePtr& vol_obj) {
        vol[cnt] = vol_obj;
        max_vol_blks[cnt] = VolInterface::get_instance()->get_vol_capacity(vol_obj).initial_total_size /
            VolInterface::get_instance()->get_page_size(vol_obj);
        m_vol_bm[cnt] = new homeds::Bitset(max_vol_blks[cnt]);
        assert(VolInterface::get_instance()->get_vol_capacity(vol_obj).initial_total_size == max_vol_size);
    }

    void vol_state_change_cb(const VolumePtr& vol, vol_state old_state, vol_state new_state) { assert(0); }

    void create_volume() {

        /* Create a volume */
        for (uint32_t i = 0; i < max_vols; i++) {
            vol_params params;
            params.page_size = 4096;
            params.size = max_vol_size;
            params.io_comp_cb = ([this](const vol_interface_req_ptr& vol_req) { process_completions(vol_req); });
            params.uuid = boost::uuids::random_generator()();
            std::string name = "/tmp/vol" + std::to_string(i);
            memcpy(params.vol_name, name.c_str(), (name.length() + 1));

            auto vol_obj = VolInterface::get_instance()->create_volume(params);
            LOGINFO("Created volume of size: {}", max_vol_size);

            /* open a corresponding file */
            vol_init(vol_cnt, vol_obj);
            ++vol_cnt;
        }
    }

    void init_done_cb(std::error_condition err, const out_params& params) {
        /* create volume */
        rdy_state = 1;
        if (init) {
            create_volume();
        } else {
            assert(vol_cnt == max_vols);
            LOGINFO("init completed");
        }
        ev_fd = eventfd(0, EFD_NONBLOCK);

        iomgr_obj->add_fd(
            ev_fd, [this](auto fd, auto cookie, auto event) { process_ev_common(fd, cookie, event); }, EPOLLIN, 9,
            nullptr);
        ep = new test_ep(iomgr_obj);
        iomgr_obj->add_ep(ep);
        iomgr_obj->start();
        outstanding_ios = 0;
        uint64_t temp = 1;
        [[maybe_unused]] auto wsize = write(ev_fd, &temp, sizeof(uint64_t));
        return;
    }

    void process_ev_common(int fd, void* cookie, int event) {
        uint64_t temp;
        [[maybe_unused]] auto rsize = read(ev_fd, &temp, sizeof(uint64_t));

        iomgr_obj->process_done(fd, event);
        if (outstanding_ios.load() < max_outstanding_ios && get_elapsed_time(start_time) < run_time) {
            /* raise an event */
            iomgr_obj->fd_reschedule(fd, event);
        }

        if (!preload_done && write_cnt < preload_writes) {
            while (outstanding_ios < max_outstanding_ios) {
                random_write();
            }
            return;
        } else if (!preload_done) {
            preload_done = true;
            start_time = Clock::now();
            LOGINFO("io started");
            write_cnt = 1;
            read_cnt = 1;
        }
        if (write_cnt == 1 && !preload_done) {
            LOGINFO("preload started");
        }

        while (outstanding_ios < max_outstanding_ios) {
            {
                std::unique_lock< std::mutex > lk(m_mutex);
                if (!rdy_state) {
                    return;
                }
            }

            if (((read_cnt * 100) / (write_cnt + read_cnt)) < read_p) {
                random_read();
            } else {
                random_write();
            }
        }
    }

    void random_write() {
        /* XXX: does it really matter if it is atomic or not */
        int cur = ++cur_vol % max_vols;
        uint64_t lba = 0;
        uint64_t nblks = 0;
        if (!io_size) {
            uint64_t max_blks = max_io_size / VolInterface::get_instance()->get_page_size(vol[cur]);
            nblks = rand() % max_blks;
            if (nblks == 0) {
                nblks = 1;
            }
        } else {
            nblks = (io_size * 1024) / (VolInterface::get_instance()->get_page_size(vol[cur]));
        }
        lba = rand() % (max_vol_blks[cur % max_vols] - nblks);
        m_vol_bm[cur]->set_bits(lba, nblks);
        uint8_t* buf = nullptr;
        uint64_t size = nblks * VolInterface::get_instance()->get_page_size(vol[cur]);
        auto ret = posix_memalign((void**)&buf, 4096, size);
        if (ret) {
            assert(0);
        }
        /* buf will be owned by homestore after sending the IO. so we need to allocate buf1 which will be used to
         * write to a file after ios are completed.
         */
        assert(buf != nullptr);

        boost::intrusive_ptr< req > req(new struct req());
        req->lba = lba;
        req->nblks = nblks;
        req->size = size;
        req->offset = lba * VolInterface::get_instance()->get_page_size(vol[cur]);
        req->is_read = false;
        req->cur_vol = cur;
        ++outstanding_ios;
        ++write_cnt;
        auto ret_io = VolInterface::get_instance()->write(vol[cur], lba, buf, nblks, req);
        if (ret_io != no_error) {
            assert(0);
            free(buf);
            outstanding_ios--;
            LOGINFO("write io failure");
            m_vol_bm[cur]->reset_bits(lba, nblks);
        }
        LOGDEBUG("Wrote {} {} ", lba, nblks);
    }

    void random_read() {
        /* XXX: does it really matter if it is atomic or not */
        int cur = ++cur_vol % max_vols;
        uint64_t lba = 0;
        uint32_t nblks = 0;
        if (!io_size) {
            uint64_t max_blks = max_io_size / VolInterface::get_instance()->get_page_size(vol[cur]);
            nblks = rand() % max_blks;
            if (nblks == 0) {
                nblks = 1;
            }
        } else {
            nblks = (io_size * 1024) / (VolInterface::get_instance()->get_page_size(vol[cur]));
        }
        lba = rand() % (max_vol_blks[cur % max_vols] - nblks);
        auto b = m_vol_bm[cur]->get_next_contiguous_n_reset_bits(lba, nblks);
        if (b.nbits == 0) {
            return;
        }

        lba = b.start_bit;
        read_vol(cur, lba, nblks);
        LOGDEBUG("Read {} {} ", lba, nblks);
    }

    void read_vol(uint32_t cur, uint64_t lba, uint64_t nblks) {
        uint64_t size = nblks * VolInterface::get_instance()->get_page_size(vol[cur]);
        boost::intrusive_ptr< req > req(new struct req());
        req->lba = lba;
        req->nblks = nblks;
        req->is_read = true;
        req->size = size;
        req->offset = lba * VolInterface::get_instance()->get_page_size(vol[cur]);
        req->cur_vol = cur;
        outstanding_ios++;
        read_cnt++;
        auto ret_io = VolInterface::get_instance()->read(vol[cur], lba, nblks, req);
        if (ret_io != no_error) {
            outstanding_ios--;
            read_err_cnt++;
            LOGINFO("read io failure");
        }
    }

    void process_completions(const vol_interface_req_ptr& vol_req) {
        /* raise an event */
        boost::intrusive_ptr< req > req = boost::static_pointer_cast< struct req >(vol_req);
        static uint64_t print_time = 30;
        uint64_t temp = 1;
        --outstanding_ios;
        auto elapsed_time = get_elapsed_time(print_startTime);
        if (elapsed_time > print_time) {
            auto temp_write = write_cnt.load();
            auto temp_read = read_cnt.load();
            LOGINFO("write ios cmpled {}", temp_write);
            LOGINFO("read ios cmpled {}", temp_read);
            print_startTime = Clock::now();
        }

        LOGTRACE("IO DONE, req_id={}, outstanding_ios={}", vol_req->request_id, outstanding_ios.load());
        if (write_cnt.load() % 100000 == 0 && ref_cnt) {
            sisl::ObjCounterRegistry::foreach ([](const std::string& name, int64_t created, int64_t alive) {
                LOGINFO("ObjLife {}: created={} alive={}", name, created, alive);
            });
        }
        if (preload_done && get_elapsed_time(start_time) > run_time) {
            LOGINFO("ios cmpled {}. waiting for outstanding ios to be completed", write_cnt.load());
            if (is_abort) {
                abort();
            }
            std::unique_lock< std::mutex > lk(m_mutex);
            rdy_state = 0;
            if (outstanding_ios.load() == 0) {
                end_time = Clock::now();
                notify_cmpl();
            }
        } else {
            [[maybe_unused]] auto rsize = read(ev_fd, &temp, sizeof(uint64_t));
            uint64_t size = write(ev_fd, &temp, sizeof(uint64_t));
            if (size != sizeof(uint64_t)) {
                assert(0);
            }
        }
    }

    uint64_t get_elapsed_time(Clock::time_point start_time) {
        std::chrono::seconds sec = std::chrono::duration_cast< std::chrono::seconds >(Clock::now() - start_time);
        return sec.count();
    }

    void notify_cmpl() { m_cv.notify_all(); }

    void wait_cmpl() {
        std::unique_lock< std::mutex > lk(m_mutex);
        m_cv.wait(lk);
    }
};

/************************** Test cases ****************************/

/*********** Below Tests init the systems. Should exit with clean shutdown *************/

TEST_F(IOTest, normal_random_io_test) {
    /* fork a new process */
    this->init = disk_init;
    /* child process */
    this->start_homestore();
    this->wait_cmpl();
    LOGINFO("Metrics for this run: {}", sisl::MetricsFarm::getInstance().get_result_in_json().dump(4));
    LOGINFO("write_cnt {}", write_cnt);
    LOGINFO("read_cnt {}", read_cnt);
    uint64_t time_dur = (std::chrono::duration_cast< std::chrono::seconds >(end_time - start_time)).count();
    LOGINFO("total time {} seconds", time_dur);
    LOGINFO("total ios {}", (write_cnt + read_cnt));
    LOGINFO("iops {}", ((write_cnt + read_cnt) / time_dur));
}

/************************* CLI options ***************************/

SDS_OPTION_GROUP(perf_test_volume,
                 (run_time, "", "run_time", "run time for io", ::cxxopts::value< uint32_t >()->default_value("30"),
                  "seconds"),
                 (num_threads, "", "num_threads", "num threads for io",
                  ::cxxopts::value< uint32_t >()->default_value("8"), "number"),
                 (queue_depth, "", "queue_depth", "io queue depth per thread",
                  ::cxxopts::value< uint32_t >()->default_value("1024"), "number"),
                 (read_percent, "", "read_percent", "read in percentage",
                  ::cxxopts::value< uint32_t >()->default_value("50"), "percentage"),
                 (device_list, "", "device_list", "List of device paths",
                  ::cxxopts::value< std::vector< std::string > >(), "path [...]"),
                 (io_size, "", "io_size", "size of io in KB", ::cxxopts::value< uint32_t >()->default_value("64"),
                  "size of io in KB"),
                 (cache_size, "", "cache_size", "size of cache in GB",
                  ::cxxopts::value< uint32_t >()->default_value("4"), "size of cache in GB"),
                 (is_file, "", "is_file", "is_it file", ::cxxopts::value< uint32_t >()->default_value("0"),
                  "is it file"),
                 (init, "", "init", "init", ::cxxopts::value< uint32_t >()->default_value("1"), 
                  "init"), 
                 (preload_writes, "", "preload_writes", "preload_writes", ::cxxopts::value< uint32_t >()->default_value("100000000"), 
                  "preload_writes"), 
                 (ref_cnt, "", "ref_count", "display object life counters",
                  ::cxxopts::value< uint32_t >()->default_value("0"), "display object life counters"))
#define ENABLED_OPTIONS logging, home_blks, perf_test_volume
SDS_OPTIONS_ENABLE(ENABLED_OPTIONS)

/* it will go away once shutdown is implemented correctly */

extern "C" __attribute__((no_sanitize_address)) const char* __asan_default_options() { return "detect_leaks=0"; }

/************************** MAIN ********************************/

/* We can run this target either by using default options which run the normal io tests or by setting different options.
 * Format is
 *   1. ./perf_test_volume --gtest_filter=*random* --run_time=120 --num_threads=16 --queue_depth 8
 *                         --device_list=file1 --device_list=file2 --io_size=8
 */
int main(int argc, char* argv[]) {
    srand(time(0));
    ::testing::GTEST_FLAG(filter) = "*normal_random*";
    testing::InitGoogleTest(&argc, argv);
    SDS_OPTIONS_LOAD(argc, argv, ENABLED_OPTIONS)
    sds_logging::SetLogger("perf_test_volume");
    spdlog::set_pattern("[%D %T.%f%z] [%^%l%$] [%t] %v");

    run_time = SDS_OPTIONS["run_time"].as< uint32_t >();
    num_threads = SDS_OPTIONS["num_threads"].as< uint32_t >();
    queue_depth = SDS_OPTIONS["queue_depth"].as< uint32_t >();
    max_outstanding_ios = num_threads * queue_depth;
    read_p = SDS_OPTIONS["read_percent"].as< uint32_t >();
    io_size = SDS_OPTIONS["io_size"].as< uint32_t >();
    if (SDS_OPTIONS.count("device_list")) {
        dev_names = SDS_OPTIONS["device_list"].as< std::vector< std::string > >();
    }
    cache_size = SDS_OPTIONS["cache_size"].as< uint32_t >();
    preload_writes = SDS_OPTIONS["preload_writes"].as< uint32_t >();
    is_file = SDS_OPTIONS["is_file"].as< uint32_t >();
    ref_cnt = SDS_OPTIONS["ref_count"].as< uint32_t >();
    disk_init = SDS_OPTIONS["init"].as< uint32_t >() ? true : false;


    if (dev_names.size() == 0) {
        LOGINFO("creating files");
        for (uint32_t i = 0; i < MAX_DEVICES; i++) {
            if (disk_init) {
                std::ofstream ofs(names[i].c_str(), std::ios::binary | std::ios::out);
                ofs.seekp(10 * Gi - 1);
                ofs.write("", 1);
                ofs.close();
            }
            dev_names.push_back(names[i]);
        }
        is_file = 1;
    }

    for (uint32_t i = 0; i < dev_names.size(); ++i) {
        auto fd = open(dev_names[0].c_str(), O_RDWR);
        size_t devsize = 0;
        if (!is_file) {
            if (ioctl(fd, BLKGETSIZE64, &devsize) < 0) {
                LOGINFO("couldn't get size");
                assert(0);
                abort();
            }
        } else {
            struct stat buf;
            if (fstat(fd, &buf) < 0) {
                assert(0);
                throw std::system_error(errno, std::system_category(), "error while getting size of the device");
            }
            devsize = buf.st_size;
        }
        max_disk_capacity += devsize;
    }
    return RUN_ALL_TESTS();
}
