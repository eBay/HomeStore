/*!
    @file   vol_gtest.cpp
    Volume Google Tests
 */
#include <gtest/gtest.h>
#include <sds_logging/logging.h>
#include <sds_options/options.h>
#include <api/vol_interface.hpp>
#include <iomgr/iomgr.hpp>
#include <iomgr/aio_drive_interface.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <fstream>
#include <iostream>
#include <string>
#include <engine/homeds/bitmap/bitset.hpp>
#include <atomic>
#include <string>
#include <utility/thread_buffer.hpp>
#include <chrono>
#include <thread>
#include <boost/filesystem.hpp>
#include <fds/utils.hpp>
extern "C" {
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timeb.h>
}

using namespace homestore;
using namespace flip;

THREAD_BUFFER_INIT;
RCU_REGISTER_INIT;

/************************** GLOBAL VARIABLES ***********************/

#define MAX_DEVICES 2
#define HOMEBLKS_SB_FLAGS_SHUTDOWN 0x00000001UL

#define STAGING_VOL_PREFIX "staging"
#define VOL_PREFIX "test_files/vol"

constexpr auto Ki = 1024ull;
constexpr auto Mi = Ki * Ki;
constexpr auto Gi = Ki * Mi;

using log_level = spdlog::level::level_enum;
SDS_LOGGING_INIT(HOMESTORE_LOG_MODS)

enum class load_type_t {
    random = 0,
    same = 1,
    sequential = 2,
};

struct TestCfg {
    std::array< std::string, 4 > default_names = {"test_files/vol_file1", "test_files/vol_file2",
                                                  "test_files/vol_file3", "test_files/vol_file4"};
    std::vector< std::string > dev_names;
    uint64_t max_vols = 50;
    uint64_t max_num_writes = 100000;
    uint64_t run_time;
    uint64_t num_threads;

    uint64_t max_io_size = 1 * Mi;
    uint64_t max_outstanding_ios = 64u;
    uint64_t max_disk_capacity = 10 * Gi;

    uint32_t atomic_phys_page_size = 512;
    uint32_t vol_page_size = 4096;
    uint32_t phy_page_size = 4096;
    uint32_t mem_btree_page_size = 4096;

    bool can_delete_volume = false;
    bool read_enable = true;
    bool enable_crash_handler = true;
    bool verify_hdr = true;
    bool verify_data = true;
    bool read_verify = false;
    bool remove_file = true;
    bool verify_only = false;
    bool is_abort = false;
    load_type_t load_type = load_type_t::random;
    uint32_t flip_set = 0;                 // TODO: change this to enum
    io_flag io_flags = io_flag::DIRECT_IO; // 2: READ_ONLY 1: DIRECT_IO, 0: BUFFERED_IO;

    homestore::vol_state expected_vol_state = homestore::vol_state::ONLINE; // TODO: Move to separate job config section
    bool init = true;
    bool expect_io_error = false;
    bool expected_init_fail = false;
    int disk_replace_cnt = 0;
    bool precreate_volume = true;
};

struct TestOutput {
    std::atomic< uint64_t > match_cnt = 0;
    std::atomic< uint64_t > hdr_only_match_cnt = 0;

    std::atomic< uint64_t > write_cnt = 0;
    std::atomic< uint64_t > read_cnt = 0;
    std::atomic< uint64_t > read_err_cnt = 0;
    std::atomic< uint64_t > vol_create_cnt = 0;
    std::atomic< uint64_t > vol_del_cnt = 0;
    std::atomic< uint64_t > vol_mounted_cnt = 0;
    std::atomic< uint64_t > vol_indx = 0;

    void print(const char* work_type) const {
        uint64_t v;
        fmt::memory_buffer buf;
        if ((v = write_cnt.load())) fmt::format_to(buf, "write_cnt={} ", v);
        if ((v = read_cnt.load())) fmt::format_to(buf, "read_cnt={} ", v);
        if ((v = read_err_cnt.load())) fmt::format_to(buf, "read_err_cnt={} ", v);
        if ((v = match_cnt.load())) fmt::format_to(buf, "match_cnt={} ", v);
        if ((v = hdr_only_match_cnt.load())) fmt::format_to(buf, "hdr_only_match_cnt={} ", v);
        if ((v = vol_create_cnt.load())) fmt::format_to(buf, "vol_create_cnt={} ", v);
        if ((v = vol_del_cnt.load())) fmt::format_to(buf, "vol_del_cnt={} ", v);
        if ((v = vol_mounted_cnt.load())) fmt::format_to(buf, "vol_mounted_cnt={} ", v);
        if ((v = vol_indx.load())) fmt::format_to(buf, "vol_indx={} ", v);

        LOGINFO("{} Output: [{}]", work_type, buf.data());
    }
};

class VolTest;
struct io_req_t;
class TestJob {
public:
    TestJob(VolTest* test) : m_voltest(test), m_start_time(Clock::now()) {}
    virtual void run_one_iteration() = 0;
    virtual bool on_one_iteration_completed(const boost::intrusive_ptr< io_req_t >& req) = 0;
    virtual bool time_to_stop() const = 0;
    virtual bool is_async_job() const = 0;
    virtual std::string job_name() const = 0;

    virtual void new_thread_executing() {
        std::unique_lock< std::mutex > lk(m_mutex);
        m_job_started = true;
        ++m_threads_executing_job;
    }

    virtual bool thread_done_executing() {
        std::unique_lock< std::mutex > lk(m_mutex);
        if (--m_threads_executing_job == 0) {
            m_cv.notify_all();
            return true;
        }
        return false;
    }

    virtual void wait_for_completion() {
        std::unique_lock< std::mutex > lk(m_mutex);
        m_cv.wait(lk, [this] { return (is_job_done()); });
        m_job_started = false;
    }

    virtual bool is_job_done() { return (m_job_started && (m_threads_executing_job == 0)); }

protected:
    VolTest* m_voltest;
    std::mutex m_mutex;
    std::condition_variable m_cv;
    Clock::time_point m_start_time;
    bool m_job_started = false;
    int64_t m_threads_executing_job = 0;
};

struct vol_info_t {
    VolumePtr vol;
    boost::uuids::uuid uuid;
    int fd;
    std::mutex vol_mutex;
    std::unique_ptr< homeds::Bitset > m_vol_bm;
    uint64_t max_vol_blks;
    uint64_t cur_checkpoint;
    std::atomic< uint64_t > start_lba = 0;
    std::atomic< uint64_t > start_large_lba = 0;
    std::atomic< uint64_t > num_io = 0;
    size_t vol_idx = 0;

    vol_info_t() = default;
    ~vol_info_t() = default;
};

struct io_req_t : public vol_interface_req {
    ssize_t size;
    off_t offset;
    int fd;
    uint8_t* validate_buf;
    bool is_read;
    uint64_t cur_vol;
    std::shared_ptr< vol_info_t > vol_info;
    bool done = false;

    io_req_t(const std::shared_ptr< vol_info_t >& vinfo, void* wbuf, uint64_t lba, uint32_t nblks) :
            vol_interface_req(wbuf, lba, nblks),
            vol_info(vinfo) {
        auto page_size = VolInterface::get_instance()->get_page_size(vinfo->vol);
        size = nblks * page_size;
        offset = lba * page_size;
        fd = vinfo->fd;
        is_read = (wbuf == nullptr);
        cur_vol = vinfo->vol_idx;

        auto ret = posix_memalign((void**)&validate_buf, 4096, size);
        assert(!ret);
        assert(validate_buf != nullptr);
        if (wbuf) memcpy(validate_buf, wbuf, size);
    }

    virtual ~io_req_t() { free(validate_buf); }
};

TestCfg tcfg;

/**************** Common class created for all tests ***************/
class VolTest : public ::testing::Test {
    friend class TestJob;
    friend class VolCreateDeleteJob;
    friend class IOTestJob;
    friend class VolVerifyJob;

#if 0
    /* Simulated a target that drives the workload */
    class TestTargetInterface : public iomgr::IOInterface {
    public:
        TestTargetInterface() : iomgr::IOInterface() {}
        virtual void on_io_thread_start(iomgr::ioMgrThreadContext* ctx) override{};
        virtual void on_io_thread_stopped(iomgr::ioMgrThreadContext* ctx) override{};
    };

    /* Simulating a test target - similar to SCST or NVMEoF target */
    class TestTarget {
    public:
        TestTarget(VolTest* test) { m_io_test = test; }
        void init() {
            m_iface = std::make_shared< VolTest::TestTargetInterface >();
            iomanager.add_interface(m_iface);

            m_ev_fd = eventfd(0, EFD_NONBLOCK);
            m_ev_fdinfo = iomanager.add_fd(m_iface.get(), m_ev_fd, bind_this(TestTarget::on_new_io_request, 3), EPOLLIN,
                                           9, nullptr);
        }

        void shutdown() { iomanager.remove_fd(m_iface.get(), m_ev_fdinfo); }
        void kickstart_io() {
            uint64_t temp = 1;
            [[maybe_unused]] auto wsize = write(m_ev_fd, &temp, sizeof(uint64_t));
        }

        void on_new_io_request(int fd, void* cookie, int event) {
            uint64_t temp;
            [[maybe_unused]] auto rsize = read(m_ev_fd, &temp, sizeof(uint64_t));
            m_io_test->process_new_request();
        }

        void io_request_done() {
            uint64_t temp = 1;
            [[maybe_unused]] auto wsize = write(m_ev_fd, &temp, sizeof(uint64_t));
        }

    private:
        int m_ev_fd;
        std::shared_ptr< iomgr::fd_info > m_ev_fdinfo;
        std::shared_ptr< TestTargetInterface > m_iface;
        VolTest* m_io_test;
    };
#endif

protected:
    std::atomic< size_t > outstanding_ios;
    TestOutput output;

    std::vector< std::shared_ptr< vol_info_t > > vol_info;

    // std::condition_variable m_cv;
    std::condition_variable m_init_done_cv;
    std::mutex m_mutex;
    void* init_buf = nullptr;

    // uint64_t cur_vol;
    // Clock::time_point startTime;
    std::vector< dev_info > device_info;
    uint64_t max_vol_size;
    // bool verify_done;
    // bool move_verify_to_done;
    // bool vol_create_del_test;

    // Clock::time_point print_startTime;

    // std::atomic< bool > io_stalled = false;
    // bool expected_init_fail = false;

public:
    static thread_local uint32_t _n_completed_this_thread;

    VolTest() : vol_info(0), device_info(0) {
        // cur_vol = 0;
        max_vol_size = 0;
        // verify_done = false;
        // vol_create_del_test = false;
        // move_verify_to_done = false;
        // print_startTime = Clock::now();

        // outstanding_ios = 0;
        srandom(time(NULL));
    }

    ~VolTest() {
        if (init_buf) { free(init_buf); }
    }

    void remove_files() {
        /* no need to delete the user created file/disk */
        if (tcfg.dev_names.size() == 0) {
            for (auto& n : tcfg.default_names) {
                remove(n.c_str());
            }
        }

        for (uint32_t i = 0; i < tcfg.max_vols; i++) {
            std::string name = VOL_PREFIX + std::to_string(i);
            remove(name.c_str());
            name = name + STAGING_VOL_PREFIX;
            remove(name.c_str());
        }
    }

    void start_homestore() {
        uint64_t max_capacity = 0;

        /* start homestore */
        /* create files */
        struct stat st;
        if (stat("test_files", &st) == -1) { mkdir("test_files", 0700); }

        /* create files */
        if (tcfg.dev_names.size() != 0) {
            for (uint32_t i = 0; i < tcfg.dev_names.size(); i++) {
                dev_info temp_info;
                temp_info.dev_names = tcfg.dev_names[i];
                /* we use this capacity to calculate volume size */
                max_capacity += tcfg.max_disk_capacity;
                device_info.push_back(temp_info);
            }
        } else {
            for (uint32_t i = 0; i < MAX_DEVICES; i++) {
                dev_info temp_info;
                temp_info.dev_names = tcfg.default_names[i];
                device_info.push_back(temp_info);
                if (tcfg.init || tcfg.disk_replace_cnt > 0) {
                    if (!tcfg.init) { remove(tcfg.default_names[i].c_str()); }
                    std::ofstream ofs(tcfg.default_names[i].c_str(), std::ios::binary | std::ios::out);
                    ofs.seekp(tcfg.max_disk_capacity - 1);
                    ofs.write("", 1);
                    ofs.close();
                    --tcfg.disk_replace_cnt;
                }
                max_capacity += tcfg.max_disk_capacity;
            }
        }
        /* Don't populate the whole disks. Only 80 % of it */
        max_vol_size = (60 * max_capacity) / (100 * tcfg.max_vols);

        iomanager.start(1 /* total interfaces */, tcfg.num_threads, bind_this(VolTest::handle_iothread_msg, 1));
        iomanager.add_drive_interface(
            std::dynamic_pointer_cast< iomgr::DriveInterface >(std::make_shared< iomgr::AioDriveInterface >()),
            true /* is_default */);
        // m_tgt.init();

        init_params params;
        params.open_flags = tcfg.io_flags;
        params.min_virtual_page_size = tcfg.vol_page_size;
        params.cache_size = 4 * 1024 * 1024 * 1024ul;
        params.disk_init = tcfg.init;
        params.devices = device_info;
        params.is_file = tcfg.dev_names.size() ? false : true;
        params.init_done_cb = bind_this(VolTest::init_done_cb, 2);
        params.vol_mounted_cb = bind_this(VolTest::vol_mounted_cb, 2);
        params.vol_state_change_cb = bind_this(VolTest::vol_state_change_cb, 3);
        params.vol_found_cb = bind_this(VolTest::vol_found_cb, 1);
        params.end_of_batch_cb = bind_this(VolTest::process_end_of_batch, 1);

        params.disk_attr = disk_attributes();
        params.disk_attr->phys_page_size = tcfg.phy_page_size;
        params.disk_attr->align_size = 4096;
        params.disk_attr->atomic_phys_page_size = tcfg.atomic_phys_page_size;

        boost::uuids::string_generator gen;
        params.system_uuid = gen("01970496-0262-11e9-8eb2-f2801f1b9fd1");
        VolInterface::init(params);
    }

    bool fix_vol_mapping_btree() {
        /* fix all volumes mapping btrees */
        for (uint64_t i = 0; i < tcfg.max_vols; ++i) {
            auto vol_ptr = vol_info[i]->vol;
            auto ret = VolInterface::get_instance()->fix_tree(vol_ptr, true /* verify */);
            if (ret == false) {
                LOGERROR("fix_tree of vol: {} failed!", VolInterface::get_instance()->get_name(vol_ptr));
                return false;
            }
        }
        return true;
    }

    void move_vol_to_offline() {
        /* move all volumes to offline */
        for (uint64_t i = 0; i < tcfg.max_vols; ++i) {
            VolInterface::get_instance()->vol_state_change(vol_info[i]->vol, homestore::vol_state::OFFLINE);
        }
    }

    void move_vol_to_online() {
        /* move all volumes to online */
        for (uint64_t i = 0; i < tcfg.max_vols; ++i) {
            VolInterface::get_instance()->vol_state_change(vol_info[i]->vol, homestore::vol_state::ONLINE);
        }
        /* start ios */
        // m_tgt.io_request_done();
    }

    bool vol_found_cb(boost::uuids::uuid uuid) {
        assert(!tcfg.init);
        return true;
    }

    void vol_mounted_cb(const VolumePtr& vol_obj, vol_state state) {
        assert(!tcfg.init);
        int cnt = output.vol_mounted_cnt.fetch_add(1, std::memory_order_relaxed);
        vol_init(vol_obj);
        VolInterface::get_instance()->attach_vol_completion_cb(vol_obj,
                                                               bind_this(VolTest::process_multi_completions, 1));
        VolInterface::get_instance()->attach_end_of_batch_cb(bind_this(VolTest::process_end_of_batch, 1));
        assert(state == tcfg.expected_vol_state);
        if (tcfg.expected_vol_state == homestore::vol_state::DEGRADED ||
            tcfg.expected_vol_state == homestore::vol_state::OFFLINE) {
            VolInterface::get_instance()->vol_state_change(vol_obj, vol_state::ONLINE);
        }
    }

    void vol_init(const VolumePtr& vol_obj) {
        std::string file_name = std::string(VolInterface::get_instance()->get_name(vol_obj));
        std::string staging_file_name = file_name + STAGING_VOL_PREFIX;

        std::shared_ptr< vol_info_t > info = std::make_shared< vol_info_t >();
        info->vol = vol_obj;
        info->uuid = VolInterface::get_instance()->get_uuid(vol_obj);
        info->fd = open(file_name.c_str(), O_RDWR);
        info->max_vol_blks =
            VolInterface::get_instance()->get_size(vol_obj) / VolInterface::get_instance()->get_page_size(vol_obj);
        info->m_vol_bm = std::make_unique< homeds::Bitset >(info->max_vol_blks);
        info->cur_checkpoint = 0;

        assert(info->fd > 0);

        {
            std::unique_lock< std::mutex > lk(m_mutex);
            vol_info.push_back(info);
            info->vol_idx = vol_info.size();
        }
    }

    void vol_state_change_cb(const VolumePtr& vol, vol_state old_state, vol_state new_state) {
        assert(new_state == homestore::vol_state::FAILED);
    }

    void create_volume() {
        static std::atomic< uint32_t > _vol_counter = 1;

        /* Create a volume */
        vol_params params;
        params.page_size = tcfg.vol_page_size;
        params.size = max_vol_size;
        params.io_comp_cb = bind_this(VolTest::process_multi_completions, 1);
        params.uuid = boost::uuids::random_generator()();
        std::string name = VOL_PREFIX + std::to_string(_vol_counter.fetch_add(1));
        memcpy(params.vol_name, name.c_str(), (name.length() + 1));

        auto vol_obj = VolInterface::get_instance()->create_volume(params);
        if (vol_obj == nullptr) {
            LOGINFO("creation failed");
            return;
        }
        assert(VolInterface::get_instance()->lookup_volume(params.uuid) == vol_obj);
        /* create file for verification */
        std::ofstream ofs(name, std::ios::binary | std::ios::out);
        ofs.seekp(max_vol_size);
        ofs.write("", 1);
        ofs.close();

        /* create staging file for the outstanding IOs. we compare it from staging file
         * if mismatch fails from main file.
         */
        std::string staging_name = name + STAGING_VOL_PREFIX;
        std::ofstream staging_ofs(staging_name, std::ios::binary | std::ios::out);
        staging_ofs.seekp(max_vol_size);
        staging_ofs.write("", 1);
        staging_ofs.close();

        LOGINFO("Created volume of size: {}", max_vol_size);
        output.vol_create_cnt++;

        /* open a corresponding file */
        vol_init(vol_obj);
    }

    void init_done_cb(std::error_condition err, const out_params& params) {
        /* create volume */
        if (err) {
            assert(tcfg.expected_init_fail);
            {
                std::unique_lock< std::mutex > lk(m_mutex);
                m_init_done_cv.notify_all();
            }
            // notify_cmpl();
            return;
        }
        tcfg.max_io_size = params.max_io_size;
        auto ret = posix_memalign((void**)&init_buf, 4096, tcfg.max_io_size);
        assert(!ret);
        bzero(init_buf, tcfg.max_io_size);
        assert(!tcfg.expected_init_fail);
        if (tcfg.init) {
            if (tcfg.precreate_volume) {
                for (int i = 0; i < (int)tcfg.max_vols; ++i) {
                    create_volume();
                }
                init_files();
            }
            // verify_done = true;
            // startTime = Clock::now();
        } else {
            assert(output.vol_mounted_cnt == tcfg.max_vols);
#if 0
            if (tcfg.verify_hdr || tcfg.verify_data) {
                verify_done = false;
                LOGINFO("init completed, verify started");
            } else {
                verify_done = true;
                startTime = Clock::now();
            }
#endif
        }
        tcfg.max_io_size = params.max_io_size;
        /* TODO :- Rishabh: remove it */
        tcfg.max_io_size = 128 * Ki;
        outstanding_ios = 0;

        std::unique_lock< std::mutex > lk(m_mutex);
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

#if 0
    void vol_create_del() {
        while (1) {
            {
                if (output.vol_create_cnt >= tcfg.max_vols && output.vol_del_cnt >= tcfg.max_vols) {
                    notify_cmpl();
                    return;
                }

                std::unique_lock< std::mutex > lk(m_mutex);
                if (!io_stalled) { outstanding_ios++; }
            }
            create_volume();
            output.vol_create_cnt++;
            if (delete_volume(random() % tcfg.max_vols)) { vol_del_cnt++; }
            outstanding_ios--;
        }
    }

    void kickstart_io() { m_tgt.kickstart_io(); }

    void process_new_request() {
        if (vol_create_del_test) {
            // iomgr_obj->fd_reschedule(fd, event);
            vol_create_del();
            return;
        }

        if ((outstanding_ios.load() >= tcfg.max_outstanding_ios) || io_stalled.load()) {
            // Can't take any more IOs
            return;
        }

        /* raise an event */
        // iomgr_obj->fd_reschedule(fd, event);
        if (!verify_done) {
            verify_vols();
            return;
        }

        size_t cnt = 0;
        /* send 8 IOs in one schedule */
        while (cnt < 8 && outstanding_ios < tcfg.max_outstanding_ios) {
            {
                if (io_stalled) { break; }
            }
            write_io();
            if (tcfg.read_enable) { read_io(); }
            ++cnt;
        }
    }

    void shutdown() {
        // release the ref_count to volumes;

#if 0
        {
            std::unique_lock< std::mutex > lk(m_mutex);
            assert(io_stalled);
            m_cv.wait(lk, [this] { return (outstanding_ios.load() == 0); });
        }
#endif
        m_tgt.shutdown();

        LOGINFO("shutting down homeblks");
        VolInterface::get_instance()->shutdown();

        {
            std::unique_lock< std::mutex > lk(m_mutex);
            vol_info.clear();
        }

        LOGINFO("stopping iomgr");
        iomanager.stop();
    }
#endif

    void shutdown() {
        LOGINFO("shutting down homeblks");
        VolInterface::get_instance()->shutdown();

        {
            std::unique_lock< std::mutex > lk(m_mutex);
            vol_info.clear();
        }

        LOGINFO("stopping iomgr");
        iomanager.stop();
    }

    void handle_iothread_msg(const iomgr::iomgr_msg& msg) {
        if (msg.m_type == iomgr::iomgr_msg_type::CUSTOM_MSG) {
            TestJob* job = (TestJob*)msg.m_data_buf;
            job->new_thread_executing();
            job->run_one_iteration();
            if (job->time_to_stop()) { job->thread_done_executing(); }
        }
    }

    void start_job(TestJob* job, bool wait_for_completion = true) {
        iomanager.send_msg(-1,
                           iomgr::iomgr_msg(iomgr::iomgr_msg_type::CUSTOM_MSG, nullptr, -1, (void*)job, sizeof(*job)));
        if (wait_for_completion) {
            job->wait_for_completion();
            LOGINFO("Job {} is completed", job->job_name());
        }
    }

    void wait_homestore_init_done() {
        std::unique_lock< std::mutex > lk(m_mutex);
        m_init_done_cv.wait(lk);
    }

#if 0
    void wait_cmpl() {
        std::unique_lock< std::mutex > lk(m_mutex);
        if (io_stalled) { return; }
        m_cv.wait(lk);
    }
#endif

    void delete_volumes() {
        uint64_t tot_cap = VolInterface::get_instance()->get_system_capacity().initial_total_size;
        uint64_t used_cap = VolInterface::get_instance()->get_system_capacity().used_total_size;
        assert(used_cap <= tot_cap);
        for (uint64_t i = 0; i < vol_info.size(); ++i) {
            delete_volume(i);
        }
        used_cap = VolInterface::get_instance()->get_system_capacity().used_total_size;
        if (used_cap != 0) {
            // assert(0);
        }
    }

private:
#if 0
    void write_io() {
        switch (tcfg.load_type) {
        case 0:
            random_write();
            break;
        case 1:
            same_write();
            break;
        case 2:
            seq_write();
            break;
        }
    }

    void read_io() {
        switch (tcfg.load_type) {
        case 0:
            random_read();
            break;
        case 1:
            same_read();
            break;
        }
    }
#endif

    void init_files() {
        /* initialize the file */
        for (uint32_t i = 0; i < tcfg.max_vols; ++i) {
            for (off_t offset = 0; offset < (off_t)max_vol_size; offset = offset + tcfg.max_io_size) {
                ssize_t write_size;
                if (offset + tcfg.max_io_size > max_vol_size) {
                    write_size = max_vol_size - offset;
                } else {
                    write_size = tcfg.max_io_size;
                }
                auto ret = pwrite(vol_info[i]->fd, init_buf, write_size, (off_t)offset);
                assert(ret == write_size);
                if (ret != 0) { return; }
            }
        }
    }

#if 0
    void same_write() { write_vol(0, 5, 100); }

    void seq_write() {
        /* XXX: does it really matter if it is atomic or not */
        int cur = ++cur_vol % tcfg.max_vols;
        uint64_t lba;
        uint64_t nblks;
    start:
        /* we won't be writing more then 128 blocks in one io */
        auto vol = vol_info[cur]->vol;
        if (vol == nullptr) { return; }
        if (vol_info[cur]->num_io.fetch_add(1, std::memory_order_acquire) == 1000) {
            nblks = 200;
            lba = (vol_info[cur]->start_large_lba.fetch_add(nblks, std::memory_order_acquire)) %
                (vol_info[cur]->max_vol_blks - nblks);
        } else {
            nblks = 2;
            lba = (vol_info[cur]->start_lba.fetch_add(nblks, std::memory_order_acquire)) %
                (vol_info[cur]->max_vol_blks - nblks);
        }
        if (nblks == 0) { nblks = 1; }

        if (tcfg.load_type != 2) {
            /* can not support concurrent overlapping writes if whole data need to be verified */
            std::unique_lock< std::mutex > lk(vol_info[cur]->vol_mutex);
            /* check if someone is already doing writes/reads */
            if (nblks && vol_info[cur]->m_vol_bm->is_bits_reset(lba, nblks)) {
                vol_info[cur]->m_vol_bm->set_bits(lba, nblks);
            } else {
                goto start;
            }
        }
        write_vol(cur, lba, nblks);
    }

    void same_read() { read_vol(0, 5, 100); }

    void random_write() {
        /* XXX: does it really matter if it is atomic or not */
        int cur = ++cur_vol % tcfg.max_vols;
        uint64_t lba;
        uint64_t nblks;
    start:
        /* we won't be writing more then 128 blocks in one io */
        auto vol = vol_info[cur]->vol;
        if (vol == nullptr) { return; }
        uint64_t max_blks = tcfg.max_io_size / VolInterface::get_instance()->get_page_size(vol);
        // lba: [0, max_vol_blks - max_blks)

        lba = rand() % (vol_info[cur]->max_vol_blks - max_blks);
        // nblks: [1, max_blks]
        nblks = rand() % (max_blks + 1);
        if (nblks == 0) { nblks = 1; }

        if (tcfg.load_type != 2) {
            /* can not support concurrent overlapping writes if whole data need to be verified */
            std::unique_lock< std::mutex > lk(vol_info[cur]->vol_mutex);
            /* check if someone is already doing writes/reads */
            if (nblks && vol_info[cur]->m_vol_bm->is_bits_reset(lba, nblks)) {
                vol_info[cur]->m_vol_bm->set_bits(lba, nblks);
            } else {
                goto start;
            }
        }
        write_vol(cur, lba, nblks);
    }

    void write_vol(uint32_t cur, uint64_t lba, uint64_t nblks) {
        uint8_t* buf = nullptr;
        uint8_t* buf1 = nullptr;
        auto vol = vol_info[cur]->vol;
        if (vol == nullptr) { return; }
        {
            std::unique_lock< std::mutex > lk(m_mutex);
            if (io_stalled) {
                return;
            } else {
                ++outstanding_ios;
            }
        }
        uint64_t size = nblks * VolInterface::get_instance()->get_page_size(vol);
        auto ret = posix_memalign((void**)&buf, 4096, size);
        if (ret) { assert(0); }
        ret = posix_memalign((void**)&buf1, 4096, size);
        assert(!ret);
        /* buf will be owned by homestore after sending the IO. so we need to allocate buf1 which will be used to
         * write to a file after ios are completed.
         */
        assert(buf != nullptr);
        assert(buf1 != nullptr);
        populate_buf(buf, size, lba, cur);

        memcpy(buf1, buf, size);

        io_req_t* req = new io_req_t();
        req->lba = lba;
        req->nblks = nblks;
        req->size = size;
        req->offset = lba * VolInterface::get_instance()->get_page_size(vol);
        req->buf = buf1;
        req->fd = vol_info[cur]->fd;
        req->is_read = false;
        req->cur_vol = cur;

        ++m_voltest->output.write_cnt;
        auto vreq = VolInterface::get_instance()->create_vol_interface_req(buf, lba, nblks, false);
        vreq->cookie = req;
        auto ret_io = VolInterface::get_instance()->write(vol, vreq);
        if (ret_io != no_error) { assert(ret_io == std::errc::no_such_device || expect_io_error); }

        LOGDEBUG("Wrote lba: {}, nblks: {} ", lba, nblks);
    }

    void populate_buf(uint8_t* buf, uint64_t size, uint64_t lba, int cur) {
        for (uint64_t write_sz = 0; write_sz < size; write_sz = write_sz + sizeof(uint64_t)) {
            if (!(write_sz % tcfg.vol_page_size)) {
                *((uint64_t*)(buf + write_sz)) = lba;
                auto vol = vol_info[cur]->vol;
                if (vol == nullptr) { return; }
                if (!((write_sz % VolInterface::get_instance()->get_page_size(vol)))) { ++lba; }
            } else {
                *((uint64_t*)(buf + write_sz)) = random();
            }
        }
    }

    void random_read() {
        /* XXX: does it really matter if it is atomic or not */
        int cur = ++cur_vol % tcfg.max_vols;
        uint64_t lba;
        uint64_t nblks;
    start:
        /* we won't be writing more then 128 blocks in one io */
        auto vol = vol_info[cur]->vol;
        if (vol == nullptr) { return; }
        uint64_t max_blks = tcfg.max_io_size / VolInterface::get_instance()->get_page_size(vol);

        lba = rand() % (vol_info[cur]->max_vol_blks - max_blks);
        nblks = rand() % max_blks;
        if (nblks == 0) { nblks = 1; }

        if (tcfg.load_type != 2) {
            /* Don't send overlapping reads with pending writes if data verification is on */
            std::unique_lock< std::mutex > lk(vol_info[cur]->vol_mutex);
            /* check if someone is already doing writes/reads */
            if (vol_info[cur]->m_vol_bm->is_bits_reset(lba, nblks)) {
                vol_info[cur]->m_vol_bm->set_bits(lba, nblks);
            } else {
                goto start;
            }
        }

        read_vol(cur, lba, nblks);
        LOGDEBUG("Read {} {} ", lba, nblks);
    }

    void read_vol(uint32_t cur, uint64_t lba, uint64_t nblks) {
        uint8_t* buf = nullptr;
        auto vol = vol_info[cur]->vol;
        if (vol == nullptr) { return; }
        {
            std::unique_lock< std::mutex > lk(m_mutex);
            if (io_stalled) {
                return;
            } else {
                ++outstanding_ios;
            }
        }
        uint64_t size = nblks * VolInterface::get_instance()->get_page_size(vol);
        auto ret = posix_memalign((void**)&buf, 4096, size);
        if (ret) { assert(0); }
        assert(buf != nullptr);
        io_req_t* req = new io_req_t();
        req->lba = lba;
        req->nblks = nblks;
        req->fd = vol_info[cur]->fd;
        req->is_read = true;
        req->size = size;
        req->offset = lba * VolInterface::get_instance()->get_page_size(vol);
        req->buf = buf;
        req->cur_vol = cur;
        read_cnt++;
        auto vreq = VolInterface::get_instance()->create_vol_interface_req(nullptr, lba, nblks, false);
        vreq->cookie = req;
        auto ret_io = VolInterface::get_instance()->read(vol, vreq);
        if (ret_io != no_error) { assert(ret_io == std::errc::no_such_device || expect_io_error); }
    }

    bool verify(const VolumePtr& vol, io_req_t* request, const vol_interface_req_ptr& vol_req, bool can_panic) {
        int64_t tot_size_read = 0;
        for (auto& info : vol_req->read_buf_list) {
            auto offset = info.offset;
            auto size = info.size;
            auto buf = info.buf;
            while (size != 0) {
                uint32_t size_read = 0;
                homeds::blob b = VolInterface::get_instance()->at_offset(buf, offset);
                if (b.size > size) {
                    size_read = size;
                } else {
                    size_read = b.size;
                }
                size_read = tcfg.vol_page_size;
                int j = 0;
                if (tcfg.verify_data) {
                    j = memcmp((void*)b.bytes, (uint8_t*)((uint64_t)request->buf + tot_size_read), size_read);
                    output.match_cnt++;
                }

                if (j != 0 && (!tcfg.verify_data || !verify_done)) {
                    /* we will only verify the header. We write lba number in the header */
                    j = memcmp((void*)b.bytes, (uint8_t*)((uint64_t)request->buf + tot_size_read), sizeof(uint64_t));
                    if (!j) {
                        /* copy the data */
                        auto ret =
                            pwrite(vol_info[request->cur_vol]->fd, b.bytes, b.size, tot_size_read + request->offset);
                        assert(ret == b.size);
                    }
                    output.hdr_only_match_cnt++;
                }
                if (j) {
                    if (can_panic) {
                        /* verify the header */
                        j = memcmp((void*)b.bytes, (uint8_t*)((uint64_t)request->buf + tot_size_read),
                                   sizeof(uint64_t));
                        if (j != 0) { LOGINFO("header mismatch lba read {}", *((uint64_t*)b.bytes)); }
                        LOGINFO("mismatch found lba {} nblks {} total_size_read {}", request->lba, request->nblks,
                                tot_size_read);
#ifndef NDEBUG
                        VolInterface::get_instance()->print_tree(vol);
#endif
                        LOGINFO("lba {} {}", request->lba, request->nblks);
                        std::this_thread::sleep_for(std::chrono::seconds(5));
                        sleep(30);
                        assert(0);
                    }
                    // need to return false
                    return false;
                }
                size -= size_read;
                offset += size_read;
                tot_size_read += size_read;
            }
        }
        assert(tot_size_read == request->size);
        return true;
    }

    void verify_vols() {
        static uint64_t print_time = 30;
        auto elapsed_time = get_elapsed_time(print_startTime);
        if (elapsed_time > print_time) {
            LOGINFO("verifying vols");
            print_startTime = Clock::now();
        }

        for (uint32_t cur = 0; cur < tcfg.max_vols; ++cur) {
            uint64_t max_blks = (tcfg.max_io_size / VolInterface::get_instance()->get_page_size(vol_info[cur]->vol));
            for (uint64_t lba = vol_info[cur]->cur_checkpoint; lba < vol_info[cur]->max_vol_blks;) {
                uint64_t io_size = 0;
                if (lba + max_blks > vol_info[cur]->max_vol_blks) {
                    io_size = vol_info[cur]->max_vol_blks - lba;
                } else {
                    io_size = max_blks;
                }
                read_vol(cur, lba, io_size);
                vol_info[cur]->cur_checkpoint = lba + io_size;
                if (outstanding_ios > tcfg.max_outstanding_ios) { return; }
                lba = lba + io_size;
            }
        }

        /* we move verify_done when all the outstanding IOs are completed */
        move_verify_to_done = true;
    }

    void process_multi_completions(const std::vector< vol_interface_req_ptr >& reqs) {
        for (auto& vol_req : reqs) {
            // Expected the entire batch to be from same volume
            ASSERT_EQ(vol_req->vol_instance.get(), reqs[0]->vol_instance.get());
            process_completions(vol_req, true);
        }
        LOGTRACE("Got {} completions for volume {} in one event", reqs.size(),
                 VolInterface::get_instance()->get_name(reqs[0]->vol_instance));
    }

    void process_end_of_batch(int ncompletions) {
        LOGTRACE("Got total {} callbacks with completions = {} across multiple volumes in one event", ncompletions,
                 _n_completed_this_thread);
        _n_completed_this_thread = 0;
        m_tgt.io_request_done();
    }

    void process_completions(const vol_interface_req_ptr& vol_req, bool part_of_batch = false) {
        /* raise an event */
        io_req_t* request = (io_req_t*)vol_req->cookie;
        static uint64_t print_time = 30;
        uint64_t temp = 1;
        auto elapsed_time = get_elapsed_time(print_startTime);

        /* it validates that we don't have two completions for the same requests */
        assert(!request->done);
        request->done = true;

        if (elapsed_time > print_time) {
            LOGINFO("write ios cmpled {}", output.write_cnt.load());
            LOGINFO("read ios cmpled {}", output.read_cnt.load());
            print_startTime = Clock::now();
        }

        assert(vol_req->err == no_error || vol_req->err == std::errc::no_such_device ||
               m_voltest->job_cfg.expect_io_error);
        LOGTRACE("IO DONE, req_id={}, outstanding_ios={}", vol_req->request_id, outstanding_ios.load());
        if (!vol_req->is_read && vol_req->err == no_error) {
            /* write to a file */
            auto ret = pwrite(request->fd, request->buf, request->size, request->offset);
            assert(ret == request->size);
        }

        bool verify_io = false;

        if (!vol_req->is_read && vol_req->err == no_error && tcfg.read_verify) {
#if 0
            (void)VolInterface::get_instance()->sync_read(vol_info[request->cur_vol]->vol, request->lba, request->nblks,
                                                          vol_req);
#endif
            LOGTRACE("IO DONE, req_id={}, outstanding_ios={}", vol_req->request_id, outstanding_ios.load());
            verify_io = true;
        } else if ((vol_req->is_read && vol_req->err == no_error)) {
            verify_io = true;
        }

        if (verify_io && (tcfg.verify_hdr || tcfg.verify_data)) {
            /* read from the file and verify it */
            auto ret = pread(request->fd, request->buf, request->size, request->offset);
            if (ret != request->size) { assert(0); }
            verify(vol_info[request->cur_vol]->vol, request, vol_req, true);
        }

        {
            std::unique_lock< std::mutex > lk(vol_info[request->cur_vol]->vol_mutex);
            vol_info[request->cur_vol]->m_vol_bm->reset_bits(request->lba, request->nblks);
        }

        delete request; // no longer needed

        outstanding_ios--;
        if (move_verify_to_done && !verify_done) {
            if (outstanding_ios.load() == 0) {
                verify_done = true;
                LOGINFO("verfied only hdr {} number of blks", output.hdr_only_match_cnt.load());
                LOGINFO("verify is done. starting IOs");
                if (tcfg.verify_only) {
                    notify_cmpl();
                    return;
                }
                startTime = Clock::now();
                one_req_completed(part_of_batch);
            }
        }

        if (verify_done && tcfg.is_abort) {
            if (get_elapsed_time(startTime) > (random() % tcfg.run_time)) { abort(); }
        }

        if (verify_done && time_to_stop()) {
            LOGINFO("Time to stop the IO, write_cnt={}, outstanding_ios={}", output.write_cnt, outstanding_ios.load());
            notify_cmpl();
        } else {
            one_req_completed(part_of_batch);
        }
    }

    void one_req_completed(bool part_of_batch) {
        if (part_of_batch) {
            _n_completed_this_thread++;
        } else {
            m_tgt.io_request_done();
        }
    }

    bool time_to_stop() {
        return (output.write_cnt >= tcfg.max_num_writes) || (get_elapsed_time(startTime) > tcfg.run_time);
    }
#endif

    static thread_local std::set< TestJob* > _completed_jobs_this_thread;

    void process_multi_completions(const std::vector< vol_interface_req_ptr >& reqs) {
        LOGINFO("Multi completions for {} reqs", reqs.size());
        for (auto& vol_req : reqs) {
            LOGINFO("vol req id = {} is completed", vol_req->request_id);
            // Expected the entire batch to be from same volume
            ASSERT_EQ(vol_req->vol_instance.get(), reqs[0]->vol_instance.get());
            TestJob* job = (TestJob*)vol_req->cookie;
            if (job->on_one_iteration_completed(boost::static_pointer_cast< io_req_t >(vol_req))) {
                job->run_one_iteration();
            } else {
                _completed_jobs_this_thread.insert(job);
            }
        }
        LOGTRACE("Got {} completions for volume {} in one event", reqs.size(),
                 VolInterface::get_instance()->get_name(reqs[0]->vol_instance));
    }

    void process_end_of_batch(int ncompletions) {
        LOGTRACE("Got total {} callbacks with completions = {} across multiple volumes in one event", ncompletions);
        for (auto pjob : _completed_jobs_this_thread) {
            LOGINFO("Completed the job {} for this thread", pjob->job_name());
            pjob->thread_done_executing();
        }
        _completed_jobs_this_thread.clear();
    }

#if 0
    void notify_cmpl() {
        std::unique_lock< std::mutex > lk(m_mutex);
        io_stalled = true;
        m_cv.notify_all();
    }
#endif

    bool delete_volume(int vol_indx) {
        // std::move will release the ref_count in VolTest::vol and pass to HomeBlks::remove_volume
        boost::uuids::uuid uuid;
        {
            std::unique_lock< std::mutex > lk(m_mutex);
            if (vol_indx >= (int)vol_info.size() || vol_info[vol_indx]->vol == nullptr) { return false; }
            uuid = VolInterface::get_instance()->get_uuid(vol_info[vol_indx]->vol);
            vol_info[vol_indx]->vol = nullptr;
        }
        VolInterface::get_instance()->remove_volume(uuid);
        output.vol_del_cnt++;
        return true;
    }

    void shutdown_force(bool timeout) {
        std::unique_lock< std::mutex > lk(m_mutex);
        bool force = false;
        // release the ref_count to volumes;
        if (!timeout) {
            remove_journal_files();
            vol_info.clear();
            force = true;
        }
        VolInterface::get_instance()->shutdown(force);
    }

    void remove_journal_files() {
        // Remove journal folders
        for (auto i = 0u; i < vol_info.size(); i++) {
            std::string name = boost::lexical_cast< std::string >(vol_info[i]->uuid);
            boost::filesystem::remove_all(name);
            LOGINFO("Removed journal dir: {}", name);
            remove(name.c_str());
        }
    }
};

class VolCreateDeleteJob : public TestJob {
public:
    VolCreateDeleteJob(VolTest* test) : TestJob(test) {}

    void run_one_iteration() override {
        while (!time_to_stop()) {
            m_voltest->create_volume();
            m_voltest->delete_volume(random() % tcfg.max_vols);
        }
    }

    bool on_one_iteration_completed(const boost::intrusive_ptr< io_req_t >& req) override { return true; }

    bool time_to_stop() const override {
        return ((m_voltest->output.vol_create_cnt >= tcfg.max_vols && m_voltest->output.vol_del_cnt >= tcfg.max_vols) ||
                (get_elapsed_time_sec(m_start_time) > tcfg.run_time));
    }

    bool is_async_job() const override { return false; };

    std::string job_name() const { return "VolCreateDeleteJob"; }
};

class IOTestJob : public TestJob {
public:
    IOTestJob(VolTest* test, load_type_t type) : TestJob(test), m_load_type(type) {}
    virtual ~IOTestJob() = default;

    virtual void run_one_iteration() override {
        int cnt = 0;
        while ((cnt++ < 8) && m_outstanding_ios < (int64_t)tcfg.max_outstanding_ios) {
            write_io();
            if (tcfg.read_enable) { read_io(); }
        }
    }

    bool on_one_iteration_completed(const boost::intrusive_ptr< io_req_t >& req) override {
        if (req->is_read && (tcfg.read_verify || tcfg.verify_hdr || tcfg.verify_data)) {
            /* read from the file and verify it */
            auto ret = pread(req->fd, req->validate_buf, req->size, req->offset);
            assert(ret == req->size);
            verify(req);
        }

        if (!req->is_read && (req->err == no_error)) {
            /* write to a file */
            auto ret = pwrite(req->fd, req->validate_buf, req->size, req->offset);
            assert(ret == req->size);
        }

        {
            std::unique_lock< std::mutex > lk(req->vol_info->vol_mutex);
            req->vol_info->m_vol_bm->reset_bits(req->lba, req->nblks);
        }
        --m_outstanding_ios;

        return !time_to_stop();
    }

    bool time_to_stop() const override {
        return ((m_voltest->output.write_cnt >= tcfg.max_num_writes) ||
                ((get_elapsed_time_sec(m_start_time) * 1000) > tcfg.run_time));
    }

    bool is_async_job() const override { return true; }
    std::string job_name() const { return "IOJob"; }

protected:
    load_type_t m_load_type;
    uint64_t m_cur_vol = 0;
    std::atomic< int64_t > m_outstanding_ios = 0;

protected:
    void write_io() {
        switch (m_load_type) {
        case load_type_t::random:
            random_write();
            break;
        case load_type_t::same:
            same_write();
            break;
        case load_type_t::sequential:
            seq_write();
            break;
        }
    }

    void read_io() {
        switch (m_load_type) {
        case load_type_t::random:
            random_read();
            break;
        case load_type_t::same:
            same_read();
            break;
        case load_type_t::sequential:
            assert(0);
            break;
        }
    }

    void same_write() { write_vol(0, 5, 100); }

    void seq_write() {
        /* XXX: does it really matter if it is atomic or not */
        int cur = ++m_cur_vol % tcfg.max_vols;
        uint64_t lba;
        uint64_t nblks;
    start:
        /* we won't be writing more then 128 blocks in one io */
        auto vinfo = m_voltest->vol_info[cur];
        auto vol = vinfo->vol;
        if (vol == nullptr) { return; }
        if (vinfo->num_io.fetch_add(1, std::memory_order_acquire) == 1000) {
            nblks = 200;
            lba = (vinfo->start_large_lba.fetch_add(nblks, std::memory_order_acquire)) % (vinfo->max_vol_blks - nblks);
        } else {
            nblks = 2;
            lba = (vinfo->start_lba.fetch_add(nblks, std::memory_order_acquire)) % (vinfo->max_vol_blks - nblks);
        }
        if (nblks == 0) { nblks = 1; }

        if (m_load_type != load_type_t::sequential) {
            /* can not support concurrent overlapping writes if whole data need to be verified */
            std::unique_lock< std::mutex > lk(vinfo->vol_mutex);
            /* check if someone is already doing writes/reads */
            if (nblks && vinfo->m_vol_bm->is_bits_reset(lba, nblks)) {
                vinfo->m_vol_bm->set_bits(lba, nblks);
            } else {
                goto start;
            }
        }
        write_vol(cur, lba, nblks);
    }

    void same_read() { read_vol(0, 5, 100); }

    void random_write() {
        /* XXX: does it really matter if it is atomic or not */
        int cur = ++m_cur_vol % tcfg.max_vols;
        uint64_t lba;
        uint64_t nblks;
    start:
        /* we won't be writing more then 128 blocks in one io */
        auto vinfo = m_voltest->vol_info[cur];
        auto vol = vinfo->vol;
        if (vol == nullptr) { return; }
        uint64_t max_blks = tcfg.max_io_size / VolInterface::get_instance()->get_page_size(vol);
        // lba: [0, max_vol_blks - max_blks)

        lba = rand() % (vinfo->max_vol_blks - max_blks);
        // nblks: [1, max_blks]
        nblks = rand() % (max_blks + 1);
        if (nblks == 0) { nblks = 1; }

        if (m_load_type != load_type_t::sequential) {
            /* can not support concurrent overlapping writes if whole data need to be verified */
            std::unique_lock< std::mutex > lk(vinfo->vol_mutex);
            /* check if someone is already doing writes/reads */
            if (nblks && vinfo->m_vol_bm->is_bits_reset(lba, nblks)) {
                vinfo->m_vol_bm->set_bits(lba, nblks);
            } else {
                goto start;
            }
        }
        write_vol(cur, lba, nblks);
    }

    void write_vol(uint32_t cur, uint64_t lba, uint64_t nblks) {
        uint8_t* wbuf;
        auto vinfo = m_voltest->vol_info[cur];
        auto vol = vinfo->vol;
        if (vol == nullptr) { return; }

        uint64_t size = nblks * VolInterface::get_instance()->get_page_size(vol);
        auto ret = posix_memalign((void**)&wbuf, 4096, size);
        assert(ret == 0);

        /* buf will be owned by homestore after sending the IO. so we need to allocate buf1 which will be used to
         * write to a file after ios are completed.
         */
        populate_buf(wbuf, size, lba, vinfo.get());
        auto vreq = boost::intrusive_ptr< io_req_t >(new io_req_t(vinfo, wbuf, lba, nblks));
        vreq->cookie = (void*)this;

        ++m_voltest->output.write_cnt;
        ++m_outstanding_ios;
        auto ret_io = VolInterface::get_instance()->write(vol, vreq);
        if (ret_io != no_error) { assert(ret_io == std::errc::no_such_device || tcfg.expect_io_error); }

        LOGDEBUG("Wrote lba: {}, nblks: {} ", lba, nblks);
    }

    void populate_buf(uint8_t* buf, uint64_t size, uint64_t lba, vol_info_t* vinfo) {
        for (uint64_t write_sz = 0; write_sz < size; write_sz = write_sz + sizeof(uint64_t)) {
            if (!(write_sz % tcfg.vol_page_size)) {
                *((uint64_t*)(buf + write_sz)) = lba;
                if (vinfo->vol == nullptr) { return; }
                if (!((write_sz % VolInterface::get_instance()->get_page_size(vinfo->vol)))) { ++lba; }
            } else {
                *((uint64_t*)(buf + write_sz)) = random();
            }
        }
    }

    void random_read() {
        /* XXX: does it really matter if it is atomic or not */
        int cur = ++m_cur_vol % tcfg.max_vols;
        uint64_t lba;
        uint64_t nblks;

    start:
        /* we won't be writing more then 128 blocks in one io */
        auto vinfo = m_voltest->vol_info[cur];
        auto vol = vinfo->vol;
        if (vol == nullptr) { return; }
        uint64_t max_blks = tcfg.max_io_size / VolInterface::get_instance()->get_page_size(vol);

        lba = rand() % (vinfo->max_vol_blks - max_blks);
        nblks = rand() % max_blks;
        if (nblks == 0) { nblks = 1; }

        if (tcfg.load_type != load_type_t::sequential) {
            /* Don't send overlapping reads with pending writes if data verification is on */
            std::unique_lock< std::mutex > lk(vinfo->vol_mutex);
            /* check if someone is already doing writes/reads */
            if (vinfo->m_vol_bm->is_bits_reset(lba, nblks)) {
                vinfo->m_vol_bm->set_bits(lba, nblks);
            } else {
                goto start;
            }
        }

        read_vol(cur, lba, nblks);
        LOGDEBUG("Read {} {} ", lba, nblks);
    }

    void read_vol(uint32_t cur, uint64_t lba, uint64_t nblks) {
        auto vinfo = m_voltest->vol_info[cur];
        auto vol = vinfo->vol;
        if (vol == nullptr) { return; }

        auto vreq = boost::intrusive_ptr< io_req_t >(new io_req_t(vinfo, nullptr, lba, nblks));
        vreq->cookie = (void*)this;

        ++m_voltest->output.read_cnt;
        ++m_outstanding_ios;
        auto ret_io = VolInterface::get_instance()->read(vol, vreq);
        if (ret_io != no_error) { assert(ret_io == std::errc::no_such_device || tcfg.expect_io_error); }
    }

    bool verify(const boost::intrusive_ptr< io_req_t >& req, bool can_panic = true) {
        auto& vol_req = (vol_interface_req_ptr&)req;

        int64_t tot_size_read = 0;
        for (auto& info : vol_req->read_buf_list) {
            auto offset = info.offset;
            auto size = info.size;
            auto buf = info.buf;
            while (size != 0) {
                uint32_t size_read = 0;
                homeds::blob b = VolInterface::get_instance()->at_offset(buf, offset);

                size_read = tcfg.vol_page_size;
                int j = 0;
                if (tcfg.verify_data) {
                    j = memcmp((void*)b.bytes, (uint8_t*)((uint64_t)req->validate_buf + tot_size_read), size_read);
                    m_voltest->output.match_cnt++;
                }

                if ((j != 0) && !tcfg.verify_data) {
                    /* we will only verify the header. We write lba number in the header */
                    j = memcmp((void*)b.bytes, (uint8_t*)((uint64_t)req->validate_buf + tot_size_read),
                               sizeof(uint64_t));
                    if (!j) {
                        /* copy the data */
                        auto ret = pwrite(req->fd, b.bytes, b.size, tot_size_read + req->offset);
                        assert(ret == b.size);
                    }
                    m_voltest->output.hdr_only_match_cnt++;
                }

                if (j) {
                    if (can_panic) {
                        /* verify the header */
                        j = memcmp((void*)b.bytes, (uint8_t*)((uint64_t)req->validate_buf + tot_size_read),
                                   sizeof(uint64_t));
                        if (j != 0) { LOGINFO("header mismatch lba read {}", *((uint64_t*)b.bytes)); }
                        LOGINFO("mismatch found lba {} nblks {} total_size_read {}", req->lba, req->nblks,
                                tot_size_read);
#ifndef NDEBUG
                        VolInterface::get_instance()->print_tree(req->vol_info->vol);
#endif
                        LOGINFO("lba {} {}", req->lba, req->nblks);
                        std::this_thread::sleep_for(std::chrono::seconds(5));
                        sleep(30);
                        assert(0);
                    }
                    // need to return false
                    return false;
                }
                size -= size_read;
                offset += size_read;
                tot_size_read += size_read;
            }
        }
        assert(tot_size_read == req->size);
        return true;
    }
};

class VolVerifyJob : public IOTestJob {
public:
    VolVerifyJob(VolTest* test) : IOTestJob(test, load_type_t::sequential) {
        m_start_time = Clock::now();
        LOGINFO("verifying vols");
    }

    void run_one_iteration() override {
        for (uint32_t cur = 0u; cur < tcfg.max_vols; ++cur) {
            uint64_t max_blks = (tcfg.max_io_size / VolInterface::get_instance()->get_page_size(vol_info(cur)->vol));
            for (uint64_t lba = vol_info(cur)->cur_checkpoint; lba < vol_info(cur)->max_vol_blks;) {
                uint64_t io_size = 0;
                if (lba + max_blks > vol_info(cur)->max_vol_blks) {
                    io_size = vol_info(cur)->max_vol_blks - lba;
                } else {
                    io_size = max_blks;
                }
                read_vol(cur, lba, io_size);
                vol_info(cur)->cur_checkpoint = lba + io_size;
                if (m_outstanding_ios > (int64_t)tcfg.max_outstanding_ios) { return; }
                lba = lba + io_size;
            }
        }
        m_is_job_done = true;
    }

    bool time_to_stop() const override { return m_is_job_done; }
    bool is_async_job() const override { return true; };
    std::string job_name() const override { return "VerifyJob"; }

private:
    std::shared_ptr< vol_info_t >& vol_info(uint32_t nth) { return m_voltest->vol_info[nth]; }
    bool m_is_job_done = false;
};

thread_local std::set< TestJob* > VolTest::_completed_jobs_this_thread = {};

/************************** Test cases ****************************/

/*********** Below Tests does IO and exit with clean shutdown *************/

/*!
    @test   lifecycle_test
    @brief  It initialize the homestore, create volume, delete volume and shutdown the system
 */
TEST_F(VolTest, lifecycle_test) {
    this->start_homestore();
    this->wait_homestore_init_done();
    auto io_job = new IOTestJob(this, load_type_t::random);
    this->start_job(io_job, true /* wait_for_completion */);
    delete (io_job);

#if 0
    this->kickstart_io();
    this->wait_cmpl();
#endif

    //    LOGINFO("Metrics: {}", sisl::MetricsFarm::getInstance().get_result_in_json().dump(2));
    output.print("lifecycle_test");

    FlipClient fc(HomeStoreFlip::instance());
    FlipFrequency freq;
    freq.set_count(10);
    freq.set_percent(100);

    fc.inject_retval_flip("vol_comp_delay_us", {}, freq, 100);
    this->delete_volumes();

    LOGINFO("All volumes are deleted, do a shutdown of homestore");
    this->shutdown();

    LOGINFO("Shutdown of homestore is completed, removing files");
    this->remove_files();
}

#if 0
/*!
    @test   init_io_test
    @brief  It initialize the homestore, create volume and
            shutdown the system
 */
TEST_F(VolTest, init_io_test) {
    this->start_homestore();
    this->wait_homestore_init_done();
    this->kickstart_io();
    this->wait_cmpl();
    output.print("init_io_test");
    this->shutdown();
    if (tcfg.remove_file) { this->remove_files(); }
}

/*!
    @test   recovery_io_test
    @brief  Tests which does recovery. End up with a clean shutdown
 */
TEST_F(VolTest, recovery_io_test) {
    this->set_job_cfg({.init = false});
    this->start_homestore();
    this->wait_homestore_init_done();
    this->kickstart_io();
    this->wait_cmpl();
    if (tcfg.can_delete_volume) { this->delete_volumes(); }
    this->shutdown();
    if (tcfg.remove_file) { this->remove_files(); }
}

/*!
    @test   vol_create_del_test
    @brief  Below tests delete volumes. Should exit with clean shutdown.
 */
TEST_F(VolTest, vol_create_del_test) {
    this->vol_create_del_test = true;
    tcfg.precreate_volume = false;
    this->start_homestore();
    this->wait_cmpl();
    this->shutdown();
    this->remove_files();
}

/************ Below tests check the workflows ***********/

TEST_F(VolTest, one_disk_replace_test) {
    this->set_job_cfg({.init = false, .disk_replace_cnt = 1});
    tcfg.expected_vol_state = homestore::vol_state::DEGRADED;
    this->start_homestore();
    this->wait_cmpl();
    this->shutdown();
    if (tcfg.remove_file) { this->remove_files(); }
}

TEST_F(VolTest, one_disk_replace_abort_test) {
    this->set_job_cfg({.init = false, .disk_replace_cnt = 1, .expected_init_fail = true});
    jcfg.expected_vol_state = homestore::vol_state::DEGRADED;

    FlipClient fc(HomeStoreFlip::instance());
    FlipFrequency freq;
    freq.set_count(100);
    freq.set_percent(100);
    fc.inject_noreturn_flip("reboot_abort", {}, freq);

    this->start_homestore();
    this->wait_cmpl();
    this->shutdown();
    if (tcfg.remove_file) { this->remove_files(); }
}

TEST_F(VolTest, two_disk_replace_test) {
    this->set_job_cfg({.init = false, .disk_replace_cnt = 2, .expected_init_fail = true});
    this->start_homestore();
    this->wait_homestore_init_done();
    this->kickstart_io();
    this->wait_cmpl();
    this->shutdown();
}

TEST_F(VolTest, one_disk_fail_test) {
    FlipClient fc(HomeStoreFlip::instance());
    FlipFrequency freq;
    FlipCondition cond1;
    FlipCondition cond2;
    freq.set_count(100);
    freq.set_percent(100);
    fc.create_condition("setting error on file1", flip::Operator::EQUAL, tcfg.default_names[0], &cond1);
    fc.inject_noreturn_flip("device_boot_fail", {cond1}, freq);

    this->set_job_cfg({.init = false, .expected_init_fail = true});
    this->start_homestore();
    this->wait_homestore_init_done();
    this->kickstart_io();
    this->wait_cmpl();
    this->shutdown();
    if (tcfg.remove_file) { this->remove_files(); }
}

TEST_F(VolTest, vol_offline_test) {
    this->set_job_cfg({.expect_io_error = true});
    tcfg.expected_vol_state = vol_state::OFFLINE;
    this->start_homestore();
    this->wait_homestore_init_done();
    this->move_vol_to_offline();
    this->wait_cmpl();
    this->shutdown();
}

TEST_F(VolTest, vol_io_fail_test) {
    this->set_job_cfg({.expect_io_error = true});
    this->start_homestore();
    this->wait_homestore_init_done();

    FlipClient fc(HomeStoreFlip::instance());
    FlipCondition cond1;
    FlipCondition cond2;
    FlipFrequency freq;
    fc.create_condition("setting error on file1", flip::Operator::EQUAL, tcfg.default_names[0], &cond1);
    fc.create_condition("setting error on file2", flip::Operator::EQUAL, tcfg.default_names[1], &cond2);
    freq.set_count(2000);
    freq.set_percent(50);
    fc.inject_noreturn_flip("io_write_comp_error_flip", {}, freq);
    fc.inject_noreturn_flip("device_fail", {cond1, cond2}, freq);

    this->wait_cmpl();
    this->shutdown();
    if (tcfg.remove_file) { this->remove_files(); }
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
    this->wait_homestore_init_done();
    this->kickstart_io();
    this->wait_cmpl();

    output.print("btree_fix_read_failure_test");

    sleep(5);

    this->move_vol_to_offline();

    VolInterface::get_instance()->set_error_flip();

    auto ret = this->fix_vol_mapping_btree();
    EXPECT_EQ(ret, false);

    this->delete_volumes();

    this->shutdown();
    if (tcfg.remove_file) { this->remove_files(); }
}

/**
 * @brief :
 * Test Procedure :
 * 1. Start homestore and do customerized IO based on input parameter
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
    this->wait_homestore_init_done();
    this->kickstart_io();
    this->wait_cmpl();

    output.print("btree_fix_test");

    sleep(5);
    assert(outstanding_ios == 0);

    this->move_vol_to_offline();
    auto ret = this->fix_vol_mapping_btree();
    EXPECT_EQ(ret, true);

    this->delete_volumes();

    this->shutdown();
    if (tcfg.remove_file) { this->remove_files(); }
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
    this->wait_homestore_init_done();
    this->kickstart_io();
    this->wait_cmpl();

    output.print("btree_fix_rerun_io_test");

    sleep(5);
    assert(outstanding_ios == 0);

    this->move_vol_to_offline();
    auto ret = this->fix_vol_mapping_btree();
    EXPECT_EQ(ret, true);

    startTime = Clock::now();
    output.write_cnt = 0;
    output.read_cnt = 0;
    io_stalled = false;
    this->move_vol_to_online();

    this->wait_cmpl();
    output.print("btree_fix_rerun_io_test");

    sleep(5);
    assert(outstanding_ios == 0);

    if (tcfg.can_delete_volume) { this->delete_volumes(); }

    this->shutdown();
    if (tcfg.remove_file) { this->remove_files(); }
}
#endif

/************************* CLI options ***************************/

SDS_OPTION_GROUP(
    test_volume,
    (run_time, "", "run_time", "run time for io", ::cxxopts::value< uint32_t >()->default_value("30"), "seconds"),
    (load_type, "", "load_type", "load_type", ::cxxopts::value< uint32_t >()->default_value("0"),
     "random_write_read:0, same_write_read:1, overlap_write=2"),
    (num_threads, "", "num_threads", "num threads for io", ::cxxopts::value< uint32_t >()->default_value("8"),
     "number"),
    (read_enable, "", "read_enable", "read enable 0 or 1", ::cxxopts::value< uint32_t >()->default_value("1"), "flag"),
    (max_disk_capacity, "", "max_disk_capacity", "max disk capacity",
     ::cxxopts::value< uint64_t >()->default_value("7"), "GB"),
    (max_volume, "", "max_volume", "max volume", ::cxxopts::value< uint64_t >()->default_value("50"), "number"),
    (max_num_writes, "", "max_num_writes", "max num of writes", ::cxxopts::value< uint64_t >()->default_value("100000"),
     "number"),
    (verify_hdr, "", "verify_hdr", "data verification", ::cxxopts::value< uint64_t >()->default_value("1"), "0 or 1"),
    (verify_data, "", "verify_data", "data verification", ::cxxopts::value< uint64_t >()->default_value("1"), "0 or 1"),
    (read_verify, "", "read_verify", "read verification for each write",
     ::cxxopts::value< uint64_t >()->default_value("0"), "0 or 1"),
    (enable_crash_handler, "", "enable_crash_handler", "enable crash handler 0 or 1",
     ::cxxopts::value< uint32_t >()->default_value("1"), "flag"),
    (remove_file, "", "remove_file", "remove file at the end of test 0 or 1",
     ::cxxopts::value< uint32_t >()->default_value("1"), "flag"),
    (expected_vol_state, "", "expected_vol_state", "volume state expected during boot",
     ::cxxopts::value< uint32_t >()->default_value("0"), "flag"),
    (verify_only, "", "verify_only", "verify only boot", ::cxxopts::value< uint32_t >()->default_value("0"), "flag"),
    (abort, "", "abort", "abort", ::cxxopts::value< uint32_t >()->default_value("0"), "flag"),
    (flip, "", "flip", "flip", ::cxxopts::value< uint32_t >()->default_value("0"), "flag"),
    (delete_volume, "", "delete_volume", "delete_volume", ::cxxopts::value< uint32_t >()->default_value("0"), "flag"),
    (atomic_phys_page_size, "", "atomic_phys_page_size", "atomic_phys_page_size",
     ::cxxopts::value< uint32_t >()->default_value("4096"), "atomic_phys_page_size"),
    (vol_page_size, "", "vol_page_size", "vol_page_size", ::cxxopts::value< uint32_t >()->default_value("4096"),
     "vol_page_size"),
    (device_list, "", "device_list", "List of device paths", ::cxxopts::value< std::vector< std::string > >(),
     "path [...]"),
    (phy_page_size, "", "phy_page_size", "phy_page_size", ::cxxopts::value< uint32_t >()->default_value("4096"),
     "phy_page_size"),
    (io_flags, "", "io_flags", "io_flags", ::cxxopts::value< uint32_t >()->default_value("1"), "0 or 1"),
    (mem_btree_page_size, "", "mem_btree_page_size", "mem_btree_page_size",
     ::cxxopts::value< uint32_t >()->default_value("8192"), "mem_btree_page_size"))

#define ENABLED_OPTIONS logging, home_blks, test_volume

SDS_OPTIONS_ENABLE(ENABLED_OPTIONS)

/************************** MAIN ********************************/

/* We can run this target either by using default options which run the normal io tests or by setting different
 * options. Format is
 *   1. ./test_volume
 *   2. ./test_volume --gtest_filter=*recovery* --run_time=120 --num_threads=16 --max_disk_capacity=10 --max_volume=50
 * Above command run all tests having a recovery keyword for 120 seconds with 16 threads , 10g disk capacity and 50
 * volumes
 */
int main(int argc, char* argv[]) {
    srand(time(0));
    ::testing::GTEST_FLAG(filter) = "*lifecycle_test*";
    testing::InitGoogleTest(&argc, argv);
    SDS_OPTIONS_LOAD(argc, argv, ENABLED_OPTIONS)
    sds_logging::SetLogger("test_volume");
    spdlog::set_pattern("[%D %T.%f] [%^%L%$] [%t] %v");

    tcfg.run_time = SDS_OPTIONS["run_time"].as< uint32_t >();
    tcfg.num_threads = SDS_OPTIONS["num_threads"].as< uint32_t >();
    tcfg.read_enable = SDS_OPTIONS["read_enable"].as< uint32_t >();
    tcfg.max_disk_capacity = ((SDS_OPTIONS["max_disk_capacity"].as< uint64_t >()) * (1ul << 30));
    tcfg.max_vols = SDS_OPTIONS["max_volume"].as< uint64_t >();
    tcfg.max_num_writes = SDS_OPTIONS["max_num_writes"].as< uint64_t >();
    tcfg.enable_crash_handler = SDS_OPTIONS["enable_crash_handler"].as< uint32_t >();
    tcfg.verify_hdr = SDS_OPTIONS["verify_hdr"].as< uint64_t >() ? true : false;
    tcfg.verify_data = SDS_OPTIONS["verify_data"].as< uint64_t >() ? true : false;
    tcfg.read_verify = SDS_OPTIONS["read_verify"].as< uint64_t >() ? true : false;
    tcfg.load_type = static_cast< load_type_t >(SDS_OPTIONS["load_type"].as< uint32_t >());
    tcfg.remove_file = SDS_OPTIONS["remove_file"].as< uint32_t >();
    tcfg.expected_vol_state = static_cast< homestore::vol_state >(SDS_OPTIONS["expected_vol_state"].as< uint32_t >());
    tcfg.verify_only = SDS_OPTIONS["verify_only"].as< uint32_t >();
    tcfg.is_abort = SDS_OPTIONS["abort"].as< uint32_t >();
    tcfg.flip_set = SDS_OPTIONS["flip"].as< uint32_t >();
    tcfg.can_delete_volume = SDS_OPTIONS["delete_volume"].as< uint32_t >() ? true : false;
    tcfg.atomic_phys_page_size = SDS_OPTIONS["atomic_phys_page_size"].as< uint32_t >();
    tcfg.vol_page_size = SDS_OPTIONS["vol_page_size"].as< uint32_t >();
    tcfg.phy_page_size = SDS_OPTIONS["phy_page_size"].as< uint32_t >();
    tcfg.mem_btree_page_size = SDS_OPTIONS["mem_btree_page_size"].as< uint32_t >();
    tcfg.io_flags = static_cast< io_flag >(SDS_OPTIONS["io_flags"].as< uint32_t >());

    if (SDS_OPTIONS.count("device_list")) {
        tcfg.dev_names = SDS_OPTIONS["device_list"].as< std::vector< std::string > >();
    }

    if (tcfg.load_type == load_type_t::sequential) { tcfg.verify_data = 0; }

    if (tcfg.enable_crash_handler) { sds_logging::install_crash_handler(); }
    return RUN_ALL_TESTS();
}
