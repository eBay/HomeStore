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
#include <iomgr/spdk_drive_interface.hpp>
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
#include <fds/atomic_status_counter.hpp>
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
    uint64_t run_time = 60;
    uint64_t num_threads = 8;

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
    bool expected_init_fail = false;
    int disk_replace_cnt = 0;
    bool precreate_volume = true;
    bool expect_io_error = false;
    uint32_t p_volume_size = 60;
    bool is_spdk = false;
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

    void print(const char* work_type, bool metrics_dump = false) const {
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
        if (metrics_dump) LOGINFO("Metrics: {}", sisl::MetricsFarm::getInstance().get_result_in_json().dump(2));
    }
};

class VolTest;
struct io_req_t;
enum class wait_type_t { no_wait = 0, for_execution = 1, for_completion = 2 };

class TestJob {
public:
    enum class job_status_t { not_started = 0, running = 1, stopped = 2, completed = 3 };

    TestJob(VolTest* test) : m_voltest(test), m_start_time(Clock::now()) {}
    virtual void run_one_iteration() = 0;
    virtual void on_one_iteration_completed(const boost::intrusive_ptr< io_req_t >& req) = 0;
    virtual bool time_to_stop() const = 0;
    virtual bool is_job_done() const = 0;
    virtual bool is_async_job() const = 0;
    virtual std::string job_name() const = 0;

    virtual void start_in_this_thread() {
        m_status_threads_executing.set_status(job_status_t::running);
        try_run_one_iteration();
        if (time_to_stop()) { notify_completions(); }
        VolInterface::get_instance()->submit_io_batch();
    }

    virtual void try_run_one_iteration() {
        bool notify = true;
        if (!time_to_stop() && m_status_threads_executing.increment_if_status(job_status_t::running)) {
            run_one_iteration();
            notify = m_status_threads_executing.decrement_testz_and_test_status(job_status_t::stopped);
        }

        if (notify) { notify_completions(); }
    }

    void notify_completions() {
        auto notify_job_done = false;
        if (is_job_done()) {
            m_status_threads_executing.set_status(job_status_t::completed);
            notify_job_done = true;
        } else {
            m_status_threads_executing.set_status(job_status_t::stopped);
        }

        {
            std::unique_lock< std::mutex > lk(m_mutex);
            m_execution_cv.notify_all();
            if (notify_job_done) m_completion_cv.notify_all();
        }
    }

    virtual void wait_for_execution() {
        std::unique_lock< std::mutex > lk(m_mutex);
        m_execution_cv.wait(lk, [this] {
            auto status = m_status_threads_executing.get_status();
            return (((status == job_status_t::stopped) || (status == job_status_t::completed)) &&
                    (m_status_threads_executing.count() == 0));
        });
        LOGINFO("Job {} is done executing", job_name());
    }

    virtual void wait_for_completion() {
        std::unique_lock< std::mutex > lk(m_mutex);
        /*m_completion_cv.wait(
            lk, [this] { return (m_status_threads_executing.get_status() == job_status_t::job_completed); }); */
        m_completion_cv.wait(lk,
                             [this] { return (m_status_threads_executing.get_status() == job_status_t::completed); });
        LOGINFO("Job {} is completed", job_name());
    }

protected:
    VolTest* m_voltest;
    std::mutex m_mutex;
    std::condition_variable m_execution_cv;
    std::condition_variable m_completion_cv;
    Clock::time_point m_start_time;
    // std::atomic< job_status_t > m_status = job_status_t::not_started;
    // std::atomic< int32_t > m_threads_executing = 0;
    sisl::atomic_status_counter< job_status_t, job_status_t::not_started > m_status_threads_executing;
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

    io_req_t(const std::shared_ptr< vol_info_t >& vinfo, void* wbuf, uint64_t lba, uint32_t nlbas) :
            vol_interface_req(wbuf, lba, nlbas),
            vol_info(vinfo) {
        auto page_size = VolInterface::get_instance()->get_page_size(vinfo->vol);
        size = nlbas * page_size;
        offset = lba * page_size;
        fd = vinfo->fd;
        is_read = (wbuf == nullptr);
        cur_vol = vinfo->vol_idx;

        validate_buf = iomanager.iobuf_alloc(512, size);
        assert(validate_buf != nullptr);
        if (wbuf) memcpy(validate_buf, wbuf, size);
    }

    virtual ~io_req_t() { iomanager.iobuf_free(validate_buf); }
};

TestCfg tcfg;            // Config for each VolTest
const TestCfg gcfg = {}; // Config for global for all tests

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

    std::vector< std::shared_ptr< vol_info_t > > vol_info;

    // std::condition_variable m_cv;
    std::condition_variable m_init_done_cv;
    std::mutex m_mutex;
    void* init_buf = nullptr;

    // uint64_t cur_vol;
    // Clock::time_point startTime;
    std::vector< dev_info > device_info;
    uint64_t max_vol_size;
    std::shared_ptr< IOTestJob > m_io_job;

    // bool verify_done;
    // bool move_verify_to_done;
    // bool vol_create_del_test;

    // Clock::time_point print_startTime;

    // std::atomic< bool > io_stalled = false;
    // bool expected_init_fail = false;

public:
    static thread_local uint32_t _n_completed_this_thread;

    VolTest() : vol_info(0), device_info(0) {
        tcfg = gcfg; // Reset the config from global config

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
        if (init_buf) { iomanager.iobuf_free((uint8_t*)init_buf); }
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

    void start_homestore(bool wait_for_init_done = true) {
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
        /* Don't populate the whole disks. Only 60 % of it */
        max_vol_size = (tcfg.p_volume_size * max_capacity) / (100 * tcfg.max_vols);

        iomanager.start(tcfg.num_threads, tcfg.is_spdk);

        init_params params;
        params.open_flags = tcfg.io_flags;
        params.min_virtual_page_size = tcfg.vol_page_size;
        params.app_mem_size = 5 * 1024 * 1024 * 1024ul;
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
        params.disk_attr->align_size = 512;
        params.disk_attr->atomic_phys_page_size = tcfg.atomic_phys_page_size;

        boost::uuids::string_generator gen;
        params.system_uuid = gen("01970496-0262-11e9-8eb2-f2801f1b9fd1");
        VolInterface::init(params);

        if (wait_for_init_done) { wait_homestore_init_done(); }
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
            return;
        }
        tcfg.max_io_size = params.max_io_size;
        init_buf = iomanager.iobuf_alloc(512, tcfg.max_io_size);
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

    void start_job(TestJob* job, wait_type_t wait_type = wait_type_t::for_completion) {
        iomanager.run_on(iomgr::thread_regex::all_iomgr_created_io,
                         [job, this](iomgr::io_thread_addr_t a) { job->start_in_this_thread(); });
        if (wait_type == wait_type_t::for_execution) {
            job->wait_for_execution();
        } else if (wait_type == wait_type_t::for_completion) {
            job->wait_for_completion();
        }
    }

    std::shared_ptr< IOTestJob > start_io_job(wait_type_t wait_type = wait_type_t::for_execution,
                                              load_type_t load_type = tcfg.load_type);

    void wait_homestore_init_done() {
        std::unique_lock< std::mutex > lk(m_mutex);
        m_init_done_cv.wait(lk);
    }

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

    static thread_local std::list< vol_interface_req_ptr > _completed_reqs_this_thread;

    void process_multi_completions(const std::vector< vol_interface_req_ptr >& reqs) {
        LOGTRACE("Multi completions for {} reqs", reqs.size());
        for (auto& vol_req : reqs) {
            LOGTRACE("vol req id = {} is completed", vol_req->request_id);
            ASSERT_EQ(vol_req->vol_instance.get(), reqs[0]->vol_instance.get());
            _completed_reqs_this_thread.push_back(vol_req);
        }
        LOGTRACE("Got {} completions for volume {} in one event", reqs.size(),
                 VolInterface::get_instance()->get_name(reqs[0]->vol_instance));
    }

    void process_end_of_batch(int ncompletions) {
        LOGTRACE("Got total {} callbacks across multiple volumes in one event, num_jobs_completed_this_thread={}",
                 ncompletions, _completed_reqs_this_thread.size());

        // First iteration goes thru all jobs and call their on_completion method
        for (auto& vol_req : _completed_reqs_this_thread) {
            TestJob* job = (TestJob*)vol_req->cookie;
            job->on_one_iteration_completed(boost::static_pointer_cast< io_req_t >(vol_req));
        }

        // Second iteration gives the job a chance to refill the work if it is not time to stop
        while (!_completed_reqs_this_thread.empty()) {
            auto vol_req = _completed_reqs_this_thread.front();
            _completed_reqs_this_thread.pop_front();

            TestJob* job = (TestJob*)vol_req->cookie;
            job->try_run_one_iteration();
        }

        VolInterface::get_instance()->submit_io_batch();
    }

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
        m_is_job_done = true;
    }

    void on_one_iteration_completed(const boost::intrusive_ptr< io_req_t >& req) override {}

    bool time_to_stop() const override {
        return ((m_voltest->output.vol_create_cnt >= tcfg.max_vols && m_voltest->output.vol_del_cnt >= tcfg.max_vols) ||
                (get_elapsed_time_sec(m_start_time) > tcfg.run_time));
    }

    virtual bool is_job_done() const override { return m_is_job_done; }
    bool is_async_job() const override { return false; };

    std::string job_name() const { return "VolCreateDeleteJob"; }

private:
    bool m_is_job_done = false;
};

class IOTestJob : public TestJob {
public:
    IOTestJob(VolTest* test, load_type_t type = tcfg.load_type) : TestJob(test), m_load_type(type) {}
    virtual ~IOTestJob() = default;

    virtual void run_one_iteration() override {
        int cnt = 0;
        while ((cnt++ < 1) && m_outstanding_ios < (int64_t)tcfg.max_outstanding_ios) {
            write_io();
            if (tcfg.read_enable) { read_io(); }
        }
    }

    void on_one_iteration_completed(const boost::intrusive_ptr< io_req_t >& req) override {
        if (req->err != no_error) {
            assert((req->err == std::errc::no_such_device) || tcfg.expect_io_error);
        } else {
            if (req->is_read && (tcfg.read_verify || tcfg.verify_hdr || tcfg.verify_data)) {
                /* read from the file and verify it */
                auto ret = pread(req->fd, req->validate_buf, req->size, req->offset);
                assert(ret == req->size);
                verify(req);
            } else if (!req->is_read) {
                /* write to a file */
                auto ret = pwrite(req->fd, req->validate_buf, req->size, req->offset);
                assert(ret == req->size);
            }
        }

        {
            std::unique_lock< std::mutex > lk(req->vol_info->vol_mutex);
            req->vol_info->m_vol_bm->reset_bits(req->lba, req->nlbas);
        }
        --m_outstanding_ios;
    }

    bool time_to_stop() const override {
        return ((m_voltest->output.write_cnt >= tcfg.max_num_writes) ||
                (get_elapsed_time_sec(m_start_time) > tcfg.run_time));
    }

    virtual bool is_job_done() const override { return (m_outstanding_ios == 0); }
    bool is_async_job() const override { return true; }
    std::string job_name() const { return "IOJob"; }

protected:
    load_type_t m_load_type;
    uint64_t m_cur_vol = 0;
    std::atomic< int64_t > m_outstanding_ios = 0;

protected:
    bool write_io() {
        bool ret = false;
        switch (m_load_type) {
        case load_type_t::random:
            ret = random_write();
            break;
        case load_type_t::same:
            ret = same_write();
            break;
        case load_type_t::sequential:
            ret = seq_write();
            break;
        }
        return ret;
    }

    bool read_io() {
        bool ret = false;
        switch (m_load_type) {
        case load_type_t::random:
            ret = random_read();
            break;
        case load_type_t::same:
            ret = same_read();
            break;
        case load_type_t::sequential:
            assert(0);
            break;
        }
        return ret;
    }

    bool same_write() { return write_vol(0, 5, 100); }

    bool seq_write() {
        /* XXX: does it really matter if it is atomic or not */
        int cur = ++m_cur_vol % tcfg.max_vols;
        uint64_t lba;
        uint64_t nlbas;
    start:
        /* we won't be writing more then 128 blocks in one io */
        auto vinfo = m_voltest->vol_info[cur];
        auto vol = vinfo->vol;
        if (vol == nullptr) { return false; }
        if (vinfo->num_io.fetch_add(1, std::memory_order_acquire) == 1000) {
            nlbas = 200;
            lba = (vinfo->start_large_lba.fetch_add(nlbas, std::memory_order_acquire)) % (vinfo->max_vol_blks - nlbas);
        } else {
            nlbas = 2;
            lba = (vinfo->start_lba.fetch_add(nlbas, std::memory_order_acquire)) % (vinfo->max_vol_blks - nlbas);
        }
        if (nlbas == 0) { nlbas = 1; }

        if (m_load_type != load_type_t::sequential) {
            /* can not support concurrent overlapping writes if whole data need to be verified */
            std::unique_lock< std::mutex > lk(vinfo->vol_mutex);
            /* check if someone is already doing writes/reads */
            if (nlbas && vinfo->m_vol_bm->is_bits_reset(lba, nlbas)) {
                vinfo->m_vol_bm->set_bits(lba, nlbas);
            } else {
                goto start;
            }
        }
        return write_vol(cur, lba, nlbas);
    }

    bool same_read() { return read_vol(0, 5, 100); }

    bool random_write() {
        /* XXX: does it really matter if it is atomic or not */
        int cur = ++m_cur_vol % tcfg.max_vols;
        uint64_t lba;
        uint64_t nlbas;
    start:
        /* we won't be writing more then 128 blocks in one io */
        auto vinfo = m_voltest->vol_info[cur];
        auto vol = vinfo->vol;
        if (vol == nullptr) { return false; }
        uint64_t max_blks = tcfg.max_io_size / VolInterface::get_instance()->get_page_size(vol);
        // lba: [0, max_vol_blks - max_blks)

        lba = rand() % (vinfo->max_vol_blks - max_blks);
        // nlbas: [1, max_blks]
        nlbas = rand() % (max_blks + 1);
        if (nlbas == 0) { nlbas = 1; }

        if (m_load_type != load_type_t::sequential) {
            /* can not support concurrent overlapping writes if whole data need to be verified */
            std::unique_lock< std::mutex > lk(vinfo->vol_mutex);
            /* check if someone is already doing writes/reads */
            if (nlbas && vinfo->m_vol_bm->is_bits_reset(lba, nlbas)) {
                vinfo->m_vol_bm->set_bits(lba, nlbas);
            } else {
                goto start;
            }
        }
        return write_vol(cur, lba, nlbas);
    }

    bool write_vol(uint32_t cur, uint64_t lba, uint64_t nlbas) {
        uint8_t* wbuf;
        auto vinfo = m_voltest->vol_info[cur];
        auto vol = vinfo->vol;
        if (vol == nullptr) { return false; }

        uint64_t size = nlbas * VolInterface::get_instance()->get_page_size(vol);
        wbuf = iomanager.iobuf_alloc(512, size);

        /* buf will be owned by homestore after sending the IO. so we need to allocate buf1 which will be used
         * to write to a file after ios are completed.
         */
        populate_buf(wbuf, size, lba, vinfo.get());
        auto vreq = boost::intrusive_ptr< io_req_t >(new io_req_t(vinfo, wbuf, lba, nlbas));
        vreq->cookie = (void*)this;

        ++m_voltest->output.write_cnt;
        ++m_outstanding_ios;
        auto ret_io = VolInterface::get_instance()->write(vol, vreq);
        LOGDEBUG("Wrote lba: {}, nlbas: {} outstanding_ios={}", lba, nlbas, m_outstanding_ios.load());
        if (ret_io != no_error) { return false; }
        return true;
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

    bool random_read() {
        /* XXX: does it really matter if it is atomic or not */
        int cur = ++m_cur_vol % tcfg.max_vols;
        uint64_t lba;
        uint64_t nlbas;

    start:
        /* we won't be writing more then 128 blocks in one io */
        auto vinfo = m_voltest->vol_info[cur];
        auto vol = vinfo->vol;
        if (vol == nullptr) { return false; }
        uint64_t max_blks = tcfg.max_io_size / VolInterface::get_instance()->get_page_size(vol);

        lba = rand() % (vinfo->max_vol_blks - max_blks);
        nlbas = rand() % max_blks;
        if (nlbas == 0) { nlbas = 1; }

        if (m_load_type != load_type_t::sequential) {
            /* Don't send overlapping reads with pending writes if data verification is on */
            std::unique_lock< std::mutex > lk(vinfo->vol_mutex);
            /* check if someone is already doing writes/reads */
            if (vinfo->m_vol_bm->is_bits_reset(lba, nlbas)) {
                vinfo->m_vol_bm->set_bits(lba, nlbas);
            } else {
                goto start;
            }
        }

        auto ret = read_vol(cur, lba, nlbas);
        return ret;
    }

    bool read_vol(uint32_t cur, uint64_t lba, uint64_t nlbas) {
        auto vinfo = m_voltest->vol_info[cur];
        auto vol = vinfo->vol;
        if (vol == nullptr) { return false; }

        auto vreq = boost::intrusive_ptr< io_req_t >(new io_req_t(vinfo, nullptr, lba, nlbas));
        vreq->cookie = (void*)this;

        ++m_voltest->output.read_cnt;
        ++m_outstanding_ios;
        auto ret_io = VolInterface::get_instance()->read(vol, vreq);
        LOGDEBUG("Read lba: {}, nlbas: {} outstanding_ios={}", lba, nlbas, m_outstanding_ios.load());
        if (ret_io != no_error) { return false; }
        return true;
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
                sisl::blob b = VolInterface::get_instance()->at_offset(buf, offset);

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
                        LOGINFO("mismatch found lba {} nlbas {} total_size_read {}", req->lba, req->nlbas,
                                tot_size_read);
#ifndef NDEBUG
                        VolInterface::get_instance()->print_tree(req->vol_info->vol);
#endif
                        LOGINFO("lba {} {}", req->lba, req->nlbas);
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
    bool is_job_done() const override { return m_is_job_done; }
    bool is_async_job() const override { return true; };
    std::string job_name() const override { return "VerifyJob"; }

private:
    std::shared_ptr< vol_info_t >& vol_info(uint32_t nth) { return m_voltest->vol_info[nth]; }
    bool m_is_job_done = false;
};

std::shared_ptr< IOTestJob > VolTest::start_io_job(wait_type_t wait_type, load_type_t load_type) {
    m_io_job = std::make_shared< IOTestJob >(this, load_type);
    this->start_job(m_io_job.get(), wait_type);
    return m_io_job;
}

thread_local std::list< vol_interface_req_ptr > VolTest::_completed_reqs_this_thread = {};

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

    FlipClient fc(HomeStoreFlip::instance());
    FlipFrequency freq;
    freq.set_count(10);
    freq.set_percent(100);

    fc.inject_retval_flip("vol_comp_delay_us", {}, freq, 100);
    this->delete_volumes();

    LOGINFO("All volumes are deleted, do a shutdown of homestore");
    this->shutdown();

    LOGINFO("Shutdown of homestore is completed, removing files");
    if (tcfg.remove_file) { this->remove_files(); }
}

/*!
    @test   init_io_test
    @brief  It initialize the homestore, create volume and
            shutdown the system
 */
TEST_F(VolTest, init_io_test) {
    this->start_homestore();
    this->start_io_job();
    output.print("init_io_test");
    this->shutdown();
    if (tcfg.remove_file) { this->remove_files(); }
}

/*!
    @test   recovery_io_test
    @brief  Tests which does recovery. End up with a clean shutdown
 */
TEST_F(VolTest, recovery_io_test) {
    tcfg.init = false;
    this->start_homestore();

    if (tcfg.verify_hdr || tcfg.verify_data || tcfg.verify_only) {
        auto verify_job = std::make_unique< VolVerifyJob >(this);
        this->start_job(verify_job.get(), wait_type_t::for_completion);
    }

    this->start_io_job();
    output.print("recovery_io_test");
    if (tcfg.can_delete_volume) { this->delete_volumes(); }
    this->shutdown();
    if (tcfg.remove_file) { this->remove_files(); }
}

/*!
    @test   vol_create_del_test
    @brief  Below tests delete volumes. Should exit with clean shutdown.
 */
TEST_F(VolTest, vol_create_del_test) {
    tcfg.precreate_volume = false;
    this->start_homestore();

    auto cdjob = std::make_unique< VolCreateDeleteJob >(this);
    this->start_job(cdjob.get(), wait_type_t::for_completion);
    output.print("vol_create_del_test");
    this->shutdown();
    if (tcfg.remove_file) { this->remove_files(); }
}

/************ Below tests check the workflows ***********/

TEST_F(VolTest, one_disk_replace_test) {
    tcfg.init = false;
    tcfg.disk_replace_cnt = 1;
    tcfg.expected_vol_state = homestore::vol_state::DEGRADED;
    this->start_homestore();

    output.print("one_disk_replace_test");
    this->shutdown();
    if (tcfg.remove_file) { this->remove_files(); }
}

TEST_F(VolTest, one_disk_replace_abort_test) {
    tcfg.init = false;
    tcfg.disk_replace_cnt = 1;
    tcfg.expected_init_fail = true;
    tcfg.expected_vol_state = homestore::vol_state::DEGRADED;

    FlipClient fc(HomeStoreFlip::instance());
    FlipFrequency freq;
    freq.set_count(100);
    freq.set_percent(100);
    fc.inject_noreturn_flip("reboot_abort", {}, freq);

    this->start_homestore();
    output.print("one_disk_replace_abort_test");
    this->shutdown();
    if (tcfg.remove_file) { this->remove_files(); }
}

TEST_F(VolTest, two_disk_replace_test) {
    tcfg.init = false;
    tcfg.disk_replace_cnt = 2;
    tcfg.expected_init_fail = true;

    this->start_homestore();
    this->start_io_job();

    output.print("two_disk_replace_test");
    this->shutdown();
    if (tcfg.remove_file) { this->remove_files(); }
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

    tcfg.init = false;
    tcfg.expected_init_fail = true;
    this->start_homestore();
    this->start_io_job();

    output.print("one_disk_fail_test");
    this->shutdown();
    if (tcfg.remove_file) { this->remove_files(); }
}

TEST_F(VolTest, vol_offline_test) {
    tcfg.expected_vol_state = vol_state::OFFLINE;
    this->start_homestore();

    tcfg.expect_io_error = true;
    auto job = this->start_io_job(wait_type_t::no_wait);
    this->move_vol_to_offline();
    job->wait_for_completion();
    this->shutdown();
}

TEST_F(VolTest, vol_io_fail_test) {
    tcfg.expect_io_error = true;
    this->start_homestore();

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

    auto job = this->start_io_job(wait_type_t::for_completion);
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
    this->start_io_job(wait_type_t::for_completion);
    output.print("btree_fix_read_failure_test");

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
    this->start_io_job(wait_type_t::for_completion);
    output.print("btree_fix_test");

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
    this->start_io_job(wait_type_t::for_completion);
    output.print("btree_fix_rerun_io_test");

    this->move_vol_to_offline();
    auto ret = this->fix_vol_mapping_btree();
    EXPECT_EQ(ret, true);

    output.write_cnt = 0;
    output.read_cnt = 0;
    this->move_vol_to_online();
    this->start_io_job(wait_type_t::for_execution);
    output.print("btree_fix_rerun_io_test");

    if (tcfg.can_delete_volume) { this->delete_volumes(); }
    this->shutdown();
    if (tcfg.remove_file) { this->remove_files(); }
}

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
     ::cxxopts::value< uint32_t >()->default_value("8192"), "mem_btree_page_size"),
    (expect_io_error, "", "expect_io_error", "expect_io_error", ::cxxopts::value< uint32_t >()->default_value("0"),
     "0 or 1"),
    (p_volume_size, "", "p_volume_size", "p_volume_size", ::cxxopts::value< uint32_t >()->default_value("60"),
     "0 to 200"),
    (spdk, "", "spdk", "spdk", ::cxxopts::value< bool >()->default_value("false"), "true or false"))
#define ENABLED_OPTIONS logging, home_blks, test_volume

SDS_OPTIONS_ENABLE(ENABLED_OPTIONS)

/************************** MAIN ********************************/

/* We can run this target either by using default options which run the normal io tests or by setting different
 * options. Format is
 *   1. ./test_volume
 *   2. ./test_volume --gtest_filter=*recovery* --run_time=120 --num_threads=16 --max_disk_capacity=10
 * --max_volume=50 Above command run all tests having a recovery keyword for 120 seconds with 16 threads , 10g
 * disk capacity and 50 volumes
 */
int main(int argc, char* argv[]) {
    srand(time(0));
    ::testing::GTEST_FLAG(filter) = "*lifecycle_test*";
    testing::InitGoogleTest(&argc, argv);
    SDS_OPTIONS_LOAD(argc, argv, ENABLED_OPTIONS)
    sds_logging::SetLogger("test_volume");
    spdlog::set_pattern("[%D %T.%f] [%^%L%$] [%t] %v");

    TestCfg& _gcfg = const_cast< TestCfg& >(gcfg);
    _gcfg.run_time = SDS_OPTIONS["run_time"].as< uint32_t >();
    _gcfg.num_threads = SDS_OPTIONS["num_threads"].as< uint32_t >();
    _gcfg.read_enable = SDS_OPTIONS["read_enable"].as< uint32_t >();
    _gcfg.max_disk_capacity = ((SDS_OPTIONS["max_disk_capacity"].as< uint64_t >()) * (1ul << 30));
    _gcfg.max_vols = SDS_OPTIONS["max_volume"].as< uint64_t >();
    _gcfg.max_num_writes = SDS_OPTIONS["max_num_writes"].as< uint64_t >();
    _gcfg.enable_crash_handler = SDS_OPTIONS["enable_crash_handler"].as< uint32_t >();
    _gcfg.verify_hdr = SDS_OPTIONS["verify_hdr"].as< uint64_t >() ? true : false;
    _gcfg.verify_data = SDS_OPTIONS["verify_data"].as< uint64_t >() ? true : false;
    _gcfg.read_verify = SDS_OPTIONS["read_verify"].as< uint64_t >() ? true : false;
    _gcfg.load_type = static_cast< load_type_t >(SDS_OPTIONS["load_type"].as< uint32_t >());
    _gcfg.remove_file = SDS_OPTIONS["remove_file"].as< uint32_t >();
    _gcfg.expected_vol_state = static_cast< homestore::vol_state >(SDS_OPTIONS["expected_vol_state"].as< uint32_t >());
    _gcfg.verify_only = SDS_OPTIONS["verify_only"].as< uint32_t >();
    _gcfg.is_abort = SDS_OPTIONS["abort"].as< uint32_t >();
    _gcfg.flip_set = SDS_OPTIONS["flip"].as< uint32_t >();
    _gcfg.can_delete_volume = SDS_OPTIONS["delete_volume"].as< uint32_t >() ? true : false;
    _gcfg.atomic_phys_page_size = SDS_OPTIONS["atomic_phys_page_size"].as< uint32_t >();
    _gcfg.vol_page_size = SDS_OPTIONS["vol_page_size"].as< uint32_t >();
    _gcfg.phy_page_size = SDS_OPTIONS["phy_page_size"].as< uint32_t >();
    _gcfg.mem_btree_page_size = SDS_OPTIONS["mem_btree_page_size"].as< uint32_t >();
    _gcfg.io_flags = static_cast< io_flag >(SDS_OPTIONS["io_flags"].as< uint32_t >());
    _gcfg.expect_io_error = SDS_OPTIONS["expect_io_error"].as< uint32_t >() ? true : false;
    _gcfg.p_volume_size = SDS_OPTIONS["p_volume_size"].as< uint32_t >();
    _gcfg.is_spdk = SDS_OPTIONS["spdk"].as< bool >();

    if (SDS_OPTIONS.count("device_list")) {
        _gcfg.dev_names = SDS_OPTIONS["device_list"].as< std::vector< std::string > >();
    }

    if (_gcfg.load_type == load_type_t::sequential) { _gcfg.verify_data = 0; }

    if (_gcfg.enable_crash_handler) { sds_logging::install_crash_handler(); }
    return RUN_ALL_TESTS();
}
