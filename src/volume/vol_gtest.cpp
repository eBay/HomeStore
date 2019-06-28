#include <gtest/gtest.h>
#include <iomgr/iomgr.hpp>
#include <sds_logging/logging.h>
#include <sds_options/options.h>
#include <main/vol_interface.hpp>
//#include <volume/home_blks.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <fstream>
#include <iostream>
#include <string>
#include <homeds/bitmap/bitset.hpp>
#include <atomic>
#include <string>
#include <utility/thread_buffer.hpp>
#include <chrono>
#include <thread>
extern "C" {
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timeb.h>
}

using namespace homestore;

THREAD_BUFFER_INIT;

/************************** GLOBAL VARIABLES ***********************/


#define MAX_DEVICES 2
#define HOMEBLKS_SB_FLAGS_SHUTDOWN 0x00000001UL

#define STAGING_VOL_PREFIX "staging"
#define VOL_PREFIX "/tmp/vol"

std::array< std::string, 4 > names = {"/tmp/file1", "/tmp/file2", "/tmp/file3", "/tmp/file4"};
uint64_t max_vols = 50;
uint64_t max_num_writes = 100000;
uint64_t run_time;
uint64_t num_threads;
bool read_enable = true;
bool enable_crash_handler = true;
constexpr auto Ki = 1024ull;
constexpr auto Mi = Ki * Ki;
constexpr auto Gi = Ki * Mi;
uint64_t max_io_size = 1 * Mi;
uint64_t max_outstanding_ios = 64u;
uint64_t max_disk_capacity = 10 * Gi;
uint64_t match_cnt = 0;
using log_level = spdlog::level::level_enum;
SDS_LOGGING_INIT(HOMESTORE_LOG_MODS)

/**************** Common class created for all tests ***************/

class test_ep : public iomgr::EndPoint {
public:
    test_ep(std::shared_ptr<iomgr::ioMgr> iomgr) :iomgr::EndPoint(iomgr) {
    }
    void shutdown_local() override {
    }
    void init_local() override {
    }
    void print_perf() override {
    }
};

uint64_t req_cnt = 0;
uint64_t req_free_cnt = 0;
class IOTest :  public ::testing::Test {
    struct req : vol_interface_req {
        ssize_t size;
        off_t offset;
        uint64_t lba;
        uint32_t nblks;
        int fd;
        uint8_t *buf;
        bool is_read;
        uint64_t cur_vol;
        req() {
            buf = nullptr;
            req_cnt++;
        }
        virtual ~req() {
            free(buf);
            req_free_cnt++;
        }   
    };
    struct vol_info_t {
       VolumePtr vol;
       int fd;
       int staging_fd;
       std::mutex vol_mutex;
       homeds::Bitset *m_vol_bm;
       uint64_t max_vol_blks;
       uint64_t cur_checkpoint;
       ~vol_info_t() {delete m_vol_bm;}
    };

protected:
    std::atomic<size_t> outstanding_ios;
    std::atomic<uint64_t> write_cnt;
    std::atomic<uint64_t> read_cnt;
    std::atomic<uint64_t> read_err_cnt;
    std::shared_ptr<iomgr::ioMgr> iomgr_obj;
    bool init;
    std::vector< std::shared_ptr<vol_info_t> > vol_info;
    std::atomic<uint64_t> vol_cnt;
    test_ep *ep;
    int ev_fd;
    std::condition_variable m_cv;
    std::mutex m_mutex;
    void *init_buf;
    uint64_t cur_vol;
    Clock::time_point startTime;
    std::vector<dev_info> device_info;
    uint64_t max_capacity;
    uint64_t max_vol_size;
    bool verify_done;
    bool move_verify_to_done;
    std::atomic<int> rdy_state;
    bool is_abort;
    bool shutdown_on_reboot;
    bool vol_create_del_test;
    Clock::time_point print_startTime;
    std::atomic<uint64_t> staging_match_cnt;
    std::atomic<uint64_t> vol_create_cnt;
    std::atomic<uint64_t> vol_del_cnt;
    std::atomic<uint64_t> vol_indx;

public:
    IOTest():vol_info(0), device_info(0), is_abort(false), staging_match_cnt(0) {
        vol_cnt = 0;
        cur_vol = 0;
        max_vol_size = 0;
        max_capacity = 0;
        verify_done = false;
        vol_create_del_test = false;
        move_verify_to_done = false;
        print_startTime = Clock::now();
        vol_indx = 0;
        vol_create_cnt = 0;
        vol_del_cnt = 0;
        outstanding_ios = 0;
        write_cnt = 0;
        read_cnt = 0;
        read_err_cnt = 0;
    }
    ~IOTest() {
        iomgr_obj->stop(); 
        iomgr_obj.reset();
        free(init_buf);
    }
    void remove_files() {
        for (auto &n : names) {
            remove(n.c_str());
        }

        for (uint32_t i = 0; i < max_vols; i++) {
            std::string name = VOL_PREFIX + std::to_string(i);
            remove(name.c_str());
            name = name + STAGING_VOL_PREFIX;
            remove(name.c_str());
        }
    }

    void print() {
    }

    void start_homestore() {
        /* start homestore */
            /* create files */
        for (uint32_t i = 0; i < MAX_DEVICES; i++) {
            dev_info temp_info;
            temp_info.dev_names = names[i];
            device_info.push_back(temp_info);
            if (init) {
                std::ofstream ofs(names[i].c_str(), std::ios::binary | std::ios::out);
                ofs.seekp(max_disk_capacity - 1);
                ofs.write("", 1);
                ofs.close();
            }
            max_capacity += max_disk_capacity;
        }
        /* Don't populate the whole disks. Only 80 % of it */
        max_vol_size = (60 * max_capacity)/ (100 * max_vols);

        iomgr_obj = std::make_shared<iomgr::ioMgr>(2, num_threads); 
        LOGINFO("OK1 iomgr_obj use_count: {}", iomgr_obj.use_count()); 
        init_params params; 
#if 0
        params.flag = homestore::io_flag::BUFFERED_IO;
#else
        params.flag = homestore::io_flag::DIRECT_IO;
#endif
        params.min_virtual_page_size = 2048;
        params.cache_size = 4 * 1024 * 1024 * 1024ul;
        params.disk_init = init;
        params.devices = device_info;
        params.is_file = true;
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
       vol_init(vol_obj);
       auto cb = [this](boost::intrusive_ptr<vol_interface_req> vol_req) { process_completions(vol_req); };
       VolInterface::get_instance()->attach_vol_completion_cb(vol_obj, cb);
    }

    void vol_init(const VolumePtr& vol_obj) {
        std::string file_name = std::string(VolInterface::get_instance()->get_name(vol_obj));
        std::string staging_file_name = file_name + STAGING_VOL_PREFIX;
        
        std::shared_ptr<vol_info_t> info = std::make_shared<vol_info_t> ();
        info->vol = vol_obj;
        info->fd = open(file_name.c_str(), O_RDWR | O_DIRECT); 
        info->staging_fd = open(staging_file_name.c_str(), O_RDWR | O_DIRECT);
        info->max_vol_blks = VolInterface::get_instance()->get_vol_capacity(vol_obj).initial_total_size /
                                VolInterface::get_instance()->get_page_size(vol_obj);
        info->m_vol_bm = new homeds::Bitset(info->max_vol_blks);;
        info->cur_checkpoint = 0;

        assert(info->fd > 0);
        assert(VolInterface::get_instance()->get_vol_capacity(vol_obj).initial_total_size == max_vol_size);
     
        std::unique_lock< std::mutex > lk(m_mutex);
        vol_info.push_back(info);
    }

    void vol_state_change_cb(const VolumePtr& vol, vol_state old_state, vol_state new_state) {
        assert(0);
    }
    void create_volume() {
        
        /* Create a volume */
        vol_params params;
        int cnt = vol_indx.fetch_add(1, std::memory_order_acquire);
        params.page_size = (cnt/2) ? 2048 : 4096;
        params.size = max_vol_size;
        params.io_comp_cb = ([this](const vol_interface_req_ptr& vol_req)
                { process_completions(vol_req); });
        params.uuid = boost::uuids::random_generator()();
        std::string name = VOL_PREFIX + std::to_string(cnt);
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

        /* open a corresponding file */
        vol_init(vol_obj);
    }

    void init_done_cb(std::error_condition err, const out_params& params) {
        /* create volume */
        rdy_state = 1;
        if (init) {
            if (!vol_create_del_test) {
                for (int vol_cnt = 0; vol_cnt < (int)max_vols; vol_cnt++) {
                    create_volume();
                }
                init_files();
            }
            verify_done = true;
            startTime = Clock::now();
        } else {
            assert(vol_cnt == max_vols);
            verify_done = false;
            LOGINFO("init completed, verify started");
        }
        max_io_size = params.max_io_size;
        auto ret = posix_memalign((void **) &init_buf, 4096, max_io_size);
        assert(!ret);
        bzero(init_buf, max_io_size);
        ev_fd = eventfd(0, EFD_NONBLOCK);

        iomgr_obj->add_fd(ev_fd, [this](auto fd, auto cookie, auto event) { process_ev_common(fd, cookie, event); },
                        EPOLLIN, 9, nullptr);
        ep = new test_ep(iomgr_obj);
        iomgr_obj->add_ep(ep);
        iomgr_obj->start();
        outstanding_ios = 0;
        uint64_t temp = 1;
        [[maybe_unused]] auto wsize = write(ev_fd, &temp, sizeof(uint64_t));
        return;
    }

    void vol_create_del() {
        while (1) {
            {
                std::unique_lock< std::mutex > lk(m_mutex);
                if (vol_create_cnt >= max_vols && vol_del_cnt >= max_vols) {
                    if (!outstanding_ios.load()) {
                        notify_cmpl();
                     }
                    return;
                }
                outstanding_ios++;
            }
            create_volume();
            vol_create_cnt++;
            if (delete_volume(random() % max_vols)) {
                vol_del_cnt++;
            }
            outstanding_ios--;
        }
    }

    void process_ev_common(int fd, void *cookie, int event) {
        uint64_t temp;
        [[maybe_unused]] auto rsize = read(ev_fd, &temp, sizeof(uint64_t));

        iomgr_obj->process_done(fd, event);
        if (vol_create_del_test) {
            iomgr_obj->fd_reschedule(fd, event);
            vol_create_del();
            return;
        }

        if ((write_cnt < max_num_writes) || (outstanding_ios.load() < max_outstanding_ios && get_elapsed_time(startTime) < run_time)) {
            /* raise an event */
            iomgr_obj->fd_reschedule(fd, event);
        }

        if (!verify_done) {
            verify_vols();
            return;
        }
        size_t cnt = 0;
        /* send 8 IOs in one schedule */
        while (cnt < 8 && outstanding_ios < max_outstanding_ios) {
            {
                std::unique_lock< std::mutex > lk(m_mutex);
                if (!rdy_state) {
                    return;
                }
            }
            random_write();
            if (read_enable) {
                random_read();
            }
            ++cnt;
        }
    }
    
    void init_files() {
        /* initialize the file */
        for (uint32_t i = 0; i < max_vols; ++i) {
            for (off_t offset = 0; offset < (off_t)max_vol_size; offset = offset + max_io_size) {
                ssize_t write_size;
                if (offset + max_io_size > max_vol_size) {
                    write_size = max_vol_size - offset;
                } else {
                    write_size = max_io_size;
                }
                auto ret = pwrite(vol_info[i]->fd, init_buf, write_size, (off_t) offset);
                assert(ret = write_size);
                if (ret != 0) {
                    return;
                }
                ret = pwrite(vol_info[i]->staging_fd, init_buf, write_size, (off_t) offset);
                assert(ret = write_size);
                if (ret != 0) {
                    return;
                }
            }
        }
    }

    void random_write() {
        /* XXX: does it really matter if it is atomic or not */
        int cur = ++cur_vol % max_vols;
        uint64_t lba;
        uint64_t nblks;
    start:
        /* we won't be writing more then 128 blocks in one io */
        uint64_t max_blks = max_io_size/VolInterface::get_instance()->get_page_size(vol_info[cur]->vol);
        lba = rand() % (vol_info[cur]->max_vol_blks - max_blks);
        nblks = rand() % max_blks;
        if (nblks == 0) { nblks = 1; }
        {
            std::unique_lock< std::mutex > lk(vol_info[cur]->vol_mutex);
            /* check if someone is already doing writes/reads */ 
            if (nblks && vol_info[cur]->m_vol_bm->is_bits_reset(lba, nblks)) {
                vol_info[cur]->m_vol_bm->set_bits(lba, nblks);
            } else {
                goto start;
            }
        }
        uint8_t *buf = nullptr;
        uint8_t *buf1 = nullptr;
        uint64_t size = nblks * VolInterface::get_instance()->get_page_size(vol_info[cur]->vol);
        auto ret = posix_memalign((void **) &buf, 4096, size);
        if (ret) {
            assert(0);
        }
        ret = posix_memalign((void **) &buf1, 4096, size);
        assert(!ret);
        /* buf will be owned by homestore after sending the IO. so we need to allocate buf1 which will be used to
         * write to a file after ios are completed.
         */
        assert(buf != nullptr);
        assert(buf1 != nullptr);
        populate_buf(buf, size, lba, cur);
       
        memcpy(buf1, buf, size);

        boost::intrusive_ptr<req> req(new struct req());
        req->lba = lba;
        req->nblks = nblks;
        req->size = size;
        req->offset = lba * VolInterface::get_instance()->get_page_size(vol_info[cur]->vol);
        req->buf = buf1;
        req->fd = vol_info[cur]->fd;
        req->is_read = false;
        req->cur_vol = cur;
        ++outstanding_ios;
        ++write_cnt;
        ret = pwrite(vol_info[cur]->staging_fd, req->buf, req->size, req->offset);
        assert(ret == req->size);
        auto ret_io = VolInterface::get_instance()->write(vol_info[cur]->vol, lba, buf, nblks, req);
        if (ret_io != no_error) {
            assert(0);
            free(buf);
            outstanding_ios--;
            std::unique_lock< std::mutex > lk(vol_info[cur]->vol_mutex);
            vol_info[cur]->m_vol_bm->reset_bits(lba, nblks);
        }
        LOGDEBUG("Wrote {} {} ",lba,nblks);
    }
    void populate_buf(uint8_t *buf, uint64_t size, uint64_t lba, int cur) {
        for (uint64_t write_sz = 0; (write_sz + sizeof(uint64_t)) < size; write_sz = write_sz + sizeof(uint64_t)) {
            *((uint64_t *)(buf + write_sz)) = random();
            if (!(write_sz % VolInterface::get_instance()->get_page_size(vol_info[cur]->vol))) {
                *((uint64_t *)(buf + write_sz)) = lba;
                ++lba;
            }
        }
    }

    void random_read() {
        /* XXX: does it really matter if it is atomic or not */
        int cur = ++cur_vol % max_vols;
        uint64_t lba;
        uint64_t nblks;
    start:
        /* we won't be writing more then 128 blocks in one io */
        uint64_t max_blks = max_io_size/VolInterface::get_instance()->get_page_size(vol_info[cur]->vol);

        lba = rand() % (vol_info[cur]->max_vol_blks - max_blks);
        nblks = rand() % max_blks;
        if (nblks == 0) { nblks = 1; }
        {
            std::unique_lock< std::mutex > lk(vol_info[cur]->vol_mutex);
            /* check if someone is already doing writes/reads */ 
            if (vol_info[cur]->m_vol_bm->is_bits_reset(lba, nblks))
                vol_info[cur]->m_vol_bm->set_bits(lba, nblks);
            else
                goto start;
        }
        read_vol(cur, lba, nblks);
        LOGDEBUG("Read {} {} ",lba,nblks);
    }

    void read_vol(uint32_t cur, uint64_t lba, uint64_t nblks) {
        uint8_t *buf = nullptr;
        uint64_t size = nblks * VolInterface::get_instance()->get_page_size(vol_info[cur]->vol);
        auto ret = posix_memalign((void **) &buf, 4096, size);
        if (ret) {
            assert(0);
        }
        assert(buf != nullptr);
        boost::intrusive_ptr<req> req(new struct req());
        req->lba = lba;
        req->nblks = nblks;
        req->fd = vol_info[cur]->fd;
        req->is_read = true;
        req->size = size;
        req->offset = lba * VolInterface::get_instance()->get_page_size(vol_info[cur]->vol);
        req->buf = buf;
        req->cur_vol = cur;
        outstanding_ios++;
        read_cnt++;
        auto ret_io = VolInterface::get_instance()->read(vol_info[cur]->vol, lba, nblks, req);
        if (ret_io != no_error) {
            outstanding_ios--;
            read_err_cnt++;
            std::unique_lock< std::mutex > lk(vol_info[cur]->vol_mutex);
            vol_info[cur]->m_vol_bm->reset_bits(lba, nblks);
        }
    }

    void verify(const VolumePtr& vol, boost::intrusive_ptr<req> req) {
        int64_t tot_size_read = 0;
        for (auto &info : req->read_buf_list) {
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
                size_read = 2048;
                int j = memcmp((void *) b.bytes, (uint8_t *)((uint64_t)req->buf + tot_size_read), size_read);
                match_cnt++;
                if (j) {
                   
                    if (!verify_done) {
                        /* compare it from the staging file */
                        auto ret = pread(vol_info[req->cur_vol]->staging_fd, (uint8_t *)((uint64_t)req->buf + tot_size_read),
                                            size_read, req->offset + tot_size_read);
                        if (ret != size_read) {
                            assert(0);
                        }
                        int j = memcmp((void *) b.bytes, (uint8_t *)((uint64_t)req->buf + tot_size_read), size_read);
                        staging_match_cnt++;
                        assert(j == 0);
                        /* update the data in primary file */
                        ret = pwrite(vol_info[req->cur_vol]->fd, (uint8_t *)((uint64_t)req->buf + tot_size_read), size_read, 
                                    req->offset + tot_size_read);
                        if (ret != size_read) {
                            assert(0);
                            return;
                        }
                    } else {
                        LOGINFO("mismatch found offset {} size {}", tot_size_read, size_read);
#ifndef NDEBUG
                        VolInterface::get_instance()->print_tree(vol);
#endif
                        LOGINFO("lba {} {}", req->lba, req->nblks);
                        std::this_thread::sleep_for(std::chrono::seconds(5)); 
                        sleep(30);
                        assert(0);
                    }
                }
                size -= size_read;
                offset += size_read;
                tot_size_read += size_read;
            }
        }
        assert(tot_size_read == req->size);
    }

    void verify_vols() {
        static uint64_t print_time = 30;
        auto elapsed_time = get_elapsed_time(print_startTime);
        if (elapsed_time > print_time) {
            LOGINFO("verifying vols");
            print_startTime = Clock::now();
       } 

        for (uint32_t cur = 0; cur < max_vols; ++cur) {
            uint64_t max_blks = (max_io_size / VolInterface::get_instance()->get_page_size(vol_info[cur]->vol));
            for (uint64_t lba = vol_info[cur]->cur_checkpoint; lba < vol_info[cur]->max_vol_blks;) {
                uint64_t io_size = 0;
                if (lba + max_blks > vol_info[cur]->max_vol_blks) {
                    io_size = vol_info[cur]->max_vol_blks - lba;
                } else {
                    io_size = max_blks;
                }
                read_vol(cur, lba, io_size);
                vol_info[cur]->cur_checkpoint = lba;
                if (outstanding_ios > max_outstanding_ios) {
                    return;
                }
                lba = lba + io_size;
            }
        }

        /* we move verify_done when all the outstanding IOs are completed */
        move_verify_to_done = true;
    }

    void process_completions(const vol_interface_req_ptr& vol_req) {
        /* raise an event */
        boost::intrusive_ptr<req> req = boost::static_pointer_cast<struct req>(vol_req);
        static uint64_t print_time = 30;
        uint64_t temp = 1;
        auto elapsed_time = get_elapsed_time(print_startTime);
        if (elapsed_time > print_time) {
            LOGINFO("write ios cmpled {}", write_cnt.load());
            LOGINFO("read ios cmpled {}", read_cnt.load());
            print_startTime = Clock::now();
        }
        

        LOGTRACE("IO DONE, req_id={}, outstanding_ios={}", vol_req->request_id, outstanding_ios.load());
        if (!req->is_read && req->err == no_error) {
            /* write to a file */
            auto ret = pwrite(req->fd, req->buf, req->size, req->offset);
            assert(ret == req->size);
        }
        assert(req->err == no_error);

        bool verify_io = false;
        
        if (!req->is_read && req->err == no_error && read_enable) {
            (void)VolInterface::get_instance()->sync_read(vol_info[req->cur_vol]->vol, req->lba, req->nblks, req);
            LOGTRACE("IO DONE, req_id={}, outstanding_ios={}", req->request_id, outstanding_ios.load());
            verify_io = true;
        }
        if ((req->is_read && req->err == no_error) || verify_io) {
            /* read from the file and verify it */
            auto ret = pread(req->fd, req->buf, req->size, req->offset);
            if (ret != req->size) {
                assert(0);
            }
            verify(vol_info[req->cur_vol]->vol, req);
        }
       
        {
            std::unique_lock< std::mutex > lk(vol_info[req->cur_vol]->vol_mutex);
            vol_info[req->cur_vol]->m_vol_bm->reset_bits(req->lba, req->nblks);
        }
        
        --outstanding_ios;
        if (move_verify_to_done && !verify_done) {
            if (outstanding_ios.load() == 0) {
                verify_done = true;
                LOGINFO("verfication from the staging file for {} number of blks", staging_match_cnt.load());
                LOGINFO("verify is done. starting IOs");
                startTime = Clock::now();
                [[maybe_unused]] auto rsize = read(ev_fd, &temp, sizeof(uint64_t));
                uint64_t size = write(ev_fd, &temp, sizeof(uint64_t));
                if (size != sizeof(uint64_t)) {
                    assert(0);
                }
            }
        }

        if (verify_done && ((write_cnt >= max_num_writes) || (get_elapsed_time(startTime) > run_time))) {
            LOGINFO("ios cmpled {}. waiting for outstanding ios to be completed", write_cnt.load());
            if (is_abort) {
                abort();
            }
            std::unique_lock< std::mutex > lk(m_mutex);
            rdy_state = 0;
            if (outstanding_ios.load() == 0) {
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

    uint64_t get_elapsed_time(Clock::time_point startTime) {
        std::chrono::seconds sec = std::chrono::duration_cast< std::chrono::seconds >(Clock::now() - startTime);
        return sec.count();
    }

    void notify_cmpl() {
        m_cv.notify_all();
    }

    void wait_cmpl() {
        std::unique_lock< std::mutex > lk(m_mutex);
        m_cv.wait(lk);
    }

    bool delete_volume(int vol_indx) {
        // std::move will release the ref_count in IOTest::vol and pass to HomeBlks::remove_volume
        boost::uuids::uuid uuid;
        {
            std::unique_lock< std::mutex > lk(m_mutex);
            if (vol_indx >= (int)vol_info.size()) {
                return false;
            }
            uuid = VolInterface::get_instance()->get_uuid(vol_info[vol_indx]->vol);
            vol_info.erase(vol_info.begin() + vol_indx);
        }
        VolInterface::get_instance()->remove_volume(uuid);
        assert(VolInterface::get_instance()->lookup_volume(uuid) == nullptr);
        return true;
    }

    void delete_volumes() {
        uint64_t tot_cap = VolInterface::get_instance()->get_system_capacity().initial_total_size;
        uint64_t used_cap = VolInterface::get_instance()->get_system_capacity().used_total_size;
        assert(used_cap <= tot_cap);
        while (!vol_info.empty()) {
            delete_volume(0);
        }
        used_cap = VolInterface::get_instance()->get_system_capacity().used_total_size;
        if (used_cap != 0) {
            assert(0);
        }
    }

    void shutdown_callback(bool success) {
        VolInterface::del_instance();
        assert(success);
    }
    
    void shutdown_force(bool timeout) {
        std::unique_lock< std::mutex > lk(m_mutex);
        bool force = false;
        // release the ref_count to volumes;
        if (!timeout) {
            vol_info.clear();
            force = true;
        }
        VolInterface::get_instance()->shutdown(std::bind(&IOTest::shutdown_callback, this, std::placeholders::_1), force);
    }

    void shutdown() {
        // release the ref_count to volumes;
        std::unique_lock< std::mutex > lk(m_mutex);
        vol_info.clear();
        VolInterface::get_instance()->shutdown(std::bind(&IOTest::shutdown_callback, this, std::placeholders::_1));
    }
};

/************************** Test cases ****************************/

/*********** Below Tests init the systems. Should exit with clean shutdown *************/

TEST_F(IOTest, normal_random_io_test) {
    /* fork a new process */
    this->init = true;
    /* child process */
    this->start_homestore();
    this->wait_cmpl();
    LOGINFO("write_cnt {}", write_cnt);
    LOGINFO("read_cnt {}", read_cnt);
    this->delete_volumes();
    this->shutdown();
    this->remove_files();
}

/* it bursts the IOs. max outstanding IOs are very high. In this testcase, it
 * will automatically be flow controlled by device.
 */
TEST_F(IOTest, burst_random_io_test) {
    /* fork a new process */
    max_outstanding_ios = 20000;
    this->init = true;
    /* child process */
    this->start_homestore();
    this->wait_cmpl();
    LOGINFO("write_cnt {}", write_cnt);
    LOGINFO("read_cnt {}", read_cnt);
    this->shutdown();
    this->remove_files();
}

/************ Below tests init the systems. Exit with abort. ****************/ 

TEST_F(IOTest, abort_random_io_test) {
    /* fork a new process */
    this->init = true;
    this->is_abort = true;
    /* child process */
    this->start_homestore();
    this->wait_cmpl();
    LOGINFO("write_cnt {}", write_cnt);
    LOGINFO("read_cnt {}", read_cnt);
}

/************ Below tests recover the systems. Exit with clean shutdown. *********/ 

/* Tests which does recovery. End up with a clean shutdown */
TEST_F(IOTest, recovery_random_io_test) {
    /* fork a new process */
    this->init = false;
    /* child process */
    this->start_homestore();
    this->wait_cmpl();
    this->remove_files();
}

/************ Below tests recover the systems. Exit with abort. ***********/ 

TEST_F(IOTest, recovery_abort_random_io_test) {
    /* fork a new process */
    this->init = false;
    this->is_abort = true;
    /* child process */
    this->start_homestore();
    this->wait_cmpl();
    this->remove_files();
}

/************ Below tests delete volumes. Should exit with clean shutdown. ***********/ 
TEST_F(IOTest, normal_vol_create_del_test) {
    this->init = true;
    this->vol_create_del_test = true;
    max_vols = 1000;
    this->start_homestore();
    this->wait_cmpl();
    this->shutdown();
}

/************ Below tests shutdown homestore. Should exit with clean shutdown. ***********/ 
TEST_F(IOTest, normal_force_shutdown_by_timeout_homeblks_test) {
    /* fork a new process */
    this->init = true;
    /* child process */
    this->start_homestore();
    this->wait_cmpl();
    LOGINFO("write_cnt {}", write_cnt);
    LOGINFO("read_cnt {}", read_cnt);
  
    this->shutdown_force(true);
    this->remove_files();
}

TEST_F(IOTest, normal_force_shutdown_by_api_homeblks_test) {
    /* fork a new process */
    this->init = true;
    /* child process */
    this->start_homestore();
    this->wait_cmpl();
    LOGINFO("write_cnt {}", write_cnt);
    LOGINFO("read_cnt {}", read_cnt);
  
    this->shutdown_force(false);
    this->remove_files();
}

// simulate reboot with m_cfg_sb flags set w/ shutdown bit 
TEST_F(IOTest, shutdown_on_reboot_homeblks_test) {
    /* fork a new process */
    this->init = false;
    this->shutdown_on_reboot = true;
    /* child process */
    this->start_homestore();
    this->wait_cmpl();
    this->remove_files();
}

TEST_F(IOTest, normal_shutdown_homeblks_with_incoming_io_test) {
 
}
   
/************************* CLI options ***************************/

SDS_OPTION_GROUP(test_volume, 
(run_time, "", "run_time", "run time for io", ::cxxopts::value<uint32_t>()->default_value("30"), "seconds"),
(num_threads, "", "num_threads", "num threads for io", ::cxxopts::value<uint32_t>()->default_value("8"), "number"),
(read_enable, "", "read_enable", "read enable 0 or 1", ::cxxopts::value<uint32_t>()->default_value("1"), "flag"),
(max_disk_capacity, "", "max_disk_capacity", "max disk capacity", ::cxxopts::value<uint64_t>()->default_value("7"), "GB"),
(max_volume, "", "max_volume", "max volume", ::cxxopts::value<uint64_t>()->default_value("50"), "number"),
(max_num_writes, "", "max_num_writes", "max num of writes", ::cxxopts::value<uint64_t>()->default_value("100000"), "number"),
(enable_crash_handler, "", "enable_crash_handler", "enable crash handler 0 or 1", ::cxxopts::value<uint32_t>()->default_value("1"), "flag"))


#define ENABLED_OPTIONS logging, home_blks, test_volume
SDS_OPTIONS_ENABLE(ENABLED_OPTIONS)

/************************** MAIN ********************************/

/* We can run this target either by using default options which run the normal io tests or by setting different options.
 * Format is
 *   1. ./test_volume
 *   2. ./test_volume --gtest_filter=*recovery* --run_time=120 --num_threads=16 --max_disk_capacity=10 --max_volume=50
 * Above command run all tests having a recovery keyword for 120 seconds with 16 threads , 10g disk capacity and 50 volumes
 */
int main(int argc, char *argv[]) {
    srand(time(0));
    ::testing::GTEST_FLAG(filter) = "*normal_random*";
    testing::InitGoogleTest(&argc, argv);
    SDS_OPTIONS_LOAD(argc, argv, ENABLED_OPTIONS)
    sds_logging::SetLogger("test_volume");
    spdlog::set_pattern("[%D %T.%f] [%^%L%$] [%t] %v");

    run_time = SDS_OPTIONS["run_time"].as<uint32_t>();
    num_threads = SDS_OPTIONS["num_threads"].as<uint32_t>();
    read_enable = SDS_OPTIONS["read_enable"].as<uint32_t>();
    max_disk_capacity = ((SDS_OPTIONS["max_disk_capacity"].as<uint64_t>())  * (1ul<< 30));
    max_vols = SDS_OPTIONS["max_volume"].as<uint64_t>();
    max_num_writes= SDS_OPTIONS["max_num_writes"].as<uint64_t>();
    enable_crash_handler = SDS_OPTIONS["enable_crash_handler"].as<uint32_t>();
    if (enable_crash_handler) sds_logging::install_crash_handler();
    return RUN_ALL_TESTS();
}
