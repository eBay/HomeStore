/*!
    @file   vol_gtest.cpp
    Volume Google Tests
 */
#include <gtest/gtest.h>
#include <iomgr/iomgr.hpp>
#include <sds_logging/logging.h>
#include <sds_options/options.h>
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
#include <chrono>
#include <thread>
extern "C" {
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timeb.h>
}

using namespace homestore;
using namespace flip;

THREAD_BUFFER_INIT;

/************************** GLOBAL VARIABLES ***********************/


#define MAX_DEVICES 2
#define HOMEBLKS_SB_FLAGS_SHUTDOWN 0x00000001UL

#define STAGING_VOL_PREFIX "staging"
#define VOL_PREFIX "/tmp/vol"

std::array< std::string, 4 > names = {"/tmp/vol_file1", "/tmp/vol_file2", "/tmp/vol_file3", "/tmp/vol_file4"};
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
std::atomic<uint64_t> match_cnt = 0;
std::atomic<uint64_t> hdr_only_match_cnt = 0;
using log_level = spdlog::level::level_enum;
bool verify_hdr = true;
bool verify_data = true;
bool read_verify = false;
uint32_t load_type = 0;
uint32_t remove_file = 1;
uint32_t expected_vol_state = 0;
uint32_t verify_only = 0;
uint32_t is_abort = 0;
uint32_t flip_set = 0;
uint32_t atomic_page_size = 512;
uint32_t vol_page_size = 4096;
uint32_t phy_page_size = 4096;
uint32_t mem_btree_page_size = 4096;
bool can_delete_volume = false;
extern bool vol_gtest;
std::vector< std::string > dev_names;
#define VOL_PAGE_SIZE 4096
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
        bool done = false;
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
       std::mutex vol_mutex;
       homeds::Bitset *m_vol_bm;
       uint64_t max_vol_blks;
       uint64_t cur_checkpoint;
       std::atomic<uint64_t> start_lba;
       std::atomic<uint64_t> start_large_lba; 
       std::atomic<uint64_t> num_io;
       vol_info_t() : start_lba(0), start_large_lba(0), num_io(0) {}; 
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
    std::condition_variable m_init_done_cv;
    std::mutex m_mutex;
    void *init_buf = nullptr;
    uint64_t cur_vol;
    Clock::time_point startTime;
    std::vector<dev_info> device_info;
    uint64_t max_capacity;
    uint64_t max_vol_size;
    bool verify_done;
    bool move_verify_to_done;
    bool shutdown_on_reboot;
    bool vol_create_del_test;
    int disk_replace_cnt = 0;
    bool vol_offline = false;
    bool expect_io_error = false;
    Clock::time_point print_startTime;
    std::atomic<uint64_t> vol_create_cnt;
    std::atomic<uint64_t> vol_del_cnt;
    std::atomic<uint64_t> vol_indx;
    std::atomic<bool> io_stalled = false;
    homestore::vol_state m_expected_vol_state = homestore::vol_state::ONLINE;
    bool expected_init_fail = false;
    bool cmpl_done_signaled = false;
    bool iomgr_start = false;

public:
    IOTest():vol_info(0), device_info(0) {
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
        srandom(time(NULL));
    }
    ~IOTest() {
        iomgr_obj.reset();
        if (init_buf) {
            free(init_buf);
        }
    }
    void remove_files() {
        /* no need to delete the user created file/disk */
        if (dev_names.size() == 0) {
            for (auto &n : names) {
                remove(n.c_str());
            }
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

        if (dev_names.size() != 0) {
            for (uint32_t i = 0; i < dev_names.size(); i++) {
                dev_info temp_info;
                temp_info.dev_names = dev_names[i];
                /* we use this capacity to calculate volume size */
                max_capacity += max_disk_capacity;
                device_info.push_back(temp_info);
            }
        } else {
            for (uint32_t i = 0; i < MAX_DEVICES; i++) {
                dev_info temp_info;
                temp_info.dev_names = names[i];
                device_info.push_back(temp_info);
                if (init || disk_replace_cnt > 0) {
                    if (!init) {
                        remove(names[i].c_str());
                    }
                    std::ofstream ofs(names[i].c_str(), std::ios::binary | std::ios::out);
                    ofs.seekp(max_disk_capacity - 1);
                    ofs.write("", 1);
                    ofs.close();
                    --disk_replace_cnt;
                }
                max_capacity += max_disk_capacity;
            }
        }
        /* Don't populate the whole disks. Only 80 % of it */
        max_vol_size = (60 * max_capacity)/ (100 * max_vols);

        iomgr_obj = std::make_shared<iomgr::ioMgr>(2, num_threads); 
        
        init_params params; 
#if 0
        params.flag = homestore::io_flag::BUFFERED_IO;
#else
        params.flag = homestore::io_flag::DIRECT_IO;
#endif
        params.min_virtual_page_size = vol_page_size;
        params.cache_size = 4 * 1024 * 1024 * 1024ul;
        params.disk_init = init;
        params.devices = device_info;
        params.is_file = dev_names.size() ? false : true;
        params.iomgr = iomgr_obj;
        params.init_done_cb = std::bind(&IOTest::init_done_cb, this, std::placeholders::_1, std::placeholders::_2);
        params.vol_mounted_cb = std::bind(&IOTest::vol_mounted_cb, this, std::placeholders::_1, std::placeholders::_2);
        params.vol_state_change_cb = std::bind(&IOTest::vol_state_change_cb, this, std::placeholders::_1, 
                                                std::placeholders::_2, std::placeholders::_3);
        params.vol_found_cb = std::bind(&IOTest::vol_found_cb, this, std::placeholders::_1);
       
        params.disk_attr = disk_attributes();
        params.disk_attr->physical_page_size = phy_page_size;
        params.disk_attr->disk_align_size = 4096;
        params.disk_attr->atomic_page_size = atomic_page_size;
#ifndef NDEBUG
        params.mem_btree_page_size = mem_btree_page_size;
#endif  
        boost::uuids::string_generator gen;
        params.system_uuid = gen("01970496-0262-11e9-8eb2-f2801f1b9fd1");
        VolInterface::init(params);
    }
   
    bool fix_vol_mapping_btree() {
        /* fix all volumes mapping btrees */
        for (uint64_t i = 0; i < max_vols; ++i) {
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
        for (uint64_t i = 0; i < max_vols; ++i) {
            VolInterface::get_instance()->vol_state_change(vol_info[i]->vol, homestore::vol_state::OFFLINE);
        }
    }

    void move_vol_to_online() {
        /* move all volumes to online */
        for (uint64_t i = 0; i < max_vols; ++i) {
            VolInterface::get_instance()->vol_state_change(vol_info[i]->vol, homestore::vol_state::ONLINE);
        }
        /* start ios */
        uint64_t temp = 1;
        [[maybe_unused]] auto wsize = write(ev_fd, &temp, sizeof(uint64_t));
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
       assert(state == m_expected_vol_state);
       if (m_expected_vol_state == homestore::vol_state::DEGRADED || 
            m_expected_vol_state == homestore::vol_state::OFFLINE) {
            VolInterface::get_instance()->vol_state_change(vol_obj, ONLINE);
       }
    }

    void vol_init(const VolumePtr& vol_obj) {
        std::string file_name = std::string(VolInterface::get_instance()->get_name(vol_obj));
        std::string staging_file_name = file_name + STAGING_VOL_PREFIX;
        
        std::shared_ptr<vol_info_t> info = std::make_shared<vol_info_t> ();
        info->vol = vol_obj;
        info->fd = open(file_name.c_str(), O_RDWR); 
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
        assert(new_state == homestore::vol_state::FAILED);
    }
    
    void create_volume() {
        
        /* Create a volume */
        vol_params params;
        int cnt = vol_indx.fetch_add(1, std::memory_order_acquire);
        params.page_size = vol_page_size;
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
        if (err) {
            assert(expected_init_fail);
            {
                std::unique_lock< std::mutex > lk(m_mutex);
                m_init_done_cv.notify_all();
            }
            notify_cmpl();
            return;
        }
        max_io_size = params.max_io_size;
        auto ret = posix_memalign((void **) &init_buf, 4096, max_io_size);
        assert(!ret);
        bzero(init_buf, max_io_size);
        assert(!expected_init_fail);
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
            if (verify_hdr || verify_data) {
                verify_done = false;
                LOGINFO("init completed, verify started");
            } else {
                verify_done = true;
                startTime = Clock::now();
            }
        }
        max_io_size = params.max_io_size;
        ev_fd = eventfd(0, EFD_NONBLOCK);

        iomgr_obj->add_fd(ev_fd, [this](auto fd, auto cookie, auto event) { process_ev_common(fd, cookie, event); },
                        EPOLLIN, 9, nullptr);
        ep = new test_ep(iomgr_obj);
        iomgr_obj->add_ep(ep);
        iomgr_obj->start();
        iomgr_start = true;
        outstanding_ios = 0;

        uint64_t temp = 1;
        [[maybe_unused]] auto wsize = write(ev_fd, &temp, sizeof(uint64_t));

        std::unique_lock< std::mutex > lk(m_mutex);
        /* notify who is waiting for init to be completed */
        m_init_done_cv.notify_all();

#ifdef _PRERELEASE
        if (flip_set == 1) {
            VolInterface::get_instance()->set_io_flip();
        } else if (flip_set == 2) {
            expect_io_error = true;
            VolInterface::get_instance()->set_io_flip();
            VolInterface::get_instance()->set_error_flip();
        }
#endif
        return;
    }

    void vol_create_del() {
        while (1) {
            {
                if (vol_create_cnt >= max_vols && vol_del_cnt >= max_vols) {
                    notify_cmpl();
                    return;
                }

                std::unique_lock< std::mutex > lk(m_mutex);
                if (!io_stalled) {
                    outstanding_ios++;
                }
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

        if ((outstanding_ios.load() < max_outstanding_ios && io_stalled.load() == false)) {
            /* raise an event */
            iomgr_obj->fd_reschedule(fd, event);
        } else {
            return;
        }

        if (!verify_done) {
            verify_vols();
            return;
        }
        size_t cnt = 0;
        /* send 8 IOs in one schedule */
        while (cnt < 8 && outstanding_ios < max_outstanding_ios) {
            {
                if (io_stalled) {
                    break;
                }
            }
            write_io();
            if (read_enable) {
                read_io();
            }
            ++cnt;
        }
        
    }
    
    void write_io() {
        switch (load_type) {
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
        switch (load_type) {
            case 0:
                random_read();
                break;
            case 1:
                same_read();
                break;
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
                assert(ret == write_size);
                if (ret != 0) {
                    return;
                }
            }
        }
    }

    void same_write() {
        write_vol(0, 5, 100);
    }

    void seq_write() { 
        /* XXX: does it really matter if it is atomic or not */
        int cur = ++cur_vol % max_vols;
        uint64_t lba; 
        uint64_t nblks;
start:
        /* we won't be writing more then 128 blocks in one io */
        auto vol = vol_info[cur]->vol;
        if (vol == nullptr) {
            return;
        }    
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

        if (load_type != 2) {
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

    void same_read() {
        read_vol(0, 5, 100);
    }

    void random_write() {
        /* XXX: does it really matter if it is atomic or not */
        int cur = ++cur_vol % max_vols;
        uint64_t lba;
        uint64_t nblks;
    start:
        /* we won't be writing more then 128 blocks in one io */
        auto vol = vol_info[cur]->vol;
        if (vol == nullptr) {
            return;
        }
        uint64_t max_blks = max_io_size/VolInterface::get_instance()->get_page_size(vol);
        // lba: [0, max_vol_blks - max_blks)
        lba = rand() % (vol_info[cur]->max_vol_blks - max_blks);
        // nblks: [1, max_blks]
        nblks = rand() % (max_blks + 1);
        if (nblks == 0) { nblks = 1; }

        if (load_type != 2) {
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
        uint8_t *buf = nullptr;
        uint8_t *buf1 = nullptr;
        auto vol = vol_info[cur]->vol;
        if (vol == nullptr) {
            return;
        }
        {
            std::unique_lock< std::mutex > lk(m_mutex);
            if (io_stalled) {
                return;
            } else {
                ++outstanding_ios;
            }
        }
        uint64_t size = nblks * VolInterface::get_instance()->get_page_size(vol);
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
        req->offset = lba * VolInterface::get_instance()->get_page_size(vol);
        req->buf = buf1;
        req->fd = vol_info[cur]->fd;
        req->is_read = false;
        req->cur_vol = cur;
        
        ++write_cnt;
        auto ret_io = VolInterface::get_instance()->write(vol, lba, buf, nblks, req);
        if (ret_io != no_error) {
            assert(ret_io == std::errc::no_such_device || expect_io_error);
            process_completions(req);
        }
        
        LOGDEBUG("Wrote lba: {}, nblks: {} ", lba, nblks);
    }

    void populate_buf(uint8_t *buf, uint64_t size, uint64_t lba, int cur) {
        for (uint64_t write_sz = 0; write_sz < size; write_sz = write_sz + sizeof(uint64_t)) {
            if (!(write_sz % vol_page_size)) {
                *((uint64_t *)(buf + write_sz)) = lba;
                auto vol = vol_info[cur]->vol;
                if (vol == nullptr) {
                    return;
                }
                if (!((write_sz % VolInterface::get_instance()->get_page_size(vol)))) {
                    ++lba;
                }
            } else {
                *((uint64_t *)(buf + write_sz)) = random();
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
        auto vol = vol_info[cur]->vol;
        if (vol == nullptr) {
            return;
        }
        uint64_t max_blks = max_io_size/VolInterface::get_instance()->get_page_size(vol);

        lba = rand() % (vol_info[cur]->max_vol_blks - max_blks);
        nblks = rand() % max_blks;
        if (nblks == 0) { nblks = 1; }
        
        if (load_type != 2) {
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
        LOGDEBUG("Read {} {} ",lba,nblks);
    }

    void read_vol(uint32_t cur, uint64_t lba, uint64_t nblks) {
        uint8_t *buf = nullptr;
        auto vol = vol_info[cur]->vol;
        if (vol == nullptr) {
            return;
        }
        {
            std::unique_lock< std::mutex > lk(m_mutex);
            if (io_stalled) {
                return;
            } else {
                ++outstanding_ios;
            }
        }
        uint64_t size = nblks * VolInterface::get_instance()->get_page_size(vol);
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
        req->offset = lba * VolInterface::get_instance()->get_page_size(vol);
        req->buf = buf;
        req->cur_vol = cur;
        read_cnt++;
        auto ret_io = VolInterface::get_instance()->read(vol, lba, nblks, req);
        if (ret_io != no_error) {
            assert(ret_io == std::errc::no_such_device || expect_io_error);
            process_completions(req);
        }
    }

    bool verify(const VolumePtr& vol, boost::intrusive_ptr<req> req, bool can_panic) {
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
                size_read = vol_page_size;
                int j = 0;
                if (verify_data) {
                    j = memcmp((void *) b.bytes, (uint8_t *)((uint64_t)req->buf + tot_size_read), size_read);
                    match_cnt++;
                }

                if (j != 0 && (!verify_data || !verify_done)) {
                    /* we will only verify the header. We write lba number in the header */
                    j = memcmp((void *) b.bytes, (uint8_t *)((uint64_t)req->buf + tot_size_read), sizeof (uint64_t));
                    if (!j) {
                        /* copy the data */
                        auto ret = pwrite(vol_info[req->cur_vol]->fd, b.bytes, b.size, tot_size_read + req->offset);
                        assert(ret == b.size);
                    }
                    hdr_only_match_cnt++;
                }
                if (j) {
                    if (can_panic) {
                        
                        /* verify the header */
                        j = memcmp((void *) b.bytes, (uint8_t *)((uint64_t)req->buf + tot_size_read), sizeof (uint64_t));
                        if (j != 0) {
                            LOGINFO("header mismatch lba read {}", *((uint64_t *)b.bytes));
                        }
                        LOGINFO("mismatch found lba {} nlba {} total_size_read {}", req->lba, req->nblks, 
                                    tot_size_read);
#ifndef NDEBUG
                        VolInterface::get_instance()->print_tree(vol);
#endif
                        LOGINFO("lba {} {}", req->lba, req->nblks);
                        std::this_thread::sleep_for(std::chrono::seconds(5)); 
                        sleep(30);
                        assert(0);
                    } else {
                        return false;
                    }
                }
                size -= size_read;
                offset += size_read;
                tot_size_read += size_read;
            }
        }
        assert(tot_size_read == req->size);
        return true;
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
                vol_info[cur]->cur_checkpoint = lba + io_size;
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

        /* it validates that we don't have two completions for the same requests */
        assert(!req->done);
        req->done = true;
        
        if (elapsed_time > print_time) {
            LOGINFO("write ios cmpled {}", write_cnt.load());
            LOGINFO("read ios cmpled {}", read_cnt.load());
            print_startTime = Clock::now();
        }
        
        assert(req->err == no_error || expect_io_error || req->err == std::errc::no_such_device);
        LOGTRACE("IO DONE, req_id={}, outstanding_ios={}", vol_req->request_id, outstanding_ios.load());
        if (!req->is_read && req->err == no_error) {
            /* write to a file */
            auto ret = pwrite(req->fd, req->buf, req->size, req->offset);
            assert(ret == req->size);
        }

        bool verify_io = false;
        
        if (!req->is_read && req->err == no_error && read_verify) {
            (void)VolInterface::get_instance()->sync_read(vol_info[req->cur_vol]->vol, req->lba, req->nblks, req);
            LOGTRACE("IO DONE, req_id={}, outstanding_ios={}", req->request_id, outstanding_ios.load());
            verify_io = true;
        } else if ((req->is_read && req->err == no_error)) {
            verify_io = true;
        }

        if (verify_io && (verify_hdr || verify_data)) {
            /* read from the file and verify it */
            auto ret = pread(req->fd, req->buf, req->size, req->offset);
            if (ret != req->size) {
                assert(0);
            }
            verify(vol_info[req->cur_vol]->vol, req, true);
        }
       
        {
            std::unique_lock< std::mutex > lk(vol_info[req->cur_vol]->vol_mutex);
            vol_info[req->cur_vol]->m_vol_bm->reset_bits(req->lba, req->nblks);
        }
        
        outstanding_ios--;
        if (move_verify_to_done && !verify_done) {
            if (outstanding_ios.load() == 0) {
                verify_done = true;
                LOGINFO("verfied only hdr {} number of blks", hdr_only_match_cnt.load());
                LOGINFO("verify is done. starting IOs");
                if (verify_only) {
                    notify_cmpl();
                    return;
                }
                startTime = Clock::now();
                [[maybe_unused]] auto rsize = read(ev_fd, &temp, sizeof(uint64_t));
                uint64_t size = write(ev_fd, &temp, sizeof(uint64_t));
                if (size != sizeof(uint64_t)) {
                    assert(0);
                }
            }
        }

        if (verify_done && is_abort) {
            if (get_elapsed_time(startTime) > (random() % run_time)) {
                abort();
            }
        }

        if (verify_done && time_to_stop()) {
            notify_cmpl();
        } else {
            [[maybe_unused]] auto rsize = read(ev_fd, &temp, sizeof(uint64_t));
            uint64_t size = write(ev_fd, &temp, sizeof(uint64_t));
            if (size != sizeof(uint64_t)) {
                assert(0);
            }
        }
    }

    bool time_to_stop() {
        return (write_cnt >= max_num_writes) || (get_elapsed_time(startTime) > run_time);
    }

    uint64_t get_elapsed_time(Clock::time_point startTime) {
        std::chrono::seconds sec = std::chrono::duration_cast< std::chrono::seconds >(Clock::now() - startTime);
        return sec.count();
    }


    void notify_cmpl() {
        std::unique_lock< std::mutex > lk(m_mutex);
        io_stalled = true;
        m_cv.notify_all();
    }

    void wait_homestore_init_done() {
        std::unique_lock< std::mutex > lk(m_mutex);
        m_init_done_cv.wait(lk);
    }

    void wait_cmpl() {
        std::unique_lock< std::mutex > lk(m_mutex);
        if (io_stalled) {
            return;
        }
        m_cv.wait(lk);
    }

    bool delete_volume(int vol_indx) {
        // std::move will release the ref_count in IOTest::vol and pass to HomeBlks::remove_volume
        boost::uuids::uuid uuid;
        {
            std::unique_lock< std::mutex > lk(m_mutex);
            if (vol_indx >= (int)vol_info.size() || vol_info[vol_indx]->vol == nullptr) {
                return false;
            }
            uuid = VolInterface::get_instance()->get_uuid(vol_info[vol_indx]->vol);
            vol_info[vol_indx]->vol = nullptr;
        }
        VolInterface::get_instance()->remove_volume(uuid);
        assert(VolInterface::get_instance()->lookup_volume(uuid) == nullptr);
        return true;
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
       
        {
            std::unique_lock< std::mutex > lk(m_mutex);
            assert(io_stalled);
            while (outstanding_ios.load() != 0) {
                m_cv.wait(lk);
            }
        }
        LOGINFO("stopping iomgr");
        if (iomgr_start) {
            iomgr_obj->stop();
        }

        {
            std::unique_lock< std::mutex > lk(m_mutex);
            vol_info.clear();
        }
        LOGINFO("shutting homestore");
        VolInterface::get_instance()->shutdown(std::bind(&IOTest::shutdown_callback, this, std::placeholders::_1));
    }
};

/************************** Test cases ****************************/

/*********** Below Tests does IO and exit with clean shutdown *************/

/*!
    @test   lifecycle_test
    @brief  It initialize the homestore, create volume, delete volume 
            and shutdown the system
 */
TEST_F(IOTest, lifecycle_test) {
    this->init = true;
    this->start_homestore();
    this->wait_cmpl();
    LOGINFO("write_cnt {}", write_cnt);
    LOGINFO("read_cnt {}", read_cnt);

    FlipClient fc(HomeStoreFlip::instance());
    FlipFrequency freq;
    freq.set_count(10);
    freq.set_percent(100);

    fc.inject_retval_flip("vol_comp_delay_us", {}, freq, 100);
    this->delete_volumes();
    this->shutdown();
    this->remove_files();
}

/*!
    @test   init_io_test
    @brief  It initialize the homestore, create volume and
            shutdown the system
 */
TEST_F(IOTest, init_io_test) {
    this->init = true;
    this->start_homestore();
    this->wait_cmpl();
    LOGINFO("write_cnt {}", write_cnt);
    LOGINFO("read_cnt {}", read_cnt);
    this->shutdown();
    if (remove_file) {
        this->remove_files();
    }
}

/*!
    @test   recovery_io_test
    @brief  Tests which does recovery. End up with a clean shutdown
 */
TEST_F(IOTest, recovery_io_test) {
    this->init = false;
    switch (expected_vol_state) {
        case 0:
            this->m_expected_vol_state = homestore::vol_state::ONLINE;
            break;
        case 1:
            this->m_expected_vol_state = homestore::vol_state::OFFLINE;
            break;
        case 2:
            this->m_expected_vol_state = homestore::vol_state::DEGRADED;
            break;
        case 3:
            this->m_expected_vol_state = homestore::vol_state::FAILED;
            break;
    }
    this->start_homestore();
    this->wait_cmpl();
    if (can_delete_volume) {
        this->delete_volumes();
    }
    this->shutdown();
    if (remove_file) {
        this->remove_files();
    }
}

/*!
    @test   vol_create_del_test
    @brief  Below tests delete volumes. Should exit with clean shutdown.
 */
TEST_F(IOTest, vol_create_del_test) {
    this->init = true;
    this->vol_create_del_test = true;
    this->start_homestore();
    this->wait_cmpl();
    this->shutdown();
    this->remove_files();
}

/************ Below tests check the workflows ***********/

TEST_F(IOTest, one_disk_replace_test) {
    this->init = false;
    this->disk_replace_cnt = 1;
    this->m_expected_vol_state = homestore::vol_state::DEGRADED;
    this->start_homestore();
    this->wait_cmpl();
    this->shutdown();
    if (remove_file) {
        this->remove_files();
    }
}

TEST_F(IOTest, one_disk_replace_abort_test) {
    this->init = false;
    this->disk_replace_cnt = 1;
    this->expected_init_fail = true;
    this->m_expected_vol_state = homestore::vol_state::DEGRADED;
    
    FlipClient fc(HomeStoreFlip::instance());
    FlipFrequency freq;
    freq.set_count(100);
    freq.set_percent(100);
    fc.inject_noreturn_flip("reboot_abort", { }, freq);
    
    this->start_homestore();
    this->wait_cmpl();
    this->shutdown();
    if (remove_file) {
        this->remove_files();
    }
}

TEST_F(IOTest, two_disk_replace_test) {
    this->init = false;
    this->disk_replace_cnt = 2;
    this->expected_init_fail = true;
    this->start_homestore();
    this->wait_cmpl();
    this->shutdown();
}

TEST_F(IOTest, one_disk_fail_test) {
    this->init = false;

    FlipClient fc(HomeStoreFlip::instance());
    FlipFrequency freq;
    FlipCondition cond1;
    FlipCondition cond2;
    freq.set_count(100);
    freq.set_percent(100);
    fc.create_condition("setting error on file1", flip::Operator::EQUAL, names[0], &cond1);
    fc.inject_noreturn_flip("device_boot_fail", { cond1 }, freq);

    this->expected_init_fail = true;
    this->start_homestore();
    this->wait_cmpl();
    this->shutdown();
    if (remove_file) {
        this->remove_files();
    }
}

TEST_F(IOTest, vol_offline_test) {
    this->init = true;
    this->m_expected_vol_state = OFFLINE;
    this->start_homestore();
    this->wait_homestore_init_done();
    this->expect_io_error = true;
    this->move_vol_to_offline();
    this->wait_cmpl();
    this->shutdown();
}

TEST_F(IOTest, vol_io_fail_test) {
    this->init = true;
    this->expect_io_error = true;
    this->start_homestore();
    this->wait_homestore_init_done();
    
    FlipClient fc(HomeStoreFlip::instance());
    FlipCondition cond1;
    FlipCondition cond2;
    FlipFrequency freq;
    fc.create_condition("setting error on file1", flip::Operator::EQUAL, names[0], &cond1);
    fc.create_condition("setting error on file2", flip::Operator::EQUAL, names[1], &cond2);
    freq.set_count(2000);
    freq.set_percent(50);
    fc.inject_noreturn_flip("io_write_comp_error_flip", {}, freq);
    fc.inject_noreturn_flip("device_fail", { cond1, cond2 }, freq);
    
    this->wait_cmpl();
    this->shutdown();
    if (remove_file) {
        this->remove_files();
    }
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
 * @param IOTest
 * @param btree_fix_read_failure_test
 */
TEST_F(IOTest, btree_fix_read_failure_test) {
    this->init = true;
    this->start_homestore();

    this->wait_cmpl();
    LOGINFO("write_cnt {}", write_cnt);
    LOGINFO("read_cnt {}", read_cnt);

    sleep(5);

    this->move_vol_to_offline();

    VolInterface::get_instance()->set_error_flip();

    auto ret = this->fix_vol_mapping_btree();
    EXPECT_EQ(ret, false);

    this->delete_volumes();

    this->shutdown();
    if (remove_file) {
        this->remove_files();
    }
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
 * @param IOTest
 * @param btree_fix_test
 */
TEST_F(IOTest, btree_fix_test) {
    this->init = true;
    this->start_homestore();

    this->wait_cmpl();
    LOGINFO("write_cnt {}", write_cnt);
    LOGINFO("read_cnt {}", read_cnt);

    sleep(5);
    assert(outstanding_ios == 0);  

    this->move_vol_to_offline();
    auto ret = this->fix_vol_mapping_btree();
    EXPECT_EQ(ret, true);

    this->delete_volumes();

    this->shutdown();
    if (remove_file) {
        this->remove_files();
    }
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
 * @param IOTest
 * @param btree_fix_test
 */
TEST_F(IOTest, btree_fix_rerun_io_test) {
    this->init = true;
    this->start_homestore();

    this->wait_cmpl();
    LOGINFO("write_cnt {}", write_cnt);
    LOGINFO("read_cnt {}", read_cnt);

    sleep(5);
    assert(outstanding_ios == 0);  

    this->move_vol_to_offline();
    auto ret = this->fix_vol_mapping_btree();
    EXPECT_EQ(ret, true);

    startTime = Clock::now();
    write_cnt = 0;
    read_cnt = 0;
    io_stalled = false;
    this->move_vol_to_online();
    
    this->wait_cmpl();
    LOGINFO("write_cnt {}", write_cnt);
    LOGINFO("read_cnt {}", read_cnt);
    
    sleep(5);
    assert(outstanding_ios == 0);  
        
    if (can_delete_volume) {
        this->delete_volumes();
    }

    this->shutdown();
    if (remove_file) {
        this->remove_files();
    }
}
 
/************************* CLI options ***************************/

SDS_OPTION_GROUP(test_volume, 
(run_time, "", "run_time", "run time for io", ::cxxopts::value<uint32_t>()->default_value("30"), "seconds"),
(load_type, "", "load_type", "load_type", ::cxxopts::value<uint32_t>()->default_value("0"), "random_write_read:0, same_write_read:1, overlap_write=2"),
(num_threads, "", "num_threads", "num threads for io", ::cxxopts::value<uint32_t>()->default_value("8"), "number"),
(read_enable, "", "read_enable", "read enable 0 or 1", ::cxxopts::value<uint32_t>()->default_value("1"), "flag"),
(max_disk_capacity, "", "max_disk_capacity", "max disk capacity", ::cxxopts::value<uint64_t>()->default_value("7"), "GB"),
(max_volume, "", "max_volume", "max volume", ::cxxopts::value<uint64_t>()->default_value("50"), "number"),
(max_num_writes, "", "max_num_writes", "max num of writes", ::cxxopts::value<uint64_t>()->default_value("100000"), "number"),
(verify_hdr, "", "verify_hdr", "data verification", ::cxxopts::value<uint64_t>()->default_value("1"), "0 or 1"),
(verify_data, "", "verify_data", "data verification", ::cxxopts::value<uint64_t>()->default_value("1"), "0 or 1"),
(read_verify, "", "read_verify", "read verification for each write", ::cxxopts::value<uint64_t>()->default_value("0"), "0 or 1"),
(enable_crash_handler, "", "enable_crash_handler", "enable crash handler 0 or 1", ::cxxopts::value<uint32_t>()->default_value("1"), "flag"),
(remove_file, "", "remove_file", "remove file at the end of test 0 or 1", ::cxxopts::value<uint32_t>()->default_value("1"), "flag"),
(expected_vol_state,"", "expected_vol_state", "volume state expected during boot", ::cxxopts::value<uint32_t>()->default_value("0"), "flag"),
(verify_only,"", "verify_only", "verify only boot", ::cxxopts::value<uint32_t>()->default_value("0"), "flag"),
(abort,"", "abort", "abort", ::cxxopts::value<uint32_t>()->default_value("0"), "flag"),
(flip,"", "flip", "flip", ::cxxopts::value<uint32_t>()->default_value("0"), "flag"),
(delete_volume,"", "delete_volume", "delete_volume", ::cxxopts::value<uint32_t>()->default_value("0"), "flag"),
(atomic_page_size,"", "atomic_page_size", "atomic_page_size", ::cxxopts::value<uint32_t>()->default_value("4096"), "atomic_page_size"),
(vol_page_size,"", "vol_page_size", "vol_page_size", ::cxxopts::value<uint32_t>()->default_value("4096"), "vol_page_size"),
(device_list, "", "device_list", "List of device paths", ::cxxopts::value< std::vector< std::string > >(), "path [...]"),
(phy_page_size,"", "phy_page_size", "phy_page_size", ::cxxopts::value<uint32_t>()->default_value("4096"), "phy_page_size"),
(mem_btree_page_size,"", "mem_btree_page_size", "mem_btree_page_size", ::cxxopts::value<uint32_t>()->default_value("8192"), "mem_btree_page_size"))


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
    ::testing::GTEST_FLAG(filter) = "*lifecycle_test*";
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
    verify_hdr = SDS_OPTIONS["verify_hdr"].as<uint64_t>() ? true : false;
    verify_data = SDS_OPTIONS["verify_data"].as<uint64_t>() ? true : false;
    read_verify = SDS_OPTIONS["read_verify"].as<uint64_t>() ? true : false;
    load_type = SDS_OPTIONS["load_type"].as<uint32_t>();
    remove_file = SDS_OPTIONS["remove_file"].as<uint32_t>();
    expected_vol_state = SDS_OPTIONS["expected_vol_state"].as<uint32_t>();
    verify_only = SDS_OPTIONS["verify_only"].as<uint32_t>();
    is_abort = SDS_OPTIONS["abort"].as<uint32_t>();
    flip_set = SDS_OPTIONS["flip"].as<uint32_t>();
    can_delete_volume = SDS_OPTIONS["delete_volume"].as<uint32_t>() ?  true : false;
    atomic_page_size = SDS_OPTIONS["atomic_page_size"].as<uint32_t>();
    vol_page_size = SDS_OPTIONS["vol_page_size"].as<uint32_t>();
    phy_page_size = SDS_OPTIONS["phy_page_size"].as<uint32_t>();
    mem_btree_page_size = SDS_OPTIONS["mem_btree_page_size"].as<uint32_t>();  
    
    if (SDS_OPTIONS.count("device_list")) {
        dev_names = SDS_OPTIONS["device_list"].as< std::vector< std::string > >();
    }
    
    if (load_type == 2) {
        verify_data = 0;
    }
    if (enable_crash_handler) sds_logging::install_crash_handler();
    return RUN_ALL_TESTS();
}
