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
extern "C" {
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timeb.h>
}

using namespace homestore;

/************************** GLOBAL VARIABLES ***********************/

#define MAX_DEVICES 2
std::string names[4] = {"file1", "file2", "file3", "file4"};
uint64_t max_vols = 50;
uint64_t run_time;
uint64_t num_threads;
bool read_enable;
constexpr auto Ki = 1024ull;
constexpr auto Mi = Ki * Ki;
constexpr auto Gi = Ki * Mi;
constexpr auto max_io_size = 1 * Mi;
uint64_t max_outstanding_ios = 64u;
uint64_t max_disk_capacity = 10 * Gi;
uint64_t match_cnt = 0;
std::atomic<uint64_t> write_cnt;
std::atomic<uint64_t> read_cnt;
std::atomic<uint64_t> read_err_cnt;
std::atomic<size_t> outstanding_ios;
using log_level = spdlog::level::level_enum;
SDS_LOGGING_INIT(cache_vmod_evict, cache_vmod_write, iomgr, VMOD_BTREE_MERGE, VMOD_BTREE_SPLIT, varsize_blk_alloc,
                 VMOD_VOL_MAPPING,VMOD_BTREE)

/**************** Common class created for all tests ***************/

class test_ep : public iomgr::EndPoint {
public:
    test_ep(std::shared_ptr<iomgr::ioMgr> iomgr) :iomgr::EndPoint(iomgr) {
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

protected:
    std::shared_ptr<iomgr::ioMgr> iomgr_obj;
    bool init;
    std::vector<std::shared_ptr<homestore::Volume>> vol;
    std::vector<int> fd;
    std::vector<std::mutex> vol_mutex;
    std::vector<homeds::Bitset *> m_vol_bm;
    std::vector<uint64_t> max_vol_blks;
    std::vector<uint64_t> cur_checkpoint;
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
    std::atomic<int> rdy_state;
    bool is_abort;

public:
    IOTest():vol(max_vols), fd(max_vols), vol_mutex(max_vols), m_vol_bm(max_vols), 
              max_vol_blks(max_vols), cur_checkpoint(max_vols), device_info(0) {
        vol_cnt = 0;
        cur_vol = 0;
        max_vol_size = 0;
        max_capacity = 0;
        verify_done = false;
    }

    void remove_files() {
        remove("file1");
        remove("file2");
        remove("file3");
        remove("file4");
        for (uint32_t i = 0; i < max_vols; i++) {
            std::string name = "vol" + std::to_string(i);
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
            }
            max_capacity += max_disk_capacity;
        }
        /* Don't populate the whole disks. Only 80 % of it */
        max_vol_size = (60 * max_capacity)/ (100 * max_vols);

        iomgr_obj = std::make_shared<iomgr::ioMgr>(2, num_threads);
        init_params params;
#ifndef NDEBUG
        params.flag = homestore::io_flag::BUFFERED_IO;
#else
        params.flag = homestore::io_flag::DIRECT_IO;
#endif
        params.min_virtual_page_size = 4096;
        params.cache_size = 4 * 1024 * 1024 * 1024ul;
        params.disk_init = init;
        params.devices = device_info;
        params.is_file = true;
        params.max_cap = max_capacity ;
        params.physical_page_size = 8192;
        params.disk_align_size = 4096;
        params.atomic_page_size = 8192;
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
    
    bool vol_found_cb (boost::uuids::uuid uuid) {
        assert(!init);
        return true;
    }

    void vol_mounted_cb(std::shared_ptr<Volume> vol_obj, vol_state state) {
       assert(!init);
       int cnt = vol_cnt.fetch_add(1, std::memory_order_relaxed);
       vol_init(cnt, vol_obj);
       auto cb = [this](boost::intrusive_ptr<vol_interface_req> vol_req) { process_completions(vol_req); };
       VolInterface::get_instance()->attach_vol_completion_cb(vol_obj, cb);
    }

    void vol_init(int cnt, std::shared_ptr<homestore::Volume> vol_obj) {
        vol[cnt] = vol_obj;
        fd[cnt] = open(VolInterface::get_instance()->get_name(vol_obj), O_RDWR);
        max_vol_blks[cnt] = VolInterface::get_instance()->get_size(vol_obj) / 
                                           VolInterface::get_instance()->get_page_size(vol_obj);
        m_vol_bm[cnt] = new homeds::Bitset(max_vol_blks[cnt]);
        cur_checkpoint[cnt] = 0;
        assert(fd[cnt] > 0);
        assert(VolInterface::get_instance()->get_size(vol_obj) == max_vol_size);
    }

    void vol_state_change_cb(std::shared_ptr<Volume> vol, vol_state old_state, vol_state new_state) {
        assert(0);
    }

    void create_volume() {
        
        /* Create a volume */
        for (uint32_t i = 0; i < max_vols; i++) {
            vol_params params;
            params.page_size = 4096;//((i > (max_vols/2)) ? 4096 : 8192);
            params.size = max_vol_size;
            params.io_comp_cb = ([this](boost::intrusive_ptr<vol_interface_req> vol_req) 
                                 { process_completions(vol_req); });
            params.uuid = boost::uuids::random_generator()();
            std::string name = "vol" + std::to_string(i);
            memcpy(params.vol_name, name.c_str(), (name.length() + 1));

            auto vol_obj = VolInterface::get_instance()->createVolume(params); 
            /* create file */
            std::ofstream ofs(name, std::ios::binary | std::ios::out);
            ofs.seekp(max_vol_size);
            ofs.write("", 1);
            LOGINFO("Created volume of size: {}", max_vol_size);
            
            /* open a corresponding file */
            vol_init(vol_cnt, vol_obj);
            ++vol_cnt;
        }
        init_files();
    }

    void init_done_cb(std::error_condition err, struct out_params params) {
        /* create volume */
        rdy_state = 1;
        if (init) {
            create_volume();
            verify_done = true;
            startTime = Clock::now();
        } else {
            assert(vol_cnt == max_vols);
            verify_done = false;
        }
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

    void process_ev_common(int fd, void *cookie, int event) {
        uint64_t temp;
        [[maybe_unused]] auto rsize = read(ev_fd, &temp, sizeof(uint64_t));

        iomgr_obj->process_done(fd, event);
        if (outstanding_ios.load() < max_outstanding_ios && get_elapsed_time(startTime) < run_time) { 
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
                ++outstanding_ios;
            }
            ++write_cnt;
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
                auto ret = pwrite(fd[i], init_buf, write_size, (off_t) offset);
                assert(ret = write_size);
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
        uint64_t max_blks = max_io_size/VolInterface::get_instance()->get_page_size(vol[cur]);
        lba = rand() % (max_vol_blks[cur] - max_blks);
        nblks = rand() % max_blks;
        {
            std::unique_lock< std::mutex > lk(vol_mutex[cur]);
            /* check if someone is already doing writes/reads */ 
            if (m_vol_bm[cur]->is_bits_reset(lba, nblks))
                m_vol_bm[cur]->set_bits(lba, nblks);
            else
                goto start;
        }
        uint8_t *buf = nullptr;
        uint8_t *buf1 = nullptr;
        uint64_t size = nblks * VolInterface::get_instance()->get_page_size(vol[cur]);
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
        populate_buf(buf, size);
       
        memcpy(buf1, buf, size);
        
        boost::intrusive_ptr<req> req(new struct req());
        req->lba = lba;
        req->nblks = nblks;
        req->size = size;
        req->offset = lba * VolInterface::get_instance()->get_page_size(vol[cur]);
        req->buf = buf1;
        req->fd = fd[cur];
        req->is_read = false;
        req->cur_vol = cur;
        auto ret_io = VolInterface::get_instance()->write(vol[cur], lba, buf, nblks, req);
        if (ret_io != no_error) {
            assert(0);
            free(buf);
            --outstanding_ios;
            std::unique_lock< std::mutex > lk(vol_mutex[cur]);
            m_vol_bm[cur]->reset_bits(lba, nblks);
        }
        LOGDEBUG("Wrote {} {} ",lba,nblks);
    }
   
    void populate_buf(uint8_t *buf, uint64_t size) {
        for (uint64_t write_sz = 0; (write_sz + sizeof(uint64_t)) < size; write_sz = write_sz + sizeof(uint64_t)) {
            *((uint64_t *)(buf + write_sz)) = random();
        }
    }

    void random_read() {
        /* XXX: does it really matter if it is atomic or not */
        int cur = ++cur_vol % max_vols;
        uint64_t lba;
        uint64_t nblks;
    start:
        /* we won't be writing more then 128 blocks in one io */
        uint64_t max_blks = max_io_size/VolInterface::get_instance()->get_page_size(vol[cur]);

        lba = rand() % (max_vol_blks[cur % max_vols] - max_blks);
       nblks = rand() % max_blks;
        {
            std::unique_lock< std::mutex > lk(vol_mutex[cur]);
            /* check if someone is already doing writes/reads */ 
            if (m_vol_bm[cur]->is_bits_reset(lba, nblks))
                m_vol_bm[cur]->set_bits(lba, nblks);
            else
                goto start;
        }
        read_vol(cur, lba, nblks);
        LOGDEBUG("Read {} {} ",lba,nblks);
    }

    void read_vol(uint32_t cur, uint64_t lba, uint64_t nblks) {
        uint8_t *buf = nullptr;
        uint64_t size = nblks * VolInterface::get_instance()->get_page_size(vol[cur]);
        auto ret = posix_memalign((void **) &buf, 4096, size);
        if (ret) {
            assert(0);
        }
        assert(buf != nullptr);
        boost::intrusive_ptr<req> req(new struct req());
        req->lba = lba;
        req->nblks = nblks;
        req->fd = fd[cur];
        req->is_read = true;
        req->size = size;
        req->offset = lba * VolInterface::get_instance()->get_page_size(vol[cur]);
        req->buf = buf;
        req->cur_vol = cur;
        ++outstanding_ios;
        ++read_cnt;
        auto ret_io = VolInterface::get_instance()->read(vol[cur], lba, nblks, req);
        if (ret_io != no_error) {
            --outstanding_ios;
            ++read_err_cnt;
            std::unique_lock< std::mutex > lk(vol_mutex[cur]);
            m_vol_bm[cur]->reset_bits(lba, nblks);
        }
    }

    void verify(std::shared_ptr<homestore::Volume> vol,boost::intrusive_ptr<req> req) {
        int64_t tot_size = 0;
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
                int j = memcmp((void *) b.bytes, (uint8_t *)((uint64_t)req->buf + tot_size), size_read);
                //assert(j == 0);
                match_cnt++;
                if (j) {
                    LOGINFO("mismatch found offset {} size {}", tot_size, size_read);
#ifndef NDEBUG
                    VolInterface::get_instance()->print_tree(vol);
#endif
                    assert(0);
                }
                size -= size_read;
                offset += size_read;
                tot_size += size_read;
            }
        }
        assert(tot_size == req->size);
    }

    void verify_vols() {
    #if 0
        for (uint32_t cur = 0; cur < max_vols; ++cur) {
            for (uint64_t lba = cur_checkpoint[cur]; lba < max_vol_blks[cur]; ++lba) {
                read_vol(cur, lba, (max_io_size / VolInterface::get_instance()->get_page_size(vol[cur])));
                cur_checkpoint[cur] = lba;
                if (outstanding_ios > max_outstanding_ios) {
                    return;
                }
            }
        }
     #endif
        verify_done = true;
        uint64_t temp = 1;
        [[maybe_unused]] auto wsize = write(ev_fd, &temp, sizeof(uint64_t));
        startTime = Clock::now();
    }

    void process_completions(boost::intrusive_ptr<vol_interface_req> vol_req) {
        /* raise an event */
        boost::intrusive_ptr<req> req = boost::static_pointer_cast<struct req>(vol_req);
        uint64_t temp = 1;
        --outstanding_ios;
        
        if (!req->is_read && req->err == no_error) {
            /* write to a file */
            auto ret = pwrite(req->fd, req->buf, req->size, req->offset);
            assert(ret == req->size);
        }

        bool verify_io = false;
        
        if (!req->is_read && req->err == no_error) {
            (void)VolInterface::get_instance()->sync_read(vol[req->cur_vol], req->lba, req->nblks, req);
            verify_io = true;
        }
        if ((req->is_read && req->err == no_error) || verify_io) {
            /* read from the file and verify it */
            auto ret = pread(req->fd, req->buf, req->size, req->offset);
            if(ret != req->size){
                assert(0);
            }
            verify(vol[req->cur_vol],req);
        }
       
        {
            std::unique_lock< std::mutex > lk(vol_mutex[req->cur_vol]);
            m_vol_bm[req->cur_vol]->reset_bits(req->lba, req->nblks);
        }
        
        if (verify_done && get_elapsed_time(startTime) > run_time) {
            if (is_abort) {
                abort();
            }
            std::unique_lock< std::mutex > lk(m_mutex);
            rdy_state = 0;
            if (outstanding_ios == 0) {
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
    this->remove_files();
}

/* it bursts the IOs. max outstanding IOs are very high. In this testcase, it
 * will automatically be flow controlled by device.
 */
TEST_F(IOTest, normal_burst_random_io_test) {
    /* fork a new process */
    max_outstanding_ios = 20000;
    this->init = true;
    /* child process */
    this->start_homestore();
    this->wait_cmpl();
    LOGINFO("write_cnt {}", write_cnt);
    LOGINFO("read_cnt {}", read_cnt);
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
}

/************************* CLI options ***************************/

SDS_OPTION_GROUP(test_volume, 
(run_time, "", "run_time", "run time for io", ::cxxopts::value<uint32_t>()->default_value("30"), "seconds"),
(num_threads, "", "num_threads", "num threads for io", ::cxxopts::value<uint32_t>()->default_value("8"), "number"),
(read_enable, "", "read_enable", "read enable 0 or 1", ::cxxopts::value<uint32_t>()->default_value("1"), "flag"),
(max_disk_capacity, "", "max_disk_capacity", "max disk capacity", ::cxxopts::value<uint64_t>()->default_value("7"), "GB"),
(max_volume, "", "max_volume", "max volume", ::cxxopts::value<uint64_t>()->default_value("50"), "number"))
SDS_OPTIONS_ENABLE(logging, test_volume)

/* it will go away once shutdown is implemented correctly */
extern "C" 
__attribute__((no_sanitize_address))
const char* __asan_default_options() { 
    return "detect_leaks=0"; 
}

/************************** MAIN ********************************/

/* We can run this target either by using default options which run the normal io tests or by setting different options.
 * Format is
 *   1. ./test_volume
 *   2. ./test_volume --gtest_filter=*recovery* --run_time=120 --num_threads=16 --max_disk_capacity=10 --max_volume=50
 * Above command run all tests having a recovery keyword for 120 seconds with 16 threads , 10g disk capacity and 50 volumes
 */
int main(int argc, char *argv[]) {
    ::testing::GTEST_FLAG(filter) = "*normal_random*";
    testing::InitGoogleTest(&argc, argv);
    SDS_OPTIONS_LOAD(argc, argv, logging, test_volume)
    sds_logging::SetLogger("test_volume");
    spdlog::set_pattern("[%D %T.%f%z] [%^%l%$] [%t] %v");

    run_time = SDS_OPTIONS["run_time"].as<uint32_t>();
    num_threads = SDS_OPTIONS["num_threads"].as<uint32_t>();
    read_enable = SDS_OPTIONS["read_enable"].as<uint32_t>();
    max_disk_capacity = ((SDS_OPTIONS["max_disk_capacity"].as<uint64_t>())  * (1ul<< 30));
    max_vols = SDS_OPTIONS["max_volume"].as<uint64_t>();
    return RUN_ALL_TESTS();
}
