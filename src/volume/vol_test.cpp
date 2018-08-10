#include <cassert>
#include <cstdio>
#include <ctime>

extern "C" {
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timeb.h>
}

#include <atomic>
#include <iostream>
#include <vector>

#include <iomgr/iomgr.hpp>
#include <sds_logging/logging.h>

#include "device/device.h"
#include "device/virtual_dev.hpp"
#include "volume.hpp"
#include <condition_variable>

using namespace std;
using namespace homestore;
using namespace homeio;

static size_t const page_size = sysconf(_SC_PAGESIZE);

using log_level = spdlog::level::level_enum;

SDS_LOGGING_INIT(cache_vmod_evict, cache_vmod_write, iomgr, VMOD_BTREE_MERGE, VMOD_BTREE_SPLIT)

homestore::DeviceManager *dev_mgr = nullptr;
std::shared_ptr<homestore::Volume> vol;

constexpr auto MAX_OUTSTANDING_IOs = 64u;
auto MAX_CNT_THREAD = 8u;
auto MAX_THREADS = 8u;

constexpr auto WRITE_SIZE = 4 * Ki;//each block  size
constexpr auto BUF_SIZE = WRITE_SIZE / (4 * Ki);// size of each write (n blocks)
constexpr auto MAX_BUF = (8 * Mi) / WRITE_SIZE;//window of lba's to use
constexpr auto MAX_VOL_SIZE = (1 * Gi);// maximum volume size
constexpr auto MAX_READ = MAX_BUF;

uint64_t max_vol_size = MAX_VOL_SIZE;
int is_random_read = false;
int is_random_write = false;
bool is_read = false;
bool is_write = false;
bool can_read = false;
bool can_write = true;
std::mutex cv_mtx;
std::condition_variable cv;

uint8_t *bufs[MAX_BUF];
uint64_t written_lba[MAX_BUF];//lba written
uint64_t written_nblks[MAX_BUF];//nblks for each lba

/* change it to atomic counters */
std::atomic<uint64_t> read_cnt(0);
std::atomic<uint64_t> write_cnt(0);
homeio::Clock::time_point read_startTime;
homeio::Clock::time_point write_startTime;

uint64_t get_elapsed_time(homeio::Clock::time_point startTime) {
    std::chrono::nanoseconds ns = std::chrono::duration_cast
            <std::chrono::nanoseconds>(homeio::Clock::now() - startTime);
    return ns.count() / 1000;
}


std::atomic<size_t> outstanding_ios(0);

class test_ep : iomgr::EndPoint {
    struct req : volume_req {
        uint64_t lba_to_check;
        uint64_t nblks_to_check;
    };
public:
    int const ev_fd;
    struct thread_info {
        int outstanding_ios_per_thread;
    };

    static thread_local thread_info info;

    void process_ev_common(int fd, void *cookie, int event) {
        uint64_t temp;
        [[maybe_unused]] auto rsize = read(ev_fd, &temp, sizeof(uint64_t));

        iomgr->process_done(fd, event);
        if ((atomic_load(&outstanding_ios) + MAX_CNT_THREAD) < MAX_OUTSTANDING_IOs) {
            /* raise an event */
            iomgr->fd_reschedule(fd, event);
        }

        size_t cnt = 0;
        while (atomic_load(&outstanding_ios) < MAX_OUTSTANDING_IOs && cnt < MAX_CNT_THREAD) {
            size_t temp;
            if ((temp = write_cnt.fetch_add(1, std::memory_order_relaxed)) < MAX_BUF) {
                if (temp == 0) {
                    write_startTime = homeio::Clock::now();
                }
                ++outstanding_ios;
                writefunc(temp);
            } else if (can_read &&
                       (temp = read_cnt.fetch_add(1, std::memory_order_relaxed)) < MAX_READ) {
                if (temp == 0) {
                    read_startTime = homeio::Clock::now();
                }
                ++outstanding_ios;
                readfunc(temp);
            }
            ++cnt;
            assert(outstanding_ios != SIZE_MAX);
        }
    }

    test_ep(iomgr::ioMgr *iomgr) :
            iomgr::EndPoint(iomgr),
            ev_fd(eventfd(0, EFD_NONBLOCK)) {
        iomgr->add_fd(ev_fd,
                      [this](auto fd, auto cookie, auto event) { process_ev_common(fd, cookie, event); },
                      EPOLLIN,
                      9,
                      NULL);

        iomgr->add_ep(this);

        /* Create a volume */
        vol = homestore::Volume::createVolume("my_volume",
                                              dev_mgr,
                                              max_vol_size,
                                              [this](auto vol_req) { process_completions(vol_req); });
        LOGINFO("Created volume of size: {}", max_vol_size);
    }

    uint8_t *create_temp_buff(uint64_t lba, uint64_t nblks) {
        //create temp buffer based on lba/nblks from buf[x] array
        uint8_t *temp_buff = (uint8_t *) malloc(WRITE_SIZE * nblks);
        uint8_t *curr_location = temp_buff;
        uint64_t i = 0;
        while (i < nblks) {
            memcpy(curr_location, bufs[lba + i], WRITE_SIZE);
            curr_location += WRITE_SIZE;
            i++;
        }
        return temp_buff;
    }

    void writefunc(int const cnt) {

        struct req *req = new struct req();
        req->is_read = false;
        if (is_random_write) {
            //choose random lba and nblks to write.
            uint64_t max_nblks = 10;
            written_lba[cnt] = (rand() % (MAX_BUF - max_nblks));
            written_nblks[cnt] = 1 + (rand() % (max_nblks - 1));
            LOGINFO("Writing -> {}:{}", written_lba[cnt], written_nblks[cnt]);
            uint8_t *temp_buff = create_temp_buff(written_lba[cnt], written_nblks[cnt]);

            //write temp buff
            vol->write(written_lba[cnt], temp_buff, written_nblks[cnt], req);

            //free temp buff
            //free(temp_buff);

        } else {
            LOGDEBUG("Writing -> {}:{}", cnt * BUF_SIZE, BUF_SIZE);
            std::vector<boost::intrusive_ptr<BlkBuffer >> buf_list;
            vol->write(cnt * BUF_SIZE, bufs[cnt], BUF_SIZE, req);
        }
    }

    void readfunc(int const cnt) {
        struct req *req = new struct req();
        req->is_read = true;
        if (is_random_read) {
            req->lba_to_check = written_lba[cnt];
            req->nblks_to_check = written_nblks[cnt];
            vol->read(req->lba_to_check, req->nblks_to_check, req);
        } else {
            req->lba_to_check = cnt;
            vol->read(cnt * BUF_SIZE, BUF_SIZE, req);
        }
    }


    uint64_t get_size(std::vector<boost::intrusive_ptr<BlkBuffer >> &read_buf_list) {
        uint64_t size = 0;
        for (uint64_t i = 0; i < read_buf_list.size(); i++) {
            homeds::blob b = read_buf_list[i]->at_offset(0);
            size += b.size;
        }
        return size;
    }

    uint8_t *create_temp_buff(std::vector<boost::intrusive_ptr<BlkBuffer >> &read_buf_list) {
        uint8_t *temp_buff = (uint8_t *) malloc(get_size(read_buf_list));
        uint8_t *curr_buff = temp_buff;
        for (uint64_t i = 0; i < read_buf_list.size(); i++) {
            homeds::blob b = read_buf_list[i]->at_offset(0);
            memcpy(curr_buff, b.bytes, b.size);
            curr_buff += b.size;
        }
        return temp_buff;
    }

    void print_read_details(volume_req *vol_req) {
        LOGDEBUG("Read request for {}:{}", vol_req->lba, vol_req->nblks);
        for (uint64_t i = 0; i < vol_req->read_buf_list.size(); i++) {
            //homeds::blob b = vol_req->read_buf_list[i]->at_offset(0);
           BlkId  blk = ((boost::intrusive_ptr<homestore::BlkBuffer>)vol_req->read_buf_list[i])->get_key();
           LOGDEBUG("{}->{}", blk.m_id, blk.m_nblks);
        }
    }

    void process_completions(volume_req *vol_req) {
        struct req *req = static_cast< struct req * >(vol_req);
        /* raise an event */
        uint64_t temp = 1;
        outstanding_ios--;
        assert(outstanding_ios != SIZE_MAX);
        uint64_t size = write(ev_fd, &temp, sizeof(uint64_t));
        if (size != sizeof(uint64_t)) {
            assert(0);
        }

        if (req->is_read) {
            /* memcmp */
#ifndef NDEBUG
            homeds::blob b = req->read_buf_list[0]->at_offset(0);

            if (is_random_read) {
                if (get_size(req->read_buf_list) != req->nblks_to_check * WRITE_SIZE) {
                    LOGDEBUG("Size not matching:{}:{}", get_size(req->read_buf_list), req->nblks_to_check * WRITE_SIZE);
                    print_read_details(vol_req);
                    assert(0);
                }
                uint8_t *temp_buff = create_temp_buff(req->lba_to_check, req->nblks_to_check);
                uint8_t *temp_buff1 = create_temp_buff(req->read_buf_list);
                int j = memcmp((void *) temp_buff1, (void *) temp_buff, b.size);
                if(j != 0){
                    LOGDEBUG("Data not matching");
                    print_read_details(vol_req);
                    assert(0);
                }
                free(temp_buff);
                free(temp_buff1);
            } else {
                assert(b.size == BUF_SIZE * WRITE_SIZE);
                int j = memcmp((void *) b.bytes, (void *) bufs[req->lba_to_check], b.size);
                assert(j == 0);
            }
            
#endif
        }
        LOGDEBUG("Finished {} for {}:{}", req->is_read?"read":"write",req->lba, req->nblks);
        delete (req);
        if (outstanding_ios == 0 && write_cnt >= MAX_BUF && can_write) {
            /* signal main thread */
            if (is_read) {
                can_read = true;
                [[maybe_unused]] auto rsize = read(ev_fd, &temp, sizeof(uint64_t));
                temp = 1;
                [[maybe_unused]] auto wsize = write(ev_fd, &temp, sizeof(uint64_t));
            }
            vol->print_tree();
            can_read = true;
            can_write = false;
            cv.notify_all();
        }
        if (outstanding_ios == 0 && read_cnt >= MAX_BUF && can_read) {
            cv.notify_all();
        }
    }

    void init_local() override {
    }

    void print_perf() override {
    }
};

thread_local test_ep::thread_info test_ep::info = {0};

SDS_OPTION_GROUP(test_volume, (threads, "", "threads", "Number of threads", ::cxxopts::value<uint64_t>(), ""), \
                              (is_read, "", "is_read", "serial read", ::cxxopts::value<bool>(), ""), \
                              (is_rand_read, "", "is_random_read", "random read", ::cxxopts::value<bool>(), ""), \
                              (is_write, "", "is_write", "serial write", ::cxxopts::value<bool>(), ""), \
                              (is_rand_write, "", "is_random_write", "random write", ::cxxopts::value<bool>(), ""), \

                 (device_list, "c", "device_list", "List of device paths", ::cxxopts::value<std::vector<std::string>>(), "path [...]"), \
(max_vol_size, "", "max_vol_size", "max volume size", ::cxxopts::value<uint64_t>()->default_value(
        "1073741824"), "bytes"))
SDS_OPTIONS_ENABLE(logging, test_volume)


int main(int argc, char **argv) {
    //spdlog::set_async_mode(4096, spdlog::async_overflow_policy::block_retry, nullptr, std::chrono::seconds(2));
    SDS_OPTIONS_LOAD(argc, argv, logging, test_volume)
    SDS_OPTIONS.parse_positional("device_list");

    sds_logging::SetLogger(spdlog::stdout_color_mt("test_volume"));
    spdlog::set_pattern("[%D %T.%f%z] [%^%l%$] [%t] %v");

    if (0 == SDS_OPTIONS.count("device_list")) {
        LOGERROR("Need at least one device listed.");
        exit(-1);
    }
    auto dev_names = SDS_OPTIONS["device_list"].as<std::vector<std::string>>();


    if (SDS_OPTIONS.count("is_random_read")) {
        is_random_read = true;
    }
    if (SDS_OPTIONS.count("is_random_write")) {
        is_random_write = true;
    }
    if (SDS_OPTIONS.count("is_read")) {
        is_read = true;
    }
    if (SDS_OPTIONS.count("is_write")) {
        is_write = true;
    }
    if (SDS_OPTIONS.count("max_vol_size")) {
        max_vol_size = SDS_OPTIONS["max_vol_size"].as<uint64_t>();
    }
    if (SDS_OPTIONS.count("threads")) {
        MAX_CNT_THREAD = SDS_OPTIONS["threads"].as<uint64_t>();
        MAX_THREADS = SDS_OPTIONS["threads"].as<uint64_t>();
    }

    srand(time(NULL));

    /* create iomgr */
    iomgr::ioMgr iomgr(2, MAX_THREADS);

    /* Create/Load the devices */
    LOGINFO("Creating devices.");
    dev_mgr = new homestore::DeviceManager(Volume::new_vdev_found,
                                           0,
                                           &iomgr,
                                           virtual_dev_process_completions);
    try {
        dev_mgr->add_devices(dev_names);
    } catch (std::exception &e) {
        LOGCRITICAL("Exception info {}", e.what());
        exit(1);
    }

    /* create endpoint */
    iomgr.start();
    test_ep ep(&iomgr);

    /* create dataset */
    auto devs = dev_mgr->get_all_devices();
    LOGINFO("Creating dataset.");
    for (auto i = 0u; i < MAX_BUF; i++) {
        //		bufs[i] = new uint8_t[8192*1000]();
        if (auto ec = posix_memalign((void **) &bufs[i], page_size, WRITE_SIZE * BUF_SIZE))
            throw std::system_error(std::error_code(ec, std::generic_category()));
        uint8_t *bufp = bufs[i];
        for (auto j = 0u; j < (WRITE_SIZE * BUF_SIZE / 8); j++) {
            memset(bufp, i%7 , 8);
            bufp = bufp + 8;
        }
    }

    LOGINFO("Initializing performance counters.");
    vol->init_perf_cntrs();

    /* send an event */
    uint64_t temp = 1;
    [[maybe_unused]] auto wsize = write(ep.ev_fd, &temp, sizeof(uint64_t));

    LOGINFO("Waiting for writes to finish.");
    {
        std::unique_lock<std::mutex> lck(cv_mtx);
        cv.wait(lck);
    }

    uint64_t time_us = get_elapsed_time(write_startTime);
    printf("write counters..........\n");
    printf("total writes %lu\n", atomic_load(&write_cnt));
    printf("total time spent %lu us\n", time_us);
    printf("total time spend per io %lu us\n", time_us / atomic_load(&write_cnt));
    printf("iops %lu\n", (atomic_load(&write_cnt) * 1000 * 1000) / time_us);

    LOGINFO("Waiting for reads to finish.");
    {
        std::unique_lock<std::mutex> lck(cv_mtx);
        cv.wait(lck);
    }

    time_us = get_elapsed_time(read_startTime);
    printf("read counters..........\n");
    printf("total reads %lu\n", atomic_load(&read_cnt));
    printf("total time spent %lu us\n", time_us);
    if (read_cnt)
        printf("total time spend per io %lu us\n", time_us / read_cnt);
    printf("iops %lu \n", (read_cnt * 1000 * 1000) / time_us);
    printf("additional counters.........\n");
    vol->print_perf_cntrs();
    // Expect this to fail!!!
//    auto err = Volume::removeVolume("my_volume");
//    assert(err);
//    vol.reset();
//    err = Volume::removeVolume("my_volume");
//    assert(!err);
    iomgr.print_perf_cntrs();
    LOGINFO("Complete");
}
