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
#include "vol_alloc_recovery.h"
#include <condition_variable>
#include <main/vol_interface.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

using namespace std;
using namespace homestore;
using namespace homeio;

static size_t const page_size = sysconf(_SC_PAGESIZE);

using log_level = spdlog::level::level_enum;

SDS_LOGGING_INIT(cache_vmod_evict, cache_vmod_write, iomgr, VMOD_BTREE_MERGE, VMOD_BTREE_SPLIT
)

homestore::DeviceManager *dev_mgr = nullptr;
std::shared_ptr<homestore::Volume> vol;
#define BLKSTORE_BLK_SIZE 8192

constexpr auto MAX_OUTSTANDING_IOs = 128u;
constexpr auto MAX_THREADS = 8u;

constexpr auto MAX_VOL_SIZE = (1 * Gi);

static uint32_t buf_size;
static uint32_t write_length;
static uint32_t max_buf;
static uint32_t max_writes;
uint64_t max_vol_size = MAX_VOL_SIZE;
int is_random_read = false;
int is_random_write = false;
bool is_read = false;
bool is_write = false;
bool init = true;
std::atomic_bool can_read = false;
std::atomic_bool can_write = true;
std::mutex cv_mtx;
std::condition_variable cv;

uint8_t **bufs;
uint64_t *written_lba;//lba written
uint64_t *written_nblks;//nblks for each lba
boost::intrusive_ptr<homestore::BlkBuffer> *boost_buf;
class test_ep;
test_ep *ep;

/* change it to atomic counters */
std::atomic<uint64_t> read_cnt(0);
std::atomic<uint64_t> write_cnt(0);
homeio::Clock::time_point read_startTime;
homeio::Clock::time_point write_startTime;
int free_req_cnt = 0;

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
        int indx;

        ~req() {
            free_req_cnt++;
        }
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
        if ((atomic_load(&outstanding_ios) + MAX_THREADS) < MAX_OUTSTANDING_IOs) {
            /* raise an event */
            iomgr->fd_reschedule(fd, event);
        }

        size_t cnt = 0;
        while (atomic_load(&outstanding_ios) < MAX_OUTSTANDING_IOs && cnt < MAX_THREADS) {
            size_t temp = write_cnt.load(std::memory_order_relaxed);
            if (can_write && temp < max_writes) {
                temp = write_cnt.fetch_add(1, std::memory_order_relaxed);
                if (temp == 0) {
                    write_startTime = homeio::Clock::now();
                }
                ++outstanding_ios;
                writefunc(temp);
            } else if (can_read) {
                temp = read_cnt.load(std::memory_order_relaxed);
                if (temp < write_cnt) {
                    read_cnt.fetch_add(1, std::memory_order_relaxed);
                    if (temp == 0) {
                        read_startTime = homeio::Clock::now();
                    }
                    ++outstanding_ios;
                    readfunc(temp);
                }
            }
            ++cnt;
            assert(outstanding_ios != SIZE_MAX);
        }
    }

    test_ep(std::shared_ptr<iomgr::ioMgr> iomgr) :
            iomgr::EndPoint(iomgr),
            ev_fd(eventfd(0, EFD_NONBLOCK)) {
        iomgr->add_fd(ev_fd,
                      [this](auto fd, auto cookie, auto event) { process_ev_common(fd, cookie, event); },
                      EPOLLIN,
                      9,
                      NULL);

        iomgr->add_ep(this);

        vol_params params;
        params.page_size = 8192;
        params.size = max_vol_size;
        params.io_comp_cb = ([this](auto vol_req) { process_completions(vol_req); });
        memcpy(params.vol_name, "vol1", sizeof("vol1"));

        /* Create a volume */
        vol = VolInterface::get_instance()->createVolume(params);
        LOGDEBUG("Created volume of size: {}", max_vol_size);
    }

    uint8_t *create_temp_buff(uint64_t lba, uint64_t nblks) {
        //create temp buffer based on lba/nblks from buf[x] array
        uint8_t *temp_buff;
        if (auto ec = posix_memalign((void **) &temp_buff, page_size, buf_size * nblks))
            throw std::system_error(std::error_code(ec, std::generic_category()));

        uint8_t *curr_location = temp_buff;
        uint64_t i = 0;
        while (i < nblks) {
            memcpy(curr_location, bufs[lba + i], buf_size);
            curr_location += buf_size;
            i++;
        }
        return temp_buff;
    }

    void writefunc(int const cnt) {
        boost::intrusive_ptr<req> req(new struct req());
        req->is_read = false;
        if (is_random_write) {
            //choose random lba and nblks to write.
            uint64_t max_nblks = 10;
            written_lba[cnt] = (rand() % (max_buf - max_nblks));
            written_nblks[cnt] = 1 + (rand() % (max_nblks - 1));
            LOGDEBUG("Writing -> {}:{}", written_lba[cnt], written_nblks[cnt]);
            uint8_t *temp_buff = create_temp_buff(written_lba[cnt], written_nblks[cnt]);

            //write temp buff
            VolInterface::get_instance()->write(vol, written_lba[cnt], temp_buff, written_nblks[cnt], req);

            //free temp buff
            //free(temp_buff);
            /* store intrusive buffer pointer */
        } else {

            std::vector<boost::intrusive_ptr<BlkBuffer >> buf_list;
            void *write_buf;
            if (0 == posix_memalign((void **) &write_buf, page_size, buf_size)) {
                memcpy(write_buf, bufs[cnt], buf_size);
                LOGDEBUG("Writing -> {}:{}", cnt * write_length, write_length);
                VolInterface::get_instance()->write(vol, cnt * write_length, (uint8_t *) write_buf, write_length, req);
            } else {
                throw std::runtime_error("Out of Memory");
            }
        }
    }

    void readfunc(int const cnt) {
        boost::intrusive_ptr<req> req(new struct req());
        req->is_read = true;
        if (is_random_read) {
            req->lba_to_check = written_lba[cnt];
            req->nblks_to_check = rand() % written_nblks[cnt];
            VolInterface::get_instance()->read(vol, req->lba_to_check, req->nblks_to_check, req);
        } else {
            req->indx = cnt;
            VolInterface::get_instance()->read(vol, cnt * write_length, write_length, req);
        }
    }

    uint64_t get_size(std::vector<buf_info> &read_buf_list) {
        uint64_t size = 0;
        for (uint64_t i = 0; i < read_buf_list.size(); i++) {
            boost::intrusive_ptr<BlkBuffer> ptr = read_buf_list[i].buf;
            //homeds::blob b = ptr->at_offset(read_buf_list[i].offset);
            //assert(b.size>=read_buf_list[i].size);
            size += read_buf_list[i].size;
        }
        return size;
    }

    uint8_t *create_temp_buff(std::vector<buf_info> &read_buf_list) {
        uint8_t *temp_buff;
        if (auto ec = posix_memalign((void **) &temp_buff, page_size, get_size(read_buf_list)))
            throw std::system_error(std::error_code(ec, std::generic_category()));

        uint8_t *curr_buff = temp_buff;
        for (uint64_t i = 0; i < read_buf_list.size(); i++) {
            boost::intrusive_ptr<BlkBuffer> ptr = read_buf_list[i].buf;
            homeds::blob b = ptr->at_offset(read_buf_list[i].offset);
            //assert(b.size>=read_buf_list[i].size);
            memcpy(curr_buff, b.bytes, read_buf_list[i].size);
            curr_buff += read_buf_list[i].size;
        }
        return temp_buff;
    }

    void print_read_details(boost::intrusive_ptr<volume_req> &vol_req) {
        LOGERROR("Read request for {}:{}", vol_req->lba, vol_req->nblks);
        for (uint64_t i = 0; i < vol_req->read_buf_list.size(); i++) {
            boost::intrusive_ptr<BlkBuffer> ptr = vol_req->read_buf_list[i].buf;
            BlkId blk = ptr->get_key();
            LOGERROR("{}->{}", blk.m_id, blk.m_nblks);
        }
    }

    void process_completions(boost::intrusive_ptr<volume_req> vol_req) {
        boost::intrusive_ptr<req> req = boost::static_pointer_cast<struct req>(vol_req);
        /* raise an event */
        uint64_t temp = 1;
        outstanding_ios--;
        assert(outstanding_ios != SIZE_MAX);
        uint64_t size = write(ev_fd, &temp, sizeof(uint64_t));
        if (size != sizeof(uint64_t)) {
            assert(0);
        }
#ifndef NDEBUG
        if (req->is_read && !req->read_buf_list.empty()) {
            if (is_random_read) {
                if (get_size(req->read_buf_list) != req->nblks_to_check * buf_size) {
                    //vol->print_tree();
                    LOGERROR("Size not matching:{}:{}", get_size(req->read_buf_list), req->nblks_to_check * buf_size);
                    print_read_details(vol_req);
                    assert(0);
                }
                uint8_t *temp_buff = create_temp_buff(req->lba_to_check, req->nblks_to_check);
                uint8_t *temp_buff1 = create_temp_buff(req->read_buf_list);
                int j = memcmp((void *) temp_buff1, (void *) temp_buff, req->nblks_to_check * write_length);
                if (j != 0) {
                    LOGERROR("Data not matching");
                    print_read_details(vol_req);
                    assert(0);
                }
                free(temp_buff);
                free(temp_buff1);
            } else {
                /* memcmp */
                auto tot_size = 0u;
                for (auto &info : req->read_buf_list) { 
                    auto offset = info.offset;
                    auto size = info.size;
                    auto buf = info.buf;
                    while (size != 0) {
                        uint32_t size_read = 0;
                        homeds::blob b = buf->at_offset(offset);
                        if (b.size > size) {
                            size_read = size;
                        } else {
                            size_read = b.size;
                        }
                        int j = memcmp((void *) b.bytes,
                                       (void *) ((uint64_t) bufs[req->indx] + tot_size),
                                       size_read);
                        assert(j == 0);
                        size -= size_read;
                        offset += size_read;
                        tot_size += size_read;
                    }
                }
                assert(tot_size == buf_size);
            }
        }
#endif
        std::lock_guard<std::mutex> lg(cv_mtx);
        LOGTRACE("Finished {} for {}:{}", req->is_read ? "read" : "write", req->lba, req->nblks);
        if (outstanding_ios == 0 && write_cnt >= max_writes && can_write) {
            /* signal main thread */
            can_write = false;
            if (is_read) {
                can_read = true;
                [[maybe_unused]] auto rsize = read(ev_fd, &temp, sizeof(uint64_t));
                temp = 1;
                [[maybe_unused]] auto wsize = write(ev_fd, &temp, sizeof(uint64_t));
            }

            //vol->print_tree();

            LOGDEBUG("NOtify");
            cv.notify_all();
            return;
        } else if (can_read && read_cnt >= write_cnt && outstanding_ios == 0) {
            LOGDEBUG("NOtify {} {}", read_cnt, write_cnt);
            can_read = false;
            cv.notify_all();
            return;
        }
    }

    void init_local() override {
    }

    void print_perf() override {
    }
};

thread_local test_ep::thread_info test_ep::info = {0};

SDS_OPTION_GROUP(test_volume, (num_of_writes, "", "num_of_writes", "Number of writes", ::cxxopts::value<uint32_t>(), "numwrites"),\
                              (block_size, "", "block_size", "Block size for IO", ::cxxopts::value<uint32_t>()->default_value("4096"), "numbytes"), \
                              (is_read, "", "is_read", "serial read", ::cxxopts::value<bool>(), ""), \
                              (is_rand_read, "", "is_random_read", "random read", ::cxxopts::value<bool>(), ""), \
                              (is_write, "", "is_write", "serial write", ::cxxopts::value<bool>(), ""), \
                              (is_rand_write, "", "is_random_write", "random write", ::cxxopts::value<bool>(), ""), \
                              (device_list, "", "device_list", "List of device paths", ::cxxopts::value<std::vector<std::string>>(), "path [...]"), \
                              (max_vol_size, "", "max_vol_size", "max volume size", ::cxxopts::value<uint64_t>()->default_value("1073741824"), "bytes"), \
                              (thread_cnt, "", "threads", "Thread count", ::cxxopts::value<uint32_t>()->default_value("2"), "numthreads"),
                              (max_capacity, "", "maximum capacity", "maximum capacity", ::cxxopts::value<uint64_t>()->default_value("0"), "bytes"))
SDS_OPTIONS_ENABLE(logging, test_volume)

std::shared_ptr<iomgr::ioMgr> iomgr_obj;

void init_done_cb(std::error_condition err, struct out_params params) {
    if (init) {
        ep = new test_ep (iomgr_obj);
        /* send an event */
        uint64_t temp = 1;
        [[maybe_unused]] auto wsize = write(ep->ev_fd, &temp, sizeof(uint64_t)); 
    }
}

bool vol_found_cb (boost::uuids::uuid uuid) {
    return true;
}

void vol_mounted_cb(std::shared_ptr<Volume> vol, vol_state state) {
}

void vol_state_change_cb(std::shared_ptr<Volume> vol, vol_state old_state, vol_state new_state) {
}

void blk_recovery_callback(MappingValue& mv) {
    std::cout << __FUNCTION__ << " called.\n";
}

void blk_recovery_comp_callback(bool success) {
    std::cout << __FUNCTION__ << " called.\n";
}

int main(int argc, char **argv) {
    SDS_OPTIONS_LOAD(argc, argv, logging, test_volume)
    SDS_PARSER.parse_positional("device_list");

    sds_logging::SetLogger("test_volume");
    spdlog::set_pattern("[%D %T.%f%z] [%^%l%$] [%t] %v");
#ifndef NDEBUG
    vol_test_enable = true;
#endif

    if (0 == SDS_OPTIONS.count("device_list")) {
        LOGERROR("Need at least one device listed.");
        exit(-1);
    }

    if (0 == SDS_OPTIONS.count("max_capacity")) {
        LOGERROR("Need max capacity.");
//        exit(-1);
    }
   
   auto dev_names = SDS_OPTIONS["device_list"].as<std::vector<std::string>>();
  // auto max_capacity = SDS_OPTIONS["max_capacity"].as<uint64_t>();

   std::vector<dev_info> device_info;
   for (uint32_t i = 0; i < dev_names.size(); i++) {
        dev_info temp_info;
        boost::uuids::string_generator gen;
        temp_info.dev_names = dev_names[0];
        temp_info.uuid = gen("01970496-0262-11e9-8eb2-f2801f1b9fd1");
        device_info.push_back(temp_info);
   }

    if (SDS_OPTIONS.count("max_capacity")) {
        
    }
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
    if (SDS_OPTIONS.count("num_of_writes")) {
        max_writes = SDS_OPTIONS["num_of_writes"].as<uint32_t>();
    }
    srand(time(NULL));

    buf_size = SDS_OPTIONS["block_size"].as<uint32_t>();
    write_length = buf_size / BLKSTORE_BLK_SIZE;
    max_buf = (8 * Mi) / buf_size;
    if(max_writes==0)max_writes = max_buf;
    bufs = (uint8_t **) malloc(sizeof(uint8_t *) * max_buf);
    written_lba = (uint64_t *) malloc(sizeof(uint64_t) * max_buf);
    written_nblks = (uint64_t *) malloc(sizeof(uint64_t) * max_buf);
    boost_buf = (boost::intrusive_ptr<homestore::BlkBuffer> *) malloc(
            sizeof(boost::intrusive_ptr<homestore::BlkBuffer>) * max_buf);
 
    
    /* create iomgr */
    iomgr_obj = std::make_shared<iomgr::ioMgr>(2, SDS_OPTIONS["threads"].as<uint32_t>());

    /* start homestore */
    init_params params;

    params.min_virtual_page_size = 4096;
    params.cache_size = 1 * 1024 * 1024 * 1024;
    params.disk_init = init;
    params.devices = device_info;
    params.is_file = true;
    params.max_cap = (5 * 1024 * 1024 * 1024ul) ;
    params.physical_page_size = 8192;
    params.disk_align_size = 4096;
    params.atomic_page_size = 8192;
    params.iomgr = iomgr_obj;
    params.init_done_cb = init_done_cb;
    params.vol_mounted_cb = vol_mounted_cb;
    params.vol_state_change_cb = vol_state_change_cb;
    params.vol_found_cb = vol_found_cb;
    VolInterface::init(params);

    /* create endpoint */
    iomgr_obj->start();

    /* create dataset */
    LOGDEBUG("Creating dataset.");
    for (auto i = 0u; i < max_buf; i++) {
        if (auto ec = posix_memalign((void **) &bufs[i], page_size, buf_size))
            throw std::system_error(std::error_code(ec, std::generic_category()));
        uint8_t *bufp = bufs[i];
        for (auto j = 0u; j < (buf_size / 8); j++) {
            memset(bufp, i % 7, 8);
            bufp = bufp + 8;
        }
    }

    LOGDEBUG("Initializing performance counters.");


    LOGDEBUG("Waiting for writes to finish.");
    {
        std::unique_lock<std::mutex> lck(cv_mtx);
        cv.wait(lck, [] { return (!can_write && 0 == outstanding_ios); });
    }

    uint64_t time_us = get_elapsed_time(write_startTime);
    printf("write counters..........\n");
    printf("total writes %lu\n", atomic_load(&write_cnt));
    printf("total time spent %lu us\n", time_us);
    printf("total time spend per io %lu us\n", time_us / atomic_load(&write_cnt));
    printf("iops %lu\n", (atomic_load(&write_cnt) * 1000 * 1000) / time_us);

    vol->print_tree();
 
    BlkAllocBitmapBuilder* b = new BlkAllocBitmapBuilder(vol.get(), blk_recovery_callback, blk_recovery_comp_callback);
    b->get_allocated_blks();
    delete b;

    LOGDEBUG("Waiting for reads to finish.");
    {
        std::unique_lock<std::mutex> lck(cv_mtx);
        cv.wait(lck, [] { return (!can_read && 0 == outstanding_ios); });
    }

    time_us = get_elapsed_time(read_startTime);
    printf("read counters..........\n");
    printf("total reads %lu\n", atomic_load(&read_cnt));
    printf("total time spent %lu us\n", time_us);
    if (read_cnt)
        printf("total time spend per io %lu us\n", time_us / read_cnt);
    printf("iops %lu \n", (read_cnt * 1000 * 1000) / time_us);
    printf("additional counters.........\n");
    vol->print_perf_report();
    iomgr_obj->print_perf_cntrs();
    LOGDEBUG("Complete");
}
