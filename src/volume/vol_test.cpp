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

constexpr auto MAX_OUTSTANDING_IOs = 128u;
constexpr auto MAX_THREADS = 8u;

constexpr auto Ki = 1024ull;
constexpr auto Mi = Ki * Ki;
constexpr auto Gi = Ki * Mi;
constexpr auto MAX_VOL_SIZE = (1 * Gi);

static uint32_t buf_size;
static uint32_t write_length;
static uint32_t max_buf;

uint64_t max_vol_size = MAX_VOL_SIZE;
int is_random_read = false;
int is_random_write = false;
bool is_read = false;
bool is_write = false;
std::atomic_bool can_read = false;
std::atomic_bool can_write = true;
std::mutex cv_mtx;
std::condition_variable cv;

uint8_t **bufs;
boost::intrusive_ptr<homestore::BlkBuffer> *boost_buf;

/* change it to atomic counters */
std::atomic<uint64_t> read_cnt(0);
std::atomic<uint64_t> write_cnt(0);
homeio::Clock::time_point read_startTime;
homeio::Clock::time_point write_startTime;
int free_req_cnt = 0;

uint64_t get_elapsed_time(homeio::Clock::time_point startTime) 
{
   std::chrono::nanoseconds ns = std::chrono::duration_cast
       < std::chrono::nanoseconds >(homeio::Clock::now() - startTime);
   return ns.count() / 1000;
}


std::atomic<size_t> outstanding_ios(0);
class test_ep : iomgr::EndPoint {
   struct req:volume_req {
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
         if(can_write && temp < max_buf) {
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
       ev_fd(eventfd(0, EFD_NONBLOCK))
   {
      iomgr->add_fd(ev_fd,
                    [this] (auto fd, auto cookie, auto event) { process_ev_common(fd, cookie, event); },
                    EPOLLIN,
                    9,
                    NULL);

      iomgr->add_ep(this);

      /* Create a volume */
      vol = homestore::Volume::createVolume("my_volume",
                                            dev_mgr,
                                            max_vol_size,
                                            [this] (auto vol_req) { process_completions(vol_req); });
      LOGINFO("Created volume of size: {}", max_vol_size);
   }

   void writefunc(int const cnt) {
      boost::intrusive_ptr <req> req(new struct req());
      req->is_read = false;
      if (is_random_write) {
         assert(!is_read);
         uint64_t random = rand();

         uint64_t i = (random % (max_buf));
         void * write_buf;
         if (0 == posix_memalign((void**)&write_buf, page_size, buf_size)) {
            memcpy(write_buf, bufs[i], buf_size);
            vol->write(i * write_length, (uint8_t *)write_buf, write_length, req);
         } else {
            throw std::runtime_error("Out of Memory");
         }
         /* store intrusive buffer pointer */
      } else {
         std::vector<boost::intrusive_ptr< BlkBuffer >> buf_list;
         void * write_buf;
         if (0 == posix_memalign((void**)&write_buf, page_size, buf_size)) {
            memcpy(write_buf, bufs[cnt], buf_size);
            vol->write(cnt * write_length, (uint8_t *)write_buf, write_length, req);
         } else {
            throw std::runtime_error("Out of Memory");
         }
      }
   }

   void readfunc(int const cnt) {
      if (!is_read) {
         return;
      }
      assert(is_write);
      boost::intrusive_ptr <req> req(new struct req());
      req->is_read = true;
      if (is_random_read) {
         uint64_t random = rand();
         uint64_t i = random % max_buf;
         req->indx = i;
         vol->read(i * write_length, write_length, req);
      } else {
         req->indx = cnt;
         vol->read(cnt * write_length, write_length, req);
      }
   }


   void process_completions(boost::intrusive_ptr<volume_req> vol_req) {
       boost::intrusive_ptr <req>  req = boost::static_pointer_cast< struct req >(vol_req);
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
           /* memcmp */
           auto tot_size = 0u;
           for (auto const& buf : req->read_buf_list) {
               homeds::blob const &b = buf->at_offset(0);
               tot_size += b.size;
               int j = memcmp((void *) b.bytes, (void *) bufs[req->indx], b.size);
               assert(j == 0);
           }
           assert(tot_size == buf_size);
       }
#endif
       std::lock_guard<std::mutex> lg(cv_mtx);
       if (outstanding_ios == 0 && write_cnt >= max_buf && can_write) {
           /* signal main thread */
           if (is_read) {
               can_read = true;
               [[maybe_unused]] auto rsize = read(ev_fd, &temp, sizeof(uint64_t));
               temp = 1;
               [[maybe_unused]] auto wsize = write(ev_fd, &temp, sizeof(uint64_t));
           }
           can_write = false;
           LOGINFO("NOtify");
           cv.notify_all();
           return;
       }  else if (can_read && read_cnt >= write_cnt && outstanding_ios == 0) {
           LOGINFO("NOtify {} {}", read_cnt, write_cnt);
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

SDS_OPTION_GROUP(test_volume, (block_size, "", "block_size", "Block size for IO", ::cxxopts::value<uint32_t>()->default_value("4096"), "numbytes"), \
                              (is_read, "", "is_read", "serial read", ::cxxopts::value<bool>(), ""), \
                              (is_rand_read, "", "is_random_read", "random read", ::cxxopts::value<bool>(), ""), \
                              (is_write, "", "is_write", "serial write", ::cxxopts::value<bool>(), ""), \
                              (is_rand_write, "", "is_random_write", "random write", ::cxxopts::value<bool>(), ""), \
                              (device_list, "c", "device_list", "List of device paths", ::cxxopts::value<std::vector<std::string>>(), "path [...]"), \
                              (max_vol_size, "", "max_vol_size", "max volume size", ::cxxopts::value<uint64_t>()->default_value("1073741824"), "bytes"), \
                              (thread_cnt, "", "threads", "Thread count", ::cxxopts::value<uint32_t>()->default_value("2"), "numthreads"))
SDS_OPTIONS_ENABLE(logging, test_volume)


int main(int argc, char** argv) {
   spdlog::set_async_mode(4096, spdlog::async_overflow_policy::block_retry, nullptr, std::chrono::seconds(2));
   SDS_OPTIONS_LOAD(argc, argv, logging, test_volume)
   SDS_PARSER.parse_positional("device_list");

   sds_logging::SetLogger(spdlog::stdout_color_mt("test_volume"));
   spdlog::set_pattern("[%D %T.%f%z] [%^%l%$] [%t] %v");
#ifndef NDEBUG
   vol_test_enable = true;
#endif

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
    if(is_random_read && is_random_write){
        cout << "Random read supported only with sequential write!";
        return 1;
    }else if(is_read && is_random_write){
        cout << "Read is not supported with random write!";
        return 1;
    }

    buf_size = SDS_OPTIONS["block_size"].as<uint32_t>();
    write_length = buf_size / BLKSTORE_BLK_SIZE;
    max_buf = (8 * Mi) / buf_size;
    bufs = (uint8_t**)malloc(sizeof(uint8_t*) * max_buf);
    boost_buf = (boost::intrusive_ptr<homestore::BlkBuffer>*)malloc(sizeof(boost::intrusive_ptr<homestore::BlkBuffer>) * max_buf);

   /* create iomgr */
   auto iomgr = std::make_shared<iomgr::ioMgr>(2, SDS_OPTIONS["threads"].as<uint32_t>());

   /* Create/Load the devices */
   LOGINFO("Creating devices.");
   dev_mgr = new homestore::DeviceManager(Volume::new_vdev_found,
                                          0,
                                          iomgr,
                                          virtual_dev_process_completions);
   try {
      dev_mgr->add_devices(dev_names);
   } catch (std::exception &e) {
      LOGCRITICAL("Exception info {}", e.what());
      exit(1);
   }

   /* create endpoint */
   iomgr->start();
   test_ep ep(iomgr);

   /* create dataset */
   auto devs = dev_mgr->get_all_devices();
   LOGINFO("Creating dataset.");
   for (auto i = 0u; i < max_buf; i++) {
      if (auto ec = posix_memalign((void**)&bufs[i], page_size, buf_size))
         throw std::system_error(std::error_code(ec, std::generic_category()));
      uint8_t *bufp = bufs[i];
      for (auto j = 0u; j < (buf_size/8); j++) {
        memset(bufp, i + j + 1 , 8);
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
   	cv.wait(lck, [] { return (!can_write && 0 == outstanding_ios);});
   }

   uint64_t time_us = get_elapsed_time(write_startTime);
   printf("write counters..........\n");
   printf("total writes %lu\n", atomic_load(&write_cnt));
   printf("total time spent %lu us\n", time_us);
   printf("total time spend per io %lu us\n", time_us/atomic_load(&write_cnt));
   printf("iops %lu\n",(atomic_load(&write_cnt) * 1000 * 1000)/time_us);

   LOGINFO("Waiting for reads to finish.");
   {
   	std::unique_lock<std::mutex> lck(cv_mtx);
   	cv.wait(lck, [] { return (!can_read && 0 == outstanding_ios);});
   }

   time_us = get_elapsed_time(read_startTime);
   printf("read counters..........\n");
   printf("total reads %lu\n", atomic_load(&read_cnt));
   printf("total time spent %lu us\n", time_us);
   if (read_cnt)
      printf("total time spend per io %lu us\n", time_us/read_cnt);
   printf("iops %lu \n", (read_cnt * 1000 * 1000)/time_us);
   printf("additional counters.........\n");	
   vol->print_perf_cntrs();
   // Expect this to fail!!!
   auto err = Volume::removeVolume("my_volume");
   assert(err);
   vol.reset();
   err = Volume::removeVolume("my_volume");
   assert(!err);
   iomgr->print_perf_cntrs();
   LOGINFO("Complete");
}
