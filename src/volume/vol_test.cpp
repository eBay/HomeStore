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
constexpr auto MAX_CNT_THREAD = 8u;
constexpr auto MAX_THREADS = 8u;

constexpr auto WRITE_SIZE = 4 * Ki;
constexpr auto BUF_SIZE = WRITE_SIZE / (4 * Ki);
constexpr auto MAX_BUF = (8 * Mi) / WRITE_SIZE;
constexpr auto MAX_VOL_SIZE = (1 * Gi);
constexpr auto MAX_READ = MAX_BUF ;

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
boost::intrusive_ptr<homestore::BlkBuffer>boost_buf[MAX_BUF];

/* change it to atomic counters */
std::atomic<uint64_t> read_cnt(0);
std::atomic<uint64_t> write_cnt(0);
homeio::Clock::time_point read_startTime;
homeio::Clock::time_point write_startTime;

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
         if((temp = write_cnt.fetch_add(1, std::memory_order_relaxed)) < MAX_BUF) {
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
      struct req *req = new struct req();
      req->is_read = false;
      if (is_random_write) {
         assert(!is_read);
         uint64_t random = rand();
         uint64_t i = (random % (MAX_BUF));
         boost_buf[cnt] = vol->write(i * BUF_SIZE, bufs[i], BUF_SIZE, req);
         /* store intrusive buffer pointer */
      } else {
         std::vector<boost::intrusive_ptr< BlkBuffer >> buf_list;
         boost_buf[cnt] = vol->write(cnt * BUF_SIZE, bufs[cnt], BUF_SIZE, req);
      }
   }

   void readfunc(int const cnt) {
      if (!is_read) {
         return;
      }
      assert(is_write);
      struct req *req = new struct req();
      req->is_read = true;
      if (is_random_read) {
         uint64_t random = rand();
         uint64_t i = random % MAX_BUF;
         req->indx = i;
         vol->read(i * BUF_SIZE, BUF_SIZE, req);
      } else {
         req->indx = cnt;
         vol->read(cnt * BUF_SIZE, BUF_SIZE, req);
      }
   }

   void process_completions(volume_req *vol_req) {
      struct req * req = static_cast< struct req* >(vol_req);
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
         homeds::blob b  = req->read_buf_list[0]->at_offset(0);	
         assert(b.size == BUF_SIZE * WRITE_SIZE);
         int j = memcmp((void *)b.bytes, (void *)bufs[req->indx], b.size);
         assert(j == 0);
#endif
      }
      delete(req);
      if (outstanding_ios == 0 && write_cnt >= MAX_BUF && can_write) {
	 /* signal main thread */
	if (is_read) {
	    can_read = true;
            [[maybe_unused]] auto rsize = read(ev_fd, &temp, sizeof(uint64_t));
	    temp = 1;
            [[maybe_unused]] auto wsize = write(ev_fd, &temp, sizeof(uint64_t));
	}
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

SDS_OPTION_GROUP(test_volume, (is_read, "", "is_read", "serial read", ::cxxopts::value<bool>(), ""), \
                              (is_rand_read, "", "is_random_read", "random read", ::cxxopts::value<bool>(), ""), \
                              (is_write, "", "is_write", "serial write", ::cxxopts::value<bool>(), ""), \
                              (is_rand_write, "", "is_random_write", "random write", ::cxxopts::value<bool>(), ""), \
                              (device_list, "c", "device_list", "List of device paths", ::cxxopts::value<std::vector<std::string>>(), "path [...]"), \
                              (max_vol_size, "", "max_vol_size", "max volume size", ::cxxopts::value<uint64_t>()->default_value("1073741824"), "bytes"))
SDS_OPTIONS_ENABLE(logging, test_volume)


int main(int argc, char** argv) {
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
    if(is_random_read && is_random_write){
        cout << "Random read supported only with sequential write!";
        return 1;
    }else if(is_read && is_random_write){
        cout << "Read is not supported with random write!";
        return 1;
    }

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
      if (auto ec = posix_memalign((void**)&bufs[i], page_size, WRITE_SIZE * BUF_SIZE))
         throw std::system_error(std::error_code(ec, std::generic_category()));
      uint8_t *bufp = bufs[i];
      for (auto j = 0u; j < (WRITE_SIZE * BUF_SIZE/8); j++) {
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
   	cv.wait(lck);
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
   	cv.wait(lck);
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
   iomgr.print_perf_cntrs();
   LOGINFO("Complete");
}
