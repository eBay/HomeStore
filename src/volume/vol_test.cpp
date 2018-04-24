#include <iostream>
		
#include "device/device.h"
#include "iomgr/iomgr.hpp"
#include "device/virtual_dev.hpp"
#include <fcntl.h>
#include "volume.hpp"
#include <ctime>
#include <sys/timeb.h>
#include <cassert>
#include <stdio.h>
#include <atomic>
#include <sys/eventfd.h>
#include <stdio.h>

using namespace std; 
using namespace homestore;


INIT_VMODULES(BTREE_VMODULES);

homestore::DeviceManager *dev_mgr = nullptr;
homestore::Volume *vol;

#define WRITE_SIZE (8 * 1024) /* should be multple of 8k */
int is_random_read = false;
int is_random_write = false;
bool is_read = false;
bool is_write = true;
#define MAX_THREADS 8

#define BUF_SIZE (WRITE_SIZE/8192) /* it will go away once mapping layer is fixed */
#define MAX_BUF ((32 * 1024ul * 1024ul * 1024ul)/WRITE_SIZE)
#define MAX_VOL_SIZE (40ul * 1024ul * 1024ul * 1024ul) 
uint8_t *bufs[MAX_BUF];
boost::intrusive_ptr< CacheBuffer<BlkId> > *boost_buf[MAX_BUF_CACHE];

#define MAX_READ MAX_BUF 
/* change it to atomic counters */
std::atomic<uint64_t> read_cnt = 0;
std::atomic<uint64_t> write_cnt = 0;
Clock::time_point read_startTime = 0;
Clock::time_point write_startTime = 0;

uint64_t get_elapsed_time(Clock::time_point startTime) 
{
	std::chrono::nanoseconds ns = std::chrono::duration_cast
					< std::chrono::nanoseconds >(Clock::now() - startTime);
	return ns.count() / 1000; 
}


#define MAX_OUTSTANDING_IOs 64
#define MAX_CNT_THREAD 10

thread_local std::atomic<int> outstanding_ios = 0;
class testEndPoint : public EndPoint {
	 std::atomic<int> outstanding_ios;
	 int ev_fd;
	 struct req::vol_req {
		int indx;
	 }

	 testEndpoint(ioMgr *iomgr):EndPoint(iomgr) {
		/* create a event fd */
		ev_fd = eventfd(0, 0);
		iomgr->add_ep(this);
		iomgr->add_fd(ev_fd, process_ev);
		
		/* Create a volume */
		if (create) {
			printf("creating volume\n");
			LOG(INFO) << "Creating volume\n";
			uint64_t size = MAX_VOL_SIZE;
			comp_callback cb = std::bind(&testEndPoint::process_completions, this);
			vol = new homestore::Volume(dev_mgr, size, 
						cb, iomgr);
			printf("created volume\n");
		}
	 }

	void process_ev(int fd, int event) {
		int cnt = 0;
		while (atomic_load(&outstanding_ios) < MAX_OUTSTANDING_IOs && 
						cnt < MAX_CNT_THREAD) {
			if (write_cnt < MAX_BUF) {
				int temp = write_cnt.fetch_add(1, std::memory_order_acquire);;
				if (temp == 1) {
					write_startTime = Clock::now();
				}
				writefunc(temp - 1);
			} else if (is_read && read_cnt < MAX_READ && 
					atomic_load(&read_cnt) < MAX_READ) {
				int temp = read_cnt.fetch_add(1, std::memory_order_acquire);;
				if (temp == 1) {
					read_startTime = Clock::now();
				}
				read_func(temp - 1);
			}
			cnt++;
			outstanding_ios++;
		}
		if (atomic_load(&outstanding_ios) < MAX_OUTSTANDING_IOs) {
			/* raise an event */
			uint64_t temp = 1;
			write(ep->ev_fd, &temp, sizeof(uint64_t));
		}
	 }

	 void writefunc(int cnt) {
		struct req *req = (struct req *)malloc(sizeof(struct req));
		req->is_read = false;
		 if (is_random_write) {
			 assert(!is_read);
			 uint64_t random = rand();
			 uint64_t i = (random % (MAX_BUF));
			 boost_bufs[i] = vol->write(i * BUF_SIZE, bufs[i], BUF_SIZE, req);
			/* store intrusive buffer pointer */
		 } else {
			 std::vector<boost::intrusive_ptr< BlkBuffer >> buf_list;
			 boost_bufs[i] = vol->write(cnt * BUF_SIZE, bufs[cnt], BUF_SIZE, req);
		 }
	 }
	 
	void readfunc(int cnt) {
		 if (!is_read) {
			 return;
		 }
		 assert(is_write);
		 struct req *req = (struct req *)malloc(sizeof(struct req));
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

	 void process_completions(int status, volume_req *vol_req) {
		assert(status == 0);
		req * req = dynamic_cast< volume_req* >(vol_req);
		/* raise an event */
		uint64_t temp = 1;
		outstanding_ios--;
		write(ep->ev_fd, &temp, sizeof(uint64_t));
		if (req->is_read) {
			/* memcmp */
			homeds::blob b  = req->buf_list[0]->at_offset(0);	
			assert(b.size == BUF_SIZE * 8192);
#ifndef NDEBUG
			int j = memcmp((void *)b.bytes, (void *)(bufs[req->indx], b.size);
			assert(j == 0);
#endif
		}
		free(req);
	 }

	 void init_local() override {
	 }
}

int main(int argc, char** argv) {
	std::vector<std::string> dev_names; 
	bool create = ((argc > 1) && (!strcmp(argv[1], "-c")));

	for (auto i : boost::irange(create ? 2 : 1, argc)) {
		dev_names.emplace_back(argv[i]);  
	}
	
	/* create iomgr */
	ioMgr iomgr(2, MAX_THREADS);

	/* Create/Load the devices */
	printf("creating devices\n");
	dev_mgr = new homestore::DeviceManager(Volume::new_vdev_found, 
				iomgr, VirtualDev::process_completions);
	try {
		dev_mgr->add_devices(dev_names);
	} catch (std::exception &e) {
		LOG(INFO) << "Exception info " << e.what();
		exit(1);
	}


	/* create endpoint */
	testEndPoint ep(iomgr);

	/* create dataset */
	auto devs = dev_mgr->get_all_devices(); 
	printf("creating dataset \n");
	for (auto i = 0; i < MAX_BUF; i++) {
//		bufs[i] = new uint8_t[8192*1000]();
		bufs[i] = (uint8_t *)malloc(8192 * BUF_SIZE);
		uint8_t *bufp = bufs[i];
		for (auto j = 0; j < (8192 * BUF_SIZE/8); j++) {
			memset(bufp, i + j + 1 , 8);
			bufp = bufp + 8;
		}
	}
	printf("created dataset \n");

	vol->init_perf_cntrs();	
	
	/* send an event */
	uint64_t temp = 1;
	write(ep->ev_fd, &temp, sizeof(uint64_t));


	while(atomic_load(&write_cnt) < MAX_BUF) {
	}	
	
	uint64_t time_us = get_elapsed_time(write_startTime);
	printf("write counters..........\n");
	printf("total writes %lu\n", write_cnt);
	printf("total time spent %lu us\n", time_us);
	printf("total time spend per io %lu us\n", time_us/write_cnt);
	printf("iops %lu\n",(write_cnt * 1000 * 1000)/time_us);
	
	while(is_read && atomic_load(&read_cnt) < MAX_READ) {
	}
	
	time_us = get_elapsed_time(read_startTime);
	printf("read counters..........\n");
	printf("total reads %lu\n", read_cnt);
	printf("total time spent %lu us\n", time_us);
	if (read_cnt) 
		printf("total time spend per io %lu us\n", time_us/read_cnt);
	printf("iops %lu \n", (read_cnt * 1000 * 1000)/time_us);
	printf("additional counters.........\n");	
	vol->print_perf_cntrs();
	iomgr->print_perf_cntrs();
}
