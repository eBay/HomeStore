#include <iostream>
		
#include "device/device.h"
#include <fcntl.h>
#include "volume.hpp"
#include <ctime>
#include <sys/timeb.h>
#include <cassert>
#include <stdio.h>
#include <atomic>

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

#define BUF_SIZE (WRITE_SIZE/8192) /* it will go away once mapping layer is fixed */
#define MAX_BUF ((32 * 1024ul * 1024ul * 1024ul)/WRITE_SIZE)
#define MAX_BUF_CACHE (1 * 1024ul)
#define MAX_VOL_SIZE (100ul * 1024ul * 1024ul * 1024ul) 
uint8_t *bufs[MAX_BUF_CACHE];
#define NUM_READ_THREADS 1 /* it should be power of 2 */
#define NUM_WRITE_THREADS 1 /* it should be power of 2 */

#define MAX_READ MAX_BUF 
/* change it to atomic counters */
uint64_t read_cnt = 0;
uint64_t write_cnt = 0;
std::atomic<int> thread_exit(0);


uint64_t get_elapsed_time(Clock::time_point startTime) 
{
	std::chrono::nanoseconds ns = std::chrono::duration_cast
					< std::chrono::nanoseconds >(Clock::now() - startTime);
	return ns.count() / 1000; 
}

void *readThread(void *arg) 
{
	if (!is_read) {
		thread_exit++;
		return NULL;
	}
	assert(is_write);
	int id = *(int *)arg;
	uint64_t temp_read_cnt = 0;
//	printf("reading thread started %d\n", id);
	if (is_random_read) {
		while (temp_read_cnt < MAX_READ/NUM_READ_THREADS) {
			std::vector<boost::intrusive_ptr< BlkBuffer >> buf_list;
			uint64_t random = rand();
			uint64_t i = random % MAX_BUF;
#ifdef DEBUG
//			printf("%d\n", i);
#endif
			vol->read(i * BUF_SIZE, BUF_SIZE, buf_list);
			uint64_t size = 0;

			uint64_t *tmp = (uint64_t *)bufs[i % MAX_BUF_CACHE];
			*tmp = i; 
#ifndef NDEBUG
			for(auto buf:buf_list) {
				homeds::blob b  = buf->at_offset(0);
				assert(!std::memcmp(b.bytes, 
							(void *)((uint32_t *)bufs[i % MAX_BUF_CACHE] + size), b.size));
				size += b.size;
				i++;
			}
#endif
			temp_read_cnt++;
			read_cnt++;
			assert(size == BUF_SIZE * 8192);
		}
	} else {
		uint64_t i = id * (MAX_BUF/NUM_READ_THREADS);
		while (temp_read_cnt < MAX_BUF/NUM_READ_THREADS) {
			std::vector<boost::intrusive_ptr< BlkBuffer >> buf_list;
#ifdef DEBUG
//			printf("%d\n", i);
#endif
			vol->read(i * BUF_SIZE, BUF_SIZE, buf_list);
			temp_read_cnt++;
			read_cnt++;
			homeds::blob b  = buf_list[0]->at_offset(0);	
			assert(b.size == BUF_SIZE * 8192);
			uint64_t *tmp = (uint64_t *)bufs[i % MAX_BUF_CACHE];
			*tmp = i * BUF_SIZE; 
#ifndef NDEBUG
			int j = memcmp((void *)b.bytes, (void *)(bufs[i % MAX_BUF_CACHE]), b.size);
			assert(j == 0);
#endif
			i++;
		}
	}

	thread_exit++;
}

void *writeThread(void *arg) 
{
	int id = *(int *)arg;
	uint64_t temp_write_cnt = 0;
	if (is_random_write) {
		while (temp_write_cnt < MAX_BUF/NUM_WRITE_THREADS) {
			assert(!is_read);
			uint64_t random = rand();
			uint64_t i = (id * (MAX_BUF/NUM_WRITE_THREADS)) + 
						(random % (MAX_BUF/NUM_WRITE_THREADS));
			uint64_t *tmp = (uint64_t *)bufs[i % MAX_BUF_CACHE];
			*tmp = i * BUF_SIZE; 
			vol->write(i * BUF_SIZE, bufs[i % MAX_BUF_CACHE], BUF_SIZE);
			temp_write_cnt++;
			write_cnt++;
		}
	} else {
		uint64_t i = id * (MAX_BUF/NUM_WRITE_THREADS);
		//	printf("writing thread %d started from %d to %d\n", id, i, (i+(MAX_BUF/NUM_WRITE_THREADS)));
		while (temp_write_cnt < MAX_BUF/NUM_WRITE_THREADS) {
			std::vector<boost::intrusive_ptr< BlkBuffer >> buf_list;
			uint64_t *tmp = (uint64_t *)bufs[i % MAX_BUF_CACHE];
			*tmp = i * BUF_SIZE; 
			vol->write(i * BUF_SIZE, bufs[i % MAX_BUF_CACHE], BUF_SIZE);
			temp_write_cnt++;
			write_cnt++;
			i++;	
		//	printf("%d\n", i);
		}
	}
	thread_exit++;
}

int main(int argc, char** argv) {
	std::vector<std::string> dev_names; 
	bool create = ((argc > 1) && (!strcmp(argv[1], "-c")));

	for (auto i : boost::irange(create ? 2 : 1, argc)) {
		dev_names.emplace_back(argv[i]);  
	}
	
	/* Create/Load the devices */
	printf("creating devices\n");
	dev_mgr = new homestore::DeviceManager(Volume::new_vdev_found, 0);
	try {
		dev_mgr->add_devices(dev_names);
	} catch (std::exception &e) {
		LOG(INFO) << "Exception info " << e.what();
		exit(1);
	}
	auto devs = dev_mgr->get_all_devices(); 
	
	/* Create a volume */
	if (create) {
		printf("creating volume\n");
		LOG(INFO) << "Creating volume\n";
		uint64_t size = MAX_VOL_SIZE;
		vol = new homestore::Volume(dev_mgr, size);
		printf("created volume\n");
	}
	for (auto i = 0; i < MAX_BUF_CACHE; i++) {
//		bufs[i] = new uint8_t[8192*1000]();
		bufs[i] = (uint8_t *)malloc(8192 * BUF_SIZE);
		uint8_t *bufp = bufs[i];
		for (auto j = 0; j < (8192 * BUF_SIZE/8); j++) {
			memset(bufp, i + j + 1 , 8);
			bufp = bufp + 8;
		}
	}

	vol->init_perf_cntrs();	
	pthread_t tid;
	
	printf("writing \n");
	int writearray[NUM_WRITE_THREADS];
	Clock::time_point write_startTime = Clock::now();
	atomic_store(&thread_exit, 0); 
	for (int i = 0; i < NUM_WRITE_THREADS; i++) {
		writearray[i] = i;
		pthread_create(&tid, NULL, writeThread, &writearray[i]);
	}
	while(atomic_load(&thread_exit) != NUM_WRITE_THREADS) {
	}
	uint64_t time_us = get_elapsed_time(write_startTime);
	printf("write counters..........\n");
	printf("total writes %lu\n", write_cnt);
	printf("total time spent %lu us\n", time_us);
	printf("total time spend per io %lu us\n", time_us/write_cnt);
	printf("iops %lu\n",(write_cnt * 1000 * 1000)/time_us);
	
	printf("reading\n");
	int readarray[NUM_READ_THREADS];
	Clock::time_point read_startTime = Clock::now();
	atomic_store(&thread_exit, 0); 
	for (int i = 0; i < NUM_READ_THREADS; i++) {
		readarray[i] = i;
		pthread_create(&tid, NULL, readThread, &readarray[i]);
	}	
	while(atomic_load(&thread_exit) != NUM_READ_THREADS) {
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
}
