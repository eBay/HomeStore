#include <iostream>
		
#include "device/device.h"
#include <fcntl.h>
#include "volume.hpp"
#include <ctime>
#include <sys/timeb.h>
#include <cassert>
#include <stdio.h>

using namespace std; 
using namespace homestore;


INIT_VMODULES(BTREE_VMODULES);

homestore::DeviceManager *dev_mgr = nullptr;
homestore::Volume *vol;

#define MAX_BUF 1 * 1024 * 1024
#define MAX_BUF_CACHE 1 * 1024
#define MAX_VOL_SIZE (100ul * 1024ul * 1024ul * 1024ul) 
uint8_t *bufs[MAX_BUF];
#define BUF_SIZE 1

#define MAX_READ 250000 // 1 million
uint64_t read_cnt = 0;


uint64_t get_elapsed_time(Clock::time_point startTime) 
{
	std::chrono::nanoseconds ns = std::chrono::duration_cast< std::chrono::nanoseconds >(Clock::now() - startTime);
	return ns.count() / 1000; 
}

void *readThread(void *arg) 
{
	while (read_cnt < MAX_READ) {
		std::vector<boost::intrusive_ptr< BlkBuffer >> buf_list;
		int i = rand() % MAX_BUF;
		vol->read(rand() % MAX_BUF, BUF_SIZE, buf_list);
		read_cnt++;
		uint64_t size = 0;
		for(auto buf:buf_list) {
			homeds::blob b  = buf->at_offset(0);
			assert(!std::memcmp(b.bytes, 
				(void *)((uint32_t *)bufs[i % MAX_BUF_CACHE] + size), b.size));
			printf("read verified\n");
			size += b.size;
			i++;
		}
		assert(size == 8192);
	}
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
	
	for (auto i = 0; i < MAX_BUF; i++) {	
		vol->write(i * BUF_SIZE, bufs[i % MAX_BUF_CACHE], BUF_SIZE);
	}


	printf("creating threads \n");
	// create threads for reading
	pthread_t tid;
	for (int i = 0; i < 15; i++) {
		pthread_create(&tid, NULL, readThread, NULL);
	}	
	printf("reading\n");
	
	Clock::time_point startTime = Clock::now();
	while (read_cnt < MAX_READ) {	
	}
	uint64_t time_us = get_elapsed_time(startTime);
	printf("total time spent %lu", time_us);
}
