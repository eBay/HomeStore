#include <iostream>
#include "device/device.h"
#include <fcntl.h>
#include "volume.hpp"

using namespace std; 
using namespace omstore;


INIT_VMODULES(BTREE_VMODULES);

omstore::DeviceManager *dev_mgr = nullptr;
omstore::Volume *vol;

int main(int argc, char** argv) {
	std::vector<std::string> dev_names; 
	bool create = ((argc > 1) && (!strcmp(argv[1], "-c")));

	for (auto i : boost::irange(create ? 2 : 1, argc)) {
		dev_names.emplace_back(argv[i]);  
	}
	
	/* Create/Load the devices */
	printf("creating devices\n");
	dev_mgr = new omstore::DeviceManager(Volume::new_vdev_found, 0);
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
		uint64_t size = 512 * 1024 * 1024 * 1024;
		vol = new omstore::Volume(dev_mgr, size);
		printf("created volume\n");
	}

	uint8_t *bufs[100];
	for (auto i = 0; i < 100; i++) {
//		bufs[i] = new uint8_t[8192*1000]();
		bufs[i] = (uint8_t *)malloc(8192 * 1000);
		for (auto j = 0; j < (8192 * 1000/8); j++) {
			memset(bufs[i], i * j , 8);
		}
	}
	
	for (auto i = 0; i < 100; i++) {	
		vol->write(i * 1000, bufs[i], 1000);
	}

	for (auto i = 0; i < 100; i++) {
		std::vector<boost::intrusive_ptr< BlkBuffer >> buf_list;
		vol->read(i * 1000, 1000, buf_list);
		uint64_t size = 0;
		for(auto buf:buf_list) {
			 homeds::blob b  = buf->at_offset(0);
			assert(!memcmp(b.bytes, bufs[i] + size, b.size));
			size += b.size;
		}
	}
}
