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
		LOG(INFO) << "Creating volume\n";
		uint64_t size = 512 * 1024 * 1024;
		vol = new omstore::Volume(dev_mgr, size);
	}
}
