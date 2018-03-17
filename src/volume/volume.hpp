#include <glog/logging.h>
#include "device/device.h"
#include <fcntl.h>
#include <cache/cache.h>
#include "blkstore.hpp"

using namespace std;

namespace omstore {
class Volume {

	uint64_t size;

public:
	omstore::BlkStore< omstore::VdevFixedBlkAllocatorPolicy > *blk_store;
	static Cache< BlkId > *glob_cache;

	static AbstractVirtualDev *new_vdev_found(DeviceManager *dev_mgr, omstore::vdev_info_block *vb);	
	Volume(DeviceManager *mgr, uint64_t size);
	Volume(DeviceManager *dev_mgr, omstore::vdev_info_block *vb);
	int write(uint64_t lba, uint8_t *buf, int nblks);
	boost::intrusive_ptr< BlkBuffer > read(uint64_t lba, int nblks);
};
}
