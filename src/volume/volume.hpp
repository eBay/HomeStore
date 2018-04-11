#include <glog/logging.h>
#include "device/device.h"
#include <fcntl.h>
#include <cache/cache.h>
#include "blkstore.hpp"
#include <mapping/mapping.hpp>

using namespace std;

namespace homestore {
class Volume {

	uint64_t size;
	mapping *map;
	uint64_t alloc_blk_time;
	uint64_t write_time;
	uint64_t map_time;
	uint64_t write_cnt;

public:
	homestore::BlkStore< homestore::VdevVarSizeBlkAllocatorPolicy > *blk_store;
	static Cache< BlkId > *glob_cache;

	static AbstractVirtualDev *new_vdev_found(DeviceManager *dev_mgr, homestore::vdev_info_block *vb);
	Volume(DeviceManager *mgr, uint64_t size);
	Volume(DeviceManager *dev_mgr, homestore::vdev_info_block *vb);
	int write(uint64_t lba, uint8_t *buf, uint32_t nblks);
	int read(uint64_t lba, int nblks, std::vector<boost::intrusive_ptr< BlkBuffer >> &buf_list);
	void init_perf_cntrs();
	void print_perf_cntrs();
	uint64_t get_elapsed_time(Clock::time_point startTime);
};
}
