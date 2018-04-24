#include <glog/logging.h>
#include "device/device.h"
#include <fcntl.h>
#include <cache/cache.h>
#include "blkstore.hpp"
#include <mapping/mapping.hpp>

using namespace std;

namespace homestore {

/* this structure is not thread safe. But as of
 * now there is no use where we can access it in
 * multiple threads.
 */
struct vol_req::blkstore_req {
	uint64_t lba;
	int nblks;
	Clock::time_point startTime;
	int read_cnt;
};

class Volume {

	typedef std::function< void (int status, vol_req* req) > comp_callback;
	uint64_t size;
	mapping *map;
	uint64_t alloc_blk_time;
	uint64_t write_time;
	uint64_t map_time;
	uint64_t io_time;
	uint64_t write_cnt;
	homestore::comp_callback comp_cb;

public:
	homestore::BlkStore< homestore::VdevVarSizeBlkAllocatorPolicy > *blk_store;
	static Cache< BlkId > *glob_cache;

	static AbstractVirtualDev *new_vdev_found(DeviceManager *dev_mgr, homestore::vdev_info_block *vb);
	Volume(DeviceManager *mgr, uint64_t size);
	Volume(DeviceManager *dev_mgr, homestore::vdev_info_block *vb);
	int write(uint64_t lba, uint8_t *buf, uint32_t nblks, volume_req* req);
	int read(uint64_t lba, int nblks, std::vector<boost::intrusive_ptr< BlkBuffer >> &buf_list, 
						volume_req* req);
	void init_perf_cntrs();
	void print_perf_cntrs();
	uint64_t get_elapsed_time(Clock::time_point startTime);
	void process_completions(int status, blockstore_req *bs_req);
};
}
