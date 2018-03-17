
//
// Created by Kadayam, Hari on 06/11/17.
//

#include "volume.hpp"
#include <device/blkbuffer.hpp>

using namespace std;
using namespace omstore;

#define MAX_CACHE_SIZE     2 * 1024 * 1024 * 1024
#define BLOCK_SIZE	   8 * 1024

Cache< BlkId > * Volume::glob_cache = NULL;

AbstractVirtualDev *
omstore::Volume::new_vdev_found(DeviceManager *dev_mgr, omstore::vdev_info_block *vb) {
    LOG(INFO) << "New virtual device found id = " << vb->vdev_id << " size = " << vb->size;
    omstore::Volume *volume = new omstore::Volume(dev_mgr, vb);
    return volume->blk_store->get_vdev();
}

omstore::Volume::Volume(omstore::DeviceManager *dev_mgr, uint64_t size) {
    size = size;
    if (Volume::glob_cache == NULL) {
	new omstore::Cache< BlkId >(MAX_CACHE_SIZE, BLOCK_SIZE);
    }
    blk_store = new omstore::BlkStore< omstore::VdevFixedBlkAllocatorPolicy >(dev_mgr, Volume::glob_cache, size,
                                                                                  WRITETHRU_CACHE, 1);
}

omstore::Volume::Volume(DeviceManager *dev_mgr, omstore::vdev_info_block *vb) {
    size = vb->size; 
    if (Volume::glob_cache == NULL) {
	new omstore::Cache< BlkId >(MAX_CACHE_SIZE, BLOCK_SIZE);
    }
    blk_store = new omstore::BlkStore< omstore::VdevFixedBlkAllocatorPolicy >(dev_mgr, Volume::glob_cache, vb, WRITETHRU_CACHE);
}

int 
omstore::Volume::write(uint64_t lba, uint8_t *buf, int nblks) {
    omstore::BlkId bid;
    omstore::blk_alloc_hints hints;
    hints.desired_temp = 0;
    hints.dev_id_hint = -1;

    blk_store->alloc_blk(nblks, hints, &bid);

    LOG(INFO) << "Requested nblks: " << (uint32_t)nblks << " Allocation info: " << bid.to_string();

    omds::blob b = {buf, BLOCK_SIZE * nblks};

    boost::intrusive_ptr< BlkBuffer > bbuf = blk_store->write(bid, b);
    LOG(INFO) << "Written on " << bid.to_string() << " for 8192 bytes";
    return 0;
}

boost::intrusive_ptr< BlkBuffer > 
omstore::Volume::read(uint64_t lba, int nblks) {
    	omstore::BlkId bid;
        LOG(INFO) << "Read from " << bid.to_string() << " for 8192 bytes";

        boost::intrusive_ptr< BlkBuffer > bbuf = blk_store->read(bid, 0, nblks * BLOCK_SIZE);
    	return bbuf;
}
