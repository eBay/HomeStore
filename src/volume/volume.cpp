
//
// Created by Kadayam, Hari on 06/11/17.
//

#include "volume.hpp"
#include <device/blkbuffer.hpp>

using namespace std;
using namespace homestore;

#define MAX_CACHE_SIZE     16 * 1024ul * 1024ul * 1024ul /* it has to be a multiple of 16k */
#define BLOCK_SIZE	   8 * 1024

Cache< BlkId > * Volume::glob_cache = NULL;

AbstractVirtualDev *
homestore::Volume::new_vdev_found(DeviceManager *dev_mgr, homestore::vdev_info_block *vb) {
    LOG(INFO) << "New virtual device found id = " << vb->vdev_id << " size = " << vb->size;

   /* TODO: enable it after testing */
#if 0
    homestore::Volume *volume = new homestore::Volume(dev_mgr, vb);
    return volume->blk_store->get_vdev();
#endif
    return NULL;
}

homestore::Volume::Volume(homestore::DeviceManager *dev_mgr, uint64_t size) {
    size = size;
    if (Volume::glob_cache == NULL) {
	Volume::glob_cache = new homestore::Cache< BlkId >(MAX_CACHE_SIZE, BLOCK_SIZE);
	cout << "cache created\n";
    }
    blk_store = new homestore::BlkStore< homestore::VdevVarSizeBlkAllocatorPolicy >(dev_mgr, Volume::glob_cache, size,
                                                                                  WRITETHRU_CACHE, 0);
    map = new mapping(size);
}

homestore::Volume::Volume(DeviceManager *dev_mgr, homestore::vdev_info_block *vb) {
    size = vb->size; 
    if (Volume::glob_cache == NULL) {
	Volume::glob_cache = new homestore::Cache< BlkId >(MAX_CACHE_SIZE, BLOCK_SIZE);
	cout << "cache created\n";
    }
    blk_store = new homestore::BlkStore< homestore::VdevVarSizeBlkAllocatorPolicy >(dev_mgr, Volume::glob_cache, 
										vb, WRITETHRU_CACHE);
    map = new mapping(size);
}

int 
homestore::Volume::write(uint64_t lba, uint8_t *buf, uint32_t nblks) {
    homestore::BlkId bid;
    homestore::blk_alloc_hints hints;
    hints.desired_temp = 0;
    hints.dev_id_hint = -1;

    blk_store->alloc_blk(nblks, hints, &bid);

    LOG(INFO) << "Requested nblks: " << (uint32_t)nblks << " Allocation info: " << bid.to_string();

    homeds::blob b = {buf, BLOCK_SIZE * nblks};

    boost::intrusive_ptr< BlkBuffer > bbuf = blk_store->write(bid, b);
    cout << "written\n";
    map->put(lba, nblks, bid);
    LOG(INFO) << "Written on " << bid.to_string() << " for 8192 bytes";
    return 0;
}

int
homestore::Volume::read(uint64_t lba, int nblks, std::vector<boost::intrusive_ptr< BlkBuffer >> &buf_list) {

	/* TODO: pass a pointer */
	std::vector<struct BlkId> blkIdList;
	boost::intrusive_ptr< BlkBuffer > bbuf;
//	cout << "value in read";
//	cout << lba;
//	cout << "number of blocks";
//	cout << nblks;
	if (map->get(lba, nblks, blkIdList)) {
		ASSERT(0);
	}
	
	for (auto bInfo: blkIdList) {
        //	LOG(INFO) << "Read from " << bInfo.to_string() << " for 8192 bytes";
        	bbuf = blk_store->read(bInfo, 0, BLOCK_SIZE * bInfo.get_nblks());
		buf_list.push_back(bbuf);
		/* TODO: we need to copy it in the buffer */		
	}
    	return 0;
}
