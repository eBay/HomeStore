
//
// Created by Kadayam, Hari on 06/11/17.
//

#include "volume.hpp"
#include <device/blkbuffer.hpp>

using namespace std;
using namespace homestore;

#define MAX_CACHE_SIZE     (8 * 1024ul * 1024ul * 1024ul) /* it has to be a multiple of 16k */
#define BLOCK_SIZE       (8 * 1024ul)


Cache< BlkId > * Volume::glob_cache = NULL;
uint64_t 
homestore::Volume::get_elapsed_time(Clock::time_point startTime) {
	std::chrono::nanoseconds ns = std::chrono::duration_cast
					< std::chrono::nanoseconds >(Clock::now() - startTime);
	return ns.count() / 1000;
}

static AbstractVirtualDev *
homestore::Volume::new_vdev_found(DeviceManager *dev_mgr, homestore::vdev_info_block *vb) {
    LOG(INFO) << "New virtual device found id = " << vb->vdev_id << " size = " << vb->size;

    /* TODO: enable it after testing */
#if 0
    homestore::Volume *volume = new homestore::Volume(dev_mgr, vb);
    return volume->blk_store->get_vdev();
#endif
    return NULL;
}

homestore::Volume::Volume(homestore::DeviceManager *dev_mgr, uint64_t size, 
						comp_callback comp_cb):comp_cb(comp_cb) {
    fLI::FLAGS_minloglevel=3;
    if (Volume::glob_cache == NULL) {
        Volume::glob_cache = new homestore::Cache< BlkId >(MAX_CACHE_SIZE, BLOCK_SIZE);
        cout << "cache created\n";
    }
    comp_callback cb = std::bind(&Volume::process_completions, this);
    blk_store = new homestore::BlkStore< homestore::VdevVarSizeBlkAllocatorPolicy >
							(dev_mgr, Volume::glob_cache, size,
                                                         WRITETHRU_CACHE, 0, cb);
    map = new mapping(size);
}

homestore::Volume::Volume(DeviceManager *dev_mgr, homestore::vdev_info_block *vb) {
    size = vb->size;
    if (Volume::glob_cache == NULL) {
        Volume::glob_cache = new homestore::Cache< BlkId >(MAX_CACHE_SIZE, BLOCK_SIZE);
        cout << "cache created\n";
    }
    comp_callback cb = std::bind(&Volume::process_completions, this);
    blk_store = new homestore::BlkStore< homestore::VdevVarSizeBlkAllocatorPolicy >
							(dev_mgr, Volume::glob_cache, vb, 
							 WRITETHRU_CACHE, cb);
    map = new mapping(size);
    /* TODO: rishabh, We need a attach function to register completion callback if layers
     * are called from bottomup.
     */
}

void 
homestore::Volume::process_completions(int status, blockstore_req *bs_req) {
	
   struct vol_req * req = dynamic_cast< vol_req * >(bs_req);
   if (status) {
	io_time += get_elapsed_time(req->startTime);
	completion_cb(status, req);
   }
	
   if (!req->is_read) {
	Clock::time_point startTime = Clock::now();
    	map->put(req->lba, req->nblks, req->bid);
	map_time += get_elapsed_time(startTime);
   } else {
	/* TODO:assuming that reads are coming in order.
	 * However it is not true because one read can 
	 * split into two different reads from two different disks 
	 * and it can come out of order. Need it fix it.
	 */
	req->read_cnt--;
	req->buf_list.push_back(req->read_bbuf);
	if (read_cnt != 0) {
		return;
	}
   }
   io_time += get_elapsed_time(req->startTime);
   comp_cb(status, req);
}

void
homestore::Volume::init_perf_cntrs() {
    write_cnt = 0;
    alloc_blk_time = 0;
    write_time = 0;
    map_time = 0;
    io_time = 0;
    blk_store->init_perf_cnts();
}

void
homestore::Volume::print_perf_cntrs() {
    printf("total writes %lu \n", write_cnt);
    printf("avg time taken in alloc_blk %lu us\n", alloc_blk_time/write_cnt);
    printf("avg time taken in write %lu us\n", write_time/write_cnt);
    printf("avg time taken in map %lu us\n", map_time/write_cnt);
    printf("avg time taken in map %lu us\n", io_time/write_cnt);
    blk_store->print_perf_cnts();
}

int 
homestore::Volume::write(uint64_t lba, uint8_t *buf, uint32_t nblks, volumeIO_req* req) {
    homestore::BlkId bid;
    homestore::blk_alloc_hints hints;
    hints.desired_temp = 0;
    hints.dev_id_hint = -1;
    
    req->lba = lba;
    req->nblks = nblks;
    req->is_read = false;
    req->send_cnt = 0;
    req->startTime = Clock::now();

    write_cnt++;
    {
    	Clock::time_point startTime = Clock::now();
    	blk_store->alloc_blk(nblks, hints, &bid);
    	alloc_blk_time += get_elapsed_time(startTime);
    }

    LOG(INFO) << "Requested nblks: " << (uint32_t) nblks << " Allocation info: " << bid.to_string();

    homeds::blob b = {buf, (uint32_t)(BLOCK_SIZE * nblks)};

    {
    	Clock::time_point startTime = Clock::now();
  	boost::intrusive_ptr< BlkBuffer > bbuf = blk_store->write(bid, b, req);
	/* TODO: should check the write status */
	write_time += get_elapsed_time(startTime);
    }
   // cout << "written\n";
    LOG(INFO) << "Written on " << bid.to_string() << " for 8192 bytes";
    return 0;
}

int
homestore::Volume::read(uint64_t lba, int nblks, 
			std::vector< boost::intrusive_ptr< BlkBuffer >> &buf_list, 
			volumeIO_req* req) {

    /* TODO: pass a pointer */
    std::vector< struct BlkId > blkIdList;
    boost::intrusive_ptr< BlkBuffer > bbuf;
//	cout << "value in read";
//	cout << lba;
//	cout << "number of blocks";
//	cout << nblks;
    if (map->get(lba, nblks, blkIdList)) {
        ASSERT(0);
    }

    req->lba = lba;
    req->nblks = nblks;
    req->is_read = true;
    req->send_cnt = 0;
    req->startTime = Clock::now();
    
    for (auto bInfo: blkIdList) {
       // LOG(INFO) << "Read from " << bInfo.to_string() << " for 8192 bytes";
//	printf("blkid %d\n", bInfo.m_id);
        blk_store->read(bInfo, 0, BLOCK_SIZE * bInfo.get_nblks());
	req->send_cnt++;
    }
    return 0;
}
