
//
// Created by Kadayam, Hari on 06/11/17.
//

#include "volume.hpp"

using namespace std;
using namespace homestore;

#define MAX_CACHE_SIZE     (2 * 1024ul * 1024ul * 1024ul) /* it has to be a multiple of 16k */
constexpr auto BLOCK_SIZE = (8 * 1024ul);


Cache< BlkId > * Volume::glob_cache = NULL;
uint64_t 
homestore::Volume::get_elapsed_time(Clock::time_point startTime) {
	std::chrono::nanoseconds ns = std::chrono::duration_cast
					< std::chrono::nanoseconds >(Clock::now() - startTime);
	return ns.count() / 1000;
}

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

homestore::Volume::Volume(homestore::DeviceManager *dev_mgr, uint64_t size, 
						comp_callback comp_cb):comp_cb(comp_cb) {
    fLI::FLAGS_minloglevel=3;
    if (Volume::glob_cache == NULL) {
        Volume::glob_cache = new homestore::Cache< BlkId >(MAX_CACHE_SIZE, BLOCK_SIZE);
        cout << "cache created\n";
    }
    blk_store = new homestore::BlkStore< homestore::VdevVarSizeBlkAllocatorPolicy >
							(dev_mgr, Volume::glob_cache, size,
                                                         WRITETHRU_CACHE, 0, 
							 (std::bind(&Volume::process_completions, 
							  this, std::placeholders::_1, 
							  std::placeholders::_2)));
    map = new mapping(size);
}

homestore::Volume::Volume(DeviceManager *dev_mgr, homestore::vdev_info_block *vb) {
    size = vb->size;
    if (Volume::glob_cache == NULL) {
        Volume::glob_cache = new homestore::Cache< BlkId >(MAX_CACHE_SIZE, BLOCK_SIZE);
        cout << "cache created\n";
    }
    blk_store = new homestore::BlkStore< homestore::VdevVarSizeBlkAllocatorPolicy >
							(dev_mgr, Volume::glob_cache, vb, 
							 WRITETHRU_CACHE, 
							 (std::bind(&Volume::process_completions, this,
							  std::placeholders::_1, std::placeholders::_2)));
    map = new mapping(size);
    /* TODO: rishabh, We need a attach function to register completion callback if layers
     * are called from bottomup.
     */
}

void 
homestore::Volume::process_completions(int status, blkstore_req *bs_req) {
	
   struct volume_req * req = static_cast< struct volume_req * >(bs_req);
   if (status) {
	comp_cb(status, req);
   }
	
   if (!req->is_read) {
	Clock::time_point startTime = Clock::now();
    	map->put(req->lba, req->nblks, req->bid);
	map_time += get_elapsed_time(startTime);
   	io_write_time.fetch_add(get_elapsed_time(req->startTime), memory_order_relaxed);
   } else {
	req->read_cnt--;
	if (req->read_cnt != 0) {
		return;
	}
   	io_read_time.fetch_add(get_elapsed_time(req->startTime), memory_order_relaxed);
   }
   comp_cb(status, req);
}

void
homestore::Volume::init_perf_cntrs() {
    write_cnt = 0;
    alloc_blk_time = 0;
    write_time = 0;
    map_time = 0;
    io_write_time = 0;
    blk_store->init_perf_cnts();
}

void
homestore::Volume::print_perf_cntrs() {
    printf("avg time taken in alloc_blk %lu us\n", alloc_blk_time/write_cnt);
    printf("avg time taken in issuing write from volume layer %lu us\n", 
							write_time/write_cnt);
    printf("avg time taken in writing map %lu us\n", map_time/write_cnt);
    printf("avg time taken in write %lu us\n", io_write_time/write_cnt);
    if (atomic_load(&read_cnt) != 0) {
    	printf("avg time taken in read %lu us\n", io_read_time/read_cnt);
    	printf("avg time taken in reading map %lu us\n", 
					map_read_time/read_cnt);
    	printf("avg time taken in issuing read from volume layer %lu us\n", 
							read_time/read_cnt);
    }
    blk_store->print_perf_cnts();
}

boost::intrusive_ptr< BlkBuffer > 
homestore::Volume::write(uint64_t lba, uint8_t *buf, uint32_t nblks, volume_req* req) {
    homestore::BlkId bid;
    homestore::blk_alloc_hints hints;
    hints.desired_temp = 0;
    hints.dev_id_hint = -1;
    
    req->lba = lba;
    req->nblks = nblks;
    req->is_read = false;
    req->read_cnt = 0;
    req->startTime = Clock::now();

    write_cnt.fetch_add(1, memory_order_relaxed);
    {
    	Clock::time_point startTime = Clock::now();
    	blk_store->alloc_blk(nblks, hints, &bid);
    	alloc_blk_time.fetch_add(get_elapsed_time(startTime), memory_order_relaxed);
    }
    req->bid = bid;

   // LOG(INFO) << "Requested nblks: " << (uint32_t) nblks << " Allocation info: " << bid.to_string();

    homeds::blob b = {buf, (uint32_t)(BLOCK_SIZE * nblks)};

    Clock::time_point startTime = Clock::now();
    boost::intrusive_ptr< BlkBuffer > bbuf = blk_store->write(bid, b, req);
    /* TODO: should check the write status */
    write_time.fetch_add(get_elapsed_time(startTime), memory_order_relaxed);
    // cout << "written\n";
//    cout << "Written on " << bid.to_string() << " for 8192 bytes";
  //  LOG(INFO) << "Written on " << bid.to_string() << " for 8192 bytes";
    return bbuf;
}

int
homestore::Volume::read(uint64_t lba, int nblks, volume_req* req) {

    std::vector< struct BlkId > blkIdList;
    req->startTime = Clock::now();
    Clock::time_point startTime = Clock::now();
    req->read_cnt = 0;
    
    int ret = map->get(lba, nblks, blkIdList);
    /* TODO: map is also going to be async once persistent bree comes.
     * This check will be removed later. 
     */
    if (ret == EMAP_NOTFOUND) {
	process_completions(EMAP_NOTFOUND, req); 
    	return 0;
    } else {
	assert(ret == 0);
    }

    map_read_time.fetch_add(get_elapsed_time(startTime), memory_order_relaxed);

    read_cnt.fetch_add(1, memory_order_relaxed);
    req->lba = lba;
    req->nblks = nblks;
    req->is_read = true;
    req->read_cnt = blkIdList.size();
    
    startTime = Clock::now();
    for (auto bInfo: blkIdList) {
       // LOG(INFO) << "Read from " << bInfo.to_string() << " for 8192 bytes";
//	printf("blkid %d\n", bInfo.m_id);
        boost::intrusive_ptr< BlkBuffer > bbuf = blk_store->read(bInfo, 0, BLOCK_SIZE * bInfo.get_nblks(), req);
    }
    read_time.fetch_add(get_elapsed_time(startTime), memory_order_relaxed);
    return 0;
}
