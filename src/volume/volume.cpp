
//
// Created by Kadayam, Hari on 06/11/17.
//

#include "volume.hpp"

using namespace std;

#define MAX_CACHE_SIZE     (2 * 1024ul * 1024ul * 1024ul) /* it has to be a multiple of 16k */
constexpr auto BLOCK_SIZE = (4 * 1024ul);

static std::map<std::string, std::shared_ptr<homestore::Volume>> volume_map;
static std::mutex map_lock;

namespace homestore
{

std::shared_ptr<Volume>
Volume::createVolume(std::string const& uuid,
                     DeviceManager* mgr,
                     uint64_t const size,
                     comp_callback comp_cb) {
   decltype(volume_map)::iterator it;
   // Try to add an entry for this volume
   {  std::lock_guard<std::mutex> lg (map_lock);
      bool happened {false};
      std::tie(it, happened) = volume_map.emplace(std::make_pair(uuid, nullptr));
      if (!happened) {
         if (volume_map.end() != it) return it->second;
         throw std::runtime_error("Unknown bug");
      }
   }
   // Okay, this is a new volume so let's create it
   auto new_vol = new Volume(mgr, size, comp_cb);
   it->second.reset(new_vol);
   return it->second;
}

std::error_condition
Volume::removeVolume(std::string const& uuid) {
   std::shared_ptr<Volume> volume;
   // Locked Map
   { std::lock_guard<std::mutex> lg(map_lock);
      if (auto it = volume_map.find(uuid); volume_map.end() != it) {
         if (2 <= it->second.use_count()) {
            LOGERROR("Refusing to delete volume with outstanding references: {}", uuid);
            return std::make_error_condition(std::errc::device_or_resource_busy);
         }
         volume = std::move(it->second);
         volume_map.erase(it);
      }
   } // Unlock Map
   return (volume ? volume->destroy() : std::make_error_condition(std::errc::no_such_device_or_address));
}

std::shared_ptr<Volume>
Volume::lookupVolume(std::string const& uuid) {
   {  std::lock_guard<std::mutex> lg (map_lock);
      auto it = volume_map.find(uuid);
      if (volume_map.end() != it) return it->second;
   }
   return nullptr;
}

Cache< BlkId > * Volume::glob_cache = NULL;
uint64_t 
Volume::get_elapsed_time(Clock::time_point startTime) {
	std::chrono::nanoseconds ns = std::chrono::duration_cast
					< std::chrono::nanoseconds >(Clock::now() - startTime);
	return ns.count() / 1000;
}

AbstractVirtualDev *
Volume::new_vdev_found(DeviceManager *dev_mgr, vdev_info_block *vb) {
    LOGINFO("New virtual device found id = {} size = {}", vb->vdev_id, vb->size);

    /* TODO: enable it after testing */
#if 0
    Volume *volume = new Volume(dev_mgr, vb);
    return volume->blk_store->get_vdev();
#endif
    return NULL;
}

Volume::Volume(DeviceManager *dev_mgr, uint64_t size,
						comp_callback comp_cb):comp_cb(comp_cb) {
    fLI::FLAGS_minloglevel=3;
    if (Volume::glob_cache == NULL) {
        Volume::glob_cache = new Cache< BlkId >(MAX_CACHE_SIZE, BLOCK_SIZE);
        cout << "cache created\n";
    }
    blk_store = new BlkStore< VdevVarSizeBlkAllocatorPolicy >
							(dev_mgr, Volume::glob_cache, size,
                                                         WRITETHRU_CACHE, 0, 
							 (std::bind(&Volume::process_completions, 
							  this, std::placeholders::_1)));
    map = new mapping(size,
		[this] (homestore::BlkId bid) { free_blk(bid); }, dev_mgr);
    alloc_single_block_in_mem();
}

Volume::Volume(DeviceManager *dev_mgr, vdev_info_block *vb) {
    size = vb->size;
    if (Volume::glob_cache == NULL) {
        Volume::glob_cache = new Cache< BlkId >(MAX_CACHE_SIZE, BLOCK_SIZE);
        cout << "cache created\n";
    }
    blk_store = new BlkStore< VdevVarSizeBlkAllocatorPolicy >
							(dev_mgr, Volume::glob_cache, vb, 
							 WRITETHRU_CACHE, 
							 (std::bind(&Volume::process_completions, this,
							  std::placeholders::_1)));
    map = new mapping(size, 
		[this] (homestore::BlkId bid) { free_blk(bid); }, dev_mgr);
    alloc_single_block_in_mem();
    /* TODO: rishabh, We need a attach function to register completion callback if layers
     * are called from bottomup.
     */
}

std::error_condition
Volume::destroy() {
   LOGWARN("UnImplemented volume destruction!");
   return std::error_condition();
}

void 
homestore::Volume::process_completions(blkstore_req<BlkBuffer> *bs_req) {
	
   struct volume_req * req = static_cast< struct volume_req * >(bs_req);
   if (req->err != no_error) {
	comp_cb(req);
        return;
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
   comp_cb(req);
}

void
Volume::init_perf_cntrs() {
    write_cnt = 0;
    alloc_blk_time = 0;
    write_time = 0;
    map_time = 0;
    io_write_time = 0;
    blk_store->init_perf_cnts();
}

void
Volume::print_perf_cntrs() {
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

void
homestore::Volume::free_blk(homestore::BlkId bid) {
	blk_store->free_blk(bid, boost::none, boost::none);
}

boost::intrusive_ptr< BlkBuffer > 
Volume::write(uint64_t lba, uint8_t *buf, uint32_t nblks, volume_req* req) {
    BlkId bid;
    blk_alloc_hints hints;
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
    	BlkAllocStatus status = blk_store->alloc_blk(nblks, hints, &bid);
	if (status != BLK_ALLOC_SUCCESS) {
		assert(0);
	}
    	alloc_blk_time.fetch_add(get_elapsed_time(startTime), memory_order_relaxed);
    }
    req->bid = bid;

   // LOG(INFO) << "Requested nblks: " << (uint32_t) nblks << " Allocation info: " << bid.to_string();

    homeds::blob b = {buf, (uint32_t)(BLOCK_SIZE * nblks)};

    Clock::time_point startTime = Clock::now();
    boost::intrusive_ptr< BlkBuffer > bbuf = blk_store->write(bid, b, req);
    /* TODO: should check the write status */
    write_time.fetch_add(get_elapsed_time(startTime), memory_order_relaxed);
  //  LOG(INFO) << "Written on " << bid.to_string() << " for 8192 bytes";
    return bbuf;
}

void Volume::print_tree(){
    map->print_tree();
}

int
Volume::read(uint64_t lba, int nblks, volume_req* req) {

    std::vector< struct lba_BlkId_mapping > mappingList;
    req->startTime = Clock::now();
    Clock::time_point startTime = Clock::now();
    req->read_cnt = 0;
    
    map->get(lba, nblks, mappingList);
    /* TODO: map is also going to be async once persistent bree comes.
     * This check will be removed later. 
     */

    map_read_time.fetch_add(get_elapsed_time(startTime), memory_order_relaxed);

    read_cnt.fetch_add(1, memory_order_relaxed);
    req->lba = lba;
    req->nblks = nblks;
    req->is_read = true;
    req->read_cnt = mappingList.size();
    
    startTime = Clock::now();
    for (auto bInfo: mappingList) {
        if(!bInfo.blkid_found){
            req->read_buf_list.push_back(only_in_mem_buff);
        }else {
            boost::intrusive_ptr<BlkBuffer> bbuf = blk_store->read(bInfo.blkId, 0, BLOCK_SIZE * bInfo.blkId.get_nblks(),
                                                                   req);
        }
    }
    read_time.fetch_add(get_elapsed_time(startTime), memory_order_relaxed);
    return 0;
}

    /* Just create single block in memory, not on physical device and not in cache */
    void Volume::alloc_single_block_in_mem() {
        BlkId *out_blkid = new BlkId(0);
        // Create an object for the buffer
        only_in_mem_buff = BlkBuffer::make_object();
        only_in_mem_buff->set_key(*out_blkid);
    
        // Create a new block of memory for the blocks requested and set the memvec pointer to that
        uint8_t *ptr;
        uint32_t size = BLKSTORE_BLK_SIZE;
        int ret = posix_memalign((void **) &ptr, 4096, size); // TODO: Align based on hw needs instead of 4k
        if (ret != 0) {
            throw std::bad_alloc();
        }
        memset(ptr, 0, size);
        homeds::MemVector< BLKSTORE_BLK_SIZE > &mvec = only_in_mem_buff->get_memvec_mutable();
        mvec.set(ptr, size, 0);
    }
} /* homestore */
