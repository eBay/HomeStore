#pragma once

#include "device/device.h"
#include <fcntl.h>
#include <cache/cache_common.hpp>
#include <cache/cache.h>
#include <mapping/mapping.hpp>
#include <device/blkbuffer.hpp>
#include <blkstore/blkstore.hpp>

using namespace std;

namespace homestore {

/* this structure is not thread safe. But as of
 * now there is no use where we can access it in
 * multiple threads.
 */
struct volume_req:blkstore_req<BlkBuffer> {
	uint64_t lba;
	int nblks;
	Clock::time_point startTime;
	int read_cnt;
	std::vector< boost::intrusive_ptr< BlkBuffer >> read_buf_list;

    volume_req():read_buf_list(0){};

    /* any derived class should have the virtual destructor to prevent
     * memory leak because pointer can be free with the base class. 
     */
    virtual ~volume_req() {
    }
};

class Volume {

	typedef std::function< void (boost::intrusive_ptr<volume_req> req) > comp_callback;
    uint64_t size;
    mapping *map;
    atomic<uint64_t> alloc_blk_time;
    atomic<uint64_t> write_time;
    atomic<uint64_t> read_time;
    atomic<uint64_t> map_time;
    atomic<uint64_t> io_write_time;
    atomic<uint64_t> io_read_time;
    atomic<uint64_t> map_read_time;
    atomic<uint64_t> write_cnt;
    atomic<uint64_t> read_cnt;
    comp_callback comp_cb;
    boost::intrusive_ptr< BlkBuffer > only_in_mem_buff;

    Volume(DeviceManager *mgr, uint64_t size, comp_callback comp_cb);
    Volume(DeviceManager *dev_mgr, homestore::vdev_info_block *vb);

    public:


    static std::shared_ptr<Volume> createVolume(std::string const& uuid,
            DeviceManager* mgr,
            uint64_t const size,
            comp_callback comp_cb);

	// !!! Permanent destroy the volume reclaiming all allocations !!!
   // - Must be called with no remaining references to the volume and through
	// - the Volume::removeVolume(uuid) call.
	std::error_condition destroy();

 public:

    homestore::BlkStore< homestore::VdevVarSizeBlkAllocatorPolicy > *blk_store;
    static Cache< BlkId > *glob_cache;

    static std::error_condition removeVolume(std::string const& uuid);

    static std::shared_ptr<Volume> lookupVolume(std::string const& uuid);


    static AbstractVirtualDev *new_vdev_found(DeviceManager *dev_mgr, 
            homestore::vdev_info_block *vb);
    boost::intrusive_ptr< BlkBuffer > write(uint64_t lba, uint8_t *buf, 
            uint32_t nblks, 
            boost::intrusive_ptr<volume_req> req);
    int read(uint64_t lba, int nblks, boost::intrusive_ptr<volume_req> req);
    void init_perf_cntrs();
    void print_perf_cntrs();
    uint64_t get_elapsed_time(Clock::time_point startTime);

    void process_data_completions(boost::intrusive_ptr<blkstore_req<BlkBuffer>> bs_req);
    void process_metadata_completions(boost::intrusive_ptr<volume_req> wb_req, 
            std::error_condition status);

    void free_blk(homestore::BlkId bid);
    void set_cb(comp_callback cb) { comp_cb = cb; };

 private:
    void alloc_single_block_in_mem();
};
}
