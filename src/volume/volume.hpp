#pragma once

#include "device/device.h"
#include <fcntl.h>
#include <cache/cache_common.hpp>
#include <cache/cache.h>
#include "blkstore/writeBack_cache.hpp"
#include <device/blkbuffer.hpp>
#include <blkstore/blkstore.hpp>

using namespace std;

#ifndef NDEBUG
extern std::atomic<int> vol_req_alloc;
#endif
namespace homestore {

    struct buf_info {
        uint64_t size;
        int offset;
        boost::intrusive_ptr<BlkBuffer> buf;
    };

    class mapping;

/* this structure is not thread safe. But as of
 * now there is no use where we can access it in
 * multiple threads.
 */
    struct Free_Blk_Entry {
        BlkId blkId;
        uint16_t blkId_offset;
        uint16_t nblks_to_free;

        Free_Blk_Entry(const BlkId &blkId,
                       uint16_t blkId_offset,
                       int nblks_to_free) : blkId(blkId),
                                            blkId_offset(
                                                    blkId_offset),
                                            nblks_to_free(
                                                    nblks_to_free) {}

        std::string to_string() {
            std::stringstream ss;
            ss << nblks_to_free << "," << blkId_offset << "--->" << blkId.to_string();
            return ss.str();
        }
    };

    struct volume_req : blkstore_req<BlkBuffer> {
        uint64_t lba;
        int nblks;
        Clock::time_point startTime;
        std::vector<buf_info> read_buf_list;
        bool is_read;

        std::vector<std::shared_ptr<Free_Blk_Entry>> blkids_to_free_due_to_overwrite;

        /* number of times mapping table need to be updated for this req. It can
         * break the ios update in mapping btree depending on the key range.
         */
        std::atomic<int> num_mapping_update;
        boost::intrusive_ptr<volume_req> parent_req;
        std::atomic<int> ref_cnt; /* It is initialized to 1 if there is no child created */

        volume_req() : read_buf_list(0), is_read(false), 
            num_mapping_update(0), parent_req(nullptr), ref_cnt(0) {
#ifndef NDEBUG
            vol_req_alloc++;
#endif
        }

        /* any derived class should have the virtual destructor to prevent
         * memory leak because pointer can be free with the base class. 
         */
        virtual ~volume_req() {
#ifndef NDEBUG
            vol_req_alloc--;
#endif
        }
    };

    class Volume {

        typedef std::function<void(boost::intrusive_ptr<volume_req> req)> comp_callback;
        uint64_t size;
        mapping *map;
        atomic<uint64_t> outstanding_write_cnt;
        comp_callback comp_cb;
        boost::intrusive_ptr<BlkBuffer> only_in_mem_buff;

        Volume(DeviceManager *mgr, uint64_t size, comp_callback comp_cb);

        Volume(DeviceManager *dev_mgr, homestore::vdev_info_block *vb);

    public:


        static std::shared_ptr<Volume> createVolume(std::string const &uuid,
                                                    DeviceManager *mgr,
                                                    uint64_t const size,
                                                    comp_callback comp_cb);

        // !!! Permanent destroy the volume reclaiming all allocations !!!
        // - Must be called with no remaining references to the volume and through
        // - the Volume::removeVolume(uuid) call.
        std::error_condition destroy();

    public:

        homestore::BlkStore<homestore::VdevVarSizeBlkAllocatorPolicy> *blk_store;
        static Cache<BlkId> *glob_cache;

        static std::error_condition removeVolume(std::string const &uuid);

        static std::shared_ptr<Volume> lookupVolume(std::string const &uuid);


        static AbstractVirtualDev *new_vdev_found(DeviceManager *dev_mgr,
                                                  homestore::vdev_info_block *vb);

        void write(uint64_t lba, uint8_t *buf, uint32_t nblks,
                              boost::intrusive_ptr<volume_req> req);

        int read(uint64_t lba, int nblks, boost::intrusive_ptr<volume_req> req);
    void init_perf_report();
    void print_perf_report();
        uint64_t get_elapsed_time(Clock::time_point startTime);

        void process_data_completions(boost::intrusive_ptr<blkstore_req<BlkBuffer>> bs_req);

        void process_metadata_completions(boost::intrusive_ptr<volume_req> wb_req);

        void free_blk(homestore::BlkId bid);

        void set_cb(comp_callback cb) { comp_cb = cb; };

        void print_tree();

    private:
        void alloc_single_block_in_mem();


    };
}
