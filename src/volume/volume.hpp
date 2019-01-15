#pragma once

#include "device/device.h"
#include <fcntl.h>
#include <cache/cache_common.hpp>
#include <cache/cache.h>
#include "blkstore/writeBack_cache.hpp"
#include <device/blkbuffer.hpp>
#include <blkstore/blkstore.hpp>
#include "home_blks.hpp"

#include "threadpool/thread_pool.h"
using namespace std;

#ifndef NDEBUG
extern std::atomic<int> vol_req_alloc;
#endif
namespace homestore {

class mapping;
enum vol_state;

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
    bool is_read;
    std::shared_ptr<Volume> vol_instance;

    std::vector<std::shared_ptr<Free_Blk_Entry>> blkids_to_free_due_to_overwrite;

    /* number of times mapping table need to be updated for this req. It can
     * break the ios update in mapping btree depending on the key range.
     */
    std::atomic<int> num_mapping_update;
    boost::intrusive_ptr<vol_interface_req> parent_req;
    bool done;

    volume_req() : is_read(false), num_mapping_update(0), parent_req(nullptr), done(false) {
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
    mapping *m_map;
    boost::intrusive_ptr<BlkBuffer> m_only_in_mem_buff;
    struct vol_sb *m_sb;
    enum vol_state m_state;
    void alloc_single_block_in_mem();
    void vol_scan_alloc_blks();
    io_comp_callback m_comp_cb;
    std::shared_ptr<Volume> m_vol_ptr;

 public:
    Volume(vol_params &params);
    Volume(vol_sb *sb);
    ~Volume() { free(m_sb); };
    std::error_condition destroy();
   
    static homestore::BlkStore<homestore::VdevVarSizeBlkAllocatorPolicy> *m_data_blkstore;
    static void process_vol_data_completions(boost::intrusive_ptr<blkstore_req<BlkBuffer>> bs_req);
    void process_metadata_completions(boost::intrusive_ptr<volume_req> wb_req);
    void process_data_completions(boost::intrusive_ptr<blkstore_req<BlkBuffer>> bs_req);

    std::error_condition write(uint64_t lba, uint8_t *buf, uint32_t nblks,
            boost::intrusive_ptr<vol_interface_req> req);

    std::error_condition read(uint64_t lba, int nblks, boost::intrusive_ptr<vol_interface_req> req, bool sync);
    void init_perf_report();
    void print_perf_report();
    uint64_t get_elapsed_time(Clock::time_point startTime);
    void attach_completion_cb(io_comp_callback &cb);

    void print_tree();
    struct vol_sb *get_sb() {return m_sb;};
    std::shared_ptr<Volume> get_shared_ptr() { return m_vol_ptr; };
    
    void blk_recovery_process_completions(bool success);
    void blk_recovery_callback(MappingValue& mv);

    mapping* get_mapping_handle() {
        return m_map;
    }

    uint64_t get_last_lba() {
        assert(m_sb->size != 0);
        // lba starts from 0, then 1, 2, ... 
        if (m_sb->size % HomeStoreConfig::phys_page_size == 0)
            return m_sb->size / HomeStoreConfig::phys_page_size - 1;
        else 
            return m_sb->size / HomeStoreConfig::phys_page_size;
    }

    char *get_name();
    uint64_t get_page_size();
    uint64_t get_size();


#ifndef NDEBUG
    void enable_split_merge_crash_simulation();
#endif
};

#define BLKSTORE_BLK_SIZE_IN_BYTES          HomeStoreConfig::phys_page_size
#define QUERY_RANGE_IN_BYTES                (64*1024*1024ull)
#define NUM_BLKS_PER_THREAD_TO_QUERY        (QUERY_RANGE_IN_BYTES/BLKSTORE_BLK_SIZE_IN_BYTES)

class BlkAllocBitmapBuilder {
    typedef std::function< void (MappingValue& mv) > blk_recovery_callback;
    typedef std::function< void (bool success) > comp_callback;
  private:
    homestore::Volume*                      m_vol_handle;
    blk_recovery_callback                   m_blk_recovery_cb;
    comp_callback                           m_comp_cb;

  public:
    BlkAllocBitmapBuilder(homestore::Volume* vol, blk_recovery_callback blk_rec_cb, comp_callback comp_cb): m_vol_handle(vol), m_blk_recovery_cb(blk_rec_cb), m_comp_cb(comp_cb) { }
    ~BlkAllocBitmapBuilder();

    // async call to start the multi-threaded work.
    void get_allocated_blks();

  private:
    // do the real work of getting all allocated blks in multi-threaded manner
    void do_work();
};

}
