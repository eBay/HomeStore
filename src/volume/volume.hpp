#pragma once

#include "device/device.h"
#include <fcntl.h>
#include <cache/cache_common.hpp>
#include <cache/cache.h>
#include "blkstore/writeBack_cache.hpp"
#include <device/blkbuffer.hpp>
#include <blkstore/blkstore.hpp>
#include "home_blks.hpp"

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
    static homestore::BlkStore<homestore::VdevVarSizeBlkAllocatorPolicy> *m_data_blkstore;
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
    char *get_name();
    uint64_t get_page_size();
    uint64_t get_size();

#ifndef NDEBUG
    void enable_split_merge_crash_simulation();
#endif
};
}
