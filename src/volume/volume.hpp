#pragma once

#include "device/device.h"
#include <fcntl.h>
#include <cache/cache_common.hpp>
#include <cache/cache.h>
#include "blkstore/writeBack_cache.hpp"
#include <device/blkbuffer.hpp>
#include <blkstore/blkstore.hpp>
#include "home_blks.hpp"
#include <metrics/metrics.hpp>
#include <utility/atomic_counter.hpp>

using namespace std;

#ifndef NDEBUG
extern std::atomic< int > vol_req_alloc;
#endif
namespace homestore {

class mapping;
enum vol_state;

/* this structure is not thread safe. But as of
 * now there is no use where we can access it in
 * multiple threads.
 */
struct Free_Blk_Entry {
    BlkId    blkId;
    uint16_t blkId_offset;
    uint16_t nblks_to_free;

    Free_Blk_Entry(const BlkId& blkId, uint16_t blkId_offset, int nblks_to_free) :
            blkId(blkId),
            blkId_offset(blkId_offset),
            nblks_to_free(nblks_to_free) {}

    std::string to_string() {
        std::stringstream ss;
        ss << nblks_to_free << "," << blkId_offset << "--->" << blkId.to_string();
        return ss.str();
    }
};

struct volume_req : blkstore_req< BlkBuffer > {
public:
    uint64_t                  lba;
    int                       nblks;
    bool                      is_read;
    std::shared_ptr< Volume > vol_instance;
    Clock::time_point         op_start_time;

    std::vector< std::shared_ptr< Free_Blk_Entry > > blkids_to_free_due_to_overwrite;

    /* number of times mapping table need to be updated for this req. It can
     * break the ios update in mapping btree depending on the key range.
     */
    std::atomic< int >                        num_mapping_update;
    boost::intrusive_ptr< vol_interface_req > parent_req;
    bool                                      done;

public:
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

class VolumeMetrics : public sisl::MetricsGroupWrapper {
public:
    explicit VolumeMetrics(const char* vol_name) : sisl::MetricsGroupWrapper(vol_name) {
        REGISTER_COUNTER(volume_read_count, "Total Volume read operations");
        REGISTER_COUNTER(volume_write_count, "Total Volume write operations");
        REGISTER_COUNTER(volume_read_error_count, "Total Volume read error count");
        REGISTER_COUNTER(volume_write_error_count, "Total Volume write error count");
        REGISTER_COUNTER(volume_write_error_count, "Total Volume write error count");

        REGISTER_HISTOGRAM(volume_read_latency, "Volume overall read latency");
        REGISTER_HISTOGRAM(volume_write_latency, "Volume overall write latency");
        REGISTER_HISTOGRAM(volume_data_read_latency, "Volume data blocks read latency");
        REGISTER_HISTOGRAM(volume_data_write_latency, "Volume data blocks write latency");
        REGISTER_HISTOGRAM(volume_map_read_latency, "Volume mapping read latency");
        REGISTER_HISTOGRAM(volume_map_write_latency, "Volume mapping write latency");
        REGISTER_HISTOGRAM(volume_blkalloc_latency, "Volume block allocation latency");
        REGISTER_HISTOGRAM(volume_pieces_per_write, "Number of individual pieces per write",
                           sisl::HistogramBucketsType(LinearUpto64Buckets));

        register_me_to_farm();
    }
};

class Volume : public std::enable_shared_from_this< Volume > {
private:
    static homestore::BlkStore< homestore::VdevVarSizeBlkAllocatorPolicy >* m_data_blkstore;

    mapping*                          m_map;
    boost::intrusive_ptr< BlkBuffer > m_only_in_mem_buff;
    vol_sb*                           m_sb;
    vol_state                         m_state;
    io_comp_callback                  m_comp_cb;
    VolumeMetrics                     m_metrics;

private:
    Volume(const vol_params& params);
    Volume(vol_sb* sb);

    void alloc_single_block_in_mem();
    void vol_scan_alloc_blks();
    void check_and_complete_io(boost::intrusive_ptr< vol_interface_req >& req, bool call_completion = true);

public:
    template< typename... Args >
    static std::shared_ptr< Volume > make_volume(Args&&... args) {
        return std::shared_ptr< Volume >(new Volume(std::forward< Args >(args)...));
    }

    static void process_vol_data_completions(boost::intrusive_ptr< blkstore_req< BlkBuffer > > bs_req);

    ~Volume() { free(m_sb); };
    std::error_condition destroy();

    std::error_condition write(uint64_t lba, uint8_t* buf, uint32_t nblks,
                               boost::intrusive_ptr< vol_interface_req > req);

    std::error_condition read(uint64_t lba, int nblks, boost::intrusive_ptr< vol_interface_req > req, bool sync);

    void process_metadata_completions(boost::intrusive_ptr< volume_req > req);
    void process_data_completions(boost::intrusive_ptr< blkstore_req< BlkBuffer > > bs_req);

    uint64_t get_elapsed_time(Clock::time_point startTime);
    void attach_completion_cb(io_comp_callback& cb);

    void print_tree();
    vol_sb* get_sb() { return m_sb; };

    const char* get_name() const { return (m_sb->vol_name); }
    uint64_t get_page_size() const { return m_sb->page_size; }
    uint64_t get_size() const { return m_sb->size; }

#ifndef NDEBUG
    void enable_split_merge_crash_simulation();
#endif
};
} // namespace homestore
