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
#include <utility/obj_life_counter.hpp>
#include <memory>
#include "homeds/memory/obj_allocator.hpp"

#include "threadpool/thread_pool.h"
using namespace std;

namespace homestore {

#define MAX_NUM_LBA ((1 << NBLKS_BITS) - 1)
#define INVALID_SEQ_ID UINT64_MAX
class mapping;
enum vol_state;

struct Free_Blk_Entry {
    BlkId   m_blkId;
    uint8_t m_blk_offset : NBLKS_BITS;
    uint8_t m_nblks_to_free : NBLKS_BITS;

    Free_Blk_Entry(const BlkId& m_blkId, uint8_t m_blk_offset, uint8_t m_nblks_to_free) :
            m_blkId(m_blkId),
            m_blk_offset(m_blk_offset),
            m_nblks_to_free(m_nblks_to_free) {}
};

struct volume_req;
typedef boost::intrusive_ptr< volume_req > volume_req_ptr;

/* first 48 bits are actual sequence ID and last 16 bits are boot cnt */
#define SEQ_ID_BIT_CNT 48ul
#define BOOT_CNT_MASK 0x0000fffffffffffful
#define GET_IO_SEQ_ID(sid) ((HomeBlks::instance()->get_boot_cnt() << SEQ_ID_BIT_CNT) | (sid & BOOT_CNT_MASK))

struct volume_req : public blkstore_req< BlkBuffer > {
    uint64_t                      lba;
    int                           nlbas;
    bool                          is_read;
    std::shared_ptr< Volume >     vol_instance;
    std::vector< Free_Blk_Entry > blkIds_to_free;
    uint64_t                      seqId;
    uint64_t                      lastCommited_seqId;
    Clock::time_point             op_start_time;
    uint16_t                      checksum[MAX_NUM_LBA];
    uint64_t                      read_buf_offset;

    /* number of times mapping table need to be updated for this req. It can
     * break the ios update in mapping btree depending on the key range.
     */
    std::atomic< int >                        num_mapping_update;
    boost::intrusive_ptr< vol_interface_req > parent_req;

#ifndef NDEBUG
    bool               done;
    boost::uuids::uuid vol_uuid;
#endif

public:
    static boost::intrusive_ptr< volume_req > make_request() {
        return boost::intrusive_ptr< volume_req >(homeds::ObjectAllocator< volume_req >::make_object());
    }

    virtual void free_yourself() override { homeds::ObjectAllocator< volume_req >::deallocate(this); }

    /* any derived class should have the virtual destructor to prevent
     * memory leak because pointer can be free with the base class.
     */
    virtual ~volume_req() = default;

    // virtual size_t get_your_size() const override { return sizeof(volume_req); }

    static volume_req_ptr cast(const boost::intrusive_ptr< blkstore_req< BlkBuffer > >& bs_req) {
        return boost::static_pointer_cast< volume_req >(bs_req);
    }

    friend class Volume;

protected:
    friend class homeds::ObjectAllocator< volume_req >;

    // Volume req should always be created from Volume::create_vol_req()
    volume_req() : is_read(false), num_mapping_update(0), parent_req(nullptr) {
#ifndef NDEBUG
        done = false;
#endif
    }
};

class VolumeMetrics : public sisl::MetricsGroupWrapper {
public:
    explicit VolumeMetrics(const char* vol_name) : sisl::MetricsGroupWrapper("Volume", vol_name) {
        REGISTER_COUNTER(volume_read_count, "Total Volume read operations", "volume_op_count", {"op", "read"});
        REGISTER_COUNTER(volume_write_count, "Total Volume write operations", "volume_op_count", {"op", "write"});
        REGISTER_COUNTER(volume_read_error_count, "Total Volume read error count", "volume_error_count", {"op", "read"});
        REGISTER_COUNTER(volume_write_error_count, "Total Volume write error count", "volume_error_count", {"op", "write"});
        REGISTER_COUNTER(volume_write_size_total, "Total Volume data size written", "volume_data_size", {"op", "write"});
        REGISTER_COUNTER(volume_read_size_total, "Total Volume data size read", "volume_data_size", {"op", "read"});

        REGISTER_HISTOGRAM(volume_read_latency, "Volume overall read latency", "volume_op_latency", {"op", "read"});
        REGISTER_HISTOGRAM(volume_write_latency, "Volume overall write latency", "volume_op_latency", {"op", "write"});
        REGISTER_HISTOGRAM(volume_data_read_latency, "Volume data blocks read latency",
                "volume_data_op_latency", {"op", "read"});
        REGISTER_HISTOGRAM(volume_data_write_latency, "Volume data blocks write latency",
                "volume_data_op_latency", {"op", "write"});
        REGISTER_HISTOGRAM(volume_map_read_latency, "Volume mapping read latency",
                           "volume_map_op_latency", {"op", "read"});
        REGISTER_HISTOGRAM(volume_map_write_latency, "Volume mapping write latency",
                           "volume_map_op_latency", {"op", "write"});
        REGISTER_HISTOGRAM(volume_blkalloc_latency, "Volume block allocation latency");
        REGISTER_HISTOGRAM(volume_pieces_per_write, "Number of individual pieces per write",
                           HistogramBucketsType(LinearUpto64Buckets));
        REGISTER_HISTOGRAM(volume_write_size_distribution, "Distribution of volume write sizes",
                           HistogramBucketsType(ExponentialOfTwoBuckets));
        REGISTER_HISTOGRAM(volume_read_size_distribution, "Distribution of volume read sizes",
                           HistogramBucketsType(LinearUpto64Buckets));

        register_me_to_farm();
    }
};

class Volume : public std::enable_shared_from_this< Volume > {
private:
    mapping*                          m_map;
    boost::intrusive_ptr< BlkBuffer > m_only_in_mem_buff;
    struct vol_sb*                    m_sb;
    enum vol_state                    m_state;
    void                              alloc_single_block_in_mem();
    void                              vol_scan_alloc_blks();
    io_comp_callback                  m_comp_cb;
    std::atomic< uint64_t >           seq_Id;
    VolumeMetrics                     m_metrics;

private:
    Volume(const vol_params& params);
    Volume(vol_sb* sb);
    void check_and_complete_req(const vol_interface_req_ptr& hb_req, const std::error_condition& err,
                                bool call_completion_cb);

public:
    template < typename... Args >
    static std::shared_ptr< Volume > make_volume(Args&&... args) {
        return std::shared_ptr< Volume >(new Volume(std::forward< Args >(args)...));
    }

    static homestore::BlkStore< homestore::VdevVarSizeBlkAllocatorPolicy >* m_data_blkstore;
    static void           process_vol_data_completions(const boost::intrusive_ptr< blkstore_req< BlkBuffer > >& bs_req);
    static volume_req_ptr create_vol_req(Volume* vol, const vol_interface_req_ptr& hb_req);

    ~Volume() { free(m_sb); };

    std::error_condition destroy();
    std::error_condition write(uint64_t lba, uint8_t* buf, uint32_t nblks, const vol_interface_req_ptr& hb_req);
    std::error_condition read(uint64_t lba, int nblks, const vol_interface_req_ptr& hb_req, bool sync);

    struct vol_sb *get_sb() {return m_sb;};
    
    void blk_recovery_process_completions(bool success);
    void alloc_blk_callback(struct BlkId bid, size_t offset_size, size_t size);
    void blk_recovery_callback(MappingValue& mv);
    // async call to start the multi-threaded work.
    void get_allocated_blks();
    void process_metadata_completions(const volume_req_ptr& wb_req);
    void process_data_completions(const boost::intrusive_ptr< blkstore_req< BlkBuffer > >& bs_req);
    void recovery_start();

    uint64_t get_elapsed_time(Clock::time_point startTime);
    void     attach_completion_cb(const io_comp_callback& cb);
    void     print_tree();
    void     blk_recovery_callback(const MappingValue& mv);

    mapping* get_mapping_handle() { return m_map; }

    uint64_t get_last_lba() {
        assert(m_sb->size != 0);
        // lba starts from 0, then 1, 2, ... 
        return (get_size() / get_page_size()) - 1;
    }


    const char* get_name() const { return (m_sb->vol_name); }
    uint64_t    get_page_size() const { return m_sb->page_size; }
    uint64_t    get_size() const { return m_sb->size; }
};

#define NUM_BLKS_PER_THREAD_TO_QUERY        10000ull
}
