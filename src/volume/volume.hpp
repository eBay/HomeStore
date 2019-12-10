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
#include <sds_logging/logging.h>
#include <spdlog/fmt/fmt.h>
#include "main/homestore_assert.hpp"
#include "threadpool/thread_pool.h"
#include "blk_read_tracker.hpp"

using namespace std;

namespace homestore {

#define MAX_NUM_LBA ((1 << NBLKS_BITS) - 1)
#define INVALID_SEQ_ID UINT64_MAX
class mapping;
enum vol_state;

struct volume_req;
typedef boost::intrusive_ptr< volume_req > volume_req_ptr;

/* first 48 bits are actual sequence ID and last 16 bits are boot cnt */
#define SEQ_ID_BIT_CNT 48ul
#define BOOT_CNT_MASK 0x0000fffffffffffful
#define GET_IO_SEQ_ID(sid) ((HomeBlks::instance()->get_boot_cnt() << SEQ_ID_BIT_CNT) | (sid & BOOT_CNT_MASK))

#define _VOL_REQ_LOG_FORMAT "[req_id={}]: "
#define _VOL_REQ_LOG_MSG(req) req->request_id
#define _VOL_REQ_LOG_VERBOSE_FORMAT "[request={}]"
#define _VOL_REQ_LOG_VERBOSE_MSG(req) req->to_string()
#define _VOLMSG_EXPAND(...) __VA_ARGS__

#define VOL_LOG(level, mod, req, msg, ...) HS_SUBMOD_LOG(level, mod, req, "vol", this->m_vol_name, msg, ##__VA_ARGS__)
#define VOL_ASSERT(assert_type, cond, req, ...)                                                                        \
    HS_SUBMOD_ASSERT(assert_type, cond, req, "vol", this->m_vol_name, ##__VA_ARGS__)
#define VOL_ASSERT_CMP(assert_type, val1, cmp, val2, req, ...)                                                         \
    HS_SUBMOD_ASSERT_CMP(assert_type, val1, cmp, val2, req, "vol", this->m_vol_name, ##__VA_ARGS__)

#define VOL_DEBUG_ASSERT(...) VOL_ASSERT(DEBUG, __VA_ARGS__)
#define VOL_RELEASE_ASSERT(...) VOL_ASSERT(RELEASE, __VA_ARGS__)
#define VOL_LOG_ASSERT(...) VOL_ASSERT(LOGMSG, __VA_ARGS__)

#define VOL_DEBUG_ASSERT_CMP(...) VOL_ASSERT_CMP(DEBUG, ##__VA_ARGS__)
#define VOL_RELEASE_ASSERT_CMP(...) VOL_ASSERT_CMP(RELEASE, ##__VA_ARGS__)
#define VOL_LOG_ASSERT_CMP(...) VOL_ASSERT_CMP(LOGMSG, ##__VA_ARGS__)

struct volume_req : public blkstore_req< BlkBuffer > {
    uint64_t                      lba;
    int                           nlbas;
    bool                          is_read;
    std::shared_ptr< Volume >     vol_instance;
    std::vector< Free_Blk_Entry > blkIds_to_free;
    uint64_t                      seqId;
    uint64_t                      reqId;
    uint64_t                      lastCommited_seqId;
    Clock::time_point             op_start_time;
    uint16_t                      checksum[MAX_NUM_LBA];
    uint64_t                      read_buf_offset;
    uint64_t                      read_size;

    /* number of times mapping table need to be updated for this req. It can
     * break the ios update in mapping btree depending on the key range.
     */
    std::atomic< int >                        num_mapping_update;
    boost::intrusive_ptr< vol_interface_req > parent_req;
    BlkId                                     blkId; // used only for debugging purpose

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

    // virtual size_t get_your_size() const override { return
    // sizeof(volume_req); }

    static volume_req_ptr cast(const boost::intrusive_ptr< blkstore_req< BlkBuffer > >& bs_req) {
        return boost::static_pointer_cast< volume_req >(bs_req);
    }

    friend class Volume;

    std::string to_string() {
        std::stringstream ss;
        ss << ((is_read) ? "READ" : "WRITE") << ": lba=" << lba << " nlbas=" << nlbas << " seqId=" << seqId
           << " num_mapping_update=" << num_mapping_update;
        return ss.str();
    }

protected:
    friend class homeds::ObjectAllocator< volume_req >;

    // Volume req should always be created from Volume::create_vol_req()
    volume_req() : is_read(false), blkIds_to_free(0), num_mapping_update(0), parent_req(nullptr) {
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
        REGISTER_COUNTER(volume_outstanding_data_read_count, "Total Volume data outstanding read cnt",
                         sisl::_publish_as::publish_as_gauge);
        REGISTER_COUNTER(volume_outstanding_data_write_count, "Total Volume data outstanding write cnt",
                         sisl::_publish_as::publish_as_gauge);
        REGISTER_COUNTER(volume_outstanding_metadata_read_count, "Total Volume meta data outstanding read cnt",
                         sisl::_publish_as::publish_as_gauge);
        REGISTER_COUNTER(volume_outstanding_metadata_write_count, "Total Volume meta data outstanding write cnt",
                         sisl::_publish_as::publish_as_gauge);
        REGISTER_COUNTER(volume_read_error_count, "Total Volume read error count", "volume_error_count",
                         {"op", "read"});
        REGISTER_COUNTER(volume_write_error_count, "Total Volume write error count", "volume_error_count",
                         {"op", "write"});
        REGISTER_COUNTER(volume_write_size_total, "Total Volume data size written", "volume_data_size",
                         {"op", "write"});
        REGISTER_COUNTER(volume_read_size_total, "Total Volume data size read", "volume_data_size", {"op", "read"});

        REGISTER_HISTOGRAM(volume_read_latency, "Volume overall read latency", "volume_op_latency", {"op", "read"});
        REGISTER_HISTOGRAM(volume_write_latency, "Volume overall write latency", "volume_op_latency", {"op", "write"});
        REGISTER_HISTOGRAM(volume_data_read_latency, "Volume data blocks read latency", "volume_data_op_latency",
                           {"op", "read"});
        REGISTER_HISTOGRAM(volume_data_write_latency, "Volume data blocks write latency", "volume_data_op_latency",
                           {"op", "write"});
        REGISTER_HISTOGRAM(volume_map_read_latency, "Volume mapping read latency", "volume_map_op_latency",
                           {"op", "read"});
        REGISTER_HISTOGRAM(volume_map_write_latency, "Volume mapping write latency", "volume_map_op_latency",
                           {"op", "write"});
        REGISTER_HISTOGRAM(volume_blkalloc_latency, "Volume block allocation latency (in ns)");
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
    struct vol_mem_sb*                m_sb;
    enum vol_state                    m_state;
    void                              alloc_single_block_in_mem();
    io_comp_callback                  m_comp_cb;
    std::atomic< uint64_t >           seq_Id;
    VolumeMetrics                     m_metrics;
    std::mutex                        m_sb_lock; // lock for updating vol's sb
    std::atomic< uint64_t >           m_used_size = 0;
    bool                              m_recovery_error = false;
    std::atomic< uint64_t >           m_err_cnt = 0;
    std::string                       m_vol_name;
#ifndef NDEBUG
    std::mutex                           m_req_mtx;
    std::map< uint64_t, volume_req_ptr > m_req_map;
#endif
    std::atomic< uint64_t > m_req_id = 0;
    // Map of blks for which read is requested, to prevent parallel writes to free those blks
    // it also stores corresponding eviction record created by any parallel writes
    std::unique_ptr< Blk_Read_Tracker > m_read_blk_tracker;

private:
    Volume(const vol_params& params);
    Volume(vol_mem_sb* sb);
    void check_and_complete_req(const vol_interface_req_ptr& hb_req, const std::error_condition& err,
                                bool call_completion_cb, std::vector< Free_Blk_Entry >* fbes = nullptr);

public:
    template < typename... Args >
    static std::shared_ptr< Volume > make_volume(Args&&... args) {
        return std::shared_ptr< Volume >(new Volume(std::forward< Args >(args)...));
    }

    static homestore::BlkStore< homestore::VdevVarSizeBlkAllocatorPolicy >* m_data_blkstore;
    static void           process_vol_data_completions(const boost::intrusive_ptr< blkstore_req< BlkBuffer > >& bs_req);
    static volume_req_ptr create_vol_req(Volume* vol, const vol_interface_req_ptr& hb_req);
#ifdef _PRERELEASE
    static void set_io_flip();
    static void set_error_flip();
#endif

    ~Volume();

    std::error_condition destroy();
    std::error_condition write(uint64_t lba, uint8_t* buf, uint32_t nblks, const vol_interface_req_ptr& hb_req);
    std::error_condition read(uint64_t lba, int nblks, const vol_interface_req_ptr& hb_req, bool sync);

    template < typename... Args >
    void cmp_assert_formatter(fmt::memory_buffer& buf, const char* msg, const std::string& req_str,
                              const Args&... args) {
        sds_logging::default_cmp_assert_formatter(buf, msg, args...);
        assert_formatter(buf, msg, req_str, args...);
    }

    template < typename... Args >
    void assert_formatter(fmt::memory_buffer& buf, const char* msg, const std::string& req_str, const Args&... args) {
        fmt::format_to(buf, "\n[vol={}]", m_vol_name);
        if (req_str.size()) {
            fmt::format_to(buf, "\n[request={}]", req_str);
        }
        fmt::format_to(buf, "\nMetrics = {}\n", sisl::MetricsFarm::getInstance().get_result_in_json_string());
    }

    /* Note: We should not take m_vol_lock in homeblks after taking this lock.
     * Otherwise it will lead to deadlock. We should take this lock whenever in
     * memory sb is modified.
     */
    struct vol_mem_sb* get_sb() {
        return m_sb;
    };

    void vol_scan_alloc_blks();
    void blk_recovery_process_completions(bool success);
    void alloc_blk_callback(struct BlkId bid, size_t offset_size, size_t size);
    void blk_recovery_callback(MappingValue& mv);
    // async call to start the multi-threaded work.
    void get_allocated_blks();
    void process_metadata_completions(const volume_req_ptr& wb_req);
    void process_data_completions(const boost::intrusive_ptr< blkstore_req< BlkBuffer > >& bs_req);
    void recovery_start();

    // callback from mapping layer for free leaf node(data blks) so that volume
    // layer could do blk free.
    void process_free_blk_callback(Free_Blk_Entry fbe);

    void pending_read_blk_cb(BlkId& bid);
    void get_free_blk_entries(std::vector< std::pair< MappingKey, MappingValue > >& kvs,
                              std::vector< Free_Blk_Entry >&                        fbes);
    bool remove_free_blk_entry(std::vector< Free_Blk_Entry >& fbes, std::pair< MappingKey, MappingValue >& kv);

    uint64_t get_elapsed_time(Clock::time_point startTime);
    void     attach_completion_cb(const io_comp_callback& cb);
    void     print_tree();
    void     verify_tree();
    void     print_node(uint64_t blkid);
    void     blk_recovery_callback(const MappingValue& mv);
    void     set_recovery_error();

    mapping* get_mapping_handle() { return m_map; }

    uint64_t get_last_lba() {
        assert(m_sb->ondisk_sb->size != 0);
        // lba starts from 0, then 1, 2, ...
        return (get_size() / get_page_size()) - 1;
    }

    uint64_t           get_data_used_size() { return m_used_size; }
    uint64_t           get_metadata_used_size();
    const char*        get_name() const { return (m_sb->ondisk_sb->vol_name); }
    uint64_t           get_page_size() const { return m_sb->ondisk_sb->page_size; }
    uint64_t           get_size() const { return m_sb->ondisk_sb->size; }
    boost::uuids::uuid get_uuid();
    vol_state          get_state();
    void               set_state(vol_state state, bool persist = true);
    bool               is_offline();

#ifndef NDEBUG
    void verify_pending_blks();
#endif
};

#define NUM_BLKS_PER_THREAD_TO_QUERY 10000ull
} // namespace homestore
