#pragma once

#include <fcntl.h>
#include "engine/device/device.h"
#include "engine/cache/cache.h"
#include "engine/blkstore/writeBack_cache.hpp"
#include "engine/device/blkbuffer.hpp"
#include "engine/blkstore/blkstore.hpp"
#include "homeblks/home_blks.hpp"
#include <metrics/metrics.hpp>
#include <utility/atomic_counter.hpp>
#include <utility/obj_life_counter.hpp>
#include <memory>
#include <fds/obj_allocator.hpp>
#include <sds_logging/logging.h>
#include <spdlog/fmt/fmt.h>
#include "engine/common/homestore_assert.hpp"
#include "engine/homeds/thread/threadpool/thread_pool.h"
#include "blk_read_tracker.hpp"
#include "snapshot.hpp"
#include "indx_mgr.hpp"
#include <utility/enum.hpp>

using namespace std;

namespace homestore {

#define MAX_NUM_LBA ((1 << NBLKS_BITS) - 1)
#define INVALID_SEQ_ID UINT64_MAX
class mapping;
class VolumeJournal;
enum vol_state;

struct volume_req;
struct volume_child_req;
class IndxCP;
typedef boost::intrusive_ptr< volume_req > volume_req_ptr;
typedef boost::intrusive_ptr< volume_child_req > volume_child_req_ptr;

/* first 48 bits are actual sequence ID and last 16 bits are boot cnt */
#define SEQ_ID_BIT_CNT 48ul
#define BOOT_CNT_MASK 0x0000fffffffffffful
#define GET_IO_SEQ_ID(sid) ((m_hb->get_boot_cnt() << SEQ_ID_BIT_CNT) | (sid & BOOT_CNT_MASK))

#define VOL_INFO_LOG(volname, msg, ...) HS_SUBMOD_LOG(INFO, base, , "vol", volname, msg, ##__VA_ARGS__)
#define VOL_ERROR_LOG(volname, msg, ...) HS_SUBMOD_LOG(ERROR, base, , "vol", volname, msg, ##__VA_ARGS__)
#define THIS_VOL_LOG(level, mod, req, msg, ...)                                                                        \
    HS_SUBMOD_LOG(level, mod, req, "vol", this->m_vol_uuid, msg, ##__VA_ARGS__)
#define VOL_ASSERT(assert_type, cond, req, ...)                                                                        \
    HS_SUBMOD_ASSERT(assert_type, cond, req, "vol", this->m_vol_uuid, ##__VA_ARGS__)
#define VOL_ASSERT_CMP(assert_type, val1, cmp, val2, req, ...)                                                         \
    HS_SUBMOD_ASSERT_CMP(assert_type, val1, cmp, val2, req, "vol", this->m_vol_uuid, ##__VA_ARGS__)

#define VOL_DEBUG_ASSERT(...) VOL_ASSERT(DEBUG, __VA_ARGS__)
#define VOL_RELEASE_ASSERT(...) VOL_ASSERT(RELEASE, __VA_ARGS__)
#define VOL_LOG_ASSERT(...) VOL_ASSERT(LOGMSG, __VA_ARGS__)

#define VOL_DEBUG_ASSERT_CMP(...) VOL_ASSERT_CMP(DEBUG, ##__VA_ARGS__)
#define VOL_RELEASE_ASSERT_CMP(...) VOL_ASSERT_CMP(RELEASE, ##__VA_ARGS__)
#define VOL_LOG_ASSERT_CMP(...) VOL_ASSERT_CMP(LOGMSG, ##__VA_ARGS__)

struct volume_child_req : public blkstore_req< BlkBuffer > {
    uint64_t lba;
    int nblks;
    bool is_read = false;
    std::vector< Free_Blk_Entry > blkIds_to_free;
    uint64_t reqId;
    Clock::time_point op_start_time;
    uint16_t checksum[MAX_NUM_LBA];
    uint64_t read_buf_offset;
    uint64_t read_size;
    bool sync = false;

    /* number of times mapping table need to be updated for this req. It can
     * break the ios update in mapping btree depending on the key range.
     */
    std::atomic< int > num_mapping_update = 0;
    volume_req* parent_req = nullptr;
    BlkId blkId; // used only for debugging purpose

#ifndef NDEBUG
    boost::uuids::uuid vol_uuid;
#endif

public:
    static boost::intrusive_ptr< volume_child_req > make_request() {
        return boost::intrusive_ptr< volume_child_req >(sisl::ObjectAllocator< volume_child_req >::make_object());
    }

    virtual void free_yourself() override { sisl::ObjectAllocator< volume_child_req >::deallocate(this); }

    /* any derived class should have the virtual destructor to prevent
     * memory leak because pointer can be free with the base class.
     */
    virtual ~volume_child_req() = default;

    // virtual size_t get_your_size() const override { return
    // sizeof(volume_child_req); }

    static volume_child_req_ptr cast(const boost::intrusive_ptr< blkstore_req< BlkBuffer > >& bs_req) {
        return boost::static_pointer_cast< volume_child_req >(bs_req);
    }

    friend class Volume;

    std::string to_string() {
        std::stringstream ss;
        ss << ((is_read) ? "READ" : "WRITE") << ": lba=" << lba << " nblks=" << nblks;
        return ss.str();
    }

protected:
    friend class sisl::ObjectAllocator< volume_child_req >;

    // Volume req should always be created from Volume::create_vol_req()
    volume_child_req() = default;
};

#define CHECKSUM_SIZE 2

struct Free_Blk_Entry {
    BlkId m_blkId;
    uint8_t m_blk_offset : NBLKS_BITS;
    uint8_t m_nblks_to_free : NBLKS_BITS;

    Free_Blk_Entry(){};
    Free_Blk_Entry(const BlkId& m_blkId, uint8_t m_blk_offset, uint8_t m_nblks_to_free) :
            m_blkId(m_blkId),
            m_blk_offset(m_blk_offset),
            m_nblks_to_free(m_nblks_to_free) {}

    BlkId blk_id() const { return m_blkId; }
    uint8_t blk_offset() const { return m_blk_offset; }
    uint8_t blks_to_free() const { return m_nblks_to_free; }
};

class VolumeMetrics : public sisl::MetricsGroupWrapper {
public:
    explicit VolumeMetrics(const char* vol_uuid) : sisl::MetricsGroupWrapper("Volume", vol_uuid) {
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
        REGISTER_HISTOGRAM(volume_pieces_per_read, "Number of individual pieces per write",
                           HistogramBucketsType(LinearUpto64Buckets));
        REGISTER_HISTOGRAM(volume_write_size_distribution, "Distribution of volume write sizes",
                           HistogramBucketsType(ExponentialOfTwoBuckets));
        REGISTER_HISTOGRAM(volume_read_size_distribution, "Distribution of volume read sizes",
                           HistogramBucketsType(ExponentialOfTwoBuckets));
        register_me_to_farm();
    }
};

class Volume : public std::enable_shared_from_this< Volume > {
private:
    boost::intrusive_ptr< BlkBuffer > m_only_in_mem_buff;
    std::unique_ptr< vol_mem_sb > m_sb;
    std::atomic< vol_state > m_state;
    void alloc_single_block_in_mem();
    io_comp_callback m_comp_cb;
    std::atomic< uint64_t > seq_Id;
    VolumeMetrics m_metrics;
    std::mutex m_sb_lock; // lock for updating vol's sb
    std::atomic< uint64_t > m_used_size = 0;
    bool m_recovery_error = false;
    std::atomic< uint64_t > m_err_cnt = 0;
    std::string m_vol_name;
    std::string m_vol_uuid;
    std::atomic< uint64_t > m_req_id = 0;

    std::atomic< uint64_t > m_snap_id = 0;       // Next snapshot Id for this vol. Always grows
                                                 // TODO: Goes into vol sb.
    std::map< uint64_t, SnapshotPtr > m_snapmap; // Id to Snapshot.

    // Map of blks for which read is requested, to prevent parallel writes to free those blks
    // it also stores corresponding eviction record created by any parallel writes
    std::unique_ptr< Blk_Read_Tracker > m_read_blk_tracker;
    static homestore::BlkStore< homestore::VdevVarSizeBlkAllocatorPolicy >* m_data_blkstore;
    IndxMgr* m_indx_mgr;

    HomeBlksSafePtr m_hb; // Hold onto the homeblks to maintain reference

    // Per thread buffer which holds the completed reqs which will be batched before making batch callback
    sisl::ActiveOnlyThreadBuffer< std::vector< vol_interface_req_ptr > > m_completed_reqs;

private:
    Volume(const vol_params& params);
    Volume(vol_mem_sb* sb);
    void check_and_complete_req(volume_req* vreq, const std::error_condition& err);

    volume_child_req_ptr create_vol_child_req(BlkId& bid, volume_req* vreq, uint32_t start_lba, int nblks);

    template < typename... Args >
    void assert_formatter(fmt::memory_buffer& buf, const char* msg, const std::string& req_str, const Args&... args) {
        fmt::format_to(buf, "\n[vol={}]", m_vol_uuid);
        if (req_str.size()) { fmt::format_to(buf, "\n[request={}]", req_str); }
        fmt::format_to(buf, "\nMetrics = {}\n", sisl::MetricsFarm::getInstance().get_result_in_json_string());
    }

    template < typename... Args >
    void cmp_assert_formatter(fmt::memory_buffer& buf, const char* msg, const std::string& req_str,
                              const Args&... args) {
        sds_logging::default_cmp_assert_formatter(buf, msg, args...);
        assert_formatter(buf, msg, req_str, args...);
    }

    void vol_scan_alloc_blks();
    void blk_recovery_process_completions(bool success);
    void alloc_blk_callback(struct BlkId bid, size_t offset_size, size_t size);
    void blk_recovery_callback(MappingValue& mv);
    // async call to start the multi-threaded work.
    void get_allocated_blks();
    void process_indx_completions(volume_req* vreq);
    void process_data_completions(const boost::intrusive_ptr< blkstore_req< BlkBuffer > >& bs_req);

    // callback from mapping layer for free leaf node(data blks) so that volume
    // layer could do blk free.
    void process_free_blk_callback(Free_Blk_Entry fbe);

    void pending_read_blk_cb(volume_req* vreq, BlkId& bid);
    std::error_condition alloc_blk(volume_req* vreq, std::vector< BlkId >& bid);
    void verify_csum(volume_req* vreq);
    std::error_condition read_indx(volume_req* vreq, std::vector< std::pair< MappingKey, MappingValue > >& kvs);

    void interface_req_done(const vol_interface_req_ptr& vreq);

public:
    template < typename... Args >
    static std::shared_ptr< Volume > make_volume(Args&&... args) {
        return std::shared_ptr< Volume >(new Volume(std::forward< Args >(args)...));
    }

    std::shared_ptr< Snapshot > make_snapshot() {
        auto sp = std::shared_ptr< Snapshot >(new Snapshot(this, m_snap_id, seq_Id));
        m_snapmap[m_snap_id++] = sp;
        return sp;
    }

    void recovery_start();

    static void process_vol_data_completions(const boost::intrusive_ptr< blkstore_req< BlkBuffer > >& bs_req);
    static vol_interface_req_ptr create_volume_req(std::shared_ptr< Volume >& vol, void* buf, uint64_t lba,
                                                   uint32_t nblks, bool read, bool sync, uint32_t private_data_size);

#ifdef _PRERELEASE
    static void set_io_flip();
    static void set_error_flip();
#endif

    uint64_t inc_and_get_seq_id() {
        uint64_t id = seq_Id.fetch_add(1);
        return id;
    }
    ~Volume();
    void shutdown();

    void destroy();
    std::error_condition write(const vol_interface_req_ptr& hb_req);
    std::error_condition read(const vol_interface_req_ptr& hb_req);

    /* Note: We should not take m_vol_lock in homeblks after taking this lock.
     * Otherwise it will lead to deadlock. We should take this lock whenever in
     * memory sb is modified.
     */
    struct vol_mem_sb* get_sb() {
        return m_sb.get();
    };

    uint64_t get_elapsed_time(Clock::time_point startTime);
    void attach_completion_cb(const io_comp_callback& cb);
    void print_tree();
    bool verify_tree();
    void print_node(uint64_t blkid);
    void blk_recovery_callback(const MappingValue& mv);
    void set_recovery_error();
    mapping* get_mapping_handle();

    uint64_t get_last_lba() {
        assert(m_sb->ondisk_sb->size != 0);
        // lba starts from 0, then 1, 2, ...
        return (get_size() / get_page_size()) - 1;
    }

    /**
     * @brief : fix mapping btree
     *
     * @return : true for successfully fixed.
     *           false for fail to fix
     */
    bool fix_mapping_btree(bool verify);

    uint64_t get_data_used_size() { return m_used_size; }
    uint64_t get_index_used_size();
    const char* get_name() const { return (m_sb->ondisk_sb->vol_name); }
    uint64_t get_page_size() const { return m_sb->ondisk_sb->page_size; }
    uint64_t get_size() const { return m_sb->ondisk_sb->size; }
    boost::uuids::uuid get_uuid() { return m_sb->ondisk_sb->uuid; }
    vol_state get_state() const { return m_state.load(std::memory_order_acquire); }
    void set_state(vol_state state, bool persist = true);
    bool is_offline();

    void volume_req_done(volume_req* vreq);
    size_t call_batch_completion_cbs();
#ifndef NDEBUG
    void verify_pending_blks();
#endif

    std::string to_string() {
        std::stringstream ss;
        ss << "Name :" << get_name() << ", UUID :" << get_uuid() << ", Size:" << get_size()
           << ((is_offline()) ? ", Offline" : ", Not Offline") << ", State :" << get_state();
        return ss.str();
    }
};

/* Note :- Any member inside this structure is not lock protected. Its caller responsibility to call it under lock
 * or make sure it is single threaded.
 */
struct volume_req {
    vol_interface_req_ptr iface_req; // Corresponding Interface API request which has all the details about requests
    boost::intrusive_ptr< homeds::MemVector > mvec; // data
    sisl::atomic_counter< int > outstanding_io_cnt; // how many IOs are outstanding for this request

    indx_cp_id* cp_id = nullptr; // checkpoint ID of this request is part of
    vol_journal_entry j_ent;

    bool index_updated = false;                     // if index is already updated
    Clock::time_point io_start_time = Clock::now(); // start time
    Clock::time_point indx_start_time;
    int vc_req_cnt = 0; // how many child requests are issued.
    uint64_t lastCommited_seqId = INVALID_SEQ_ID;
    uint64_t seqId = INVALID_SEQ_ID;
    uint64_t request_id; // Copy of the id from interface request

    /* Below entries are used for journal or to store checksum */
    std::vector< uint16_t > csum_list;
    std::vector< BlkId > alloc_blkid_list;
    std::vector< Free_Blk_Entry > fbe_list;

    volume_req(const vol_interface_req_ptr& vi_req) :
            iface_req(vi_req), // We explicitly create cyclic dependency to maintain lifecycle correctly
            mvec(new homeds::MemVector()),
            outstanding_io_cnt(1) {
        request_id = iface_req->request_id;

        assert((iface_req->vol_instance->get_page_size() * iface_req->nblks) <= VOL_MAX_IO_SIZE);
        if (!iface_req->is_read) {
            mvec->set((uint8_t*)iface_req->write_buf, iface_req->vol_instance->get_page_size() * iface_req->nblks, 0);
        }

        /* Trying to reserve the max possible size so that memory allocation is efficient */
        csum_list.reserve(VOL_MAX_IO_SIZE / iface_req->vol_instance->get_page_size());
        fbe_list.reserve(VOL_MAX_IO_SIZE / iface_req->vol_instance->get_page_size());
        alloc_blkid_list.reserve(VOL_MAX_IO_SIZE / iface_req->vol_instance->get_page_size());
        seqId = iface_req->vol_instance->inc_and_get_seq_id();
    }

    virtual ~volume_req() = default;

    void push_blkid(BlkId& bid) { alloc_blkid_list.push_back(bid); }

    /* It push to the existing check sum list */
    void push_csum(uint16_t csum) { csum_list.push_back(csum); }

    /* push fbe to the existing list */
    void push_fbe(Free_Blk_Entry& fbe) { fbe_list.push_back(fbe); }

    sisl::blob create_journal_entry() {
        auto blob = j_ent.create_journal_entry(this);
        return blob;
    }

    virtual std::string to_string() {
        std::stringstream ss;
        ss << "vol_interface_req: request_id=" << iface_req->request_id << " dir=" << (is_read_op() ? "R" : "W")
           << " outstanding_io_cnt=" << outstanding_io_cnt.get();
        return ss.str();
    }

    Volume* vol() { return iface_req->vol_instance.get(); }
    bool is_read_op() const { return iface_req->is_read; }
    uint64_t lba() const { return iface_req->lba; }
    uint32_t nblks() const { return iface_req->nblks; }
    bool is_sync() const { return iface_req->sync; }
    std::error_condition& err() const { return iface_req->err; }
};

#define NUM_BLKS_PER_THREAD_TO_QUERY 10000ull
} // namespace homestore
