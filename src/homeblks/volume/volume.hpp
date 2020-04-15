#pragma once

#include <fcntl.h>
#include "engine/device/device.h"
#include "engine/cache/cache_common.hpp"
#include "engine/cache/cache.h"
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
    HS_SUBMOD_LOG(level, mod, req, "vol", boost::lexical_cast< std::string >(this->get_uuid()), msg, ##__VA_ARGS__)
#define VOL_ASSERT(assert_type, cond, req, ...)                                                                        \
    HS_SUBMOD_ASSERT(assert_type, cond, req, "vol", boost::lexical_cast< std::string >(this->get_uuid()), ##__VA_ARGS__)
#define VOL_ASSERT_CMP(assert_type, val1, cmp, val2, req, ...)                                                         \
   HS_SUBMOD_ASSERT_CMP(assert_type, val1, cmp, val2, req, "vol", boost::lexical_cast< std::string >(this->get_uuid()),\
   ##__VA_ARGS__)

#define VOL_DEBUG_ASSERT(...) VOL_ASSERT(DEBUG, __VA_ARGS__)
#define VOL_RELEASE_ASSERT(...) VOL_ASSERT(RELEASE, __VA_ARGS__)
#define VOL_LOG_ASSERT(...) VOL_ASSERT(LOGMSG, __VA_ARGS__)

#define VOL_DEBUG_ASSERT_CMP(...) VOL_ASSERT_CMP(DEBUG, ##__VA_ARGS__)
#define VOL_RELEASE_ASSERT_CMP(...) VOL_ASSERT_CMP(RELEASE, ##__VA_ARGS__)
#define VOL_LOG_ASSERT_CMP(...) VOL_ASSERT_CMP(LOGMSG, ##__VA_ARGS__)

struct volume_child_req : public blkstore_req< BlkBuffer > {
    uint64_t lba;
    int nlbas;
    bool is_read;
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
    std::atomic< int > num_mapping_update;
    volume_req_ptr parent_req;
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
        ss << ((is_read) ? "READ" : "WRITE") << ": lba=" << lba << " nlbas=" << nlbas;
        return ss.str();
    }

protected:
    friend class sisl::ObjectAllocator< volume_child_req >;

    // Volume req should always be created from Volume::create_vol_req()
    volume_child_req() : is_read(false), blkIds_to_free(0), num_mapping_update(0), parent_req(nullptr) {}
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

#define VOL_SB_VERSION 0x2
struct vol_sb_hdr {
    /* Immutable members */
    const uint64_t version;
    const uint64_t page_size;
    const uint64_t size;
    const boost::uuids::uuid uuid;
    const char vol_name[VOL_NAME_SIZE];
    const indx_mgr_active_sb active_sb;
    vol_sb_hdr(uint64_t page_size, uint64_t size, char in_vol_name[VOL_NAME_SIZE], boost::uuids::uuid uuid, 
                indx_mgr_active_sb active_sb) :
        version(VOL_SB_VERSION), page_size(page_size), size(size),  uuid(uuid), vol_name(""), active_sb(active_sb) {
            /* XXX : is there a better way ? */
            char *ptr = (char *)vol_name;
            strncpy(ptr, in_vol_name, VOL_NAME_SIZE);
        };
    
    /* these variables are mutable. Always update these values before writing the superblock */
    vol_state state;
    /* add snapshot superblock */
};

class Volume : public std::enable_shared_from_this< Volume > {
private:
    vol_params m_params;
    VolumeMetrics m_metrics;
    HomeBlksSafePtr m_hb; // Hold onto the homeblks to maintain reference
    std::unique_ptr< Blk_Read_Tracker > m_read_blk_tracker;
    IndxMgr* m_indx_mgr;
    std::map< uint64_t, SnapshotPtr > m_snapmap; // Id to Snapshot.
    boost::intrusive_ptr< BlkBuffer > m_only_in_mem_buff;
    io_comp_callback m_comp_cb;
    
    std::atomic< vol_state > m_state;
    std::atomic< int64_t > seq_Id;
    std::atomic< uint64_t > m_err_cnt = 0;
    std::atomic< uint64_t > m_req_id = 0;
    std::atomic< uint64_t > m_snap_id = 0;       // Next snapshot Id for this vol. Always grows
    std::atomic< uint64_t > vol_ref_cnt = 0;  // volume can not be destroy/shutdown until it is not zero
    
    std::mutex m_sb_lock; // lock for updating vol's sb
    vol_sb_hdr *m_sb;
    indxmgr_stop_cb m_destroy_done_cb;

private:
    /* static members */
    /* home_blks can not be shutdown until it is not zero. It is the superset of vol_ref_cnt. If it is zero then 
     * volume_ref count has to zero. But it is not true other way round.
     */
    static std::atomic< uint64_t > home_blks_ref_cnt;

private:
    Volume(const vol_params& params);
    Volume(vol_sb_hdr &sb);
    void alloc_single_block_in_mem();
    void check_and_complete_req(volume_req_ptr& vreq, const std::error_condition& err);

    volume_child_req_ptr create_vol_child_req(BlkId& bid, const volume_req_ptr& vreq, uint32_t start_lba, int nlba);

    template < typename... Args >
    void assert_formatter(fmt::memory_buffer& buf, const char* msg, const std::string& req_str, const Args&... args) {
        fmt::format_to(buf, "\n[vol={}]", boost::lexical_cast< std::string >(get_uuid()));
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
    // async call to start the multi-threaded work.
    void get_allocated_blks();
    void process_indx_completions(volume_req_ptr& vreq, std::error_condition err);
    void process_data_completions(const boost::intrusive_ptr< blkstore_req< BlkBuffer > >& bs_req);

    // callback from mapping layer for free leaf node(data blks) so that volume
    // layer could do blk free.
    void process_free_blk_callback(Free_Blk_Entry fbe);

    void pending_read_blk_cb(volume_req_ptr vreq, BlkId& bid);
    std::error_condition alloc_blk(volume_req_ptr& vreq, std::vector< BlkId >& bid);
    void verify_csum(volume_req_ptr& vreq);
    std::error_condition read_indx(volume_req_ptr& vreq, std::vector< std::pair< MappingKey, MappingValue > >& kvs);
    void recovery_start();
    uint64_t get_elapsed_time(Clock::time_point startTime);
    mapping* get_mapping_handle();
    void set_recovery_error();
    uint64_t get_last_lba() {
        assert(get_size() != 0);
        // lba starts from 0, then 1, 2, ...
        return (get_size() / get_page_size()) - 1;
    }
    void write_sb();
    void remove_sb();
    void try_shutdown_destroy();
    void destroy_internal();

public:
    /******************** static functions exposed to home_blks *******************/
    template < typename... Args >
    static std::shared_ptr< Volume > make_volume(Args&&... args) {
        auto vol_ptr = (std::shared_ptr< Volume >(new Volume(std::forward< Args >(args)...)));
        vol_ptr->init();
        return vol_ptr;
    }
    static vol_interface_req_ptr create_volume_req(std::shared_ptr< Volume >& vol, void* buf, uint64_t lba,
                                                   uint32_t nlbas, bool read, bool sync);
#ifdef _PRERELEASE
    static void set_io_flip();
    static void set_error_flip();
#endif
    static bool can_all_vols_shutdown() {
        if (home_blks_ref_cnt.load() != 0) {
            return true;
        }
        return false;
    }
    
    /* Called during shutdown. */
    static void shutdown(indxmgr_stop_cb cb);
    static void process_vol_data_completions(const boost::intrusive_ptr< blkstore_req< BlkBuffer > >& bs_req);
    static void trigger_system_cp() { IndxMgr::trigger_system_cp(); };

public:
    /******************** APIs exposed to home_blks *******************/
    ~Volume();
    
    /* should be called after volume is created. It initialize indx mgr */
    void init();
    
    /* Write to lba
     * @param hb_req :- it expects this request to be created
     * @return :- no_error if there is no error. It doesn't throw any exception
     */
    std::error_condition write(const vol_interface_req_ptr& hb_req);
    
    /* Read from lba
     * @param hb_req :- it expects this request to be created
     * @return :- no_error if there is no error. It doesn't throw any exception
     */
    std::error_condition read(const vol_interface_req_ptr& hb_req);
    
    /* shutdown the volume. It assumes caller has ensure that there are no outstanding ios. */
    void shutdown();

    /* Called when volume is destroy. */
    void destroy(indxmgr_stop_cb cb);

    /* Attach completion callback which is used when data read/write is completed by volume.
     * @param io_comp_callback :- completion callback
     */
    void attach_completion_cb(const io_comp_callback& cb);

    /* Print active indx */
    void print_tree();

    /* verify active indx */
    bool verify_tree();

    /* Print the content of a blkid
     * @param blkid :- blkid of data to be read
     */
    void print_node(uint64_t blkid);

    /**
     * @brief : fix mapping btree
     *
     * @return : true for successfully fixed.
     *           false for fail to fix
     */
    bool fix_mapping_btree(bool verify);

    /* Get name of this volume. 
     * @return :- name
     */
    const char* get_name() const { return (m_sb->vol_name); }

    /* Get page size of this volume.
     * @return :- page size
     */
    uint64_t get_page_size() const { return m_sb->page_size; }

    /* Get size of this volume. 
     * @return :- size
     */
    uint64_t get_size() const { return m_sb->size; }

    /* Get uuid of this volume.
     * @return :- uuid
     */
    boost::uuids::uuid get_uuid() { return m_sb->uuid; }

    /* Get state of this volume.
     * @return :- state
     */
    vol_state get_state() const { return m_state.load(std::memory_order_acquire); }

    /* Set state of this volume.
     * @params state :- new state of the volume
     * @params persist :- It persist its state if it is true.
     * @return :- return previous state of the volume. 
     */
    vol_state set_state(vol_state state, bool persist = true);

    /* Check if volume is offline
     * @params :- return true if it is offline
     */
    bool is_offline();

    /* Update a new cp of this volume. 
     * @params vol_id :- current cp id of this volume
     * @params home_blks_id :- current cp id of home_blks
     */
    vol_cp_id_ptr attach_prepare_volume_cp_id(vol_cp_id_ptr vol_id, indx_cp_id* home_blks_id);

    /* get indx mgr
     * @return indx mgr
     */
    IndxMgr* get_indx_mgr() { return m_indx_mgr; }

#ifndef NDEBUG
    void verify_pending_blks();
#endif

    std::string to_string() {
        std::stringstream ss;
        ss << "Name :" << get_name() << ", UUID :" << boost::lexical_cast< std::string >(get_uuid()) << ", Size:" << get_size()
           << ((is_offline()) ? ", Offline" : ", Not Offline") << ", State :" << get_state();
        return ss.str();
    }
    std::shared_ptr< Snapshot > make_snapshot() {
        auto sp = std::shared_ptr< Snapshot >(new Snapshot(this, m_snap_id, seq_Id));
        m_snapmap[m_snap_id++] = sp;
        return sp;
    }
    uint64_t inc_and_get_seq_id() {
        uint64_t id = seq_Id.fetch_add(1);
        return id;
    }

    void truncate(vol_cp_id_ptr vol_id) { m_indx_mgr->truncate(vol_id); }
};

/* Note :- Any member inside this structure is not lock protected. Its caller responsibility to call it under lock
 * or make sure it is single threaded.
 */
struct volume_req : public vol_interface_req {

    /********** members used to write data blocks **********/
    Clock::time_point io_start_time;                // start time
    boost::intrusive_ptr< homeds::MemVector > mvec; // data
    sisl::atomic_counter< int > outstanding_io_cnt; // how many IOs are outstanding for this request
    int vc_req_cnt = 0; // how many child requests are issued.

    /********** members used by indx mgr **********/
    indx_cp_id* cp_id = nullptr; // checkpoint ID of this request is part of
    bool update_indx = false;                       // if index is alrady updated
    Clock::time_point indx_start_time;
    uint64_t lastCommited_seqId = INVALID_SEQ_ID;
    uint64_t seqId = INVALID_SEQ_ID;

    /********** Below entries are used for journal or to store checksum **********/
    vol_journal_entry j_ent;
    uint64_t indx_start_lba; // it points the last lba written + 1. It is helpful if a io is written partially
    std::vector< uint16_t > csum_list;
    std::vector< BlkId > alloc_blkid_list;
    std::vector< Free_Blk_Entry > fbe_list;

    /********** Constructor/Destructor **********/
    volume_req() : csum_list(0), alloc_blkid_list(0), fbe_list(0) {};
    volume_req(std::shared_ptr< Volume > vol, void* buf, uint64_t lba, uint32_t nlbas, bool read, bool sync) :
            vol_interface_req(vol, lba, nlbas, read, sync),
            io_start_time(Clock::now()), mvec(new homeds::MemVector()), outstanding_io_cnt(1), indx_start_lba(lba),
            csum_list(0), alloc_blkid_list(0), fbe_list(0) {
        assert((vol->get_page_size() * nlbas) <= VOL_MAX_IO_SIZE);
        if (!read) { mvec->set((uint8_t*)buf, vol->get_page_size() * nlbas, 0); }

        /* Trying to reserve the max possible size so that memory allocation is efficient */
        csum_list.reserve(VOL_MAX_IO_SIZE / vol->get_page_size());
        fbe_list.reserve(VOL_MAX_IO_SIZE / vol->get_page_size());
        alloc_blkid_list.reserve(VOL_MAX_IO_SIZE / vol->get_page_size());
        seqId = vol->inc_and_get_seq_id();
    };
    virtual ~volume_req() = default;
    virtual void free_yourself() override { delete this; }

    /********** member functions **********/
    static vol_interface_req_ptr make_instance(std::shared_ptr< Volume > vol, void* buf, uint64_t lba, uint32_t nlbas,
                                               bool read, bool sync) {
        return vol_interface_req_ptr((vol_interface_req*)new volume_req(vol, buf, lba, nlbas, read, sync));
    }
    static volume_req_ptr cast(const vol_interface_req_ptr& hb_req) {
        return (boost::static_pointer_cast< volume_req >(hb_req));
    }
    sisl::blob create_journal_entry() {
        auto blob = j_ent.create_journal_entry(this);
        return blob;
    }
    virtual std::string to_string() {
        std::stringstream ss;
        ss << "vol_interface_req: request_id=" << request_id << " dir=" << (is_read ? "R" : "W")
           << " outstanding_io_cnt=" << outstanding_io_cnt.get();
        return ss.str();
    }
    
    void push_blkid(BlkId& bid) { alloc_blkid_list.push_back(bid); }

    /* It push to the existing check sum list */
    void push_csum(uint16_t csum) { csum_list.push_back(csum); }

    /* push fbe to the existing list */
    void push_fbe(Free_Blk_Entry& fbe) { fbe_list.push_back(fbe); }
};

#define NUM_BLKS_PER_THREAD_TO_QUERY 10000ull
} // namespace homestore
