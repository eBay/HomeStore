#pragma once

#include <cstdint>
#include <memory>
#include <sstream>
#include <variant>

#include <fcntl.h>
#include <sys/uio.h>

#include "homeblks/home_blks.hpp"
#include "engine/blkstore/blkstore.hpp"
#include "engine/cache/cache.h"
#include "engine/common/homestore_assert.hpp"
#include "engine/device/blkbuffer.hpp"
#include "engine/device/device.h"
#include "engine/homeds/thread/threadpool/thread_pool.h"
#include "engine/index/snap_mgr.hpp"
#include "engine/meta/meta_blks_mgr.hpp"
#include "fds/obj_allocator.hpp"
#include "fds/vector_pool.hpp"
#include "mapping.hpp"
#include "metrics/metrics.hpp"
#include "sds_logging/logging.h"
#include "spdlog/fmt/fmt.h"
#include "utility/atomic_counter.hpp"
#include "utility/enum.hpp"
#include "utility/obj_life_counter.hpp"

namespace homestore {

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
    HS_SUBMOD_LOG(level, mod, req, "vol", this->get_name(), msg, ##__VA_ARGS__)
#define VOL_ASSERT(assert_type, cond, req, ...)                                                                        \
    HS_SUBMOD_ASSERT(assert_type, cond, req, "vol", this->get_name(), ##__VA_ARGS__)
#define VOL_ASSERT_CMP(assert_type, val1, cmp, val2, req, ...)                                                         \
    HS_SUBMOD_ASSERT_CMP(assert_type, val1, cmp, val2, req, "vol", this->get_name(), ##__VA_ARGS__)

#define VOL_DEBUG_ASSERT(...) VOL_ASSERT(DEBUG, __VA_ARGS__)
#define VOL_RELEASE_ASSERT(...) VOL_ASSERT(RELEASE, __VA_ARGS__)
#define VOL_LOG_ASSERT(...) VOL_ASSERT(LOGMSG, __VA_ARGS__)

#define VOL_DEBUG_ASSERT_CMP(...) VOL_ASSERT_CMP(DEBUG, ##__VA_ARGS__)
#define VOL_RELEASE_ASSERT_CMP(...) VOL_ASSERT_CMP(RELEASE, ##__VA_ARGS__)
#define VOL_LOG_ASSERT_CMP(...) VOL_ASSERT_CMP(LOGMSG, ##__VA_ARGS__)

struct volume_child_req : public blkstore_req< BlkBuffer > {
    uint64_t lba;
    int nlbas;
    bool is_read = false;
    std::vector< Free_Blk_Entry > blkIds_to_free;
    uint64_t reqId;
    Clock::time_point op_start_time;
    uint16_t checksum[MAX_NUM_LBA];
    uint64_t read_buf_offset;
    uint64_t read_size;
    bool sync = false;
    bool use_cache{false};

    volume_req_ptr parent_req = nullptr;
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
        std::ostringstream ss;
        ss << ((is_read) ? "READ" : "WRITE") << ": lba=" << lba << " nlbas=" << nlbas;
        return ss.str();
    }

protected:
    friend class sisl::ObjectAllocator< volume_child_req >;

    // Volume req should always be created from Volume::create_vol_req()
    volume_child_req() = default;
};

#define CHECKSUM_SIZE 2

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
        REGISTER_HISTOGRAM(volume_pieces_per_read, "Number of individual pieces per write",
                           HistogramBucketsType(LinearUpto64Buckets));
        REGISTER_HISTOGRAM(volume_write_size_distribution, "Distribution of volume write sizes",
                           HistogramBucketsType(ExponentialOfTwoBuckets));
        REGISTER_HISTOGRAM(volume_read_size_distribution, "Distribution of volume read sizes",
                           HistogramBucketsType(ExponentialOfTwoBuckets));
        register_me_to_farm();
    }

    ~VolumeMetrics() { deregister_me_from_farm(); }
};

#define VOL_SB_VERSION 0x2
struct vol_sb_hdr {
    /* Immutable members */
    const uint64_t version;
    const uint64_t page_size;
    const uint64_t size;
    const boost::uuids::uuid uuid;
    const char vol_name[VOL_NAME_SIZE];
    indx_mgr_sb indx_sb;
    vol_sb_hdr(const uint64_t& page_size, const uint64_t& size, const char* in_vol_name,
               const boost::uuids::uuid& uuid) :
            version(VOL_SB_VERSION), page_size(page_size), size(size), uuid(uuid), vol_name("") {
        memcpy((char*)vol_name, in_vol_name, VOL_NAME_SIZE);
    };

    /* these variables are mutable. Always update these values before writing the superblock */
    vol_state state;
};

/* A simple self contained wrapper for completion list, which uses vector pool to avoid additional allocations */
struct vol_completion_req_list {
    vol_completion_req_list() { m_cur = sisl::VectorPool< vol_interface_req_ptr >::alloc(); }
    ~vol_completion_req_list() { sisl::VectorPool< vol_interface_req_ptr >::free(m_cur, true /* no_cache */); }

    void push_back(const vol_interface_req_ptr& req) { m_cur->push_back(req); }
    size_t size() const { return m_cur->size(); }
    std::vector< vol_interface_req_ptr >* swap() {
        auto ret = m_cur;
        m_cur = sisl::VectorPool< vol_interface_req_ptr >::alloc();
        return ret;
    }

    void drop(std::vector< vol_interface_req_ptr >* v) { sisl::VectorPool< vol_interface_req_ptr >::free(v); }

private:
    std::vector< vol_interface_req_ptr >* m_cur = nullptr;
};

class Volume : public std::enable_shared_from_this< Volume > {
private:
    vol_params m_params;
    VolumeMetrics m_metrics;
    HomeBlksSafePtr m_hb; // Hold onto the homeblks to maintain reference
    std::shared_ptr< SnapMgr > m_indx_mgr;
    boost::intrusive_ptr< BlkBuffer > m_only_in_mem_buff;
    io_comp_callback m_comp_cb;

    std::atomic< vol_state > m_state;
    std::atomic< int64_t > seq_Id;
    std::atomic< uint64_t > m_err_cnt = 0;
    std::atomic< uint64_t > m_req_id = 0;
    sisl::atomic_counter< uint64_t > vol_ref_cnt = 0; // volume can not be destroy/shutdown until it is not zero

    std::mutex m_sb_lock; // lock for updating vol's sb
    // sisl::aligned_unique_ptr< vol_sb_hdr > m_sb_buf;
    sisl::byte_view m_sb_buf;
    indxmgr_stop_cb m_destroy_done_cb;
    std::atomic< bool > m_indx_mgr_destroy_started;
    void* m_sb_cookie = nullptr;

private:
    /* static members */
    /* home_blks can not be shutdown until it is not zero. It is the superset of vol_ref_cnt. If it is zero then
     * volume_ref count has to zero. But it is not true other way round.
     */
    static sisl::atomic_counter< uint64_t > home_blks_ref_cnt;

    // Per thread buffer which holds the completed reqs which will be batched before making batch callback
    sisl::ActiveOnlyThreadBuffer< vol_completion_req_list > m_completed_reqs;

private:
    Volume(const vol_params& params);
    Volume(meta_blk* mblk_cookie, sisl::byte_view sb_buf);
    void alloc_single_block_in_mem();
    bool check_and_complete_req(const volume_req_ptr& vreq, const std::error_condition& err);

    volume_child_req_ptr create_vol_child_req(BlkId& bid, const volume_req_ptr& vreq, const uint64_t start_lba, int nlbas);

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
    void process_indx_completions(const indx_req_ptr& ireq, std::error_condition err);
    void process_read_indx_completions(const boost::intrusive_ptr< indx_req >& ireq, std::error_condition err);
    void process_data_completions(const boost::intrusive_ptr< blkstore_req< BlkBuffer > >& bs_req);

    std::error_condition alloc_blk(const volume_req_ptr& vreq, std::vector< BlkId >& bid);
    void verify_csum(const volume_req_ptr& vreq);

    void interface_req_done(const vol_interface_req_ptr& iface_req);

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
    void shutdown_if_needed();
    void destroy_internal();
    indx_tbl* create_indx_tbl();
    indx_tbl* recover_indx_tbl(btree_super_block& sb, btree_cp_sb& cp_sb);
    mapping* get_active_indx();

    void vol_sb_init();

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
        if (home_blks_ref_cnt.get() != 0) { return false; }
        return true;
    }

    /* Called during shutdown. */
    static void shutdown(const indxmgr_stop_cb& cb);

    /* called during io completions from data blk store */
    static void process_vol_data_completions(const boost::intrusive_ptr< blkstore_req< BlkBuffer > >& bs_req);

    /* used to trigger system level cp */
    static void trigger_homeblks_cp(const cp_done_cb& cb = nullptr) { SnapMgr::trigger_hs_cp(cb); };

    /* it is used in fake reboot */
    static void reinit() { SnapMgr::reinit(); }

    static void meta_blk_found_cb(meta_blk* mblk, sisl::byte_view buf, size_t size);

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

    /* Trim lba
     * @param hb_req :- it expects this request to be created
     * @return :- no_error if there is no error. It doesn't throw any exception
     */
    std::error_condition unmap(const vol_interface_req_ptr& hb_req);

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
    const char* get_name() const { return (((vol_sb_hdr*)m_sb_buf.bytes())->vol_name); }

    /* Get page size of this volume.
     * @return :- page size
     */
    uint64_t get_page_size() const { return ((vol_sb_hdr*)m_sb_buf.bytes())->page_size; }

    /* Get size of this volume.
     * @return :- size
     */
    uint64_t get_size() const { return ((vol_sb_hdr*)m_sb_buf.bytes())->size; }
    cap_attrs get_used_size() { return m_indx_mgr->get_used_size(); }

    /* Get uuid of this volume.
     * @return :- uuid
     */
    boost::uuids::uuid get_uuid() { return ((vol_sb_hdr*)m_sb_buf.bytes())->uuid; }

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

    size_t call_batch_completion_cbs();

    /* Update a new cp of this volume.
     * @params icp :- current cp of this volume
     * @params cur_hcp :- current cp of home_blks
     */
    indx_cp_ptr attach_prepare_volume_cp(const indx_cp_ptr& icp, hs_cp* cur_hcp, hs_cp* new_hcp);

    std::string to_string() {
        std::stringstream ss;
        ss << "Name :" << get_name() << ", UUID :" << boost::lexical_cast< std::string >(get_uuid())
           << ", Size:" << get_size() << ((is_offline()) ? ", Offline" : ", Not Offline") << ", State :" << get_state();
        return ss.str();
    }
    uint64_t inc_and_get_seq_id() {
        uint64_t id = seq_Id.fetch_add(1, std::memory_order_relaxed);
        return (id + 1);
    }

    /**
     * @brief
     */
    void migrate_sb();
    void recovery_start_phase1();
    void recovery_start_phase2();
};

/* Note :- Any member inside this structure is not lock protected. Its caller responsibility to call it under lock
 * or make sure it is single threaded.
 */
typedef boost::intrusive_ptr< volume_req > volume_req_ptr;

ENUM(volume_req_state, uint8_t, preparing, data_io, journal_io, completed);
struct journal_key {
    uint64_t lba;
    uint32_t nlbas;
} __attribute__((__packed__));

struct volume_req : indx_req {
    volume_req(const volume_req&) = delete;
    volume_req(volume_req&&) noexcept = delete;
    volume_req& operator=(const volume_req&) = delete;
    volume_req& operator=(volume_req&&) noexcept = delete;

    /********** generic counters **********/
    vol_interface_req_ptr iface_req; // Corresponding Interface API request which has all the details about requests
    sisl::atomic_counter< int > ref_count = 1;            // Initialize the count
    volume_req_state state = volume_req_state::preparing; // State of the volume request

    /********** members used to write data blocks **********/
    Clock::time_point io_start_time;                    // start time
    Clock::time_point indx_start_time;                  // indx start time
    typedef boost::intrusive_ptr< homeds::MemVector > MemVecData; // HomeStore memory managed data
    typedef std::vector< iovec > IoVecData; // External scatter/gather data
    std::variant<MemVecData, IoVecData>  data;

    sisl::atomic_counter< int > outstanding_io_cnt = 1; // how many IOs are outstanding for this request
    int vc_req_cnt = 0;                                 // how many child requests are issued.

    /********* members used by read ***********/
    bool first_read_indx_call = false;
    std::vector< std::pair< MappingKey, MappingValue > > result_kv;

    /********** members used by indx_mgr and mapping **********/
    int64_t lastCommited_seqid = INVALID_SEQ_ID;
    int64_t seqid = INVALID_SEQ_ID;

    /********** Below entries are used for journal or to store checksum **********/
    std::vector< uint16_t > csum_list;
    void push_csum(uint16_t csum) { csum_list.push_back(csum); }
    std::vector< BlkId > alloc_blkid_list;
    void push_blkid(BlkId& bid) { alloc_blkid_list.push_back(bid); }

    /********** member functions **********/
    virtual std::string to_string() {
        std::ostringstream ss;
        ss << "vol_interface_req: request_id=" << iface_req->request_id << " dir=" << (is_read_op() ? "R" : "W")
           << " outstanding_io_cnt=" << outstanding_io_cnt.get();
        return ss.str();
    }

    static volume_req_ptr make(const vol_interface_req_ptr& iface_req) {
        return volume_req_ptr(sisl::ObjectAllocator< volume_req >::make_object(iface_req), false);
    }

    virtual ~volume_req() override = default;

    Volume* vol() { return iface_req->vol_instance.get(); }
    bool is_read_op() const { return iface_req->is_read(); }
    uint64_t lba() const { return iface_req->lba; }
    uint32_t nlbas() const { return iface_req->nlbas; }
    bool is_sync() const { return iface_req->sync; }
    bool use_cache() const { return iface_req->cache; }
    std::error_condition& err() const { return iface_req->err; }
    std::vector< buf_info >& read_buf() { return iface_req->read_buf_list; }

    friend class sisl::ObjectAllocator< volume_req >;

    /***************** Virtual functions required by indx mgr *********************/
    virtual void free_yourself() override { sisl::ObjectAllocator< volume_req >::deallocate(this); }
    virtual uint64_t get_seqid() override { return seqid; }
    virtual uint32_t get_key_size() override { return (sizeof(journal_key)); }
    virtual uint32_t get_val_size() override {
        uint64_t active_nlbas_written = mapping::get_nlbas_from_cursor(lba(), active_btree_cur);
        return (sizeof(uint16_t) * active_nlbas_written);
    }
    virtual void fill_key(void* mem, uint32_t size) override {
        uint64_t active_nlbas_written = mapping::get_nlbas_from_cursor(lba(), active_btree_cur);
        assert(size == sizeof(journal_key));
        journal_key* key = (journal_key*)mem;
        key->lba = lba();
        key->nlbas = active_nlbas_written;
    }

    virtual void fill_val(void* mem, uint32_t size) override {
        uint64_t active_nlbas_written = mapping::get_nlbas_from_cursor(lba(), active_btree_cur);
        /* we only populating check sum. Allocate blkids are already populated by indx mgr */
        uint16_t* j_csum = (uint16_t*)mem;
        assert(active_nlbas_written == nlbas());
        for (uint32_t i = 0; i < active_nlbas_written; ++i) {
            j_csum[i] = csum_list[i];
        }
    }
    virtual uint32_t get_io_size() override {
        uint64_t active_nlbas_written = mapping::get_nlbas_from_cursor(lba(), active_btree_cur);
        return active_nlbas_written * vol()->get_page_size();
    }

private:
    /********** Constructor/Destructor **********/
    // volume_req() : csum_list(0), alloc_blkid_list(0), fbe_list(0){};
    volume_req(const vol_interface_req_ptr& vi_req) :
            indx_req(vi_req->request_id),
            iface_req(vi_req),
            io_start_time(Clock::now()) {
        assert((vi_req->vol_instance->get_page_size() * vi_req->nlbas) <= VOL_MAX_IO_SIZE);
        if (vi_req->use_cache()) {
            // a cached request is assumed to have lifetime managed by HomeStore
            if (vi_req->is_write()) {
                data.emplace<MemVecData>(new homeds::MemVector{
                    static_cast< uint8_t* >(vi_req->buffer),
                    static_cast< uint32_t >(vi_req->vol_instance->get_page_size() * vi_req->nlbas), 0});
            }
        } else {
            // a non-cached request is assume to have lifetime managed external to HomeStore
            // convert read/write to single scatter/gather
            iovec buffer{};
            buffer.iov_base = vi_req->buffer;
            buffer.iov_len = static_cast< size_t >(vi_req->vol_instance->get_page_size() * vi_req->nlbas);
            data.emplace<IoVecData>();
            std::get< IoVecData >(data).emplace_back(std::move(buffer));
        }

        /* Trying to reserve the max possible size so that memory allocation is efficient */
        csum_list.reserve(VOL_MAX_IO_SIZE / vi_req->vol_instance->get_page_size());
        indx_fbe_list.reserve(VOL_MAX_IO_SIZE / vi_req->vol_instance->get_page_size());
        alloc_blkid_list.reserve(VOL_MAX_IO_SIZE / vi_req->vol_instance->get_page_size());
        if (vi_req->is_write()) { seqid = vi_req->vol_instance->inc_and_get_seq_id(); }
    }
};

#define NUM_BLKS_PER_THREAD_TO_QUERY 10000ull
} // namespace homestore
