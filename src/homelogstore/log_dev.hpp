#pragma once

#include <sds_logging/logging.h>
#include <fds/stream_tracker.hpp>
#include <fds/utils.hpp>
#include "engine/blkstore/blkstore.hpp"
#include <fds/id_reserver.hpp>
#include <boost/intrusive_ptr.hpp>
#include <fmt/format.h>
#include <map>
#include "engine/homestore_base.hpp"

SDS_LOGGING_DECL(logdev)

namespace homestore {

typedef int64_t logid_t;
typedef uint32_t logstore_id_t;
typedef int64_t logstore_seq_num_t;

static constexpr uint32_t LOG_GROUP_HDR_MAGIC = 0xDABAF00D;
static constexpr uint32_t dma_boundary = 512; // Mininum size the dma/writes to be aligned with
static constexpr uint32_t initial_read_size = 4096;
static constexpr uint64_t bulk_read_size = 512 * 1024;

// Extra blks read during recovery to validate if indeed there is no corruption.
static constexpr uint32_t max_blks_read_for_additional_check = 20;

// clang-format off
/*
 * LogGroup Layout:
 *
 *   <----        Log Group Header         ---> <--   Record 1   --> <--   Record 2   -->        <-- -  Inline data area  --> 
 *  |----------------------------------------- |--------------------|--------------------|      |----------------|-----------|----------------|
 *  |#records|...| oob area   | inline area    | Size | data offset | Size | data offset | ...  | Record #1 data |     ...   |   OOB Record 1 |
 *  |----------------------------------------- |--------------------|--------------------|      |----------------|-----------|----------------|
 *                      |             |                     |                                     ^                            ^ 
 *                      |             |                     |                                     |                            |
 *                      |             |                      -------------------------------------|                            |
 *                      |             ------------------------------------------------------------|                            |
 *                      |------------------------------------------------------------------------------------------------------|         
 */
// clang-format on

/************************************* Log Record Section ************************************/
/* Each log record which is serialized to the persistent store in the following format */
struct serialized_log_record {
    uint32_t size;                    // Size of this log record
    uint32_t offset : 31;             // Offset within the log_group where data is residing
    uint32_t is_inlined : 1;          // Is the log data is inlined or out-of-band area
    logstore_seq_num_t store_seq_num; // Seqnum by the log store
    logstore_id_t store_id;           // ID of the store this log is associated with
} __attribute__((packed));

/* This structure represents the in-memory representation of a log record */
struct log_record {
    static constexpr uint32_t inline_size = dma_boundary;

    serialized_log_record* pers_record = nullptr;
    uint8_t* data_ptr;
    uint32_t size;
    void* context;
    logstore_id_t store_id;
    logstore_seq_num_t seq_num;

    log_record(logstore_id_t sid, logstore_seq_num_t snum, uint8_t* d, uint32_t sz, void* ctx) {
        store_id = sid;
        seq_num = snum;
        data_ptr = d;
        size = sz;
        context = ctx;
    }

    size_t inlined_size() const { return sizeof(serialized_log_record) + (is_inlineable() ? size : 0); }
    size_t serialized_size() const { return sizeof(serialized_log_record) + size; }
    bool is_inlineable() const {
        // Need inlining if size is smaller or size/buffer is not in dma'ble boundary.
        return ((size < inline_size) || ((size % dma_boundary) != 0) || (((uintptr_t)data_ptr % dma_boundary) != 0));
    }
    static size_t serialized_size(uint32_t sz) { return sizeof(serialized_log_record) + sz; }
};

/************************************* Log Group Section ************************************/
/* This structure represents a group commit log header */
struct log_group_header {
    uint32_t magic;
    uint32_t n_log_records;      // Total number of log records
    logid_t start_log_idx;       // log id of the first log record
    uint32_t group_size;         // Total size of this group including this header
    uint32_t inline_data_offset; // Offset of inlined area of data
    uint32_t oob_data_offset;    // Offset of where the data which are not inlined starts
    crc32_t prev_grp_crc;        // Checksum of the previous group that was written
    crc32_t cur_grp_crc;         // Checksum of the current group record

    uint32_t inline_data_size() const {
        return oob_data_offset ? (oob_data_offset - inline_data_offset) : (group_size - inline_data_offset);
    }

    uint8_t* inline_area() const { return (((uint8_t*)this) + inline_data_offset); }
    uint8_t* oob_area() const { return (((uint8_t*)this) + oob_data_offset); }
    uint8_t* record_area() const { return (((uint8_t*)this) + sizeof(log_group_header)); }

    serialized_log_record* nth_record(uint32_t n) const {
        return (serialized_log_record*)(record_area() + (sizeof(serialized_log_record) * n));
    }

    sisl::blob data(logid_t idx) const {
        assert(idx >= start_log_idx);
        assert(idx - start_log_idx < n_log_records);

        serialized_log_record* lr = nth_record(start_log_idx - idx);

        sisl::blob b;
        b.bytes = (lr->is_inlined ? inline_area() : oob_area()) + lr->offset;
        b.size = lr->size;
        return b;
    }

    uint32_t magic_word() const { return magic; }
    logid_t start_idx() const { return start_log_idx; }
    uint32_t nrecords() const { return n_log_records; }
    uint32_t total_size() const { return group_size; }
    crc32_t this_group_crc() const { return cur_grp_crc; }
    crc32_t prev_group_crc() const { return prev_grp_crc; }
    uint32_t _inline_data_offset() const { return inline_data_offset; }

    friend std::ostream& operator<<(std::ostream& os, const log_group_header& h) {
        auto s = fmt::format("magic = {} n_log_records = {} start_log_idx = {} group_size = {} inline_data_offset = {} "
                             "oob_data_offset = {} prev_grp_crc = {} cur_grp_crc = {}",
                             h.magic, h.n_log_records, h.start_log_idx, h.group_size, h.inline_data_offset,
                             h.oob_data_offset, h.prev_grp_crc, h.cur_grp_crc);
        os << s;
        return os;
    }
} __attribute__((packed));

struct iovec_wrapper : public iovec {
    iovec_wrapper(void* base, size_t len) {
        iov_base = base;
        iov_len = len;
    }
};
typedef std::vector< iovec_wrapper > iovec_array;

/* In memory representation of a log group which will be written as a group together */
class LogGroup {
public:
    static constexpr uint32_t optimal_num_records = 16;
    static constexpr uint32_t estimated_iovs = 10;
    static constexpr size_t inline_log_buf_size = log_record::inline_size * optimal_num_records;
    static constexpr uint32_t max_records_in_a_batch =
        (initial_read_size - sizeof(log_group_header)) / sizeof(serialized_log_record);

    friend class LogDev;

    LogGroup();
    ~LogGroup() = default;

    void reset(uint32_t max_records);
    void create_overflow_buf(uint32_t min_needed);
    bool add_record(const log_record& record, int64_t log_idx);
    bool can_accomodate(const log_record& record) const { return (m_nrecords <= m_max_records); }

    const iovec_array& finish();
    crc32_t compute_crc();

    log_group_header* header() const { return (log_group_header*)m_cur_log_buf; }
    iovec_array& iovecs() { return m_iovecs; }
    // uint32_t data_size() const { return header()->group_size - sizeof(log_group_header); }
    uint32_t actual_data_size() const { return m_actual_data_size; }

    friend std::ostream& operator<<(std::ostream& os, const LogGroup& lg) {
        auto s = fmt::format("Header:[{}]\nLog_idx_range: [{} - {}] DevOffset: {} Max_Records: {} IOVecSize: {}\n"
                             "-----------------------------------------------------------------\n",
                             *((log_group_header*)lg.m_cur_log_buf), lg.m_flush_log_idx_from, lg.m_flush_log_idx_upto,
                             lg.m_log_dev_offset, lg.m_max_records, lg.m_iovecs.size());
        os << s;
        return os;
    }

private:
    static LogGroup* make_log_group(uint32_t estimated_records) {
        _log_group_idx = !_log_group_idx;
        _log_group[_log_group_idx].reset(estimated_records);
        return &_log_group[_log_group_idx];
    }

private:
    static LogGroup _log_group[2];
    static uint32_t _log_group_idx;

    sisl::aligned_unique_ptr< uint8_t > m_log_buf;
    sisl::aligned_unique_ptr< uint8_t > m_overflow_log_buf;

    uint8_t* m_cur_log_buf;
    uint32_t m_cur_buf_len;

    serialized_log_record* m_record_slots;
    uint32_t m_inline_data_pos;
    uint32_t m_oob_data_pos;

    uint32_t m_nrecords = 0;
    uint32_t m_max_records = 0;
    uint32_t m_actual_data_size = 0;

    // Info about the final data
    iovec_array m_iovecs;
    int64_t m_flush_log_idx_from;
    int64_t m_flush_log_idx_upto;
    uint64_t m_log_dev_offset;
};

/************************************* LogDev Request to BlkStore Section ************************************/
struct logdev_req;
#define to_logdev_req(req) boost::static_pointer_cast< logdev_req >(req)
typedef boost::intrusive_ptr< logdev_req > logdev_req_ptr;

struct logdev_req : public blkstore_req< BlkBuffer > {
public:
    static boost::intrusive_ptr< logdev_req > make_request() {
        return boost::intrusive_ptr< logdev_req >(sisl::ObjectAllocator< logdev_req >::make_object());
    }

    virtual void free_yourself() override { sisl::ObjectAllocator< logdev_req >::deallocate(this); }

    virtual ~logdev_req() = default;

    // virtual size_t get_your_size() const override { return sizeof(ssd_loadgen_req); }

    static logdev_req_ptr cast(const boost::intrusive_ptr< blkstore_req< BlkBuffer > >& bs_req) {
        return boost::static_pointer_cast< logdev_req >(bs_req);
    }

    LogGroup* m_log_group;

protected:
    friend class sisl::ObjectAllocator< logdev_req >;
};

typedef int64_t logid_t;
struct logdev_key {
    logid_t idx = -1;
    uint64_t dev_offset = 0;

    bool operator==(const logdev_key& other) { return (other.idx == idx) && (other.dev_offset == dev_offset); }
    friend std::ostream& operator<<(std::ostream& os, const logdev_key& k) {
        os << "[idx=" << k.idx << " dev_offset=" << k.dev_offset << "]";
        return os;
    }

    operator bool() const { return is_valid(); }
    bool is_valid() const { return (idx != -1); }
};
} // namespace homestore

namespace fmt {
template <>
struct formatter< homestore::logdev_key > {
    template < typename ParseContext >
    constexpr auto parse(ParseContext& ctx) {
        return ctx.begin();
    }

    template < typename FormatContext >
    auto format(homestore::logdev_key const& k, FormatContext& ctx) {
        return format_to(ctx.out(), "[idx={} dev_offset={}]", k.idx, k.dev_offset);
    }
};
} // namespace fmt

namespace homestore {
typedef sisl::byte_view log_buffer;

struct truncation_request_t {
    logstore_id_t store_id;
    logstore_seq_num_t upto_seq_num;
};

/* This structure represents the logdevice super block which will sit inside the user_context block of the
 * vdev_info_block. */
struct logdev_info_block {
    static constexpr uint32_t size = 2048;
    static constexpr uint32_t store_info_size() { return size - sizeof(logdev_info_block); }

    uint32_t blkstore_type = 4; // TODO: Padding. Once this persistent area is moved to recovery mgr, this 4 bytes
                                // padding can be removed.
    uint64_t start_dev_offset = 0;
    uint8_t store_id_info[0];
} __attribute__((packed));

class log_stream_reader {
public:
    log_stream_reader(uint64_t device_cursor);
    sisl::byte_view next_group(uint64_t* out_dev_offset);
    sisl::byte_view group_in_next_page();
    uint64_t group_cursor() const { return m_cur_group_cursor; }

private:
    sisl::byte_view read_next_bytes(uint64_t nbytes);

private:
    boost::intrusive_ptr< HomeStoreBase > m_hb;
    sisl::byte_view m_cur_log_buf;
    uint64_t m_cur_group_cursor;
};

class LogDev {
public:
    typedef std::function< void(logstore_id_t, logdev_key, logdev_key, uint32_t nremaining_in_batch, void*) >
        log_append_comp_callback;
    typedef std::function< void(logstore_id_t, logstore_seq_num_t, logdev_key, log_buffer) > log_found_callback;
    typedef std::function< void(logstore_id_t) > store_found_callback;
    typedef std::function< void(void) > flush_blocked_callback;

    static constexpr int64_t flush_threshold_size = 4096;
    // static constexpr int64_t flush_threshold_size = 512;
    static constexpr int64_t flush_data_threshold_size = flush_threshold_size - sizeof(log_group_header);
    static constexpr uint64_t flush_timer_frequency_us = 750;
    static constexpr uint64_t max_time_between_flush_us = 500;

    LogDev();
    ~LogDev();

    /**
     * @brief Start the logdev. This method reads the log virtual dev info block, loads all of the store and prepares
     * to the recovery. It is expected that all callbacks are registered before calling the start.
     *
     * @param format: Do we need to format the logdev or not.
     */
    void start(bool format);

    /**
     * @brief Stop the logdev. It resets all the parameters it is using and thus can be started later
     *
     */
    void stop();

    /**
     * @brief Append the data to the log device asynchronously. The buffer that is passed is expected to be valid, till
     * the append callback is done.
     *
     * @param store_id: The upper layer store id for this log record
     * @param seq_num: Upper layer store seq_num
     * @param data : Pointer to the data to be appended
     * @param size : Size of the data. At this point it does not support size > Max_Atomic_Page_size of underlying
     * structure which could be 8K
     * @param cb_context Context to put upon a callback once append is. Upon completion the registered callback is
     * called.
     *
     * @return logid_t : log_idx of the log of the data.
     */
    logid_t append_async(logstore_id_t store_id, logstore_seq_num_t seq_num, uint8_t* data, uint32_t size,
                         void* cb_context);

    /**
     * @brief Read the log id from the device offset
     *
     * @param idx log_id to read
     * @param dev_offset device offset of the log id which was provided upon append. This is needed to locate the log
     * idx within the device. A log data can be looked up only by pair of log_id and dev_offset.
     *
     * @return log_buffer : Opaque structure which contains the data blob and its size. It is safe buffer and hence it
     * need not be freed and can be cheaply passed it around.
     */
    log_buffer read(const logdev_key& key);

    /**
     * @brief Load the data from the blkstore starting with offset. This method loads data in bulk and then call
     * the registered logfound_cb with key and buffer. NOTE: This method is not thread safe. It is expected to be called
     * during recovery
     *
     * @param offset Log blkstore device offset.
     */
    void load(uint64_t offset);

    /**
     * @brief Register the callback to receive upon completion of append.
     * NOTE: This method is not thread safe.
     *
     * @param cb Callback to call upon completion of append. It will call with 2 parameters
     * a) logdev_key: The key to access the log dev data. It can be treated as opaque (internally has log_id and device
     * offset)
     * b) Context: The context which was passed to append method.
     */
    void register_append_cb(const log_append_comp_callback& cb) { m_append_comp_cb = cb; }

    /**
     * @brief Register the callback to receive new logs during recovery from the device.
     * NOTE: This method is not thread safe.
     *
     * @param cb Callback to call upon completion of append. It will call with 3 parameters
     * a) logdev_key: The key to access the log dev data, which is retrieved from the device. It can be treated as
     * opaque (internally has log_id and device offset) b) log_buffer: Opaque structure which contains the data and size
     * of the log which key refers to. The underlying buffer it returns is ref counted and hence it need not be
     * explicitly freed.
     */
    void register_logfound_cb(const log_found_callback& cb) { m_logfound_cb = cb; }

    /**
     * @brief Register the callback when a store is found during loading phase
     *
     * @param cb This callback is called only during load phase where it found a log store. The parameter is a store id
     * used to register earlier.
     */
    void register_store_found_cb(const store_found_callback& cb) { m_store_found_cb = cb; }

    // callback from blkstore, registered at blkstore creation;
    void process_logdev_completions(const boost::intrusive_ptr< blkstore_req< BlkBuffer > >& bs_req);

    /**
     * @brief Reserve logstore id and persist if needed. It persists the entire map about the logstore id inside the
     *
     * @param persist : Need to persist the reserved id or not
     * @return uint32_t : Return the reserved id
     */
    logstore_id_t reserve_store_id(bool persist = true);

    /**
     * @brief Unreserve the logstore id. It does not immediately unregisters and persist the unregistered map, but it
     * will add to the waiting list (garbage list) and then during truncation, it actually unreserves and persits map.
     *
     * @param store_id
     */
    void unreserve_store_id(uint32_t store_id);

    /**
     * @brief Is the given store id already reserved.
     *
     * @return true or false
     */
    bool is_reserved_store_id(logstore_id_t id);

    /**
     * @brief This method persist the store ids reserved/unreserved inside the vdev super block
     */
    void persist_store_ids();

    /**
     * @brief This method get all the store ids that are registered already and out of them which are being garbaged
     * and waiting to be garbage collected. Predominant use of this method is for validation and testing
     *
     * @param registered out - Reference to the vector where all registered ids are pushed
     * @param garbage out - Reference to the vector where all garbage ids
     */
    void get_registered_store_ids(std::vector< logstore_id_t >& registered, std::vector< logstore_id_t >& garbage);

    crc32_t get_prev_crc() const { return m_last_crc; }

    /**
     * @brief This method attempts to block the log flush and then make a callback cb. If it is already blocked,
     * then after previous flush is completed, it will make the callback (while log flush is still under blocked state)
     *
     * @param cb Callback
     * @return true or false based on if it is able to block the flush right away.
     */
    bool try_lock_flush(const flush_blocked_callback& cb);

    /**
     * @brief Unblock the flush. While unblocking if there are other requests to block or any flush pending it first
     * executes them before unblocking
     */
    void unlock_flush();

    /**
     * @brief : truncate up to input log id;
     *
     * @param key : the key containing log id that needs to be truncate up to;
     */
    void truncate(const logdev_key& key);
    void meta_blk_found(meta_blk* mblk, sisl::byte_view buf, size_t size);

private:
    static LogGroup* new_log_group();

    LogGroup* prepare_flush(int32_t estimated_record);
    void do_flush(LogGroup* lg);
    void flush_if_needed(const uint32_t new_record_size = 0, logid_t new_idx = -1);
    void flush_by_size(const uint32_t min_threshold, const uint32_t new_record_size = 0, logid_t new_idx = -1);
    void on_flush_completion(LogGroup* lg);
    void do_load(uint64_t offset);

#if 0
    log_group_header* read_validate_header(uint8_t* buf, uint32_t size, bool* read_more);
    sisl::byte_array read_next_header(uint32_t max_buf_reads);
#endif

    void _persist_info_block();
    void assert_next_pages(log_stream_reader& lstream);
    
private:
    boost::intrusive_ptr< HomeStoreBase > m_hb; // Back pointer to homestore
    std::unique_ptr< sisl::StreamTracker< log_record > >
        m_log_records; // The container which stores all in-memory log records
    std::unique_ptr< sisl::IDReserver > m_id_reserver;
    std::atomic< logid_t > m_log_idx = 0;            // Generator of log idx
    std::atomic< int64_t > m_pending_flush_size = 0; // How much flushable logs are pending
    std::atomic< bool > m_is_flushing = false; // Is LogDev currently flushing (so far supports one flusher at a time)
    std::map< logid_t, logstore_id_t > m_garbage_store_ids;
    Clock::time_point m_last_flush_time;

    logid_t m_last_flush_idx = -1; // Track last flushed and truncated log idx
    logid_t m_last_truncate_idx = -1;

    crc32_t m_last_crc = INVALID_CRC32_VALUE;
    log_append_comp_callback m_append_comp_cb = nullptr;
    log_found_callback m_logfound_cb = nullptr;
    store_found_callback m_store_found_cb = nullptr;

    // LogDev Info block related fields
    std::mutex m_store_reserve_mutex;
    sisl::byte_view m_info_blk_buf;

    // Block flush Q request Q
    std::mutex m_block_flush_q_mutex;
    std::vector< flush_blocked_callback > m_block_flush_q;

    // Timer handle
    iomgr::timer_handle_t m_flush_timer_hdl;
    void* m_sb_cookie = nullptr;
}; // LogDev

} // namespace homestore
