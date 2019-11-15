#pragma once

#include <sds_logging/logging.h>
#include <fds/stream_tracker.hpp>
#include <fds/utils.hpp>
#include <volume/home_blks.hpp>
#include <blkstore/blkstore.hpp>

SDS_LOGGING_DECL(logdev)

namespace homestore {

typedef int64_t logid_t;

typedef uint32_t crc32_t;

static constexpr crc32_t init_crc32 = 0x12345678;
static constexpr crc32_t INVALID_CRC32_VALUE = 0x0u;
static constexpr uint32_t LOG_GROUP_HDR_MAGIC = 0xDABAF00D;
static constexpr uint32_t dma_boundary = 512; // Mininum size the dma/writes to be aligned with
static constexpr uint32_t initial_read_size = 4096;
static constexpr uint32_t bulk_read_size = 512 * 1024;

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
    uint32_t size;           // Size of this log record
    uint32_t offset : 31;    // Offset within the log_group where data is residing
    uint32_t is_inlined : 1; // Is the log data is inlined or out-of-band area
} __attribute__((packed));

/* This structure represents the in-memory representation of a log record */
struct log_record {
    static constexpr uint32_t inline_size = dma_boundary;

    serialized_log_record* pers_record = nullptr;
    uint8_t* data_ptr;
    uint32_t size;
    void* context;

    log_record(uint8_t* d, uint32_t sz, void* ctx) {
        data_ptr = d;
        size = sz;
        context = ctx;
    }

    size_t inlined_size() const { return sizeof(serialized_log_record) + (is_inlinebale() ? size : 0); }
    size_t serialized_size() const { return sizeof(serialized_log_record) + size; }
    bool is_inlinebale() const { return (size < inline_size); }
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
        auto s = fmt::format("Header:[{}]\nLog_idx_range: [{} - {}] DevOffset: {} Max_Records: {} \n"
                             "-----------------------------------------------------------------\n",
                             *((log_group_header*)lg.m_cur_log_buf), lg.m_flush_log_idx_from, lg.m_flush_log_idx_upto,
                             lg.m_log_dev_offset, lg.m_max_records);
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

//
// We have only one LogDev instance serving all the volume log write requests;
//
// LogDev exposes APIs to LogStore layer.
//
// TODO:
// 1. Handle multiple chunk in blkstore layer
// 2. Recovery support : journal superblock;
//

typedef int64_t logid_t;
struct log_key {
    logid_t idx;
    uint64_t dev_offset;
};

struct log_buffer {
public:
    log_buffer(const std::shared_ptr< sisl::byte_array >& base_data, uint32_t offset, uint32_t size) :
            m_base_buffer(base_data),
            m_log_data_view(m_base_buffer->bytes + offset, size) {}

    log_buffer(const std::shared_ptr< sisl::byte_array >& base_data) : log_buffer(base_data, 0, base_data->size) {}
    log_buffer(const log_buffer& other) = default;

    sisl::blob blob() const { return m_log_data_view; }
    uint8_t* data() const { return m_log_data_view.bytes; }
    uint32_t size() const { return m_log_data_view.size; }

private:
    std::shared_ptr< sisl::byte_array > m_base_buffer;
    sisl::blob m_log_data_view;
};

class LogDev {
public:
    typedef std::function< void(log_key, void*) > log_append_comp_callback;
    typedef std::function< void(log_key, log_buffer) > log_found_callback;

    // static constexpr int64_t flush_threshold_size = 4096;
    static constexpr int64_t flush_threshold_size = 100;
    static constexpr int64_t flush_data_threshold_size = flush_threshold_size - sizeof(log_group_header);

    static LogDev* instance() {
        static LogDev _instance;
        return &_instance;
    }

    /**
     * @brief Append the data to the log device asynchronously. The buffer that is passed is expected to be valid, till
     * the append callback is done.
     *
     * @param data : Pointer to the data to be appended
     * @param size : Size of the data. At this point it does not support size > Max_Atomic_Page_size of underlying
     * structure which could be 8K
     * @param cb_context Context to put upon a callback once append is. Upon completion the registered callback is
     * called.
     *
     * @return logid_t : log_idx of the log of the data.
     */
    logid_t append(uint8_t* data, uint32_t size, void* cb_context);

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
    log_buffer read(const log_key& key);

    /**
     * @brief Load the data from the blkstore starting with offset. This method loads data in bulk and then call the
     * registered logfound_cb with key and buffer.
     * NOTE: This method is not thread safe. It is expected to be called during recovery
     *
     * @param offset Log blkstore device offset.
     */
    void load(uint64_t offset);

    /**
     * @brief Register the callback to receive upon completion of append.
     * NOTE: This method is not thread safe.
     *
     * @param cb Callback to call upon completion of append. It will call with 2 parameters
     * a) log_key: The key to access the log dev data. It can be treated as opaque (internally has log_id and device
     * offset)
     * b) Context: The context which was passed to append method.
     */
    void register_append_cb(const log_append_comp_callback& cb) { m_append_comp_cb = cb; }

    /**
     * @brief Register the callback to receive new logs during recovery from the device.
     * NOTE: This method is not thread safe.
     *
     * @param cb Callback to call upon completion of append. It will call with 3 parameters
     * a) log_key: The key to access the log dev data, which is retrieved from the device. It can be treated as opaque
     * (internally has log_id and device offset)
     * b) log_buffer: Opaque structure which contains the data and size of the log which key refers to. The underlying
     * buffer it returns is ref counted and hence it need not be explicitly freed.
     */
    void register_logfound_cb(const log_found_callback& cb) { m_logfound_cb = cb; }

    // callback from blkstore, registered at blkstore creation;
    void process_logdev_completions(const boost::intrusive_ptr< blkstore_req< BlkBuffer > >& bs_req);

#if 0
    // returns offset
    bool append_write(struct iovec* iov, int iovcnt, uint64_t& out_offset, logdev_comp_callback cb);

    bool write_at_offset(const uint64_t offset, struct iovec* iov, int iovcnt, logdev_comp_callback cb);

    //
    // read is sync
    // return actual bytes read on success or -1 on failure
    //
    ssize_t read(const uint64_t offset, const uint64_t size, const void* buf);

    ssize_t readv(const uint64_t offset, struct iovec* iov, int iovcnt);

    // truncate
    void truncate(const uint64_t offset);

    // Group Commit
#endif

    crc32_t get_prev_crc() const { return m_last_crc; }

private:
#if 0
    // header verification
    bool header_verify(LogDevRecordHeader* hdr);

    // copy iov pointers and len
    bool copy_iov(struct iovec* dest, struct iovec* src, int iovcnt);

    //
    // Reserve offset,
    // Current assumption is single threaded;
    //
    uint64_t reserve(const uint64_t size);
#endif

    LogDev() = default;
    ~LogDev() = default;
    static LogGroup* new_log_group();

    LogGroup* prepare_flush(int32_t estimated_record);
    void do_flush(LogGroup* lg);
    void flush_if_needed(const uint32_t new_record_size, logid_t new_idx = -1);
    void on_flush_completion(LogGroup* lg);
    // sisl::blob do_read(uint32_t offset, uint32_t size, uint8_t* already_read_buf, uint32_t already_read_size);
    void do_load(uint64_t offset);

private:
    sisl::StreamTracker< log_record > m_log_records; // The container which stores all in-memory log records
    std::atomic< logid_t > m_log_idx = 0;            // Generator of log idx
    std::atomic< int64_t > m_pending_flush_size = 0; // How much flushable logs are pending
    std::atomic< bool > m_is_flushing = false; // Is LogDev currently flushing (so far supports one flusher at a time)

    logid_t m_last_flush_idx = -1; // Track last flushed and truncated log idx
    logid_t m_last_truncate_idx = -1;

    crc32_t m_last_crc = INVALID_CRC32_VALUE;
    log_append_comp_callback m_append_comp_cb = nullptr;
    log_found_callback m_logfound_cb = nullptr;

}; // LogDev
} // namespace homestore
