#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <ostream>
#include <set>
#include <vector>

#include <boost/intrusive_ptr.hpp>
#include <fds/id_reserver.hpp>
#include <fds/stream_tracker.hpp>
#include <fds/utils.hpp>
#include <fmt/format.h>
#include <sds_logging/logging.h>

#include "engine/blkstore/blkstore.hpp"
#include "engine/homestore_base.hpp"
#include "homelogstore/logstore_header.hpp"

namespace homestore {

static constexpr uint32_t LOG_GROUP_HDR_MAGIC{0xDABAF00D};
static constexpr uint32_t dma_address_boundary{512}; // Mininum size the dma/writes to be aligned with
static constexpr uint32_t initial_read_size{4096};

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
#pragma pack(1)
struct serialized_log_record {
    uint32_t size;                    // Size of this log record
    uint32_t offset : 31;             // Offset within the log_group where data is residing
    uint32_t is_inlined : 1;          // Is the log data is inlined or out-of-band area
    logstore_seq_num_t store_seq_num; // Seqnum by the log store
    logstore_id_t store_id;           // ID of the store this log is associated with

    void set_inlined(const bool inlined) { is_inlined = static_cast< uint32_t >(inlined ? 0x1 : 0x0); }
    [[nodiscard]] bool get_inlined() const { return ((is_inlined == static_cast< uint32_t >(0x1)) ? true : false); }

    serialized_log_record() = default;
    serialized_log_record(const uint32_t s, const uint32_t o, const bool inlined, const logstore_seq_num_t sq,
                          const logstore_id_t id) :
            size{s}, offset{o}, store_seq_num{sq}, store_id{id} {
        set_inlined(inlined);
    }
    serialized_log_record(const serialized_log_record&) = default;
    serialized_log_record& operator=(const serialized_log_record&) = default;
    serialized_log_record(serialized_log_record&&) noexcept = default;
    serialized_log_record& operator=(serialized_log_record&&) noexcept = default;
    ~serialized_log_record() = default;
};
#pragma pack()

/* This structure represents the in-memory representation of a log record */
struct log_record {
    serialized_log_record* pers_record{nullptr};
    uint8_t* data_ptr;
    uint32_t size;
    void* context;
    logstore_id_t store_id;
    logstore_seq_num_t seq_num;

    log_record(const logstore_id_t sid, const logstore_seq_num_t snum, uint8_t* const d, const uint32_t sz, void* const ctx) :
            data_ptr{d}, size{sz}, context{ctx}, store_id{sid}, seq_num{snum} {}
    log_record(const log_record&) = delete;
    log_record& operator=(const log_record&) = delete;
    log_record(log_record&&) noexcept = delete;
    log_record& operator=(log_record&&) noexcept = delete;
    ~log_record() = default;

    [[nodiscard]] size_t inlined_size() const { return sizeof(serialized_log_record) + (is_inlineable() ? size : 0); }
    [[nodiscard]] size_t serialized_size() const { return sizeof(serialized_log_record) + size; }
    [[nodiscard]] bool is_inlineable() const {
        // Need inlining if size is smaller or size/buffer is not in dma'ble boundary.
        return (is_size_inlineable(size) || ((reinterpret_cast< uintptr_t >(data_ptr) % dma_boundary()) != 0));
    }

    [[nodiscard]] static size_t dma_boundary() { return HS_STATIC_CONFIG(drive_attr.phys_page_size); }
    [[nodiscard]] static bool is_size_inlineable(const size_t sz) {
        return ((sz < HS_DYNAMIC_CONFIG(logstore.optimal_inline_data_size)) || ((sz % dma_boundary()) != 0));
    }

    [[nodiscard]] static size_t serialized_size(const uint32_t sz) { return sizeof(serialized_log_record) + sz; }
};

/************************************* Log Group Section ************************************/
/* This structure represents a group commit log header */
#pragma pack(1)
struct log_group_header {
    uint32_t magic;
    uint32_t n_log_records;      // Total number of log records
    logid_t start_log_idx;       // log id of the first log record
    uint32_t group_size;         // Total size of this group including this header
    uint32_t inline_data_offset; // Offset of inlined area of data
    uint32_t oob_data_offset;    // Offset of where the data which are not inlined starts
    crc32_t prev_grp_crc;        // Checksum of the previous group that was written
    crc32_t cur_grp_crc;         // Checksum of the current group record

    log_group_header() = default;
    log_group_header(const log_group_header&) = delete;
    log_group_header& operator=(const log_group_header&) = delete;
    log_group_header(log_group_header&&) noexcept = delete;
    log_group_header& operator=(log_group_header&&) noexcept = delete;
    ~log_group_header() = default;

    [[nodiscard]] uint32_t inline_data_size() const {
        return oob_data_offset ? (oob_data_offset - inline_data_offset) : (group_size - inline_data_offset);
    }

    [[nodiscard]] const uint8_t* inline_area() const {
        return (reinterpret_cast< const uint8_t* >(this) + inline_data_offset);
    }
    [[nodiscard]] const uint8_t* oob_area() const {
        return (reinterpret_cast< const uint8_t* >(this) + oob_data_offset);
    }
    [[nodiscard]] const uint8_t* record_area() const {
        return (reinterpret_cast< const uint8_t* >(this) + sizeof(log_group_header));
    }

    [[nodiscard]] const serialized_log_record* nth_record(const uint32_t n) const {
        return reinterpret_cast< const serialized_log_record* >(record_area() + (sizeof(serialized_log_record) * n));
    }

    [[nodiscard]] sisl::blob data(const logid_t idx) const {
        assert(idx >= start_log_idx);
        assert(idx - start_log_idx < n_log_records);

        const serialized_log_record* const lr{nth_record(start_log_idx - idx)};

        sisl::blob b{};
        b.bytes = const_cast< uint8_t* >(lr->get_inlined() ? inline_area() : oob_area()) + lr->offset;
        b.size = lr->size;
        return b;
    }

    [[nodiscard]] uint32_t magic_word() const { return magic; }
    [[nodiscard]] logid_t start_idx() const { return start_log_idx; }
    [[nodiscard]] uint32_t nrecords() const { return n_log_records; }
    [[nodiscard]] uint32_t total_size() const { return group_size; }
    [[nodiscard]] crc32_t this_group_crc() const { return cur_grp_crc; }
    [[nodiscard]] crc32_t prev_group_crc() const { return prev_grp_crc; }
    [[nodiscard]] uint32_t _inline_data_offset() const { return inline_data_offset; }
};
#pragma pack()

template < typename charT, typename traits >
std::basic_ostream< charT, traits >& operator<<(std::basic_ostream< charT, traits >& out_stream,
                                                const log_group_header& header) {
    // copy the stream formatting
    std::basic_ostringstream< charT, traits > out_string_stream;
    out_string_stream.copyfmt(out_stream);

    // print the stream
    const auto s{fmt::format("magic = {} n_log_records = {} start_log_idx = {} group_size = {} inline_data_offset = {} "
                         "oob_data_offset = {} prev_grp_crc = {} cur_grp_crc = {}",
                             header.magic, header.n_log_records, header.start_log_idx, header.group_size,
                             header.inline_data_offset, header.oob_data_offset, header.prev_grp_crc,
                             header.cur_grp_crc)};
    out_string_stream << s;
    out_stream << out_string_stream.str();

    return out_stream;
}

struct iovec_wrapper : public iovec {
    iovec_wrapper(void* const base, const size_t len) : iovec{base, len} {}
    iovec_wrapper(const iovec_wrapper&) = default;
    iovec_wrapper& operator=(const iovec_wrapper&) = default;
    iovec_wrapper(iovec_wrapper&&) noexcept = default;
    iovec_wrapper& operator=(iovec_wrapper&&) noexcept = default;
    ~iovec_wrapper() = default;
};
typedef std::vector< iovec_wrapper > iovec_array;

/* In memory representation of a log group which will be written as a group together */
class LogGroup {
public:
    /* These are going to be compile time constants to build the inline array, so they are not using dynamic
     * settings to change them */
    static constexpr uint32_t optimal_num_records{16};
    static constexpr uint32_t estimated_iovs{10};
    static constexpr size_t inline_log_buf_size{512 * optimal_num_records};
    static constexpr uint32_t max_records_in_a_batch{(initial_read_size - sizeof(log_group_header)) /
                                                     sizeof(serialized_log_record)};

    friend class LogDev;

    LogGroup();
    LogGroup(const LogGroup&) = delete;
    LogGroup& operator=(const LogGroup&) = delete;
    LogGroup(LogGroup&&) noexcept = delete;
    LogGroup& operator=(LogGroup&&) noexcept = delete;
    ~LogGroup() = default;

    void reset(const uint32_t max_records);
    void create_overflow_buf(const uint32_t min_needed);
    [[nodiscard]] bool add_record(const log_record& record, const int64_t log_idx);
    [[nodiscard]] bool can_accomodate(const log_record& record) const { return (m_nrecords <= m_max_records); }

    const iovec_array& finish();
    crc32_t compute_crc();

    [[nodiscard]] log_group_header* header() { return reinterpret_cast< log_group_header* >(m_cur_log_buf); }
    [[nodiscard]] const log_group_header* header() const {
        return reinterpret_cast< const log_group_header* >(m_cur_log_buf);
    }
    [[nodiscard]] iovec_array& iovecs() { return m_iovecs; }
    // uint32_t data_size() const { return header()->group_size - sizeof(log_group_header); }
    [[nodiscard]] uint32_t actual_data_size() const { return m_actual_data_size; }
    [[nodiscard]] uint32_t nrecords() const { return m_nrecords; }

private:
    sisl::aligned_unique_ptr< uint8_t > m_log_buf;
    sisl::aligned_unique_ptr< uint8_t > m_overflow_log_buf;

    uint8_t* m_cur_log_buf;
    uint32_t m_cur_buf_len;

    serialized_log_record* m_record_slots;
    uint32_t m_inline_data_pos;
    uint32_t m_oob_data_pos;

    uint32_t m_nrecords{0};
    uint32_t m_max_records{0};
    uint32_t m_actual_data_size{0};

    // Info about the final data
    iovec_array m_iovecs;
    int64_t m_flush_log_idx_from;
    int64_t m_flush_log_idx_upto;
    off_t m_log_dev_offset;
};

template < typename charT, typename traits >
std::basic_ostream< charT, traits >& operator<<(std::basic_ostream< charT, traits >& out_stream,
                                                const LogGroup& lg) {
    // copy the stream formatting
    std::basic_ostringstream< charT, traits > out_string_stream;
    out_string_stream.copyfmt(out_stream);

    // print the stream
    const auto* const header{reinterpret_cast<const log_group_header*>(lg.m_cur_log_buf)};
    const auto s{fmt::format("Header:[{}]\nLog_idx_range: [{} - {}] DevOffset: {} Max_Records: {} IOVecSize: {}\n"
                             "-----------------------------------------------------------------\n",
                             *header, lg.m_flush_log_idx_from, lg.m_flush_log_idx_upto, lg.m_log_dev_offset,
                             lg.m_max_records, lg.m_iovecs.size())};
    out_string_stream << s;
    out_stream << out_string_stream.str();

    return out_stream;
}

/************************************* LogDev Request to BlkStore Section ************************************/
struct logdev_req;
#define to_logdev_req(req) boost::static_pointer_cast< logdev_req >(req)
typedef boost::intrusive_ptr< logdev_req > logdev_req_ptr;

struct logdev_req : public blkstore_req< BlkBuffer > {
public:
    [[nodiscard]] static boost::intrusive_ptr< logdev_req > make_request() {
        return boost::intrusive_ptr< logdev_req >(sisl::ObjectAllocator< logdev_req >::make_object());
    }

    virtual void free_yourself() override { sisl::ObjectAllocator< logdev_req >::deallocate(this); }

    logdev_req(const logdev_req&) = delete;
    logdev_req& operator=(const logdev_req&) = delete;
    logdev_req(logdev_req&&) noexcept = delete;
    logdev_req& operator=(logdev_req&&) noexcept = delete;
    virtual ~logdev_req() override = default;

    // virtual size_t get_your_size() const override { return sizeof(ssd_loadgen_req); }

    [[nodiscard]] static logdev_req_ptr cast(const boost::intrusive_ptr< blkstore_req< BlkBuffer > >& bs_req) {
        return boost::static_pointer_cast< logdev_req >(bs_req);
    }

    LogGroup* m_log_group;

protected:
    friend class sisl::ObjectAllocator< logdev_req >;

private:
    logdev_req() = default;
};

typedef int64_t logid_t;
struct logdev_key {
    constexpr logdev_key(const logid_t idx = std::numeric_limits< logid_t >::min(),
                         const off_t dev_offset = std::numeric_limits< uint64_t >::min()) :
            idx{idx}, dev_offset{dev_offset} {}
    logdev_key(const logdev_key&) = default;
    logdev_key& operator=(const logdev_key&) = default;
    logdev_key(logdev_key&&) noexcept = default;
    logdev_key& operator=(logdev_key&&) noexcept = default;
    ~logdev_key() = default;

    bool operator==(const logdev_key& other) { return (other.idx == idx) && (other.dev_offset == dev_offset); }

    operator bool() const { return is_valid(); }
    bool is_valid() const { return !is_lowest() && !is_highest(); }

    bool is_lowest() const { return (idx == std::numeric_limits< logid_t >::min()); }
    bool is_highest() const { return (idx == std::numeric_limits< logid_t >::max()); }

    void set_lowest() {
        idx = std::numeric_limits< logid_t >::min();
        dev_offset = std::numeric_limits< uint64_t >::min();
    }

    void set_highest() {
        idx = std::numeric_limits< logid_t >::max();
        dev_offset = std::numeric_limits< uint64_t >::max();
    }

    static const logdev_key& out_of_bound_ld_key()
    {
        static constexpr logdev_key s_out_of_bound_ld_key{std::numeric_limits< logid_t >::max(), 0};
        return s_out_of_bound_ld_key;
    }

    logid_t idx;
    off_t dev_offset;
};

template < typename charT, typename traits >
std::basic_ostream< charT, traits >& operator<<(std::basic_ostream< charT, traits >& out_stream,
                                                const logdev_key& key) {

    // copy the stream formatting
    std::basic_ostringstream< charT, traits > out_string_stream;
    out_string_stream.copyfmt(out_stream);

    // print the stream
    out_string_stream << "[idx=" << key.idx << " dev_offset=" << key.dev_offset << "]";
    out_stream << out_string_stream.str();

    return out_stream;
}

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
using log_buffer = sisl::byte_view;

struct truncation_request_t {
    logstore_id_t store_id;
    logstore_seq_num_t upto_seq_num;
};

/* This structure represents the logdevice super block which will be loaded upto start of the homestore */
struct logstore_meta;

#pragma pack(1)
struct logdev_superblk {
    static constexpr uint32_t LOGDEV_SB_VERSION{1};

    uint32_t version{LOGDEV_SB_VERSION};
    uint32_t num_stores{0};
    off_t start_dev_offset{0};
    logid_t last_log_idx;

    [[nodiscard]] uint32_t get_version() const { return version; }
    // The meta data starts immediately after the super block
    [[nodiscard]] logstore_meta* get_logstore_meta() {
        return reinterpret_cast< logstore_meta* >(reinterpret_cast< uint8_t* >(this) + sizeof(logdev_superblk));
    }
    [[nodiscard]] const logstore_meta* get_logstore_meta() const {
        return reinterpret_cast< const logstore_meta* >(reinterpret_cast< const uint8_t* >(this) +
                                                        sizeof(logdev_superblk));
    }
};
#pragma pack()

class logstore_meta;
// This class represents the metadata of logdev providing methods to change/access log dev super block.
class LogDevMetadata {
public:
    LogDevMetadata() = default;
    LogDevMetadata(const LogDevMetadata&) = delete;
    LogDevMetadata& operator=(const LogDevMetadata&) = delete;
    LogDevMetadata(LogDevMetadata&&) noexcept = delete;
    LogDevMetadata& operator=(LogDevMetadata&&) noexcept = delete;
    ~LogDevMetadata() = default;

    [[nodiscard]] logdev_superblk* create();
    void reset();
    void meta_buf_found(const sisl::byte_view& buf, void* const meta_cookie);
    [[nodiscard]] std::vector< std::pair< logstore_id_t, logstore_meta > > load();
    void persist();

    [[nodiscard]] bool is_empty() const { return (m_sb == nullptr); }
    [[nodiscard]] inline off_t get_start_dev_offset() const { return (m_sb->start_dev_offset); }
    [[nodiscard]] logid_t get_last_log_indx() const { return (m_sb->last_log_idx); }
    void update_start_dev_offset(const off_t offset, logid_t id, const bool persist_now);

    [[nodiscard]] logstore_id_t reserve_store(const bool persist_now);
    void unreserve_store(const logstore_id_t idx, const bool persist_now);
    [[nodiscard]] const std::set< logstore_id_t >& reserved_store_ids() const { return m_store_info; }

    void update_store_meta(const logstore_id_t idx, const logstore_meta& meta, const bool persist_now);
    [[nodiscard]] logstore_meta& mutable_store_meta(const logstore_id_t idx);

private:
    [[nodiscard]] bool resize_if_needed();

    [[nodiscard]] uint32_t required_sb_size(const uint32_t nstores) const {
        return sisl::round_up(size_needed(nstores), HS_STATIC_CONFIG(drive_attr.phys_page_size));
    }

    [[nodiscard]] uint32_t size_needed(const uint32_t nstores) const {
        return sizeof(logdev_superblk) + (nstores * sizeof(logstore_seq_num_t));
    }

    [[nodiscard]] uint32_t store_capacity() const;

    sisl::byte_view m_raw_buf;
    logdev_superblk* m_sb{nullptr};
    void* m_meta_mgr_cookie{nullptr};
    std::unique_ptr< sisl::IDReserver > m_id_reserver;
    std::set< logstore_id_t > m_store_info;
};

class log_stream_reader {
public:
    log_stream_reader(const off_t device_cursor);
    log_stream_reader(const log_stream_reader&) = delete;
    log_stream_reader& operator=(const log_stream_reader&) = delete;
    log_stream_reader(log_stream_reader&&) noexcept = delete;
    log_stream_reader& operator=(log_stream_reader&&) noexcept = delete;
    ~log_stream_reader() = default;

    [[nodiscard]] sisl::byte_view next_group(off_t* const out_dev_offset);
    [[nodiscard]] sisl::byte_view group_in_next_page();

private:
    [[nodiscard]] sisl::byte_view read_next_bytes(const uint64_t nbytes);

private:
    boost::intrusive_ptr< HomeStoreBase > m_hb;
    sisl::byte_view m_cur_log_buf;
    off_t m_first_group_cursor;
    off_t m_cur_read_bytes{0};
    crc32_t m_prev_crc{0};
};

enum log_dump_verbosity : uint8_t { CONTENT, HEADER };

class LogDev {
public:
    // NOTE: Possibly change these in future to include constant correctness
    typedef std::function< void(logstore_id_t, logdev_key, logdev_key, uint32_t nremaining_in_batch, void*) >
        log_append_comp_callback;
    typedef std::function< void(logstore_id_t, logstore_seq_num_t, logdev_key, log_buffer) > log_found_callback;
    typedef std::function< void(logstore_id_t, const logstore_meta&) > store_found_callback;
    typedef std::function< void(void) > flush_blocked_callback;

    [[nodiscard]] static inline int64_t flush_data_threshold_size() {
        return HS_DYNAMIC_CONFIG(logstore.flush_threshold_size) - sizeof(log_group_header);
    }

    LogDev();
    LogDev(const LogDev&) = delete;
    LogDev& operator=(const LogDev&) = delete;
    LogDev(LogDev&&) noexcept = delete;
    LogDev& operator=(LogDev&&) noexcept = delete;
    ~LogDev();

    /**
     * @brief Start the logdev. This method reads the log virtual dev info block, loads all of the store and prepares
     * to the recovery. It is expected that all callbacks are registered before calling the start.
     *
     * @param format: Do we need to format the logdev or not.
     */
    void start(const bool format);

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
    [[nodiscard]] logid_t append_async(const logstore_id_t store_id, const logstore_seq_num_t seq_num, uint8_t* const data, const uint32_t size,
                         void* const cb_context);

    /**
     * @brief Read the log id from the device offset
     *
     * @param idx log_id to read
     * @param dev_offset device offset of the log id which was provided upon append. This is needed to locate the log
     * idx within the device. A log data can be looked up only by pair of log_id and dev_offset.
     *
     * @param record_header Pass the pointer to the header of the read record
     *
     * @return log_buffer : Opaque structure which contains the data blob and its size. It is safe buffer and hence it
     * need not be freed and can be cheaply passed it around.
     */
    [[nodiscard]] log_buffer read(const logdev_key& key, serialized_log_record& record_header);

    /**
     * @brief Load the data from the blkstore starting with offset. This method loads data in bulk and then call
     * the registered logfound_cb with key and buffer. NOTE: This method is not thread safe. It is expected to be called
     * during recovery
     *
     * @param offset Log blkstore device offset.
     */
    void load(const uint64_t offset);

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
     * @return uint32_t : Return the reserved id
     */
    [[nodiscard]] logstore_id_t reserve_store_id();

    /**
     * @brief Unreserve the logstore id. It does not immediately unregisters and persist the unregistered map, but it
     * will add to the waiting list (garbage list) and then during truncation, it actually unreserves and persits map.
     *
     * @param store_id
     */
    void unreserve_store_id(const uint32_t store_id);

    /**
     * @brief Is the given store id already reserved.
     *
     * @return true or false
     */
    [[nodiscard]] bool is_reserved_store_id(const logstore_id_t id);

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

    [[nodiscard]] crc32_t get_prev_crc() const { return m_last_crc; }

    /**
     * @brief This method attempts to block the log flush and then make a callback cb. If it is already blocked,
     * then after previous flush is completed, it will make the callback (while log flush is still under blocked state)
     *
     * @param cb Callback
     * @return true or false based on if it is able to block the flush right away.
     */
    [[nodiscard]] bool try_lock_flush(const flush_blocked_callback& cb);

    /**
     * @brief Unblock the flush. While unblocking if there are other requests to block or any flush pending it first
     * executes them before unblocking
     */
    void unlock_flush();

    /**
     * @brief : truncate up to input log id;
     *
     * @param key : the key containing log id that needs to be truncate up to;
     * @return number of records to truncate
     */
    [[nodiscard]] uint64_t truncate(const logdev_key& key);
    void meta_blk_found(meta_blk* const mblk, const sisl::byte_view buf, const size_t size);

    void update_store_meta(const logstore_id_t idx, const logstore_meta& meta, const bool persist_now);

private:
    [[nodiscard]] LogGroup* make_log_group(const uint32_t estimated_records) {
        m_log_group_idx = !m_log_group_idx;
        m_log_group_pool[m_log_group_idx].reset(estimated_records);
        return &m_log_group_pool[m_log_group_idx];
    }

    [[nodiscard]] LogGroup* prepare_flush(const int32_t estimated_record);
    void do_flush(LogGroup* const lg);
    void flush_if_needed(const uint32_t new_record_size = 0, logid_t new_idx = -1);
    void flush_by_size(const uint32_t min_threshold, const uint32_t new_record_size = 0, const logid_t new_idx = -1);
    void on_flush_completion(LogGroup* const lg);
    void do_load(const off_t offset);

#if 0
    log_group_header* read_validate_header(uint8_t* buf, uint32_t size, bool* read_more);
    sisl::byte_array read_next_header(uint32_t max_buf_reads);
#endif

    void _persist_info_block();
    void assert_next_pages(log_stream_reader& lstream);

private:
    boost::intrusive_ptr< HomeStoreBase > m_hb; // Back pointer to homestore
    std::unique_ptr< sisl::StreamTracker< log_record > >
        m_log_records;                               // The container which stores all in-memory log records
    std::atomic< logid_t > m_log_idx{0};             // Generator of log idx
    std::atomic< int64_t > m_pending_flush_size{0};  // How much flushable logs are pending
    std::atomic< bool > m_is_flushing{false}; // Is LogDev currently flushing (so far supports one flusher at a time)
    bool m_stopped{false}; // Is Logdev stopped. We don't need lock here, because it is updated under flush lock
    std::map< logid_t, logstore_id_t > m_garbage_store_ids;
    Clock::time_point m_last_flush_time;

    logid_t m_last_flush_idx{-1}; // Track last flushed and truncated log idx
    logid_t m_last_truncate_idx{-1};

    crc32_t m_last_crc{INVALID_CRC32_VALUE};
    log_append_comp_callback m_append_comp_cb{nullptr};
    log_found_callback m_logfound_cb{nullptr};
    store_found_callback m_store_found_cb{nullptr};

    // LogDev Info block related fields
    std::mutex m_meta_mutex;
    LogDevMetadata m_logdev_meta;

    // Block flush Q request Q
    std::mutex m_block_flush_q_mutex;
    std::vector< flush_blocked_callback >* m_block_flush_q;

    // Timer handle
    iomgr::timer_handle_t m_flush_timer_hdl;
    void* m_sb_cookie{nullptr};

    // Pool for creating log group
    LogGroup m_log_group_pool[2];
    uint32_t m_log_group_idx{1};
}; // LogDev

} // namespace homestore
