#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <system_error>
#include <vector>

#include <fds/buffer.hpp>
#include <metrics/metrics.hpp>
#include <nlohmann/json.hpp>

namespace homestore {

// forward declarations
struct meta_blk_ovf_hdr;
struct meta_blk_sb;
struct meta_blk;
struct sb_blkstore_blob;
struct MetaSubRegInfo;
struct BlkId;
class BlkBuffer;
template < typename BAllocator, typename Buffer >
class BlkStore;
class VdevVarSizeBlkAllocatorPolicy;

typedef homestore::BlkStore< homestore::VdevVarSizeBlkAllocatorPolicy, BlkBuffer > blk_store_t;
// each subsystem could receive callbacks multiple times
// NOTE: look at this prototype some other time for const correctness and efficiency
typedef std::function< void(meta_blk* mblk, sisl::byte_view buf,
                            size_t size) >
    meta_blk_found_cb_t;                                                // new blk found subsystem callback
typedef std::function< void(bool success) > meta_blk_recover_comp_cb_t; // recover complete subsystem callbacks;
typedef std::map< uint64_t, meta_blk* > meta_blk_map_t;                 // blkid to meta_blk map;
typedef std::map< uint64_t, meta_blk_ovf_hdr* > ovf_hdr_map_t;          // ovf_blkid to ovf_blk_hdr map;
typedef std::string meta_sub_type;

class MetablkMetrics : public sisl::MetricsGroupWrapper {
public:
    explicit MetablkMetrics(const char* const inst_name) : sisl::MetricsGroupWrapper{"MetaBlkStore", inst_name} {
        REGISTER_COUNTER(compress_success_cnt, "compression successful cnt");
        REGISTER_COUNTER(compress_backoff_memory_cnt, "compression back-off cnt because of exceending memory limit")
        REGISTER_COUNTER(compress_backoff_ratio_cnt, "compression back-off cnt because of exceeding ratio limit");

        REGISTER_HISTOGRAM(compress_ratio_percent, "compression ration percentage");
        register_me_to_farm();
    }

    MetablkMetrics(const MetablkMetrics&) = delete;
    MetablkMetrics& operator=(const MetablkMetrics&) = delete;
    MetablkMetrics(MetablkMetrics&&) noexcept = delete;
    MetablkMetrics& operator=(MetablkMetrics&&) noexcept = delete;

    ~MetablkMetrics() { deregister_me_from_farm(); }
};

class MetaBlkMgr {
private:
    static std::unique_ptr< MetaBlkMgr > s_instance;
    static bool m_self_recover;
    blk_store_t* m_sb_blk_store{nullptr}; // super blockstore
    std::mutex m_meta_mtx;                // mutex to access to meta_map;
    std::mutex m_shutdown_mtx;            // protects concurrent operations between recover and shutdown;
    meta_blk_map_t m_meta_blks;           // subsystem type to meta blk map;
    ovf_hdr_map_t m_ovf_blk_hdrs;         // ovf blk map;
    std::map< meta_sub_type, MetaSubRegInfo > m_sub_info; // map of callbacks
    std::unique_ptr< BlkId > m_last_mblk_id;              // last meta blk;
    meta_blk_sb* m_ssb{nullptr};                          // meta super super blk;
    sisl::blob m_compress_info;
    MetablkMetrics m_metrics;

public:
    MetaBlkMgr(const char* const name = "MetaBlkStore");
    MetaBlkMgr(const MetaBlkMgr&) = delete;
    MetaBlkMgr(MetaBlkMgr&&) noexcept = delete;
    MetaBlkMgr& operator=(const MetaBlkMgr&) = delete;
    MetaBlkMgr& operator=(MetaBlkMgr&&) noexcept = delete;

    ~MetaBlkMgr();

    /**
     * @brief :
     *
     * @param sb_blk_store : superblock store
     * @param blob : super block store vb context data blob
     * @param init : true of initialized, false if recovery
     * @return
     */
    void start(blk_store_t* const sb_blk_store, const sb_blkstore_blob* const blob, const bool is_init);

    void stop();

    /**
     * @brief
     *
     * @return
     */
    static MetaBlkMgr* instance();

    /* Note: it assumes that it is called in a single thread */
    static void fake_reboot();

    static void del_instance();

    /**
     * @brief : Register subsystem callbacks
     * @param type : subsystem type
     * @param cb : subsystem cb
     */
    void register_handler(const meta_sub_type type, const meta_blk_found_cb_t& cb,
                          const meta_blk_recover_comp_cb_t& comp_cb, const bool do_crc = true);

    /**
     * @brief
     *
     * @param type
     */
    void deregister_handler(const meta_sub_type type);

    /**
     * @brief : add subsystem superblock to meta blk mgr
     *
     * @param type : subsystem type
     * @param context_data : subsystem sb
     * @param sz : size of context_data
     * @param cookie : returned handle by meta blk mgr.
     *                 Subsystem is supposed to use this cookie to do update and remove of the sb;
     *
     */
    void add_sub_sb(const meta_sub_type type, const void* const context_data, const uint64_t sz, void*& cookie);

    /**
     * @brief : remove subsystem sb based on cookie
     *
     * @param cookie : handle address unique subsystem sb that is being removed;
     *
     * @return : ok on success, not-ok on failure;
     */
    [[nodiscard]] std::error_condition remove_sub_sb(void* const cookie);

    /**
     * @brief : update metablk in-place
     *
     * @param type : type of subsytem
     * @param context_data : subsytem sb;
     * @param sz : size of context_data
     * @param cookie : handle to address the unique subsytem sb that is being updated;
     */
    void update_sub_sb(const void* const context_data, const uint64_t sz, void*& cookie);

    // size_t read_sub_sb(const meta_sub_type type, sisl::byte_view& buf);
    void read_sub_sb(const meta_sub_type type);

    /**
     * @brief :
     *
     * @return
     */
    bool migrated();

    void set_migrated();

    /**
     * @brief : Callback to each subsytem for each meta rec based on priority
     *
     * @return :
     */
    void recover(const bool do_comp_cb = true);

    /**
     * @brief : scan the blkstore to load meta blks into memory
     */
    void scan_meta_blks();

    [[nodiscard]] uint64_t get_size() const;

    [[nodiscard]] uint64_t get_used_size() const;

    [[nodiscard]] bool is_aligned_buf_needed(const size_t size);

    [[nodiscard]] uint32_t get_page_size() const;

    [[nodiscard]] uint64_t get_available_blks() const;

    /**
     * @brief : Return the total space used in bytes that was occupied by this meta blk;
     *          Currently used for testing only.
     *
     * @param cookie : hanlde to meta blk;
     *
     * @return : size of space occupied by this meta blk;
     */
    [[nodiscard]] uint64_t get_meta_size(const void* const cookie) const;

    [[nodiscard]] uint64_t meta_blk_context_sz() const;

    [[nodiscard]] uint64_t ovf_blk_max_num_data_blk() const;

    /**
     * @brief : called by client or by metablkmgr to check the sanity of cookie being sent back to client or received
     * from client;
     *
     * @param cookie
     */
    void cookie_sanity_check(const void* const cookie);

public:
    /*********************** static public function **********************/
    static void set_self_recover() { m_self_recover = true; }

    static void reset_self_recover() { m_self_recover = false; }

    static bool is_self_recovered() { return m_self_recover; }

private:
    /**
     * @brief
     *
     * @param type
     *
     * @return
     */
    [[nodiscard]] bool is_sub_type_valid(const meta_sub_type type);

    /**
     * @brief : write in-memory copy of meta_blk to disk;
     *
     * @param mblk
     *
     * @return
     */
    void write_meta_blk_to_disk(meta_blk* const mblk);

    void write_ovf_blk_to_disk(meta_blk_ovf_hdr* const ovf_hdr, const void* const context_data, const uint64_t sz,
                               const uint64_t offset, const std::string& type);

    /**
     * @brief : load meta blk super super block into memory
     *
     * @param bid : the blk id that belongs to meta ssb;
     */
    void load_ssb(const sb_blkstore_blob* const blob);

    /**
     * @brief : init super super block
     *
     * @return
     */
    void init_ssb();

    /**
     * @brief : Write MetaBlkMgr's superblock to disk;
     */
    void write_ssb();

    /**
     * @brief : Allocate meta BlkId
     *
     */
    void alloc_meta_blk(BlkId& bid);
    void alloc_meta_blk(const uint64_t size, std::vector< BlkId >& bid);

    void free_meta_blk(meta_blk* const mblk);

    /**
     * @brief : free the overflow blk chain
     *  1. free on-disk overflow blk header
     *  2. free on-disk data blk
     *  3. free in-memory copy of ovf blk header;
     *  4. remove from ovf hdr map;
     * @param obid : the start ovf blk id in the chain;
     */
    void free_ovf_blk_chain(const BlkId& obid);

    /**
     * @brief : Initialize meta blk
     *
     * @param bid
     *
     * @return
     */
    [[nodiscard]] meta_blk* init_meta_blk(BlkId& bid, const meta_sub_type type, const void* const context_data,
                                          const size_t sz);

    /**
     * @brief
     *
     * @param bid
     * @param context_data
     * @param sz
     * @param offset
     */
    void write_meta_blk_ovf(BlkId& bid, const void* const context_data, const uint64_t sz, const std::string& type);

    /**
     * @brief : internal implementation of populating and writing a meta block;
     *
     * @param mblk
     * @param context_data
     * @param sz
     */
    void write_meta_blk_internal(meta_blk* const mblk, const void* context_data, const uint64_t sz);

    /**
     * @brief : sync read;
     *
     * @param bid
     * @param b
     */
    void read(const BlkId& bid, void* const dest, const size_t sz) const;

    void cache_clear();

    /**
     * @brief
     *
     * @param mblk
     * @param buf
     */
    sisl::byte_array read_sub_sb_internal(const meta_blk* const mblk) const;

    void free_compress_buf();
    void alloc_compress_buf(size_t size);

    [[nodiscard]] uint64_t get_min_compress_size() const;
    [[nodiscard]] uint64_t get_max_compress_memory_size() const;
    [[nodiscard]] uint64_t get_init_compress_memory_size() const;
    [[nodiscard]] uint32_t get_compress_ratio_limit() const;
    [[nodiscard]] bool compress_feature_on() const;

    [[nodiscard]] nlohmann::json get_status(const int log_level);

    /**
     * @brief : check the field in this cookie whether they are correct and consistent;
     *
     * @param cookie
     */
    void _cookie_sanity_check(const void* const cookie) const;

    /**
     * @brief :  On-disk sanity check by walking through meta blk chain for sanity check;
     *
     * @param check_ovf_chain:
     * if set to true, also walk through ovf chain for each meta blk if there is any;
     * if false, skip ovf chain sanity check;
     */
    bool sanity_check(const bool check_ovf_chain = false);
    [[nodiscard]] bool ssb_sanity_check() const;
};

extern MetaBlkMgr* MetaBlkMgrSI();

} // namespace homestore
