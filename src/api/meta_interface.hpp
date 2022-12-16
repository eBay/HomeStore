/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 * Author/Developer(s): Yaming Kuang
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 *********************************************************************************/
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <system_error>
#include <vector>

#include <sisl/fds/buffer.hpp>
#include <sisl/metrics/metrics.hpp>
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
template < typename Buffer >
class BlkStore;

typedef homestore::BlkStore< BlkBuffer > blk_store_t;

// each subsystem could receive callbacks multiple times
// NOTE: look at this prototype some other time for const correctness and efficiency
// new blk found subsystem callback
typedef std::function< void(meta_blk* mblk, sisl::byte_view buf, size_t size) > meta_blk_found_cb_t;
typedef std::string meta_sub_type;
typedef std::function< void(bool success) > meta_blk_recover_comp_cb_t; // recover complete subsystem callbacks;
typedef std::map< uint64_t, meta_blk* > meta_blk_map_t;                 // blkid to meta_blk map;
typedef std::map< uint64_t, meta_blk_ovf_hdr* > ovf_hdr_map_t;          // ovf_blkid to ovf_blk_hdr map;
typedef std::map< meta_sub_type, MetaSubRegInfo > client_info_map_t;    // client information map;

class MetablkMetrics : public sisl::MetricsGroupWrapper {
public:
    explicit MetablkMetrics(const char* inst_name) : sisl::MetricsGroupWrapper{"MetaBlkStore", inst_name} {
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
    blk_store_t* m_sb_blk_store{nullptr};    // super blockstore
    std::mutex m_meta_mtx;                   // mutex to access to meta_map;
    std::mutex m_shutdown_mtx;               // protects concurrent operations between recover and shutdown;
    meta_blk_map_t m_meta_blks;              // subsystem type to meta blk map;
    ovf_hdr_map_t m_ovf_blk_hdrs;            // ovf blk map;
    client_info_map_t m_sub_info;            // map of callbacks
    std::unique_ptr< BlkId > m_last_mblk_id; // last meta blk;
    meta_blk_sb* m_ssb{nullptr};             // meta super super blk;
    sisl::blob m_compress_info;
    MetablkMetrics m_metrics;
    bool m_inited{false};

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
    void start(blk_store_t* sb_blk_store, const sb_blkstore_blob* blob, const bool is_init);

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
    void add_sub_sb(const meta_sub_type type, const void* context_data, const uint64_t sz, void*& cookie);

    /**
     * @brief : remove subsystem sb based on cookie
     *
     * @param cookie : handle address unique subsystem sb that is being removed;
     *
     * @return : ok on success, not-ok on failure;
     */
    [[nodiscard]] std::error_condition remove_sub_sb(void* cookie);

    /**
     * @brief : update metablk in-place
     *
     * @param type : type of subsytem
     * @param context_data : subsytem sb;
     * @param sz : size of context_data
     * @param cookie : handle to address the unique subsytem sb that is being updated;
     */
    void update_sub_sb(const void* context_data, const uint64_t sz, void*& cookie);

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
    [[nodiscard]] uint64_t get_meta_size(const void* cookie) const;

    [[nodiscard]] uint64_t meta_blk_context_sz() const;

    [[nodiscard]] uint64_t ovf_blk_max_num_data_blk() const;
    [[nodiscard]] uint32_t get_align_size() const;

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
    void write_meta_blk_to_disk(meta_blk* mblk);

    void write_ovf_blk_to_disk(meta_blk_ovf_hdr* ovf_hdr, const void* context_data, const uint64_t sz,
                               const uint64_t offset, const std::string& type);

    /**
     * @brief : load meta blk super super block into memory
     *
     * @param bid : the blk id that belongs to meta ssb;
     */
    void load_ssb(const sb_blkstore_blob* blob);

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

    void free_meta_blk(meta_blk* mblk);

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
    [[nodiscard]] meta_blk* init_meta_blk(BlkId& bid, const meta_sub_type type, const void* context_data,
                                          const size_t sz);

    /**
     * @brief
     *
     * @param bid
     * @param context_data
     * @param sz
     * @param offset
     */
    void write_meta_blk_ovf(BlkId& bid, const void* context_data, const uint64_t sz, const std::string& type);

    /**
     * @brief : internal implementation of populating and writing a meta block;
     *
     * @param mblk
     * @param context_data
     * @param sz
     */
    void write_meta_blk_internal(meta_blk* mblk, const void* context_data, const uint64_t sz);

    /**
     * @brief : sync read;
     *
     * @param bid
     * @param b
     */
    void read(const BlkId& bid, void* dest, const size_t sz) const;

    void cache_clear();

    /**
     * @brief
     *
     * @param mblk
     * @param buf
     */
    sisl::byte_array read_sub_sb_internal(const meta_blk* mblk) const;

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
    void _cookie_sanity_check(const void* cookie) const;

    /**
     * @brief :  On-disk sanity check by walking through meta blk chain for sanity check;
     *
     * @param check_ovf_chain:
     * if set to true, also walk through ovf chain for each meta blk if there is any;
     * if false, skip ovf chain sanity check;
     */
    bool sanity_check(const bool check_ovf_chain = false);

    [[nodiscard]] bool ssb_sanity_check() const;

    [[nodiscard]] bool scan_and_load_meta_blks(meta_blk_map_t& meta_blks, ovf_hdr_map_t& ovf_blk_hdrs,
                                               BlkId* last_mblk_id, client_info_map_t& sub_info);

    [[nodiscard]] bool verify_metablk_store();

    [[nodiscard]] nlohmann::json dump_disk_metablks(const std::string& client);
    nlohmann::json populate_json(const int log_level, meta_blk_map_t& meta_blks, ovf_hdr_map_t& ovf_blk_hdrs,
                                 BlkId* last_mblk_id, client_info_map_t& sub_info, const bool self_recover,
                                 const std::string& client);
};

extern MetaBlkMgr* MetaBlkMgrSI();

} // namespace homestore
