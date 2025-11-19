/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
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
#include <unordered_map>
#include <memory>
#include <mutex>
#include <string>
#include <system_error>
#include <vector>
#include <optional>

#include <sisl/fds/buffer.hpp>
#include <sisl/metrics/metrics.hpp>
#include <nlohmann/json.hpp>
#include <homestore/homestore_decl.hpp>

namespace homestore {

// forward declarations
struct meta_blk_ovf_hdr;
struct meta_blk_sb;
struct meta_blk;
struct meta_vdev_context;
struct MetaSubRegInfo;
struct BlkId;
class VirtualDev;
struct vdev_info;

// each subsystem could receive callbacks multiple times
// NOTE: look at this prototype some other time for const correctness and efficiency
// new blk found subsystem callback
typedef std::function< void(meta_blk* mblk, sisl::byte_view buf, size_t size) > meta_blk_found_cb_t;
typedef std::string meta_sub_type;
typedef std::vector< meta_sub_type > meta_subtype_vec_t;
typedef std::function< void(bool success) > meta_blk_recover_comp_cb_t; // recover complete subsystem callbacks;
typedef std::map< uint64_t, meta_blk* > meta_blk_map_t;                 // blkid to meta_blk map;
typedef std::map< uint64_t, meta_blk_ovf_hdr* > ovf_hdr_map_t;          // ovf_blkid to ovf_blk_hdr map;
typedef std::map< meta_sub_type, MetaSubRegInfo > client_info_map_t;    // client information map;
typedef std::unordered_map< meta_sub_type, std::vector< meta_sub_type > > subtype_graph_t;

class MetablkMetrics : public sisl::MetricsGroupWrapper {
public:
    explicit MetablkMetrics(const char* inst_name) : sisl::MetricsGroupWrapper{"MetaService", inst_name} {
        REGISTER_COUNTER(compress_success_cnt, "compression successful cnt");
        REGISTER_COUNTER(compress_backoff_memory_cnt, "compression back-off cnt because of exceending memory limit")
        REGISTER_COUNTER(compress_backoff_ratio_cnt, "compression back-off cnt because of exceeding ratio limit");

        REGISTER_HISTOGRAM(compress_ratio_percent, "compression ration percentage",
                           HistogramBucketsType(PercentileBuckets));
        register_me_to_farm();
    }

    MetablkMetrics(const MetablkMetrics&) = delete;
    MetablkMetrics& operator=(const MetablkMetrics&) = delete;
    MetablkMetrics(MetablkMetrics&&) noexcept = delete;
    MetablkMetrics& operator=(MetablkMetrics&&) noexcept = delete;

    ~MetablkMetrics() { deregister_me_from_farm(); }
};

struct meta_vdev_context;

class MetaBlkService {
private:
    static bool s_self_recover;
    std::shared_ptr< VirtualDev > m_sb_vdev; // super block vdev
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
    std::unique_ptr< meta_vdev_context > m_meta_vdev_context;
    subtype_graph_t m_dep_topo_graph;

public:
    MetaBlkService(const char* name = "MetaBlkStore");
    MetaBlkService(const MetaBlkService&) = delete;
    MetaBlkService(MetaBlkService&&) noexcept = delete;
    MetaBlkService& operator=(const MetaBlkService&) = delete;
    MetaBlkService& operator=(MetaBlkService&&) noexcept = delete;

    ~MetaBlkService() = default;

    // Creates the vdev that is needed to initialize the device
    void create_vdev(uint64_t size, HSDevType devType, uint32_t num_chunks);

    // Open the existing vdev which is represented by the vdev_info
    shared< VirtualDev > open_vdev(const vdev_info& vinfo, bool load_existing);

    /**
     * @brief :
     *
     * @param sb_blk_store : superblock store
     * @param blob : super block store vb context data blob
     * @param init : true of initialized, false if recovery
     * @return
     */
    void start(bool is_init);

    void stop();

    /**
     * @brief : Register subsystem callbacks
     * @param type : subsystem type
     * @param cb : subsystem cb
     */
    void register_handler(meta_sub_type type, const meta_blk_found_cb_t& cb, const meta_blk_recover_comp_cb_t& comp_cb,
                          bool do_crc = true, std::optional< meta_subtype_vec_t > deps = std::nullopt);

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
    void add_sub_sb(meta_sub_type type, const uint8_t* context_data, uint64_t sz, void*& cookie);

    /**
     * @brief : remove subsystem sb based on cookie
     *
     * @param cookie : handle address unique subsystem sb that is being removed;
     *
     * @return : ok on success, not-ok on failure;
     */
    std::error_condition remove_sub_sb(void* cookie);

    /**
     * @brief : update metablk in-place
     *
     * @param type : type of subsytem
     * @param context_data : subsytem sb;
     * @param sz : size of context_data
     * @param cookie : handle to address the unique subsytem sb that is being updated;
     */
    void update_sub_sb(const uint8_t* context_data, uint64_t sz, void* cookie);

    // size_t read_sub_sb(const meta_sub_type type, sisl::byte_view& buf);
    void read_sub_sb(meta_sub_type type);

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
    void recover(bool do_comp_cb = true);

    /**
     * @brief : scan the blkstore to load meta blks into memory
     */

    void scan_meta_blks();

    /**
     * @brief : Return the total space used in bytes that was occupied by this meta blk;
     *          Currently used for testing only.
     *
     * @param cookie : handle to meta blk;
     *
     * @return : size of space occupied by this meta blk;
     */
    uint64_t meta_size(const void* cookie) const;

    uint64_t total_size() const;
    uint64_t used_size() const;
    uint32_t block_size() const;
    uint32_t align_size() const;
    uint64_t available_blks() const;
    bool is_aligned_buf_needed(size_t size) const;

    uint64_t meta_blk_context_sz() const;

    nlohmann::json get_status(const int log_level);

public:
    /************************* metacli function **********************/
    void scan(const std::string& scan_type, std::optional< uint16_t > debug_chunk_id = std::nullopt,
              std::optional< uint32_t > debug_blk_num = std::nullopt);
    void scan_blks_on_all_chunks(std::optional< uint16_t > debug_chunk_id = std::nullopt,
                                 std::optional< uint32_t > debug_blk_num = std::nullopt) const;
    void scan_blks_by_chain() const;

public:
    /*********************** static public function **********************/
    uint64_t ovf_blk_max_num_data_blk() const;

    sisl::byte_array to_meta_buf(sisl::byte_view buf, size_t size) const;

public:
    /*********************** static public function **********************/
    static void set_self_recover() { s_self_recover = true; }
    static void reset_self_recover() { s_self_recover = false; }
    static bool is_self_recovered() { return s_self_recover; }

private:
    /**
     * @brief
     *
     * @param type
     *
     * @return
     */
    bool is_sub_type_valid(meta_sub_type type);

    /**
     * @brief : write in-memory copy of meta_blk to disk;
     *
     * @param mblk
     *
     * @return
     */
    void write_meta_blk_to_disk(meta_blk* mblk);

    void write_ovf_blk_to_disk(meta_blk_ovf_hdr* ovf_hdr, const uint8_t* context_data, uint64_t sz, uint64_t offset,
                               const std::string& type);

    /**
     * @brief : load meta blk super super block into memory
     *
     * @param bid : the blk id that belongs to meta ssb;
     */
    void load_ssb();

    /**
     * @brief : format super super block
     *
     * @return
     */
    void format_ssb();

    /**
     * @brief : Write MetaBlkService's superblock to disk;
     */
    void write_ssb();

    /**
     * @brief : Allocate meta BlkId
     *
     */
    void alloc_meta_blk(BlkId& bid);
    void alloc_meta_blks(uint64_t size, std::vector< BlkId >& bid);

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
    meta_blk* init_meta_blk(BlkId& bid, meta_sub_type type, const uint8_t* context_data, size_t sz);

    /**
     * @brief
     *
     * @param bid
     * @param context_data
     * @param sz
     * @param offset
     */
    void write_meta_blk_ovf(BlkId& bid, const uint8_t* context_data, uint64_t sz, const std::string& type);

    /**
     * @brief : internal implementation of populating and writing a meta block;
     *
     * @param mblk
     * @param context_data
     * @param sz
     */
    void write_meta_blk_internal(meta_blk* mblk, const uint8_t* context_data, uint64_t sz);

    /**
     * @brief : sync read;
     *
     * @param bid
     * @param b
     */
    void read(const BlkId& bid, uint8_t* dest, size_t sz) const;

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

    uint64_t min_compress_size() const;
    uint64_t max_compress_memory_size() const;
    uint64_t init_compress_memory_size() const;

public:
    bool get_skip_hdr_check() const;

private:
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
    bool sanity_check(bool check_ovf_chain = false);

    bool ssb_sanity_check() const;

    bool scan_and_load_meta_blks(meta_blk_map_t& meta_blks, ovf_hdr_map_t& ovf_blk_hdrs, BlkId* last_mblk_id,
                                 client_info_map_t& sub_info);

    void recover_meta_block(meta_blk* meta_block);
    void recover_meta_sub_type(bool do_comp_cb, const meta_sub_type&);

public:
    bool verify_metablk_store();

    nlohmann::json dump_disk_metablks(const std::string& client);
    nlohmann::json populate_json(int log_level, meta_blk_map_t& meta_blks, ovf_hdr_map_t& ovf_blk_hdrs,
                                 BlkId* last_mblk_id, client_info_map_t& sub_info, bool self_recover,
                                 const std::string& client);
    shared< VirtualDev > do_open_vdev(const vdev_info& vinfo);
};

extern MetaBlkService& meta_service();

} // namespace homestore
