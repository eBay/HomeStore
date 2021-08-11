#pragma once
#include <boost/intrusive_ptr.hpp>
#include "common/homestore_config.hpp"
#include <fds/buffer.hpp>

typedef uint32_t crc32_t;
typedef uint16_t csum_t;
typedef int64_t seq_id_t;
const csum_t init_crc_16 = 0x8005;

static constexpr crc32_t init_crc32 = 0x12345678;
static constexpr crc32_t INVALID_CRC32_VALUE = 0x0u;

namespace spdlog {
class logger;
} // namespace spdlog

namespace homestore {

struct blkalloc_cp;
struct indx_cp;
using indx_cp_ptr = boost::intrusive_ptr< homestore::indx_cp >;
struct hs_cp;
struct DeviceManager;
class BlkBuffer;
template < typename BAllocator, typename Buffer >
class BlkStore;
class VdevVarSizeBlkAllocatorPolicy;
typedef homestore::BlkStore< homestore::VdevVarSizeBlkAllocatorPolicy, BlkBuffer > data_blkstore_t;
typedef homestore::BlkStore< homestore::VdevVarSizeBlkAllocatorPolicy, BlkBuffer > logdev_blkstore_t;

class HomeStoreBase;
typedef boost::intrusive_ptr< HomeStoreBase > HomeStoreBaseSafePtr;

class HomeStoreStatusMgr;
struct sb_blkstore_blob;

/* This class is introduced only to avoid template in any of its subsystem. Subsystem can get any homestore info other
 * then indx blkstore from this base class.
 */
class HomeStoreBase {
private:
    sisl::atomic_counter< uint64_t > m_usage_counter{0};
    std::shared_ptr< sds_logging::logger_t > m_periodic_logger;
    std::unique_ptr< HomeStoreStatusMgr > m_status_mgr;

    static HomeStoreBaseSafePtr s_instance;

protected:
    bool m_vdev_failed{false};
    bool m_print_checksum{true};
    uint64_t m_size_avail{0};
    uint32_t m_data_pagesz{0};
    std::atomic< uint32_t > m_format_cnt{1};
    sb_blkstore_blob* m_meta_sb_blob{nullptr};

public:
    virtual ~HomeStoreBase();
    friend void intrusive_ptr_add_ref(HomeStoreBase* hs) { hs->m_usage_counter.increment(1); }
    friend void intrusive_ptr_release(HomeStoreBase* hs) {
        if (hs->m_usage_counter.decrement_testz()) { delete hs; }
    }

    static void set_instance(HomeStoreBaseSafePtr instance);
    static void reset_instance();
    static HomeStoreBase* instance() { return s_instance.get(); }
    static HomeStoreBaseSafePtr safe_instance() { return s_instance; }
    static std::shared_ptr< spdlog::logger >& periodic_logger();

    virtual data_blkstore_t* get_data_blkstore() const = 0;
    virtual void attach_prepare_indx_cp(std::map< boost::uuids::uuid, indx_cp_ptr >* cur_icp_map,
                                        std::map< boost::uuids::uuid, indx_cp_ptr >* new_icp_map, hs_cp* cur_hcp,
                                        hs_cp* new_hcp) = 0;
    virtual void blkalloc_cp_start(std::shared_ptr< blkalloc_cp > cp) = 0;
    virtual std::shared_ptr< blkalloc_cp > blkalloc_attach_prepare_cp(std::shared_ptr< blkalloc_cp > cur_ba_cp) = 0;
    virtual uint32_t get_data_pagesz() const = 0;
    virtual DeviceManager* get_device_manager() = 0;
    virtual logdev_blkstore_t* get_data_logdev_blkstore() const = 0;
    virtual logdev_blkstore_t* get_ctrl_logdev_blkstore() const = 0;
    virtual void call_multi_completions() = 0;
    virtual bool inc_hs_ref_cnt(boost::uuids::uuid& uuid) = 0;
    virtual bool dec_hs_ref_cnt(boost::uuids::uuid& uuid) = 0;
    virtual bool fault_containment(boost::uuids::uuid& uuid) = 0;

    HomeStoreStatusMgr* status_mgr();
};

static inline HomeStoreBaseSafePtr HomeStorePtr() { return HomeStoreBase::safe_instance(); }
static inline HomeStoreBase* HomeStoreRawPtr() { return HomeStoreBase::instance(); }

using hs_uuid_t = time_t;
static constexpr hs_uuid_t INVALID_SYSTEM_UUID{0};

class hs_utils {
public:
    static uint8_t* iobuf_alloc(size_t size, const sisl::buftag tag);
    static void iobuf_free(uint8_t* ptr, const sisl::buftag tag);
    static uint64_t aligned_size(size_t size);
    static bool mod_aligned_sz(size_t size_to_check, size_t align_sz);
    static sisl::byte_view create_byte_view(uint64_t size, bool is_aligned_needed, const sisl::buftag tag);
    static sisl::io_blob create_io_blob(uint64_t size, bool is_aligned_needed, const sisl::buftag tag);
    static sisl::byte_array extract_byte_array(const sisl::byte_view& b, bool is_aligned_needed = true);
    static sisl::byte_array make_byte_array(uint64_t size, bool is_aligned_needed, const sisl::buftag tag);
    static hs_uuid_t gen_system_uuid();
};

} // namespace homestore
