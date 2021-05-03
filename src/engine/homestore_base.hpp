#pragma once
#include <boost/intrusive_ptr.hpp>
#include "common/homestore_header.hpp"
#include "common/homestore_assert.hpp"
#include "common/homestore_config.hpp"
#include <metrics/metrics.hpp>
#include <iomgr/iomgr.hpp>

typedef uint32_t crc32_t;
typedef uint16_t csum_t;
typedef int64_t seq_id_t;
const csum_t init_crc_16 = 0x8005;

static constexpr crc32_t init_crc32 = 0x12345678;
static constexpr crc32_t INVALID_CRC32_VALUE = 0x0u;

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

/* This class is introduced only to avoid template in any of its subsystem. Subsystem can get any homestore info other
 * then indx blkstore from this base class.
 */
class HomeStoreBase {
private:
    sisl::atomic_counter< uint64_t > m_usage_counter{0};
    std::shared_ptr< sds_logging::logger_t > m_periodic_logger;
    static HomeStoreBaseSafePtr s_instance;

public:
    virtual ~HomeStoreBase() = default;
    friend void intrusive_ptr_add_ref(HomeStoreBase* hs) { hs->m_usage_counter.increment(1); }
    friend void intrusive_ptr_release(HomeStoreBase* hs) {
        if (hs->m_usage_counter.decrement_testz()) { delete hs; }
    }

    static void set_instance(HomeStoreBaseSafePtr instance) { s_instance = instance; }
    static void reset_instance() { s_instance.reset(); }
    static HomeStoreBase* instance() { return s_instance.get(); }
    static HomeStoreBaseSafePtr safe_instance() { return s_instance; }
    static std::shared_ptr< spdlog::logger >& periodic_logger() { return instance()->m_periodic_logger; }

    virtual data_blkstore_t* get_data_blkstore() const = 0;
    virtual void attach_prepare_indx_cp(std::map< boost::uuids::uuid, indx_cp_ptr >* cur_icp_map,
                                        std::map< boost::uuids::uuid, indx_cp_ptr >* new_icp_map, hs_cp* cur_hcp,
                                        hs_cp* new_hcp) = 0;
    virtual void blkalloc_cp_start(std::shared_ptr< blkalloc_cp > cp) = 0;
    virtual std::shared_ptr< blkalloc_cp > blkalloc_attach_prepare_cp(std::shared_ptr< blkalloc_cp > cur_ba_cp) = 0;
    virtual uint32_t get_data_pagesz() const = 0;
    virtual DeviceManager* get_device_manager() = 0;
    virtual logdev_blkstore_t* get_logdev_blkstore() const = 0;
};

static inline HomeStoreBaseSafePtr HomeStorePtr() { return HomeStoreBase::safe_instance(); }
static inline HomeStoreBase* HomeStoreRawPtr() { return HomeStoreBase::instance(); }

static inline auto hs_iobuf_alloc(size_t size) {
    auto buf = iomanager.iobuf_alloc(HS_STATIC_CONFIG(drive_attr.align_size), size);
    HS_ASSERT_NOTNULL(RELEASE, buf, "io buf is null. probably going out of memory");
    return buf;
}

using hs_uuid_t = time_t;
#define INVALID_SYSTEM_UUID 0
static inline hs_uuid_t hs_gen_system_uuid() {
    return std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
}

static inline void hs_iobuf_free(uint8_t* ptr) { iomanager.iobuf_free(ptr); }

static inline uint64_t hs_aligned_size(size_t size) {
    return sisl::round_up(size, HS_STATIC_CONFIG(drive_attr.align_size));
}

static inline bool hs_mod_aligned_sz(size_t size_to_check, size_t align_sz) {
    HS_DEBUG_ASSERT_EQ((align_sz & (align_sz - 1)), 0);
    return !(size_to_check & static_cast< size_t >(align_sz - 1)); // return true if it is aligned.
}

static inline sisl::byte_view hs_create_byte_view(uint64_t size, bool is_aligned_needed) {
    return (is_aligned_needed)
        ? sisl::byte_view{(uint32_t)hs_aligned_size(size), HS_STATIC_CONFIG(drive_attr.align_size)}
        : sisl::byte_view{(uint32_t)size};
}

static inline sisl::io_blob hs_create_io_blob(uint64_t size, bool is_aligned_needed) {
    return (is_aligned_needed) ? sisl::io_blob{size, HS_STATIC_CONFIG(drive_attr.align_size)} : sisl::io_blob{size, 0};
}
} // namespace homestore
