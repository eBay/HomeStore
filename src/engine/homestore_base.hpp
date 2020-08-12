#pragma once
#include <boost/intrusive_ptr.hpp>
#include "common/homestore_header.hpp"
#include "common/homestore_assert.hpp"
#include <metrics/metrics.hpp>

const uint16_t init_crc_16 = 0x8005;
typedef uint32_t crc32_t;
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

/* This class is introduced only to avoid template in any of its subsystem. Subsystem can get any homestore info other
 * then indx blkstore from this base class.
 */
class HomeStoreBase {
public:
    using HomeStoreBaseSafePtr = boost::intrusive_ptr< HomeStoreBase >;

private:
    sisl::atomic_counter< uint64_t > m_usage_counter = 1;
    static HomeStoreBaseSafePtr _instance;

public:
    virtual ~HomeStoreBase() = default;
    friend void intrusive_ptr_add_ref(HomeStoreBase* hs) { hs->m_usage_counter.increment(1); }
    friend void intrusive_ptr_release(HomeStoreBase* hs) {
        // If there is only one reference remaining after decrementing, then we are done with shutdown, cleanup the
        // _instance and delete the homeblks.
        if (hs->m_usage_counter.decrement_test_eq(1)) {
            auto p = HomeStoreBase::_instance.detach();
            HS_DEBUG_ASSERT_EQ((void*)p, (void*)hs);
            delete hs;
        }
    }

    static void set_instance(HomeStoreBaseSafePtr instance) { _instance = instance; }
    static HomeStoreBase* instance() { return _instance.get(); }
    static HomeStoreBaseSafePtr safe_instance() { return _instance; }
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
} // namespace homestore
