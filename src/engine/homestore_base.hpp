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
#include <boost/intrusive_ptr.hpp>
#include <sisl/fds/buffer.hpp>
#include "engine/blkalloc/blk.h"
#include "common/homestore_config.hpp"

namespace spdlog {
class logger;
} // namespace spdlog

namespace sisl {
class sobject_manager;
}

namespace homestore {

struct blkalloc_cp;
struct indx_cp;
using indx_cp_ptr = boost::intrusive_ptr< homestore::indx_cp >;
struct hs_cp;
struct DeviceManager;
class BlkBuffer;
class JournalVirtualDev;

template < typename Buffer >
class BlkStore;

class HomeStoreBase;
typedef boost::intrusive_ptr< HomeStoreBase > HomeStoreBaseSafePtr;

struct sb_blkstore_blob;

typedef BlkStore< BlkBuffer > meta_blkstore_t;

typedef boost::intrusive_ptr< BlkBuffer > blk_buf_t;

VENUM(blkstore_type, uint32_t, DATA_STORE = 1, INDEX_STORE = 2, SB_STORE = 3, DATA_LOGDEV_STORE = 4,
      CTRL_LOGDEV_STORE = 5, META_STORE = 6);

struct blkstore_blob {
    enum blkstore_type type;
};

struct sb_blkstore_blob : blkstore_blob {
    BlkId blkid;
};

/* This class is introduced only to avoid template in any of its subsystem. Subsystem can get any homestore info other
 * then indx blkstore from this base class.
 */
class HomeStoreBase {
private:
    sisl::atomic_counter< uint64_t > m_usage_counter{0};

    static HomeStoreBaseSafePtr s_instance;

protected:
    std::shared_ptr< sisl::logging::logger_t > m_periodic_logger;
    std::unique_ptr< sisl::sobject_manager > m_sobject_mgr;

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

    virtual BlkStore< BlkBuffer >* get_data_blkstore() const = 0;
    virtual void attach_prepare_indx_cp(std::map< boost::uuids::uuid, indx_cp_ptr >* cur_icp_map,
                                        std::map< boost::uuids::uuid, indx_cp_ptr >* new_icp_map, hs_cp* cur_hcp,
                                        hs_cp* new_hcp) = 0;
    virtual void blkalloc_cp_start(std::shared_ptr< blkalloc_cp > cp) = 0;
    virtual std::shared_ptr< blkalloc_cp >
    blkalloc_attach_prepare_cp(const std::shared_ptr< blkalloc_cp >& cur_ba_cp) = 0;
    virtual uint32_t get_data_pagesz() const = 0;
    virtual DeviceManager* get_device_manager() = 0;
    virtual JournalVirtualDev* get_data_logdev_blkstore() const = 0;
    virtual JournalVirtualDev* get_ctrl_logdev_blkstore() const = 0;
    virtual void call_multi_completions() = 0;
    virtual bool inc_hs_ref_cnt(const boost::uuids::uuid& uuid) = 0;
    virtual bool dec_hs_ref_cnt(const boost::uuids::uuid& uuid) = 0;
    virtual bool fault_containment(const boost::uuids::uuid& uuid) = 0;
    virtual void set_indx_btree_start_destroying(const boost::uuids::uuid& uuid) = 0;
    virtual iomgr::io_thread_t get_hs_flush_thread() const = 0;
    sisl::sobject_manager* sobject_mgr();
};

static inline HomeStoreBaseSafePtr HomeStorePtr() { return HomeStoreBase::safe_instance(); }
static inline HomeStoreBase* HomeStoreRawPtr() { return HomeStoreBase::instance(); }

} // namespace homestore
