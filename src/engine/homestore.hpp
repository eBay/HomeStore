#pragma once
#include "engine/common/homestore_config.hpp"
#include "homelogstore/log_store.hpp"
#include "engine/blkstore/blkstore.hpp"
#include "engine/homeds/btree/btree.hpp"
#include "engine/homeds/btree/ssd_btree.hpp"
#include "engine/device/device.h"
#include <fds/utils.hpp>
#include "engine/meta/meta_sb.hpp"

using namespace homeds::btree;

namespace homestore {
typedef BlkStore< VdevVarSizeBlkAllocatorPolicy > data_blkstore_t;
typedef BlkStore< VdevVarSizeBlkAllocatorPolicy > sb_blkstore_t;

template < typename IndexBuffer >
using index_blkstore_t = BlkStore< VdevFixedBlkAllocatorPolicy, IndexBuffer >;

typedef BlkStore< homestore::VdevVarSizeBlkAllocatorPolicy > logdev_blkstore_t;
typedef BlkStore< homestore::VdevVarSizeBlkAllocatorPolicy > meta_blkstore_t;

typedef boost::intrusive_ptr< BlkBuffer > blk_buf_t;

VENUM(blkstore_type, uint32_t, DATA_STORE = 1, INDEX_STORE = 2, SB_STORE = 3, LOGDEV_STORE = 4, META_STORE = 5);

struct blkstore_blob {
    enum blkstore_type type;
};

struct sb_blkstore_blob : blkstore_blob {
    BlkId blkid;
};

template < typename IndexBuffer >
class HomeStore {
public:
    HomeStore() = default;
    ~HomeStore() = default;

    void init(const hs_input_params& input) {
        auto& hs_config = HomeStoreStaticConfig::instance();

        /* set the homestore static config parameters */
        hs_config.input = input;
        hs_config.disk_attr = (input.disk_attr) ? *input.disk_attr : get_disk_attrs(input.is_file);

#ifndef NDEBUG
        flip::Flip::instance().start_rpc_server();
#endif

        /* Btree leaf node in index btree should accamodate minimum 2 entries to do the split. And on a average
         * a value consume 2 bytes (for checksum) per blk and few bytes for each IO and node header.
         * max_blk_cnt represents max number of blks blk allocator should give in a blk. We are taking
         * conservatively 4 entries in a node with avg size of 2 for each blk.
         * Note :- This restriction will go away once btree start supporinting higher size value.
         */
        hs_config.engine.max_blk_cnt = hs_config.disk_attr.atomic_phys_page_size / (4 * 2);
        hs_config.engine.min_io_size =
            std::min(input.min_virtual_page_size, (uint32_t)hs_config.disk_attr.atomic_phys_page_size);
        m_data_pagesz = input.min_virtual_page_size;

        if (input.devices.size() == 0) {
            LOGERROR("no devices given");
            throw std::invalid_argument("null device list");
        }

        std::ofstream hs_config_stream("hs_static_config.json");
        auto j = hs_config.to_json();
        hs_config_stream << j.dump(4);
        LOGINFO("HomeStore starting with config: {}", j.dump(4));

#ifndef NDEBUG
        hs_config.validate();
#endif

        /* create cache */
        m_cache = std::make_unique< Cache< BlkId > >(input.cache_size, hs_config.disk_attr.atomic_phys_page_size);

        /* create device manager */
        m_dev_mgr = std::make_unique< DeviceManager >(
            std::bind(&HomeStore::new_vdev_found, this, std::placeholders::_1, std::placeholders::_2),
            sizeof(sb_blkstore_blob), virtual_dev_process_completions, input.is_file, input.system_uuid,
            std::bind(&HomeStore::process_vdev_error, this, std::placeholders::_1));
    }

    cap_attrs get_system_capacity() {
        cap_attrs cap;
        cap.used_data_size = get_data_blkstore()->get_used_size();
        cap.used_index_size = get_index_blkstore()->get_used_size();
        cap.used_total_size = cap.used_data_size + cap.used_index_size;
        cap.initial_total_size = get_data_blkstore()->get_size() + get_index_blkstore()->get_size();
        return cap;
    }

    data_blkstore_t* get_data_blkstore() const { return m_data_blk_store.get(); }
    index_blkstore_t< IndexBuffer >* get_index_blkstore() const { return m_index_blk_store.get(); }
    sb_blkstore_t* get_sb_blkstore() const { return m_sb_blk_store.get(); }
    logdev_blkstore_t* get_logdev_blkstore() const { return m_logdev_blk_store.get(); }
    meta_blkstore_t* get_meta_blkstore() const { return m_meta_blk_store.get(); }

    uint32_t get_data_pagesz() const { return m_data_pagesz; }
    bool print_checksum() const { return m_print_checksum; }

    BlkId alloc_sb_blk(size_t sz) {
        BlkId bid;
        blk_alloc_hints hints;
        hints.desired_temp = 0;
        hints.dev_id_hint = -1;
        hints.is_contiguous = true;
        auto ret = m_sb_blk_store->alloc_blk(sz, hints, &bid);
        if (ret != BLK_ALLOC_SUCCESS) {
            throw homestore::homestore_exception("space not available", homestore_error::space_not_avail);
        }
        assert(ret == BLK_ALLOC_SUCCESS);
        return bid;
    }

protected:
    virtual void metablk_init(sb_blkstore_blob* blob, bool init) = 0;
    virtual data_blkstore_t::comp_callback data_completion_cb() = 0;
    virtual void process_vdev_error(vdev_info_block* vb) = 0;

    void init_devices() {
        auto& hs_config = HomeStoreStaticConfig::instance();

        /* attach physical devices */
        m_dev_mgr->add_devices(hs_config.input.devices, hs_config.input.disk_init);
        HS_ASSERT_CMP(LOGMSG, m_dev_mgr->get_total_cap() / hs_config.input.devices.size(), >, MIN_DISK_CAP_SUPPORTED);
        HS_ASSERT_CMP(LOGMSG, m_dev_mgr->get_total_cap(), <, MAX_SUPPORTED_CAP);

        /* create blkstore if it is a first time boot */
        if (hs_config.input.disk_init) {
            create_data_blkstore(nullptr);
            create_index_blkstore(nullptr);
            create_sb_blkstore(nullptr);
            create_logdev_blkstore(nullptr);
            create_meta_blkstore(nullptr);
        }
    }

    void new_vdev_found(DeviceManager* dev_mgr, vdev_info_block* vb) {
        /* create blkstore */
        blkstore_blob* blob = (blkstore_blob*)vb->context_data;
        switch (blob->type) {
        case blkstore_type::DATA_STORE:
            create_data_blkstore(vb);
            break;
        case blkstore_type::INDEX_STORE:
            create_index_blkstore(vb);
            break;
        case blkstore_type::SB_STORE:
            create_sb_blkstore(vb);
            break;
        case blkstore_type::LOGDEV_STORE:
            create_logdev_blkstore(vb);
            break;
        case blkstore_type::META_STORE:
            create_meta_blkstore(vb);
            break;
        default:
            HS_ASSERT(LOGMSG, 0, "Unknown blkstore_type {}", blob->type);
        }
    }

    void create_data_blkstore(vdev_info_block* vb) {
        if (vb == nullptr) {
            /* change it to context */
            struct blkstore_blob blob;
            blob.type = blkstore_type::DATA_STORE;
            uint64_t size = (90 * m_dev_mgr->get_total_cap()) / 100;
            size = sisl::round_up(size, HS_STATIC_CONFIG(disk_attr.phys_page_size));
            m_size_avail = size;
            LOGINFO("maximum capacity for data blocks is {}", m_size_avail);
            m_data_blk_store = std::make_unique< data_blkstore_t >(
                m_dev_mgr.get(), m_cache.get(), size, WRITEBACK_CACHE, 0, (char*)&blob, sizeof(blkstore_blob),
                m_data_pagesz, "data", data_completion_cb());
        } else {
            m_data_blk_store =
                std::make_unique< data_blkstore_t >(m_dev_mgr.get(), m_cache.get(), vb, WRITEBACK_CACHE, m_data_pagesz,
                                                    "data", (vb->failed ? true : false), data_completion_cb());
            if (vb->failed) {
                m_vdev_failed = true;
                LOGINFO("data block store is in failed state");
            }
        }
    }

    void create_index_blkstore(vdev_info_block* vb) {
        if (vb == nullptr) {
            struct blkstore_blob blob;
            blob.type = blkstore_type::INDEX_STORE;
            uint64_t size = (2 * m_dev_mgr->get_total_cap()) / 100;
            size = sisl::round_up(size, HS_STATIC_CONFIG(disk_attr.phys_page_size));
            m_index_blk_store = std::make_unique< index_blkstore_t< IndexBuffer > >(
                m_dev_mgr.get(), m_cache.get(), size, RD_MODIFY_WRITEBACK_CACHE, 0, (char*)&blob, sizeof(blkstore_blob),
                HS_STATIC_CONFIG(disk_attr.atomic_phys_page_size), "index");
        } else {
            m_index_blk_store = std::make_unique< index_blkstore_t< IndexBuffer > >(
                m_dev_mgr.get(), m_cache.get(), vb, RD_MODIFY_WRITEBACK_CACHE,
                HS_STATIC_CONFIG(disk_attr.atomic_phys_page_size), "index", (vb->failed ? true : false));
            if (vb->failed) {
                m_vdev_failed = true;
                LOGINFO("index block store is in failed state");
            }
        }
    }

    void create_sb_blkstore(vdev_info_block* vb) {
        if (vb == nullptr) {
            /* create a blkstore */
            struct sb_blkstore_blob blob;
            blob.type = blkstore_type::SB_STORE;
            blob.blkid.set(BlkId::invalid_internal_id());
            uint64_t size = (1 * m_dev_mgr->get_total_cap()) / 100;
            size = sisl::round_up(size, HS_STATIC_CONFIG(disk_attr.phys_page_size));
            m_sb_blk_store = std::make_unique< sb_blkstore_t >(
                m_dev_mgr.get(), m_cache.get(), size, PASS_THRU, HS_STATIC_CONFIG(input.devices).size() - 1,
                (char*)&blob, sizeof(sb_blkstore_blob), HS_STATIC_CONFIG(disk_attr.atomic_phys_page_size),
                "superblock");

            /* allocate a new blk id */
            BlkId bid = alloc_sb_blk(HS_STATIC_CONFIG(disk_attr.atomic_phys_page_size));
            blob.type = blkstore_type::SB_STORE;
            blob.blkid.set(bid);

            /* update the context info */
            m_sb_blk_store->update_vb_context(sisl::blob((uint8_t*)&blob, (uint32_t)sizeof(sb_blkstore_blob)));
        } else {
            /* create a blkstore */
            m_sb_blk_store = std::make_unique< sb_blkstore_t >(m_dev_mgr.get(), m_cache.get(), vb, PASS_THRU,
                                                               HS_STATIC_CONFIG(disk_attr.atomic_phys_page_size),
                                                               "superblock", false);
            if (vb->failed) {
                m_vdev_failed = true;
                LOGINFO("super block store is in failed state");
            }

            /* get the blkid of homestore super block */
            sb_blkstore_blob* blob = (sb_blkstore_blob*)(&(vb->context_data));
            if (blob->blkid.to_integer() == BlkId::invalid_internal_id()) {
                LOGINFO("init was failed last time. Should retry it with init flag");
                throw homestore::homestore_exception("init was failed last time. Should retry it with init",
                                                     homestore_error::init_failed);
            }

            /* read and build the appln super block */
            std::vector< blk_buf_t > bbuf =
                m_sb_blk_store->read_nmirror(blob->blkid, HS_STATIC_CONFIG(input.devices).size() - 1);
            //   superblock_load(bbuf, blob->blkid);
        }
    }

    void create_meta_blkstore(vdev_info_block* vb) {
        if (vb == nullptr) {
            struct blkstore_blob blob;
            blob.type = blkstore_type::META_STORE;
            uint64_t size = (1 * m_dev_mgr->get_total_cap()) / 100;
            size = sisl::round_up(size, HS_STATIC_CONFIG(disk_attr.phys_page_size));
            m_meta_blk_store =
                std::make_unique< meta_blkstore_t >(m_dev_mgr.get(), m_cache.get(), size, PASS_THRU, 0, (char*)&blob,
                                                    sizeof(blkstore_blob), META_BLK_PAGE_SZ, "meta");

            metablk_init(nullptr, true);
        } else {
            m_meta_blk_store = std::make_unique< meta_blkstore_t >(
                m_dev_mgr.get(), m_cache.get(), vb, PASS_THRU, META_BLK_PAGE_SZ, "meta", (vb->failed ? true : false));
            if (vb->failed) {
                m_vdev_failed = true;
                LOGINFO("meta block store is in failed state");
            }

            /* get the blkid of homestore super block */
            sb_blkstore_blob* blob = (sb_blkstore_blob*)(&(vb->context_data));
            if (blob->blkid.to_integer() == BlkId::invalid_internal_id()) {
                LOGINFO("init was failed last time. Should retry it with init flag");
                throw homestore::homestore_exception("init was failed last time. Should retry it with init",
                                                     homestore_error::init_failed);
            }
#if 0 
            /* read and build the appln super block */
            std::vector< blk_buf_t > bbuf =
                m_meta_blk_store->read_nmirror(blob->blkid, HS_STATIC_CONFIG(input.devices).size() - 1);
#endif
            metablk_init(blob, false);
        }
    }

    void create_logdev_blkstore(vdev_info_block* vb) {
        if (vb == nullptr) {
            struct blkstore_blob blob;
            blob.type = blkstore_type::LOGDEV_STORE;
            uint64_t size = (1 * m_dev_mgr->get_total_cap()) / 100;
            size = sisl::round_up(size, HS_STATIC_CONFIG(disk_attr.phys_page_size));
            m_logdev_blk_store = std::make_unique< BlkStore< VdevVarSizeBlkAllocatorPolicy > >(
                m_dev_mgr.get(), m_cache.get(), size, PASS_THRU, 0, (char*)&blob, sizeof(blkstore_blob),
                HS_STATIC_CONFIG(disk_attr.atomic_phys_page_size), "logdev",
                std::bind(&LogDev::process_logdev_completions, &HomeLogStoreMgr::logdev(), std::placeholders::_1));
        } else {
            m_logdev_blk_store = std::make_unique< BlkStore< VdevVarSizeBlkAllocatorPolicy > >(
                m_dev_mgr.get(), m_cache.get(), vb, PASS_THRU, HS_STATIC_CONFIG(disk_attr.atomic_phys_page_size),
                "logdev", (vb->failed ? true : false),
                std::bind(&LogDev::process_logdev_completions, &HomeLogStoreMgr::logdev(), std::placeholders::_1));
            if (vb->failed) {
                m_vdev_failed = true;
                LOGINFO("logdev block store is in failed state");
            }
        }
        home_log_store_mgr.start((vb == nullptr));
    }

    uint64_t available_size() const { return m_size_avail; }
    void set_available_size(uint64_t sz) { m_size_avail = sz; }

private:
    disk_attributes get_disk_attrs(bool is_file) {
        disk_attributes attr;
        /* We should take these params from the config file or from the disks direectly */
        attr.phys_page_size = 4096;
        attr.align_size = 512;
#ifndef NDEBUG
        attr.atomic_phys_page_size = is_file ? 4096 : 512;
#else
        attr.atomic_phys_page_size = 4096;
#endif
        return attr;
    }

protected:
    bool m_vdev_failed = false;
    bool m_print_checksum = true;

    std::unique_ptr< data_blkstore_t > m_data_blk_store;
    std::unique_ptr< index_blkstore_t< IndexBuffer > > m_index_blk_store;
    std::unique_ptr< sb_blkstore_t > m_sb_blk_store;
    std::unique_ptr< logdev_blkstore_t > m_logdev_blk_store;
    std::unique_ptr< meta_blkstore_t > m_meta_blk_store;
    std::unique_ptr< DeviceManager > m_dev_mgr;
    std::unique_ptr< Cache< BlkId > > m_cache;

private:
    uint64_t m_size_avail = 0;
    uint32_t m_data_pagesz = 0;
}; // namespace homestore
} // namespace homestore
