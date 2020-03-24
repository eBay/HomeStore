#include "homestore.hpp"
#include "homelogstore/log_store.hpp"

namespace homestore {
template < typename IndexBuffer >
void HomeStore< IndexBuffer >::init(const hs_input_params& input) {
    auto& hs_config = HomeStoreStaticConfig::instance();

    /* set the homestore static config parameters */
    hs_config.input = input;
    hs_config.disk_attr = (input.disk_attr) ? input.disk_attr : get_disk_attrs(input.is_file);

#ifndef NDEBUG
    flip::Flip::instance().start_rpc_server();
#endif

    /* Btree leaf node in index btree should accamodate minimum 2 entries to do the split. And on a average
     * a value consume 2 bytes (for checksum) per blk and few bytes for each IO and node header.
     * max_blk_cnt represents max number of blks blk allocator should give in a blk. We are taking
     * conservatively 4 entries in a node with avg size of 2 for each blk.
     * Note :- This restriction will go away once btree start supporinting higher size value.
     */
    hs_config.generic.max_blk_cnt = hs_config.disk_attr.atomic_phys_page_size / (4 * 2);
    m_data_pagesz = input.min_virtual_page_size;

    if (input.devices.size() == 0) {
        LOGERROR("no devices given");
        throw std::invalid_argument("null device list");
    }

    std::ofstream hs_config_stream("hs_static_config.json");
    auto json = hs_config.to_json();
    hs_config_stream << json.dump(4);
    LOGINFO("HomeStore starting with config: {}", json);

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

template < typename IndexBuffer >
disk_attributes HomeStore< IndexBuffer >::get_disk_attrs(bool is_file) {
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

template < typename IndexBuffer >
cap_attrs HomeStore< IndexBuffer >::get_system_capacity() {
    cap_attrs cap;
    cap.used_data_size = get_data_blkstore()->get_used_size();
    cap.used_index_size = get_index_blkstore()->get_used_size();
    cap.used_total_size = cap.used_data_size + cap.used_index_size;
    cap.initial_total_size = get_data_blkstore()->get_size() + get_index_blkstore()->get_size();
    return cap;
}

template < typename IndexBuffer >
BlkId HomeStore< IndexBuffer >::alloc_sb_blk() {
    BlkId bid;
    blk_alloc_hints hints;
    hints.desired_temp = 0;
    hints.dev_id_hint = -1;
    hints.is_contiguous = true;
    auto ret = m_sb_blk_store->alloc_blk(VOL_SB_SIZE, hints, &bid);
    if (ret != BLK_ALLOC_SUCCESS) {
        throw homestore::homestore_exception("space not available", homestore_error::space_not_avail);
    }
    assert(ret == BLK_ALLOC_SUCCESS);
    return bid;
}

template < typename IndexBuffer >
void HomeStore< IndexBuffer >::init_devices() {
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
    }
}

template < typename IndexBuffer >
void HomeStore< IndexBuffer >::new_vdev_found(DeviceManager* dev_mgr, vdev_info_block* vb) {
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
    default:
        HS_ASSERT(LOGMSG, 0, "Unknown blkstore_type {}", blob->type);
    }
}

template < typename IndexBuffer >
void HomeStore< IndexBuffer >::create_data_blkstore(vdev_info_block* vb) {
    if (vb == nullptr) {
        /* change it to context */
        struct blkstore_blob blob;
        blob.type = blkstore_type::DATA_STORE;
        uint64_t size = (90 * m_dev_mgr->get_total_cap()) / 100;
        size = ALIGN_SIZE(size, HS_STATIC_CONFIG(disk_attr.phys_page_size));
        m_size_avail = size;
        LOGINFO("maximum capacity for data blocks is {}", m_size_avail);
        m_data_blk_store =
            std::make_unique< data_blkstore_t >(m_dev_mgr.get(), m_cache.get(), size, WRITEBACK_CACHE, 0, (char*)&blob,
                                                sizeof(blkstore_blob), m_data_pagesz, "data", data_completion_cb());
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

template < typename IndexBuffer >
void HomeStore< IndexBuffer >::create_index_blkstore(vdev_info_block* vb) {
    if (vb == nullptr) {
        struct blkstore_blob blob;
        blob.type = blkstore_type::INDEX_STORE;
        uint64_t size = (2 * m_dev_mgr->get_total_cap()) / 100;
        size = ALIGN_SIZE(size, HS_STATIC_CONFIG(disk_attr.phys_page_size));
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

template < typename IndexBuffer >
void HomeStore< IndexBuffer >::create_sb_blkstore(vdev_info_block* vb) {
    if (vb == nullptr) {
        /* create a blkstore */
        struct sb_blkstore_blob blob;
        blob.type = blkstore_type::SB_STORE;
        blob.blkid.set(BlkId::invalid_internal_id());
        uint64_t size = (1 * m_dev_mgr->get_total_cap()) / 100;
        size = ALIGN_SIZE(size, HS_STATIC_CONFIG(disk_attr.phys_page_size));
        m_sb_blk_store = std::make_unique< sb_blkstore_t >(
            m_dev_mgr.get(), m_cache.get(), size, PASS_THRU, HS_STATIC_CONFIG(input.devices).size() - 1, (char*)&blob,
            sizeof(sb_blkstore_blob), HS_STATIC_CONFIG(disk_attr.atomic_phys_page_size), "superblock");

        /* allocate a new blk id */
        BlkId bid = alloc_sb_blk();
        blob.type = blkstore_type::SB_STORE;
        blob.blkid.set(bid);

        /* build the appln super block */
        superblock_init(bid);

        /* update the context info */
        m_sb_blk_store->update_vb_context(sisl::blob((uint8_t*)&blob, (uint32_t)sizeof(sb_blkstore_blob)));
    } else {
        /* create a blkstore */
        m_sb_blk_store =
            std::make_unique< sb_blkstore_t >(m_dev_mgr.get(), m_cache.get(), vb, PASS_THRU,
                                              HS_STATIC_CONFIG(disk_attr.atomic_phys_page_size), "superblock", false);
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
        superblock_load(bbuf, blob->blkid);
    }
}

template < typename IndexBuffer >
void HomeStore< IndexBuffer >::create_logdev_blkstore(vdev_info_block* vb) {
    if (vb == nullptr) {
        struct blkstore_blob blob;
        blob.type = blkstore_type::LOGDEV_STORE;
        uint64_t size = (1 * m_dev_mgr->get_total_cap()) / 100;
        size = ALIGN_SIZE(size, HS_STATIC_CONFIG(disk_attr.phys_page_size));
        m_logdev_blk_store = std::make_unique< BlkStore< VdevVarSizeBlkAllocatorPolicy > >(
            m_dev_mgr.get(), m_cache.get(), size, PASS_THRU, 0, (char*)&blob, sizeof(blkstore_blob),
            HS_STATIC_CONFIG(disk_attr.atomic_phys_page_size), "logdev",
            std::bind(&LogDev::process_logdev_completions, &HomeLogStoreMgr::logdev(), std::placeholders::_1));
    } else {
        m_logdev_blk_store = std::make_unique< BlkStore< VdevVarSizeBlkAllocatorPolicy > >(
            m_dev_mgr.get(), m_cache.get(), vb, PASS_THRU, HS_STATIC_CONFIG(disk_attr.atomic_phys_page_size), "logdev",
            (vb->failed ? true : false),
            std::bind(&LogDev::process_logdev_completions, &HomeLogStoreMgr::logdev(), std::placeholders::_1));
        if (vb->failed) {
            m_vdev_failed = true;
            LOGINFO("logdev block store is in failed state");
        }
    }
    home_log_store_mgr.start((vb == nullptr));
}

} // namespace homestore