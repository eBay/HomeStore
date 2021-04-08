/* If it exceeds 8k then we need to use two buffer to keep the data consistent */
struct vol_ondisk_sb {
    uint64_t magic;
    uint64_t version;
    uint32_t gen_cnt;
    BlkId blkid;
    boost::uuids::uuid uuid;

    BlkId next_blkid;
    BlkId prev_blkid;

    vol_state state;
    uint64_t page_size;
    uint64_t size;
    char vol_name[VOL_NAME_SIZE];
    homeds::btree::btree_super_block btree_sb;

    vol_state get_state() const { return state; }
    uint64_t get_page_size() const { return page_size; }
    uint64_t get_size() const { return size; }
    const char* get_vol_name() const { return vol_name; }
} __attribute((packed));

bool HomeBlks::vol_sb_sanity(vol_mem_sb* sb) {
    return ((sb->ondisk_sb->magic == VOL_SB_MAGIC) && (sb->ondisk_sb->version == VOL_SB_VERSION));
}

vol_mem_sb* HomeBlks::vol_sb_read(BlkId bid) {
    bool rewrite = false;
    if (!bid.is_valid()) return nullptr;
    std::vector< blk_buf_t > bbuf = m_sb_blk_store->read_nmirror(bid, m_cfg.devices.size() - 1);
    blk_buf_t valid_buf = get_valid_buf(bbuf, rewrite);

    vol_mem_sb* sb = new vol_mem_sb(HomeStoreConfig::align_size, VOL_SB_SIZE);
    memcpy(sb->ondisk_sb.get(), valid_buf->at_offset(0).bytes, sizeof(vol_ondisk_sb));

    // TODO: how do we recover this if it fails in release mode?
    assert(sb->ondisk_sb->blkid.to_integer() == bid.to_integer());

    if (!vol_sb_sanity(sb)) {
        VOL_ERROR_LOG(sb->ondisk_sb->vol_name, "Sanity check failure in volume superblock");
        return nullptr;
    }

    if (rewrite) {
        /* update the super block */
        vol_sb_write(sb);
    }

    return sb;
}

blk_buf_t HomeBlks::get_valid_buf(const std::vector< blk_buf_t >& bbuf, bool& rewrite) {
    blk_buf_t valid_buf = nullptr;
    uint32_t gen_cnt = 0;
    boost::uuids::uuid uuid;
    for (uint32_t i = 0; i < bbuf.size(); i++) {
        vol_ondisk_sb* hdr = (vol_ondisk_sb*)(bbuf[i]->at_offset(0).bytes);

        if (hdr->magic != VOL_SB_MAGIC || hdr->version != VOL_SB_VERSION) {
            LOGINFO("found superblock with invalid magic and version");
            continue;
        }

        if (gen_cnt == 0) {
            /* update only for first valid sb */
            uuid = hdr->uuid;
        }

        /* It is not possible to get two valid super blocks with different uuid. */
        HS_ASSERT_CMP(RELEASE, uuid, ==, hdr->uuid)

        if (hdr->gen_cnt > gen_cnt) {
            if (valid_buf != nullptr) {
                /* superblock is not consistent across the disks */
                rewrite = true;
                LOGINFO("gen_cnt is mismatched of vol superblock");
            }
            gen_cnt = hdr->gen_cnt;
            valid_buf = bbuf[i];
        }
    }
    assert(gen_cnt > 0);
    return valid_buf;
}

//
// TODO: Do we need to handle shutdown request during scan_volumes since it may take a long to
// time to finish scan all the volumes?
//
// Does it make sense to let consumer wait until a shutdown request can be served by HomeStore after scan_volumes?
//
void HomeBlks::scan_volumes() {
    auto blkid = m_homeblks_sb->vol_list_head;
    bool rewrite = false;
    m_scan_cnt++;
    int num_vol = 0;
#ifdef _PRERELEASE
    if (homestore_flip->test_flip("reboot_abort")) { abort(); }
#endif
    try {
        while (blkid.is_valid()) {
            vol_mem_sb* sb = vol_sb_read(blkid);
            if (sb == nullptr) {
                // TODO: Error handling here...
            }

            auto vol_uuid = sb->ondisk_sb->uuid;

            if (!m_cfg.vol_found_cb(vol_uuid)) {
                VOL_INFO_LOG(vol_uuid, "Deleting the volume after recovery: Vol name {}", sb->ondisk_sb->vol_name);
                //                             boost::uuids::to_string(vol_uuid));

                /* don't need to mount this volume. Delete this volume. Its block will be recaimed automatically */
                if (m_last_vol_sb) {
                    m_last_vol_sb->ondisk_sb->next_blkid = sb->ondisk_sb->next_blkid;
                    /* write vdev superblocks */
                    vol_sb_write(m_last_vol_sb);
                } else {
                    m_homeblks_sb->vol_list_head = sb->ondisk_sb->next_blkid;
                }
                m_homeblks_sb->num_vols--;
            } else {
                /* create the volume */
                assert(sb->ondisk_sb->state != vol_state::DESTROYING);
                if (m_last_vol_sb && BlkId::compare(sb->ondisk_sb->prev_blkid, m_last_vol_sb->ondisk_sb->blkid)) {
                    /* prev volume is deleted. update the prev blkid */
                    LOGINFO("updating the previous volume blkid");
                    sb->ondisk_sb->prev_blkid.set(m_last_vol_sb->ondisk_sb->blkid);
                    vol_sb_write(sb);
                }

                if (sb->ondisk_sb->state == vol_state::ONLINE && m_vdev_failed) {
                    /* Move all the volumes to failed state */
                    sb->ondisk_sb->state = vol_state::FAILED;
                    vol_sb_write(sb);
                }
                num_vol++;
                decltype(m_volume_map)::iterator it;

                bool happened{false};
                std::tie(it, happened) = m_volume_map.emplace(std::make_pair(vol_uuid, nullptr));
                assert(happened);

                m_scan_cnt++;
                VolumePtr new_vol;
                try {
                    new_vol = Volume::make_volume(sb);
                    new_vol->recovery_start();
                } catch (const std::exception& e) {
                    m_scan_cnt--;
                    throw e;
                }
                it->second = new_vol;

                /* allocate this blkid in the sb blkstore */
                m_sb_blk_store->reserve_blk(blkid);
                m_last_vol_sb = sb;
            }
            blkid = sb->ondisk_sb->next_blkid;
            VOL_INFO_LOG(sb->ondisk_sb->uuid, "Found the volume name: {}", sb->ondisk_sb->vol_name);
        }
        assert(num_vol <= m_homeblks_sb->num_vols);
        m_homeblks_sb->num_vols = num_vol;
        if (!m_cfg.is_read_only) { homeblks_sb_write(); }
        /* clear the state in virtual devices as appropiate state is set in volume superblocks */
        if (m_vdev_failed) {
            m_data_blk_store->reset_vdev_failed_state();
            m_metadata_blk_store->reset_vdev_failed_state();
            m_sb_blk_store->reset_vdev_failed_state();
            m_logdev_blk_store->reset_vdev_failed_state();
            m_vdev_failed = false;
        }
    } catch (const std::exception& e) {
        m_init_failed = true;
        int cnt = m_scan_cnt.fetch_sub(1, std::memory_order_relaxed);
        if (cnt == 1) {
            LOGERROR("{}", e.what());
            auto error = std::make_error_condition(std::errc::io_error);
            init_done(error, m_out_params);
        }
        return;
    }

    int cnt = m_scan_cnt.fetch_sub(1, std::memory_order_relaxed);
    if (cnt == 1) {
        m_rdy = true;
        m_dev_mgr->inited();
        init_done(no_error, m_out_params);
    }
}

void HomeBlks::create_sb_blkstore(vdev_info_block* vb) {
    /* create a blkstore */
    m_sb_blk_store = std::make_unique< sb_blkstore_t >(m_dev_mgr.get(), m_cache.get(), vb, BlkStoreCacheType::PASS_THRU,
                                                       HomeStoreConfig::atomic_phys_page_size, "superblock", false);
    if (vb->failed) {
        m_vdev_failed = true;
        LOGINFO("super block store is in failed state");
    }

    /* get the blkid of homeblks super block */
    sb_blkstore_blob* blob = (sb_blkstore_blob*)(&(vb->context_data));
    if (!blob->blkid.is_valid()) {
        LOGINFO("init was failed last time. Should retry it with init flag");
        throw homestore::homestore_exception("init was failed last time. Should retry it with init",
                                             homestore_error::init_failed);
    }

    /* read and build the homeblks super block */
    std::vector< blk_buf_t > bbuf = m_sb_blk_store->read_nmirror(blob->blkid, m_cfg.devices.size() - 1);
    bool rewrite = false;
    blk_buf_t valid_buf = get_valid_buf(bbuf, rewrite);
    memcpy(m_homeblks_sb.get(), valid_buf->at_offset(0).bytes, sizeof(*m_homeblks_sb));
    assert(m_homeblks_sb->gen_cnt > 0);
    assert(m_homeblks_sb->blkid.to_integer() == blob->blkid.to_integer());
    m_homeblks_sb->boot_cnt++;

    /* update the homeblks super block */
    if (!m_cfg.is_read_only) { homeblks_sb_write(); }
}

void HomeBlks::superblock_load(const std::vector< blk_buf_t >& bbuf, BlkId sb_blk_id) {
    bool rewrite = false;
    blk_buf_t valid_buf = get_valid_buf(bbuf, rewrite);
    memcpy(m_homeblks_sb.get(), valid_buf->at_offset(0).bytes, sizeof(*m_homeblks_sb));
    assert(m_homeblks_sb->gen_cnt > 0);
    assert(m_homeblks_sb->blkid.to_integer() == sb_blk_id.to_integer());
    m_homeblks_sb->boot_cnt++;

    /* update the homeblks super block */
    if (!m_cfg.is_read_only) { homeblks_sb_write(); }
}

void Volume::vol_scan_alloc_blks() {
    std::vector< ThreadPool::TaskFuture< void > > task_result;
    task_result.push_back(submit_job([this]() { this->get_allocated_blks(); }));
    return;
}

std::error_condition Volume::alloc_blk(volume_req_ptr& vreq, std::vector< BlkId >& bid) {
    blk_alloc_hints hints;
    hints.desired_temp = 0;
    hints.dev_id_hint = -1;
    hints.multiplier = (get_page_size() / m_hb->get_data_pagesz());

    THIS_VOL_LOG(TRACE, volume, vreq, "write: lba={}, nlbas={}", vreq->lba, vreq->nlbas);
    try {
        BlkAllocStatus status = m_hb->get_data_blkstore()->alloc_blk(vreq->nlbas * get_page_size(), hints, bid);
        if (status != BlkAllocStatus::SUCCESS) {
            if (status == BlkAllocStatus::PARTIAL) { m_hb->get_data_blkstore()->free(bid); }
            LOGERROR("failing IO as it is out of disk space");
            check_and_complete_req(vreq, std::make_error_condition(std::errc::no_space_on_device));
            return std::errc::no_space_on_device;
        }
        assert(status == BlkAllocStatus::SUCCESS);
        HISTOGRAM_OBSERVE(m_metrics, volume_blkalloc_latency, get_elapsed_time_ns(vreq->io_start_time));
        COUNTER_INCREMENT(m_metrics, volume_write_count, 1);
    } catch (const std::exception& e) {
        VOL_LOG_ASSERT(0, vreq, "Exception: {}", e.what());
        return std::errc::device_or_resource_busy;
    }
    return no_error;
}

void Volume::get_allocated_blks() {

    mapping* mp = get_mapping_handle();

    int64_t max_lba = get_last_lba();

    int64_t start_lba = 0, end_lba = -1;

    std::vector< ThreadPool::TaskFuture< void > > v;

    bool success = true;
    while (end_lba < max_lba) {
        // if high watermark is hit, wait for a while so that we do not consuming too
        // much memory pushing new tasks. This is helpful when volume size is extreamly large.
        if (get_thread_pool().high_watermark()) {
            std::this_thread::yield();
            continue;
        }

        start_lba = end_lba + 1;
        end_lba = std::min((uint64_t)max_lba, end_lba + HB_DYNAMIC_CONFIG(volume->blks_scan_query_batch_size));
        v.push_back(submit_job([this, start_lba, end_lba, mp]() {
            if (mp->sweep_alloc_blks(start_lba, end_lba)) { this->set_recovery_error(); }
        }));
    }

    for (auto& x : v) {
        x.get();
    }

    // return completed with success to the caller
    blk_recovery_process_completions(!m_recovery_error);
}

void Volume::alloc_blk_callback(struct BlkId bid, size_t offset_size, size_t size) {
    assert(get_state() == vol_state::MOUNTING);
    BlkId free_bid(bid.get_blkid_at(offset_size, size, m_hb->get_data_pagesz()));
    THIS_VOL_LOG(TRACE, volume, , "bid={}", free_bid.to_string());
    m_hb->get_data_blkstore()->reserve_blk(free_bid);
    m_used_size.fetch_add(size, std::memory_order_relaxed);
}
