#include "meta_sb.hpp"
#include "homestore.hpp"
#include "meta_blks_mgr.hpp"
#include "blkstore/blkstore.hpp"

SDS_LOGGING_DECL(metablk)
namespace homestore {

void MetaBlkMgr::init(blk_store_type* sb_blk_store, sb_blkstore_blob* blob, bool is_init) {
    m_sb_blk_store = sb_blk_store;
    if (is_init) {
        // write the meta blk manager's sb;
        init_ssb();
    } else {
        load_ssb(blob);
        scan_meta_blks();
        recover();
    }
}

MetaBlkMgr::~MetaBlkMgr() {
    std::lock_guard< decltype(m_meta_mtx) > lg(m_meta_mtx);
    for (auto it = m_meta_blks.cbegin(); it != m_meta_blks.cend(); it++) {
        for (auto it_m = it->second.cbegin(); it_m != it->second.cend(); it_m++) {
            free(it_m->second);
        }
    }

    for (auto it = m_meta_blks.begin(); it != m_meta_blks.end(); it++) {
        it->second.clear();
    }

    m_meta_blks.clear();

    m_cb_map.clear();

    free(m_ssb);
}

void MetaBlkMgr::load_ssb(sb_blkstore_blob* blob) {
    BlkId bid = blob->blkid;

    m_sb_blk_store->alloc_blk(bid);

    HS_ASSERT(RELEASE, blob->type == blkstore_type::META_STORE, "Invalid blkstore type: {}", blob->type);
    HS_LOG(INFO, metablk, "Loading meta ssb blkid: {}", bid.to_string());

    auto req = blkstore_req< BlkBuffer >::make_request();
    req->isSyncCall = true;

    blk_buf_t bbuf = m_sb_blk_store->read(bid, 0, META_BLK_PAGE_SZ, req);

    homeds::blob b = bbuf->at_offset(0);
    assert(b.size == META_BLK_PAGE_SZ);

    int aret = posix_memalign((void**)&(m_ssb), HS_STATIC_CONFIG(disk_attr.align_size), META_BLK_PAGE_SZ);
    if (aret != 0) {
        assert(0);
        throw std::bad_alloc();
    }

    memset((void*)m_ssb, 0, META_BLK_PAGE_SZ);

    memcpy((void*)m_ssb, b.bytes, sizeof(meta_blk_sb));

    // verify magic
    assert(m_ssb->magic == META_BLK_SB_MAGIC);
}

void MetaBlkMgr::set_migrated() {
    std::lock_guard< decltype(m_meta_mtx) > lg(m_meta_mtx);
    m_ssb->migrated = true;
}

bool MetaBlkMgr::migrated() {
    std::lock_guard< decltype(m_meta_mtx) > lg(m_meta_mtx);
    return m_ssb->migrated;
}

void MetaBlkMgr::init_ssb() {
    BlkId bid;
    auto ret = alloc_meta_blk(bid);
    if (no_error != ret) {
        HS_ASSERT(RELEASE, 0, "alloc blk failed with status: {}", ret.message());
        return;
    }

    struct sb_blkstore_blob blob;
    blob.type = blkstore_type::META_STORE;
    blob.blkid.set(bid);
    m_sb_blk_store->update_vb_context(sisl::blob((uint8_t*)&blob, (uint32_t)sizeof(sb_blkstore_blob)));

    m_ssb = (meta_blk_sb*)iomanager.iobuf_alloc(HS_STATIC_CONFIG(disk_attr.align_size), META_BLK_PAGE_SZ);
    memset((void*)m_ssb, 0, META_BLK_PAGE_SZ);

    std::lock_guard< decltype(m_meta_mtx) > lk(m_meta_mtx);
    assert(m_last_mblk == nullptr);
    m_ssb->next_blkid.set(BlkId::invalid_internal_id());
    m_ssb->prev_blkid.set(BlkId::invalid_internal_id());
    m_ssb->magic = META_BLK_SB_MAGIC;
    m_ssb->version = META_BLK_SB_VERSION;
    m_ssb->migrated = false;
    m_ssb->blkid.set(bid);

    write_ssb();
}

// m_meta_lock should be while calling this function;
void MetaBlkMgr::write_ssb() {
    // persist to disk;
    write_blk(m_ssb->blkid, (void*)m_ssb, META_BLK_PAGE_SZ);
}

//
// TODO:
// Alternatives:
// 1. update this api by look up metablock by chain reading;
// 2. read per chunk;
//
void MetaBlkMgr::scan_meta_blks() {
    m_sb_blk_store->lseek(0, SEEK_SET);
    const uint64_t total_sz = m_sb_blk_store->get_size();

    // this might not be a valid assert, but good to have blkstore size align to 512 bytes;
    assert(total_sz % HS_STATIC_CONFIG(disk_attr.phys_page_size) == 0);

    uint8_t* buf = iomanager.iobuf_alloc(HS_STATIC_CONFIG(disk_attr.align_size), total_sz);
    auto total_bytes_read = m_sb_blk_store->read(buf, total_sz);
    HS_ASSERT(RELEASE, total_bytes_read > 0, "bytes read returned: {} from blkstore.", total_bytes_read);

    // set read_batch_sz to be the chunk size;
    uint64_t read_batch_sz = total_bytes_read;
    while ((uint64_t)total_bytes_read < total_sz) {
        auto bytes_read = m_sb_blk_store->read(buf, read_batch_sz);
        if (bytes_read == -1 || bytes_read == 0) { HS_ASSERT(RELEASE, 0, "read failure from blkstore."); }
        total_bytes_read += bytes_read;
    }

    HS_ASSERT(DEBUG, (uint64_t)total_bytes_read == total_sz, "total read size: {} not equal to total_sz: {}",
              total_bytes_read, total_sz);

    // parse the buf
    std::vector< meta_blk* > mblks;
    extract_meta_blks(buf, total_sz, mblks);
    uint64_t mblk_cnt = 0;

    for (auto it = mblks.begin(); it != mblks.end(); it++) {
        if ((*it)->hdr.magic == META_BLK_MAGIC) {
            auto crc = crc32_ieee(init_crc32, ((uint8_t*)(*it)), sizeof(meta_blk));

            // TODO: internal crc calculation is not correct, crc will change every time it is stored;
            if (crc != (*it)->hdr.crc) { continue; }

            mblk_cnt++;
            meta_blk* mblk = (meta_blk*)iomanager.iobuf_alloc(HS_STATIC_CONFIG(disk_attr.align_size), META_BLK_PAGE_SZ);
            memcpy(*it, mblk, META_BLK_PAGE_SZ);

            if (false == is_meta_blk_type_valid(mblk->hdr.type)) {
                HS_ASSERT(RELEASE, 0, "data corruption found with unrecognized subsystem type.");
            }

            std::lock_guard< decltype(m_meta_mtx) > lk(m_meta_mtx);

            // insert this meta blk to in-memory copy;
            m_meta_blks[mblk->hdr.type][mblk->hdr.blkid.to_integer()] = mblk;

            // alloc this blk id in bitmap
            m_sb_blk_store->alloc_blk(mblk->hdr.blkid);

            // if overflow bid is valid, allocate the overflow bid;
            if (mblk->hdr.ovf_blkid.to_integer() != BlkId::invalid_internal_id()) {
                m_sb_blk_store->alloc_blk(mblk->hdr.ovf_blkid);
            }
        }
    }

    free(buf);

    // starting from the meta ssb
    sanity_check(mblk_cnt);
}

//
// starting from this ssb, verify the blkid/prev_blkid/next_blkid until hit the end of the chain and
//    verify the total entries equal to total_mblks_cnt;
//
bool MetaBlkMgr::sanity_check(const uint64_t total_mblks_cnt) {
    // TODO : to be implemented;
    return true;
}

bool MetaBlkMgr::is_meta_blk_type_valid(meta_sub_type type) {
    bool valid = false;
    switch (type) {
    case meta_sub_type::HOMEBLK:
    case meta_sub_type::VOLUME:
    case meta_sub_type::INDX_MGR_CP:
    case meta_sub_type::JOURNAL:
        valid = true;
        break;
    default:
        valid = false;
    }
    return valid;
}

void MetaBlkMgr::extract_meta_blks(uint8_t* buf, const uint64_t size, std::vector< meta_blk* >& mblks) {
    uint8_t* meta_blk_ptr = buf;
    uint64_t nbytes = META_BLK_PAGE_SZ;

    while (meta_blk_ptr < buf) {
        meta_blk* mblk = (meta_blk*)meta_blk_ptr;
        mblks.push_back(mblk);
        meta_blk_ptr += META_BLK_PAGE_SZ;
    }

    assert(meta_blk_ptr == buf);
}

void MetaBlkMgr::deregister_handler(meta_sub_type type) {
    std::lock_guard< decltype(m_meta_mtx) > lk(m_meta_mtx);

    auto it = m_cb_map.find(type);
    if (it != m_cb_map.end()) { m_cb_map.erase(it); }

    auto cit = m_comp_cb_map.find(type);
    if (cit != m_comp_cb_map.end()) { m_comp_cb_map.erase(cit); }
}

void MetaBlkMgr::register_handler(meta_sub_type type, meta_blk_found_cb cb, meta_blk_recover_comp_cb comp_cb) {
    std::lock_guard< decltype(m_meta_mtx) > lk(m_meta_mtx);
    if (is_meta_blk_type_valid(type)) {
        HS_ASSERT(DEBUG, m_cb_map.find(type) == m_cb_map.end(), "type: {} handler already registered!", type);
    } else {
        HS_ASSERT(RELEASE, 0, "invalide meta subsystem type: {}", type);
    }

    m_cb_map[type] = cb;
    m_comp_cb_map[type] = comp_cb;
}

void MetaBlkMgr::add_sub_sb(meta_sub_type type, void* context_data, uint64_t sz, void*& cookie) {
    BlkId meta_bid;
    auto ret = alloc_meta_blk(meta_bid);

    HS_LOG(INFO, metablk, "adding meta blkid: {}, type: {}", meta_bid.to_string(), type);
    if (no_error != ret) {
        HS_ASSERT(RELEASE, 0, "alloc blk failed with status: {}", ret.message());
        return;
    }

    meta_blk* mblk = init_meta_blk(meta_bid, type, context_data, sz);
    cookie = (void*)mblk;
}

void MetaBlkMgr::write_meta_blk(meta_blk* mblk) {
    homeds::MemVector mvec;

    // recalculate crc before write to disk;
    mblk->hdr.crc = crc32_ieee(init_crc32, ((uint8_t*)mblk), META_BLK_PAGE_SZ);

    try {
        mvec.set((uint8_t*)mblk, META_BLK_PAGE_SZ, 0);
        m_sb_blk_store->write(mblk->hdr.blkid, mvec);
    } catch (std::exception& e) { throw e; }
}

void MetaBlkMgr::write_blk(BlkId bid, void* context_data, uint32_t sz) {
    homeds::MemVector mvec;
    try {
        mvec.set((uint8_t*)context_data, sz, 0);
        m_sb_blk_store->write(bid, mvec);
    } catch (std::exception& e) { throw e; }
}

meta_blk* MetaBlkMgr::init_meta_blk(BlkId bid, meta_sub_type type, void* context_data, size_t sz) {
    meta_blk* mblk = (meta_blk*)iomanager.iobuf_alloc(HS_STATIC_CONFIG(disk_attr.align_size), META_BLK_PAGE_SZ);
    mblk->hdr.blkid.set(bid);
    mblk->hdr.type = type;

    std::lock_guard< decltype(m_meta_mtx) > lg(m_meta_mtx);
    mblk->hdr.magic = META_BLK_MAGIC;

    // handle prev/next pointer linkage;
    if (m_last_mblk) {
        mblk->hdr.prev_blkid.set(m_last_mblk->hdr.blkid);
        assert(m_last_mblk->hdr.next_blkid.to_integer() == BlkId::invalid_internal_id());
        m_last_mblk->hdr.next_blkid.set(bid);

        // persist the changes;
        write_meta_blk(m_last_mblk);
    } else {
        // this is the first sub sb being added;
        mblk->hdr.prev_blkid.set(m_ssb->blkid);
        assert(m_ssb->next_blkid.to_integer() == BlkId::invalid_internal_id());
        m_ssb->next_blkid.set(bid);

        // persiste the changes;
        write_ssb();
    }

    mblk->hdr.next_blkid.set(BlkId::invalid_internal_id());

    // write this meta blk to disk
    write_meta_blk_internal(mblk, context_data, sz);

    // update in-memory data structure;
    m_last_mblk = mblk;

    m_meta_blks[type][bid.to_integer()] = mblk;

    return mblk;
}

void MetaBlkMgr::write_meta_blk_internal(meta_blk* mblk, void* context_data, uint64_t sz) {
    mblk->hdr.context_sz = sz;

    // within 512 Bytes
    if (sz <= META_BLK_CONTEXT_SZ) {
        // for inline case, set ovf_blkid to invalid
        mblk->hdr.ovf_blkid.set(BlkId::invalid_internal_id());

        memcpy(mblk->context_data, context_data, sz);
    } else {
        // overflow handling
        assert(sz % META_BLK_PAGE_SZ == 0);
        BlkId obid;
        auto ret = alloc_meta_blk(obid, sz);

        HS_LOG(INFO, metablk, "allocating overflow bid: {}, sz: {}", obid.to_string(), sz);

        if (ret != no_error) {
            HS_LOG(ERROR, metablk, "Failed to allocate contigous overflow blk with size: {}", sz);
            HS_ASSERT(RELEASE, 0, "failed to allocate overflow blk id with size: {}", sz);
        }

        mblk->hdr.ovf_blkid = obid;

        // write overflow block to disk;
        write_blk(obid, context_data, sz);
    }

    // write meta blk;
    write_meta_blk(mblk);
}

void MetaBlkMgr::update_sub_sb(meta_sub_type type, void* context_data, uint64_t sz, void*& cookie) {
    //
    // Do in-place update, don't update prev/next meta blk;
    // 1. free old ovf_blkid if there is any
    // 2. allcate ovf_blkid if needed
    // 3. update the meta_blk
    std::lock_guard< decltype(m_meta_mtx) > lg(m_meta_mtx);
    meta_blk* mblk = (meta_blk*)cookie;

    LOGINFO("old sb: context_sz: {}, ovf_blkid: {}", (unsigned long)(mblk->hdr.context_sz),
            mblk->hdr.ovf_blkid.to_string());

    // free the overflow blkid if it is there
    // TODO: try to remove this lock as it is not required and we don't need to hold lock for concurrent write while
    // writing to blkstore. And if without lock, this free should happen after meta blk is updated;
    if (mblk->hdr.ovf_blkid.to_integer() != BlkId::invalid_internal_id()) {
        m_sb_blk_store->free_blk(mblk->hdr.ovf_blkid, 0, mblk->hdr.context_sz);
        mblk->hdr.ovf_blkid.set(BlkId::invalid_internal_id());
    }

    // write this meta blk to disk
    write_meta_blk_internal(mblk, context_data, sz);

    LOGINFO("new sb: context_sz: {}, ovf_blkid: {}", mblk->hdr.context_sz, mblk->hdr.ovf_blkid.to_string());

    // no need to update cookie and in-memory meta blk map since they
    // all points to same memory address that does't change;
}

std::error_condition MetaBlkMgr::remove_sub_sb(void* cookie) {
    meta_blk* rm_blk = (meta_blk*)cookie;
    BlkId bid = rm_blk->hdr.blkid;
    auto type = rm_blk->hdr.type;

    std::lock_guard< decltype(m_meta_mtx) > lg(m_meta_mtx);

    // type must exist
    assert(m_meta_blks.find(type) != m_meta_blks.end());

    // remove from disk;
    auto prev_blkid = m_meta_blks[type][bid.to_integer()]->hdr.prev_blkid;
    auto next_blkid = m_meta_blks[type][bid.to_integer()]->hdr.next_blkid;

    HS_LOG(INFO, metablk, "removing meta blk id: {}, type: {}, prev_blkid: {}, next_blkid: {}", bid.to_string(), type,
           prev_blkid.to_string(), next_blkid.to_string());

    // this record must exist in-memory copy
    assert(m_meta_blks[type].find(bid.to_integer()) != m_meta_blks[type].end());

    assert(m_meta_blks[type][bid.to_integer()] == rm_blk);

    // remove the in-memory handle from meta blk map;
    m_meta_blks[rm_blk->hdr.type].erase(bid.to_integer());
    assert(m_meta_blks[type].find(bid.to_integer()) == m_meta_blks[type].end());

    // 1. update prev-blk's next pointer
    if (prev_blkid.to_integer() == m_ssb->blkid.to_integer()) {
        m_ssb->next_blkid.set(next_blkid);
        // persist m_ssb to disk;
        write_ssb();

        if (m_last_mblk == rm_blk) { m_last_mblk = nullptr; }
    } else {
        auto found = false;
        // find the in-memory copy of prev meta block;
        for (auto& x : m_meta_blks) {
            if (x.second.find(prev_blkid.to_integer()) != x.second.end()) {
                found = true;
                auto prev_mblk = x.second[prev_blkid.to_integer()];

                // update prev meta blk's both in-memory and on-disk copy;
                prev_mblk->hdr.next_blkid.set(next_blkid);
                write_meta_blk(prev_mblk);

                // if we are removing the last meta blk, update m_last_mblk to its previous blk;
                if (m_last_mblk == rm_blk) { m_last_mblk = prev_mblk; }

                break;
            }
        }

        if (!found) { HS_ASSERT(DEBUG, found, "prev_blkid: {} not found", prev_blkid.to_string()); }
    }

    // 2. update next-blk's prev pointer
    if (next_blkid.to_integer() != BlkId::invalid_internal_id()) {
        auto found = false;
        for (auto& x : m_meta_blks) {
            if (x.second.find(next_blkid.to_integer()) != x.second.end()) {
                found = true;
                auto next_mblk = x.second[next_blkid.to_integer()];

                // update next meta blk's both in-memory and on-disk copy;
                next_mblk->hdr.prev_blkid.set(prev_blkid);
                write_meta_blk(next_mblk);
                break;
            }
        }

        if (!found) { HS_ASSERT(DEBUG, true, "next_blkid: {} not found", next_blkid.to_string()); }
    }

    // free the on-disk meta blk
    free_meta_blk(rm_blk);

    return no_error;
}

void MetaBlkMgr::free_meta_blk(meta_blk* mblk) {
    m_sb_blk_store->free_blk(mblk->hdr.blkid, boost::none, boost::none);

    // free the overflow blkid if it is there
    if (mblk->hdr.ovf_blkid.to_integer() != BlkId::invalid_internal_id()) {
        assert(mblk->hdr.context_sz >= META_BLK_PAGE_SZ);
        m_sb_blk_store->free_blk(mblk->hdr.ovf_blkid, 0, mblk->hdr.context_sz);
    }

    free(mblk);
}

std::error_condition MetaBlkMgr::alloc_meta_blk(BlkId& bid, uint32_t alloc_sz) {
    blk_alloc_hints hints;
    hints.desired_temp = 0;
    hints.dev_id_hint = -1;
    hints.is_contiguous = true;
    try {
        auto ret = m_sb_blk_store->alloc_blk(alloc_sz, hints, &bid);
        if (ret != BLK_ALLOC_SUCCESS) {
            HS_LOG(ERROR, metablk, "failing as it is out of disk space!");
            return std::errc::no_space_on_device;
        }
    } catch (const std::exception& e) {
        HS_ASSERT(RELEASE, 0, "{}", e.what());
        return std::errc::device_or_resource_busy;
    }

    return no_error;
}

void MetaBlkMgr::recover() {
    for (auto type : sub_priority_list) {
        auto it = m_meta_blks.find(type);
        if (it == m_meta_blks.end()) { continue; }

        auto cb_it = m_cb_map.find(type);
        auto comp_cb_it = m_comp_cb_map.find(type);
        HS_ASSERT(RELEASE, cb_it != m_cb_map.end(), "nullptr blk found cb for type: {}", type);
        HS_ASSERT(RELEASE, comp_cb_it != m_comp_cb_map.end(), "null recover compl cb for type: {}", type);

        meta_blk_found_cb cb = cb_it->second;

        for (auto& m : it->second) {
            auto buf = sisl::make_aligned_unique< uint8_t >(dma_boundary, m.second->hdr.context_sz);

            if (m.second->hdr.context_sz <= META_BLK_CONTEXT_SZ) {
                HS_ASSERT(RELEASE, m.second->hdr.ovf_blkid.to_integer() == BlkId::invalid_internal_id(),
                          "corrupted ovf_blkid: {}", m.second->hdr.ovf_blkid.to_string());
                memcpy(buf.get(), (void*)m.second->context_data, m.second->hdr.context_sz);
            } else {
                HS_ASSERT(RELEASE, m.second->hdr.ovf_blkid.to_integer() != BlkId::invalid_internal_id(),
                          "corrupted ovf_blkid: {}", m.second->hdr.ovf_blkid.to_string());
                // TODO: handle ovf_blk buffer chain;
            }
            cb(m.second, std::move(buf), m.second->hdr.context_sz);
        }
    }

    for (auto type : sub_priority_list) {
        auto it = m_comp_cb_map.find(type);

        if (it == m_comp_cb_map.end()) { continue; }

        meta_blk_recover_comp_cb comp_cb = it->second;

        // notify each subsystem that recovery has completed;
        comp_cb(true);
    }
}

MetaBlkMgr* MetaBlkMgr::_instance = nullptr;
} // namespace homestore
