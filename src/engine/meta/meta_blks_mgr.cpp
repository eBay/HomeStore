#include "meta_sb.hpp"
#include "homestore.hpp"
#include "meta_blks_mgr.hpp"
#include "blkstore/blkstore.hpp"

SDS_LOGGING_DECL(metablk)
namespace homestore {

void MetaBlkMgr::start(blk_store_t* sb_blk_store, const sb_blkstore_blob* blob, const bool is_init) {
    m_sb_blk_store = sb_blk_store;
    if (is_init) {
        // write the meta blk manager's sb;
        init_ssb();
    } else {
        load_ssb(blob);
        scan_meta_blks();
        m_sb_blk_store->recovery_done();
    }
    recover();
}

void MetaBlkMgr::stop() { del_instance(); }

void MetaBlkMgr::cache_clear() {
    std::lock_guard< decltype(m_meta_mtx) > lg(m_meta_mtx);
    for (auto it = m_meta_blks.cbegin(); it != m_meta_blks.cend(); it++) {
        for (auto it_m = it->second.cbegin(); it_m != it->second.cend(); it_m++) {
            iomanager.iobuf_free((uint8_t*)(it_m->second));
        }
    }

    for (auto it = m_meta_blks.begin(); it != m_meta_blks.end(); it++) {
        it->second.clear();
    }

    for (auto it = m_ovf_blk_hdrs.cbegin(); it != m_ovf_blk_hdrs.end(); it++) {
        iomanager.iobuf_free((uint8_t*)(it->second));
    }

    m_meta_blks.clear();
    m_ovf_blk_hdrs.clear();
}

MetaBlkMgr::~MetaBlkMgr() {
    std::lock_guard< decltype(m_meta_mtx) > lg_shutdown(m_shutdown_mtx);
    cache_clear();

    std::lock_guard< decltype(m_meta_mtx) > lg(m_meta_mtx);
    m_sub_info.clear();
    iomanager.iobuf_free((uint8_t*)m_ssb);
}

// sync read
void MetaBlkMgr::read(BlkId& bid, sisl::blob& b) {
    auto req = blkstore_req< BlkBuffer >::make_request();
    req->isSyncCall = true;

    auto bbuf = m_sb_blk_store->read(bid, 0, META_BLK_PAGE_SZ, req);
    b = bbuf->at_offset(0);
    HS_ASSERT_CMP(DEBUG, b.size, ==, META_BLK_PAGE_SZ);
}

void MetaBlkMgr::load_ssb(const sb_blkstore_blob* blob) {
    BlkId bid = blob->blkid;

    m_sb_blk_store->reserve_blk(bid);

    HS_ASSERT(RELEASE, blob->type == blkstore_type::META_STORE, "Invalid blkstore type: {}", blob->type);
    HS_LOG(INFO, metablk, "Loading meta ssb blkid: {}", bid.to_string());

    sisl::blob b;
    read(bid, b);

    m_ssb = (meta_blk_sb*)iomanager.iobuf_alloc(HS_STATIC_CONFIG(disk_attr.align_size), META_BLK_PAGE_SZ);

    memset((void*)m_ssb, 0, META_BLK_PAGE_SZ);
    memcpy((void*)m_ssb, b.bytes, sizeof(meta_blk_sb));

    // verify magic
    HS_ASSERT_CMP(DEBUG, (uint32_t)m_ssb->magic, ==, META_BLK_SB_MAGIC);
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
    HS_ASSERT(DEBUG, m_last_mblk == nullptr, "last mblk is not null, memory corruption!");
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

void MetaBlkMgr::scan_meta_blks() {
    cache_clear();

    // take a look so that before scan is complete, no add/remove/update operations will be allowed;
    std::lock_guard< decltype(m_meta_mtx) > lg(m_meta_mtx);
    auto bid = m_ssb->next_blkid;

    while (bid.to_integer() != BlkId::invalid_internal_id()) {
        sisl::blob b;
        read(bid, b);
        auto mblk = (meta_blk*)b.bytes;

        m_last_mblk = mblk;

        // TODO: add a new API in blkstore read to by pass cache;
        // e.g. take caller's read buf to avoid this extra memory copy;
        uint8_t* buf = iomanager.iobuf_alloc(HS_STATIC_CONFIG(disk_attr.align_size), b.size);
        memcpy(buf, b.bytes, b.size);

        // add meta blk to cache;
        m_meta_blks[mblk->hdr.h.type][mblk->hdr.h.blkid.to_integer()] = (meta_blk*)buf;

        // mark allocated for this block
        m_sb_blk_store->reserve_blk(mblk->hdr.h.blkid);

        // populate overflow blk chain;
        auto obid = mblk->hdr.h.ovf_blkid;

        // used to valid linkage chain;
        auto prev_obid = mblk->hdr.h.blkid;

        HS_ASSERT(RELEASE, prev_obid.to_integer() == bid.to_integer(),
                  "corrupted: meta_ssb's next_blkid:{} should equal to meta_blk's blkid: {}", bid.to_string(),
                  prev_obid.to_string());

        uint64_t read_sz = mblk->hdr.h.context_sz >= META_BLK_CONTEXT_SZ ? META_BLK_CONTEXT_SZ : mblk->hdr.h.context_sz;

        while (obid.to_integer() != BlkId::invalid_internal_id()) {
            sisl::blob b;
            read(obid, b);

            auto ovf_hdr = (meta_blk_ovf_hdr*)b.bytes;

            uint8_t* ovf_hdr_cp =
                iomanager.iobuf_alloc(HS_STATIC_CONFIG(disk_attr.align_size), META_BLK_OVF_HDR_MAX_SZ);
            memcpy(ovf_hdr_cp, b.bytes, META_BLK_OVF_HDR_MAX_SZ);

            // verify linkage;
            HS_ASSERT(RELEASE, ovf_hdr->h.blkid.to_integer() == obid.to_integer(), "Corrupted self-bid: {}/{}",
                      ovf_hdr->h.blkid.to_string(), obid.to_string());
            HS_ASSERT(RELEASE, ovf_hdr->h.prev_blkid.to_integer() == prev_obid.to_integer(),
                      "Corrupted prev_blkid: {}/{}", ovf_hdr->h.prev_blkid.to_string(), prev_obid.to_string());

            read_sz += ovf_hdr->h.context_sz;

            // add to ovf blk cache;
            m_ovf_blk_hdrs[obid.to_integer()] = (meta_blk_ovf_hdr*)ovf_hdr_cp;

            // allocate overflow blkid;
            m_sb_blk_store->reserve_blk(obid);

            prev_obid = obid;

            // move on to next overflow blk;
            obid = ovf_hdr->h.next_blkid;
        }

        HS_ASSERT(RELEASE, read_sz == mblk->hdr.h.context_sz,
                  "total size read: {} mismatch from meta blk context_sz: {}", read_sz,
                  (uint64_t)mblk->hdr.h.context_sz);

        // move on to next meta blk;
        bid = mblk->hdr.h.next_blkid;
    }
}

//
// read per chunk is not used yet;
//
void MetaBlkMgr::scan_meta_blks_per_chunk() {
    m_sb_blk_store->lseek(0, SEEK_SET);
    const uint64_t total_sz = m_sb_blk_store->get_size();

    // this might not be a valid assert, but good to have blkstore size align to 512 bytes;
    HS_ASSERT_CMP(DEBUG, total_sz % HS_STATIC_CONFIG(disk_attr.phys_page_size), ==, 0);

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
        if ((*it)->hdr.h.magic == META_BLK_MAGIC) {
            auto crc = crc32_ieee(init_crc32, ((uint8_t*)(*it)), sizeof(meta_blk));

            // TODO: internal crc calculation is not correct, crc will change every time it is stored;
            if (crc != (*it)->hdr.h.crc) { continue; }

            mblk_cnt++;
            meta_blk* mblk = (meta_blk*)iomanager.iobuf_alloc(HS_STATIC_CONFIG(disk_attr.align_size), META_BLK_PAGE_SZ);
            memcpy(*it, mblk, META_BLK_PAGE_SZ);

            if (false == is_sub_type_valid(mblk->hdr.h.type)) {
                HS_ASSERT(RELEASE, 0, "data corruption found with unrecognized subsystem type.");
            }

            std::lock_guard< decltype(m_meta_mtx) > lk(m_meta_mtx);

            // insert this meta blk to in-memory copy;
            m_meta_blks[mblk->hdr.h.type][mblk->hdr.h.blkid.to_integer()] = mblk;

            // alloc this blk id in bitmap
            m_sb_blk_store->reserve_blk(mblk->hdr.h.blkid);

            // if overflow bid is valid, allocate the overflow bid;
            if (mblk->hdr.h.ovf_blkid.to_integer() != BlkId::invalid_internal_id()) {
                m_sb_blk_store->reserve_blk(mblk->hdr.h.ovf_blkid);
            }
        }
    }

    iomanager.iobuf_free(buf);
}

bool MetaBlkMgr::is_sub_type_valid(const meta_sub_type type) { return m_sub_info.find(type) != m_sub_info.end(); }

void MetaBlkMgr::extract_meta_blks(uint8_t* buf, const uint64_t size, std::vector< meta_blk* >& mblks) {
    uint8_t* meta_blk_ptr = buf;
    uint64_t nbytes = META_BLK_PAGE_SZ;

    while (meta_blk_ptr < buf) {
        meta_blk* mblk = (meta_blk*)meta_blk_ptr;
        mblks.push_back(mblk);
        meta_blk_ptr += META_BLK_PAGE_SZ;
    }

    HS_ASSERT_CMP(DEBUG, meta_blk_ptr, ==, buf);
}

void MetaBlkMgr::deregister_handler(const meta_sub_type type) {
    std::lock_guard< decltype(m_meta_mtx) > lk(m_meta_mtx);

    auto it = m_sub_info.find(type);
    if (it != m_sub_info.end()) { m_sub_info.erase(it); }
}

void MetaBlkMgr::register_handler(const meta_sub_type type, const meta_blk_found_cb_t& cb,
                                  const meta_blk_recover_comp_cb_t& comp_cb) {
    std::lock_guard< decltype(m_meta_mtx) > lk(m_meta_mtx);
    HS_ASSERT(RELEASE, type.length() < MAX_SUBSYS_TYPE_LEN, "type len: {} should not exceed len: {}", type.length(),
              MAX_SUBSYS_TYPE_LEN);
    HS_ASSERT(DEBUG, m_sub_info.find(type) == m_sub_info.end(), "type: {} handler has already registered!", type);
    m_sub_info[type].cb = cb;
    m_sub_info[type].comp_cb = comp_cb;
}

void MetaBlkMgr::add_sub_sb(const meta_sub_type type, const void* context_data, const uint64_t sz, void*& cookie) {
    HS_ASSERT(RELEASE, type.length() < MAX_SUBSYS_TYPE_LEN, "type len: {} should not exceed len: {}", type.length(),
              MAX_SUBSYS_TYPE_LEN);
    // not allowing add sub sb before registration
    HS_ASSERT(RELEASE, m_sub_info.find(type) != m_sub_info.end(), "type: {} not registered yet!", type);

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

void MetaBlkMgr::write_meta_blk_to_disk(meta_blk* mblk) {
    homeds::MemVector mvec;
    try {
        mvec.set((uint8_t*)mblk, META_BLK_PAGE_SZ, 0);
        m_sb_blk_store->write(mblk->hdr.h.blkid, mvec);
    } catch (std::exception& e) { throw e; }
}

void MetaBlkMgr::write_blk(BlkId& bid, const void* context_data, const uint32_t sz) {
    homeds::MemVector mvec;
    try {
        mvec.set((uint8_t*)context_data, sz, 0);
        m_sb_blk_store->write(bid, mvec);
    } catch (std::exception& e) { throw e; }
}

meta_blk* MetaBlkMgr::init_meta_blk(BlkId& bid, const meta_sub_type type, const void* context_data, const size_t sz) {
    meta_blk* mblk = (meta_blk*)iomanager.iobuf_alloc(HS_STATIC_CONFIG(disk_attr.align_size), META_BLK_PAGE_SZ);
    mblk->hdr.h.blkid.set(bid);
    memset(mblk->hdr.h.type, 0, MAX_SUBSYS_TYPE_LEN);
    memcpy(mblk->hdr.h.type, type.c_str(), type.length());

    std::lock_guard< decltype(m_meta_mtx) > lg(m_meta_mtx);
    mblk->hdr.h.magic = META_BLK_MAGIC;

    // for both in-band and ovf buffer, we store crc in meta blk header;
    mblk->hdr.h.crc = crc32_ieee(init_crc32, ((uint8_t*)context_data), sz);

    // handle prev/next pointer linkage;
    if (m_last_mblk) {
        mblk->hdr.h.prev_blkid.set(m_last_mblk->hdr.h.blkid);
        HS_ASSERT_CMP(DEBUG, m_last_mblk->hdr.h.next_blkid.to_integer(), ==, BlkId::invalid_internal_id());
        m_last_mblk->hdr.h.next_blkid.set(bid);

        // persist the changes;
        write_meta_blk_to_disk(m_last_mblk);
    } else {
        // this is the first sub sb being added;
        mblk->hdr.h.prev_blkid.set(m_ssb->blkid);
        HS_ASSERT_CMP(DEBUG, m_ssb->next_blkid.to_integer(), ==, BlkId::invalid_internal_id());
        m_ssb->next_blkid.set(bid);

        // persiste the changes;
        write_ssb();
    }

    mblk->hdr.h.next_blkid.set(BlkId::invalid_internal_id());

    // write this meta blk to disk
    write_meta_blk_internal(mblk, context_data, sz);

    // update in-memory data structure;
    m_last_mblk = mblk;

    // add to cache;
    m_meta_blks[type][bid.to_integer()] = mblk;

    return mblk;
}

//
// The ovf blk is written to disk in reverse order to survive crash-in-the-middle;
// E.g. the tail is written firstly, then the prev blk of tail, until the head ovf blk;
//
// If crash happens at any point before the head ovf blk is written to disk, we are fine because those blks will be
// free after reboot
//
void MetaBlkMgr::write_meta_blk_ovf(BlkId& prev_bid, BlkId& bid, const void* context_data, const uint64_t sz,
                                    const uint64_t offset) {
    HS_ASSERT(RELEASE, offset < sz, "offset:{} should be less than sz:{}", offset, sz);

    meta_blk_ovf_hdr* ovf_hdr =
        (meta_blk_ovf_hdr*)iomanager.iobuf_alloc(HS_STATIC_CONFIG(disk_attr.align_size), META_BLK_OVF_HDR_MAX_SZ);

    HS_ASSERT(DEBUG, m_meta_mtx.try_lock() == false, "mutex should be already be locked");

    // add to ovf blk cache;
    HS_ASSERT(DEBUG, m_ovf_blk_hdrs.find(bid.to_integer()) == m_ovf_blk_hdrs.end(), "ovf_blks: {} already assigned",
              bid.to_string());
    m_ovf_blk_hdrs[bid.to_integer()] = ovf_hdr;

    ovf_hdr->h.magic = META_BLK_OVF_MAGIC;
    ovf_hdr->h.prev_blkid = prev_bid;
    ovf_hdr->h.blkid = bid;

    if ((offset + META_BLK_OVF_CONTEXT_SZ) < sz) {
        // can't hold all the portion, need to write to next blk;
        ovf_hdr->h.context_sz = META_BLK_OVF_CONTEXT_SZ;

        BlkId obid;
        auto ret = alloc_meta_blk(obid);
        HS_LOG(INFO, metablk, "allocating overflow bid: {}", obid.to_string());
        if (ret != no_error) {
            HS_LOG(ERROR, metablk, "Failed to allocate contigous overflow blk with size: {}", sz);
            HS_ASSERT(RELEASE, 0, "failed to allocate overflow blk id with size: {}", sz);
        }
        ovf_hdr->h.next_blkid = obid;

        // keep writing next ovf blk
        write_meta_blk_ovf(bid, obid, context_data, sz, offset + META_BLK_OVF_CONTEXT_SZ);
    } else {
        // current ovf blk can hold all the remaining portion, we are done;
        ovf_hdr->h.context_sz = sz - offset;

        // set the tail to invalid id;
        ovf_hdr->h.next_blkid.set(BlkId::invalid_internal_id());
    }

    // write current ovf blk to disk
    write_ovf_blk_to_disk(ovf_hdr, context_data, sz, offset);
}

void MetaBlkMgr::write_ovf_blk_to_disk(meta_blk_ovf_hdr* ovf_hdr, const void* context_data, const uint64_t sz,
                                       const uint64_t offset) {
    HS_ASSERT_CMP(DEBUG, ovf_hdr->h.context_sz + offset, <=, sz);
    HS_ASSERT_CMP(DEBUG, ovf_hdr->h.context_sz + META_BLK_OVF_HDR_MAX_SZ, <=, META_BLK_PAGE_SZ);

    struct iovec iov[2];
    int iovcnt = 2;
    iov[0].iov_base = (void*)ovf_hdr;
    iov[0].iov_len = META_BLK_OVF_HDR_MAX_SZ;
    iov[1].iov_base = (uint8_t*)context_data + offset;
    iov[1].iov_len = ovf_hdr->h.context_sz;

    // write current ovf blk to disk;
    try {
        m_sb_blk_store->write(ovf_hdr->h.blkid, iov, iovcnt);
    } catch (std::exception& e) { throw e; }
}

void MetaBlkMgr::write_meta_blk_internal(meta_blk* mblk, const void* context_data, const uint64_t sz) {
    mblk->hdr.h.context_sz = sz;

    // within block context size;
    if (sz <= META_BLK_CONTEXT_SZ) {
        // for inline case, set ovf_blkid to invalid
        mblk->hdr.h.ovf_blkid.set(BlkId::invalid_internal_id());

        memcpy(mblk->context_data, context_data, sz);
    } else {
        HS_ASSERT(RELEASE, sz % dma_boundary == 0, "context_data sz: {} needs to be dma_boundary {} aligned. ", sz,
                  dma_boundary);

        // only copy context_data for the 1st metablk, the ovf blk will use iov to avoid copy;
        memcpy(mblk->context_data, context_data, META_BLK_CONTEXT_SZ);

        BlkId obid;
        auto ret = alloc_meta_blk(obid);
        HS_LOG(INFO, metablk, "allocating overflow bid: {}", obid.to_string());
        if (ret != no_error) {
            HS_LOG(ERROR, metablk, "Failed to allocate contigous overflow blk with size: {}", sz);
            HS_ASSERT(RELEASE, 0, "failed to allocate overflow blk id with size: {}", sz);
        }

        mblk->hdr.h.ovf_blkid = obid;

        auto offset = META_BLK_CONTEXT_SZ;

        // write overflow block to disk;
        write_meta_blk_ovf(mblk->hdr.h.blkid, obid, context_data, sz, offset);
    }

    // write meta blk;
    write_meta_blk_to_disk(mblk);
}

void MetaBlkMgr::update_sub_sb(const meta_sub_type type, const void* context_data, const uint64_t sz, void*& cookie) {
    //
    // Do in-place update:
    // 1. free old ovf_blkid if there is any
    // 2. allcate ovf_blkid if needed
    // 3. update the meta_blk
    //
    std::lock_guard< decltype(m_meta_mtx) > lg(m_meta_mtx);
    meta_blk* mblk = (meta_blk*)cookie;

    HS_LOG(INFO, metablk, "old sb: context_sz: {}, ovf_blkid: {}", (unsigned long)(mblk->hdr.h.context_sz),
           mblk->hdr.h.ovf_blkid.to_string());

    // TODO: try to remove this lock as it is not required and we don't need to hold lock for concurrent write while
    // writing to blkstore. And if without lock, this free should happen after meta blk is updated;

    // free the overflow blkid if it is there
    free_ovf_blk_chain(mblk);
    mblk->hdr.h.ovf_blkid.set(BlkId::invalid_internal_id());

    mblk->hdr.h.crc = crc32_ieee(init_crc32, ((uint8_t*)context_data), sz);

    // write this meta blk to disk
    write_meta_blk_internal(mblk, context_data, sz);

    HS_LOG(INFO, metablk, "new sb: context_sz: {}, ovf_blkid: {}", (uint64_t)mblk->hdr.h.context_sz,
           mblk->hdr.h.ovf_blkid.to_string());

    // no need to update cookie and in-memory meta blk map
}

std::error_condition MetaBlkMgr::remove_sub_sb(const void* cookie) {
    meta_blk* rm_blk = (meta_blk*)cookie;
    BlkId bid = rm_blk->hdr.h.blkid;
    auto type = rm_blk->hdr.h.type;

    std::lock_guard< decltype(m_meta_mtx) > lg(m_meta_mtx);

    // type must exist
    HS_ASSERT(DEBUG, m_meta_blks.find(type) != m_meta_blks.end(), "Un-registered type: {} received, which is not supported!", type);

    // remove from disk;
    auto prev_blkid = m_meta_blks[type][bid.to_integer()]->hdr.h.prev_blkid;
    auto next_blkid = m_meta_blks[type][bid.to_integer()]->hdr.h.next_blkid;

    HS_LOG(INFO, metablk, "removing meta blk id: {}, type: {}, prev_blkid: {}, next_blkid: {}", bid.to_string(), type,
           prev_blkid.to_string(), next_blkid.to_string());

    // this record must exist in-memory copy
    HS_ASSERT(DEBUG, m_meta_blks[type].find(bid.to_integer()) != m_meta_blks[type].end(), "Blk type: {}, id: {} not found!", type, bid.to_string());

    HS_ASSERT(DEBUG, m_meta_blks[type][bid.to_integer()] == rm_blk, "Received blk pointer not equal to cache, memory corruption!");

    // remove the in-memory handle from meta blk map;
    m_meta_blks[rm_blk->hdr.h.type].erase(bid.to_integer());

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
                prev_mblk->hdr.h.next_blkid.set(next_blkid);
                write_meta_blk_to_disk(prev_mblk);

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
                next_mblk->hdr.h.prev_blkid.set(prev_blkid);
                write_meta_blk_to_disk(next_mblk);
                break;
            }
        }

        if (!found) { HS_ASSERT(DEBUG, true, "next_blkid: {} not found", next_blkid.to_string()); }
    }

    // free the on-disk meta blk
    free_meta_blk(rm_blk);

    return no_error;
}

// if we crash in the middle, after reboot the ovf blk will be treaded as free automatically;
void MetaBlkMgr::free_ovf_blk_chain(meta_blk* mblk) {
    auto next_obid = mblk->hdr.h.ovf_blkid;
    while (next_obid.to_integer() != BlkId::invalid_internal_id()) {
        HS_LOG(INFO, metablk, "free ovf blk: {}", next_obid.to_string());
        m_sb_blk_store->free_blk(next_obid, boost::none, boost::none);

        auto save_old = next_obid;

        // get next chained ovf blk id from cache;
        next_obid = m_ovf_blk_hdrs[next_obid.to_integer()]->h.next_blkid;

        auto it = m_ovf_blk_hdrs.find(save_old.to_integer());

        // free the memory;
        iomanager.iobuf_free((uint8_t*)(it->second));

        // remove from ovf blk cache;
        m_ovf_blk_hdrs.erase(it);
    }
}

void MetaBlkMgr::free_meta_blk(meta_blk* mblk) {
    m_sb_blk_store->free_blk(mblk->hdr.h.blkid, boost::none, boost::none);
    // free the overflow blkid if it is there
    if (mblk->hdr.h.ovf_blkid.to_integer() != BlkId::invalid_internal_id()) {
        HS_ASSERT_CMP(DEBUG, (uint64_t)(mblk->hdr.h.context_sz), >=, META_BLK_CONTEXT_SZ);
        free_ovf_blk_chain(mblk);
    }
    iomanager.iobuf_free((uint8_t*)mblk);
}

std::error_condition MetaBlkMgr::alloc_meta_blk(BlkId& bid, uint32_t alloc_sz) {
    blk_alloc_hints hints;
    hints.desired_temp = 0;
    hints.dev_id_hint = -1;
    hints.is_contiguous = true;
    try {
        auto ret = m_sb_blk_store->alloc_contiguous_blk(alloc_sz, hints, &bid);
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

// m_meta_mtx is used for concurrency between add/remove/update APIs and shutdown threads;
// m_shutdown_mtx is used for concurrency between recover and shutdown threads;
//
// Note: Client will call add/remove/update APIs in recover function (in complete_cb);
void MetaBlkMgr::recover(const bool do_comp_cb) {
    // for each registered subsystem, look up in cache for their meta blks;
    std::lock_guard< decltype(m_meta_mtx) > lg(m_shutdown_mtx);
    for (auto& sub : m_sub_info) {
        auto type = sub.first;
        auto it = m_meta_blks.find(type);
        if (it == m_meta_blks.end()) {
            // some subsystem registered but don't have active blks, which is fine;
            continue;
        }

        auto cb = sub.second.cb;
        for (auto& m : it->second) {
            auto mblk = m.second;
            sisl::byte_view buf;

            if (mblk->hdr.h.context_sz <= META_BLK_CONTEXT_SZ) {
                sisl::byte_view b(mblk->hdr.h.context_sz);
                buf = b;
                HS_ASSERT(RELEASE, mblk->hdr.h.ovf_blkid.to_integer() == BlkId::invalid_internal_id(),
                          "corrupted ovf_blkid: {}", mblk->hdr.h.ovf_blkid.to_string());
                memcpy((void*)buf.bytes(), (void*)mblk->context_data, mblk->hdr.h.context_sz);
            } else {
                // read through the ovf blk chain to get the buffer;
                // first, copy the context data from meta blk context portion
                sisl::byte_view b(mblk->hdr.h.context_sz, HS_STATIC_CONFIG(disk_attr.align_size));
                buf = b;
                memcpy((void*)buf.bytes(), (void*)mblk->context_data, META_BLK_CONTEXT_SZ);
                auto total_sz = mblk->hdr.h.context_sz;
                uint64_t read_offset = META_BLK_CONTEXT_SZ;

                auto bid = mblk->hdr.h.ovf_blkid;
                auto prev_bid = mblk->hdr.h.blkid;
                while (read_offset < total_sz) {
                    HS_ASSERT(RELEASE, bid.to_integer() != BlkId::invalid_internal_id(), "corrupted ovf_blkid: {}",
                              bid.to_string());
                    // copy the remaining data from ovf blk chain;
                    // we don't cache context data, so read from disk;
                    sisl::blob b;
                    read(bid, b);

                    auto ovf_hdr = (meta_blk_ovf_hdr*)b.bytes;

                    // verify linkage;
                    HS_ASSERT(RELEASE, ovf_hdr->h.blkid.to_integer() == bid.to_integer(), "Corrupted self-bid: {}/{}",
                              ovf_hdr->h.blkid.to_string(), bid.to_string());
                    HS_ASSERT(RELEASE, ovf_hdr->h.prev_blkid.to_integer() == prev_bid.to_integer(),
                              "Corrupted prev_blkid: {}/{}", ovf_hdr->h.prev_blkid.to_string(), prev_bid.to_string());

                    memcpy((uint8_t*)buf.bytes() + read_offset, b.bytes + META_BLK_OVF_HDR_MAX_SZ,
                           ovf_hdr->h.context_sz);
                    read_offset += ovf_hdr->h.context_sz;

                    prev_bid = bid;
                    bid = ovf_hdr->h.next_blkid;
                }

                HS_ASSERT(RELEASE, read_offset == total_sz, "incorrect data read from disk: {}, total_sz: {}",
                          read_offset, total_sz);
            }

            // verify crc before sending to subsystem;
            auto crc = crc32_ieee(init_crc32, (uint8_t*)(buf.bytes()), mblk->hdr.h.context_sz);
            HS_ASSERT(RELEASE, crc == mblk->hdr.h.crc, "CRC mismatch: {}/{}", crc, (uint32_t)mblk->hdr.h.crc);

            // found a meta blk and callback to sub system;
            cb(mblk, buf, mblk->hdr.h.context_sz);
        }
    }

    if (do_comp_cb) {
        // for each registered subsystem, do recovery complete callback;
        for (auto& sub : m_sub_info) {
            if (sub.second.comp_cb != nullptr) { sub.second.comp_cb(true); }
        }
    }
}

uint64_t MetaBlkMgr::get_size() { return m_sb_blk_store->get_size(); }

uint64_t MetaBlkMgr::get_used_size() { return m_sb_blk_store->get_used_size(); }

MetaBlkMgr* MetaBlkMgr::_instance = nullptr;
} // namespace homestore
