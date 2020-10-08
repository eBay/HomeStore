#include "meta_sb.hpp"
#include "homestore.hpp"
#include "meta_blks_mgr.hpp"
#include "blkstore/blkstore.hpp"

SDS_LOGGING_DECL(metablk)
namespace homestore {

void MetaBlkMgr::start(blk_store_t* sb_blk_store, const sb_blkstore_blob* blob, const bool is_init) {
    LOGINFO("Initialize MetaBlkStore with total size: {}, used size: {}", sb_blk_store->get_size(),
            sb_blk_store->get_used_size());
    m_sb_blk_store = sb_blk_store;
    MetaBlkMgr::reset_self_recover();
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
        iomanager.iobuf_free((uint8_t*)(it->second));
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
void MetaBlkMgr::read(BlkId& bid, void* dest, size_t sz) {
    auto req = blkstore_req< BlkBuffer >::make_request();
    req->isSyncCall = true;
    struct iovec iov;
    iov.iov_base = dest;
    iov.iov_len = sisl::round_up(sz, HS_STATIC_CONFIG(drive_attr.align_size));
    std::vector< iovec > iov_vector = {iov};

    m_sb_blk_store->read(bid, iov_vector, sz, req);
    HS_DEBUG_ASSERT_LE(sz, bid.get_nblks() * META_BLK_PAGE_SZ);
}

void MetaBlkMgr::load_ssb(const sb_blkstore_blob* blob) {
    BlkId bid = blob->blkid;

    m_sb_blk_store->reserve_blk(bid);

    HS_RELEASE_ASSERT_EQ(blob->type, blkstore_type::META_STORE, "Invalid blkstore type: {}", blob->type);
    HS_LOG(INFO, metablk, "Loading meta ssb blkid: {}", bid.to_string());

    m_ssb = (meta_blk_sb*)hs_iobuf_alloc(META_BLK_PAGE_SZ);
    memset((void*)m_ssb, 0, META_BLK_PAGE_SZ);

    read(bid, (void*)m_ssb, META_BLK_PAGE_SZ);

    // verify magic
    HS_DEBUG_ASSERT_EQ((uint32_t)m_ssb->magic, META_BLK_SB_MAGIC);
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
    HS_LOG(INFO, metablk, "allocated ssb blk: {}", bid.to_string());
    struct sb_blkstore_blob blob;
    blob.type = blkstore_type::META_STORE;
    blob.blkid.set(bid);
    m_sb_blk_store->update_vb_context(sisl::blob((uint8_t*)&blob, (uint32_t)sizeof(sb_blkstore_blob)));

    m_ssb = (meta_blk_sb*)hs_iobuf_alloc(META_BLK_PAGE_SZ);
    memset((void*)m_ssb, 0, META_BLK_PAGE_SZ);

    std::lock_guard< decltype(m_meta_mtx) > lk(m_meta_mtx);
    m_last_mblk_id.set(invalid_bid);
    m_ssb->next_bid.set(invalid_bid);
    m_ssb->prev_bid.set(invalid_bid);
    m_ssb->magic = META_BLK_SB_MAGIC;
    m_ssb->version = META_BLK_SB_VERSION;
    m_ssb->migrated = false;
    m_ssb->bid.set(bid);

    write_ssb();
}

// m_meta_lock should be while calling this function;
void MetaBlkMgr::write_ssb() {
    struct iovec iov[1];
    int iovcnt = 1;
    iov[0].iov_base = (void*)m_ssb;
    iov[0].iov_len = META_BLK_PAGE_SZ;

    // write current ovf blk to disk;
    try {
        m_sb_blk_store->write(m_ssb->bid, iov, iovcnt);
    } catch (std::exception& e) { throw e; }
}

void MetaBlkMgr::scan_meta_blks() {
    cache_clear();

    // take a look so that before scan is complete, no add/remove/update operations will be allowed;
    std::lock_guard< decltype(m_meta_mtx) > lg(m_meta_mtx);
    auto bid = m_ssb->next_bid;
    auto prev_meta_bid = m_ssb->bid;

    while (bid.to_integer() != invalid_bid) {
        m_last_mblk_id.set(bid);

        // TODO: add a new API in blkstore read to by pass cache;
        // e.g. take caller's read buf to avoid this extra memory copy;
        auto mblk = (meta_blk*)hs_iobuf_alloc(META_BLK_PAGE_SZ);
        read(bid, mblk);

        // add meta blk to cache;
        m_meta_blks[bid.to_integer()] = mblk;

        HS_DEBUG_ASSERT_EQ(mblk->hdr.h.bid.to_integer(), bid.to_integer(), "{}, bid mismatch: {} : {} ",
                           mblk->hdr.h.type, mblk->hdr.h.bid.to_string(), bid.to_string());

        if (prev_meta_bid.to_integer() != mblk->hdr.h.prev_bid.to_integer()) {
            // recover from previous crash during remove_sub_sb;
            HS_LOG(INFO, metablk, "{}, Recovering fromp previous crash. Fixing prev linkage.", mblk->hdr.h.type);
            mblk->hdr.h.prev_bid = prev_meta_bid;
            MetaBlkMgr::set_self_recover();
            // persist updated mblk to disk
            write_meta_blk_to_disk(mblk);
        }

        prev_meta_bid = bid;

        // mark allocated for this block
        m_sb_blk_store->reserve_blk(mblk->hdr.h.bid);

        // populate overflow blk chain;
        auto obid = mblk->hdr.h.ovf_bid;

        // verify self bid;
        HS_RELEASE_ASSERT_EQ(mblk->hdr.h.bid.to_integer(), bid.to_integer(),
                             "{}, corrupted: prev_mblk's next_bid: {} should equal to mblk's bid: {}", mblk->hdr.h.type,
                             bid.to_string(), mblk->hdr.h.bid.to_string());
        // verify magic
        HS_RELEASE_ASSERT_EQ(mblk->hdr.h.magic, META_BLK_MAGIC, "type: {}, magic mismatch: found: {}, expected: {}",
                             mblk->hdr.h.type, mblk->hdr.h.magic, META_BLK_MAGIC);

        // verify version
        HS_RELEASE_ASSERT_EQ(mblk->hdr.h.version, META_BLK_VERSION,
                             "type: {}, version mismatch: found: {}, expected: {}", mblk->hdr.h.type,
                             mblk->hdr.h.version, META_BLK_VERSION);

        // if context sz can't fit in mblk, we currently don't store any data in it, but store all of the data to ovf
        // blks; this is to scale for 512 blk page size;
        uint64_t read_sz = mblk->hdr.h.context_sz > META_BLK_CONTEXT_SZ ? 0 : mblk->hdr.h.context_sz;

#ifndef NDEBUG
        if (read_sz) {
            HS_DEBUG_ASSERT_EQ(obid.to_integer(), invalid_bid);
        } else {
            HS_DEBUG_ASSERT_NE(obid.to_integer(), invalid_bid);
        }
#endif

        while (obid.to_integer() != invalid_bid) {
            // ovf blk header occupies whole blk;
            auto ovf_hdr = (meta_blk_ovf_hdr*)hs_iobuf_alloc(META_BLK_PAGE_SZ);
            read(obid, ovf_hdr, META_BLK_PAGE_SZ);

            // verify self bid
            HS_RELEASE_ASSERT_EQ(ovf_hdr->h.bid.to_integer(), obid.to_integer(), "Corrupted self-bid: {}/{}",
                                 ovf_hdr->h.bid.to_string(), obid.to_string());
            // verify magic
            HS_RELEASE_ASSERT_EQ(ovf_hdr->h.magic, META_BLK_OVF_MAGIC, "Ovf blk magic corrupted: {}, expected: {}",
                                 ovf_hdr->h.magic, META_BLK_OVF_MAGIC);

            read_sz += ovf_hdr->h.context_sz;

            // add to ovf blk cache;
            m_ovf_blk_hdrs[obid.to_integer()] = ovf_hdr;

            // allocate overflow bid;
            m_sb_blk_store->reserve_blk(obid);

            // allocate data bid
            for (size_t i = 0; i < ovf_hdr->nbids; ++i) {
                m_sb_blk_store->reserve_blk(ovf_hdr->data_bid[i]);
            }

            // move on to next overflow blk;
            obid = ovf_hdr->h.next_bid;
        }

        HS_RELEASE_ASSERT_EQ(read_sz, mblk->hdr.h.context_sz,
                             "{}, total size read: {} mismatch from meta blk context_sz: {}", mblk->hdr.h.type, read_sz,
                             mblk->hdr.h.context_sz);

        // move on to next meta blk;
        bid = mblk->hdr.h.next_bid;
    }
}

bool MetaBlkMgr::is_sub_type_valid(const meta_sub_type type) { return m_sub_info.find(type) != m_sub_info.end(); }

void MetaBlkMgr::deregister_handler(const meta_sub_type type) {
    std::lock_guard< decltype(m_meta_mtx) > lk(m_meta_mtx);

    auto it = m_sub_info.find(type);
    if (it != m_sub_info.end()) { m_sub_info.erase(it); }
}

void MetaBlkMgr::register_handler(const meta_sub_type type, const meta_blk_found_cb_t& cb,
                                  const meta_blk_recover_comp_cb_t& comp_cb, const bool do_crc) {
    std::lock_guard< decltype(m_meta_mtx) > lk(m_meta_mtx);
    HS_RELEASE_ASSERT_LT(type.length(), MAX_SUBSYS_TYPE_LEN, "type len: {} should not exceed len: {}", type.length(),
                         MAX_SUBSYS_TYPE_LEN);
    HS_ASSERT(DEBUG, m_sub_info.find(type) == m_sub_info.end(), "type: {} handler has already registered!", type);
    HS_LOG(DEBUG, metablk, "type: {} registered with do_crc: {}", type, do_crc);
    m_sub_info[type].cb = cb;
    m_sub_info[type].comp_cb = comp_cb;
    m_sub_info[type].do_crc = do_crc;
}

void MetaBlkMgr::add_sub_sb(const meta_sub_type type, const void* context_data, const uint64_t sz, void*& cookie) {
    std::lock_guard< decltype(m_meta_mtx) > lg(m_meta_mtx);
    HS_RELEASE_ASSERT_LT(type.length(), MAX_SUBSYS_TYPE_LEN, "type len: {} should not exceed len: {}", type.length(),
                         MAX_SUBSYS_TYPE_LEN);
    // not allowing add sub sb before registration
    HS_ASSERT(RELEASE, m_sub_info.find(type) != m_sub_info.end(), "type: {} not registered yet!", type);

    BlkId meta_bid;
    auto ret = alloc_meta_blk(meta_bid);

#ifndef NDEBUG
    uint32_t crc = 0;
    if (m_sub_info[type].do_crc) { crc = crc32_ieee(init_crc32, static_cast< const uint8_t* >(context_data), sz); }
#endif

    HS_LOG(DEBUG, metablk, "{}, adding meta bid: {}, sz: {}, mstore used size: {}", type, meta_bid.to_string(), sz,
           m_sb_blk_store->get_used_size());
    if (no_error != ret) {
        HS_ASSERT(RELEASE, 0, "{}, alloc blk failed with status: {}", type, ret.message());
        return;
    }

    meta_blk* mblk = init_meta_blk(meta_bid, type, context_data, sz);

    HS_LOG(DEBUG, metablk, "{}, Done adding bid: {}, prev: {}, next: {}, size: {}, crc: {}, mstore used size: {}", type,
           mblk->hdr.h.bid, mblk->hdr.h.prev_bid, mblk->hdr.h.next_bid, mblk->hdr.h.context_sz, mblk->hdr.h.crc,
           m_sb_blk_store->get_used_size());

#ifndef NDEBUG
    if (m_sub_info[type].do_crc) {
        HS_DEBUG_ASSERT_EQ(crc, mblk->hdr.h.crc,
                           "Input context data has been changed since received, crc mismatch: {}/{}", crc,
                           mblk->hdr.h.crc);
    }
#endif

    cookie = static_cast< void* >(mblk);
}

void MetaBlkMgr::write_ovf_blk_to_disk(meta_blk_ovf_hdr* ovf_hdr, const void* context_data, const uint64_t sz,
                                       const uint64_t offset) {
    HS_DEBUG_ASSERT_LE(ovf_hdr->h.context_sz + offset, sz);

    struct iovec iov[1];
    int iovcnt = 1;
    iov[0].iov_base = (void*)ovf_hdr;
    iov[0].iov_len = META_BLK_PAGE_SZ;

    // write current ovf blk to disk;
    try {
        m_sb_blk_store->write(ovf_hdr->h.bid, iov, iovcnt);
    } catch (std::exception& e) { throw e; }

    // write data blk to disk;
    size_t size_written = 0;
    for (size_t i = 0; i < ovf_hdr->nbids; ++i) {
        struct iovec iovd[1];
        int iovcntd = 1;
        iovd[0].iov_base = (uint8_t*)context_data + offset + size_written;
        iovd[0].iov_len = i < ovf_hdr->nbids - 1 ? ovf_hdr->data_bid[i].get_nblks() * META_BLK_PAGE_SZ
                                                 : ovf_hdr->h.context_sz - size_written;

        try {
            m_sb_blk_store->write(ovf_hdr->data_bid[i], iovd, iovcntd);
        } catch (std::exception& e) { throw e; }

        size_written += iovd[0].iov_len;
    }

    HS_DEBUG_ASSERT_EQ(size_written, ovf_hdr->h.context_sz);
}

void MetaBlkMgr::write_meta_blk_to_disk(meta_blk* mblk) {
    struct iovec iov[1];
    int iovcnt = 1;
    iov[0].iov_base = (void*)mblk;
    iov[0].iov_len = META_BLK_PAGE_SZ;

    // write current ovf blk to disk;
    try {
        m_sb_blk_store->write(mblk->hdr.h.bid, iov, iovcnt);
    } catch (std::exception& e) { throw e; }
}

//
// write blks to disks in reverse order
// 1. write meta blk chain to disk;
// 2. update in-memory m_last_mblk and write to disk or
//    update in-memory m_ssb and write to disk;
// 3. update in-memory meta blks map;
//
meta_blk* MetaBlkMgr::init_meta_blk(BlkId& bid, const meta_sub_type type, const void* context_data, const size_t sz) {
    meta_blk* mblk = (meta_blk*)hs_iobuf_alloc(META_BLK_PAGE_SZ);
    mblk->hdr.h.bid.set(bid);
    memset(mblk->hdr.h.type, 0, MAX_SUBSYS_TYPE_LEN);
    memcpy(mblk->hdr.h.type, type.c_str(), type.length());

    mblk->hdr.h.magic = META_BLK_MAGIC;
    mblk->hdr.h.version = META_BLK_VERSION;

    // handle prev/next pointer linkage;
    if (m_last_mblk_id.to_integer() != invalid_bid) {
        // update this mblk's prev bid to last mblk;
        mblk->hdr.h.prev_bid.set(m_last_mblk_id);

        // update last mblk's next to this mblk;
        m_meta_blks[m_last_mblk_id.to_integer()]->hdr.h.next_bid.set(bid);
    } else {
        // this is the first sub sb being added;
        mblk->hdr.h.prev_bid.set(m_ssb->bid);
        HS_DEBUG_ASSERT_EQ(m_ssb->next_bid.to_integer(), invalid_bid);
        HS_LOG(INFO, metablk, "{}, Changing meta ssb bid: {}'s next_bid to {}", type, m_ssb->bid, bid.to_string());
        m_ssb->next_bid.set(bid);
    }

    // this mblk is now the last;
    mblk->hdr.h.next_bid.set(invalid_bid);

    // write this meta blk to disk
    write_meta_blk_internal(mblk, context_data, sz);

    // now update previous last mblk or ssb. They can only be updated after meta blk is written to disk;
    if (m_last_mblk_id.to_integer() != invalid_bid) {
        // persist the changes to last mblk;
        write_meta_blk_to_disk(m_meta_blks[m_last_mblk_id.to_integer()]);
    } else {
        // persiste the changes;
        write_ssb();
    }

    // point last mblk to this mblk;
    m_last_mblk_id.set(bid);

    // add to cache;
    HS_ASSERT(DEBUG, m_meta_blks.find(bid.to_integer()) == m_meta_blks.end(),
              "{}, memory corruption, bid: {} already added to cache.", type, bid.to_string());
    m_meta_blks[bid.to_integer()] = mblk;

    return mblk;
}

//
// The ovf blk is written to disk in reverse order to survive crash-in-the-middle;
// E.g. the tail is written firstly, then the prev blk of tail, until the head ovf blk;
//
// If crash happens at any point before the head ovf blk is written to disk, we are fine because those blks will be
// free after reboot
//
void MetaBlkMgr::write_meta_blk_ovf(BlkId& out_obid, const void* context_data, const uint64_t sz) {
    HS_ASSERT(DEBUG, m_meta_mtx.try_lock() == false, "mutex should be already be locked");

    // allocate data blocks
    std::vector< BlkId > context_data_blkids;
    auto ret = alloc_meta_blk(sisl::round_up(sz, META_BLK_PAGE_SZ), context_data_blkids);
    if (ret != no_error) { HS_ASSERT(RELEASE, false, "failed to allocate blk with status: {}", ret.message()); }

    HS_LOG(DEBUG, metablk, "Start to allocate nblks(data): {}, mstore used size: {}", context_data_blkids.size(),
           m_sb_blk_store->get_used_size());

    // return the 1st ovf header blk id to caller;
    alloc_meta_blk(out_obid);
    BlkId next_bid = out_obid;
    uint64_t offset_in_ctx = 0;
    uint32_t data_blkid_indx = 0;
    while (next_bid != invalid_bid) {

        meta_blk_ovf_hdr* ovf_hdr = (meta_blk_ovf_hdr*)hs_iobuf_alloc(META_BLK_PAGE_SZ);
        BlkId cur_bid = next_bid;
        ovf_hdr->h.magic = META_BLK_OVF_MAGIC;
        ovf_hdr->h.bid = cur_bid;

        if ((context_data_blkids.size() - (data_blkid_indx + 1)) <= MAX_NUM_DATA_BLKID) {
            ovf_hdr->h.next_bid.set(invalid_bid);
        } else {
            alloc_meta_blk(ovf_hdr->h.next_bid);
            if (ret != no_error) { HS_ASSERT(RELEASE, false, "failed to allocate blk with status: {}", ret.message()); }
        }
        next_bid = ovf_hdr->h.next_bid;

        // save data bids to ovf hdr block;
        uint32_t j = 0;
        uint64_t data_size = 0;
        for (j = 0; j < MAX_NUM_DATA_BLKID && data_blkid_indx < context_data_blkids.size(); ++j) {
            data_size += context_data_blkids[data_blkid_indx].data_size(META_BLK_PAGE_SZ);
            ovf_hdr->data_bid[j] = context_data_blkids[data_blkid_indx++];
        }

        ovf_hdr->nbids = j;
        // context_sz points to the actual context data written into data_bid;
        ovf_hdr->h.context_sz = (data_blkid_indx < context_data_blkids.size() - 1) ? data_size : (sz - offset_in_ctx);
        m_ovf_blk_hdrs[cur_bid.to_integer()] = ovf_hdr;

        // write ovf header blk to disk
        write_ovf_blk_to_disk(ovf_hdr, context_data, sz, offset_in_ctx);

        offset_in_ctx += ovf_hdr->h.context_sz;
    }

    HS_RELEASE_ASSERT_EQ(offset_in_ctx, sz);
}

void MetaBlkMgr::write_meta_blk_internal(meta_blk* mblk, const void* context_data, const uint64_t sz) {
    mblk->hdr.h.context_sz = sz;

    // within block context size;
    if (sz <= META_BLK_CONTEXT_SZ) {
        // for inline case, set ovf_bid to invalid
        mblk->hdr.h.ovf_bid.set(invalid_bid);

        memcpy(mblk->context_data, context_data, sz);
    } else {
        HS_RELEASE_ASSERT_EQ(sz % HS_STATIC_CONFIG(drive_attr.align_size), 0,
                             "{}, context_data sz: {} needs to be dma_boundary {} aligned. ", mblk->hdr.h.type, sz,
                             HS_STATIC_CONFIG(drive_attr.align_size));

        // all context data will be in overflow buffer to avoid data copy and non dma_boundary aligned write;
        BlkId obid(invalid_bid);

        // write overflow block to disk;
        write_meta_blk_ovf(obid, context_data, sz);

        HS_DEBUG_ASSERT_NE(obid.to_integer(), invalid_bid);
        mblk->hdr.h.ovf_bid = obid;
    }

    // for both in-band and ovf buffer, we store crc in meta blk header;
    if (m_sub_info[mblk->hdr.h.type].do_crc) {
        mblk->hdr.h.crc = crc32_ieee(init_crc32, static_cast< const uint8_t* >(context_data), sz);
    }

    // write meta blk;
    write_meta_blk_to_disk(mblk);
}

//
// Do in-place update:
// 1. allcate ovf_bid if needed
// 2. update the meta_blk
// 3. free old ovf_bid if there is any
//
void MetaBlkMgr::update_sub_sb(const void* context_data, const uint64_t sz, void*& cookie) {
    std::lock_guard< decltype(m_meta_mtx) > lg(m_meta_mtx); // TODO: see if this lock can be removed;
    meta_blk* mblk = static_cast< meta_blk* >(cookie);

    HS_LOG(DEBUG, metablk, "{}, update_sub_sb old sb: context_sz: {}, ovf_bid: {}, mstore used size: {}",
           mblk->hdr.h.type, (unsigned long)(mblk->hdr.h.context_sz), mblk->hdr.h.ovf_bid.to_string(),
           m_sb_blk_store->get_used_size());

    auto ovf_bid_to_free = mblk->hdr.h.ovf_bid;

#ifndef NDEBUG
    uint32_t crc = 0;
    const auto it = m_sub_info.find(mblk->hdr.h.type);
    HS_ASSERT(DEBUG, it != m_sub_info.end(), "type: {} not registered yet!", mblk->hdr.h.type);
    if (it->second.do_crc) { crc = crc32_ieee(init_crc32, static_cast< const uint8_t* >(context_data), sz); }
#endif

    mblk->hdr.h.ovf_bid.set(invalid_bid);
    // write this meta blk to disk
    write_meta_blk_internal(mblk, context_data, sz);

    // free the overflow bid if it is there
    free_ovf_blk_chain(ovf_bid_to_free);

    HS_LOG(DEBUG, metablk, "{}, update_sub_sb new sb: context_sz: {}, ovf_bid: {}, mstore used size: {}",
           mblk->hdr.h.type, mblk->hdr.h.context_sz, mblk->hdr.h.ovf_bid.to_string(), m_sb_blk_store->get_used_size());

#ifndef NDEBUG
    if (it->second.do_crc) {
        HS_DEBUG_ASSERT_EQ(crc, mblk->hdr.h.crc,
                           "Input context data has been changed since received, crc mismatch: {}/{}", crc,
                           mblk->hdr.h.crc);
    }
#endif

    // no need to update cookie and in-memory meta blk map
}

std::error_condition MetaBlkMgr::remove_sub_sb(const void* cookie) {
    std::lock_guard< decltype(m_meta_mtx) > lg(m_meta_mtx);
    meta_blk* rm_blk = (meta_blk*)cookie;
    const BlkId rm_bid = rm_blk->hdr.h.bid;
    const auto type = rm_blk->hdr.h.type;

    // this record must exist in-memory copy
    HS_ASSERT(DEBUG, m_meta_blks.find(rm_bid.to_integer()) != m_meta_blks.end(), "{}, id: {} not found!", type,
              rm_bid.to_string());

    // remove from disk;
    const auto rm_blk_in_cache = m_meta_blks[rm_bid.to_integer()];
    auto prev_bid = rm_blk_in_cache->hdr.h.prev_bid;
    auto next_bid = rm_blk_in_cache->hdr.h.next_bid;

    HS_LOG(DEBUG, metablk, "{}, remove_sub_sb meta blk id: {}, prev_bid: {}, next_bid: {}, mstore used size: {}", type,
           rm_bid.to_string(), prev_bid.to_string(), next_bid.to_string(), m_sb_blk_store->get_used_size());

    // validate bid/prev/next with cache data;
    if (rm_blk != rm_blk_in_cache) {
        HS_ASSERT(DEBUG, false, "{}, cookie doesn't match with cached blk, invalid cookie!", type);
    }

    // update prev-blk's next pointer
    if (prev_bid.to_integer() == m_ssb->bid.to_integer()) {
        m_ssb->next_bid.set(next_bid);
        // persist m_ssb to disk;
        write_ssb();
        if (m_last_mblk_id.to_integer() == rm_bid.to_integer()) { m_last_mblk_id.set(invalid_bid); }
    } else {
        // find the in-memory copy of prev meta block;
        HS_ASSERT(DEBUG, m_meta_blks.find(prev_bid.to_integer()) != m_meta_blks.end(), "prev: {} not found!",
                  prev_bid.to_string());

        // update prev meta blk's both in-memory and on-disk copy;
        m_meta_blks[prev_bid.to_integer()]->hdr.h.next_bid.set(next_bid);
        write_meta_blk_to_disk(m_meta_blks[prev_bid.to_integer()]);
    }

    // update next-blk's prev pointer
    if (next_bid.to_integer() != invalid_bid) {
        HS_ASSERT(DEBUG, m_meta_blks.find(next_bid.to_integer()) != m_meta_blks.end(),
                  "next_bid: {} not found in cache", type, next_bid.to_string());
        auto next_mblk = m_meta_blks[next_bid.to_integer()];

        // update next meta blk's both in-memory and on-disk copy;
        next_mblk->hdr.h.prev_bid.set(prev_bid);
        write_meta_blk_to_disk(next_mblk);
    } else {
        // if we are removing the last meta blk, update last to its previous blk;
        HS_DEBUG_ASSERT_EQ(m_last_mblk_id.to_integer(), rm_bid.to_integer());

        HS_LOG(INFO, metablk, "removing last mblk, change m_last_mblk to bid: {}, type: {}", prev_bid.to_string(),
               m_meta_blks[prev_bid.to_integer()]->hdr.h.type);
        m_last_mblk_id.set(prev_bid);
    }

    // remove the in-memory handle from meta blk map;
    m_meta_blks.erase(rm_bid.to_integer());

    // free the on-disk meta blk
    free_meta_blk(rm_blk);

    HS_LOG(DEBUG, metablk, "after remove, mstore used size: {}", m_sb_blk_store->get_used_size());
    return no_error;
}

//
// if we crash in the middle, after reboot the ovf blk will be treaded as free automatically;
//
void MetaBlkMgr::free_ovf_blk_chain(BlkId& obid) {
    auto cur_obid = obid;
    while (cur_obid.to_integer() != invalid_bid) {
        auto ovf_hdr = m_ovf_blk_hdrs[cur_obid.to_integer()];

#ifndef NDEBUG
        uint64_t used_size_before_free = m_sb_blk_store->get_used_size();
        uint64_t total_nblks_freed = 0;
#endif

        HS_LOG(DEBUG, metablk, "starting to free ovf blk: {}, nbids(data): {}, mstore used size: {}",
               cur_obid.to_string(), ovf_hdr->nbids, m_sb_blk_store->get_used_size());

        // free on-disk data bid
        for (size_t i = 0; i < ovf_hdr->nbids; ++i) {
            m_sb_blk_store->free_blk(ovf_hdr->data_bid[i], boost::none, boost::none);
#ifndef NDEBUG
            total_nblks_freed += ovf_hdr->data_bid[i].get_nblks();
#endif
            HS_LOG(DEBUG, metablk, "after freeing data bid: {}, mstore used size: {}", ovf_hdr->data_bid[i].to_string(),
                   m_sb_blk_store->get_used_size());
        }

        // free on-disk ovf header blk
        m_sb_blk_store->free_blk(cur_obid, boost::none, boost::none);

#ifndef NDEBUG
        ++total_nblks_freed;
#endif
        HS_LOG(DEBUG, metablk, "after freeing ovf bidid: {}, mstore used size: {}", cur_obid.to_string(),
               m_sb_blk_store->get_used_size());

        // assert that freed space should match with the total blks freed;
        HS_DEBUG_ASSERT_EQ(used_size_before_free - m_sb_blk_store->get_used_size(),
                           total_nblks_freed * META_BLK_PAGE_SZ);

        auto save_old = cur_obid;

        // get next chained ovf blk id from cache;
        cur_obid = ovf_hdr->h.next_bid;

        auto it = m_ovf_blk_hdrs.find(save_old.to_integer());

        // free the ovf header memory;
        iomanager.iobuf_free((uint8_t*)(it->second));

        // remove from ovf blk cache;
        m_ovf_blk_hdrs.erase(it);
    }
}

void MetaBlkMgr::free_meta_blk(meta_blk* mblk) {
    HS_LOG(DEBUG, metablk, "{}, freeing blk id: {}", mblk->hdr.h.type, mblk->hdr.h.bid.to_string());

    m_sb_blk_store->free_blk(mblk->hdr.h.bid, boost::none, boost::none);

    // free the overflow bid if it is there
    if (mblk->hdr.h.ovf_bid.to_integer() != invalid_bid) {
        HS_DEBUG_ASSERT_GE((uint64_t)(mblk->hdr.h.context_sz), META_BLK_CONTEXT_SZ,
                           "{}, context_sz: {} less than {} is invalid", mblk->hdr.h.type,
                           (uint64_t)(mblk->hdr.h.context_sz), META_BLK_CONTEXT_SZ);
        free_ovf_blk_chain(mblk->hdr.h.ovf_bid);
    }

    iomanager.iobuf_free((uint8_t*)mblk);
}

std::error_condition MetaBlkMgr::alloc_meta_blk(const uint64_t size, std::vector< BlkId >& bid) {
    blk_alloc_hints hints;
    hints.desired_temp = 0;
    hints.dev_id_hint = -1;
    hints.is_contiguous = false;

    try {
        auto ret = m_sb_blk_store->alloc_blk(size, hints, bid);
        if (ret != BLK_ALLOC_SUCCESS) {
            HS_LOG(ERROR, metablk, "failing as it is out of disk space!");
            return std::errc::no_space_on_device;
        }
        HS_DEBUG_ASSERT_EQ(ret, BLK_ALLOC_SUCCESS);
    } catch (const std::exception& e) {
        HS_ASSERT(RELEASE, 0, "{}", e.what());
        return std::errc::device_or_resource_busy;
    }

    return no_error;
}

std::error_condition MetaBlkMgr::alloc_meta_blk(BlkId& bid) {
    blk_alloc_hints hints;
    hints.desired_temp = 0;
    hints.dev_id_hint = -1;
    hints.is_contiguous = true;

    try {
        auto ret = m_sb_blk_store->alloc_contiguous_blk(META_BLK_PAGE_SZ, hints, &bid);
        if (ret != BLK_ALLOC_SUCCESS) {
            HS_LOG(ERROR, metablk, "failing as it is out of disk space!");
            return std::errc::no_space_on_device;
        }
        HS_DEBUG_ASSERT_EQ(ret, BLK_ALLOC_SUCCESS);
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
    for (auto& m : m_meta_blks) {
        auto mblk = m.second;
        sisl::byte_view buf;

        if (mblk->hdr.h.context_sz <= META_BLK_CONTEXT_SZ) {
            buf = hs_create_byte_view(mblk->hdr.h.context_sz, false /* aligned_byte_view */);
            HS_DEBUG_ASSERT_EQ(mblk->hdr.h.ovf_bid.to_integer(), invalid_bid, "{}, corrupted ovf_bid: {}",
                               mblk->hdr.h.type, mblk->hdr.h.ovf_bid.to_string());
            memcpy((void*)buf.bytes(), (void*)mblk->context_data, mblk->hdr.h.context_sz);
        } else {
            //
            // read through the ovf blk chain to get the buffer;
            // all the context data was stored in ovf blk chain, nothing in meta blk context data portion;
            //
            buf = hs_create_byte_view(mblk->hdr.h.context_sz, true /* aligned byte_view */);

            auto total_sz = mblk->hdr.h.context_sz;
            uint64_t read_offset = 0;

            auto obid = mblk->hdr.h.ovf_bid;
            while (read_offset < total_sz) {
                HS_RELEASE_ASSERT_NE(obid.to_integer(), invalid_bid, "{}, corrupted ovf_bid: {}", mblk->hdr.h.type,
                                     obid.to_string());
                // copy the remaining data from ovf blk chain;
                // we don't cache context data, so read from disk;
                auto ovf_hdr = m_ovf_blk_hdrs[obid.to_integer()];
                size_t read_sz_per_db = 0;
                for (size_t i = 0; i < ovf_hdr->nbids; ++i) {
                    read_sz_per_db = (i < ovf_hdr->nbids - 1 ? ovf_hdr->data_bid[i].get_nblks() * META_BLK_PAGE_SZ
                                                             : ovf_hdr->h.context_sz - read_offset);
                    read(ovf_hdr->data_bid[i], buf.bytes() + read_offset,
                         sisl::round_up(read_sz_per_db, HS_STATIC_CONFIG(drive_attr.align_size)));
                    read_offset += read_sz_per_db;
                }

                HS_DEBUG_ASSERT_EQ(read_offset, ovf_hdr->h.context_sz);

                // verify self bid
                HS_RELEASE_ASSERT_EQ(ovf_hdr->h.bid.to_integer(), obid.to_integer(), "{}, Corrupted self-bid: {}/{}",
                                     mblk->hdr.h.type, ovf_hdr->h.bid.to_string(), obid.to_string());

                obid = ovf_hdr->h.next_bid;
            }

            HS_RELEASE_ASSERT_EQ(read_offset, total_sz, "{}, incorrect data read from disk: {}, total_sz: {}",
                                 mblk->hdr.h.type, read_offset, total_sz);
        }

        // found a meta blk and callback to sub system;
        const auto itr{m_sub_info.find(mblk->hdr.h.type)};
        if (itr != m_sub_info.end()) {
            // if subsystem registered crc protection, verify crc before sending to subsystem;
            if (itr->second.do_crc) {
                auto crc = crc32_ieee(init_crc32, static_cast< uint8_t* >(buf.bytes()), mblk->hdr.h.context_sz);
                // HS_LOG(DEBUG, metablk, "type: {}, context sz: {}, data: {}", mblk->hdr.h.type,
                // mblk->hdr.h.context_sz, static_cast< unsigned char* >(buf.bytes()));
                HS_RELEASE_ASSERT_EQ(crc, mblk->hdr.h.crc, "{}, CRC mismatch: {}/{}, on mblk bid: {}, context_sz: {}",
                                     mblk->hdr.h.type, crc, mblk->hdr.h.crc, mblk->hdr.h.bid.to_string(),
                                     mblk->hdr.h.context_sz);
            } else {
                HS_LOG(DEBUG, metablk, "type: {} meta blk found with bypassing crc.", mblk->hdr.h.type);
            }

            // send the callbck;
            auto cb = itr->second.cb;
            cb(mblk, buf, mblk->hdr.h.context_sz);
            HS_LOG(DEBUG, metablk, "type: {} meta blk sent with size: {}.", mblk->hdr.h.type, mblk->hdr.h.context_sz);
        } else {
            // should never arrive here since we do assert on type before write to disk;
            HS_ASSERT(LOGMSG, false, "type: {} not registered for mblk found on disk. Skip this meta blk. ",
                      mblk->hdr.h.type);
        }
    }

    if (do_comp_cb) {
        // for each registered subsystem, do recovery complete callback;
        for (auto& sub : m_sub_info) {
            if (sub.second.comp_cb != nullptr) {
                sub.second.comp_cb(true);
                HS_LOG(DEBUG, metablk, "type: {} completion callback sent.", sub.first);
            }
        }
    }
}

uint64_t MetaBlkMgr::get_meta_size(const void* cookie) {
    const auto mblk = static_cast< const meta_blk* >(cookie);
    size_t nblks = 1; // meta blk itself;
    auto obid = mblk->hdr.h.ovf_bid;
    while (obid.to_integer() != invalid_bid) {
        auto ovf_hdr = m_ovf_blk_hdrs[obid.to_integer()];
        nblks++; // ovf header blk;
        for (size_t i = 0; i < ovf_hdr->nbids; i++) {
            nblks += ovf_hdr->data_bid[i].get_nblks(); // data blks;
        }
        obid = ovf_hdr->h.next_bid;
    }

    return nblks * META_BLK_PAGE_SZ;
}

uint64_t MetaBlkMgr::get_size() { return m_sb_blk_store->get_size(); }

uint64_t MetaBlkMgr::get_used_size() { return m_sb_blk_store->get_used_size(); }

std::unique_ptr< MetaBlkMgr > MetaBlkMgr::s_instance{};

bool MetaBlkMgr::m_self_recover{false};
} // namespace homestore
