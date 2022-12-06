#include <array>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <filesystem>
#include <memory>
#include <mutex>
#include <system_error>

#include <sisl/fds/compress.hpp>

#include "api/meta_interface.hpp"
#include "blkstore/blkstore.hpp"
#include "engine/blkalloc/blk_allocator.h"
#include "engine/blkstore/blkstore.hpp"
#include "engine/blkstore/blkbuffer.cpp"
#include "engine/common/homestore_flip.hpp"
#include "engine/homestore_base.hpp"
#include "meta_sb.hpp"

SISL_LOGGING_DECL(metablk)

namespace homestore {

MetaBlkMgr* MetaBlkMgrSI() { return MetaBlkMgr::instance(); }

// define statics
std::unique_ptr< MetaBlkMgr > MetaBlkMgr::s_instance{};

// define static functions
// NOTE: These must be in the cpp file since std::unique_ptr reset, destructor,
// and operator= functions require a complete definition
MetaBlkMgr* MetaBlkMgr::instance() {
    static std::once_flag flag1;
    std::call_once(flag1, []() {
        if (!s_instance) s_instance = std::make_unique< MetaBlkMgr >();
    });

    return s_instance.get();
}

void MetaBlkMgr::free_compress_buf() { hs_utils::iobuf_free(m_compress_info.bytes, sisl::buftag::compression); }

void MetaBlkMgr::alloc_compress_buf(const size_t size) {
    m_compress_info.size = size;
    m_compress_info.bytes = hs_utils::iobuf_alloc(size, sisl::buftag::compression, get_align_size());

    HS_REL_ASSERT_NE(m_compress_info.bytes, nullptr, "fail to allocate iobuf for compression of size: {}", size);
}

void MetaBlkMgr::fake_reboot() { s_instance = std::make_unique< MetaBlkMgr >(); }

void MetaBlkMgr::del_instance() {
    LOGINFO("Deleting meta blk mgr instance. ");
    s_instance.reset();
}

uint64_t MetaBlkMgr::meta_blk_context_sz() const { return get_page_size() - META_BLK_HDR_MAX_SZ; }

uint64_t MetaBlkMgr::ovf_blk_max_num_data_blk() const {
    return (get_page_size() - MAX_BLK_OVF_HDR_MAX_SZ) / sizeof(BlkId);
}

MetaBlkMgr::MetaBlkMgr(const char* name) : m_metrics{name} { m_last_mblk_id = std::make_unique< BlkId >(); }

MetaBlkMgr::~MetaBlkMgr() {}

bool MetaBlkMgr::is_aligned_buf_needed(const size_t size) { return (size <= meta_blk_context_sz()) ? false : true; }

void MetaBlkMgr::start(blk_store_t* sb_blk_store, const sb_blkstore_blob* blob, const bool is_init) {
    LOGINFO("Initialize MetaBlkStore with total size: {}, used size: {}, is_init: {}", sb_blk_store->get_size(),
            sb_blk_store->get_used_size(), is_init);

    m_sb_blk_store = sb_blk_store;

    HS_REL_ASSERT_GT(get_page_size(), META_BLK_HDR_MAX_SZ);
    HS_REL_ASSERT_GT(get_page_size(), MAX_BLK_OVF_HDR_MAX_SZ);

    reset_self_recover();
    alloc_compress_buf(get_init_compress_memory_size());
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

void MetaBlkMgr::stop() {
    {
        std::lock_guard< decltype(m_shutdown_mtx) > lg_shutdown{m_shutdown_mtx};
        cache_clear();

        {
            std::lock_guard< decltype(m_meta_mtx) > lg{m_meta_mtx};
            m_sub_info.clear();
        }
        hs_utils::iobuf_free(reinterpret_cast< uint8_t* >(m_ssb), sisl::buftag::metablk);
        free_compress_buf();
    }
    del_instance();
}

void MetaBlkMgr::cache_clear() {
    std::lock_guard< decltype(m_meta_mtx) > lg{m_meta_mtx};
    for (auto it{std::cbegin(m_meta_blks)}; it != std::cend(m_meta_blks); ++it) {
        hs_utils::iobuf_free(reinterpret_cast< uint8_t* >(it->second), sisl::buftag::metablk);
    }

    for (auto it{std::cbegin(m_ovf_blk_hdrs)}; it != std::cend(m_ovf_blk_hdrs); ++it) {
        hs_utils::iobuf_free(reinterpret_cast< uint8_t* >(it->second), sisl::buftag::metablk);
    }

    m_meta_blks.clear();
    m_ovf_blk_hdrs.clear();
}

// sync read
void MetaBlkMgr::read(const BlkId& bid, void* dest, const size_t sz) const {
    auto req{blkstore_req< BlkBuffer >::make_request()};
    req->isSyncCall = true;
    // TO DO: Might need to differentiate based on data or fast type
    iovec iov{dest, static_cast< size_t >(sisl::round_up(sz, get_align_size()))};
    std::vector< iovec > iov_vector{};
    iov_vector.push_back(std::move(iov));

    try {
        m_sb_blk_store->read(bid, iov_vector, sz, req);
    } catch (std::exception& e) { HS_REL_ASSERT(0, "Exception: {}", e.what()); }
    HS_DBG_ASSERT_LE(sz, bid.get_nblks() * get_page_size());
}

void MetaBlkMgr::load_ssb(const sb_blkstore_blob* blob) {
    const BlkId bid{blob->blkid};

    m_sb_blk_store->reserve_blk(bid);

    HS_REL_ASSERT_EQ(blob->type, blkstore_type::META_STORE, "Invalid blkstore [type={}]", blob->type);
    HS_LOG(INFO, metablk, "Loading meta ssb blkid: {}", bid.to_string());

    m_ssb = reinterpret_cast< meta_blk_sb* >(
        hs_utils::iobuf_alloc(get_page_size(), sisl::buftag::metablk, get_align_size()));
    std::memset(static_cast< void* >(m_ssb), 0, get_page_size());

    read(bid, static_cast< void* >(m_ssb), get_page_size());

    LOGINFO("Successfully loaded meta ssb from disk: {}", m_ssb->to_string());

    HS_REL_ASSERT_EQ(m_ssb->magic, META_BLK_SB_MAGIC);
    HS_REL_ASSERT_EQ(m_ssb->bid.is_valid(), true);
    HS_REL_ASSERT_EQ(m_ssb->bid.to_integer(), bid.to_integer());
    HS_REL_ASSERT_EQ(m_ssb->next_bid.is_valid(), true);
    m_inited = true;
}

void MetaBlkMgr::set_migrated() {
    std::lock_guard< decltype(m_meta_mtx) > lg{m_meta_mtx};
    m_ssb->migrated = true;
}

bool MetaBlkMgr::migrated() {
    std::lock_guard< decltype(m_meta_mtx) > lg{m_meta_mtx};
    return m_ssb->migrated;
}

void MetaBlkMgr::init_ssb() {
    std::lock_guard< decltype(m_meta_mtx) > lg(m_meta_mtx);
    BlkId bid;
    alloc_meta_blk(bid);
    HS_LOG(INFO, metablk, "allocated ssb blk: {}", bid.to_string());
    sb_blkstore_blob blob;
    blob.type = blkstore_type::META_STORE;
    blob.blkid = bid;
    m_sb_blk_store->update_vb_context(
        sisl::blob{reinterpret_cast< uint8_t* >(&blob), static_cast< uint32_t >(sizeof(sb_blkstore_blob))});

    m_ssb = reinterpret_cast< meta_blk_sb* >(
        hs_utils::iobuf_alloc(get_page_size(), sisl::buftag::metablk, get_align_size()));
    std::memset(static_cast< void* >(m_ssb), 0, get_page_size());

    m_last_mblk_id->invalidate();
    m_ssb->next_bid.invalidate();
    m_ssb->magic = META_BLK_SB_MAGIC;
    m_ssb->version = META_BLK_SB_VERSION;
    m_ssb->migrated = false;
    m_ssb->bid = bid;

    write_ssb();
    m_inited = true;
}

// m_meta_lock should be while calling this function;
void MetaBlkMgr::write_ssb() {
    std::array< iovec, 1 > iov;
    iov[0].iov_base = static_cast< void* >(m_ssb);
    iov[0].iov_len = get_page_size();

    // write current ovf blk to disk;
    try {
        m_sb_blk_store->write(m_ssb->bid, iov.data(), static_cast< int >(iov.size()));
    } catch (std::exception& e) { HS_REL_ASSERT(false, "exception happen during write {}", e.what()); }

    LOGINFO("Successfully write m_ssb to disk: {}", m_ssb->to_string());

    HS_REL_ASSERT_EQ(m_ssb->magic, META_BLK_SB_MAGIC);
    HS_REL_ASSERT_EQ(m_ssb->version, META_BLK_SB_VERSION);
    HS_REL_ASSERT_EQ(m_ssb->bid.is_valid(), true);
}

void MetaBlkMgr::scan_meta_blks() {
    cache_clear();
    const auto self_recover = scan_and_load_meta_blks(m_meta_blks, m_ovf_blk_hdrs, m_last_mblk_id.get(), m_sub_info);
    if (self_recover) { set_self_recover(); }
}

bool MetaBlkMgr::scan_and_load_meta_blks(meta_blk_map_t& meta_blks, ovf_hdr_map_t& ovf_blk_hdrs, BlkId* last_mblk_id,
                                         client_info_map_t& sub_info) {
    // take a look so that before scan is complete, no add/remove/update operations will be allowed;
    std::lock_guard< decltype(m_meta_mtx) > lg{m_meta_mtx};
    auto bid{m_ssb->next_bid};
    auto prev_meta_bid{m_ssb->bid};
    auto self_recover{false};

    while (bid.is_valid()) {
        last_mblk_id->set(bid);

        // TODO: add a new API in blkstore read to by pass cache;
        // e.g. take caller's read buf to avoid this extra memory copy;
        auto* mblk{reinterpret_cast< meta_blk* >(
            hs_utils::iobuf_alloc(get_page_size(), sisl::buftag::metablk, get_align_size()))};
        read(bid, mblk, get_page_size());

        // add meta blk to cache;
        meta_blks[bid.to_integer()] = mblk;

        // add meta blk id to reverse mapping for each client (for read api);
        sub_info[mblk->hdr.h.type].meta_bids.insert(mblk->hdr.h.bid.to_integer());

        HS_DBG_ASSERT_EQ(mblk->hdr.h.bid.to_integer(), bid.to_integer(), "{}, bid mismatch: {} : {} ", mblk->hdr.h.type,
                         mblk->hdr.h.bid.to_string(), bid.to_string());

        if (prev_meta_bid.to_integer() != mblk->hdr.h.prev_bid.to_integer()) {
            // recover from previous crash during remove_sub_sb;
            HS_LOG(INFO, metablk, "[type={}], Recovering fromp previous crash. Fixing prev linkage.", mblk->hdr.h.type);
            mblk->hdr.h.prev_bid = prev_meta_bid;
            self_recover = true;
            // persist updated mblk to disk
            write_meta_blk_to_disk(mblk);
        }

        prev_meta_bid = bid;

        // mark allocated for this block
        m_sb_blk_store->reserve_blk(mblk->hdr.h.bid);

        // populate overflow blk chain;
        auto obid{mblk->hdr.h.ovf_bid};

        // verify self bid;
        HS_REL_ASSERT_EQ(mblk->hdr.h.bid.to_integer(), bid.to_integer(),
                         "[type={}], corrupted: prev_mblk's next_bid: {} should equal to mblk's bid: {}",
                         mblk->hdr.h.type, bid.to_string(), mblk->hdr.h.bid.to_string());
        // verify magic
        HS_REL_ASSERT_EQ(static_cast< uint32_t >(mblk->hdr.h.magic), META_BLK_MAGIC,
                         "[type={}], magic mismatch: found: {}, expected: {}", mblk->hdr.h.type, mblk->hdr.h.magic,
                         META_BLK_MAGIC);

        // verify version
        HS_REL_ASSERT_EQ(static_cast< uint32_t >(mblk->hdr.h.version), META_BLK_VERSION,
                         "[type={}], version mismatch: found: {}, expected: {}", mblk->hdr.h.type, mblk->hdr.h.version,
                         META_BLK_VERSION);

        // if context sz can't fit in mblk, we currently don't store any data in it, but store all of the data to ovf
        // blks; this is to scale for 512 blk page size;
        uint64_t read_sz{mblk->hdr.h.context_sz > meta_blk_context_sz() ? 0 : mblk->hdr.h.context_sz};

#ifndef NDEBUG
        if (read_sz) {
            HS_DBG_ASSERT_EQ(obid.is_valid(), false);
        } else {
            HS_DBG_ASSERT_EQ(obid.is_valid(), true);
        }
#endif

        while (obid.is_valid()) {
            // ovf blk header occupies whole blk;
            auto* ovf_hdr{reinterpret_cast< meta_blk_ovf_hdr* >(
                hs_utils::iobuf_alloc(get_page_size(), sisl::buftag::metablk, get_align_size()))};
            read(obid, ovf_hdr, get_page_size());

            // verify self bid
            HS_REL_ASSERT_EQ(ovf_hdr->h.bid.to_integer(), obid.to_integer(), "Corrupted self-bid: {}/{}",
                             ovf_hdr->h.bid.to_string(), obid.to_string());
            // verify magic
            HS_REL_ASSERT_EQ(ovf_hdr->h.magic, META_BLK_OVF_MAGIC, "Ovf blk magic corrupted: {}, expected: {}",
                             ovf_hdr->h.magic, META_BLK_OVF_MAGIC);

            read_sz += ovf_hdr->h.context_sz;

            // add to ovf blk cache
            ovf_blk_hdrs[obid.to_integer()] = ovf_hdr;

            // allocate overflow bid;
            m_sb_blk_store->reserve_blk(obid);

            // allocate data bid
            auto* data_bid{ovf_hdr->get_data_bid()};
            for (decltype(ovf_hdr->h.nbids) i{0}; i < ovf_hdr->h.nbids; ++i) {
                m_sb_blk_store->reserve_blk(data_bid[i]);
            }

            // move on to next overflow blk
            obid = ovf_hdr->h.next_bid;
        }

        HS_REL_ASSERT_EQ(read_sz, static_cast< uint64_t >(mblk->hdr.h.context_sz),
                         "[type={}], total size read: {} mismatch from meta blk context_sz: {}", mblk->hdr.h.type,
                         read_sz, mblk->hdr.h.context_sz);

        // move on to next meta blk;
        bid = mblk->hdr.h.next_bid;
    }

    return self_recover;
}

bool MetaBlkMgr::is_sub_type_valid(const meta_sub_type type) { return m_sub_info.find(type) != m_sub_info.end(); }

void MetaBlkMgr::deregister_handler(const meta_sub_type type) {
    std::lock_guard< decltype(m_meta_mtx) > lk{m_meta_mtx};

    const auto it{m_sub_info.find(type)};
    if (it != std::end(m_sub_info)) {
        m_sub_info.erase(it);
        HS_LOG(INFO, metablk, "[type={}] deregistered Successfully", type);
    } else {
        HS_LOG(INFO, metablk, "[type={}] not found in registered list, no-op", type);
    }
}

void MetaBlkMgr::register_handler(const meta_sub_type type, const meta_blk_found_cb_t& cb,
                                  const meta_blk_recover_comp_cb_t& comp_cb, const bool do_crc) {
    std::lock_guard< decltype(m_meta_mtx) > lk(m_meta_mtx);
    HS_REL_ASSERT_LT(type.length(), MAX_SUBSYS_TYPE_LEN, "type len: {} should not exceed len: {}", type.length(),
                     MAX_SUBSYS_TYPE_LEN);

    // There is use case that client will register later after SB has been scanned from disk;
    // This client will read its superblock later;
    const auto it{m_sub_info.find(type)};
    if (it != std::end(m_sub_info)) {
        LOGINFO("[type={}] being registered after scanned from disk.", type);
        HS_DBG_ASSERT_EQ(it->second.cb == nullptr, true);
        HS_DBG_ASSERT_EQ(it->second.comp_cb == nullptr, true);
    }

    m_sub_info[type].cb = cb;
    m_sub_info[type].comp_cb = comp_cb;
    m_sub_info[type].do_crc = do_crc ? 1 : 0;
    HS_LOG(INFO, metablk, "[type={}] registered with do_crc: {}", type, do_crc);
}

void MetaBlkMgr::add_sub_sb(const meta_sub_type type, const void* context_data, const uint64_t sz, void*& cookie) {
    std::lock_guard< decltype(m_meta_mtx) > lg(m_meta_mtx);
    HS_REL_ASSERT_EQ(m_inited, true, "accessing metablk store before init is not allowed.");
    HS_REL_ASSERT_LT(type.length(), MAX_SUBSYS_TYPE_LEN, "type len: {} should not exceed len: {}", type.length(),
                     MAX_SUBSYS_TYPE_LEN);
    // not allowing add sub sb before registration
    HS_REL_ASSERT(m_sub_info.find(type) != m_sub_info.end(), "[type={}] not registered yet!", type);

    BlkId meta_bid;
    alloc_meta_blk(meta_bid);

    // add meta_bid to in-memory for reverse mapping;
    m_sub_info[type].meta_bids.insert(meta_bid.to_integer());

#ifdef _PRERELEASE
    uint32_t crc{0};
    if (m_sub_info[type].do_crc) { crc = crc32_ieee(init_crc32, static_cast< const uint8_t* >(context_data), sz); }
#endif

    HS_LOG(DEBUG, metablk, "[type={}], adding meta bid: {}, sz: {}", type, meta_bid.to_string(), sz);

    meta_blk* mblk{init_meta_blk(meta_bid, type, context_data, sz)};

    HS_LOG(DEBUG, metablk, "{}, Done adding bid: {}, prev: {}, next: {}, size: {}, crc: {}, mstore used size: {}", type,
           mblk->hdr.h.bid, mblk->hdr.h.prev_bid, mblk->hdr.h.next_bid, static_cast< uint64_t >(mblk->hdr.h.context_sz),
           static_cast< uint32_t >(mblk->hdr.h.crc), m_sb_blk_store->get_used_size());

#ifdef _PRERELEASE
    if (m_sub_info[type].do_crc && !(mblk->hdr.h.compressed)) {
        HS_REL_ASSERT_EQ(crc, static_cast< uint32_t >(mblk->hdr.h.crc),
                         "Input context data has been changed since received, crc mismatch: {}/{}", crc,
                         static_cast< uint32_t >(mblk->hdr.h.crc));
    }
#endif

    cookie = static_cast< void* >(mblk);

    // validate content of cookie
#ifdef _PRERELEASE
    _cookie_sanity_check(cookie);
#endif
}

void MetaBlkMgr::write_ovf_blk_to_disk(meta_blk_ovf_hdr* ovf_hdr, const void* context_data, const uint64_t sz,
                                       const uint64_t offset, const std::string& type) {
    HS_DBG_ASSERT_LE(ovf_hdr->h.context_sz + offset, sz);

    std::array< iovec, 1 > iov;
    iov[0].iov_base = static_cast< void* >(ovf_hdr);
    iov[0].iov_len = get_page_size();

    // write current ovf blk to disk;
    try {
        m_sb_blk_store->write(ovf_hdr->h.bid, iov.data(), static_cast< int >(iov.size()));
    } catch (std::exception& e) { HS_REL_ASSERT(false, "exception happen during write {}", e.what()); }

    // NOTE: The start write pointer which is context data pointer plus offset must be dma boundary aligned
    // TO DO: Might need to differentiate based on data or fast type
    const auto align_sz{get_align_size()};
    const uint8_t* write_context_data{static_cast< const uint8_t* >(context_data) + offset};
    size_t write_size{ovf_hdr->h.context_sz};
    uint8_t* context_data_aligned{nullptr};
    if (!hs_utils::mod_aligned_sz(reinterpret_cast< size_t >(write_context_data), align_sz)) {
        HS_LOG_EVERY_N(WARN, metablk, 50, "[type={}] Unaligned address found for input context_data.", type);
        const size_t aligned_write_size{static_cast< size_t >(sisl::round_up(write_size, align_sz))};
        context_data_aligned = hs_utils::iobuf_alloc(aligned_write_size, sisl::buftag::metablk, get_align_size());
        std::memcpy(context_data_aligned, write_context_data, write_size);
        std::memset(context_data_aligned + write_size, 0, aligned_write_size - write_size);

        // update to use new pointer and size
        write_context_data = context_data_aligned;
        write_size = aligned_write_size;
    }

    uint8_t* data_buf{nullptr}; // avoid copying entire context_data if sz is not aligned
    // write data blk to disk;
    size_t size_written{0};
    auto* data_bid{ovf_hdr->get_data_bid()};
    for (decltype(ovf_hdr->h.nbids) i{0}; i < ovf_hdr->h.nbids; ++i) {
        std::array< iovec, 1 > iovd;
        iovd[0].iov_base = const_cast< uint8_t* >(write_context_data) + size_written;
        if (i < ovf_hdr->h.nbids - 1) {
            iovd[0].iov_len = data_bid[i].get_nblks() * get_page_size();
            size_written += iovd[0].iov_len;
        } else {
            const size_t remain_sz_to_write{static_cast< size_t >(write_size - size_written)};
            iovd[0].iov_len = remain_sz_to_write;
            // pad last write to dma boundary size if needed
            if (!hs_utils::mod_aligned_sz(remain_sz_to_write, align_sz)) {
                HS_LOG_EVERY_N(DEBUG, metablk, 50, "[type={}] Unaligned input sz:{} found for input context_data.",
                               type, ovf_hdr->h.context_sz);
                const size_t round_sz{static_cast< size_t >(sisl::round_up(remain_sz_to_write, align_sz))};
                iovd[0].iov_len = round_sz;
                data_buf = hs_utils::iobuf_alloc(round_sz, sisl::buftag::metablk, get_align_size());
                std::memcpy(data_buf, iovd[0].iov_base, remain_sz_to_write);
                std::memset(data_buf + remain_sz_to_write, 0, round_sz - remain_sz_to_write);
                iovd[0].iov_base = data_buf;
            }
            // adjust size written to be the actual data and not write size
            size_written += (ovf_hdr->h.context_sz - size_written);
        }

        try {
            m_sb_blk_store->write(data_bid[i], iovd.data(), static_cast< int >(iovd.size()));
        } catch (std::exception& e) { HS_REL_ASSERT(false, "exception happen during write {}", e.what()); }
    }

    if (data_buf) { hs_utils::iobuf_free(data_buf, sisl::buftag::metablk); }
    if (context_data_aligned) { hs_utils::iobuf_free(context_data_aligned, sisl::buftag::metablk); }

    HS_DBG_ASSERT_EQ(size_written, ovf_hdr->h.context_sz);
}

void MetaBlkMgr::write_meta_blk_to_disk(meta_blk* mblk) {
    std::array< iovec, 1 > iov;
    iov[0].iov_base = static_cast< void* >(mblk);
    iov[0].iov_len = get_page_size();

    // write current ovf blk to disk;
    try {
        m_sb_blk_store->write(mblk->hdr.h.bid, iov.data(), static_cast< int >(iov.size()));
    } catch (std::exception& e) { HS_REL_ASSERT(false, "exception happen during write {}", e.what()); }
}

//
// write blks to disks in reverse order
// 1. write meta blk chain to disk;
// 2. update in-memory m_last_mblk and write to disk or
//    update in-memory m_ssb and write to disk;
// 3. update in-memory meta blks map;
//
meta_blk* MetaBlkMgr::init_meta_blk(BlkId& bid, const meta_sub_type type, const void* context_data, const size_t sz) {
    meta_blk* mblk{
        reinterpret_cast< meta_blk* >(hs_utils::iobuf_alloc(get_page_size(), sisl::buftag::metablk, get_align_size()))};
    mblk->hdr.h.compressed = 0;
    mblk->hdr.h.bid = bid;
    std::memset(static_cast< void* >(mblk->hdr.h.type), 0, MAX_SUBSYS_TYPE_LEN);
    std::memcpy(static_cast< void* >(mblk->hdr.h.type), static_cast< const void* >(type.c_str()), type.length());

    mblk->hdr.h.magic = META_BLK_MAGIC;
    mblk->hdr.h.version = META_BLK_VERSION;
    mblk->hdr.h.gen_cnt = 0;

    // handle prev/next pointer linkage;
    if (m_last_mblk_id->is_valid()) {
        // update this mblk's prev bid to last mblk;
        mblk->hdr.h.prev_bid = *m_last_mblk_id;

        // update last mblk's next to this mblk;
        m_meta_blks[m_last_mblk_id->to_integer()]->hdr.h.next_bid = bid;
    } else {
        // this is the first sub sb being added;
        mblk->hdr.h.prev_bid = m_ssb->bid;
        HS_DBG_ASSERT_EQ(m_ssb->next_bid.is_valid(), false);
        HS_LOG(INFO, metablk, "{}, Changing meta ssb bid: {}'s next_bid to {}", type, m_ssb->bid, bid.to_string());
        m_ssb->next_bid = bid;
    }

    // this mblk is now the last;
    mblk->hdr.h.next_bid.invalidate();

    // write this meta blk to disk
    write_meta_blk_internal(mblk, context_data, sz);

    // now update previous last mblk or ssb. They can only be updated after meta blk is written to disk;
    if (m_last_mblk_id->is_valid()) {
        // persist the changes to last mblk;
        write_meta_blk_to_disk(m_meta_blks[m_last_mblk_id->to_integer()]);
    } else {
        // persiste the changes;
        write_ssb();
    }

    // point last mblk to this mblk;
    m_last_mblk_id->set(bid);

    // add to cache;
    HS_DBG_ASSERT(m_meta_blks.find(bid.to_integer()) == m_meta_blks.end(),
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
void MetaBlkMgr::write_meta_blk_ovf(BlkId& out_obid, const void* context_data, const uint64_t sz,
                                    const std::string& type) {
    HS_DBG_ASSERT(m_meta_mtx.try_lock() == false, "mutex should be already be locked");

    // allocate data blocks
    static thread_local std::vector< BlkId > context_data_blkids{};
    context_data_blkids.clear();
    alloc_meta_blk(sisl::round_up(sz, get_page_size()), context_data_blkids);

    HS_LOG(DEBUG, metablk, "Start to allocate nblks(data): {}, mstore used size: {}", context_data_blkids.size(),
           m_sb_blk_store->get_used_size());

    // return the 1st ovf header blk id to caller;
    alloc_meta_blk(out_obid);
    BlkId next_bid{out_obid};
    uint64_t offset_in_ctx{0};
    uint32_t data_blkid_indx{0};

    while (next_bid.is_valid()) {
        meta_blk_ovf_hdr* ovf_hdr{reinterpret_cast< meta_blk_ovf_hdr* >(
            hs_utils::iobuf_alloc(get_page_size(), sisl::buftag::metablk, get_align_size()))};
        const BlkId cur_bid{next_bid};
        ovf_hdr->h.magic = META_BLK_OVF_MAGIC;
        ovf_hdr->h.bid = cur_bid;

        if ((context_data_blkids.size() - (data_blkid_indx + 1)) <= ovf_blk_max_num_data_blk()) {
            ovf_hdr->h.next_bid.invalidate();
        } else {
            alloc_meta_blk(ovf_hdr->h.next_bid);
        }
        next_bid = ovf_hdr->h.next_bid;

        // save data bids to ovf hdr block;
        decltype(ovf_hdr->h.nbids) j{0};
        uint64_t data_size{0};
        auto* data_bid{ovf_hdr->get_data_bid_mutable()};
        for (; (j < ovf_blk_max_num_data_blk()) && (data_blkid_indx < context_data_blkids.size()); ++j) {
            data_size += context_data_blkids[data_blkid_indx].data_size(get_page_size());
            data_bid[j] = context_data_blkids[data_blkid_indx++];
        }

        ovf_hdr->h.nbids = j;
        // context_sz points to the actual context data written into data_bid;
        ovf_hdr->h.context_sz = (data_blkid_indx < context_data_blkids.size() - 1) ? data_size : (sz - offset_in_ctx);
        HS_LOG(TRACE, metablk, "MetaBlk overflow blk created, info: {}", ovf_hdr->to_string());

        m_ovf_blk_hdrs[cur_bid.to_integer()] = ovf_hdr;

        // write ovf header blk to disk
        write_ovf_blk_to_disk(ovf_hdr, context_data, sz, offset_in_ctx, type);

        offset_in_ctx += ovf_hdr->h.context_sz;
    }

    HS_REL_ASSERT_EQ(offset_in_ctx, sz);
}

void MetaBlkMgr::write_meta_blk_internal(meta_blk* mblk, const void* context_data, const uint64_t sz) {
    auto data_sz{sz};
    // start compression
    if (compress_feature_on() && (sz >= get_min_compress_size())) {
        // TO DO: Might need to differentiate based on data or fast type
        const uint64_t max_dst_size{sisl::round_up(sisl::Compress::max_compress_len(sz), get_align_size())};
        if (max_dst_size <= get_max_compress_memory_size()) {
            if (max_dst_size > m_compress_info.size) {
                free_compress_buf();
                alloc_compress_buf(max_dst_size);
            }

            std::memset(static_cast< void* >(m_compress_info.bytes), 0, max_dst_size);

            size_t compressed_size{max_dst_size};
            const auto ret{sisl::Compress::compress(static_cast< const char* >(context_data),
                                                    reinterpret_cast< char* >(m_compress_info.bytes), sz,
                                                    &compressed_size)};
            if (ret != 0) {
                LOGERROR("hs_compress_default indicates a failure trying to compress the data, ret: {}", ret);
                HS_REL_ASSERT(false, "failed to compress");
            }
            const uint32_t ratio_percent{static_cast< uint32_t >(static_cast< uint64_t >(compressed_size) * 100 / sz)};
            if (ratio_percent <= get_compress_ratio_limit()) {
                COUNTER_INCREMENT(m_metrics, compress_success_cnt, 1);
                HISTOGRAM_OBSERVE(m_metrics, compress_ratio_percent, ratio_percent);
                mblk->hdr.h.compressed = 1;
                mblk->hdr.h.src_context_sz = sz;
                // TO DO: Might need to differentiate based on data or fast type
                mblk->hdr.h.context_sz = sisl::round_up(compressed_size, get_align_size());
                mblk->hdr.h.compressed_sz = compressed_size;

                HS_PERIODIC_LOG(INFO, metablk, "[type={}] Successfully compressed some data! Ratio: {}",
                                mblk->hdr.h.type, (float)compressed_size / sz);

                HS_LOG(DEBUG, metablk, "compressed_sz: {}, src_context_sz: {}, context_sz: {}", compressed_size, sz,
                       static_cast< uint64_t >(mblk->hdr.h.context_sz));

                HS_REL_ASSERT_GE(max_dst_size, static_cast< uint64_t >(mblk->hdr.h.context_sz));

                // point context_data to compressed data;
                context_data = static_cast< const void* >(m_compress_info.bytes);
                data_sz = mblk->hdr.h.context_sz;
            } else {
                // back off compression if compress ratio doesn't meet criteria.
                HS_PERIODIC_LOG(INFO, metablk, "Bypass compress because percent ratio: {} is exceeding limit: {}",
                                ratio_percent, get_compress_ratio_limit());

                COUNTER_INCREMENT(m_metrics, compress_backoff_ratio_cnt, 1);
            }
        } else {
            // back off compression if compress memory size is exceeding limit;
            HS_PERIODIC_LOG(INFO, metablk, "Bypass compress because memory required: {} is exceeding limit: {}",
                            max_dst_size, get_max_compress_memory_size());
            COUNTER_INCREMENT(m_metrics, compress_backoff_memory_cnt, 1);
        }
    }

    if (!mblk->hdr.h.compressed) { mblk->hdr.h.context_sz = sz; }

    // within block context size;
    if (data_sz <= meta_blk_context_sz()) {
        // for inline case, set ovf_bid to invalid
        mblk->hdr.h.ovf_bid.invalidate();

        std::memcpy(static_cast< void* >(mblk->get_context_data_mutable()), static_cast< const void* >(context_data),
                    data_sz);
    } else {
        // all context data will be in overflow buffer to avoid data copy and non dma_boundary aligned write;
        BlkId obid;

        // write overflow block to disk;
        write_meta_blk_ovf(obid, context_data, data_sz, mblk->hdr.h.type);

        HS_DBG_ASSERT(obid.is_valid(), "Expected valid blkid");
        mblk->hdr.h.ovf_bid = obid;

#ifdef _PRERELEASE
        HomeStoreFlip::test_and_abort("write_with_ovf_abort");
#endif
    }

    // for both in-band and ovf buffer, we store crc in meta blk header;
    if (m_sub_info[mblk->hdr.h.type].do_crc) {
        mblk->hdr.h.crc = crc32_ieee(init_crc32, static_cast< const uint8_t* >(context_data), data_sz);
    }

    // write meta blk;
    write_meta_blk_to_disk(mblk);

#ifdef _PRERELEASE
    HomeStoreFlip::test_and_abort("write_sb_abort");
#endif
}

//
// the input cookie being checked could the the one received from client doing add/update/remove or
// a meta blk read from disk;
//
void MetaBlkMgr::_cookie_sanity_check(const void* cookie) const {
    auto mblk{static_cast< const meta_blk* >(cookie)};

    HS_REL_ASSERT_EQ(cookie != nullptr, true, "null cookie!");
    HS_REL_ASSERT_EQ(mblk->hdr.h.version == META_BLK_VERSION && mblk->hdr.h.magic == META_BLK_MAGIC, true,
                     "Corrupted version/magic: {}", mblk->to_string());

    HS_REL_ASSERT_EQ(mblk->hdr.h.prev_bid.is_valid() && mblk->hdr.h.bid.is_valid(), true,
                     "Invalid prev-bid or self-bid is not possible. Corrupted cookie: {}", mblk->to_string());

    auto it_sub_info{m_sub_info.find(mblk->hdr.h.type)};
    HS_REL_ASSERT_EQ(it_sub_info != m_sub_info.end(), true, "[type={}] not registered yet!", mblk->hdr.h.type);

    // self-bid must exist in m_sub_info meta_bids;
    bool exist{false};
    for (auto& x : it_sub_info->second.meta_bids) {
        if (x == mblk->hdr.h.bid.to_integer()) {
            auto it = m_meta_blks.find(x);
            auto cached_mblk = it->second;
            if (cached_mblk != mblk) {
                // input cookie could be read from disk, so it is not same address as cached_mblk;
                HS_REL_ASSERT_EQ(cached_mblk->hdr.h.bid.to_integer(), mblk->hdr.h.bid.to_integer());
                HS_REL_ASSERT_EQ(cached_mblk->hdr.h.gen_cnt, mblk->hdr.h.gen_cnt);
                HS_REL_ASSERT_EQ(cached_mblk->hdr.h.next_bid.to_integer(), mblk->hdr.h.next_bid.to_integer());
                HS_REL_ASSERT_EQ(cached_mblk->hdr.h.prev_bid.to_integer(), mblk->hdr.h.prev_bid.to_integer());
            }
            exist = true;
            break;
        }
    }

    HS_REL_ASSERT_EQ(exist, true, "self-bid not found in cache!");
}

//
// Do in-place update:
// 1. allcate ovf_bid if needed
// 2. update the meta_blk
// 3. free old ovf_bid if there is any
//
void MetaBlkMgr::update_sub_sb(const void* context_data, const uint64_t sz, void*& cookie) {
    std::lock_guard< decltype(m_meta_mtx) > lg{m_meta_mtx};
    HS_REL_ASSERT_EQ(m_inited, true, "accessing metablk store before init is not allowed.");

#ifdef _PRERELEASE
    _cookie_sanity_check(cookie);
#endif
    meta_blk* mblk{static_cast< meta_blk* >(cookie)};

    HS_LOG(DEBUG, metablk, "[type={}], update_sub_sb old sb: context_sz: {}, ovf_bid: {}, mstore used size: {}",
           mblk->hdr.h.type, (unsigned long)(mblk->hdr.h.context_sz), mblk->hdr.h.ovf_bid.to_string(),
           m_sb_blk_store->get_used_size());

    const auto ovf_bid_to_free{mblk->hdr.h.ovf_bid};

#ifdef _PRERELEASE
    uint32_t crc{0};
    const auto it{m_sub_info.find(mblk->hdr.h.type)};
    HS_DBG_ASSERT(it != std::end(m_sub_info), "[type={}] not registered yet!", mblk->hdr.h.type);
    if (it->second.do_crc) { crc = crc32_ieee(init_crc32, static_cast< const uint8_t* >(context_data), sz); }
#endif

    mblk->hdr.h.ovf_bid.invalidate();
    mblk->hdr.h.gen_cnt += 1;

    // write this meta blk to disk
    write_meta_blk_internal(mblk, context_data, sz);

#ifdef _PRERELEASE
    HomeStoreFlip::test_and_abort("update_sb_abort");
#endif

    // free the overflow bid if it is there
    free_ovf_blk_chain(ovf_bid_to_free);

    HS_LOG(DEBUG, metablk, "[type={}], update_sub_sb new sb: context_sz: {}, ovf_bid: {}, mstore used size: {}",
           mblk->hdr.h.type, static_cast< uint64_t >(mblk->hdr.h.context_sz), mblk->hdr.h.ovf_bid.to_string(),
           m_sb_blk_store->get_used_size());

#ifdef _PRERELEASE
    if (!(mblk->hdr.h.compressed) && it->second.do_crc) {
        HS_REL_ASSERT_EQ(crc, static_cast< uint32_t >(mblk->hdr.h.crc),
                         "[type={}]: Input context data has been changed since received, crc mismatch: {}/{}",
                         mblk->hdr.h.type, crc, static_cast< uint32_t >(mblk->hdr.h.crc));
    }
#endif

    // no need to update cookie and in-memory meta blk map

#ifdef _PRERELEASE
    // validate since update will change content of cookie
    _cookie_sanity_check(cookie);
#endif
}

std::error_condition MetaBlkMgr::remove_sub_sb(void* cookie) {
    std::lock_guard< decltype(m_meta_mtx) > lg{m_meta_mtx};
#ifdef _PRERELEASE
    _cookie_sanity_check(cookie);
#endif
    HS_REL_ASSERT_EQ(m_inited, true, "accessing metablk store before init is not allowed.");
    meta_blk* rm_blk{static_cast< meta_blk* >(cookie)};
    const BlkId rm_bid{rm_blk->hdr.h.bid};
    const auto type{rm_blk->hdr.h.type};

    // this record must exist in-memory copy
    HS_DBG_ASSERT(m_meta_blks.find(rm_bid.to_integer()) != m_meta_blks.end(), "{}, id: {} not found!", type,
                  rm_bid.to_string());
    HS_DBG_ASSERT(m_sub_info.find(type) != m_sub_info.end(), "{}, meta blk being reomved has not registered yet!",
                  type);

    // remove from disk;
    const auto rm_blk_in_cache{m_meta_blks[rm_bid.to_integer()]};
    auto prev_bid{rm_blk_in_cache->hdr.h.prev_bid};
    auto next_bid{rm_blk_in_cache->hdr.h.next_bid};

    HS_LOG(INFO, metablk, "[type={}], remove_sub_sb meta blk id: {}, prev_bid: {}, next_bid: {}, mstore used size: {}",
           type, rm_bid.to_string(), prev_bid.to_string(), next_bid.to_string(), m_sb_blk_store->get_used_size());

    // validate bid/prev/next with cache data;
    if (rm_blk != rm_blk_in_cache) {
        HS_DBG_ASSERT(false, "{}, cookie doesn't match with cached blk, invalid cookie!", type);
    }

    // update prev-blk's next pointer
    if (prev_bid.to_integer() == m_ssb->bid.to_integer()) {
        m_ssb->next_bid = next_bid;
        // persist m_ssb to disk;
        write_ssb();
        if (m_last_mblk_id->to_integer() == rm_bid.to_integer()) { m_last_mblk_id->invalidate(); }
    } else {
        // find the in-memory copy of prev meta block;
        HS_DBG_ASSERT(m_meta_blks.find(prev_bid.to_integer()) != m_meta_blks.end(), "prev: {} not found!",
                      prev_bid.to_string());

        // update prev meta blk's both in-memory and on-disk copy;
        m_meta_blks[prev_bid.to_integer()]->hdr.h.next_bid = next_bid;
        write_meta_blk_to_disk(m_meta_blks[prev_bid.to_integer()]);
    }

    // update next-blk's prev pointer
    if (next_bid.is_valid()) {
        HS_DBG_ASSERT(m_meta_blks.find(next_bid.to_integer()) != m_meta_blks.end(), "next_bid: {} not found in cache",
                      type, next_bid.to_string());
        auto next_mblk{m_meta_blks[next_bid.to_integer()]};

        // update next meta blk's both in-memory and on-disk copy;
        next_mblk->hdr.h.prev_bid = prev_bid;
        write_meta_blk_to_disk(next_mblk);
    } else {
        // if we are removing the last meta blk, update last to its previous blk;
        HS_DBG_ASSERT_EQ(m_last_mblk_id->to_integer(), rm_bid.to_integer());

        HS_LOG(DEBUG, metablk, "removing last mblk, change m_last_mblk to bid: {}, [type={}]", prev_bid.to_string(),
               m_meta_blks[prev_bid.to_integer()]->hdr.h.type);
        m_last_mblk_id->set(prev_bid);
    }

    // remove the in-memory handle from meta blk map;
    m_meta_blks.erase(rm_bid.to_integer());

    // clear in-memory cop of meta bids;
    m_sub_info[type].meta_bids.erase(rm_bid.to_integer());

    // free the on-disk meta blk
    free_meta_blk(rm_blk);

#ifdef _PRERELEASE
    HomeStoreFlip::test_and_abort("remove_sb_abort");
#endif

    HS_LOG(DEBUG, metablk, "after remove, mstore used size: {}", m_sb_blk_store->get_used_size());
    return no_error;
}

//
// if we crash in the middle, after reboot the ovf blk will be treaded as free automatically;
//
void MetaBlkMgr::free_ovf_blk_chain(const BlkId& obid) {
    auto cur_obid{obid};
    while (cur_obid.is_valid()) {
        auto* ovf_hdr{m_ovf_blk_hdrs[cur_obid.to_integer()]};

        uint64_t used_size_before_free{m_sb_blk_store->get_used_size()};
        uint64_t total_nblks_freed{0};

        HS_LOG(DEBUG, metablk, "starting to free ovf blk: {}, nbids(data): {}, mstore used size: {}",
               cur_obid.to_string(), ovf_hdr->h.nbids, m_sb_blk_store->get_used_size());

        // free on-disk data bid
        auto* data_bid{ovf_hdr->get_data_bid()};
        for (decltype(ovf_hdr->h.nbids) i{0}; i < ovf_hdr->h.nbids; ++i) {
            m_sb_blk_store->free_blk(data_bid[i], boost::none, boost::none);
            total_nblks_freed += data_bid[i].get_nblks();

            HS_LOG(DEBUG, metablk, "after freeing data bid: {}, mstore used size: {}", data_bid[i].to_string(),
                   m_sb_blk_store->get_used_size());
        }

        // free on-disk ovf header blk
        m_sb_blk_store->free_blk(cur_obid, boost::none, boost::none);
        total_nblks_freed += cur_obid.get_nblks();

        HS_LOG(DEBUG, metablk, "after freeing ovf bidid: {}, mstore used size: {}", cur_obid.to_string(),
               m_sb_blk_store->get_used_size());

        // assert that freed space should match with the total blks freed;
        HS_DBG_ASSERT_EQ(used_size_before_free - m_sb_blk_store->get_used_size(),
                         total_nblks_freed * m_sb_blk_store->get_page_size());

        const auto save_old{cur_obid};

        // get next chained ovf blk id from cache;
        cur_obid = ovf_hdr->h.next_bid;

        const auto it{m_ovf_blk_hdrs.find(save_old.to_integer())};
        if (it == std::end(m_ovf_blk_hdrs)) HS_REL_ASSERT(false, "OVF block header not find {}", save_old.to_integer());

        // free the ovf header memory;
        hs_utils::iobuf_free(reinterpret_cast< uint8_t* >(it->second), sisl::buftag::metablk);

        // remove from ovf blk cache;
        m_ovf_blk_hdrs.erase(it);
    }
}

void MetaBlkMgr::free_meta_blk(meta_blk* mblk) {
    HS_LOG(DEBUG, metablk, "[type={}], freeing blk id: {}", mblk->hdr.h.type, mblk->hdr.h.bid.to_string());

    m_sb_blk_store->free_blk(mblk->hdr.h.bid, boost::none, boost::none);

    // free the overflow bid if it is there
    if (mblk->hdr.h.ovf_bid.is_valid()) {
        HS_DBG_ASSERT_GE(static_cast< uint64_t >(mblk->hdr.h.context_sz), meta_blk_context_sz(),
                         "[type={}], context_sz: {} less than {} is invalid", mblk->hdr.h.type,
                         static_cast< uint64_t >(mblk->hdr.h.context_sz), meta_blk_context_sz());
        free_ovf_blk_chain(mblk->hdr.h.ovf_bid);
    }

    hs_utils::iobuf_free(reinterpret_cast< uint8_t* >(mblk), sisl::buftag::metablk);
}

void MetaBlkMgr::alloc_meta_blk(const uint64_t size, std::vector< BlkId >& bid) {
    blk_alloc_hints hints;
    hints.desired_temp = 0;
    hints.dev_id_hint = -1;
    hints.is_contiguous = false;

    try {
        const auto ret{m_sb_blk_store->alloc_blk(size, hints, bid)};
        HS_REL_ASSERT_EQ(ret, BlkAllocStatus::SUCCESS);
#ifndef NDEBUG
        uint64_t debug_size{0};
        for (size_t i{0}; i < bid.size(); ++i) {
            debug_size += bid[i].data_size(m_sb_blk_store->get_page_size());
        }
        HS_DBG_ASSERT_EQ(debug_size, size);
#endif

    } catch (const std::exception& e) {
        HS_REL_ASSERT(0, "{}", e.what());
        return;
    }
}

void MetaBlkMgr::alloc_meta_blk(BlkId& bid) {
    blk_alloc_hints hints;
    hints.desired_temp = 0;
    hints.dev_id_hint = -1;
    hints.is_contiguous = true;

    try {
        const auto ret{m_sb_blk_store->alloc_contiguous_blk(get_page_size(), hints, &bid)};
        HS_REL_ASSERT_EQ(ret, BlkAllocStatus::SUCCESS);
    } catch (const std::exception& e) { HS_REL_ASSERT(0, "{}", e.what()); }
}

sisl::byte_array MetaBlkMgr::read_sub_sb_internal(const meta_blk* mblk) const {
    sisl::byte_array buf;
    HS_DBG_ASSERT_EQ(mblk != nullptr, true);
    if (mblk->hdr.h.context_sz <= meta_blk_context_sz()) {
        // data can be compressed
        // TO DO: Might need to address alignment based on data or fast type
        buf = hs_utils::make_byte_array(mblk->hdr.h.context_sz, false /* aligned */, sisl::buftag::metablk,
                                        get_align_size());
        HS_DBG_ASSERT_EQ(mblk->hdr.h.ovf_bid.is_valid(), false, "[type={}], unexpected ovf_bid: {}", mblk->hdr.h.type,
                         mblk->hdr.h.ovf_bid.to_string());
        std::memcpy(static_cast< void* >(buf->bytes), static_cast< const void* >(mblk->get_context_data()),
                    mblk->hdr.h.context_sz);
    } else {
        //
        // read through the ovf blk chain to get the buffer;
        // all the context data was stored in ovf blk chain, nothing in meta blk context data portion;
        //
        // TO DO: Might need to address alignment based on data or fast type
        buf = hs_utils::make_byte_array(mblk->hdr.h.context_sz, true /* aligned */, sisl::buftag::metablk,
                                        get_align_size());
        const auto total_sz{mblk->hdr.h.context_sz};
        uint64_t read_offset{0}; // read offset in overall context data;

        auto obid{mblk->hdr.h.ovf_bid};
        while (read_offset < total_sz) {
            HS_REL_ASSERT_EQ(obid.is_valid(), true, "[type={}], corrupted ovf_bid: {}", mblk->hdr.h.type,
                             obid.to_string());

            // copy the remaining data from ovf blk chain;
            // we don't cache context data, so read from disk;
            const auto ovf_itr{m_ovf_blk_hdrs.find(obid.to_integer())};
            const auto* ovf_hdr{ovf_itr->second};
            uint64_t read_offset_in_this_ovf{0}; // read offset in data covered by this overflow blk;
            const auto* data_bid{ovf_hdr->get_data_bid()};
            for (decltype(ovf_hdr->h.nbids) i{0}; i < ovf_hdr->h.nbids; ++i) {
                size_t read_sz_per_db{0};
                if (i < ovf_hdr->h.nbids - 1) {
                    read_sz_per_db = data_bid[i].get_nblks() * get_page_size();
                } else {
                    // it is possible user context data doesn't occupy the whole block, so we need to remember the size
                    // that was written to the last data blk;
                    read_sz_per_db = ovf_hdr->h.context_sz - read_offset_in_this_ovf;
                }

                // TO DO: Might need to differentiate based on data or fast type
                read(data_bid[i], buf->bytes + read_offset, sisl::round_up(read_sz_per_db, get_align_size()));

                read_offset_in_this_ovf += read_sz_per_db;
                read_offset += read_sz_per_db;
            }

            HS_DBG_ASSERT_EQ(read_offset_in_this_ovf, ovf_hdr->h.context_sz);

            // verify self bid
            HS_REL_ASSERT_EQ(ovf_hdr->h.bid.to_integer(), obid.to_integer(), "[type={}], Corrupted self-bid: {}/{}",
                             mblk->hdr.h.type, ovf_hdr->h.bid.to_string(), obid.to_string());

            obid = ovf_hdr->h.next_bid;
        }

        HS_REL_ASSERT_EQ(read_offset, total_sz, "[type={}], incorrect data read from disk: {}, total_sz: {}",
                         mblk->hdr.h.type, read_offset, total_sz);
    }
    return buf;
}

// m_meta_mtx is used for concurrency between add/remove/update APIs and shutdown threads;
// m_shutdown_mtx is used for concurrency between recover and shutdown threads;
//
// Note: Client will call add/remove/update APIs in recover function (in complete_cb);
void MetaBlkMgr::recover(const bool do_comp_cb) {
    // for each registered subsystem, look up in cache for their meta blks;
    std::lock_guard< decltype(m_meta_mtx) > lg{m_shutdown_mtx};
    for (auto& m : m_meta_blks) {
        auto* mblk{m.second};
        auto buf{read_sub_sb_internal(mblk)};

        // found a meta blk and callback to sub system;
        const auto itr{m_sub_info.find(mblk->hdr.h.type)};
        if (itr != std::end(m_sub_info)) {
            // if subsystem registered crc protection, verify crc before sending to subsystem;
            if (itr->second.do_crc) {
                const auto crc{
                    crc32_ieee(init_crc32, static_cast< const uint8_t* >(buf->bytes), mblk->hdr.h.context_sz)};

                HS_REL_ASSERT_EQ(crc, static_cast< uint32_t >(mblk->hdr.h.crc),
                                 "[type={}], CRC mismatch: {}/{}, on mblk bid: {}, context_sz: {}", mblk->hdr.h.type,
                                 crc, static_cast< uint32_t >(mblk->hdr.h.crc), mblk->hdr.h.bid.to_string(),
                                 static_cast< uint64_t >(mblk->hdr.h.context_sz));
            } else {
                HS_LOG(DEBUG, metablk, "[type={}] meta blk found with bypassing crc.", mblk->hdr.h.type);
            }

            // send the callbck;
            auto& cb{itr->second.cb};
            if (cb) { // cb could be nullptr because client want to get its superblock via read api;
                // decompress if necessary
                if (mblk->hdr.h.compressed) {
                    // HS_DBG_ASSERT_GE(mblk->hdr.h.context_sz, META_BLK_CONTEXT_SZ);
                    // TO DO: Might need to address alignment based on data or fast type
                    auto decompressed_buf{hs_utils::make_byte_array(mblk->hdr.h.src_context_sz, true /* aligned */,
                                                                    sisl::buftag::compression, get_align_size())};
                    size_t decompressed_size{mblk->hdr.h.src_context_sz};
                    const auto ret{sisl::Compress::decompress(reinterpret_cast< const char* >(buf->bytes),
                                                              reinterpret_cast< char* >(decompressed_buf->bytes),
                                                              mblk->hdr.h.compressed_sz, &decompressed_size)};
                    if (ret != 0) {
                        LOGERROR("[type={}], negative result: {} from decompress trying to decompress the "
                                 "data. compressed_sz: {}, src_context_sz: {}",
                                 mblk->hdr.h.type, ret, static_cast< uint64_t >(mblk->hdr.h.compressed_sz),
                                 static_cast< uint64_t >(mblk->hdr.h.src_context_sz));
                        HS_REL_ASSERT(false, "failed to decompress");
                    } else {
                        // decompressed_size must equal to input sz before compress
                        HS_REL_ASSERT_EQ(
                            static_cast< uint64_t >(mblk->hdr.h.src_context_sz),
                            static_cast< uint64_t >(
                                decompressed_size)); /* since decompressed_size is >=0 it is safe to cast to uint64_t */
                        HS_LOG(DEBUG, metablk,
                               "[type={}] Successfully decompressed, compressed_sz: {}, src_context_sz: {}, "
                               "decompressed_size: {}",
                               mblk->hdr.h.type, static_cast< uint64_t >(mblk->hdr.h.compressed_sz),
                               static_cast< uint64_t >(mblk->hdr.h.src_context_sz), decompressed_size);
                    }

                    cb(mblk, decompressed_buf, mblk->hdr.h.src_context_sz);
                } else {
                    // There is use case that cb could be nullptr because client want to get its superblock via read
                    // api;
                    cb(mblk, buf, mblk->hdr.h.context_sz);
                }

                HS_LOG(DEBUG, metablk, "[type={}] meta blk sent with size: {}.", mblk->hdr.h.type,
                       static_cast< uint64_t >(mblk->hdr.h.context_sz));
            }
        } else {
            HS_LOG(DEBUG, metablk, "[type={}], unregistered client found. ");
#if 0
            // should never arrive here since we do assert on type before write to disk;
            HS_LOG_ASSERT( false, "[type={}] not registered for mblk found on disk. Skip this meta blk. ",
                      mblk->hdr.h.type);
#endif
        }
    }

    if (do_comp_cb) {
        // for each registered subsystem, do recovery complete callback;
        for (auto& sub : m_sub_info) {
            if (sub.second.comp_cb) {
                sub.second.comp_cb(true);
                HS_LOG(DEBUG, metablk, "[type={}] completion callback sent.", sub.first);
            }
        }
    }
}

//
// Acquire lock in read is to avoid same client issue update/remove/read on same cookie concurrently (though it should
// not happen in normal case).
//
void MetaBlkMgr::read_sub_sb(const meta_sub_type type) {
    std::lock_guard< decltype(m_meta_mtx) > lg{m_meta_mtx};
    HS_REL_ASSERT_EQ(m_inited, true, "accessing metablk store before init is not allowed.");
    const auto it_s{m_sub_info.find(type)};
    HS_REL_ASSERT_EQ(it_s != std::end(m_sub_info), true,
                     "Unregistered client [type={}], need to register fistly before read", type);

    // bid is stored as uint64_t
    for (const auto& bid : it_s->second.meta_bids) {
        const auto it{m_meta_blks.find(bid)};

        HS_REL_ASSERT_EQ(it != std::end(m_meta_blks), true);
        auto* mblk{it->second};
        //
        // No client writes compressed data with reads it back with read_sub_sb for now;
        // This assert can be removed if any client writes compressed data who calls read_sub_sb to read it back;
        //
        HS_REL_ASSERT_EQ(mblk->hdr.h.compressed, false);
        sisl::byte_array buf{read_sub_sb_internal(mblk)};

        // if consumer is reading its sbs with this api, the blk found cb should already be registered;
        HS_REL_ASSERT_EQ(it_s->second.cb.operator bool(), true);
        it_s->second.cb(mblk, buf, mblk->hdr.h.context_sz);
    }

    // if is allowed if consumer doesn't care about complete cb, e.g. consumer knows how many mblks it is expecting;
    if (it_s->second.comp_cb) { it_s->second.comp_cb(true); }
}

uint64_t MetaBlkMgr::get_meta_size(const void* cookie) const {
    const auto* mblk{static_cast< const meta_blk* >(cookie)};
    size_t nblks{1}; // meta blk itself;
    auto obid{mblk->hdr.h.ovf_bid};
    while (obid.is_valid()) {
        const auto ovf_itr{m_ovf_blk_hdrs.find(obid.to_integer())};
        const auto* ovf_hdr{ovf_itr->second};
        ++nblks; // ovf header blk;
        const auto* data_bid{ovf_hdr->get_data_bid()};
        for (decltype(ovf_hdr->h.nbids) i{0}; i < ovf_hdr->h.nbids; ++i) {
            nblks += data_bid[i].get_nblks(); // data blks;
        }
        obid = ovf_hdr->h.next_bid;
    }

    return nblks * get_page_size();
}

bool MetaBlkMgr::compress_feature_on() const { return HS_DYNAMIC_CONFIG(metablk.compress_feature_on); }

uint64_t MetaBlkMgr::get_min_compress_size() const {
    return HS_DYNAMIC_CONFIG(metablk.min_compress_size_mb) * static_cast< uint64_t >(1024) * 1024;
}

uint64_t MetaBlkMgr::get_max_compress_memory_size() const {
    return HS_DYNAMIC_CONFIG(metablk.max_compress_memory_size_mb) * static_cast< uint64_t >(1024) * 1024;
}

uint64_t MetaBlkMgr::get_init_compress_memory_size() const {
    return HS_DYNAMIC_CONFIG(metablk.init_compress_memory_size_mb) * static_cast< uint64_t >(1024) * 1024;
}

uint32_t MetaBlkMgr::get_compress_ratio_limit() const { return HS_DYNAMIC_CONFIG(metablk.compress_ratio_limit); }

uint64_t MetaBlkMgr::get_size() const { return m_sb_blk_store->get_size(); }

uint64_t MetaBlkMgr::get_used_size() const { return m_sb_blk_store->get_used_size(); }

uint32_t MetaBlkMgr::get_page_size() const { return m_sb_blk_store->get_page_size(); }
uint32_t MetaBlkMgr::get_align_size() const { return m_sb_blk_store->get_vdev()->get_align_size(); }

uint64_t MetaBlkMgr::get_available_blks() const { return m_sb_blk_store->get_available_blks(); }

bool MetaBlkMgr::m_self_recover{false};

//
// 1. Do sanity check on meta ssb on disk;
// 2. Can be called in both debug and release build;
//
bool MetaBlkMgr::ssb_sanity_check() const {
    if (!m_ssb || m_ssb->bid.is_valid() == false) {
        LOGERROR("Detected corrupted in-memory meta ssb: {}", m_ssb->to_string());
        HS_DBG_ASSERT_EQ(m_ssb->bid.is_valid(), true);
        return false;
    }

    auto ret{true};
    auto* const ssb_blk = reinterpret_cast< meta_blk_sb* >(
        hs_utils::iobuf_alloc(get_page_size(), sisl::buftag::metablk, get_align_size()));
    std::memset(static_cast< void* >(ssb_blk), 0, get_page_size());
    read(m_ssb->bid, static_cast< void* >(ssb_blk), get_page_size());

    HS_LOG_ASSERT_EQ(ssb_blk->magic, META_BLK_SB_MAGIC, "magic verify failed");
    HS_LOG_ASSERT_EQ(ssb_blk->version, META_BLK_SB_VERSION, "version verify failed");
    HS_LOG_ASSERT_EQ(ssb_blk->bid.to_integer(), m_ssb->bid.to_integer(), "self-bid verify failed");

    // in release build, log message and return failure to caller;
    if ((ssb_blk->magic != META_BLK_SB_MAGIC) || (ssb_blk->version != META_BLK_SB_VERSION) ||
        (ssb_blk->bid.to_integer() != m_ssb->bid.to_integer())) {
        ret = false;
    }

    hs_utils::iobuf_free(reinterpret_cast< uint8_t* >(ssb_blk), sisl::buftag::metablk);
    return ret;
}

//
// sanity check will block every operation into meta blk mgr as it takes the gloable lock;
//
// Can only be called in safe_mode, should not do release assert, but return failure to caller;
//
bool MetaBlkMgr::sanity_check(const bool check_ovf_chain) {
    HS_PERIODIC_LOG(INFO, metablk, "Sanity check started...");
    std::lock_guard< decltype(m_meta_mtx) > lg{m_meta_mtx};
    bool ret{true};
    // start from meta ssb;
    if (!ssb_sanity_check()) { return false; }

    // get total meta blks from cache, then compare it from the disk;
    uint32_t num_meta_blks_cached{0};
    for (auto& m : m_sub_info) {
        num_meta_blks_cached += m.second.meta_bids.size();
    }

    auto bid = m_ssb->next_bid;
    auto prev_bid = m_ssb->bid;
    uint32_t num_meta_blks_disk{0};
    std::unordered_set< std::string > clients;
    auto* const mblk =
        reinterpret_cast< meta_blk* >(hs_utils::iobuf_alloc(get_page_size(), sisl::buftag::metablk, get_align_size()));
    while (bid.is_valid()) {
        // reuse mblk for next;
        std::memset(static_cast< void* >(mblk), 0, get_page_size());

        ++num_meta_blks_disk;
        read(bid, static_cast< void* >(mblk), get_page_size());

        _cookie_sanity_check(static_cast< void* >(mblk));

        auto it = clients.find(mblk->hdr.h.type);
        if (it == clients.end()) { clients.insert(mblk->hdr.h.type); }

        // self-bid verify
        HS_LOG_ASSERT_EQ(mblk->hdr.h.bid.to_integer(), bid.to_integer(), "self-bid verify failed");
        // prev_bid verify
        HS_LOG_ASSERT_EQ(mblk->hdr.h.prev_bid.to_integer(), prev_bid.to_integer(), "prev_bid verify failed");
        if (mblk->hdr.h.bid.to_integer() != bid.to_integer() ||
            mblk->hdr.h.prev_bid.to_integer() != prev_bid.to_integer()) {
            ret = false;
            goto exit;
        }

        if (mblk->hdr.h.context_sz <= meta_blk_context_sz()) {
            HS_LOG_ASSERT_EQ(mblk->hdr.h.ovf_bid.is_valid(), false, "ovf_bid verify failed");
            if (mblk->hdr.h.ovf_bid.is_valid()) {
                ret = false;
                goto exit;
            }
        } else {
            // verify overflow blk
            auto obid = mblk->hdr.h.ovf_bid;
            HS_LOG_ASSERT_EQ(obid.is_valid(), true, "ovf_bid verify failed");
            if (obid.is_valid() == false) {
                ret = false;
                goto exit;
            }

            if (check_ovf_chain) {
                auto* ovf_hdr{reinterpret_cast< meta_blk_ovf_hdr* >(
                    hs_utils::iobuf_alloc(get_page_size(), sisl::buftag::metablk, get_align_size()))};
                while (obid.is_valid()) {
                    std::memset(static_cast< void* >(ovf_hdr), 0, get_page_size());
                    // read it out from disk;
                    read(obid, ovf_hdr, get_page_size());

                    // verify self bid
                    HS_LOG_ASSERT_EQ(ovf_hdr->h.bid.to_integer(), obid.to_integer(), "ovf self-bid verify failed");
                    // verify magic
                    HS_LOG_ASSERT_EQ(ovf_hdr->h.magic, META_BLK_OVF_MAGIC, "magic verify failed");
                    HS_LOG_ASSERT_NE(ovf_hdr->h.nbids, 0, "nbids verify failed");

                    if (ovf_hdr->h.bid.to_integer() != obid.to_integer() || ovf_hdr->h.magic != META_BLK_OVF_MAGIC ||
                        ovf_hdr->h.nbids == 0) {
                        hs_utils::iobuf_free(reinterpret_cast< uint8_t* >(ovf_hdr), sisl::buftag::metablk);
                        ret = false;
                        goto exit;
                    }

                    obid = ovf_hdr->h.next_bid;
                }

                hs_utils::iobuf_free(reinterpret_cast< uint8_t* >(ovf_hdr), sisl::buftag::metablk);
            }
        }

        prev_bid = bid;
        bid = mblk->hdr.h.next_bid;
    }

    HS_LOG_ASSERT_EQ(num_meta_blks_cached, num_meta_blks_disk, "Either memory is corrupted or disk is corrupted.");
    if (num_meta_blks_cached != num_meta_blks_disk) {
        ret = false;
        goto exit;
    }

    //
    // some clients might registered but not written any meta blk to disk, which is okay;
    // one case is create a volume, then delete a volume, then client: VOLUME will don't have any meta blk on disk;
    //
    HS_LOG_ASSERT_LE(clients.size(), m_sub_info.size(),
                     "client size on disk: {} is larger than registered: {}, which is not possible!", clients.size(),
                     m_sub_info.size());
    if (clients.size() > m_sub_info.size()) {
        ret = false;
        goto exit;
    }

exit:
    hs_utils::iobuf_free(reinterpret_cast< uint8_t* >(mblk), sisl::buftag::metablk);

    if (ret) {
        HS_PERIODIC_LOG(
            INFO, metablk,
            "Successfully passed sanity check. Total metablks scaned: {}, total clients on disk: {}, total registered "
            "clients: {}",
            num_meta_blks_disk, clients.size(), m_sub_info.size());
    }

    return ret;
}

//
// dump meta blks from cache;
//
// Note: get_status can be called in release build, should never hit any release assert failure, instead should print
// error log and return to caller with error message
//
nlohmann::json MetaBlkMgr::get_status(const int log_level) {
    LOGINFO("Gettting status with log_level: {}", log_level);
    std::string dummy_client;
    return populate_json(log_level, m_meta_blks, m_ovf_blk_hdrs, m_last_mblk_id.get(), m_sub_info, m_self_recover,
                         dummy_client);
}

nlohmann::json MetaBlkMgr::populate_json(const int log_level, meta_blk_map_t& meta_blks, ovf_hdr_map_t& ovf_blk_hdrs,
                                         BlkId* last_mblk_id, client_info_map_t& sub_info, const bool self_recover,
                                         const std::string& client) {
    std::string dump_dir = "/tmp/dump_meta";
    bool can_dump_to_file = false;
    const uint64_t total_free = 0;
    uint64_t free_space = 0;
    if (log_level >= 3) {
        // clear dump directory if it is already there;
        std::filesystem::path dump_path = dump_dir;
        if (std::filesystem::exists(dump_path)) {
            LOGINFO("Removing old dump dir: {}", dump_dir);
            std::filesystem::remove_all(dump_path);
        }
        std::filesystem::create_directory(dump_path);

        // check remaining space on root fs;
        std::error_code ec;
        const std::filesystem::space_info si = std::filesystem::space(dump_dir, ec);
        if (ec.value()) {
            LOGINFO("Error getting space for dir={}, error={}, skip dumping to file", dump_dir, ec.message());
        } else {
            // Don't use more than configured percentage of free space of root;
            free_space = static_cast< uint64_t >(std::min(si.free, si.available) *
                                                 HS_DYNAMIC_CONFIG(metablk.percent_of_free_space) / 100);
            can_dump_to_file = true;
        }
    }

    nlohmann::json j;

    {
        std::lock_guard< decltype(m_meta_mtx) > lg{m_meta_mtx};
        j["ssb"] = m_ssb ? m_ssb->to_string() : "";
        j["self_recovery"] = self_recover;

        for (auto& x : sub_info) {
            // if client is empty, will dump all the clients;
            // if client is not empty, only dump this client;
            if (!client.empty() && client.compare(x.first)) { continue; }

            j[x.first]["type"] = x.first;
            j[x.first]["do_crc"] = x.second.do_crc;
            j[x.first]["cb"] = x.second.cb ? "registered valid cb" : "nullptr";
            j[x.first]["comp_cb"] = x.second.comp_cb ? "registered valid cb" : "nullptr";
            j[x.first]["num_meta_bids"] = x.second.meta_bids.size();
            if (log_level >= 2 && log_level <= 3) {
                size_t bid_cnt{0};
                for (const auto& y : x.second.meta_bids) {
                    BlkId bid(y);
                    if (log_level == 2) {
                        // dump bid if log level is 2 or dump to file is not possible;
                        j[x.first]["meta_bids"][std::to_string(bid_cnt)] = bid.to_string();
                    } else if (can_dump_to_file) { // log_level >= 3 and can dump to file
                        // dump the whole data buffer to file
                        auto it = meta_blks.find(y);

                        HS_DBG_ASSERT_EQ(it != meta_blks.end(), true,
                                         "Expecting meta_bid: {} to be found in meta blks cache. Corruption detected!",
                                         bid.to_string());

                        // in release build, print error and continue to next;
                        if (it == meta_blks.end()) {
                            LOGERROR("bid: {} not found in meta blk cache, corruption detected!", y);
                            continue;
                        }

                        sisl::byte_array buf = read_sub_sb_internal(it->second);
                        if (free_space < buf->size) {
                            j[x.first]["meta_bids"][std::to_string(bid_cnt)] =
                                "Not_able_to_dump_to_file_exceeding_allowed_space";
                            HS_LOG_EVERY_N(
                                WARN, metablk, 100,
                                "[type={}] Skip dumping to file, exceeding allowed space: {}, requested_size: {}, "
                                "total_free: {}, free_fs_percent: {}",
                                x.first, free_space, buf->size, total_free,
                                HS_DYNAMIC_CONFIG(metablk.percent_of_free_space));
                            continue;
                        }

                        const std::string file_path{fmt::format("{}/{}_{}", dump_dir, x.first, bid_cnt)};
                        std::ofstream f{file_path};
                        f.write(reinterpret_cast< const char* >(buf->bytes), buf->size);
                        j[x.first]["meta_bids"][std::to_string(bid_cnt)] = file_path;

                        free_space -= buf->size;
                    }

                    ++bid_cnt;
                }
            }
        }

        j["last_mid"] = last_mblk_id->to_string();

        j["compression"] = compress_feature_on() ? "On" : "Off";
    }

    return j;
}

// sanity_check can only be called in PRERELEASE mode, which can hit release assert;
bool MetaBlkMgr::verify_metablk_store() { return sanity_check(true /* check_ovf_chain */); }

//
// Precondidtion:
// 1. m_ssb should be ready
// 2. m_blkstore should be ready to serve I/O;
//
// Requirement:
// 1. Leave the existing in-memory copy unchanged;
// 2. Can be called in release build, should never hit any release assert failure, instead should print
// error log and return to caller with error message
//
nlohmann::json MetaBlkMgr::dump_disk_metablks(const std::string& client) {
    // 0. verify m_ssb;
    {
        std::lock_guard< decltype(m_meta_mtx) > lg{m_meta_mtx};
        nlohmann::json j;
        if (!m_ssb) {
            LOGERROR("Can't serve this request, meta ssb is nullptr.");
            return j;
        }

        if ((m_ssb->magic != META_BLK_SB_MAGIC) || (m_ssb->version != META_BLK_SB_VERSION) ||
            (m_ssb->bid.is_valid() == false)) {
            LOGERROR("Can't serve this request, in-memory meta ssb is not valid, : magic: {}, version: {}, "
                     "self_bid: {}",
                     m_ssb->magic, m_ssb->version, m_ssb->bid.to_integer());
            return j;
        }
    }

    // 1. scan and load from disk to memory;
    auto last_bid = std::make_unique< BlkId >();
    meta_blk_map_t meta_blks;
    ovf_hdr_map_t ovf_blk_hdrs;
    std::map< meta_sub_type, MetaSubRegInfo > sub_info;

    const auto self_recover = scan_and_load_meta_blks(meta_blks, ovf_blk_hdrs, last_bid.get(), sub_info);

    const auto j = populate_json(3, meta_blks, ovf_blk_hdrs, last_bid.get(), sub_info, self_recover, client);

    for (auto it{std::cbegin(meta_blks)}; it != std::cend(meta_blks); ++it) {
        hs_utils::iobuf_free(reinterpret_cast< uint8_t* >(it->second), sisl::buftag::metablk);
    }

    for (auto it{std::cbegin(ovf_blk_hdrs)}; it != std::cend(ovf_blk_hdrs); ++it) {
        hs_utils::iobuf_free(reinterpret_cast< uint8_t* >(it->second), sisl::buftag::metablk);
    }

    meta_blks.clear();
    ovf_blk_hdrs.clear();
    sub_info.clear();

    return j;
}

} // namespace homestore
