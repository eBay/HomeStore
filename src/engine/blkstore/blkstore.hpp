//
// Created by Kadayam, Hari on 15/11/17.
//

#ifndef OMSTORE_BLKSTORE_HPP
#define OMSTORE_BLKSTORE_HPP

#include "engine/cache/cache.h"
#include "engine/device/device_selector.hpp"
#include "engine/device/device.h"
#include <boost/optional.hpp>
#include "engine/device/virtual_dev.hpp"
#include "engine/homeds/memory/mempiece.hpp"
#include "engine/cache/cache.cpp"
#include "engine/common/error.h"
//#include "writeBack_cache.hpp"
#include "engine/device/blkbuffer.hpp"
#include "engine/common/homestore_config.hpp"
#include <utility/atomic_counter.hpp>
#include <fds/utils.hpp>

namespace homestore {

enum BlkStoreCacheType { PASS_THRU = 0, WRITEBACK_CACHE = 1, WRITETHRU_CACHE = 2, RD_MODIFY_WRITEBACK_CACHE = 3 };

/* Threshold of size upto when there is overlap in the cache entry, that it will discard instead of copying. Say
 * there is a buffer of size 64K, out of which first N bytes are freed, then remaining bytes 64K - N bytes could
 * be either be discarded or copied into new buffer. This threshold dictates whats the value of (64K - N) upto which
 * it will copy. In other words ((64K - N) <= CACHE_DISCARD_THRESHOLD_SIZE) ? copy : discard
 */
//#define CACHE_DISCARD_THRESHOLD_SIZE 16384

class BlkStoreConfig {
public:
    /* Total size of BlkStore inital, it could grow based on demand. */
    uint64_t m_initial_size;

    /* Type of cache to use. */
    BlkStoreCacheType m_cache_type;

    /* Mirrored copy to maintain within this block store. */
    uint32_t m_nmirrors;
};

struct bufferInfo {
    uint32_t offset;
    uint32_t size;
    uint8_t* ptr;
    bufferInfo() : offset(0), size(0), ptr(nullptr){};
    bufferInfo(uint32_t offset, uint32_t size, uint8_t* ptr) : offset(offset), size(size), ptr(ptr){};
};

#define to_blkstore_req(req) boost::static_pointer_cast< blkstore_req< Buffer > >(req)

template < typename Buffer = BlkBuffer >
struct blkstore_req : public virtualdev_req {
    boost::intrusive_ptr< Buffer > bbuf;
    BlkId bid;
    sisl::atomic_counter< int > blkstore_ref_cnt; /* It is used for reads to see how many
                                                   * reads are issued for this request.
                                                   * Blkstore calls comp upcall
                                                   * only when ref_cnt becomes zero.
                                                   */
    std::vector< bufferInfo > missing_pieces;
    uint32_t data_offset;
    Clock::time_point blkstore_op_start_time;

public:
    virtual ~blkstore_req() {
        assert(missing_pieces.size() == 0);
        assert(blkstore_ref_cnt.testz());
    };

    static boost::intrusive_ptr< blkstore_req< Buffer > > make_request() {
        return boost::intrusive_ptr< blkstore_req< Buffer > >(
            sisl::ObjectAllocator< blkstore_req< Buffer > >::make_object());
    }

    bool is_blk_from_cache(uint32_t offset) {
        for (uint32_t i = 0; i < missing_pieces.size(); ++i) {
            if (offset >= missing_pieces[i].offset && offset < missing_pieces[i].offset + size) { return true; }
        }
        return false;
    }

    void start_time() { blkstore_op_start_time = Clock::now(); }

    virtual void free_yourself() { sisl::ObjectAllocator< blkstore_req< Buffer > >::deallocate(this); }

protected:
    friend class sisl::ObjectAllocator< blkstore_req< Buffer > >;
    blkstore_req() : bbuf(nullptr), blkstore_ref_cnt(0), missing_pieces(0), data_offset(0){};
};

class BlkStoreMetrics : public sisl::MetricsGroupWrapper {
public:
    explicit BlkStoreMetrics(const char* inst_name) : sisl::MetricsGroupWrapper("BlkStore", inst_name) {
        REGISTER_COUNTER(blkstore_read_op_count, "BlkStore total read ops", "blkstore_op_count", {"op", "read"});
        REGISTER_COUNTER(blkstore_write_op_count, "BlkStore total write ops", "blkstore_op_count", {"op", "write"});
        REGISTER_COUNTER(blkstore_read_data_size, "BlkStore number of bytes read");
        REGISTER_COUNTER(blkstore_cache_miss_size, "BlkStore number of bytes cache miss");
        REGISTER_COUNTER(blkstore_drive_read_count, "Number of drive reads by blkstore");
        REGISTER_COUNTER(blkstore_wbcache_write_count, "Number of writes written to writeback cache");
        REGISTER_COUNTER(blkstore_outstanding_reads, "Outstanding Read IOs at a given point",
                         sisl::_publish_as::publish_as_gauge);
        REGISTER_COUNTER(blkstore_outstanding_writes, "Outstanding Write IOs at a given point",
                         sisl::_publish_as::publish_as_gauge);

        REGISTER_HISTOGRAM(blkstore_partial_cache_distribution, "Partial cache hit ops distribution",
                           HistogramBucketsType(LinearUpto64Buckets))
        REGISTER_HISTOGRAM(blkstore_cache_read_latency, "BlkStore cache read latency");
        REGISTER_HISTOGRAM(blkstore_cache_write_latency, "BlkStore cache write latency");
        REGISTER_HISTOGRAM(blkstore_drive_write_latency, "BlkStore drive write latency");
        REGISTER_HISTOGRAM(blkstore_drive_read_latency, "BlkStore drive read latency");
        REGISTER_HISTOGRAM(blkstore_wbcache_hold_time, "Time data is held in writeback cache before flush");

        register_me_to_farm();
    }
};

template < typename BAllocator, typename Buffer = BlkBuffer >
class BlkStore {
public:
    typedef std::function< void(boost::intrusive_ptr< blkstore_req< Buffer > > req) > comp_callback;

    BlkStore(DeviceManager* mgr,           // Device manager instance
             Cache< BlkId >* cache,        // Cache Instance
             uint64_t size,                // Size of the blk store device
             BlkStoreCacheType cache_type, // Type of cache, writeback, writethru, none
             uint32_t mirrors,             // Number of mirrors
             char* blob,                   // Superblock blob for blkstore
             uint64_t context_size,        // TODO: ???
             uint64_t page_size,           // Block device page size
             const char* name,             // Name for blkstore
             bool auto_recovery,
             comp_callback comp_cb = nullptr // Callback on completion. It can be attached later as well.
             ) :
            m_pagesz(page_size),
            m_cache(cache),
            m_cache_type(cache_type),
            m_vdev(mgr, context_size, mirrors, true, m_pagesz, mgr->get_all_devices(),
                   (std::bind(&BlkStore::process_completions, this, std::placeholders::_1)), blob, size, auto_recovery),
            m_comp_cb(comp_cb),
            m_metrics(name) {}

    BlkStore(DeviceManager* mgr,           // Device manager instance
             Cache< BlkId >* cache,        // Cache Instance
             vdev_info_block* vb,          // Load vdev from this vdev_info_block
             BlkStoreCacheType cache_type, // Type of cache, writeback, writethru, none
             uint64_t page_size,           // Block device page size
             const char* name,             // Name for blkstore
             bool recovery_init,           // do we need to initialize blk allocator in recovery
             bool auto_recovery,
             comp_callback comp_cb = nullptr // Callback on completion. It can be attached later as well.
             ) :
            m_pagesz(page_size),
            m_cache(cache),
            m_cache_type(cache_type),
            m_vdev(mgr, vb, (std::bind(&BlkStore::process_completions, this, std::placeholders::_1)), recovery_init,
                   auto_recovery),
            m_comp_cb(comp_cb),
            m_metrics(name) {}

    ~BlkStore() = default;

    void attach_compl(comp_callback comp_cb) { m_comp_cb = comp_cb; }

    bool is_read_modify_cache() { return (m_cache_type == RD_MODIFY_WRITEBACK_CACHE); }

    void process_completions(boost::intrusive_ptr< virtualdev_req > v_req) {
        auto req = to_blkstore_req(v_req);

        if (!req->is_read) {
#ifdef _PRERELEASE
            if (auto flip_ret = homestore_flip->get_test_flip< int >("delay_us_and_inject_error_on_completion",
                                                                     v_req->request_id)) {
                usleep(flip_ret.get());
                req->err = homestore_error::write_failed;
            }
#endif
            HISTOGRAM_OBSERVE(m_metrics, blkstore_drive_write_latency,
                              get_elapsed_time_us(req->blkstore_op_start_time));
            m_comp_cb(req);
            return;
        }

        if (!req->blkstore_ref_cnt.decrement_testz(1)) { return; }
        HISTOGRAM_OBSERVE(m_metrics, blkstore_drive_read_latency, get_elapsed_time_us(req->blkstore_op_start_time));

        /* all buffers are read when ref_cnt becomes zero. It means
         * it is safe to do completion upcall and update cache.
         */
        if (req->err == no_error) {
            update_cache(req);
        } else {
            /* TODO add error messages */
            for (uint32_t i = 0; i < req->missing_pieces.size(); i++) {
                free(req->missing_pieces[i].ptr);
            }
        }

        m_comp_cb(req);
        req->missing_pieces.clear();
    }

    void update_cache(boost::intrusive_ptr< blkstore_req< Buffer > > req) {
        Clock::time_point start_time = Clock::now();

        for (uint32_t i = 0; i < req->missing_pieces.size(); i++) {
            boost::intrusive_ptr< Buffer > bbuf = req->bbuf;

            bool inserted = bbuf->update_missing_piece(req->missing_pieces[i].offset, req->missing_pieces[i].size,
                                                       req->missing_pieces[i].ptr);
            if (!inserted) {
                /* someone else has inserted it */
                free(req->missing_pieces[i].ptr);
            }
        }
        HISTOGRAM_OBSERVE(m_metrics, blkstore_cache_read_latency, get_elapsed_time_us(start_time));
    }

    /* Allocate a new block of the size based on the hints provided */
    BlkAllocStatus alloc_blk(uint32_t size, blk_alloc_hints& hints, std::vector< BlkId >& out_blkid) {
        // Allocate a block from the device manager
        assert(size % m_pagesz == 0);
        auto nblks = size / m_pagesz;
        return (m_vdev.alloc_blk(nblks, hints, out_blkid));
    }

    BlkAllocStatus alloc_blk(BlkId& in_blkid) { return (m_vdev.alloc_blk(in_blkid)); }

    BlkAllocStatus alloc_blk(uint32_t size, blk_alloc_hints& hints, BlkId* out_blkid) {
        // Allocate a block from the device manager
        assert(size % m_pagesz == 0);
        auto nblks = size / m_pagesz;
        hints.is_contiguous = true;
        return (m_vdev.alloc_blk(nblks, hints, out_blkid));
    }

    /* Allocate a new block and add entry to the cache. This method allows the caller to create its own
     * buffer method, but the actual data is page aligned is created by this method and returns the smart pointer
     * of the buffer, along with blkid. */
    boost::intrusive_ptr< Buffer > alloc_blk_cached(uint32_t size, blk_alloc_hints& hints, BlkId* out_blkid) {
        // Allocate a block from the device manager
        hints.is_contiguous = true;
        assert(size % m_pagesz == 0);
        auto ret_blk = alloc_blk(size, hints, out_blkid);
        if (ret_blk != BLK_ALLOC_SUCCESS) { return nullptr; }

        // Create an object for the buffer
        auto buf = Buffer::make_object();
        buf->set_key(*out_blkid);

        // Create a new block of memory for the blocks requested and set the memvec pointer to that
        uint8_t* ptr = iomanager.iobuf_alloc(HS_STATIC_CONFIG(disk_attr.align_size), size);
        boost::intrusive_ptr< homeds::MemVector > mvec(new homeds::MemVector(), true);
        mvec->set(ptr, size, 0);

        buf->set_memvec(mvec, 0, out_blkid->data_size(m_pagesz));
        // Insert this buffer to the cache.
        auto ibuf = boost::intrusive_ptr< Buffer >(buf);
        boost::intrusive_ptr< Buffer > out_bbuf;
        bool inserted = m_cache->insert(*out_blkid, boost::static_pointer_cast< CacheBuffer< BlkId > >(ibuf),
                                        (boost::intrusive_ptr< CacheBuffer< BlkId > >*)&out_bbuf);
        assert(inserted);

        return ibuf;
    }

    void cache_buf_erase_cb(boost::intrusive_ptr< Buffer > erased_buf, const BlkId bid) {
        assert(is_read_modify_cache());
        m_vdev.free_blk(bid);
        return;
    }

    /* Free the block previously allocated. Blkoffset refers to number of blks to skip in the BlkId and
     * nblks refer to the total blks from offset to free.
     */
    void free_blk(const BlkId& bid, boost::optional< uint32_t > size_offset, boost::optional< uint32_t > size,
                  bool in_cache = true) {

        boost::intrusive_ptr< Buffer > erased_buf(nullptr);

        assert(bid.data_size(m_pagesz) >= (size_offset.get_value_or(0) + size.get_value_or(0)));

        uint32_t free_size;
        if (size.get_value_or(0) != 0) {
            free_size = size.get_value_or(0);
        } else {
            free_size = bid.data_size(m_pagesz);
        }

        /* We don't call safe erase as we depend on the consumer to free the blkid then no body
         * is accessing it.
         */
#if 0
        if (is_read_modify_cache()) {
            assert(size_offset.get_value_or(0) == 0 && free_size == bid.data_size(m_pagesz));
            m_cache->safe_erase(bid, [this, bid](boost::intrusive_ptr< CacheBuffer< BlkId > > erased_buf) {
                this->cache_buf_erase_cb(boost::static_pointer_cast< Buffer >(erased_buf), bid);
            });
            /* cache will raise callback when ref_cnt becomes zero */
            return;
        } else {
#endif
        m_cache->erase(bid, size_offset.get_value_or(0), free_size,
                       (boost::intrusive_ptr< CacheBuffer< BlkId > >*)&erased_buf);
        if (in_cache) { return; }

        uint32_t offset = size_offset.get_value_or(0);
        BlkId tmp_bid(bid.get_blkid_at(offset, free_size, m_pagesz));
        m_vdev.free_blk(tmp_bid);
        return;
    }

    void write(BlkId& bid, homeds::MemVector& mvec) { m_vdev.write(bid, mvec, nullptr, 0); }

    //
    // sync write with iov;
    //
    void write(BlkId& bid, struct iovec* iov, int iovcnt) { m_vdev.write(bid, iov, iovcnt); }

    /* Write the buffer. The BlkStore write does not support write in place and so it does not also support
     * writing to an offset.
     *
     * NOTE: While one could argue that even when it is not doing write in place it could still
     * create a new blkid and then write it on an offset from the blkid. So far there is no use case for that. To
     * avoid any confusion to the interface, the value_offset parameter is not provided for this write type. If
     * needed can be added later.
     * Here data_offset is offset inside memvec. If a write is split then both the writes will point to
     * same buffer but different offsets.
     */
    boost::intrusive_ptr< Buffer > write(BlkId& bid, boost::intrusive_ptr< homeds::MemVector > mvec, int data_offset,
                                         boost::intrusive_ptr< blkstore_req< Buffer > > req, bool in_cache) {
        if (in_cache) {
            /* TODO: add try and catch exception */
            auto buf = Buffer::make_object();
            buf->set_key(bid);
            buf->set_memvec(mvec, data_offset, bid.data_size(m_pagesz));
            auto ibuf = boost::intrusive_ptr< Buffer >(buf);
            req->bid = bid;

            /*
             * First try to create/insert a record for this blk id in the cache.
             * If it already exists, it will simply upvote the item.
             */
            COUNTER_INCREMENT(m_metrics, blkstore_write_op_count, 1);

            CURRENT_CLOCK(cache_start_time);
            uint8_t* ptr;

            // Insert this buffer to the cache.
            boost::intrusive_ptr< Buffer > out_bbuf;

            bool inserted = m_cache->insert(bid, boost::static_pointer_cast< CacheBuffer< BlkId > >(ibuf),
                                            (boost::intrusive_ptr< CacheBuffer< BlkId > >*)&out_bbuf);
            /* While writing, we should not insert a blkid which already exist in the cache */
            assert(ibuf.get() == out_bbuf.get());
            assert(inserted);
            HISTOGRAM_OBSERVE(m_metrics, blkstore_cache_write_latency, get_elapsed_time_us(cache_start_time));

            req->bbuf = ibuf;
        }

        // Now write data to the device
        req->start_time();
        m_vdev.write(bid, *(mvec.get()), to_vdev_req(req), data_offset);
        if (req->isSyncCall) {
            HISTOGRAM_OBSERVE(m_metrics, blkstore_drive_write_latency,
                              get_elapsed_time_us(req->blkstore_op_start_time));
        }
        return req->bbuf;
    }

    /* Read the data for given blk id and size. This method allocates the required memory if not present in the
     * cache and returns an smart ptr to the Buffer */
    boost::intrusive_ptr< Buffer > read(BlkId& bid, uint32_t offset, uint32_t size,
                                        boost::intrusive_ptr< blkstore_req< Buffer > > req) {

        int cur_ind = 0;
        uint32_t cur_offset = offset;

        assert(req->err == no_error);

        COUNTER_INCREMENT(m_metrics, blkstore_read_op_count, 1);
        COUNTER_INCREMENT(m_metrics, blkstore_read_data_size, size);

        req->start_time();
        // Check if the entry exists in the cache.
        boost::intrusive_ptr< Buffer > bbuf;
        bool cache_found = m_cache->get(bid, (boost::intrusive_ptr< CacheBuffer< BlkId > >*)&bbuf);
        req->blkstore_ref_cnt.increment(1);
        if (!cache_found
#ifdef _PRERELEASE
            || (cache_found && (homestore_flip->test_flip("cache_insert_race")))
#endif
        ) {
            // Not found in cache, create a new block buf and prepare it for insert to dev and cache.
            bbuf = Buffer::make_object();

            /* set the key */
            bbuf->set_key(bid);

            /* set the memvec */
            boost::intrusive_ptr< homeds::MemVector > mvec(new homeds::MemVector());
            bbuf->set_memvec(mvec, 0, 0);

            /* insert it into cache */
            boost::intrusive_ptr< Buffer > new_bbuf;
            bool inserted = m_cache->insert(bbuf->get_key(), boost::static_pointer_cast< CacheBuffer< BlkId > >(bbuf),
                                            (boost::intrusive_ptr< CacheBuffer< BlkId > >*)&new_bbuf);
            if (!inserted) {
                /* Between get and insert, other thread tried the same thing and
                 * inserted into the cache. Lets use that entry in cache and
                 * free up the memory
                 */
                bbuf = new_bbuf;
            }
        }

        req->bbuf = bbuf;
        req->is_read = true;

        /* first is offset and second is size in a pair */
        vector< std::pair< uint32_t, uint32_t > > missing_mp;
        assert(bid.data_size(m_pagesz) >= (offset + size));
        bool ret = m_cache->insert_missing_pieces(bbuf, offset, size, missing_mp);
        BlkId read_blkid(bid.get_blkid_at(offset, size, m_pagesz));

        /* It might be a false assert if there is a race between read and write but keeping
         * it for now as it can be good check to see that we have recovered all the blocks
         * after boot.
         */
        assert(m_vdev.is_blk_alloced(read_blkid));

        if (missing_mp.size()) {
            HISTOGRAM_OBSERVE(m_metrics, blkstore_partial_cache_distribution, missing_mp.size());
            COUNTER_INCREMENT(m_metrics, blkstore_drive_read_count, missing_mp.size());
        }

        uint8_t* ptr;
        for (uint32_t i = 0; i < missing_mp.size(); i++) {

            // Create a new block of memory for the missing piece
            uint8_t* ptr = iomanager.iobuf_alloc(HS_STATIC_CONFIG(disk_attr.align_size), missing_mp[i].second);

            int64_t sz = (int64_t)missing_mp[i].second;
            COUNTER_INCREMENT(m_metrics, blkstore_cache_miss_size, sz);

            // Read the missing piece from the device
            BlkId tmp_bid(bid.get_blkid_at(missing_mp[i].first, missing_mp[i].second, m_pagesz));

            req->blkstore_ref_cnt.increment(1);
            homeds::MemPiece mp(ptr, missing_mp[i].second, 0);

            if (!req->isSyncCall) {
                bufferInfo missing_piece(missing_mp[i].first, missing_mp[i].second, ptr);
                /* insert it into cache after missing_piece is read */
                req->missing_pieces.push_back(missing_piece);
            }

            m_vdev.read(tmp_bid, mp, to_vdev_req(req));
            if (req->isSyncCall) {
                bool inserted = bbuf->update_missing_piece(missing_mp[i].first, missing_mp[i].second, ptr);
                if (!inserted) {
                    /* someone else has inserted it */
                    free(ptr);
                }
                req->blkstore_ref_cnt.decrement(1);
            }
        }

        assert(req->err == no_error);
        if (!req->isSyncCall) {
            /* issue the completion */
            process_completions(to_vdev_req(req));
        } else {
            req->blkstore_ref_cnt.decrement(1);
            HISTOGRAM_OBSERVE(m_metrics, blkstore_drive_read_latency, get_elapsed_time_us(req->blkstore_op_start_time));
        }
        return bbuf;
    }

    std::vector< boost::intrusive_ptr< BlkBuffer > > read_nmirror(BlkId& bid, int nmirrors) {
        std::vector< boost::intrusive_ptr< BlkBuffer > > buf_list;
        std::vector< boost::intrusive_ptr< homeds::MemVector > > mp;
        uint8_t* mem_ptr = nullptr;

        for (int i = 0; i < (nmirrors + 1); i++) {
            /* create the pointer */
            uint8_t* mem_ptr = iomanager.iobuf_alloc(HS_STATIC_CONFIG(disk_attr.align_size), bid.data_size(m_pagesz));

            /* set the memvec */
            boost::intrusive_ptr< homeds::MemVector > mvec(new homeds::MemVector());
            mvec->set(mem_ptr, bid.data_size(m_pagesz), 0);

            /* create the buffer */
            auto bbuf = Buffer::make_object();
            bbuf->set_memvec(mvec, 0, bid.data_size(m_pagesz));

            buf_list.push_back(bbuf);
            mp.push_back(mvec);
        }
        m_vdev.read_nmirror(bid, mp, bid.data_size(m_pagesz), nmirrors);
        return buf_list;
    }

    void blkalloc_cp_start(std::shared_ptr< blkalloc_cp_id > id) { m_vdev.blkalloc_cp_start(id); }
    void reset_vdev_failed_state() { m_vdev.reset_failed_state(); }

    uint64_t get_size() const { return m_vdev.get_size(); }

    /* This api is very expensive api as it goes through the entire bitmap */
    uint64_t get_used_size() const { return m_vdev.get_used_size(); }

    void update_vb_context(const sisl::blob& ctx_data) { m_vdev.update_vb_context(ctx_data); }

    void get_vb_context(const sisl::blob& ctx_data) const { m_vdev.get_vb_context(ctx_data); }

    VirtualDev< BAllocator, RoundRobinDeviceSelector >* get_vdev() { return &m_vdev; };

    off_t alloc_blk(size_t size, bool chunk_overlap_ok = false) { return m_vdev.alloc_blk(size, chunk_overlap_ok); }

    ssize_t pwrite(const void* buf, size_t count, off_t offset, boost::intrusive_ptr< virtualdev_req > req = nullptr) {
        return m_vdev.pwrite(buf, count, offset, req);
    }

    ssize_t pread(void* buf, size_t count, off_t offset) { return m_vdev.pread(buf, count, offset); }

    off_t lseek(off_t offset, int whence = SEEK_SET) { return m_vdev.lseek(offset, whence); }

    off_t seeked_pos() const { return m_vdev.seeked_pos(); }

    ssize_t read(void* buf, size_t count) { return m_vdev.read(buf, count); }

    ssize_t write(const void* buf, size_t count) { return m_vdev.write(buf, count); }

    ssize_t write(const void* buf, size_t count, boost::intrusive_ptr< virtualdev_req > req) {
        return m_vdev.write(buf, count, req);
    }

    ssize_t preadv(const struct iovec* iov, int iovcnt, off_t offset,
                   boost::intrusive_ptr< virtualdev_req > req = nullptr) {
        return m_vdev.preadv(iov, iovcnt, offset, req);
    }

    ssize_t pwritev(const struct iovec* iov, int iovcnt, off_t offset,
                    boost::intrusive_ptr< virtualdev_req > req = nullptr) {
        return m_vdev.pwritev(iov, iovcnt, offset, req);
    }

    uint64_t get_used_space() const { return m_vdev.get_used_space(); }

    off_t get_start_offset() const { return m_vdev.data_start_offset(); }

    off_t get_tail_offset() const { return m_vdev.get_tail_offset(); }

    void read(const uint64_t offset, const uint64_t size, const void* buf) { m_vdev.read(offset, size, buf); }

    void readv(const uint64_t offset, struct iovec* iov, int iovcnt) { m_vdev.readv(offset, iov, iovcnt); }

    void update_tail_offset(const off_t tail) { m_vdev.update_tail_offset(tail); }

    void truncate(const off_t offset) { m_vdev.truncate(offset); }
    void recovery_done() { m_vdev.recovery_done(); }
    std::shared_ptr< blkalloc_cp_id > attach_prepare_cp(std::shared_ptr< blkalloc_cp_id > cur_cp_id) {
        return (m_vdev.attach_prepare_cp(cur_cp_id));
    }

private:
    uint32_t m_pagesz;
    Cache< BlkId >* m_cache;
    BlkStoreCacheType m_cache_type;
    VirtualDev< BAllocator, RoundRobinDeviceSelector > m_vdev;
    comp_callback m_comp_cb;
    BlkStoreMetrics m_metrics;
};
} // namespace homestore
#endif // OMSTORE_BLKSTORE_HPP
