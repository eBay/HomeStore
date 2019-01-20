//
// Created by Kadayam, Hari on 15/11/17.
//

#ifndef OMSTORE_BLKSTORE_HPP
#define OMSTORE_BLKSTORE_HPP

#include "cache/cache.h"
#include "device/device_selector.hpp"
#include "device/device.h"
#include <boost/optional.hpp>
#include "homeds/memory/mempiece.hpp"
#include "cache/cache.cpp"
#include <error/error.h>
#include "writeBack_cache.hpp"
#include "device/blkbuffer.hpp"
#include "main/homestore_config.hpp"

namespace homestore {

enum BlkStoreCacheType {
    PASS_THRU = 0,
    WRITEBACK_CACHE = 1,
    WRITETHRU_CACHE = 2,
    RD_MODIFY_WRITEBACK_CACHE = 3
};

/* Threshold of size upto when there is overlap in the cache entry, that it will discard instead of copying. Say
 * there is a buffer of size 64K, out of which first N bytes are freed, then remaining bytes 64K - N bytes could
 * be either be discarded or copied into new buffer. This threshold dictates whats the value of (64K - N) upto which
 * it will copy. In other words ((64K - N) <= CACHE_DISCARD_THRESHOLD_SIZE) ? copy : discard
 */
#define CACHE_DISCARD_THRESHOLD_SIZE  16384

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
    uint8_t *ptr;
    bufferInfo() : offset(0), size(0), ptr(nullptr) {};
    bufferInfo(uint32_t offset, uint32_t size, uint8_t *ptr) : offset(offset), 
                    size(size), ptr(ptr) {};
};
template <typename Buffer = BlkBuffer>
struct blkstore_req : writeback_req { 
    boost::intrusive_ptr< Buffer > bbuf;
    BlkId bid;
    std::atomic<int> blkstore_ref_cnt; /* It is used for reads to see how many
                                        * reads are issued for this request.
                                        * Blkstore calls comp upcall
                                        * only when ref_cnt becomes zero.
                                        */
    bool is_read;
    std::vector<bufferInfo> missing_pieces;
    uint32_t data_offset;
    blkstore_req(): bbuf(nullptr), blkstore_ref_cnt(0), is_read(false), 
                    missing_pieces(0), data_offset(0) {};
    virtual ~blkstore_req() {
        assert(missing_pieces.size() == 0);
        assert(blkstore_ref_cnt.load() == 0);
    };
};

class BlkStoreMetrics : public sisl::MetricsGroupWrapper {
public:
    explicit BlkStoreMetrics(const char *grp_name) : sisl::MetricsGroupWrapper(grp_name) {
        REGISTER_COUNTER(blkstore_reads_count, "BlkStore total reads");
        REGISTER_COUNTER(blkstore_writes_count, "BlkStore total writes");
        REGISTER_COUNTER(blkstore_cache_hits_count, "BlkStore Cache hits");
        REGISTER_COUNTER(blkstore_outstanding_reads, "Outstanding Read IOs at a given point", "",
                         sisl::_publish_as::publish_as_gauge);
        REGISTER_COUNTER(blkstore_outstanding_writes, "Outstanding Write IOs at a given point", "",
                         sisl::_publish_as::publish_as_gauge);

        REGISTER_HISTOGRAM(blkstore_cache_read_latency, "BlkStore cache read latency");
        REGISTER_HISTOGRAM(blkstore_cache_write_latency, "BlkStore cache write latency");
        REGISTER_HISTOGRAM(blkstore_drive_write_latency, "BlkStore driver write latency");

        register_me_to_farm();
    }
};

template <typename BAllocator, typename Buffer = BlkBuffer>
class BlkStore {
    typedef std::function< void (boost::intrusive_ptr<blkstore_req<Buffer>> req) > comp_callback;

public:
    BlkStore(DeviceManager *mgr, Cache< BlkId > *cache, uint64_t size, BlkStoreCacheType cache_type,
             uint32_t mirrors, comp_callback comp_cb, char *blob, uint64_t context_size, uint64_t page_size) :
            m_pagesz(page_size),
            m_cache(cache),
            m_wb_cache(cache, ([this] (boost::intrusive_ptr<writeback_req> req, 
                                       std::error_condition status) 
                                {this->writeback_persist_blkid(req, status); }),
                       ([this] (boost::intrusive_ptr<writeback_req> req, 
                                       std::error_condition status) 
                                { this->writeback_free_blkid(req, status); })),
            m_cache_type(cache_type),
            m_vdev(mgr, context_size, mirrors, true, m_pagesz, mgr->get_all_devices(),
                    (std::bind(&BlkStore::process_completions, 
                    this, std::placeholders::_1)), blob, size),
            m_comp_cb(comp_cb),
            m_metrics("BlkStore") {}

    BlkStore(DeviceManager *mgr, Cache< BlkId > *cache, uint64_t size, BlkStoreCacheType cache_type,
             uint32_t mirrors, char *blob, uint64_t context_size, uint64_t page_size) :
            m_pagesz(page_size),
            m_cache(cache),
            m_wb_cache(cache, ([this] (boost::intrusive_ptr<writeback_req> req, 
                                       std::error_condition status) 
                                {this->writeback_persist_blkid(req, status); }),
                       ([this] (boost::intrusive_ptr<writeback_req> req, 
                                       std::error_condition status) 
                                { this->writeback_free_blkid(req, status); })),
            m_cache_type(cache_type),
            m_vdev(mgr, context_size, mirrors, true, m_pagesz, mgr->get_all_devices(), (std::bind(&BlkStore::process_completions, 
                    this, std::placeholders::_1)), blob, size),
            m_metrics("BlkStore"){
    }

    BlkStore(DeviceManager *mgr, Cache< BlkId > *cache, 
            vdev_info_block *vb, BlkStoreCacheType cache_type, comp_callback comp_cb, uint64_t page_size) :
            m_pagesz(page_size),
            m_cache(cache),
            m_wb_cache(cache, ([this] (boost::intrusive_ptr<writeback_req> req, 
                                std::error_condition status) 
                               { this->writeback_persist_blkid(req, status); }),
                       ([this] (boost::intrusive_ptr<writeback_req> req, 
                                std::error_condition status) 
                               { this->writeback_free_blkid(req, status); })),
            m_cache_type(cache_type),
            m_vdev(mgr, vb, (std::bind(&BlkStore::process_completions, this, std::placeholders::_1))),
	    m_comp_cb(comp_cb),
        m_metrics("BlkStore") {
    }
    
    BlkStore(DeviceManager *mgr, Cache< BlkId > *cache, 
            vdev_info_block *vb, BlkStoreCacheType cache_type, uint64_t page_size) :
            m_pagesz(page_size),
            m_cache(cache),
            m_wb_cache(cache, ([this] (boost::intrusive_ptr<writeback_req> req, 
                                std::error_condition status) 
                               { this->writeback_persist_blkid(req, status); }),
                       ([this] (boost::intrusive_ptr<writeback_req> req, 
                                std::error_condition status) 
                               { this->writeback_free_blkid(req, status); })),
            m_cache_type(cache_type),
            m_vdev(mgr, vb, (std::bind(&BlkStore::process_completions, this, 
			     std::placeholders::_1))),
            m_metrics("BlkStore") {
    }

    void attach_compl(comp_callback comp_cb) {
        m_comp_cb = comp_cb;
    }

    bool is_write_back_cache() {
        return (m_cache_type == WRITEBACK_CACHE || m_cache_type == RD_MODIFY_WRITEBACK_CACHE);
    }

    bool is_read_modify_cache() {
        return (m_cache_type == RD_MODIFY_WRITEBACK_CACHE);
    }

    void process_completions(boost::intrusive_ptr<virtualdev_req> v_req) {
        boost::intrusive_ptr<blkstore_req<Buffer>> req = boost::static_pointer_cast< blkstore_req<Buffer> >(v_req);

        assert(req->err == no_error);
        if (!req->is_read) {
            if (is_write_back_cache()) {
               m_wb_cache.writeBack_completion(req->bbuf, 
                                               boost::static_pointer_cast<writeback_req>(req), 
                                               req->err);
            } else {
                /* TODO: evict it from the cache if it fails */
            }
            m_comp_cb(req);
            return;
        }

        int cnt = req->blkstore_ref_cnt.fetch_sub(1, std::memory_order_relaxed);
        if (cnt != 1) {
            return;
        }

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

        req->missing_pieces.erase(req->missing_pieces.begin(), req->missing_pieces.end());
        m_comp_cb(req);
    }

    void update_cache(boost::intrusive_ptr<blkstore_req<Buffer>> req) {
        Clock::time_point start_time = Clock::now();
        
        for (uint32_t i = 0; i < req->missing_pieces.size(); i++) {
            boost::intrusive_ptr< Buffer >bbuf = req->bbuf;

            bool inserted = bbuf->update_missing_piece(req->missing_pieces[i].offset, 
                                                 req->missing_pieces[i].size, req->missing_pieces[i].ptr);
            if (!inserted) {
                /* someone else has inserted it */
                free(req->missing_pieces[i].ptr);
            }
        }
        HISTOGRAM_OBSERVE(m_metrics, blkstore_cache_read_latency, get_elapsed_time(start_time));
    }

    /* Allocate a new block of the size based on the hints provided */
    BlkAllocStatus alloc_blk(uint32_t size, blk_alloc_hints &hints, 
            std::vector<BlkId> &out_blkid) {
        // Allocate a block from the device manager
        assert(size % m_pagesz == 0);
        auto nblks = size / m_pagesz;
        return (m_vdev.alloc_blk(nblks, hints, out_blkid));
    }

    BlkAllocStatus alloc_blk(BlkId &in_blkid) {
        return(m_vdev.alloc_blk(in_blkid));
    }

    BlkAllocStatus alloc_blk(uint32_t size, blk_alloc_hints &hints, BlkId *out_blkid) {
        // Allocate a block from the device manager
        assert(size % m_pagesz == 0);
        auto nblks = size / m_pagesz;
        hints.is_contiguous = true;
        return (m_vdev.alloc_blk(nblks, hints, out_blkid));
    }

    /* Allocate a new block and add entry to the cache. This method allows the caller to create its own
     * buffer method, but the actual data is page aligned is created by this method and returns the smart pointer
     * of the buffer, along with blkid. */
    boost::intrusive_ptr< Buffer > alloc_blk_cached(uint32_t size, blk_alloc_hints &hints, BlkId *out_blkid) {
        
        // Allocate a block from the device manager
        hints.is_contiguous = true;
        assert(size % m_pagesz == 0);
        alloc_blk(size, hints, out_blkid);

        // Create an object for the buffer
        auto buf = Buffer::make_object();
        buf->set_key(*out_blkid);

        // Create a new block of memory for the blocks requested and set the memvec pointer to that
        uint8_t *ptr;
        int ret = posix_memalign((void **) &ptr, HomeStoreConfig::align_size, size);
        if (ret != 0) {
            throw std::bad_alloc();
        }
        boost::intrusive_ptr<homeds::MemVector> mvec(new homeds::MemVector(), true);
        mvec->set(ptr, size, 0);

        buf->set_memvec(mvec, 0, out_blkid->data_size(m_pagesz));
        // Insert this buffer to the cache.
        auto ibuf = boost::intrusive_ptr< Buffer >(buf);
        boost::intrusive_ptr< Buffer > out_bbuf;
        bool inserted = m_cache->insert(*out_blkid, boost::static_pointer_cast< CacheBuffer< BlkId>>(ibuf),
                                        (boost::intrusive_ptr< CacheBuffer< BlkId>> *) &out_bbuf);
        assert(inserted);

        return ibuf;
    }

    void free_blk(const BlkId &bid, boost::optional< uint32_t > size_offset,
                                                     boost::optional< uint32_t > size) {
        std::deque<boost::intrusive_ptr<homestore::writeback_req>> dependent_req_q;
        free_blk(bid, size_offset, size, dependent_req_q);
    }

    void cache_buf_erase_cb(boost::intrusive_ptr< Buffer > erased_buf,
            std::deque<boost::intrusive_ptr<homestore::writeback_req>>& dependent_req_q, const BlkId bid) {
        assert(is_read_modify_cache());
        if (is_write_back_cache()) {
            boost::intrusive_ptr< blkstore_req<Buffer> >req(new blkstore_req<Buffer> ());
            req->bid = bid;
            req->bbuf = erased_buf;
            
            m_wb_cache.free_blk(req->bbuf, boost::static_pointer_cast<writeback_req>(req), dependent_req_q);
        } else {
            m_vdev.free_blk(bid);
        }
        return;
    }

    /* Free the block previously allocated. Blkoffset refers to number of blks to skip in the BlkId and
     * nblks refer to the total blks from offset to free. 
     */
    void free_blk(const BlkId &bid, boost::optional< uint32_t > size_offset, boost::optional< uint32_t > size,
                  std::deque<boost::intrusive_ptr<homestore::writeback_req>> &dependent_req_q) {
        boost::intrusive_ptr< Buffer > erased_buf(nullptr);
        bool found = false;

        assert(bid.data_size(m_pagesz) >= (size_offset.get_value_or(0) + size.get_value_or(0)));
        
        uint32_t free_size;
        if (size.get_value_or(0) != 0) {
            free_size = size.get_value_or(0);
        } else {
            free_size = bid.data_size(m_pagesz);
        }

        if (is_read_modify_cache()) {
            assert(size_offset.get_value_or(0) == 0 && size.get_value_or(0) == bid.data_size(m_pagesz));
            m_cache->safe_erase(bid, [this, bid, &dependent_req_q](boost::intrusive_ptr< CacheBuffer<BlkId> > erased_buf) {
                                        this->cache_buf_erase_cb(boost::static_pointer_cast<Buffer>(erased_buf),
                                                dependent_req_q, bid);
                                    });
            /* cache will raise callback when ref_cnt becomes zero */
            return;
        } else {
            found = m_cache->erase(bid, size_offset.get_value_or(0), free_size, 
                    (boost::intrusive_ptr< CacheBuffer< BlkId>> *) &erased_buf);
        }

        uint32_t offset = size_offset.get_value_or(0); 
        BlkId tmp_bid(bid.get_blkid_at(offset, free_size, m_pagesz));
        if (is_write_back_cache() && found) {
            boost::intrusive_ptr< blkstore_req<Buffer> >req(new blkstore_req<Buffer> ());
            req->bid = tmp_bid;
            req->bbuf = erased_buf;
            
            m_wb_cache.free_blk(erased_buf, boost::static_pointer_cast<writeback_req>(req), dependent_req_q);
        } else {
            assert(dependent_req_q.empty());
            m_vdev.free_blk(tmp_bid);
        }

        return;
    }

    uint64_t get_elapsed_time(Clock::time_point startTime) {
        std::chrono::nanoseconds ns = std::chrono::duration_cast
                < std::chrono::nanoseconds >(Clock::now() - startTime);
        return ns.count();
    }

    void writeback_persist_blkid(boost::intrusive_ptr<writeback_req> wb_req, 
                                 std::error_condition status) {
            
        boost::intrusive_ptr<blkstore_req<Buffer>> req = boost::static_pointer_cast< blkstore_req<Buffer> >(wb_req);
        if (status != no_error) {
            req->err = status;
            process_completions(boost::static_pointer_cast<virtualdev_req>(req));
        } else {
            m_vdev.write(req->bid, m_wb_cache.writeback_get_memvec(req),
                    boost::static_pointer_cast<virtualdev_req>(req));
        }
    }

    void writeback_free_blkid(boost::intrusive_ptr<writeback_req> wb_req, 
                              std::error_condition status) {
        boost::intrusive_ptr<blkstore_req<Buffer>> req = 
            boost::static_pointer_cast< blkstore_req<Buffer> >(wb_req);
        if (status == no_error) {
            m_vdev.free_blk(req->bid);
        }
        /* mark this req as completed in writeback_cache to do the clean up. */
        m_wb_cache.writeBack_completion(req->bbuf, 
                                        boost::static_pointer_cast<writeback_req>(req), status);
    }

    void write(BlkId &bid, homeds::MemVector &mvec) {
        m_vdev.write(bid, mvec, nullptr, 0);
    }

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
    boost::intrusive_ptr< Buffer > write(BlkId &bid, 
                                         boost::intrusive_ptr<homeds::MemVector> mvec,
                                         int data_offset,
                                         boost::intrusive_ptr<blkstore_req<Buffer>> req,
                                         std::deque<boost::intrusive_ptr<writeback_req>> &dependent_req_q) {
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
        COUNTER_INCREMENT(m_metrics, blkstore_writes_count, 1);

        /* we don't support any dependent writes on the bid have blocks more then 1.
         * It is implemented primarity for async btree in which write size is not
         * more then a page. If number of blocks are more then one then cache,
         * it can be freed partially(see free_partial_cache())  making management 
         * of dependent writes a little complicated.
         */
        assert(bid.get_nblks() == 1 || dependent_req_q.empty());
        CURRENT_CLOCK(cache_start_time);
        uint8_t *ptr;
        
        // Insert this buffer to the cache.
        boost::intrusive_ptr< Buffer > out_bbuf;
        
        bool inserted = m_cache->insert(bid, boost::static_pointer_cast< CacheBuffer< BlkId>>(ibuf),
                                        (boost::intrusive_ptr< CacheBuffer< BlkId>> *) &out_bbuf);
        /* While writing, we should not insert a blkid which already exist in the cache */
        assert(ibuf.get() == out_bbuf.get());
        assert(inserted);
        HISTOGRAM_OBSERVE(m_metrics, blkstore_cache_write_latency, get_elapsed_time(cache_start_time));

        req->bbuf = ibuf;

        // check with writeback cache 
        if (is_write_back_cache() && !req->isSyncCall) {
            req->bid = bid;
            req->data_offset = data_offset;
            m_wb_cache.write_blk(ibuf, boost::static_pointer_cast<writeback_req>(req), dependent_req_q);
            return ibuf;
        }

        assert(dependent_req_q.empty());
        // Now write data to the device
        CURRENT_CLOCK(write_start_time);
        // TODO: rishabh, need to check the return status
        m_vdev.write(bid, ibuf->get_memvec(), boost::static_pointer_cast<virtualdev_req>(req), data_offset);
        HISTOGRAM_OBSERVE(m_metrics, blkstore_drive_write_latency, get_elapsed_time(write_start_time));
        return ibuf;
    }

    /* If the user already has created a blkbuffer, then use this method to use it to write the block */
    void write(BlkId &bid, boost::intrusive_ptr< Buffer > in_buf, 
               boost::intrusive_ptr<blkstore_req<Buffer>> req, 
               std::deque<boost::intrusive_ptr<writeback_req>> &dependent_req_q) {

        if (is_write_back_cache() && !req->isSyncCall) {
            req->bid = bid;
            req->bbuf = in_buf;
            m_wb_cache.write_blk(in_buf, boost::static_pointer_cast<writeback_req>(req), dependent_req_q);
            return;
        }
        assert(dependent_req_q.empty());
        m_vdev.write(bid, in_buf->get_memvec(), boost::static_pointer_cast<virtualdev_req>(req), req->data_offset);
    }

    /* Read the data for given blk id and size. This method allocates the required memory if not present in the cache
     * and returns an smart ptr to the Buffer */
    boost::intrusive_ptr< Buffer > read(BlkId &bid, uint32_t offset, uint32_t size,
            boost::intrusive_ptr<blkstore_req<Buffer>> req) {

        int cur_ind = 0;
        uint32_t cur_offset = offset;

        assert(req->err == no_error);
        // Check if the entry exists in the cache.
        boost::intrusive_ptr< Buffer > bbuf;
        bool cache_found = m_cache->get(bid, (boost::intrusive_ptr< CacheBuffer< BlkId > > *) &bbuf);
        req->blkstore_ref_cnt++;
        if (!cache_found) {
            // Not found in cache, create a new block buf and prepare it for insert to dev and cache.
            bbuf = Buffer::make_object();
            
            /* set the key */
            bbuf->set_key(bid);

            /* set the memvec */
            boost::intrusive_ptr<homeds::MemVector> mvec(new homeds::MemVector());
            bbuf->set_memvec(mvec, 0, 0);

            /* insert it into cache */
            boost::intrusive_ptr< Buffer > new_bbuf;
            bool inserted = m_cache->insert(bbuf->get_key(), boost::static_pointer_cast<CacheBuffer<BlkId>>(bbuf),
                    (boost::intrusive_ptr< CacheBuffer<BlkId> > *)&new_bbuf);
            if (!inserted) {
                /* Between get and insert, other thread tried the same thing and
                 * inserted into the cache. Lets use that entry in cache and 
                 * free up the memory
                 */
                bbuf = new_bbuf;
            }
        } else {
            COUNTER_INCREMENT(m_metrics, blkstore_cache_hits_count, 1);
        }

        req->bbuf = bbuf;
        req->is_read = true;
        /* first is offset and second is size in a pair */
        vector< std::pair<uint32_t, uint32_t> > missing_mp;
        assert(bid.data_size(m_pagesz) >= (offset + size));
        bool ret = m_cache->insert_missing_pieces(bbuf, offset, size, missing_mp);
        BlkId read_blkid(bid.get_blkid_at(offset, size, m_pagesz));
        /* It might be a false assert if there is a race between read and write but keeping
         * it for now as it can be good check to see that we have recovered all the blocks
         * after boot.
         */
        assert(m_vdev.is_blk_alloced(read_blkid));

        uint8_t *ptr;
        for (uint32_t i = 0; i < missing_mp.size(); i++) {

            // Create a new block of memory for the missing piece
            int ret = posix_memalign((void **) &ptr, HomeStoreConfig::align_size, missing_mp[i].second);
            if (ret != 0) {
                assert(0);
                throw std::bad_alloc();
            }

            // Read the missing piece from the device
            BlkId tmp_bid(bid.get_blkid_at(missing_mp[i].first, missing_mp[i].second, m_pagesz));

            req->blkstore_ref_cnt.fetch_add(1, std::memory_order_acquire);
            homeds::MemPiece mp(ptr, missing_mp[i].second, 0);
            
            if (!req->isSyncCall) {
                bufferInfo missing_piece(missing_mp[i].first, missing_mp[i].second, ptr);
                /* insert it into cache after missing_piece is read */
                req->missing_pieces.push_back(missing_piece);
            }

            m_vdev.read(tmp_bid, mp, 
                         boost::static_pointer_cast<virtualdev_req>(req));
            if (req->isSyncCall) {
                bool inserted = bbuf->update_missing_piece(missing_mp[i].first, missing_mp[i].second, ptr);
                if (!inserted) {
                    /* someone else has inserted it */
                    free(ptr);
                }
                req->blkstore_ref_cnt.fetch_sub(1, std::memory_order_acquire);
            }

            COUNTER_INCREMENT(m_metrics, blkstore_reads_count, 1);
        }

        assert(req->err == no_error);
        if (!req->isSyncCall) {
            /* issue the completion */
            process_completions(boost::static_pointer_cast<virtualdev_req>(req));
        } else {
            req->blkstore_ref_cnt.fetch_sub(1, std::memory_order_acquire);
        }
        return bbuf;
    }

    std::vector<boost::intrusive_ptr<BlkBuffer>> read_nmirror(BlkId &bid, int nmirrors) {
        std::vector<boost::intrusive_ptr<BlkBuffer>> buf_list;
        std::vector<boost::intrusive_ptr<homeds::MemVector>> mp;
        uint8_t *mem_ptr = nullptr;
        
        for (int i = 0; i < (nmirrors + 1); i++) {
            /* create the pointer */
            auto ret = posix_memalign((void **) &mem_ptr, HomeStoreConfig::align_size, bid.data_size(m_pagesz));
            assert (ret == 0);
            
            /* set the memvec */
            boost::intrusive_ptr<homeds::MemVector> mvec(new homeds::MemVector());
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

    void reset_vdev_failed_state() {
        m_vdev.reset_failed_state();
    }
    boost::intrusive_ptr<writeback_req> read_locked(boost::intrusive_ptr< Buffer > buf, bool is_write_modifiable) {
        assert(buf.get());
        if (is_write_back_cache()) {
            return(m_wb_cache.writeBack_cache_read(buf, is_write_modifiable));
        }
        
        return nullptr;
    }
                                       
    uint64_t get_size() const {
        return m_vdev.get_size();
    }

    void update_vb_context(uint8_t *blob) {
        m_vdev.update_vb_context(blob);       
    }

    VirtualDev< BAllocator, RoundRobinDeviceSelector > *get_vdev() {
        return &m_vdev;
    };


private:
    uint32_t m_pagesz;
    Cache< BlkId > *m_cache;
    WriteBackCache< BlkId > m_wb_cache;
    BlkStoreCacheType m_cache_type;
    VirtualDev<BAllocator, RoundRobinDeviceSelector> m_vdev;
    comp_callback m_comp_cb;
    BlkStoreMetrics m_metrics;
};
}
#endif //OMSTORE_BLKSTORE_HPP
