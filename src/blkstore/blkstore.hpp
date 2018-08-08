//
// Created by Kadayam, Hari on 15/11/17.
//

#ifndef OMSTORE_BLKSTORE_HPP
#define OMSTORE_BLKSTORE_HPP

#include "cache/cache.h"
#include "device/device_selector.hpp"
#include "device/device.h"
#include "main/store_limits.h"
#include <boost/optional.hpp>
#include "homeds/memory/mempiece.hpp"
#include "cache/cache.cpp"
#include <error/error.h>
#include "writeBack_cache.hpp"
#include "device/blkbuffer.hpp"

namespace homestore {
enum BlkStoreCacheType {
    PASS_THRU = 0,
    WRITEBACK_CACHE = 1,
    WRITETHRU_CACHE = 2
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


template <typename Buffer = BlkBuffer>
struct blkstore_req : writeback_req {
	boost::intrusive_ptr< Buffer > write_bbuf;
	BlkId bid;
	uint64_t size;
    std::atomic<int> blkstore_read_cnt;
    bool is_read;
    virtual ~blkstore_req(){
    };
};

template <typename BAllocator, typename Buffer = BlkBuffer>
class BlkStore {
    typedef std::function< void (boost::intrusive_ptr<blkstore_req<Buffer>> req) > comp_callback;
    public:
    void process_completions(boost::intrusive_ptr<virtualdev_req> v_req) {
        boost::intrusive_ptr<blkstore_req<Buffer>> req = 
            boost::static_pointer_cast< blkstore_req<Buffer> >(v_req);

        if (!req->is_read) {
            m_comp_cb(req);
            if (m_cache_type == WRITEBACK_CACHE) {
               m_wb_cache.writeBack_completion(req->write_bbuf, 
                                               boost::static_pointer_cast<writeback_req>(req), 
                                               req->err);
            } else {
                /* TODO: evict it from the cache if it fails */
            }
            return;
        }

        int cnt = req->blkstore_read_cnt.fetch_sub(1, 
                std::memory_order_relaxed);
        if (cnt != 1) {
            return;
        }
        m_comp_cb(req);
    }

    boost::intrusive_ptr< Buffer > update_cache(
                                         boost::intrusive_ptr< Buffer >bbuf) {

        Clock::time_point cache_startTime = Clock::now();
        boost::intrusive_ptr< Buffer > new_bbuf;
        bool inserted = m_cache->insert(bbuf->get_key(),
                dynamic_pointer_cast<CacheBuffer<BlkId>>(bbuf),
                (boost::intrusive_ptr< CacheBuffer<BlkId> > *)&new_bbuf);
        cache_read_time.fetch_add(get_elapsed_time(cache_startTime), 
                std::memory_order_relaxed);
        return new_bbuf;
    }

    BlkStore(DeviceManager *mgr, Cache< BlkId > *cache, uint64_t initial_size, BlkStoreCacheType cache_type,
             uint32_t mirrors, comp_callback comp_cb) :
            m_cache(cache),
            m_wb_cache(cache, ([this] (boost::intrusive_ptr<writeback_req> req, 
                                       std::error_condition status) 
                                {this->writeback_persist_blkid(req, status); }),
                       ([this] (boost::intrusive_ptr<writeback_req> req, 
                                       std::error_condition status) 
                                { this->writeback_free_blkid(req, status); })),
            m_cache_type(cache_type),
            m_vdev(mgr, initial_size, mirrors, true, BLKSTORE_BLK_SIZE,
				mgr->get_all_devices(), 
				(std::bind(&BlkStore::process_completions, this, 
			         std::placeholders::_1))),
	    m_comp_cb(comp_cb) {
    }

    BlkStore(DeviceManager *mgr, Cache< BlkId > *cache, 
            vdev_info_block *vb,BlkStoreCacheType cache_type, comp_callback comp_cb) :
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
	    m_comp_cb(comp_cb) {
    }

    /* Allocate a new block of the size based on the hints provided */
    BlkAllocStatus alloc_blk(uint8_t nblks, blk_alloc_hints &hints, 
            BlkId *out_blkid) {
        // Allocate a block from the device manager
        return (m_vdev.alloc_blk(nblks, hints, out_blkid));
    }

    /* Allocate a new block and add entry to the cache. This method allows the caller to create its own
     * buffer method, but the actual data is page aligned is created by this method and returns the smart pointer
     * of the buffer, along with blkid. */
    boost::intrusive_ptr< Buffer > alloc_blk_cached(uint8_t nblks, blk_alloc_hints &hints, BlkId *out_blkid) {
        // Allocate a block from the device manager
        alloc_blk(nblks, hints, out_blkid);

        // Create an object for the buffer
        auto buf = Buffer::make_object();
        buf->set_key(*out_blkid);

        // Create a new block of memory for the blocks requested and set the memvec pointer to that
        uint8_t *ptr;
        uint32_t size = nblks * BLKSTORE_BLK_SIZE;
        int ret = posix_memalign((void **) &ptr, 4096, size); // TODO: Align based on hw needs instead of 4k
        if (ret != 0) {
            throw std::bad_alloc();
        }
        homeds::MemVector< BLKSTORE_BLK_SIZE > &mvec = buf->get_memvec_mutable();
        mvec.set(ptr, size, 0);

        // Insert this buffer to the cache.
        auto ibuf = boost::intrusive_ptr< Buffer >(buf);
        boost::intrusive_ptr< Buffer > out_bbuf;
        bool inserted = m_cache->insert(*out_blkid, boost::static_pointer_cast< CacheBuffer< BlkId>>(ibuf),
                                        (boost::intrusive_ptr< CacheBuffer< BlkId>> *) &out_bbuf);

        // TODO: Raise an exception if we are not able to insert - instead of assert
        assert(inserted);

        return ibuf;
    }

    boost::optional< std::array< BlkId, 2>> free_blk(const BlkId &bid, boost::optional< uint8_t > blkoffset,
                                                     boost::optional< uint8_t > nblks) {
        std::deque<boost::intrusive_ptr<homestore::writeback_req>> dependent_req_q;
        return(free_blk(bid, blkoffset, nblks, dependent_req_q));
    }

    /* Free the block previously allocated. Blkoffset refers to number of blks to skip in the BlkId and
     * nblks refer to the total blks from offset to free. This method returns a optional array of new
     * BlkIds - max of 2 in case complete BlkIds are not free. If it is single blk, it returns no value */
    boost::optional< std::array< BlkId, 2>> free_blk(const BlkId &bid, boost::optional< uint8_t > blkoffset,
                                                     boost::optional< uint8_t > nblks, 
                                                     std::deque<boost::intrusive_ptr<homestore::writeback_req>> 
                                                     &dependent_req_q) {
        boost::intrusive_ptr< Buffer > erased_buf(nullptr);
        boost::optional< std::array< BlkId, 2>> ret_arr;
        bool found = false;

        // Check if its a full element freed. In that case remove the element in the cache and free it up
        if ((blkoffset.get_value_or(0) == 0) && ((nblks == boost::none) || (nblks == bid.get_nblks()))) {
            found = m_cache->erase(bid, (boost::intrusive_ptr< CacheBuffer< BlkId>> *) &erased_buf);
            ret_arr = boost::none;
            goto out;
        }

        /* TODO: need to see what happen if read and erase happening in parallel of same blkid */

        // Not the entire block is freed. Remove the entire entry from cache and split into possibly 2 entries
        // and insert it.
        if ((found = m_cache->erase(bid, (boost::intrusive_ptr< CacheBuffer< BlkId>> *) &erased_buf)) == true) {
            // If number of blks we are freeing is more than 80% of the total buffer in cache, it does not make sense
            // to collect other buffers, creating a copy etc.. Just consider the entire entry is out of cache
            if (nblks.get() < (bid.get_nblks() * 0.8)) {
                uint8_t from_blk = blkoffset.get_value_or(0);
                uint8_t to_blk = from_blk + nblks.get_value_or(bid.get_nblks());
                std::array< boost::intrusive_ptr< Buffer >, 2 > bbufs = free_partial_cache(erased_buf, from_blk,
                                                                                           to_blk);

                // Add the split entries to the cache.
                for (auto i = 0U; i < bbufs.size(); i++) {
                    ret_arr->at(i) = bbufs[i]->get_key();
                    boost::intrusive_ptr< Buffer > out_buf;
                    bool inserted = m_cache->insert(ret_arr->at(i), bbufs[i],
                                                    (boost::intrusive_ptr< CacheBuffer< BlkId>> *) &out_buf);
                    assert(inserted);
                }
            }
        }
        
out:
        uint8_t num_blks;
        if (nblks == boost::none) {
            num_blks = bid.get_nblks();
        } else {
            num_blks = nblks.get();
        }
        BlkId tmp_bid(bid.get_id() + blkoffset.get_value_or(0), num_blks, bid.get_chunk_num());
        if (m_cache_type == WRITEBACK_CACHE && found) {
            boost::intrusive_ptr< blkstore_req<Buffer> >req(new blkstore_req<Buffer> ());
            req->bid = tmp_bid;
            req->write_bbuf = erased_buf;
            
            m_wb_cache.free_blk(erased_buf,
                                boost::static_pointer_cast<writeback_req>(req), 
                                dependent_req_q);
        } else {
            assert(dependent_req_q.empty());
            m_vdev.free_blk(tmp_bid);
        }

        return ret_arr;
    }

    /* Allocate a new block and write the contents to the allocated block and return the blkbuffer */
    boost::intrusive_ptr< BlkBuffer > alloc_and_write(homeds::blob &blob, 
                            blk_alloc_hints &hints, 
							std::deque<boost::intrusive_ptr<writeback_req>> &dependent_req_q) {
        // First allocate the blk id based on the hints
        BlkId bid;
        m_vdev.alloc_blk(round_off(blob.size, BLKSTORE_BLK_SIZE), hints, &bid);

        // Insert the entry into the cache and then write to the device.
        return write(bid, blob, dependent_req_q);
    }


    /* Write the buffer. The BlkStore write does not support write in place and so it does not also support
     * writing to an offset.
     *
     * NOTE: While one could argue that even when it is not doing write in place it could still
     * create a new blkid and then write it on an offset from the blkid. So far there is no use case for that. To
     * avoid any confusion to the interface, the value_offset parameter is not provided for this write type. If
     * needed can be added later */
    uint64_t get_elapsed_time(Clock::time_point startTime) {
        std::chrono::nanoseconds ns = std::chrono::duration_cast
                < std::chrono::nanoseconds >(Clock::now() - startTime);
        return ns.count();
    }

    void writeback_persist_blkid(boost::intrusive_ptr<writeback_req> wb_req, 
                                 std::error_condition status) {
            
        boost::intrusive_ptr<blkstore_req<Buffer>> req = 
            boost::static_pointer_cast< blkstore_req<Buffer> >(wb_req);
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
        m_wb_cache.writeBack_completion(req->write_bbuf, 
                                        boost::static_pointer_cast<writeback_req>(req), status);
    }

    boost::intrusive_ptr< Buffer > write(BlkId &bid, homeds::blob &blob, 
            boost::intrusive_ptr<blkstore_req<Buffer>> req, 
            std::deque<boost::intrusive_ptr<writeback_req>> &dependent_req_q) {
        /* 
         * First try to create/insert a record for this blk id in the cache. 
         * If it already exists, it will simply upvote the item.
         */
        write_cnt.fetch_add(1, memory_order_relaxed);
        
        /* we don't support any dependent writes on the bid have blocks more then 1.
         * It is implemented primarity for async btree in which write size is not
         * more then a page. If number of blocks are more then one then cache,
         * it can be freed partially(see free_partial_cache())  making management 
         * of dependent writes a little complicated.
         */
        assert(bid.get_nblks() == 1 || dependent_req_q.empty());
        Clock::time_point cache_startTime = Clock::now();
        uint8_t *ptr;
        // Create an object for the buffer
        auto buf = Buffer::make_object();
        buf->set_key(bid);
        homeds::MemVector< BLKSTORE_BLK_SIZE > &mvec = buf->get_memvec_mutable();
        mvec.set(blob.bytes, blob.size, 0);
        
        // Insert this buffer to the cache.
        auto ibuf = boost::intrusive_ptr< Buffer >(buf);
        boost::intrusive_ptr< Buffer > out_bbuf;
        
        bool inserted = m_cache->insert(bid, boost::static_pointer_cast< CacheBuffer< BlkId>>(ibuf),
                                        (boost::intrusive_ptr< CacheBuffer< BlkId>> *) &out_bbuf);
        /* While writing, we should not insert a blkid which already exist in the cache */
        assert(ibuf.get() == out_bbuf.get());
        cache_write_time.fetch_add(get_elapsed_time(cache_startTime), 
                memory_order_relaxed);
        // TODO: Raise an exception if we are not able to insert - instead of assert
        assert(inserted);
        if (!inserted) {
            return NULL;
        }

        req->write_bbuf = ibuf;

        // check with writeback cache 
        if (m_cache_type == WRITEBACK_CACHE && !req->isSyncCall) {
            req->bid = bid;
            m_wb_cache.write_blk(ibuf, 
                                 boost::static_pointer_cast<writeback_req>(req),
                                 dependent_req_q);
            return ibuf;
        }

        assert(dependent_req_q.empty());
        // Now write data to the device
        Clock::time_point write_startTime = Clock::now();
        // TODO: rishabh, need to check the return status
        m_vdev.write(bid, ibuf->get_memvec(), 
                      boost::static_pointer_cast<virtualdev_req>(req));
        write_time += get_elapsed_time(write_startTime);
        return ibuf;
    }

    void print_perf_cnts() {
        printf("cache time %lu ns\n", cache_write_time/write_cnt);
        printf("physical device write time %lu ns\n", write_time/write_cnt);
         if(read_cnt != 0) {
            printf("cache_hit %lu %% \n",(cache_hit * 100)/read_cnt); 
            printf("cache time while reading %lu ns\n", cache_read_time/read_cnt);
        }
        printf("absolut cache_hit %lu \n",atomic_load(&cache_hit)); 
        printf("read_cnt in blkstore %lu \n", atomic_load(&read_cnt)); 
        m_vdev.print_cntrs();
    }

    void init_perf_cnts() {
        cache_write_time = 0;
        write_time = 0;
        write_cnt = 0;
        cache_hit = 0;
        read_cnt = 0;
        m_vdev.init_cntrs();
    }

    /* If the user already has created a blkbuffer, then use this method to use it to write the block */
    void write(BlkId &bid, boost::intrusive_ptr< Buffer > in_buf, 
               boost::intrusive_ptr<blkstore_req<Buffer>> req, 
               std::deque<boost::intrusive_ptr<writeback_req>> &dependent_req_q) {
        if (m_cache_type == WRITEBACK_CACHE && !req->isSyncCall) {
            req->bid = bid;
            req->write_bbuf = in_buf;
            m_wb_cache.write_blk(in_buf, 
                                 boost::static_pointer_cast<writeback_req>(req),
                                 dependent_req_q);
            return;
        }
        assert(dependent_req_q.empty());
        m_vdev.write(bid, in_buf->get_memvec(), 
                        boost::static_pointer_cast<virtualdev_req>(req));
    }

    /* Read the data for given blk id and size. This method allocates the required memory if not present in the cache
     * and returns an smart ptr to the Buffer */
    boost::intrusive_ptr< Buffer > read(BlkId &bid, uint32_t offset, 
                                        uint32_t size, 
                                        boost::intrusive_ptr<blkstore_req<Buffer>> req) {
        // TODO: Convert this assert to exceptions
        assert((offset + size) <= 256 * BLKSTORE_BLK_SIZE);
        assert(offset < 256 * BLKSTORE_BLK_SIZE);
        assert((offset % BLKSTORE_BLK_SIZE) == 0);
        assert((size % BLKSTORE_BLK_SIZE) == 0);

        int cur_ind = 0;
        uint32_t cur_offset = offset;

        // Check if the entry exists in the cache.
        boost::intrusive_ptr< Buffer > bbuf;
        bool cache_found = m_cache->get(bid, (boost::intrusive_ptr< CacheBuffer< BlkId > > *) &bbuf);
        if (!cache_found) {
            // Not found in cache, create a new block buf and prepare it for insert to dev and cache.
            bbuf = Buffer::make_object();
            bbuf->set_key(bid);
        } else {
            cache_hit++;
        }

        uint32_t size_to_read = size;
        homeds::MemVector<BLKSTORE_BLK_SIZE>::cursor_t c;

            uint8_t *ptr;
        while (size_to_read > 0) {
            boost::optional< homeds::MemPiece<BLKSTORE_BLK_SIZE> &> missing_mp =
                bbuf->get_memvec_mutable().fill_next_missing_piece(c, size, cur_offset);
            if (!missing_mp) {
                // We don't have any missing pieces, so we are done reading the contents
                break;
            }

            cur_offset = missing_mp->end_offset();

            // Create a new block of memory for the missing piece
            int ret = posix_memalign((void **) &ptr, 4096,
                    missing_mp->size()); // TODO: Align based on hw needs instead of 4k
            if (ret != 0) {
                throw std::bad_alloc();
            }
            missing_mp.get().set_ptr(ptr);

            // Read the missing piece from the device
            BlkId tmp_bid(bid.get_id() + missing_mp->offset()/BLKSTORE_BLK_SIZE,
                    missing_mp->size()/BLKSTORE_BLK_SIZE, bid.get_chunk_num());
            req->blkstore_read_cnt.fetch_add(1, std::memory_order_acquire);
            m_vdev.read(tmp_bid, missing_mp.get(), 
                         boost::static_pointer_cast<virtualdev_req>(req));
            size_to_read -= missing_mp->size();
            
            read_cnt.fetch_add(1, memory_order_relaxed);
        }

        if (!cache_found && req->isSyncCall) {
            boost::intrusive_ptr< Buffer > new_bbuf;
            bool inserted = m_cache->insert(bbuf->get_key(),
                    boost::static_pointer_cast<CacheBuffer<BlkId>>(bbuf),
                    (boost::intrusive_ptr< CacheBuffer<BlkId> > *)&new_bbuf);
            if (!inserted) {
                /* Between get and insert, other thread tried the same thing and
                 * inserted into the cache. Lets use that entry in cache and 
                 * free up the memory
                 */
                bbuf = new_bbuf;
            }
        }
        return bbuf;
    }

    boost::intrusive_ptr<writeback_req> read_locked(boost::intrusive_ptr< Buffer > buf, 
                                                bool is_write_modifiable) {
        assert(buf.get());
        if (m_cache_type == WRITEBACK_CACHE) {
            return(m_wb_cache.writeBack_cache_read(buf, is_write_modifiable));
        }
        
        return nullptr;
    }
                                       
    uint64_t get_size() const {
        return m_vdev.get_size();
    }

    VirtualDev< BAllocator, RoundRobinDeviceSelector > *get_vdev() {
        return &m_vdev;
    };

private:
    std::array< boost::intrusive_ptr< Buffer >, 2 > free_partial_cache(const boost::intrusive_ptr< Buffer > inbuf,
            uint8_t from_nblk, uint8_t to_nblk) {
        std::array< boost::intrusive_ptr< Buffer >, 2 > bbufs;
        uint32_t left_ind = 0, right_ind; // index within the vector the about to free blks cover
        uint32_t from_offset = from_nblk * BLKSTORE_BLK_SIZE;
        uint32_t to_offset = to_nblk * BLKSTORE_BLK_SIZE;

        auto &mvec = inbuf->get_memvec();
        const BlkId orig_b = inbuf->get_key();

        //////////////////// Do left hand side processing //////////////////////
        // Check if the from_blk in the cache is overlapping with previous blk for same BlkId range
        homeds::MemVector< BLKSTORE_BLK_SIZE > left_mvec;
        if (from_offset) {
            bool is_left_overlap = mvec.find_index(from_offset, boost::none, &left_ind);
            for (auto i = 0u; i < left_ind - 1; i++) { // Update upto the previous one.
                auto mp = mvec.get_nth_piece((uint32_t) i);
                left_mvec.push_back(mp);
            }

            if (is_left_overlap) {
                // Seems like we may be overlapping, create a new memory piece for remaining portion and set it
                auto left_mp = mvec.get_nth_piece((uint32_t) left_ind);
                auto sz = from_offset - left_mp.offset();
                if (sz) {
                    left_mp.set_size(sz);
                    left_mvec.push_back(left_mp);
                }
            }
        }

        //////////////////// Do right hand side processing //////////////////////
        // If the freed blks overlap and has some excess to the right of it, we will have to either copy the
        // remaining buffer into new buffer (so that it will be freed correctly) or simply discard them from cache
        homeds::MemVector< BLKSTORE_BLK_SIZE > right_mvec;
        mvec.find_index(to_offset, boost::none, &right_ind);
        if (left_ind == right_ind) {
            auto right_mp = mvec.get_nth_piece((uint32_t) right_ind);
            uint32_t sz = (right_mp.offset() + right_mp.size()) - to_offset;
            if (sz && (sz <= CACHE_DISCARD_THRESHOLD_SIZE)) {
                uint8_t *ptr;
                int ret = posix_memalign((void **) &ptr, 4096, sz); // TODO: Align based on hw needs instead of 4k
                if (ret != 0) {
                    throw std::bad_alloc();
                }
                right_mp.set_ptr(ptr);
                right_mp.set_size(sz);
                right_mp.set_offset(to_offset);
                right_mvec.push_back(right_mp);
                right_ind++;
            } // Else case will simply discard that buffer from adding to new bbuf
        }

        for (auto i = right_ind; i < mvec.npieces(); i++) { // Update upto the tailing ones.
            auto mp = mvec.get_nth_piece((uint32_t) i);
            right_mvec.push_back(mp);
        }

        // Finally form the new Buffer with new blkid and left mvec pieces
        uint32_t b = 0;
        if (from_nblk) {
            BlkId lb(orig_b.get_id(), from_nblk, orig_b.get_chunk_num());
            bbufs[b] = inbuf; // Use the same buffer as in buf
            bbufs[b]->set_key(lb);
            bbufs[b]->set_memvec(left_mvec);
            ++b;
        }

        // Similar to that to the right mvec pieces
        if (orig_b.get_nblks() - to_nblk) {
            BlkId rb(orig_b.get_id() + to_nblk, orig_b.get_nblks() - to_nblk, orig_b.get_chunk_num());
            bbufs[b] = homeds::ObjectAllocator< Buffer >::make_object();
            bbufs[b]->set_key(rb);
            bbufs[b]->set_memvec(right_mvec);
        }

        return bbufs;
    }

#if 0
    /* From the given blk buffer, free up portion of the cache (provided by from_blk to end_blk. It returns 2 new
     * buffer, the one before the from_blk and the one after end_blk. It is possible that the from_blk to end_blk backing
     * underlying buffer overlaps with one left to it or right to it or both, It does the following in that case
     *
     * a) If overlaps with only left: If non-overlapping buffer size is >30% of original buffer size or >16K
     * (whichever is greater)  then it retains the original buffer as is, adjust the left buffer's (mempiece) size. If
     * not, then it creates a new buffer with reduced size and copies the buffer.
     *
     * b) If overlaps with only right: Its similar to above one a)
     *
     * c) If overlaps with both left & right: If both sides satisfy condition of non-overalapping buffer size is
     * >30% of original buffer size or >16K, then it picks the one which needs least amount of copying and leaving the
     * other side to just adjust the size and not copy.
     */
    std::array<boost::intrusive_ptr< Buffer >, 2> free_partial_cache(boost::intrusive_ptr< Buffer > buf,
            uint8_t from_blk, uint8_t end_blk) {
        std::array< boost::intrusive_ptr< Buffer >, 2 > bbufs;
        int left_ind, right_ind; // index within the vector the about to free blks cover

        auto &mvec = buf->get_memvec();
        const BlkId &orig_b = buf->get_key();

        //////////////////// Do left hand side processing //////////////////////
        // Generate a new BlkId for the left side portion
        BlkId lb(orig_b.get_id(), from_blk, orig_b.get_chunk_num());
        bbufs[0]->set_key(lb);

        // Check if the from_blk in the cache is overlapping with previous blk for same BlkId range
        bool is_left_overlap = mvec.bsearch(from_blk * BLKSTORE_BLK_SIZE, &left_ind);
        for (auto i = 0; i < left_ind-1; i++) { // Update upto the previous one.
            auto &mp = mvec.get_nth_piece((uint32_t)i);
            bbufs[0]->get_memvec_mutable().push_back(mp);
        }

        if (is_left_overlap) {
            auto &left_mp = mvec.get_nth_piece_mutable((uint32_t)left_ind);
            uint32_t left_overlap_sz = left_mp.offset() - from_blk*BLKSTORE_BLK_SIZE;
            uint32_t non_overlap_sz = left_mp.size() - left_overlap_sz;
            if (non_overlap_sz < 16384) {
                uint8_t *ptr;
                int ret = posix_memalign((void **) &ptr, 4096,
                        non_overlap_sz); // TODO: Align based on hw needs instead of 4k
                if (ret != 0) {
                    throw std::bad_alloc();
                }
                left_mp.set_ptr(ptr);
            }
            left_mp.set_size(non_overlap_sz);
            bbufs[0]->get_memvec_mutable().push_back(left_mp);
        }

        //////////////////// Do right hand side processing //////////////////////
        BlkId rb(orig_b.get_id() + end_blk, orig_b.get_nblks() - end_blk, orig_b.get_chunk_num());
        bbufs[1]->set_key(rb);

        bool is_right_overlap = mvec.bsearch(end_blk * BLKSTORE_BLK_SIZE, &right_ind);
        if (is_right_overlap) {
            auto &right_mp = mvec.get_nth_piece_mutable((uint32_t)right_ind);
            uint32_t right_overlap_sz = (right_mp.offset()+right_mp.size()) - end_blk*BLKSTORE_BLK_SIZE;
            uint32_t non_overlap_sz = right_mp.size() - right_overlap_sz;
            if (non_overlap_sz < 16384) {
                uint8_t *ptr;
                int ret = posix_memalign((void **) &ptr, 4096,
                        non_overlap_sz); // TODO: Align based on hw needs instead of 4k
                if (ret != 0) {
                    throw std::bad_alloc();
                }
                right_mp.set_ptr(ptr);
            } else {
                right_mp.set_ptr(ptr + )
            }
            right_mp.set_size(non_overlap_sz);
        }

        homeds::MemPiece left_mp; homeds::MemPiece right_mp;
        if (left_overlap > right_overlap) {
            if (make_sense_to_retain(mp.size(), left_overlap)) {
                left_mp.set_size(mp.size() - left_overlap);
            } else {

            }
        }




        // Prepare the left side of the buffer

        bbufs[0]->get_memvec_mutable().push_back()

    }

    bool make_sense_to_retain(uint32_t total_sz, uint32_t overlap_sz) {
        uint32_t non_overlap_sz = total_sz - overlap_sz;

        return ((non_overlap_sz >= 16384) || (non_overlap_sz) >
                }

                BlkId gen_offset_blkid(const BlkId &bid, uint8_t upto_blk) {

                }
#endif
    private:
        Cache< BlkId > *m_cache;
        WriteBackCache< BlkId > m_wb_cache;
        BlkStoreCacheType m_cache_type;
        VirtualDev<BAllocator, RoundRobinDeviceSelector> m_vdev;
        atomic<uint64_t> write_cnt;
        atomic<uint64_t> cache_write_time;
        atomic<uint64_t> cache_read_time;
        atomic<uint64_t> cache_hit;
        atomic<uint64_t> read_cnt;
        atomic<uint64_t> write_time;
        comp_callback m_comp_cb;
    };

}
#endif //OMSTORE_BLKSTORE_HPP
