//
// Created by Kadayam, Hari on 15/11/17.
//

#ifndef OMSTORE_BLKSTORE_HPP
#define OMSTORE_BLKSTORE_HPP

#include "cache/cache.h"
#include "device/device_selector.hpp"
#include "device/device.h"
#include "device/blkbuffer.hpp"
#include "main/store_limits.h"
#include <boost/optional.hpp>
#include "homeds/memory/mempiece.hpp"
#include "cache/cache.cpp"
#include <error/error.h>

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
struct blkstore_req:virtualdev_req {
	BlkId bid;
	uint64_t size;
	boost::intrusive_ptr< Buffer > write_bbuf;
	boost::intrusive_ptr< Buffer > read_bbuf;
	std::vector< boost::intrusive_ptr< Buffer >> read_buf_list;
	int missing_piece_cnt;
	bool cache_found;
};

template <typename BAllocator, typename Buffer = BlkBuffer>
class BlkStore {
    typedef std::function< void (blkstore_req<Buffer>* req) > comp_callback;
public:
    void process_completions(virtualdev_req *v_req) {
	struct blkstore_req<Buffer> * req = static_cast< struct blkstore_req<Buffer>* >(v_req);

	if (req->err != no_error) {
		m_comp_cb(req);
	}	
	if (!req->is_read) {
		m_comp_cb(req);
		/* XXX: do we need to do anything for failure */
		return;
	}

	/* TODO: read_bbuf will be overwritten if it is reading from multiple
  	 * blocks because there is only one request for each IO. Need to
	 * fix it by calling cache after all buffers are read from volume
	 * layer.
	 */
	[[maybe_unused]] homeds::blob b = req->read_bbuf->at_offset(0);
	if (!req->cache_found) {
	    /* It is not there in the cache */
            boost::intrusive_ptr< Buffer > new_bbuf;
            boost::intrusive_ptr< Buffer > bbuf = req->read_bbuf;
	    Clock::time_point cache_startTime = Clock::now();
            bool inserted = m_cache->insert(bbuf->get_key(),
                                            dynamic_pointer_cast<CacheBuffer<BlkId>>(bbuf),
                                            (boost::intrusive_ptr< CacheBuffer<BlkId> > *)&new_bbuf);
	    cache_read_time.fetch_add(get_elapsed_time(cache_startTime), memory_order_relaxed);
            if (!inserted) {
                // Between get and insert, other thread tried the same thing and inserted into the cache. Lets use
                // that entry in cache and free up the memory
            //    req->read_bbuf = new_bbuf;
            }			
	} else {
	    req->missing_piece_cnt--;
	    if (req->missing_piece_cnt) {
		/* wait for other missing pieces to come */
		return;
	    }
			
	}
	read_complete_cnt++;
	LOGINFO("BlkStore-Read-Finish:{}",read_complete_cnt);
	
	m_comp_cb(req);
    }

    BlkStore(DeviceManager *mgr, Cache< BlkId > *cache, uint64_t initial_size, BlkStoreCacheType cache_type,
             uint32_t mirrors, comp_callback comp_cb) :
            m_cache(cache),
            m_cache_type(cache_type),
            m_vdev(mgr, initial_size, mirrors, true, BLKSTORE_BLK_SIZE,
				mgr->get_all_devices(), 
				(std::bind(&BlkStore::process_completions, this, 
			         std::placeholders::_1))),
	    m_comp_cb(comp_cb) {
        alloc_single_block_in_mem();
    }

    BlkStore(DeviceManager *mgr, Cache< BlkId > *cache, vdev_info_block *vb, 
				BlkStoreCacheType cache_type, comp_callback comp_cb) :
            m_cache(cache),
            m_cache_type(cache_type),
            m_vdev(mgr, vb, (std::bind(&BlkStore::process_completions, this, 
			     std::placeholders::_1))), 
	    m_comp_cb(comp_cb) {
        alloc_single_block_in_mem();
    }

    /* Allocate a new block of the size based on the hints provided */
    /* TODO: rishabh : we should have a return type here */ 
    BlkAllocStatus alloc_blk(uint8_t nblks, blk_alloc_hints &hints, BlkId *out_blkid) {
        // Allocate a block from the device manager
        return (m_vdev.alloc_blk(nblks, hints, out_blkid));
    }

    /* Just create single block in memory, not on physical device and not in cache */
    void alloc_single_block_in_mem() {
        BlkId *out_blkid = new BlkId(0);
        // Create an object for the buffer
        only_in_mem_buff = Buffer::make_object();
        only_in_mem_buff->set_key(*out_blkid);

        // Create a new block of memory for the blocks requested and set the memvec pointer to that
        uint8_t *ptr;
        uint32_t size = BLKSTORE_BLK_SIZE;
        int ret = posix_memalign((void **) &ptr, 4096, size); // TODO: Align based on hw needs instead of 4k
        if (ret != 0) {
            throw std::bad_alloc();
        }
        memset(ptr, 0, size);
        homeds::MemVector< BLKSTORE_BLK_SIZE > &mvec = only_in_mem_buff->get_memvec_mutable();
        mvec.set(ptr, size, 0);
    }


    const intrusive_ptr<Buffer> &get_only_in_mem_buff() const {
        return only_in_mem_buff;
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
        bool inserted = m_cache->insert(*out_blkid, static_pointer_cast< CacheBuffer< BlkId>>(ibuf),
                                        (boost::intrusive_ptr< CacheBuffer< BlkId>> *) &out_bbuf);
        //(const boost::intrusive_ptr< CacheBuffer<BlkId> >)ibuf, &out_bbuf);

        // TODO: Raise an exception if we are not able to insert - instead of assert
        assert(inserted);

        return ibuf;
    }

    /* Free the block previously allocated. Blkoffset refers to number of blks to skip in the BlkId and
     * nblks refer to the total blks from offset to free. This method returns a optional array of new
     * BlkIds - max of 2 in case complete BlkIds are not free. If it is single blk, it returns no value */
    boost::optional< std::array< BlkId, 2>> free_blk(const BlkId &bid, boost::optional< uint8_t > blkoffset,
                                                     boost::optional< uint8_t > nblks) {
        boost::intrusive_ptr< Buffer > erased_buf;
        boost::optional< std::array< BlkId, 2>> ret_arr;

        // Check if its a full element freed. In that case remove the element in the cache and free it up
        if ((blkoffset.get_value_or(0) == 0) && ((nblks == boost::none) || (nblks == bid.get_nblks()))) {
            m_cache->erase(bid, (boost::intrusive_ptr< CacheBuffer< BlkId>> *) &erased_buf);
            m_vdev.free_blk(bid);
            return boost::none;
        }

        // Not the entire block is freed. Remove the entire entry from cache and split into possibly 2 entries
        // and insert it.
        if (m_cache->erase(bid, (boost::intrusive_ptr< CacheBuffer< BlkId>> *) &erased_buf)) {
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

        BlkId tmp_bid(bid.get_id() + blkoffset.get(), bid.get_nblks(), bid.get_chunk_num());
        m_vdev.free_blk(tmp_bid);

        return ret_arr;
    }

    /* Allocate a new block and write the contents to the allocated block and return the blkbuffer */
    boost::intrusive_ptr< BlkBuffer > alloc_and_write(homeds::blob &blob, blk_alloc_hints &hints, 
							struct blkstore_req<Buffer> *req) {
        // First allocate the blk id based on the hints
        BlkId bid;
        m_vdev.alloc_blk(round_off(blob.size, BLKSTORE_BLK_SIZE), hints, &bid);

        // Insert the entry into the cache and then write to the device.
        return write(bid, blob, req);
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

    boost::intrusive_ptr< BlkBuffer > write(BlkId &bid, homeds::blob &blob, struct blkstore_req<Buffer> *req) {
        // First try to create/insert a record for this blk id in the cache. If it already exists, it will simply
        // upvote the item.
        boost::intrusive_ptr< BlkBuffer > bbuf;
	write_cnt.fetch_add(1, memory_order_relaxed);
	Clock::time_point cache_startTime = Clock::now();
	uint8_t *ptr;
        bool inserted = m_cache->insert(bid, blob, 0 /* value_offset */,
                                        (boost::intrusive_ptr< CacheBuffer<BlkId> > *)&bbuf);
	cache_write_time.fetch_add(get_elapsed_time(cache_startTime), memory_order_relaxed);

        // TODO: Raise an exception if we are not able to insert - instead of assert
        assert(inserted);

	req->write_bbuf = bbuf;
        // Now write data to the device
	Clock::time_point write_startTime = Clock::now();
        m_vdev.write(bid, bbuf->get_memvec(), req);
	// TODO: rishabh, need to check the return status
	write_time += get_elapsed_time(write_startTime);
        return bbuf;
    }

    void print_perf_cnts() {
	printf("cache time %lu ns\n", cache_write_time/write_cnt);
	printf("physical device write time %lu ns\n", write_time/write_cnt);
	if (read_cnt != 0) {
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
    void write(BlkId &bid, boost::intrusive_ptr< Buffer > in_buf, struct blkstore_req<Buffer> *req) {
        m_vdev.write(bid, in_buf->get_memvec(), req);
    }

    /* Read the data for given blk id and size. This method allocates the required memory if not present in the cache
     * and returns an smart ptr to the Buffer */
    boost::intrusive_ptr< Buffer > read(BlkId &bid, uint32_t offset, uint32_t size, 
							struct blkstore_req<Buffer> *req) {
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
            bbuf = homeds::ObjectAllocator< Buffer >::make_object();
            bbuf->set_key(bid);
        } else {
            cache_hit++;
        }

        uint32_t size_to_read = size;
        homeds::MemVector<BLKSTORE_BLK_SIZE>::cursor_t c;
	req->missing_piece_cnt = 0;
	req->read_bbuf = bbuf;
	req->cache_found = cache_found;
	req->read_buf_list.push_back(bbuf);
        
	while (size_to_read > 0) {
            boost::optional< homeds::MemPiece<BLKSTORE_BLK_SIZE> &> missing_mp =
                    bbuf->get_memvec_mutable().fill_next_missing_piece(c, size, cur_offset);
            if (!missing_mp) {
                // We don't have any missing pieces, so we are done reading the contents
                break;
            }

            cur_offset = missing_mp->end_offset();

            // Create a new block of memory for the missing piece
            uint8_t *ptr;
            int ret = posix_memalign((void **) &ptr, 4096,
                                     missing_mp->size()); // TODO: Align based on hw needs instead of 4k
            if (ret != 0) {
                throw std::bad_alloc();
            }
            missing_mp.get().set_ptr(ptr);

            // Read the missing piece from the device
            BlkId tmp_bid(bid.get_id() + missing_mp->offset()/BLKSTORE_BLK_SIZE,
                          missing_mp->size()/BLKSTORE_BLK_SIZE, bid.get_chunk_num());
	    /* TODO: we should first find number the missing pieces before calling read.
	     * it can cause incomplete reads for sync IOs.
	     */
	    req->missing_piece_cnt++;
            m_vdev.read(tmp_bid, missing_mp.get(), req);
	    read_cnt.fetch_add(1, memory_order_relaxed);
        LOGINFO("BlkStore-Read-Sent:{}",read_cnt);
            size_to_read -= missing_mp->size();
        }

	    if (req->missing_piece_cnt == 0) {
		    assert(cache_found);
            m_comp_cb(dynamic_cast< struct blkstore_req<Buffer>* >(req));
	    }
        if (!cache_found && req->isSyncCall) {
            boost::intrusive_ptr< Buffer > new_bbuf;
            bool inserted = m_cache->insert(bbuf->get_key(),
                    static_pointer_cast<CacheBuffer<BlkId>>(bbuf),
                    (boost::intrusive_ptr< CacheBuffer<BlkId> > *)&new_bbuf);
            if (!inserted) {
                // Between get and insert, other thread tried the same thing and inserted into the cache. Lets use
                // that entry in cache and free up the memory
                bbuf = new_bbuf;
            }			
        }
	    return bbuf;
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
    BlkStoreCacheType m_cache_type;
    VirtualDev<BAllocator, RoundRobinDeviceSelector> m_vdev;
    atomic<uint64_t> write_cnt;
    atomic<uint64_t> cache_write_time;
    atomic<uint64_t> cache_read_time;
    atomic<uint64_t> cache_hit;
    atomic<uint64_t> read_cnt;
    atomic<uint64_t> read_complete_cnt;
    atomic<uint64_t> write_time;
    comp_callback m_comp_cb;
    boost::intrusive_ptr< Buffer > only_in_mem_buff;
};

}
#endif //OMSTORE_BLKSTORE_HPP
