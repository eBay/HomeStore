#ifndef WRITEBACK_CACHE_HPP
#define WRITEBACK_CACHE_HPP

#include "cache/cache.h"
#include <vector>
#include <error/error.h>
#include <device/virtual_dev.hpp>

extern bool vol_test_enable;

namespace homestore {
using namespace std;

enum writeback_req_state {
    WB_REQ_INIT = 0, /* init */
    WB_REQ_SCANNING, /* scanning the dependent_req_q */
    WB_REQ_PENDING, /* waiting for dependent req to complete */
    WB_REQ_SENT, /* send to blksore to write */
    WB_REQ_COMPL,/* completed */
};

struct writeback_req;
typedef std::function< void (boost::intrusive_ptr<writeback_req> req, 
        std::error_condition status) > blkstore_callback;
struct writeback_req : virtualdev_req {

    mutex mtx;
    blkstore_callback *blkstore_cb;
    
    /* Queue of the requests which should be written only after this req is written. 
     * Reason of using stl over boost intrusive is that one request can be 
     * shared with multiple queues.
     */
    std::deque<boost::intrusive_ptr<writeback_req>> req_q;

    /* issue this request when the cnt become zero */
    atomic<int> dependent_cnt;
#ifndef NDEBUG
    /* Queue of the requests which should be written before this req is written */
    std::vector<boost::intrusive_ptr<writeback_req>> dependent_req_q;
#endif

    int mem_gen_cnt;
    writeback_req_state state;
    std::error_condition status;
    homeds::MemVector< BLKSTORE_BLK_SIZE > memvec;
    
    writeback_req(): req_q(), dependent_cnt(0),
#ifndef NDEBUG
    dependent_req_q(),
#endif
    state(WB_REQ_INIT), status(no_error) {};

    virtual ~writeback_req() {
        assert(dependent_req_q.empty());
        assert(state == WB_REQ_COMPL || state == WB_REQ_INIT);
    }
};

template <typename Buffer>
struct WriteBackCacheBuffer : public CacheBuffer< Buffer > {
    mutex mtx;
    int gen_cnt;
    /* TODO, it will be removed, once safe_evict is implmented */
    bool is_evicted;

    /* latest pending req on this buffer */
    boost::intrusive_ptr<writeback_req> last_pending_req;
    /* latest req on which error is set */
    boost::intrusive_ptr<writeback_req> error_req;

#ifndef NDEBUG
    /* Queue of the pending requests on this buffer */
    std::deque<boost::intrusive_ptr<writeback_req>> pending_req_q;
#endif
    
    WriteBackCacheBuffer(): gen_cnt(0), is_evicted(false), last_pending_req(nullptr), error_req(nullptr) 
#ifndef NDEBUG
    ,pending_req_q()
#endif
    {};

    virtual ~WriteBackCacheBuffer() {
        error_req = NULL;
        assert(last_pending_req == nullptr);
#ifndef NDEBUG
        assert(pending_req_q.empty());
#endif
    }
};

template <typename Buffer>
class WriteBackCache {

    blkstore_callback m_blkstore_write_cb;
    blkstore_callback m_blkstore_free_cb;
    Cache< BlkId > *m_cache;
public:

    WriteBackCache(Cache< BlkId > *cache, blkstore_callback blkstore_write_cb, 
                    blkstore_callback blkstore_free_cb) :
                    m_blkstore_write_cb(blkstore_write_cb), 
                    m_blkstore_free_cb(blkstore_free_cb),
                    m_cache(cache) {};
    
    void writeBack_write_internal(boost::intrusive_ptr<CacheBuffer<Buffer>> cache_buf,
              boost::intrusive_ptr<writeback_req> req, 
              std::deque<boost::intrusive_ptr<writeback_req>> &dependent_req_q) {
    
        boost::intrusive_ptr<WriteBackCacheBuffer<Buffer>> buf = 
            boost::static_pointer_cast<WriteBackCacheBuffer<Buffer>>(cache_buf);
        
        assert(req->state == WB_REQ_INIT);
        req->state = WB_REQ_SCANNING;
        error_condition status = no_error;

#ifndef NDEBUG
        /* only for debugging */
        for (auto it = dependent_req_q.begin(); it != dependent_req_q.end(); ++it) {
            assert((*it).get() != nullptr);
            req->dependent_req_q.push_back(*it);
        }
#endif       
        
        /* It won't race with another write as user should have taken a write lock
         * before updating this buffer. But it can race with the completion. 
         */
        std::unique_lock<std::mutex> buf_mtx(buf->mtx);
        req->mem_gen_cnt = buf->gen_cnt;
        req->memvec.copy(buf->get_memvec());
        
        /* every write should have the different gen_cnt then the last write req sent */
        assert(!buf->last_pending_req || 
               req->mem_gen_cnt > buf->last_pending_req->mem_gen_cnt);
        buf->last_pending_req = req;
#ifndef NDEBUG
        buf->pending_req_q.push_back(req);
#endif
        buf_mtx.unlock();
        
        for (auto it = dependent_req_q.begin(); it != dependent_req_q.end(); ++it) {
            std::unique_lock<std::mutex> mtx((*it)->mtx);
            if ((*it)->state != WB_REQ_COMPL) {
                /* insert it into dependent req queue */
                (*it)->req_q.push_back(req);
                req->dependent_cnt++;
            } else if ((*it)->state == WB_REQ_COMPL) {
                if ((*it)->status != no_error) {
                    status = (*it)->status;
                    break;
                }
            }
        }
    
        std::unique_lock<std::mutex> req_mtx(req->mtx);
        if (status != no_error || req->status != no_error) {
           req->status = ((status == no_error) ? req->status : homestore_error::dependent_req_failed);
           req->state = WB_REQ_SENT;
           req_mtx.unlock();
           (*(req->blkstore_cb))(req, req->status);
        } else if (req->dependent_cnt == 0) {
            req->state = WB_REQ_SENT;
            req_mtx.unlock();
            (*(req->blkstore_cb))(req, req->status);
        } else {
            req->state = WB_REQ_PENDING;
            req_mtx.unlock();
        }
        return;
    }

    void writeBack_completion(boost::intrusive_ptr<CacheBuffer<Buffer>> cache_buf, 
                              boost::intrusive_ptr<writeback_req> req, 
                              std::error_condition status) {
        
        boost::intrusive_ptr<WriteBackCacheBuffer<Buffer>> buf = 
            boost::static_pointer_cast<WriteBackCacheBuffer<Buffer>>(cache_buf);
        
        /* invalidate the buffer if request is failed */
        std::unique_lock<std::mutex> buf_mtx(buf->mtx);

        assert(buf->gen_cnt >= req->mem_gen_cnt);
        /* checking the gen cnt and free the buffer
         * shoud be atomic operation.
         */
        if (buf->gen_cnt != req->mem_gen_cnt) {
             /* This buffer is pointed to different memvec.
              * Free the memvec pointed by this req.
              */
             homeds::blob outb;
             req->memvec.get(&outb);
             free(outb.bytes);
        }
#ifndef NDEBUG
        bool found = false;
        for (auto it = buf->pending_req_q.begin(); it < buf->pending_req_q.end(); ++it) {
            if (*it == req) {
                it = buf->pending_req_q.erase(it);                
                found = true;
                break;
            }
        }
        assert(found);
#endif
        if (req == buf->last_pending_req) {
            /* it is the last request which is sent on this buffer */
            buf->last_pending_req = nullptr;
        }

        if (status != no_error && (!buf->is_evicted)) {
            buf->error_req = req;
            buf->is_evicted = true;
            /* evict it from the cache. New read will get the latest buf. Thread which
             * have already read and is waiting on a lock will get the stale buffer. All
             * subsequent writes will fail and also writes to its child will fail until
             * it reload the node from a disk.
             * TODO:it is better to fix cache and call safe_evict.
             */
            m_cache->erase(cache_buf);
        }
        buf_mtx.unlock();
       
        /* set status in the request */
        std::unique_lock<std::mutex> req_mtx(req->mtx);
        assert(req->state == WB_REQ_SENT);
        req->state = WB_REQ_COMPL;
        req->status = status;
#ifndef NDEBUG
        while (!req->dependent_req_q.empty()) {
            req->dependent_req_q.pop_back();
        }
#endif
        req_mtx.unlock();
        
        /* XXX: should we take a lock as no one should be adding in the queue once it is completed. */
        /* process the dependent requests */
        while (!req->req_q.empty()) {
            auto depend_req = req->req_q.back();
            req->req_q.pop_back();
            std::unique_lock<std::mutex> mtx(depend_req->mtx);

            depend_req->dependent_cnt--;
            assert(depend_req->dependent_cnt >= 0);
            if (depend_req->state != WB_REQ_PENDING) {
                assert(depend_req->state == WB_REQ_SCANNING || 
                        depend_req->status != no_error);
                continue;
            }
            if (depend_req->dependent_cnt == 0 || status != no_error) {
                depend_req->state = WB_REQ_SENT;
                depend_req->status = ((status == no_error) ? no_error : 
                                         homestore_error::dependent_req_failed);
                mtx.unlock();
                (*(depend_req->blkstore_cb))(depend_req, depend_req->status);
            }
        }
    }

    boost::intrusive_ptr<writeback_req> writeBack_cache_read(
                         boost::intrusive_ptr<CacheBuffer<Buffer>> cache_buf,
                         bool is_write_modifiable) {
 
        boost::intrusive_ptr<WriteBackCacheBuffer<Buffer>> buf = 
            boost::static_pointer_cast<WriteBackCacheBuffer<Buffer>>(cache_buf);
        boost::intrusive_ptr<writeback_req> req;
        std::unique_lock<std::mutex> buf_mtx(buf->mtx);
        if (buf->is_evicted) {
            req = buf->error_req;
        } else {
            req = buf->last_pending_req;
        }
        if (is_write_modifiable) {
            if (buf->last_pending_req && buf->gen_cnt == 
                                        buf->last_pending_req->mem_gen_cnt) {
                /* copy the buffer to avoid getting it modified while it is
                 * sent to the disk.
                 */
                assert(buf->last_pending_req->state != WB_REQ_COMPL);
                homeds::blob outb;
                (buf->get_memvec()).get(&outb);
                /* dependent writes are not supported on buffer larger then 1
                 * page size.
                 */
                assert((buf->get_memvec()).npieces() == 1);
                void *mem;
                if (0 == posix_memalign((void **) &mem, 4096, outb.size)) {
                   /* outb.bytes get freed when last_pending_req is completed */
                   memcpy(mem, outb.bytes, outb.size);
                   outb.bytes = (uint8_t *)mem;
                   (buf->get_memvec_mutable()).set(outb);
                   buf->gen_cnt++;
                }
            }
        }
        buf_mtx.unlock();
        return req;
    }

    void write_blk(boost::intrusive_ptr<CacheBuffer<Buffer>> cache_buf, 
                   boost::intrusive_ptr<writeback_req> req, 
                  std::deque<boost::intrusive_ptr<writeback_req>> &dependent_req_q) {
        req->blkstore_cb = &m_blkstore_write_cb;
        writeBack_write_internal(cache_buf, req, dependent_req_q); 
    }

    void free_blk(boost::intrusive_ptr<CacheBuffer<Buffer>> cache_buf, 
                  boost::intrusive_ptr<writeback_req> req, 
                  std::deque<boost::intrusive_ptr<writeback_req>> &dependent_req_q) {
        boost::intrusive_ptr<WriteBackCacheBuffer<Buffer>> buf = 
            boost::static_pointer_cast<WriteBackCacheBuffer<Buffer>>(cache_buf);
        req->blkstore_cb = &m_blkstore_free_cb;
        /* there is no use case in volume layer where blkid is freed while 
         * write req is pending on it. Use case exist only in btree but it read
         * before freeing it which helps in creating a dependency chain.
         */
#ifndef NDEBUG     
        if (vol_test_enable) { 
            auto req = writeBack_cache_read(cache_buf, true);
            if (req != nullptr) {
                dependent_req_q.push_back(req);
            }
        }
#endif
        writeBack_write_internal(cache_buf, req, dependent_req_q); 
    }
    
    const homeds::MemVector< BLKSTORE_BLK_SIZE > 
            &writeback_get_memvec(boost::intrusive_ptr<writeback_req> req) const {
        return req->memvec;
    }
};
}

#endif
