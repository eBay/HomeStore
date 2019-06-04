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
    WB_REQ_PENDING,  /* waiting for dependent req to complete */
    WB_REQ_SENT,     /* send to blksore to write */
    WB_REQ_COMPL,    /* completed */
};

struct writeback_req;
typedef boost::intrusive_ptr< writeback_req > writeback_req_ptr;

typedef std::function< void(const writeback_req_ptr& req, std::error_condition status) > blkstore_callback;
#define to_wb_req(req) boost::static_pointer_cast< writeback_req >(req)

struct writeback_req : public virtualdev_req {
    mutex              mtx;
    blkstore_callback* blkstore_cb;

    /* Queue of the requests which should be written only after this req is written.
     * Reason of using stl over boost intrusive is that one request can be
     * shared with multiple queues.
     */
    std::deque< writeback_req_ptr > req_q;

    /* issue this request when the cnt become zero */
    std::atomic< int > dependent_cnt;

#ifndef NDEBUG
    /* Queue of the requests which should be written before this req is written */
    std::vector< writeback_req_ptr > dependent_req_q;
#endif

    int                  mem_gen_cnt;
    writeback_req_state  state;
    std::error_condition status;
    homeds::MemVector    memvec;
    Clock::time_point    cache_start_time; // Start time to put the wb cache to the request

    static boost::intrusive_ptr< writeback_req > make_request() {
        return boost::intrusive_ptr< writeback_req >(homeds::ObjectAllocator< writeback_req >::make_object());
    }

    virtual void free_yourself() override { homeds::ObjectAllocator< writeback_req >::deallocate(this); }
    
    virtual ~writeback_req() {
        assert(dependent_req_q.empty());
        assert(state == WB_REQ_COMPL || state == WB_REQ_INIT);
    }

protected:
    friend class homeds::ObjectAllocator< writeback_req >;
    writeback_req() :
            req_q(),
            dependent_cnt(0),
#ifndef NDEBUG
            dependent_req_q(),
#endif
            state(WB_REQ_INIT),
            status(no_error){};
};

template < typename K >
struct WriteBackCacheBuffer : public CacheBuffer< K > {
    mutex mtx;
    int   gen_cnt;
    /* TODO, it will be removed, once safe_evict is implmented */

    writeback_req_ptr last_pending_req;     /* latest pending req on this buffer */
    writeback_req_ptr error_req;            /* latest req on which error is set */

#ifndef NDEBUG
    /* Queue of the pending requests on this buffer */
    std::deque< writeback_req_ptr > pending_req_q;
#endif

    WriteBackCacheBuffer() :
            gen_cnt(0),
            last_pending_req(nullptr),
            error_req(nullptr)
#ifndef NDEBUG
            ,
            pending_req_q()
#endif
                {};

    virtual ~WriteBackCacheBuffer() {
        error_req = NULL;
        assert(last_pending_req == nullptr);
#ifndef NDEBUG
        assert(pending_req_q.empty());
#endif
    }
    friend void intrusive_ptr_add_ref(WriteBackCacheBuffer< K >* buf) { intrusive_ptr_add_ref((CacheBuffer< K >*)buf); }

    friend void intrusive_ptr_release(WriteBackCacheBuffer< K >* buf) { intrusive_ptr_release((CacheBuffer< K >*)buf); }
};

template < typename K >
class WriteBackCache {
private:
    blkstore_callback m_blkstore_write_cb;
    blkstore_callback m_blkstore_free_cb;
    Cache< K >*   m_cache;

public:
    WriteBackCache(Cache< K >* cache, blkstore_callback blkstore_write_cb, blkstore_callback blkstore_free_cb) :
            m_blkstore_write_cb(blkstore_write_cb),
            m_blkstore_free_cb(blkstore_free_cb),
            m_cache(cache){};

    static boost::intrusive_ptr< WriteBackCacheBuffer< K > > to_wbc_buf(
            const boost::intrusive_ptr< CacheBuffer< K > >& cache_buf) {
        return boost::static_pointer_cast< WriteBackCacheBuffer< K > >(cache_buf);
    }

    void writeBack_write_internal(const boost::intrusive_ptr< CacheBuffer< K > >& cache_buf,
                                  const writeback_req_ptr& wb_req,
                                  std::deque< writeback_req_ptr >& dependent_req_q) {
        //auto wbc_buf = to_wbc_buf(cache_buf);
        auto& wbc_buf = (boost::intrusive_ptr< WriteBackCacheBuffer< K > > &)cache_buf;

        assert(wb_req->state == WB_REQ_INIT);
        wb_req->state = WB_REQ_SCANNING;
        error_condition status = no_error;

#ifndef NDEBUG
        /* only for debugging */
        for (auto it = dependent_req_q.begin(); it != dependent_req_q.end(); ++it) {
            assert((*it).get() != nullptr);
            wb_req->dependent_req_q.push_back(*it);
        }
#endif

        /* It won't race with another write as user should have taken a write lock
         * before updating this buffer. But it can race with the completion.
         */
        std::unique_lock< std::mutex > buf_mtx(wbc_buf->mtx);
        wb_req->mem_gen_cnt = wbc_buf->gen_cnt;
        wb_req->memvec.copy(wbc_buf->get_memvec());

        /* every write should have the different gen_cnt then the last write req sent */
        assert(!wbc_buf->last_pending_req || (wb_req->mem_gen_cnt > wbc_buf->last_pending_req->mem_gen_cnt));
        wbc_buf->last_pending_req = wb_req;
#ifndef NDEBUG
        wbc_buf->pending_req_q.push_back(wb_req);
#endif
        buf_mtx.unlock();

        for (auto it = dependent_req_q.begin(); it != dependent_req_q.end(); ++it) {
            std::unique_lock< std::mutex > mtx((*it)->mtx);
            if ((*it)->state != WB_REQ_COMPL) {
                /* insert it into dependent req queue */
                (*it)->req_q.push_back(wb_req);
                wb_req->dependent_cnt++;
            } else if ((*it)->state == WB_REQ_COMPL) {
                if ((*it)->status != no_error) {
                    status = (*it)->status;
                    break;
                }
            }
        }

        std::unique_lock< std::mutex > req_mtx(wb_req->mtx);
        if (status != no_error || wb_req->status != no_error) {
            wb_req->status = ((status == no_error) ? wb_req->status : homestore_error::dependent_req_failed);
            wb_req->state = WB_REQ_SENT;
            req_mtx.unlock();
            (*(wb_req->blkstore_cb))(wb_req, wb_req->status);
        } else if (wb_req->dependent_cnt == 0) {
            wb_req->state = WB_REQ_SENT;
            req_mtx.unlock();
            (*(wb_req->blkstore_cb))(wb_req, wb_req->status);
        } else {
            wb_req->state = WB_REQ_PENDING;
            req_mtx.unlock();
        }
        return;
    }

    void writeBack_completion(const boost::intrusive_ptr< CacheBuffer< K > >& cache_buf,
                              const writeback_req_ptr& wb_req, std::error_condition status) {
        auto& wbc_buf = (boost::intrusive_ptr< WriteBackCacheBuffer< K > > &)cache_buf;

        /* invalidate the buffer if request is failed */
        std::unique_lock< std::mutex > buf_mtx(wbc_buf->mtx);

        assert(wbc_buf->gen_cnt >= wb_req->mem_gen_cnt);
        /* checking the gen cnt and free the buffer
         * shoud be atomic operation.
         */
        if (wbc_buf->gen_cnt != wb_req->mem_gen_cnt) {
            /* This buffer is pointed to different memvec.
             * Free the memvec pointed by this req.
             */
            homeds::blob outb;
            wb_req->memvec.get(&outb);
            free(outb.bytes);
        }
#ifndef NDEBUG
        bool found = false;
        for (auto it = wbc_buf->pending_req_q.begin(); it < wbc_buf->pending_req_q.end(); ++it) {
            if (*it == wb_req) {
                it = wbc_buf->pending_req_q.erase(it);
                found = true;
                break;
            }
        }
        assert(found);
#endif
        if (wb_req == wbc_buf->last_pending_req) {
            /* it is the last request which is sent on this buffer */
            wbc_buf->last_pending_req = nullptr;
        }

        if (status != no_error) {
            assert(wbc_buf->error_req == nullptr);
            wbc_buf->error_req = wb_req;
            /* evict it from the cache. */
            m_cache->safe_erase(cache_buf, nullptr);
        }
        buf_mtx.unlock();

        /* set status in the request */
        std::unique_lock< std::mutex > req_mtx(wb_req->mtx);
        assert(wb_req->state == WB_REQ_SENT);
        wb_req->state = WB_REQ_COMPL;
        wb_req->status = status;
#ifndef NDEBUG
        while (!wb_req->dependent_req_q.empty()) {
            wb_req->dependent_req_q.pop_back();
        }
#endif
        req_mtx.unlock();

        /* XXX: should we take a lock as no one should be adding in the queue once it is completed. */
        /* process the dependent requests */
        while (!wb_req->req_q.empty()) {
            auto depend_req = wb_req->req_q.back();
            wb_req->req_q.pop_back();
            std::unique_lock< std::mutex > mtx(depend_req->mtx);

            depend_req->dependent_cnt--;
            assert(depend_req->dependent_cnt >= 0);
            if (depend_req->state != WB_REQ_PENDING) {
                assert(depend_req->state == WB_REQ_SCANNING || depend_req->status != no_error);
                continue;
            }
            if (depend_req->dependent_cnt == 0 || status != no_error) {
                depend_req->state = WB_REQ_SENT;
                depend_req->status = ((status == no_error) ? no_error : homestore_error::dependent_req_failed);
                mtx.unlock();
                (*(depend_req->blkstore_cb))(depend_req, depend_req->status);
            }
        }
    }

    writeback_req_ptr writeBack_refresh_buf(const boost::intrusive_ptr< CacheBuffer< K > >& cache_buf,
                                           bool is_write_modifiable) {
        auto& wbc_buf = (boost::intrusive_ptr< WriteBackCacheBuffer< K > > &)cache_buf;

        writeback_req_ptr req;
        std::unique_lock< std::mutex > buf_mtx(wbc_buf->mtx);
        if (wbc_buf->error_req != nullptr) {
            /* previous request on this buffer is failed. All subsequent writes
             * need to be failed until it is evicted.
             */
            req = wbc_buf->error_req;
        } else {
            req = wbc_buf->last_pending_req;
        }
        if (is_write_modifiable) {
            if (wbc_buf->last_pending_req && wbc_buf->gen_cnt == wbc_buf->last_pending_req->mem_gen_cnt) {
                /* copy the buffer to avoid getting it modified while it is
                 * sent to the disk.
                 */
                assert(wbc_buf->last_pending_req->state != WB_REQ_COMPL);
                homeds::blob outb;
                (wbc_buf->get_memvec()).get(&outb);
                /* dependent writes are not supported on buffer larger then 1
                 * page size.
                 */
                assert((wbc_buf->get_memvec()).npieces() == 1);
                void* mem;
                if (0 == posix_memalign((void**)&mem, 4096, outb.size)) {
                    /* outb.bytes get freed when last_pending_req is completed */
                    memcpy(mem, outb.bytes, outb.size);
                    outb.bytes = (uint8_t*)mem;
                    (wbc_buf->get_memvec()).set(outb);
                    wbc_buf->gen_cnt++;
                }
            }
        }
        buf_mtx.unlock();
        return req;
    }

    void write_blk(const boost::intrusive_ptr< CacheBuffer< K > >& cache_buf,
                   const writeback_req_ptr& wb_req,
                   std::deque< writeback_req_ptr >& dependent_req_q) {
        wb_req->blkstore_cb = &m_blkstore_write_cb;
        writeBack_write_internal(cache_buf, wb_req, dependent_req_q);
    }

    void free_blk(const boost::intrusive_ptr< CacheBuffer< K > >& cache_buf,
                  const writeback_req_ptr& wb_req,
                  std::deque< writeback_req_ptr >& dependent_req_q) {
        wb_req->blkstore_cb = &m_blkstore_free_cb;

        /* there is no use case in volume layer where blkid is freed while
         * write req is pending on it. Use case exist only in btree but it read
         * before freeing it which helps in creating a dependency chain.
         */
#ifndef NDEBUG
        if (vol_test_enable) {
            auto req = writeBack_refresh_buf(cache_buf, true);
            if (req != nullptr) {
                dependent_req_q.push_back(req);
            }
        }
#endif
        writeBack_write_internal(cache_buf, wb_req, dependent_req_q);
    }

    const homeds::MemVector& writeback_get_memvec(writeback_req_ptr req) const {
        return req->memvec;
    }
};
} // namespace homestore

#endif
