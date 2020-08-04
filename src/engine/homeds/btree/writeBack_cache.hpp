#ifndef WRITEBACK_CACHE_HPP
#define WRITEBACK_CACHE_HPP

#include <vector>
#include <engine/common/error.h>
#include <engine/blkstore/blkstore.hpp>
#include <engine/homeds/btree/btree_internal.h>
#include <wisr/wisr_ds.hpp>
#include <utility/thread_factory.hpp>
#include "engine/homestore.hpp"

#define MAX_DIRTY_BUF 100

#define wb_cache_buffer_t WriteBackCacheBuffer< K, V, InteriorNodeType, LeafNodeType >

namespace homeds {
namespace btree {
#define SSDBtreeNode BtreeNode< btree_store_type::SSD_BTREE, K, V, InteriorNodeType, LeafNodeType >
using namespace std;

enum writeback_req_state {
    WB_REQ_INIT = 0, /* init */
    WB_REQ_WAITING,  /* waiting for cp */
    WB_REQ_SENT,     /* send to blksore to write */
    WB_REQ_COMPL,    /* completed */
};

#define btree_blkstore_t homestore::BlkStore< homestore::VdevFixedBlkAllocatorPolicy, wb_cache_buffer_t >
#define writeback_req_t wb_cache_buffer_t::writeback_req
#define writeback_req_ptr boost::intrusive_ptr< typename writeback_req_t >
#define to_wb_req(req) boost::static_pointer_cast< typename writeback_req_t >(req)
#define wb_cache_t WriteBackCache< K, V, InteriorNodeType, LeafNodeType >
#define MAX_CP_CNT 2

/* The class BtreeBuffer represents the buffer type that is used to interact with the BlkStore. It will have
 * all the SSD Btree Node declarative type. Hence in-memory representation of this buffer is as follows
 *
 *   ****************Cache Buffer************************
 *   *    ****************Cache Record***************   *
 *   *    *   ************Hash Node**************   *   *
 *   *    *   * Singly Linked list of hash node *   *   *
 *   *    *   ***********************************   *   *
 *   *    *******************************************   *
 *   * BlkId                                            *
 *   * Memvector of actual buffer                       *
 *   * Usage Reference counter                          *
 *   ****************************************************
 *   ************** Transient Header ********************
 *   * Upgraders count                                  *
 *   * Reader Write Lock                                *
 *   ****************************************************
 */
template < typename K, typename V, btree_node_type InteriorNodeType, btree_node_type LeafNodeType >
struct WriteBackCacheBuffer : public CacheBuffer< homestore::BlkId > {

    /******************************************** writeback_req *****************************/
    struct writeback_req : public homestore::blkstore_req< wb_cache_buffer_t > {

        typedef std::function< void(const writeback_req_ptr& req, std::error_condition status) > blkstore_callback;

        mutex mtx;
        writeback_req_state state;
        BlkId bid;
        btree_cp_id_ptr cp_id;
        void* wb_cache;
        boost::intrusive_ptr< SSDBtreeNode > bn;

        /* Queue of the requests which should be written only after this req is written.
         * Reason of using stl over boost intrusive is that one request can be
         * shared with multiple queues.
         */
        std::deque< writeback_req_ptr > req_q;

        /* issue this request when the cnt become zero */
        std::atomic< int > dependent_cnt;

        boost::intrusive_ptr< homeds::MemVector > m_mem;
        Clock::time_point cache_start_time; // Start time to put the wb cache to the request

        static boost::intrusive_ptr< writeback_req > make_request() {
            return boost::intrusive_ptr< writeback_req >(sisl::ObjectAllocator< writeback_req >::make_object());
        }

        virtual void free_yourself() override { sisl::ObjectAllocator< writeback_req >::deallocate(this); }

        virtual ~writeback_req() { assert(state == WB_REQ_COMPL || state == WB_REQ_INIT); }

    protected:
        friend class sisl::ObjectAllocator< writeback_req >;
        writeback_req() : state(WB_REQ_INIT), bid(0), cp_id(nullptr), req_q(), dependent_cnt(1), m_mem(nullptr){};
    };

    /*************************************************** WriteBackCacheBuffer *******************************/

    btree_cp_id_ptr cp_id = nullptr;
    writeback_req_ptr req[MAX_CP_CNT];

    static wb_cache_buffer_t* make_object() { return sisl::ObjectAllocator< SSDBtreeNode >::make_object(); }
    virtual void free_yourself() override { sisl::ObjectAllocator< SSDBtreeNode >::deallocate((SSDBtreeNode*)this); }

    WriteBackCacheBuffer(){};
    virtual ~WriteBackCacheBuffer() = default;

    virtual void init() override {
        /* Note : it is called under cache lock to prevent multiple threads to call init. And init function
         * internally also try to take the cache lock to access cache to update in memory structure. So
         * we have to be careful in taking any lock inside this function.
         */
        ((SSDBtreeNode*)this)->init();
    }

    friend void intrusive_ptr_add_ref(wb_cache_buffer_t* buf) {
        intrusive_ptr_add_ref((CacheBuffer< homestore::BlkId >*)buf);
    }
    friend void intrusive_ptr_release(wb_cache_buffer_t* buf) {
        intrusive_ptr_release((CacheBuffer< homestore::BlkId >*)buf);
    }
};

template < typename K, typename V, btree_node_type InteriorNodeType, btree_node_type LeafNodeType >
class WriteBackCache {
private:
    /* TODO :- need to have concurrent list */
    std::unique_ptr< sisl::ThreadVector< writeback_req_ptr > > m_req_list[MAX_CP_CNT];
    homestore::blkid_list_ptr m_free_list[MAX_CP_CNT];
    atomic< uint64_t > m_dirty_buf_cnt[MAX_CP_CNT];
    cp_comp_callback m_cp_comp_cb;
    trigger_cp_callback m_trigger_cp_cb;
    uint64_t m_free_list_cnt = 0;
    static btree_blkstore_t* m_blkstore;
    static std::atomic< uint64_t > m_hs_dirty_buf_cnt;
#define WB_CACHE_THREADS 2
    static iomgr::io_thread_t m_thread_ids[WB_CACHE_THREADS];
    static std::atomic< int > m_thread_indx;

public:
    WriteBackCache(){};
    WriteBackCache(void* blkstore, uint64_t align_size, cp_comp_callback cb, trigger_cp_callback trigger_cp_cb) {
        for (int i = 0; i < MAX_CP_CNT; ++i) {
            m_free_list[i] = std::make_shared< sisl::ThreadVector< BlkId > >();
            m_req_list[i] = std::make_unique< sisl::ThreadVector< writeback_req_ptr > >();
            m_dirty_buf_cnt[i] = 0;
        }
        m_cp_comp_cb = cb;
        m_blkstore = (btree_blkstore_t*)blkstore;
        m_blkstore->attach_compl(wb_cache_t::writeBack_completion);
        m_trigger_cp_cb = trigger_cp_cb;
        static std::once_flag flag1;
        std::call_once(flag1, ([]() {
                           for (int i = 0; i < WB_CACHE_THREADS; ++i) {
                               /* XXX : there can be race condition when message is sent before run_io_loop is called */
                               auto sthread = sisl::named_thread("wbcache_flusher", [i]() {
                                   iomanager.run_io_loop(false, nullptr, ([i](bool is_started) {
                                                             if (is_started) {
                                                                 wb_cache_t::m_thread_ids[i] =
                                                                     iomanager.iothread_self();
                                                             }
                                                         }));
                               });
                               sthread.detach();
                           }
                       }));
    }

    ~WriteBackCache() {
        for (uint32_t i = 0; i < MAX_CP_CNT; ++i) {
#ifndef NDEBUG
            assert(m_dirty_buf_cnt[i] == 0);
            assert(m_req_list[i]->size() == 0);
            assert(m_free_list[i]->size() == 0);
#endif
        }
    }

    void prepare_cp(const btree_cp_id_ptr& new_cp_id, const btree_cp_id_ptr& cur_cp_id, bool blkalloc_checkpoint) {
        if (new_cp_id) {
            int cp_cnt = (new_cp_id->cp_cnt) % MAX_CP_CNT;
            assert(m_dirty_buf_cnt[cp_cnt] == 0);
            /* decrement it by all cache threads at the end after writing all pending requests */
            assert(m_req_list[cp_cnt]->size() == 0);
            blkid_list_ptr free_list;
            if (blkalloc_checkpoint || !cur_cp_id) {
                free_list = m_free_list[++m_free_list_cnt % MAX_CP_CNT];
                assert(free_list->size() == 0);
            } else {
                /* we keep accumulating the free blks until blk checkpoint is not taken */
                free_list = cur_cp_id->free_blkid_list;
            }
            new_cp_id->free_blkid_list = free_list;
        }
    }

    /* check if a new cp needs to be triggered because last cp is already completed */
    static void cp_done(trigger_cp_callback cb) {
        if (m_hs_dirty_buf_cnt > MAX_DIRTY_BUF) { cb(); }
    }

    void write(boost::intrusive_ptr< SSDBtreeNode > bn, boost::intrusive_ptr< SSDBtreeNode > dependent_bn,
               const btree_cp_id_ptr& cp_id) {
        int cp_cnt = cp_id->cp_cnt % MAX_CP_CNT;
        assert(!dependent_bn || dependent_bn->req[cp_cnt] != nullptr);
        writeback_req_ptr wbd_req = dependent_bn ? dependent_bn->req[cp_cnt] : nullptr;
        if (!bn->req[cp_cnt]) {
            /* create wb request */
            auto wb_req = writeback_req_t::make_request();
            wb_req->cp_id = cp_id;
            wb_req->m_mem = bn->get_memvec_intrusive();
            wb_req->bn = bn;
            wb_req->bid.set(bn->get_node_id());
            /* we can assume that btree is not destroyed until cp is not completed */
            wb_req->wb_cache = this;
            assert(wb_req->state == WB_REQ_INIT);
            wb_req->state = WB_REQ_WAITING;

            /* update buffer */
            bn->req[cp_cnt] = wb_req;
            bn->cp_id = cp_id;

            /* add it to the list */
            m_req_list[cp_cnt]->push_back(wb_req);

            /* check for dirty buffers cnt */
            m_dirty_buf_cnt[cp_cnt].fetch_add(1);
            auto dirty_buf_cnt = m_hs_dirty_buf_cnt.fetch_add(1);
            if ((dirty_buf_cnt == MAX_DIRTY_BUF)) { m_trigger_cp_cb(); }
        } else {
            assert(bn->req[cp_cnt]->bid.to_integer() == bn->get_node_id());
            if (bn->req[cp_cnt]->m_mem != bn->get_memvec_intrusive()) {
                bn->req[cp_cnt]->m_mem = bn->get_memvec_intrusive();
                assert(bn->req[cp_cnt]->m_mem != nullptr);
            }
        }

        auto wb_req = bn->req[cp_cnt];
        assert(wb_req->state == WB_REQ_WAITING);

        if (wbd_req) {
            std::unique_lock< std::mutex > req_mtx(wbd_req->mtx);
            wbd_req->req_q.push_back(wb_req);
            ++wb_req->dependent_cnt;
        }
    }

    /* We don't want to free the blocks until cp is persisted. Because we use these blocks
     * to recover btree.
     */
    void free_blk(bnodeid_t node_id, const blkid_list_ptr& free_blkid_list) {
        assert(node_id != empty_bnodeid);
        BlkId bid(node_id);

        /*  if cp_id is null then free it only from the cache. */
        m_blkstore->free_blk(bid, boost::none, boost::none, free_blkid_list ? true : false);
        if (free_blkid_list) { free_blkid_list->push_back(bid); }
    }

    btree_status_t refresh_buf(boost::intrusive_ptr< SSDBtreeNode > bn, bool is_write_modifiable,
                               const btree_cp_id_ptr& cp_id) {
        if (!cp_id || !bn->cp_id) { return btree_status_t::success; }

        if (!is_write_modifiable) {
            if (bn->cp_id->cp_cnt > cp_id->cp_cnt) { return btree_status_t::cp_id_mismatch; }
            return btree_status_t::success;
        }

        if (bn->cp_id->cp_cnt == cp_id->cp_cnt) {
            /* modifying the buffer multiple times in a same cp */
            return btree_status_t::success;
        }

        if (bn->cp_id->cp_cnt > cp_id->cp_cnt) { return btree_status_t::cp_id_mismatch; }

        int prev_cp_cnt = (cp_id->cp_cnt - 1) % MAX_CP_CNT;
        auto req = bn->req[prev_cp_cnt];
        if (!req || req->state == WB_REQ_COMPL) {
            /* req on last cp is already completed. No need to make copy */
            return btree_status_t::success;
        }

        /* make a copy */
        auto mem = iomanager.iobuf_alloc(HS_STATIC_CONFIG(disk_attr.align_size), bn->get_cache_size());
        sisl::blob outb;
        (bn->get_memvec()).get(&outb);
        memcpy(mem, outb.bytes, outb.size);

        /* create a new mem vec */
        boost::intrusive_ptr< homeds::MemVector > mvec(new homeds::MemVector());
        mvec->set((uint8_t*)mem, bn->get_cache_size(), 0);

        /* assign new memvec to buffer */
        bn->set_memvec(mvec, 0, bn->get_cache_size());
        return btree_status_t::success;
    }

    /* We free the block only upto the end seqid of this cp. We might have persisted the data of sequence id
     * greater then this seq_id. But we are going to replay the entry from
     */
    void flush_free_blks(const btree_cp_id_ptr& cp_id, std::shared_ptr< homestore::blkalloc_cp_id >& blkalloc_id) {
        blkalloc_id->free_blks(cp_id->free_blkid_list);
    }

    void cp_start(const btree_cp_id_ptr& cp_id) {
        static int thread_cnt = 0;
        int cp_cnt = cp_id->cp_cnt % MAX_CP_CNT;
        iomanager.run_on(m_thread_ids[thread_cnt++ % WB_CACHE_THREADS],
                         [this, cp_id](io_thread_addr_t addr) { this->flush_buffers(cp_id); });
    }

    void flush_buffers(const btree_cp_id_ptr& cp_id) {
        int cp_cnt = cp_id->cp_cnt % MAX_CP_CNT;
        m_dirty_buf_cnt[cp_cnt].fetch_add(1);
        auto list = m_req_list[cp_cnt].get();
        typename sisl::ThreadVector< writeback_req_ptr >::thread_vector_iterator it;
        auto wb_req_ptr_ref = list->begin(it);
        while (wb_req_ptr_ref) {
            auto wb_req = *wb_req_ptr_ref;
            int cnt = wb_req->dependent_cnt.fetch_sub(1);
            if (cnt == 1) {
                wb_req->state = WB_REQ_SENT;
                m_blkstore->write(wb_req->bid, wb_req->m_mem, 0, wb_req, false);
            }
            wb_req_ptr_ref = list->next(it);
        }
        list->clear();
        auto cnt = m_dirty_buf_cnt[cp_cnt].fetch_sub(1);
        assert(cnt >= 1);
        if (cnt == 1) { m_cp_comp_cb(cp_id); }
    }

    static void writeBack_completion(boost::intrusive_ptr< blkstore_req< wb_cache_buffer_t > > bs_req) {
        auto wb_req = to_wb_req(bs_req);
        wb_cache_t* wb_cache_instance = (wb_cache_t*)(wb_req->wb_cache);
        wb_cache_instance->writeBack_completion_internal(bs_req);
    }

    void writeBack_completion_internal(boost::intrusive_ptr< blkstore_req< wb_cache_buffer_t > > bs_req) {
        auto wb_req = to_wb_req(bs_req);
        int cp_cnt = wb_req->cp_id->cp_cnt % MAX_CP_CNT;
        wb_req->state = WB_REQ_COMPL;

        /* Scan if it has any req depending on this req */
        std::unique_lock< std::mutex > req_mtx(wb_req->mtx);
        while (!wb_req->req_q.empty()) {
            auto depend_req = wb_req->req_q.back();
            wb_req->req_q.pop_back();
            int cnt = depend_req->dependent_cnt.fetch_sub(1);
            if (cnt == 1) {
                depend_req->state = WB_REQ_SENT;
                m_blkstore->write(depend_req->bid, depend_req->m_mem, 0, depend_req, false);
            }
        }
        wb_req->bn->req[cp_cnt] = nullptr;
        auto cnt = m_hs_dirty_buf_cnt.fetch_sub(1);
        assert(cnt >= 1);
        cnt = m_dirty_buf_cnt[cp_cnt].fetch_sub(1);
        assert(cnt >= 1);
        if (cnt == 1) { m_cp_comp_cb(wb_req->cp_id); }
    }
};
template < typename K, typename V, btree_node_type InteriorNodeType, btree_node_type LeafNodeType >
std::atomic< uint64_t > wb_cache_t::m_hs_dirty_buf_cnt;
template < typename K, typename V, btree_node_type InteriorNodeType, btree_node_type LeafNodeType >
btree_blkstore_t* wb_cache_t::m_blkstore;
template < typename K, typename V, btree_node_type InteriorNodeType, btree_node_type LeafNodeType >
iomgr::io_thread_t wb_cache_t::m_thread_ids[WB_CACHE_THREADS];
template < typename K, typename V, btree_node_type InteriorNodeType, btree_node_type LeafNodeType >
std::atomic< int > wb_cache_t::m_thread_indx;

} // namespace btree
} // namespace homeds

#endif
