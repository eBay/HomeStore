/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 *********************************************************************************/
#ifndef WRITEBACK_CACHE_HPP
#define WRITEBACK_CACHE_HPP

#include <cassert>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <system_error>
#include <vector>
#include <chrono>
#include <thread>

#include <sisl/utility/thread_factory.hpp>

#include "engine/blkstore/blkstore.hpp"
#include "engine/common/error.h"
#include "engine/homeds/btree/btree_internal.h"
#include "engine/homestore.hpp"
#include "engine/common/resource_mgr.hpp"
#include "api/meta_interface.hpp"
#include "engine/homestore_base.hpp"

namespace homeds {
namespace btree {

#define wb_cache_buffer_t WriteBackCacheBuffer< K, V, InteriorNodeType, LeafNodeType >
#define writeback_req_t wb_cache_buffer_t::writeback_req
#define writeback_req_ptr boost::intrusive_ptr< typename writeback_req_t >
#define to_wb_req(req) boost::static_pointer_cast< typename writeback_req_t >(req)
#define wb_cache_t WriteBackCache< K, V, InteriorNodeType, LeafNodeType >
typedef std::function< bool() > flush_buffer_callback;
#define SSDBtreeNode BtreeNode< btree_store_type::SSD_BTREE, K, V, InteriorNodeType, LeafNodeType >
#define btree_blkstore_t homestore::BlkStore< wb_cache_buffer_t >

enum class writeback_req_state : uint8_t {
    WB_REQ_INIT = 0, // init
    WB_REQ_WAITING,  // waiting for cp
    WB_REQ_SENT,     // send to blksore to write
    WB_REQ_COMPL     // completed
};

// forward declaractions
template < typename K, typename V, btree_node_type InteriorNodeType, btree_node_type LeafNodeType >
class WriteBackCache;

// The class BtreeBuffer represents the buffer type that is used to interact with the BlkStore. It will have
// all the SSD Btree Node declarative type. Hence in-memory representation of this buffer is as follows
//
//   ****************Cache Buffer************************
//   *    ****************Cache Record***************   *
//   *    *   ************Hash Node**************   *   *
//   *    *   * Singly Linked list of hash node *   *   *
//   *    *   ***********************************   *   *
//   *    *******************************************   *
//   * BlkId                                            *
//   * Memvector of actual buffer                       *
//   * Usage Reference counter                          *
//   ****************************************************
//   ************** Transient Header ********************
//   * Upgraders count                                  *
//   * Reader Write Lock                                *
//   ****************************************************
//
template < typename K, typename V, btree_node_type InteriorNodeType, btree_node_type LeafNodeType >
class WriteBackCacheBuffer : public CacheBuffer< homestore::BlkId > {
public:
    //******************************************** writeback_req *********************************
    struct writeback_req : public homestore::blkstore_req< wb_cache_buffer_t >, sisl::ObjLifeCounter< writeback_req > {

        typedef std::function< void(const writeback_req_ptr& req, const std::error_condition status) >
            blkstore_callback;

        std::mutex mtx;
        writeback_req_state state;
        BlkId bid;
        btree_cp_ptr bcp;
        void* wb_cache;
        boost::intrusive_ptr< SSDBtreeNode > bn;

        // Queue of the requests which should be written only after this req is written.
        // Reason of using stl over boost intrusive is that one request can be
        // shared with multiple queues.
        std::deque< writeback_req_ptr > req_q;

        // issue this request when the cnt become zero
        sisl::atomic_counter< int > dependent_cnt;

        boost::intrusive_ptr< homeds::MemVector > m_mem;
        Clock::time_point cache_start_time; // Start time to put the wb cache to the request

        static boost::intrusive_ptr< writeback_req > make_request() {
            return boost::intrusive_ptr< writeback_req >(sisl::ObjectAllocator< writeback_req >::make_object());
        }

        virtual void free_yourself() override { sisl::ObjectAllocator< writeback_req >::deallocate(this); }

        virtual ~writeback_req() override {
            HS_DBG_ASSERT((state == writeback_req_state::WB_REQ_COMPL || state == writeback_req_state::WB_REQ_INIT),
                          "state {}", state);
        }

        writeback_req(const writeback_req&) = delete;
        writeback_req(writeback_req&&) noexcept = delete;
        writeback_req& operator=(const writeback_req&) = delete;
        writeback_req& operator=(writeback_req&&) noexcept = delete;

    protected:
        friend class sisl::ObjectAllocator< writeback_req >;
        writeback_req() :
                state(writeback_req_state::WB_REQ_INIT),
                bid(0),
                bcp(nullptr),
                req_q(),
                dependent_cnt(1),
                m_mem(nullptr){};
    };

    //*************************************************** WriteBackCacheBuffer *******************************
    typedef CacheBuffer< homestore::BlkId > CacheBufferType;

    btree_cp_ptr bcp = nullptr;
    writeback_req_ptr req[WriteBackCache< K, V, InteriorNodeType, LeafNodeType >::MAX_CP_CNT];

    static wb_cache_buffer_t* make_object() {
        // create derived object
        return static_cast< wb_cache_buffer_t* >(sisl::ObjectAllocator< SSDBtreeNode >::make_object());
    }
    static sisl::buftag get_buf_tag() { return sisl::buftag::btree_node; }
    void free_yourself() {
#ifdef NDEBUG
        SSDBtreeNode* const SSDBtreeNode_ptr{reinterpret_cast< SSDBtreeNode* >(this)};
#else
        SSDBtreeNode* const SSDBtreeNode_ptr{dynamic_cast< SSDBtreeNode* >(this)};
#endif
        sisl::ObjectAllocator< SSDBtreeNode >::deallocate(SSDBtreeNode_ptr);
    }

    WriteBackCacheBuffer() = default;
    WriteBackCacheBuffer(const WriteBackCacheBuffer&) = delete;
    WriteBackCacheBuffer(WriteBackCacheBuffer&&) noexcept = delete;
    WriteBackCacheBuffer& operator=(const WriteBackCacheBuffer&) = delete;
    WriteBackCacheBuffer& operator=(WriteBackCacheBuffer&&) noexcept = delete;
    virtual ~WriteBackCacheBuffer() override = default;

    virtual void init() override {
        // Note : it is called under cache lock to prevent multiple threads to call init. And init function
        // internally also try to take the cache lock to access cache to update in memory structure. So
        // we have to be careful in taking any lock inside this function.
#ifdef NDEBUG
        SSDBtreeNode* const SSDBtreeNode_ptr{reinterpret_cast< SSDBtreeNode* >(this)};
#else
        SSDBtreeNode* const SSDBtreeNode_ptr{dynamic_cast< SSDBtreeNode* >(this)};
#endif

        SSDBtreeNode_ptr->init();
    }

    friend void intrusive_ptr_add_ref(wb_cache_buffer_t* const buf) {
        // manage through base pointer
        intrusive_ptr_add_ref(static_cast< CacheBufferType* >(buf));
    }
    friend void intrusive_ptr_release(wb_cache_buffer_t* const buf) {
        // manage through base pointer
        intrusive_ptr_release(static_cast< CacheBufferType* >(buf));
    }
};

template < typename K, typename V, btree_node_type InteriorNodeType, btree_node_type LeafNodeType >
class WriteBackCache : public std::enable_shared_from_this< WriteBackCache< K, V, InteriorNodeType, LeafNodeType > > {
    friend struct WriteBackCacheBuffer< K, V, InteriorNodeType, LeafNodeType >;

private:
    static constexpr size_t MAX_CP_CNT{2};

    std::unique_ptr< sisl::ThreadVector< writeback_req_ptr > > m_req_list[MAX_CP_CNT];
    homestore::blkid_list_ptr m_free_list[MAX_CP_CNT];
    sisl::atomic_counter< uint64_t > m_dirty_buf_cnt[MAX_CP_CNT];
    cp_comp_callback m_cp_comp_cb;
    trigger_cp_callback m_trigger_cp_cb;
    uint64_t m_free_list_cnt = 0;
    uint64_t m_alloc_list_cnt = 0;
    btree_blkstore_t* m_blkstore;
    uint32_t m_node_size;
    static std::vector< iomgr::io_thread_t > m_thread_ids;
    static thread_local std::vector< flush_buffer_callback > flush_buffer_q;
    static thread_local uint64_t wb_cache_outstanding_cnt;
    static thread_local uint64_t s_cbq_id;

public:
    WriteBackCache(void* const blkstore, const uint32_t node_size, cp_comp_callback cb,
                   trigger_cp_callback trigger_cp_cb) :
            m_node_size(node_size) {
        for (size_t i{0}; i < MAX_CP_CNT; ++i) {
            m_free_list[i] = std::make_shared< sisl::ThreadVector< BlkId > >();
            m_req_list[i] = std::make_unique< sisl::ThreadVector< writeback_req_ptr > >();
            m_dirty_buf_cnt[i].set(0);
        }
        m_cp_comp_cb = std::move(cb);
        m_blkstore = static_cast< btree_blkstore_t* >(blkstore);
        m_blkstore->attach_compl(wb_cache_t::writeBack_completion);
        m_trigger_cp_cb = std::move(trigger_cp_cb);
        int expected_thread_cnt{0};
        std::atomic< int64_t > thread_cnt{0};
        static std::once_flag flag1;
        std::call_once(
            flag1, ([&thread_cnt, &expected_thread_cnt]() {
                const size_t flush_threads{static_cast< size_t >(HS_DYNAMIC_CONFIG(generic.cache_flush_threads))};
                std::mutex mtx; // mutex to lock all threads from pushing back thread ids;
                for (size_t i{0}; i < flush_threads; ++i) {
                    iomanager.create_reactor("wbcache_flusher", INTERRUPT_LOOP, [&thread_cnt, &mtx](bool is_started) {
                        if (is_started) {
                            {
                                std::unique_lock< std::mutex > lk{mtx};
                                wb_cache_t::m_thread_ids.push_back(iomanager.iothread_self());
                            }
                            ++thread_cnt;
                        }
                    });
                    ++expected_thread_cnt;
                }
            }));

        while (thread_cnt.load(std::memory_order_acquire) != expected_thread_cnt) {}
    }

    WriteBackCache(const WriteBackCache&) = delete;
    WriteBackCache(WriteBackCache&&) noexcept = delete;
    WriteBackCache& operator=(const WriteBackCache&) = delete;
    WriteBackCache& operator=(WriteBackCache&&) noexcept = delete;

    ~WriteBackCache() {
        for (size_t i{0}; i < MAX_CP_CNT; ++i) {
#ifndef NDEBUG
            HS_DBG_ASSERT_EQ(m_dirty_buf_cnt[i].testz(), true);
            HS_DBG_ASSERT_EQ(m_req_list[i]->size(), 0);
            HS_DBG_ASSERT_EQ(m_free_list[i]->size(), 0);
#endif
        }
    }

    void prepare_cp(const btree_cp_ptr& new_bcp, const btree_cp_ptr& cur_bcp, const bool blkalloc_checkpoint) {
        if (new_bcp) {
            const size_t cp_id{(new_bcp->cp_id) % MAX_CP_CNT};
            HS_DBG_ASSERT_EQ(m_dirty_buf_cnt[cp_id].testz(), true);
            // decrement it by all cache threads at the end after writing all pending requests
            HS_DBG_ASSERT_EQ(m_req_list[cp_id]->size(), 0);
            blkid_list_ptr free_list, alloc_list;
            if (blkalloc_checkpoint || !cur_bcp) {
                free_list = m_free_list[++m_free_list_cnt % MAX_CP_CNT];
                HS_DBG_ASSERT_EQ(free_list->size(), 0);
            } else {
                // we keep accumulating the alloc and free blks until blk checkpoint is taken
                free_list = cur_bcp->free_blkid_list;
            }
            new_bcp->free_blkid_list = free_list;
        }
    }

    void write(const boost::intrusive_ptr< SSDBtreeNode >& bn, const boost::intrusive_ptr< SSDBtreeNode >& dependent_bn,
               const btree_cp_ptr& bcp) {
        const size_t cp_id{bcp->cp_id % MAX_CP_CNT};
        HS_REL_ASSERT((!dependent_bn || dependent_bn->bcp == bcp), "dependent request is modifided by other CP");
        writeback_req_ptr wbd_req = dependent_bn ? dependent_bn->req[cp_id] : nullptr;
        if (bn->bcp != bcp) {
            // create wb request
            auto wb_req = writeback_req_t::make_request();
            wb_req->bcp = bcp;
            wb_req->m_mem = bn->get_memvec_intrusive();
            wb_req->bn = bn;
            wb_req->bid.set(bn->get_node_id());
            // batch requests
            wb_req->part_of_batch = true;
            // we can assume that btree is not destroyed until cp is not completed
            wb_req->wb_cache = this;
            HS_DBG_ASSERT_EQ(wb_req->state, writeback_req_state::WB_REQ_INIT);
            wb_req->state = writeback_req_state::WB_REQ_WAITING;

            // update buffer
            bn->req[cp_id] = wb_req;
            bn->bcp = bcp;

            // add it to the list
            m_req_list[cp_id]->push_back(wb_req);

            /* check for dirty buffers cnt */
            m_dirty_buf_cnt[cp_id].increment(1);
            ResourceMgrSI().inc_dirty_buf_cnt(m_node_size);
        } else {
            HS_DBG_ASSERT_EQ(bn->req[cp_id]->bid.to_integer(), bn->get_node_id());
            if (bn->req[cp_id]->m_mem != bn->get_memvec_intrusive()) {
                bn->req[cp_id]->m_mem = bn->get_memvec_intrusive();
                HS_DBG_ASSERT_NOTNULL(bn->req[cp_id]->m_mem.get());
            }
        }

        auto wb_req{bn->req[cp_id]};
        HS_DBG_ASSERT_EQ(wb_req->state, writeback_req_state::WB_REQ_WAITING);

        if (wbd_req) {
            {
                std::unique_lock< std::mutex > req_mtx(wbd_req->mtx);
                wbd_req->req_q.push_back(wb_req);
            }
            wb_req->dependent_cnt.increment(1);
        }
    }

    // We don't want to free the blocks until cp is persisted. Because we use these blocks
    // to recover btree.
    void free_blk(const bnodeid_t node_id, const blkid_list_ptr& free_blkid_list, const uint64_t size) {
        HS_DBG_ASSERT_NE(node_id, empty_bnodeid);
        BlkId bid(node_id);

        //  if bcp is null then free it only from the cache.
        m_blkstore->free_blk(bid, boost::none, boost::none, free_blkid_list ? true : false);
        if (free_blkid_list) {
            ResourceMgrSI().inc_free_blk(size);
            free_blkid_list->push_back(bid);
            // release on realtime bitmap;
            const auto ret = m_blkstore->free_on_realtime(bid);
            HS_REL_ASSERT(ret, "fail to free on realtime bm");
        }
    }

    btree_status_t refresh_buf(const boost::intrusive_ptr< SSDBtreeNode >& bn, const bool is_write_modifiable,
                               const btree_cp_ptr& bcp) {
        if (!bcp || !bn->bcp) { return btree_status_t::success; }

        if (!is_write_modifiable) {
            if (bn->bcp->cp_id > bcp->cp_id) { return btree_status_t::cp_mismatch; }
            return btree_status_t::success;
        }

        if (bn->bcp->cp_id == bcp->cp_id) {
            // modifying the buffer multiple times in a same cp
            return btree_status_t::success;
        }

        if (bn->bcp->cp_id > bcp->cp_id) { return btree_status_t::cp_mismatch; }

        const size_t prev_cp_id{static_cast< size_t >((bcp->cp_id - 1)) % MAX_CP_CNT};
        auto req{bn->req[prev_cp_id]};
        if (!req || req->state == writeback_req_state::WB_REQ_COMPL) {
            // req on last cp is already completed. No need to make copy
            return btree_status_t::success;
        }

        // make a copy
        // TO DO: Possible alignment
        auto mem{hs_utils::iobuf_alloc(bn->get_cache_size(), sisl::buftag::btree_node,
                                       m_blkstore->get_vdev()->get_align_size())};
        sisl::blob outb;
        (bn->get_memvec()).get(&outb);
        std::memcpy(static_cast< void* >(mem), static_cast< const void* >(outb.bytes), outb.size);

        // create a new mem vec
        boost::intrusive_ptr< homeds::MemVector > mvec(new homeds::MemVector());
        mvec->set(mem, bn->get_cache_size(), 0);
        mvec->set_tag(sisl::buftag::btree_node);

        // assign new memvec to buffer
        bn->set_memvec(mvec, 0, bn->get_cache_size());
        return btree_status_t::success;
    }

    // We free the block only upto the end seqid of this cp. We might have persisted the data of sequence id
    // greater then this seq_id. But we are going to replay the entry from
    void flush_free_blks(const btree_cp_ptr& bcp, std::shared_ptr< homestore::blkalloc_cp >& ba_cp) {
        ba_cp->free_blks(bcp->free_blkid_list);
    }

    static iomgr::io_thread_t get_next_wb_flush_thread() {
        /* not using atomic here since it is fine to arrive on same thread */
        static int next_thread = 0;
        next_thread = (next_thread + 1) % m_thread_ids.size();
        return m_thread_ids[next_thread];
    }

    void cp_start(const btree_cp_ptr& bcp) {
        static size_t thread_cnt{0};
        const size_t thread_index{static_cast< size_t >(thread_cnt++ % HS_DYNAMIC_CONFIG(generic.cache_flush_threads))};
        const size_t cp_id = bcp->cp_id % MAX_CP_CNT;
        CP_PERIODIC_LOG(INFO, cp_id, "Starting btree flush buffers dirty_buf_count={} wb_req_cnt={} flush_cb_size={}",
                        m_dirty_buf_cnt[cp_id].get(), m_req_list[cp_id]->size(), flush_buffer_q.size());
        ResourceMgrSI().reset_dirty_buf_qd();
        iomanager.run_on(get_next_wb_flush_thread(),
                         [this, bcp]([[maybe_unused]] const io_thread_addr_t addr) { this->flush_buffers(bcp); });
    }

    std::string get_cp_flush_status(const btree_cp_ptr& bcp) const {
        const size_t cp_id = bcp->cp_id % MAX_CP_CNT;
        return fmt::format("dirty buffers cnt {}", m_dirty_buf_cnt[cp_id].get());
    }

    void flush_buffers(const btree_cp_ptr& bcp) {
        const size_t cp_id = bcp->cp_id % MAX_CP_CNT;
        if (m_dirty_buf_cnt[cp_id].testz()) {
            CP_PERIODIC_LOG(DEBUG, bcp->cp_id, "no buffers to flush");
            m_cp_comp_cb(bcp);
            return; // nothing to flush
        }

        ++s_cbq_id;
        CP_PERIODIC_LOG(INFO, bcp->cp_id,
                        "[fcbq_id={}] Starting btree flush buffers dirty_buf_count={} wb_req_cnt={} flush_cb_size={}",
                        s_cbq_id, m_dirty_buf_cnt[cp_id].get(), m_req_list[cp_id]->size(), flush_buffer_q.size());

        auto shared_this = this->shared_from_this();
        queue_flush_buffers([shared_this, cp_id, it = m_req_list[cp_id]->begin(true /* latest */),
                             bt_cp_id = bcp->cp_id, cbq_id = s_cbq_id]() mutable -> bool {
            size_t write_count{0};
            size_t dep_wait_count{0};

            auto& req_list = shared_this->m_req_list[cp_id];
            writeback_req_ptr* wb_req_ref;
            while ((wb_req_ref = req_list->next(it)) != nullptr) {
                writeback_req_ptr wb_req = *wb_req_ref;
                if (wb_req->dependent_cnt.decrement_testz(1)) {
                    wb_req->state = homeds::btree::writeback_req_state::WB_REQ_SENT;
                    ++wb_cache_outstanding_cnt;
                    shared_this->m_blkstore->write(wb_req->bid, wb_req->m_mem, 0, wb_req, false);
                    ++write_count;
                    if (wb_cache_outstanding_cnt > ResourceMgrSI().get_dirty_buf_qd()) {
                        CP_PERIODIC_LOG(
                            DEBUG, bt_cp_id,
                            "[fcbq_id={}] Flush throttled: flushed_cnt={} outstanding_io_cnt={} dep_wait_cnt={}",
                            cbq_id, write_count, wb_cache_outstanding_cnt, dep_wait_count);
                        if (write_count > 0) { shared_this->m_blkstore->submit_batch(); }
                        return false;
                    }
                } else {
                    ++dep_wait_count;
                }
            }

            req_list->clear(); // Freeup the req list which frees the all wb_req memory
            CP_PERIODIC_LOG(DEBUG, bt_cp_id,
                            "[fcbq_id={}] Flush finish: flushed_cnt={} outstanding_io_cnt={} dep_wait_cnt={}", cbq_id,
                            write_count, wb_cache_outstanding_cnt, dep_wait_count);

            if (write_count > 0) { shared_this->m_blkstore->submit_batch(); }
            return true;
        });
    }

    static void writeBack_completion(boost::intrusive_ptr< blkstore_req< wb_cache_buffer_t > > bs_req) {
        auto wb_req{to_wb_req(bs_req)};
        wb_cache_t* const wb_cache_instance{static_cast< wb_cache_t* >(wb_req->wb_cache)};
        wb_cache_instance->writeBack_completion_internal(bs_req);
    }

    void writeBack_completion_internal(boost::intrusive_ptr< blkstore_req< wb_cache_buffer_t > >& bs_req) {
        if (bs_req->err != no_error) { HS_REL_ASSERT(false, "error {} happen during cp {}", bs_req->err.message()); }

        auto wb_req = to_wb_req(bs_req);
        const size_t cp_id = wb_req->bcp->cp_id % MAX_CP_CNT;
        wb_req->state = homeds::btree::writeback_req_state::WB_REQ_COMPL;

        --wb_cache_outstanding_cnt;
        auto shared_this = this->shared_from_this();
        ++s_cbq_id;

        CP_PERIODIC_LOG(
            DEBUG, wb_req->bcp->cp_id, "[wbreq_id={}] completed: depq_cnt={} dirty_buf_cnt={} outstanding_io_cnt={}",
            wb_req->request_id, wb_req->req_q.size(), m_dirty_buf_cnt[cp_id].get() - 1, wb_cache_outstanding_cnt);

        /* Scan if it has any req depending on this req */
        if (!wb_req->req_q.empty()) {
            queue_flush_buffers([shared_this, wb_req, cbq_id = s_cbq_id]() -> bool {
                size_t write_count{0};
                size_t dep_wait_count{0};

                // std::unique_lock< std::mutex > req_mtx(wb_req->mtx); No need to take a lock here
                while (!wb_req->req_q.empty()) {
                    auto depend_req = wb_req->req_q.back();
                    wb_req->req_q.pop_back();
                    if (depend_req->dependent_cnt.decrement_testz(1)) {
                        depend_req->state = homeds::btree::writeback_req_state::WB_REQ_SENT;
                        ++wb_cache_outstanding_cnt;
                        shared_this->m_blkstore->write(depend_req->bid, depend_req->m_mem, 0, depend_req, false);
                        ++write_count;
#ifdef _PRERELEASE
                        if (homestore_flip->test_flip("indx_cp_wb_flush_abort")) {
                            LOGINFO("aborting because of flip");
                            raise(SIGKILL);
                        }
#endif
                        if (wb_cache_outstanding_cnt > HS_DYNAMIC_CONFIG(generic.cache_max_throttle_cnt)) {
                            CP_PERIODIC_LOG(DEBUG, wb_req->bcp->cp_id,
                                            "[fcbq_id={}] [wbreq_id={}] dependentq flush throttled: flushed_cnt={} "
                                            "remain_depq_cnt={} outstanding_io_cnt={} dep_wait_cnt={}",
                                            cbq_id, wb_req->request_id, write_count, wb_req->req_q.size(),
                                            wb_cache_outstanding_cnt, dep_wait_count);
                            if (write_count > 0) { shared_this->m_blkstore->submit_batch(); }
                            return false;
                        }
                    } else {
                        ++dep_wait_count;
                    }
                }

                CP_PERIODIC_LOG(DEBUG, wb_req->bcp->cp_id,
                                "[fcbq_id={}] [wbreq_id={}] dependentq flushed: flushed_cnt={} outstanding_io_cnt={} "
                                "dep_wait_cnt={}",
                                cbq_id, wb_req->request_id, write_count, wb_cache_outstanding_cnt, dep_wait_count);
                if (write_count > 0) { shared_this->m_blkstore->submit_batch(); }
                return true;
            });
        } else if (wb_cache_outstanding_cnt < HS_DYNAMIC_CONFIG(generic.cache_min_throttle_cnt)) {
            CP_PERIODIC_LOG(DEBUG, wb_req->bcp->cp_id,
                            "[wbreq_id={}] no depq entries: outstanding_io_cnt={} flush next leading reqs",
                            wb_req->request_id, wb_cache_outstanding_cnt);
            queue_flush_buffers(nullptr);
        }
        ResourceMgrSI().dec_dirty_buf_cnt(m_node_size);
        /* req and btree node are pointing to each other which is preventing neither of them to be freed */
        wb_req->bn = nullptr;

        if (m_dirty_buf_cnt[cp_id].decrement_testz(1)) { m_cp_comp_cb(wb_req->bcp); };
    }

    void queue_flush_buffers(flush_buffer_callback&& cb) {
        if (cb) { flush_buffer_q.push_back(std::move(cb)); }
        while (!flush_buffer_q.empty()) {
            auto& next_cb = flush_buffer_q.back();
            if (next_cb()) {
                flush_buffer_q.pop_back();
            } else {
                /* reach the max_throttle_cnt. try it again after completions are done */
                return;
            }
        }
    }
};

template < typename K, typename V, btree_node_type InteriorNodeType, btree_node_type LeafNodeType >
std::vector< iomgr::io_thread_t > wb_cache_t::m_thread_ids;
template < typename K, typename V, btree_node_type InteriorNodeType, btree_node_type LeafNodeType >
thread_local std::vector< flush_buffer_callback > wb_cache_t::flush_buffer_q;
template < typename K, typename V, btree_node_type InteriorNodeType, btree_node_type LeafNodeType >
thread_local uint64_t wb_cache_t::wb_cache_outstanding_cnt{};
template < typename K, typename V, btree_node_type InteriorNodeType, btree_node_type LeafNodeType >
thread_local uint64_t wb_cache_t::s_cbq_id{};
} // namespace btree
} // namespace homeds

template <>
struct fmt::formatter< homeds::btree::writeback_req_state > : formatter< string_view > {
    // parse is inherited from formatter<string_view>.
    template < typename FormatContext >
    auto format(homeds::btree::writeback_req_state c, FormatContext& ctx) const {
        string_view name = "unknown";
        switch (c) {
        case homeds::btree::writeback_req_state::WB_REQ_INIT:
            name = "init";
            break;
        case homeds::btree::writeback_req_state::WB_REQ_WAITING:
            name = "waiting";
            break;
        case homeds::btree::writeback_req_state::WB_REQ_SENT:
            name = "sent";
            break;
        case homeds::btree::writeback_req_state::WB_REQ_COMPL:
            name = "complete";
            break;
        }
        return formatter< string_view >::format(name, ctx);
    }
};

#endif
