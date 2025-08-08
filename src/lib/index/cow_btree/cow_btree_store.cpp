#include <memory>
#include <homestore/btree/detail/btree_node.hpp>
#include "index/cow_btree/cow_btree_store.h"
//#include "index/cow_btree/cow_btree_node.h"
#include "index/cow_btree/cow_btree.h"
#include "index/cow_btree/cow_btree_cp.h"
#include "index/index_cp.h"
#include "device/virtual_dev.hpp"
#include "common/crash_simulator.hpp"

namespace homestore {

static std::vector< iomgr::io_fiber_t > start_flush_threads() {
    // Start WBCache flush threads
    struct Context {
        std::condition_variable cv;
        std::mutex mtx;
        uint32_t thread_cnt{0};
        std::vector< iomgr::io_fiber_t > cp_flush_fibers;
    };
    auto ctx = std::make_shared< Context >();

    auto const nthreads = HS_DYNAMIC_CONFIG(generic.btree_cp_flush_threads);
    for (uint32_t i{0}; i < nthreads; ++i) {
        iomanager.create_reactor("index_cp_flush" + std::to_string(i), iomgr::INTERRUPT_LOOP,
                                 HS_DYNAMIC_CONFIG(generic.btree_cp_flush_fibers_per_thread), [ctx](bool is_started) {
                                     if (is_started) {
                                         {
                                             auto fibers = iomanager.sync_io_capable_fibers();
                                             std::unique_lock< std::mutex > lk{ctx->mtx};
                                             ctx->cp_flush_fibers.insert(ctx->cp_flush_fibers.end(), fibers.begin(),
                                                                         fibers.end());
                                             ++(ctx->thread_cnt);
                                         }
                                         ctx->cv.notify_one();
                                     }
                                 });
    }

    {
        std::unique_lock< std::mutex > lk{ctx->mtx};
        ctx->cv.wait(lk, [ctx, nthreads] { return (ctx->thread_cnt == nthreads); });
    }
    return std::move(ctx->cp_flush_fibers);
}

COWBtreeStore::COWBtreeStore(shared< VirtualDev > vdev, std::vector< superblk< IndexStoreSuperBlock > > store_sbs) :
        m_vdev{std::move(vdev)},
        m_cache{std::make_shared< sisl::SimpleCache< bnodeid_t, BtreeNodePtr > >(
            hs()->evictor(), 500000 /* num_buckets */,
            [](const BtreeNodePtr& node) -> bnodeid_t { return node->node_id(); },
            [](const BtreeNodePtr& node) -> uint32_t { return node->node_size(); },
            [](const sisl::CacheRecord& rec) -> bool {
                const auto& hnode = (sisl::SingleEntryHashNode< BtreeNodePtr >&)rec;
                return (hnode.m_value->m_refcount.test_le(1));
            })} {
    m_bufalloc_token = BtreeNode::Allocator::add(BtreeNode::Allocator{
        [](uint32_t size) { return new uint8_t[size]; }, // alloc_btree_node
        [](BtreeNode* node) {
            node->~BtreeNode();
            delete[] uintptr_cast(node);
        },                                       // free_btree_node
        [this](uint32_t node_size) -> uint8_t* { // alloc_node_buf
            return hs_utils::iobuf_alloc(node_size, sisl::buftag::btree_node, m_vdev->align_size());
        },
        [](uint8_t* buf) { hs_utils::iobuf_free(buf, sisl::buftag::btree_node); }});

    if (store_sbs.size()) {
        // There can be multiple sbs, each sb containing a journal for a particular cp. We need to sort based on
        // cp_id and then split them as
        std::sort(store_sbs.begin(), store_sbs.end(), [](auto& lhs, auto& rhs) {
            return (r_cast< Journal* >(lhs.get())->cp_id < r_cast< Journal* >(rhs.get())->cp_id);
        });

        m_journals_by_cpid = std::move(store_sbs);
        for (auto& journal : m_journals_by_cpid) {
            load_journal(journal);
        }
    }
    m_cp_flush_fibers = std::move(start_flush_threads());

    // Register ourselves to the IndexCPCallbacks. Make sure you call this at the end of constructor.
    r_cast< IndexCPCallbacks* >(cp_mgr().get_consumer(cp_consumer_t::INDEX_SVC))
        ->register_consumer(IndexStore::Type::COPY_ON_WRITE_BTREE, std::make_unique< COWBtreeCPCallbacks >(this));
}

void COWBtreeStore::stop() {
    m_cache.reset();
    BtreeNode::Allocator::remove(m_bufalloc_token);
}

uint32_t COWBtreeStore::max_capacity() const { return m_vdev->size(); }
uint32_t COWBtreeStore::max_node_size() const { return m_vdev->atomic_page_size(); }
uint32_t COWBtreeStore::align_size() const { return m_vdev->align_size(); }

void COWBtreeStore::on_recovery_completed() {
    HS_DBG_ASSERT_EQ(m_journals_by_btree.size(), 0,
                     "Even after recovery is completed, there are some btree journals are yet to be loaded, perhaps "
                     "its index super block is missing?");

    // All btrees are loaded and recovery is completed. We can free up the journal buffers now. Note that we do not
    // free up the superblk itself which contains critical meta_cookie info to remove the journal record itself once
    // we do full map flush.
    for (auto& journal : m_journals_by_cpid) {
        journal.raw_buf().reset(); // This should free up the underlying byte_array only.
    }
}

unique< UnderlyingBtree > COWBtreeStore::create_underlying_btree(BtreeBase& btree, bool load_existing) {
    unique< COWBtree > cbtree;

    auto it = m_journals_by_btree.find(btree.ordinal());
    if (it == m_journals_by_btree.end()) {
        cbtree = std::make_unique< COWBtree >(btree, m_vdev, m_cache, std::vector< unique< COWBtree::Journal > >{},
                                              m_bufalloc_token, load_existing);
    } else {
        HS_DBG_ASSERT_EQ(load_existing, true, "Btree is found, but we are asked to create a new one");
        cbtree = std::make_unique< COWBtree >(btree, m_vdev, m_cache, std::move(it->second), m_bufalloc_token,
                                              load_existing);
        m_journals_by_btree.erase(it); // We no longer need btree specific journal records after it is created.
    }
    return cbtree;
}

folly::Future< folly::Unit > COWBtreeStore::destroy_underlying_btree(BtreeBase& bt) {
    CPGuard cpg = cp_mgr().cp_guard();
    auto context = cpg->context(cp_consumer_t::INDEX_SVC);
    auto cp_ctx = IndexCPContext::convert< COWBtreeCPContext >(context, IndexStore::Type::COPY_ON_WRITE_BTREE);
    return cp_ctx->add_to_destroyed_list(bt.shared_from_this());
}

// void COWBtreeStore::on_node_freed(BtreeNode* node) { COWBtreeNode::destruct(node); }

class FlushGuard {
public:
    FlushGuard(COWBtreeCPContext* ctx, std::function< void(COWBtreeCPContext* cp_ctx) > done_cb) :
            m_cp_ctx{ctx}, m_done_cb{std::move(done_cb)} {
        ctx->m_flushing_fibers_count.increment(1);
    }

    ~FlushGuard() {
        if (m_cp_ctx->m_flushing_fibers_count.decrement_testz(1)) { m_done_cb(m_cp_ctx); }
    }

    FlushGuard(FlushGuard const& other) {
        m_cp_ctx = other.m_cp_ctx;
        m_done_cb = other.m_done_cb;
        m_cp_ctx->m_flushing_fibers_count.increment(1);
    }

    FlushGuard(FlushGuard&& other) = delete;

    FlushGuard operator=(FlushGuard const& other) {
        m_cp_ctx = other.m_cp_ctx;
        m_done_cb = other.m_done_cb;
        m_cp_ctx->m_flushing_fibers_count.increment(1);
        return *this;
    }

    FlushGuard operator=(FlushGuard&& other) = delete;

    COWBtreeCPContext* cp_ctx() { return m_cp_ctx; }

private:
    COWBtreeCPContext* m_cp_ctx;
    std::function< void(COWBtreeCPContext* ctx) > m_done_cb;
};

folly::Future< bool > COWBtreeStore::async_cp_flush(COWBtreeCPContext* cp_ctx) {
    CP_PERIODIC_LOG(DEBUG, cp_ctx->id(), "Starting COWBtree CP Flush with cp context={}", cp_ctx->to_string());
    if (!cp_ctx->any_dirty_nodes()) {
        if (cp_ctx->id() == 0) {
            // For the first CP, we need to flush the journal buffer to the meta blk
            // LOGINFO("First time boot cp, we shall flush the vdev to ensure all cp information is created");
            // m_vdev->cp_flush(cp_ctx);
        } else {
            CP_PERIODIC_LOG(DEBUG, cp_ctx->id(), "Btree does not have any dirty buffers to flush");
        }
        return folly::makeFuture< bool >(true); // nothing to flush
    }

    auto has_hit_incremental_flush_count_threshold = [this]() -> bool {
        return (m_num_incremental_flushes >= HS_DYNAMIC_CONFIG(btree->cow_max_incremental_map_flushes));
    };

    auto has_hit_meta_vdev_size_threshold = [this]() -> bool {
        return (
            meta_service().used_size() >
            uint64_cast(
                (HS_DYNAMIC_CONFIG(btree->cow_full_map_flush_size_threshold_pct) * meta_service().total_size()) / 100));
    };

    // First determine if this CP flush should be full_map flush
    if (has_hit_incremental_flush_count_threshold() || has_hit_meta_vdev_size_threshold()) {
        cp_ctx->prepare_to_flush(true); // Full map flush
    } else {
        cp_ctx->prepare_to_flush(false); // Incremental map flush
        ++m_num_incremental_flushes;
    }

    auto on_flush_nodes_done = [this](COWBtreeCPContext* cp_ctx) {
        cp_ctx->actual_destroy_btrees();

        CP_PERIODIC_LOG(
            INFO, cp_ctx->id(),
            "CowBtreeStore has {} btrees destroyed in this cp, destroyed all persistent structures for them",
            cp_ctx->m_destroyed_btrees.size());

        // All dirty nodes from all btrees have been flushed, now we can flush the full map or journal
        // (depending on cp type) for each of the modified btree
        flush_map(cp_ctx);
    };

    FlushGuard fg{cp_ctx, on_flush_nodes_done};
    for (auto& fiber : m_cp_flush_fibers) {
        iomanager.run_on_forget(fiber, [fg]() mutable {
            // Each thread will walk through all btrees created and alive at the point of CP flush and try to flush
            // their dirty nodes. We take this approach as against marking the dirtied btree seperately while
            // dirtying is that, we keep the code path of dirtying as waitfree as possible. It is more critical code
            // path. However, we pay the cost during the flushing by walking across all btrees and then check if
            // they are dirty. I feel this is much lower cost than doing in critical IO path.
            auto cp_ctx = fg.cp_ctx();
            for (auto const& btree : cp_ctx->m_all_btrees) {
                COWBtree* cow_btree = COWBtree::cast_to(btree.get());
                auto const [has_flushed, journal] = cow_btree->flush_nodes(cp_ctx);

#ifdef _PRERELEASE
                if (iomgr_flip::instance()->test_flip("crash_on_flush_cow_btree_nodes", cow_btree->ordinal())) {
                    LOGINFOMOD(btree, "Simulating crash while flushing node for btree={}", cow_btree->ordinal());
                    hs()->crash_simulator().start_crash();
                    break;
                }
#endif

                if (has_flushed) {
                    // Notify the cp context that we have flushed a btree and provide the journal. CP context will
                    // build the journal, which we will flush after all btrees are done flushing the nodes.
                    cp_ctx->flushed_a_btree(cow_btree, journal.get());
                }
            }
        });
    }

    return std::move(cp_ctx->get_future());
}

void COWBtreeStore::flush_map(COWBtreeCPContext* cp_ctx) {
    if (cp_ctx->need_full_map_flush()) {
        auto on_flush_map_done = [this](COWBtreeCPContext* cp_ctx) {
            // We just flushed the full bnode map of all btrees, we can remove all previous journal
            // superblks
            for (auto& journal : m_journals_by_cpid) {
                journal.destroy();
            }
            CP_PERIODIC_LOG(
                INFO, cp_ctx->id(),
                "CowBtree has completed flush of nodes across {} btrees and persisted full map for all btrees",
                cp_ctx->m_flushed_btrees_count);

            cp_ctx->complete(true);
        };

        FlushGuard fg{cp_ctx, on_flush_map_done};
        for (auto& fiber : m_cp_flush_fibers) {
            iomanager.run_on_forget(fiber, [fg]() mutable {
                auto cp_ctx = fg.cp_ctx();

                // Yes we access m_active_btree_list outside of lock, but we are sure that there is no one mutating
                // this btree list
                for (auto cow_btree : cp_ctx->m_active_btree_list) {
                    cow_btree->flush_map(cp_ctx);
                }
            });
        }
    } else {
#ifdef _PRERELEASE
        if (iomgr_flip::instance()->test_flip("crash_before_incr_map_flush_commit")) {
            LOGINFO("Simulating crash before we commit the incremental map flush (btree journal write)");
            hs()->crash_simulator().start_crash();
        }
#endif

        auto sb = superblk< IndexStoreSuperBlock >{"index_store"};
        sb.load(cp_ctx->store_journal(), nullptr); // Load an empty meta_blk but with given buffer
        sb.write();                                // Write the metablk
        auto const sb_size = sb.raw_buf()->size();
        sb.raw_buf().reset(); // after we wrote the superblk, we no longer need the merged journal buffer, free it

        // We only keep track of the metablk here, not buffer (so as to free after full map write)
        m_journals_by_cpid.emplace_back(std::move(sb));

        CP_PERIODIC_LOG(INFO, cp_ctx->id(),
                        "CowBtree has completed flush of nodes across {} btrees and persisted incremental journal for "
                        "map, journal size={}",
                        cp_ctx->m_flushed_btrees_count, sb_size);
        cp_ctx->complete(true);
    }
}

void COWBtreeStore::load_journal(superblk< IndexStoreSuperBlock >& sb) {
    auto store_journal = r_cast< COWBtreeStore::Journal* >(sb.get());
    uint32_t cur_offset = sizeof(COWBtreeStore::Journal);

    for (uint32_t i{0}; i < store_journal->num_btrees; ++i) {
        COWBtree::Journal::Header* cur_bj = r_cast< COWBtree::Journal::Header* >(sb.get() + cur_offset);

        auto it = m_journals_by_btree.find(cur_bj->ordinal);
        if (it == m_journals_by_btree.end()) {
            bool happened;
            std::tie(it, happened) =
                m_journals_by_btree.insert(std::pair(cur_bj->ordinal, std::vector< unique< COWBtree::Journal > >{}));
            HS_DBG_ASSERT(happened, "Insertion journal to journals list has failed for ordinal={}", cur_bj->ordinal);
        }
        it->second.emplace_back(std::make_unique< COWBtree::Journal >(
            sisl::byte_view{sb.raw_buf(), cur_offset, cur_bj->size}, store_journal->cp_id));
        cur_offset += cur_bj->size;
    }
}

uint32_t COWBtreeStore::parallel_map_flushers_count() const {
    // We cannot have more parallel fibers flushing than max heads we can put in the btree superblk, because each
    // fiber will flush a portion of the full map and will have a head of the location chain.
    return std::min(uint32_cast(m_cp_flush_fibers.size()),
                    COWBtree::SuperBlock::max_map_heads(BtreeSuperBlock::underlying_btree_sb_size));
}
} // namespace homestore