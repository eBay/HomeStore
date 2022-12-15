#include <homestore/homestore.hpp>
#include <homestore/index_service.hpp>
#include <homestore/index/index_internal.hpp>
#include "index/wb_cache.hpp"
#include "common/homestore_utils.hpp"
#include "device/virtual_dev.hpp"
#include "device/physical_dev.hpp"

namespace homestore {
IndexService& index_service() { return hs()->index_service(); }

IndexService::IndexService(std::unique_ptr< IndexServiceCallbacks > cbs) : m_svc_cbs{std::move(cbs)} {
    meta_service().register_handler(
        "index",
        [this](meta_blk* mblk, sisl::byte_view buf, size_t size) {
            meta_blk_found(std::move(buf), voidptr_cast(mblk));
        },
        nullptr);
}

void IndexService::create_vdev(uint64_t size) {
    auto const atomic_page_size = hs()->device_mgr()->atomic_page_size({PhysicalDevGroup::FAST});

    struct blkstore_blob blob;
    blob.type = blkstore_type::INDEX_STORE;
    m_vdev =
        std::make_shared< VirtualDev >(hs()->device_mgr(), "index", PhysicalDevGroup::FAST, blk_allocator_type_t::fixed,
                                       size, 0, true, atomic_page_size, (char*)&blob, sizeof(blkstore_blob), true);
}

void IndexService::open_vdev(vdev_info_block* vb) {
    m_vdev = std::make_shared< VirtualDev >(hs()->device_mgr(), "index", vb, PhysicalDevGroup::FAST,
                                            blk_allocator_type_t::fixed, vb->is_failed(), true);
    if (vb->is_failed()) {
        LOGINFO("index vdev is in failed state");
        throw std::runtime_error("vdev in failed state");
    }
}

void IndexService::meta_blk_found(const sisl::byte_view& buf, void* meta_cookie) {
    // We have found an index table superblock. Notify the callback which should convert the superblock into actual
    // IndexTable instance
    superblk< index_table_sb > sb;
    sb.load(buf, meta_cookie);
    add_index_table(m_svc_cbs->on_index_table_found(sb));
}

void IndexService::start() {
    start_threads();

    // Start Writeback cache
    m_wb_cache = std::make_unique< IndexWBCache >(m_vdev, hs()->evictor(),
                                                  hs()->device_mgr()->atomic_page_size({PhysicalDevGroup::FAST}));
}

void IndexService::start_threads() {
    struct Context {
        std::condition_variable cv;
        std::mutex mtx;
        size_t thread_cnt{0};
    };
    auto ctx = std::make_shared< Context >();
    auto nthreads = std::max(uint32_cast(1), HS_DYNAMIC_CONFIG(generic.num_btree_write_threads));
    m_btree_write_thread_ids.reserve(nthreads);

    for (uint32_t i = 0; i < nthreads; ++i) {
        /* start user thread for btree write operations */
        iomanager.create_reactor("index_btree_write_" + std::to_string(i), INTERRUPT_LOOP,
                                 [this, &ctx](bool is_started) {
                                     if (is_started) {
                                         {
                                             std::unique_lock< std::mutex > lk{ctx->mtx};
                                             m_btree_write_thread_ids.push_back(iomanager.iothread_self());
                                             ++(ctx->thread_cnt);
                                         }
                                         ctx->cv.notify_one();
                                     }
                                 });
    }

    {
        std::unique_lock< std::mutex > lk{ctx->mtx};
        ctx->cv.wait(lk, [&ctx, nthreads] { return (ctx->thread_cnt == nthreads); });
    }
}

void IndexService::add_index_table(const std::shared_ptr< IndexTableBase >& tbl) {
    std::unique_lock lg(m_index_map_mtx);
    m_index_map.insert(std::make_pair(tbl->uuid(), tbl));
}

iomgr::io_thread_t IndexService::get_next_btree_write_thread() {
    return m_btree_write_thread_ids[m_btree_write_thrd_idx++ % m_btree_write_thread_ids.size()];
}

uint64_t IndexService::used_size() const {
    auto size{0};
    std::unique_lock lg{m_index_map_mtx};
    for (auto& [id, table] : m_index_map) {
        size += table->used_size();
    }
    return size;
}

IndexBuffer::IndexBuffer(BlkId blkid, uint32_t buf_size, uint32_t align_size) :
        m_node_buf{hs_utils::iobuf_alloc(buf_size, sisl::buftag::btree_node, align_size)}, m_blkid{blkid} {}

} // namespace homestore