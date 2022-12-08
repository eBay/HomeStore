#pragma once
#include <memory>

#include <iomgr/iomgr.hpp>

#include <homestore/index/wb_cache_base.hpp"
#include <homestore/index/index_internal.hpp>

namespace homestore {
class VirtualDev;

class IndexWBCache : public IndexWBCacheBase {
private:
    std::shared_ptr< VirtualDev > m_vdev;
    sisl::SimpleCache< BlkId, BtreeNodePtr > m_cache;
    uint32_t m_node_size;

    // Dirty buffer list arranged in a dependent list fashion
    std::unique_ptr< sisl::ThreadVector< IndexBufferPtr > > m_dirty_list[MAX_CP_CNT];
    std::unique_ptr< sisl::ThreadVector< BlkId > > m_free_blkid_list[MAX_CP_CNT]; // Free'd btree blkids per cp
    std::vector< iomgr::io_thread_t > m_flush_thread_ids;

public:
    IndexWBCache(const std::shared_ptr< VirtualDev >& vdev, const std::shared_ptr< Evictor >& evictor,
                 uint32_t node_size);

    BtreeNodePtr alloc_buf(auto&& node_initializer) override;
    void realloc_buf(const IndexBufferPtr& buf) override;
    void write_buf(const IndexBufferPtr& buf, CPContext* cp_ctx) override;
    std::error_condition read_buf(bnodeid_t id, BtreeNodePtr& node, bool cache_only, auto&& node_initializer) override;
    bool create_chain(const IndexBufferPtr& second, const IndexBufferPtr& third) override;
    void prepend_to_chain(const IndexBufferPtr& first, const IndexBufferPtr& second) override;
    void free_buf(const IndexBufferPtr& buf, CPContext* cp_ctx) override;

    //////////////////// CP Related API section /////////////////////////////////
    void cp_flush(CPContext* context) override;
    std::unique_ptr< CPContext > create_cp_context(cp_id_t cp_id) override;
    IndexBufferPtr copy_buffer(const IndexBufferPtr& cur_buf);

private:
    void do_flush_one_buf(BtreeCPContext* cp_ctx, const IndexBufferPtr& buf, bool part_of_batch);
    std::pair< IndexBufferPtr, bool > on_buf_flush_done(BtreeCPContext* cp_ctx, IndexBuffer* buf);
    std::pair< IndexBufferPtr, bool > on_buf_flush_done_internal(CPContext* cp_ctx, IndexBuffer* buf);

    void get_next_bufs(BtreeCPContext* cp_ctx, uint32_t max_count, std::vector< IndexBufferPtr >& bufs);
    void get_next_bufs_internal(BtreeCPContext* cp_ctx, uint32_t max_count, IndexBuffer* prev_flushed_buf,
                                std::vector< IndexBufferPtr >& bufs);
    void do_free_btree_blks(BtreeCPContext* cp_ctx);
}