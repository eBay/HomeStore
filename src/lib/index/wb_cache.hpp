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
#pragma once
#include <memory>

#include <iomgr/iomgr.hpp>
#include <homestore/index/wb_cache_base.hpp>
#include <homestore/index/index_internal.hpp>
#include <sisl/cache/simple_cache.hpp>
#include "index/index_cp.hpp"

namespace sisl {
template < typename T >
class ThreadVector;

class Evictor;
} // namespace sisl

namespace homestore {
class VirtualDev;

class IndexWBCache : public IndexWBCacheBase {
private:
    std::shared_ptr< VirtualDev > m_vdev;
    sisl::SimpleCache< BlkId, BtreeNodePtr > m_cache;
    uint32_t m_node_size;
    std::vector< iomgr::io_fiber_t > m_cp_flush_fibers;
    std::mutex m_flush_mtx;
    void* m_meta_blk;

#ifdef _PRERELEASE
    std::mutex flip_mtx;
    std::map< IndexBufferPtr, std::vector< std::string > > crashing_buffers;
#endif

#ifdef _PRERELEASE
    std::mutex flip_mtx;
    std::map< IndexBufferPtr, std::vector< std::string > > crashing_buffers;
#endif

public:
    IndexWBCache(const std::shared_ptr< VirtualDev >& vdev, std::pair< meta_blk*, sisl::byte_view > sb,
                 const std::shared_ptr< sisl::Evictor >& evictor, uint32_t node_size);

    BtreeNodePtr alloc_buf(node_initializer_t&& node_initializer) override;
    void write_buf(const BtreeNodePtr& node, const IndexBufferPtr& buf, CPContext* cp_ctx) override;
    void read_buf(bnodeid_t id, BtreeNodePtr& node, node_initializer_t&& node_initializer) override;

    bool get_writable_buf(const BtreeNodePtr& node, CPContext* context) override;
    void link_buf(IndexBufferPtr& up, IndexBufferPtr& down, CPContext* cp_ctx) override;
    void free_buf(const IndexBufferPtr& buf, CPContext* cp_ctx) override;

    //////////////////// CP Related API section /////////////////////////////////
    folly::Future< bool > async_cp_flush(IndexCPContext* context);
    IndexBufferPtr copy_buffer(const IndexBufferPtr& cur_buf, const CPContext* cp_ctx) const;
#ifdef _PRERELEASE
    void add_to_crashing_buffers(IndexBufferPtr, std::string) override;
#endif
private:
    void start_flush_threads();
    void recover_new_nodes(sisl::byte_view sb);
    void process_write_completion(IndexCPContext* cp_ctx, IndexBufferPtr pbuf);
    void do_flush_one_buf(IndexCPContext* cp_ctx, const IndexBufferPtr buf, bool part_of_batch);
    std::pair< IndexBufferPtr, bool > on_buf_flush_done(IndexCPContext* cp_ctx, IndexBufferPtr& buf);
    std::pair< IndexBufferPtr, bool > on_buf_flush_done_internal(IndexCPContext* cp_ctx, IndexBufferPtr& buf);

    void get_next_bufs(IndexCPContext* cp_ctx, uint32_t max_count, std::vector< IndexBufferPtr >& bufs);
    void get_next_bufs_internal(IndexCPContext* cp_ctx, uint32_t max_count, IndexBufferPtr prev_flushed_buf,
                                std::vector< IndexBufferPtr >& bufs);
};
} // namespace homestore
