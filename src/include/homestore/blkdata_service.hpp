#pragma once
#include <homestore/blk.h>
#include <homestore/homestore_decl.hpp>

namespace homestore {
typedef std::function< void(int status, void* cookie) > io_completion_cb_t;

class VirtualDev;
struct vdev_info_block;

class BlkDataService {
public:
    BlkDataService(uint64_t size, uint32_t page_size, blk_allocator_type_t blkalloc_type, bool cache = false);
    BlkDataService(vdev_info_block* vb, blk_allocator_type_t blkalloc_type, bool cache = false);

    void async_write(const sg_list& sgs, const blk_alloc_hints& hints, std::vector< BlkId >& out_blkids,
                     const io_completion_cb_t& cb);
    void async_read(const BlkId& bid, sg_list& sgs, uint32_t size, const io_completion_cb_t& cb);

    void commit_blks(const BlkId& bid);
    void async_free_blks(const BlkId& bid, const io_completion_cb_t& cb);

private:
    std::unique_ptr< VirtualDev > m_vdev;
    uint32_t m_page_size;
};
} // namespace homestore