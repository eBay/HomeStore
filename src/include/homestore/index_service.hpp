#pragma once
#include <memory>
#include <unordered_map>
#include <vector>

#include <iomgr/iomgr.hpp>
#include <homestore/homestore_decl.hpp>
#include <homestore/index/index_internal.hpp>
#include <homestore/superblk_handler.hpp>

namespace homestore {

class IndexWBCacheBase;
class IndexTableBase;
class VirtualDev;

class IndexServiceCallbacks {
public:
    virtual std::shared_ptr< IndexTableBase > on_index_table_found(const superblk< index_table_sb >& cb) = 0;
};

class IndexService {
private:
    std::unique_ptr< IndexServiceCallbacks > m_svc_cbs;
    std::unique_ptr< IndexWBCacheBase > m_wb_cache;
    std::shared_ptr< VirtualDev > m_vdev;
    std::vector< iomgr::io_thread_t > m_btree_write_thread_ids; // user io threads for btree write
    uint32_t m_btree_write_thrd_idx{0};

    std::mutex m_index_map_mtx;
    std::map< uuid_t, std::shared_ptr< IndexTableBase > > m_index_map;

public:
    IndexService(std::unique_ptr< IndexServiceCallbacks > cbs);

    // Creates the vdev that is needed to initialize the device
    void create_vdev(uint64_t size);

    // Open the existing vdev which is represnted by the vdev_info_block
    void open_vdev(vdev_info_block* vb);

    // Start the Index Service
    void start();

    // Add/Remove Index Table to/from the index service
    void add_index_table(const std::shared_ptr< IndexTableBase >& tbl);
    void remove_index_table(const std::shared_ptr< IndexTableBase >& tbl);

    iomgr::io_thread_t get_next_btree_write_thread();
    IndexWBCacheBase& wb_cache() { return *m_wb_cache; }

private:
    void meta_blk_found(const sisl::byte_view& buf, void* meta_cookie);
    void start_threads();
};

extern IndexService& index_service();
extern IndexWBCacheBase& wb_cache();

} // namespace homestore