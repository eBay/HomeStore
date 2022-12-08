#pragma once
#include <memory>
#include <unordered_map>
#include <vector>

#include <iomgr/iomgr.hpp>
#include <homestore/homestore_decl.hpp>
#include <homestore/index/index_table.hpp>

namespace homestore {

class IndexWBCache;
class IndexTable;

class IndexServiceCallbacks {
public:
    virtual std::shared_ptr< IndexTable > on_index_table_found(const index_table_sb& cb) = 0;
};

class IndexService {
private:
    std::unique_ptr< IndexServiceCallbacks > m_svc_cbs;
    std::unique_ptr< IndexWBCacheBase > m_wb_cache;
    std::vector< iomgr::io_thread_t > m_btree_write_thread_ids; // user io threads for btree write

    std::mutex m_index_map_mtx;
    std::unordered_map< uuid_t, std::shared_ptr< IndexTableBase > > m_index_map;

public:
    IndexService(std::unique_ptr< IndexServiceCallbacks > cbs, std::unique_ptr< IndexWBCache > wb_cache);

    void add_index_table(const std::shared_ptr< IndexTableBase >& tbl);
    iomgr::io_thread_t get_next_btree_write_thread();

    IndexWBCacheBase& wb_cache() { return *m_wb_cache; }
};

extern IndexService& index_service();
extern IndexWBCacheBase& wb_cache();

} // namespace homestore