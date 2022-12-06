#pragma once
#include <memory>
#include <unordered_map>
#include <vector>

#include <iomgr/iomgr.hpp>
#include "homestore_decl.hpp"

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
    std::unique_ptr< IndexWBCache > m_wb_cache;
    std::vector< iomgr::io_thread_t > m_btree_write_thread_ids; // user io threads for btree write

    std::mutex m_index_map_mtx;
    std::unordered_map< uuid_t, std::shared_ptr< IndexTable > > m_index_map;

public:
    IndexService(std::unique_ptr< IndexServiceCallbacks > cbs, std::unique_ptr< IndexWBCache > wb_cache);

    void add_index_table(const std::shared_ptr< IndexTable >& tbl);
    iomgr::io_thread_t get_next_btree_write_thread();

    IndexWBCache* wb_cache() { return m_wb_cache.get(); }
};

} // namespace homestore