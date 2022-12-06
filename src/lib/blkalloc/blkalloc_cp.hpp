#pragma once
#include <vector>
#include <sisl/fds/thread_vector.hpp>
#include "blk.h"
#include "homestore_decl.hpp"

namespace homestore {
class HomeStore;

typedef std::shared_ptr< HomeStore > HomeStoreSafePtr;

using blkid_list_ptr = std::shared_ptr< sisl::ThreadVector< BlkId > >;
typedef std::function< void(uint64_t) > notify_size_freed_cb_t;

struct blkalloc_cp {
public:
    bool suspend{false};
    std::vector< blkid_list_ptr > free_blkid_list_vector;
    HomeStoreSafePtr m_hs;
    notify_size_freed_cb_t m_notify_free;

public:
    blkalloc_cp();
    [[nodiscard]] bool is_suspend() const { return suspend; }
    void suspend_cp() { suspend = true; }
    void resume_cp() { suspend = false; }
    void free_blks(const blkid_list_ptr& list);
    void notify_size_on_done(notify_size_freed_cb_t cb) { m_notify_free = std::move(cb); }
    ~blkalloc_cp();
};
} // namespace homestore
