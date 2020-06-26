#pragma once
#include "homestore_config.hpp"
#include <iomgr/iomgr.hpp>

namespace homestore {

struct iobuf_aligned_allocator {
    uint8_t* operator()(size_t align_sz, size_t sz) { return iomanager.iobuf_alloc(align_sz, sz); }
};

struct iobuf_aligned_free {
    void operator()(uint8_t* b) { iomanager.iobuf_free(b); }
};

template < typename T >
struct iobuf_aligned_deleter {
    void operator()(T* p) {
        p->~T();
        iomanager.iobuf_free((uint8_t*)p);
    }
};

} // namespace homestore
