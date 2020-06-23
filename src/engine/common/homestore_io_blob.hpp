#pragma once
#include "homestore_config.hpp"
#include <iomgr/iomgr.hpp>

namespace homestore {
struct io_blob : public sisl::blob {
    bool aligned = false;

    io_blob() {}

    io_blob(bool is_aligned, size_t sz) : aligned(is_aligned) {
        size = sz;
        buf_alloc(aligned, sz);
    }

    ~io_blob() {}

    void buf_alloc(bool is_aligned, size_t sz) {
        aligned = is_aligned;
        size = sz;
        if (aligned) {
            bytes = iomanager.iobuf_alloc(HS_STATIC_CONFIG(disk_attr.align_size), sz);
        } else {
            bytes = (uint8_t*)malloc(sz);
        }
    }

    void buf_free() {
        if (aligned) {
            iomanager.iobuf_free(bytes);
        } else {
            free(bytes);
        }
    }
};

} // namespace homestore
