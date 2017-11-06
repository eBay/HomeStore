//
// Created by Kadayam, Hari on 30/10/17.
//
#include "cache.h"

namespace omstore {
template< typename K >
inline void intrusive_ptr_release(CacheBuffer< K > *buf) {
    if (buf->m_refcount.decrement_testz()) {
        // First free the bytes it covers
        omds::blob blob;
        buf->get_evict_record().m_mem.get(&blob);
        free((void *) blob.bytes);

        // Then free the record itself
        Cache< K >::get_allocator()->deallocate((uint8_t *) buf, sizeof(omstore::CacheBuffer< K >));
    }
}
}
