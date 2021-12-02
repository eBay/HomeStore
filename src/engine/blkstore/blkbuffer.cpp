#include "blkbuffer.hpp"

namespace homestore {

void intrusive_ptr_add_ref(BlkBuffer* const buf) {
    // manage through base pointer
    intrusive_ptr_add_ref(static_cast< typename BlkBuffer::CacheBufferType* >(buf));
}

void intrusive_ptr_release(BlkBuffer* const buf) {
    // manage through base pointer
    intrusive_ptr_release(static_cast< typename BlkBuffer::CacheBufferType* >(buf));
}

} // namespace homestore

