//
// Created by Kadayam, Hari on 15/11/17.
//

#ifndef OMSTORE_BLKBUFFER_HPP_HPP
#define OMSTORE_BLKBUFFER_HPP_HPP

#include <cstdint>

#include <boost/intrusive_ptr.hpp>
#include <fds/obj_allocator.hpp>
#include <utility/atomic_counter.hpp>

#include "engine/blkalloc/blk.h"
#include "engine/cache/cache.h"

namespace homestore {

class BlkBuffer : public CacheBuffer< BlkId > {
public:
    typedef CacheBuffer< BlkId > CacheBufferType;

    BlkBuffer() = default;
    BlkBuffer(const BlkBuffer&) = delete;
    BlkBuffer& operator=(const BlkBuffer&) = delete;
    BlkBuffer(BlkBuffer&&) noexcept = delete;
    BlkBuffer& operator=(BlkBuffer&&) noexcept = delete;
    virtual ~BlkBuffer() override = default;

    virtual void init() override {};
    
    template <typename... Args>
    static BlkBuffer* make_object(Args... args) { return sisl::ObjectAllocator< BlkBuffer >::make_object(std::forward<Args>(args)...); }
    static sisl::buftag get_buf_tag() { return sisl::buftag::common; }

    void free_yourself() { sisl::ObjectAllocator< BlkBuffer >::deallocate(this); }

    // virtual size_t get_your_size() const override { return sizeof(BlkBuffer); }

    friend void intrusive_ptr_add_ref(BlkBuffer* const buf);
    friend void intrusive_ptr_release(BlkBuffer* const buf);
};

} // namespace homestore
#endif // OMSTORE_BLKBUFFER_HPP_HPP
