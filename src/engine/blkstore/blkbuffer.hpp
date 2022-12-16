/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 * Author/Developer(s): Rishabh Mittal
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 *********************************************************************************/
#ifndef OMSTORE_BLKBUFFER_HPP_HPP
#define OMSTORE_BLKBUFFER_HPP_HPP

#include <cstdint>

#include <boost/intrusive_ptr.hpp>
#include <sisl/fds/obj_allocator.hpp>
#include <sisl/utility/atomic_counter.hpp>

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

    virtual void init() override{};

    template < typename... Args >
    static BlkBuffer* make_object(Args&&... args) {
        return sisl::ObjectAllocator< BlkBuffer >::make_object(std::forward< Args >(args)...);
    }
    static sisl::buftag get_buf_tag() { return sisl::buftag::common; }

    virtual void free_yourself() { sisl::ObjectAllocator< BlkBuffer >::deallocate(this); }

    // virtual size_t get_your_size() const override { return sizeof(BlkBuffer); }

    friend void intrusive_ptr_add_ref(BlkBuffer* const buf);
    friend void intrusive_ptr_release(BlkBuffer* const buf);
};

} // namespace homestore
#endif // OMSTORE_BLKBUFFER_HPP_HPP
