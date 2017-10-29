/*
 * MemAllocator.hpp
 *
 *  Created on: 16-May-2016
 *      Author: hkadayam
 */

//  Copyright © 2016 Kadayam, Hari. All rights reserved.
#pragma once

#include <iostream>
#include <assert.h>
#include <limits.h>
#include <boost/intrusive_ptr.hpp>

namespace omds {

struct MemBlk {
public:
    uint8_t *mem;
    uint32_t id;
    uint32_t size;
};

template <typename T>
class ObjectAllocator
{
public:
    template <class... Args>
    static boost::intrusive_ptr<T> make_object(Args &&... args) {
        //static_assert(is_base_of(T) == RefCountedObject);
        uint8_t *mem = new uint8_t[sizeof(T)];
        T *ptr = new (mem) T(std::forward<Args>(args)...);
        return boost::intrusive_ptr< T >(ptr);
    }

    static void deallocate(const T *mem) {
        delete(mem);
    }
};

template <typename T>
struct RefCountedObject
{
    mutable std::atomic< uint32_t > m_refcount;

    friend void intrusive_ptr_add_ref(const T *x)
    {
        x->m_refcount.fetch_add(1, std::memory_order_relaxed);
    }

    friend void intrusive_ptr_release(const T *x)
    {
        if (x->m_refcount.fetch_sub(1, std::memory_order_release) == 1) {
            std::atomic_thread_fence(std::memory_order_acquire);
            ObjectAllocator< T >::deallocate(x);
        }
    }
};

} // namespace omds