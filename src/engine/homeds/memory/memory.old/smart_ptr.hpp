/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 * Author/Developer(s): Harihara Kadayam
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
//
// Created by Kadayam, Hari on 03/06/17.
//

#pragma once
#include "tagged_ptr.hpp"
#include <atomic>

namespace homeds {

// A block which holds the reference count and the actual pointer. This will simply a wrapper around the tagged ptr
template < typename T >
struct smart_ptr_block {
public:
    smart_ptr_block() : m_ptr(0) {}

    smart_ptr_block(T* ptr) {
        homeds::tagged_ptr tp(ptr, 1);
        m_ptr = tp.get_packed();
    }

#if 0
    // Copy constructor, need to increment the count
    smart_ptr_block(const smart_ptr_block &other) {
        m_ptr.store(other.m_ptr.load(std::memory_order_acquire), std::memory_order_release);
    }
#endif

    smart_ptr_block(const smart_ptr_block& other) = delete;

    // Move constructor
    smart_ptr_block(smart_ptr_block&& other) noexcept : m_ptr(other.m_ptr) {}

    ~smart_ptr_block() {
        tagged_ptr tp;
        tagged_ptr::compressed_ptr_t oldval, newval;
        do {
            oldval = m_ptr.load(std::memory_order_acquire);
            tp = tagged_ptr(oldval);
            tp.dec_tag();
            newval = tp.get_packed();
        } while (!(m_ptr.compare_exchange_weak(oldval, newval, std::memory_order_acq_rel)));

        tp = tagged_ptr(newval);
        if (tp.get_tag() == 0) {
            // TODO: Change this to custom deleter
            delete (tp.get_ptr());
        }
    }

    // Copy assignment operator
    smart_ptr_block& operator=(const smart_ptr_block& other) {
        tagged_ptr tp;
        tagged_ptr::compressed_ptr_t oldval, newval;

        do {
            m_ptr = other.m_ptr;
            oldval = m_ptr.load(std::memory_order_acquire);
            tp = tagged_ptr(oldval);
            if (tp.get_ptr() == nullptr) {
                break;
            }
            tp.inc_tag();
            newval = tp.get_packed();
        } while (!(m_ptr.compare_exchange_weak(oldval, newval, std::memory_order_acq_rel)));
        return *this;
    }

    // Move assignment operator
    smart_ptr_block& operator=(smart_ptr_block&& other) {
        m_ptr = std::move(other.m_ptr);
        return *this;
    }

private:
    std::atomic< homeds::tagged_ptr::compressed_ptr_t > m_ptr;
};

template < typename T >
class atomic_smart_ptr {
public:
    atomic_smart_ptr(T* p) : m_block(p) {}

    atomic_smart_ptr(smart_ptr_block& block) : m_block(block) {}

    // Copy constructor
    atomic_smart_ptr(const atomic_smart_ptr& other) = default;

    // Move constructor
    atomic_smart_ptr(atomic_smart_ptr&& other) noexcept = default;

    // Copy assignment operator
    atomic_smart_ptr< T >& operator=(const atomic_smart_ptr< T >& other) = default;

    /// @brief the destructor releases its ownership and free if no one is referencing
    ~atomic_smart_ptr(void) = default;

    template < typename... Args >
    static atomic_smart_ptr< T > construct(Args&&... args) {
        // Allocate memory and construct the object
        uint8_t* mem = new uint8_t[sizeof(smart_ptr_block) + sizeof(T)];
        T* t = new (mem + sizeof(smart_ptr_block)) T(std::forward< Args >(args)...);

        // Use the first portion for smart_ptr_block
        smart_ptr_block* s = new (mem) T(t);
        return atomic_smart_ptr< T >(*s);
    }

    /// @brief this reset releases its ownership
    void reset(void) noexcept {

        if (m_ptr->release() == true) {
            fds::mem_allocator::instance()->free((mempool_header*)m_ptr.load());
        }
    }

    // underlying pointer operations :
    inline T& operator*() {
        // TODO: Throw excepton if m_ptr is a nullptr;
        mempool_header* hdr = (mempool_header*)(m_ptr.load());
        T* p = (T*)fds::mem_allocator::instance()->to_rawptr(hdr);
        return (T&)(*p);
    }

    inline T* operator->() {
        // TODO: Throw exception if it is a nullptr;
        mempool_header* hdr = (mempool_header*)(m_ptr.load());
        return (T*)fds::mem_allocator::instance()->to_rawptr(hdr);
    }

    inline T* get(void) {
        if (m_ptr == nullptr) {
            return nullptr;
        }

        // no assert, can return NULL
        mempool_header* hdr = (mempool_header*)(m_ptr.load());
        return (T*)fds::mem_allocator::instance()->to_rawptr(hdr);
    }

    void set_validity(bool is_valid, bool is_atomic = false) {
        if (m_ptr) {
            is_atomic ? m_ptr.load()->set_validity(is_valid) : m_ptr.load()->set_validity_atomically(is_valid);
        }
    }

    bool is_valid() { return (m_ptr ? m_ptr.load()->is_valid() : false); }

#if 0
    /// @brief this reset release its ownership and re-acquire another one
     void reset(T* p) // may throw std::bad_alloc
     {
         SHARED_ASSERT((NULL == p) || (m_rawptr != p)); // auto-reset not allowed
         release();
         acquire(p); // may throw std::bad_alloc
     }

     /// @brief Swap method for the copy-and-swap idiom (copy constructor and swap method)
     void swap(atomic_smart_ptr& lhs) throw() // never throws
     {
         std::swap(m_rawptr, lhs.m_rawptr);
         pn.swap(lhs.pn);
     }
#endif

#if 0
    bool compare_and_swap(atomic_smart_ptr &prev, atomic_smart_ptr &cur)
     {
     	m_raw_ptr.compare_exchange_weak(prev.m_raw_ptr, cur.m_raw_ptr);
     }
#endif

#if 0
    // reference counter operations :
     inline operator bool() const throw() // never throws
     {
         return (0 < pn.use_count());
     }
     inline bool unique(void)  const throw() // never throws
     {
         return (1 == pn.use_count());
     }
     long use_count(void)  const throw() // never throws
     {
         return pn.use_count();
     }
#endif

    bool cas(const fds::smart_ptr< T >& oldp, const fds::smart_ptr< T >& newp) {
        bool status = false;

        __smart_ptr< T >* old_ptr = oldp->m_ptr.load();

        // Acquire the new ptr and do a atomic swap.
        newp.m_ptr->acquire();
        status = m_ptr->compare_exchange_weak(old_ptr, newp.m_ptr);
        if (status) {
            // We need to release old_ptr and free if need be
            if (old_ptr->release() == true) {
                cout << "Freeing memory since refcount reached 0" << endl;
                fds::mem_allocator::instance()->free((mempool_header*)old_ptr);
            }
        } else {
            bool ret = newp.m_ptr->release();
            assert(ret == false); // We just inc the ref, we should not be 0.
        }

        return status;
    }

private:
    smart_ptr_block< T > m_block;
};

} // namespace homeds