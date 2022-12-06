/**
 * Copyright (C) 2017-present Jung-Sang Ahn <jungsang.ahn@gmail.com>
 * All rights reserved.
 *
 * https://github.com/greensky00
 *
 * Atomic Shared Pointer
 * Version: 0.1.2
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#pragma once

#include <atomic>
#include <mutex>

template<typename T>
class ashared_ptr {
  public:
    ashared_ptr() : object{nullptr} {}
      ashared_ptr(T* const src_ptr) : object{(src_ptr) ? new PtrWrapper< T >(src_ptr) : nullptr} {}
    ashared_ptr(const ashared_ptr< T >& src) : object{nullptr} {
        operator=(src);
    }

    ~ashared_ptr() {
        reset();
    }

    void reset() {
        std::lock_guard<std::mutex> l{lock};
        PtrWrapper< T >* const ptr{object.load(MO)};
        // Unlink pointer first, destroy object next.
        object.store(nullptr, MO);
        releaseObject(ptr);
    }

    bool operator==(const ashared_ptr<T>& src) const {
        return object.load(MO) == src.object.load(MO);
    }

    bool operator==(const T* src) const {
        if (!object.load(MO)) {
            // If current `object` is NULL,
            return src == nullptr;
        }
        return object.load(MO)->ptr.load(MO) == src;
    }

    void operator=(const ashared_ptr< T >& src) {
        std::lock_guard< std::mutex > l{lock};

        ashared_ptr< T >& writable_src{const_cast< ashared_ptr< T >& >(src)};
        PtrWrapper< T >* const src_object{writable_src.shareCurObject()};

        // Replace object.
        PtrWrapper< T >* const old{object.load(MO)};
        object.store(src_object, MO);

        // Release old object.
        releaseObject(old);
    }

    T* operator->() const {
        return object.load(MO)->ptr.load(MO);
    }
    T& operator*() const {
        return *object.load(MO)->ptr.load(MO);
    }
    T* get() const {
        return object.load(MO)->ptr.load(MO);
    }

    inline bool compare_exchange_strong(ashared_ptr<T>& expected,
                                        ashared_ptr<T> src,
                                        [[maybe_unused]] const std::memory_order order) {
        return compare_exchange(expected, src);
    }

    inline bool compare_exchange_weak(ashared_ptr<T>& expected,
                                      ashared_ptr<T> src,
                                      [[maybe_unused]] const std::memory_order order) {
        return compare_exchange(expected, src);
    }

    bool compare_exchange(ashared_ptr<T>& expected, ashared_ptr<T> src) {
        // Note: it is OK that `expected` becomes outdated.
        PtrWrapper< T >* expected_ptr{expected.object.load(MO)};
        PtrWrapper< T >* const val_ptr{src.shareCurObject()};

        {
            // Lock for `object`
            std::lock_guard< std::mutex > l{lock};
            if (object.compare_exchange_weak(expected_ptr, val_ptr)) {
                // Succeeded.
                // Release old object.
                releaseObject(expected.object.load(MO));
                return true;
            }
        }
        // Failed.
        expected = *this;
        // Release the object from `src`.
        releaseObject(val_ptr);
        return false;
    }

  private:
    template<typename T2>
    struct PtrWrapper {
        PtrWrapper() : ptr{nullptr}, refCount{0} {}
        PtrWrapper(T2* const src) : ptr{src}, refCount{1} {}

        std::atomic<T2*> ptr;
        std::atomic<uint64_t> refCount;
    };

    // Atomically increase ref count and then return.
    PtrWrapper<T>* shareCurObject() {
        std::lock_guard< std::mutex > l{lock};
        if (!object.load(MO)) return nullptr;

        // Now no one can change `object`.
        // By increasing its ref count, `object` will be safe
        // until the new holder (i.e., caller) is destructed.
        object.load(MO)->refCount.fetch_add(1, MO);
        return object.load(MO);
    }

    // Decrease ref count and delete if no one refers to it.
    void releaseObject(PtrWrapper<T>* const target) {
        if (!target) return;
        if (target->refCount.fetch_sub(1, MO) == 1) {
            std::atomic_thread_fence(std::memory_order_acquire);
            // Last shared pointer, delete it.
            delete target->ptr.load(MO);
            delete target;
        }
    }

    constexpr static std::memory_order MO{std::memory_order_relaxed};

    std::atomic<PtrWrapper<T>*> object;
    std::mutex lock;
};
