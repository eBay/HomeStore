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
#ifndef COMPOSITE_ALLOCATOR_HPP
#define COMPOSITE_ALLOCATOR_HPP

#include <vector>
#include <tuple>
#include <memory>
#include <array>
#include "mem_allocator.hpp"
#include "sys_allocator.hpp"

namespace homeds {

#if 0
template <typename... Allocators>
class CompositeMemAllocator
{
public:
    CompositeMemAllocator(uint32_t total_mem_size) {
        m_mem_size_per_allocator = total_mem_size;
        create_allocator<Allocators...>();
    }

    template<typename T1, typename T2, typename ...Ts>
    void create_allocator() {
        create_allocator<T1>();
        create_allocator<T2, Ts...>();
    }

    template<typename T>
    void create_allocator() {
        m_allocators[count++] = std::make_unique<T>(m_mem_size_per_allocator);
    }

    uint8_t *allocate(uint32_t size_needed, uint8_t **meta_blk = nullptr) {
        uint8_t *ret_mem;
        for (auto i = 0u; i < m_allocators.size(); i++) {
            ret_mem = m_allocators[i]->allocate(size_needed, meta_blk);
            if (ret_mem != nullptr) {
                break;
            }
        }
        return ret_mem;
    }

private:
    std::array< std::unique_ptr< AbstractAllocator >, sizeof...(Allocators) > m_allocators;
    uint32_t m_mem_size_per_allocator;

    static int count = 0;
};
#endif

class StackedMemAllocator {
public:
    StackedMemAllocator() {}

    void add(std::unique_ptr< AbstractMemAllocator > a) { m_allocators.push_back(std::move(a)); }

    uint8_t* allocate(uint32_t size_needed, uint8_t** meta_blk = nullptr) {
        uint8_t* ret_mem;
        for (auto i = 0u; i < m_allocators.size(); i++) {
            ret_mem = m_allocators[i]->allocate(size_needed, meta_blk);
            if (ret_mem != nullptr) { break; }
        }
        return ret_mem;
    }

    bool deallocate(uint8_t* mem, uint32_t size_alloced = 0) {
        for (auto i = 0u; i < m_allocators.size(); i++) {
            if (m_allocators[i]->deallocate(mem)) { return true; }
        }
        return false;
    }

    bool owns(uint8_t* mem) const {
        for (auto i = 0u; i < m_allocators.size(); i++) {
            if (owns(mem)) { return true; }
        }
        return false;
    }

private:
    std::vector< std::unique_ptr< AbstractMemAllocator > > m_allocators;
};

template < typename... Allocators >
class CompositeMemAllocator {
public:
    CompositeMemAllocator() {
        m_count = 0;
        create_allocator< Allocators... >();
    }

    template < typename T1, typename T2, typename... Ts >
    void create_allocator() {
        create_allocator< T1 >();
        create_allocator< T2, Ts... >();
    }

    template < typename T >
    void create_allocator() {
        m_allocators[m_count++] = std::make_unique< T >();
        // m_allocators[m_count++] = new T();
    }

    uint8_t* allocate(uint32_t size_needed, uint8_t** meta_blk = nullptr, uint32_t* out_meta_size = nullptr) {
        uint8_t* ret_mem;
        for (auto i = 0u; i < m_allocators.size(); i++) {
            ret_mem = m_allocators[i]->allocate(size_needed, meta_blk, out_meta_size);
            if (ret_mem != nullptr) { break; }
        }
        return ret_mem;
    }

    bool deallocate(uint8_t* mem, uint32_t size_alloced = 0) {
        for (auto i = 0u; i < m_allocators.size(); i++) {
            if (m_allocators[i]->deallocate(mem, size_alloced)) { return true; }
        }
        return false;
    }

    bool owns(uint8_t* mem) const {
        for (auto i = 0u; i < m_allocators.size(); i++) {
            if (owns(mem)) { return true; }
        }
        return false;
    }

private:
    std::array< std::unique_ptr< AbstractMemAllocator >, sizeof...(Allocators) > m_allocators;
    int m_count;
};

} // namespace homeds
  // namespace homeds
#endif