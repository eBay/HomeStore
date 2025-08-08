/*********************************************************************************
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
#pragma once

#include <cstdint>
#include <memory>
#include <array>
#include <vector>
#include <mutex>
#include <atomic>

namespace homestore {

template < typename T, size_t IncrementalSize = 1024 >
class ConcurrentVector {
private:
    struct Block {
        std::array< T, IncrementalSize > m_data;
    };

    std::vector< Block > m_blocks;
    std::mutex m_mutex;
    std::atomic< size_t > m_size{0};

public:
    struct iterator {
        size_t slot_num{0};
        ConcurrentVector* vec;

        iterator() = default;
        iterator(ConcurrentVector* v, size_t s) : slot_num{s}, vec{v} {}

        void operator++() { ++slot_num; }
        void operator+=(int64_t count) { slot_num += count; }

        bool operator==(iterator const& other) const = default;
        bool operator!=(iterator const& other) const = default;

        T const& operator*() const { return vec->at(slot_num); }
        T const* operator->() const { return &(vec->at(slot_num)); }
        T&& operator*() { return std::move(vec->at(slot_num)); }
    };

public:
    friend class ConcurrentVector::iterator;

    ConcurrentVector() { m_blocks.emplace_back(Block{}); }
    ConcurrentVector(size_t size) : m_blocks{(size + IncrementalSize - 1) / IncrementalSize} {}
    ConcurrentVector(const ConcurrentVector&) = delete;
    ConcurrentVector(ConcurrentVector&&) noexcept = delete;
    ConcurrentVector& operator=(const ConcurrentVector&) = delete;
    ConcurrentVector& operator=(ConcurrentVector&&) noexcept = delete;
    ~ConcurrentVector() = default;

    template < typename U = T >
    std::enable_if_t< std::is_copy_constructible_v< U >, void > push_back(U const& ele) {
        *(data(get_next_slot())) = ele;
    }
    void emplace_back(T&& ele) { *(data(get_next_slot())) = std::move(ele); }

    T& at(size_t slot) { return *(data(slot)); }
    T const& at(size_t slot) const { return *(data_const(slot)); }
    T& operator[](size_t slot) { return *(data(slot)); }
    T const& operator[](size_t slot) const { return *(data_const(slot)); }
    size_t size() const { return m_size.load(); }
    void clear() { m_size.store(0); }

    iterator begin() { return iterator(this, 0); }
    iterator end() { return iterator(this, size()); }

private:
    size_t get_next_slot() {
        auto next_id = m_size.fetch_add(1);
        if (next_id >= m_blocks.size() * IncrementalSize) {
            std::unique_lock lg{m_mutex};
            m_blocks.emplace_back(Block{});
        }
        return next_id;
    }

    T* data(size_t slot) { return &m_blocks[slot / IncrementalSize].m_data[slot % IncrementalSize]; }
    T const* data_const(size_t slot) { return &m_blocks[slot / IncrementalSize].m_data[slot % IncrementalSize]; }
};
}
