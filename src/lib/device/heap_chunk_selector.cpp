/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
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
#include "device/heap_chunk_selector.h"

namespace homestore {

void HeapChunkSelector::add_chunk(cshared< Chunk >& chunk) {
    if(!chunk) return;
    std::unique_lock<std::mutex> l(lock);
    m_chunk_heap.push(chunk);
}

Chunk* HeapChunkSelector::select(blk_count_t, const blk_alloc_hints&) {
    std::unique_lock<std::mutex> l(lock);
    if(m_chunk_heap.empty()) return nullptr;
    auto ret = m_chunk_heap.top();
    m_chunk_heap.pop(); 
    return ret.get();
}

void HeapChunkSelector::remove_chunk(cshared< Chunk >& chunk) {
    if(!chunk) return;
    std::vector<shared< Chunk >> chunks;
    chunks.reserve(m_chunk_heap.size());
    std::unique_lock<std::mutex> l(lock);
    while (!m_chunk_heap.empty()) {
        auto t = m_chunk_heap.top();
        m_chunk_heap.pop();
        if(t == chunk) break;
        chunks.push_back(t);
    }
    for (const auto& c : chunks) {
        m_chunk_heap.push(c);       
    }
}

void HeapChunkSelector::foreach_chunks(std::function< void(cshared< Chunk >&) >&& cb) {
    decltype(m_chunk_heap) tempHeap;
    while(!m_chunk_heap.empty()) {
        auto t = m_chunk_heap.top();
        m_chunk_heap.pop();
        cb(t);
        tempHeap.push(t);
    }
    m_chunk_heap.swap(tempHeap);
}

} // namespace homestore
