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
#pragma once

#include "device/heap_chunk_selector.h"
#include "device/round_robin_chunk_selector.h"


namespace homestore {
class ChunkSelectorFactory {
public:
    ChunkSelectorFactory() = default;
    ChunkSelectorFactory(const ChunkSelectorFactory&) = delete;
    ChunkSelectorFactory(ChunkSelectorFactory&&) noexcept = delete;
    ChunkSelectorFactory& operator=(const ChunkSelectorFactory&) = delete;
    ChunkSelectorFactory& operator=(ChunkSelectorFactory&&) noexcept = delete;
    ~ChunkSelectorFactory() = default;

    static std::unique_ptr<ChunkSelector> getChunkSelector(chunk_selector_type_t t) {
        switch (t) {
            case chunk_selector_type_t::HEAP:
                return std::make_unique<HeapChunkSelector>();
            default:
                return std::make_unique<RoundRobinChunkSelector>(false);
        }
    }
};
} // namespace homestore
