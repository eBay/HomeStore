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
#pragma once

namespace homeds {

class AbstractMemAllocator {
public:
    virtual uint8_t* allocate(uint32_t size_needed, uint8_t** meta_blk = nullptr,
                              uint32_t* out_meta_size = nullptr) = 0;
    virtual bool deallocate(uint8_t* mem, uint32_t size_alloced = 0) = 0;
    virtual bool owns(uint8_t* mem) const = 0;
    virtual bool is_thread_safe_allocator() const = 0;
};
} // namespace homeds
