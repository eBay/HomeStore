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
#ifndef MEMORY_SYS_ALLOCATOR_HPP_
#define MEMORY_SYS_ALLOCATOR_HPP_

namespace homeds {

class SysMemAllocator : public AbstractMemAllocator {
public:
    virtual ~SysMemAllocator() {}

    uint8_t* allocate(uint32_t size_needed, uint8_t** meta_blk, uint32_t* out_meta_size) override {
        uint8_t* ptr = nullptr;
        if (meta_blk && out_meta_size) {
            ptr = (uint8_t*)malloc(size_needed + sizeof(uint32_t));
            *meta_blk = (uint8_t*)(ptr + size_needed);
            *out_meta_size = sizeof(uint32_t);
        } else {
            ptr = (uint8_t*)malloc(size_needed);
        }

        // std::cout << "SysMemAllocator allocate size_needed = " << size_needed << " Allocated mem=" << ptr << "\n";
        return ptr;
    }

    bool deallocate(uint8_t* mem, uint32_t size_alloced) override {
        // std::cout << "Deallocating from SysMemAllocator\n";
        free(mem);
        return true;
    }

    bool owns(uint8_t* mem) const override { return true; }

    bool is_thread_safe_allocator() const override { return true; }
};
} // namespace homeds

#endif /* MEMORY_SYS_ALLOCATOR_HPP_ */
