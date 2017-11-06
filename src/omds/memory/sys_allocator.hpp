/*
 * sys_allocator.hpp
 *
 *  Created on: 01-Sep-2017
 *      Author: hkadayam
 */

#ifndef MEMORY_SYS_ALLOCATOR_HPP_
#define MEMORY_SYS_ALLOCATOR_HPP_

namespace omds {

class SysMemAllocator : public AbstractMemAllocator
{
public:
    virtual ~SysMemAllocator() {}

    uint8_t *allocate(uint32_t size_needed, uint8_t **meta_blk, uint32_t *out_meta_size) override {
        uint8_t *ptr = nullptr;
        if (meta_blk && out_meta_size) {
            ptr = (uint8_t *)malloc(size_needed + sizeof(uint32_t));
            *meta_blk = (uint8_t *)(ptr + size_needed);
            *out_meta_size = sizeof(uint32_t);
        } else {
            ptr = (uint8_t *)malloc(size_needed);
        }

        //std::cout << "SysMemAllocator allocate size_needed = " << size_needed << " Allocated mem=" << ptr << "\n";
        return ptr;
    }

     bool deallocate(uint8_t *mem, uint32_t size_alloced) override {
         //std::cout << "Deallocating from SysMemAllocator\n";
         free(mem);
         return true;
     }

     bool owns(uint8_t *mem) const override {
         return true;
     }

     bool is_thread_safe_allocator() const override {
         return true;
     }
};
}



#endif /* MEMORY_SYS_ALLOCATOR_HPP_ */
