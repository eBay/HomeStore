/*
 * memallocator.h
 *
 *  Created on: 21-Dec-2016
 *      Author: hkadayam
 */

//  Copyright © 2016 Kadayam, Hari. All rights reserved.
#pragma once

namespace omds {

class AbstractMemAllocator
{
public:
    virtual uint8_t *allocate(uint32_t size_needed, uint8_t **meta_blk = nullptr) = 0;
    virtual bool deallocate(uint8_t *mem, uint32_t size_alloced = 0) = 0;
    virtual bool owns(uint8_t *mem) const = 0;
    virtual bool is_thread_safe_allocator() const = 0;
};
}
