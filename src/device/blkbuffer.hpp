//
// Created by Kadayam, Hari on 15/11/17.
//

#ifndef OMSTORE_BLKBUFFER_HPP_HPP
#define OMSTORE_BLKBUFFER_HPP_HPP

#include "blkstore/writeBack_cache.hpp"
#include "blkalloc/blk.h"
#include "cache/cache.h"

namespace homestore {

#if 0
class BlkBuffer : private CacheBuffer< BlkId > {
public:
    /* Provides the offset gap between this and next offset available in cache */
    uint32_t offset_gap(uint8_t ind) const {
        auto b = get_key();
        auto &mp = get_memvec().get_nth_piece(ind++);
        auto prev_off = mp.offset() + mp.size();
        if (ind == get_memvec().npieces()) {
            return ((b.get_nblks() * BLKSTORE_BLK_SIZE) - prev_off);
        } else {
            mp = get_memvec().get_nth_piece(ind);
            return (mp.offset() - prev_off);
        }
    }
};
#endif

class BlkBuffer : public WriteBackCacheBuffer< BlkId > {
public:
    static BlkBuffer* make_object() { return homeds::ObjectAllocator< BlkBuffer >::make_object(); }

    virtual void free_yourself() override { homeds::ObjectAllocator< BlkBuffer >::deallocate(this); }

    // virtual size_t get_your_size() const override { return sizeof(BlkBuffer); }
};

} // namespace homestore
#endif // OMSTORE_BLKBUFFER_HPP_HPP
