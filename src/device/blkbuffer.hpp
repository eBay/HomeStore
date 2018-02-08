//
// Created by Kadayam, Hari on 15/11/17.
//

#ifndef OMSTORE_BLKBUFFER_HPP_HPP
#define OMSTORE_BLKBUFFER_HPP_HPP

#include "blkalloc/blk.h"
#include "cache/cache.h"

namespace omstore {

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

class BlkBuffer : public CacheBuffer< BlkId > {
    static BlkBuffer *make_object() {
        return omds::ObjectAllocator< BlkBuffer >::make_object();
    }
};

}
#endif //OMSTORE_BLKBUFFER_HPP_HPP
