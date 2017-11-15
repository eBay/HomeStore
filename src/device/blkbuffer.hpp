//
// Created by Kadayam, Hari on 15/11/17.
//

#ifndef OMSTORE_BLKBUFFER_HPP_HPP
#define OMSTORE_BLKBUFFER_HPP_HPP

#include "blkalloc/blk.h"
#include "cache/cache.h"

namespace omstore {
class BlkBuffer : private CacheBuffer< blk_id > {
public:
    void set_id(blk_id &bid) {
        this->set_key(bid);
    }

    void set_id(uint64_t id) {
        blk_id bid(id, 0);
        set_id(bid);
    }

    blk_id &get_id() const {
        return get_key();
    }

    void set_buf(const omds::blob &b) {
        set_mem(b);
    }

    void get_buf(omds::blob *out_b, uint32_t piece_num = 0) {
        get_mem(out_b, piece_num);
    }

    uint32_t get_size() const {
        return get_evict_record_const().m_mem.size();
    }

    uint32_t npieces() const {
        return get_evict_record_const().m_mem.npieces();
    }
};
}
#endif //OMSTORE_BLKBUFFER_HPP_HPP
