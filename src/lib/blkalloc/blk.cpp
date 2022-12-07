#include <homestore/blk.h>
#include "common/homestore_assert.hpp"

namespace homestore {
int BlkId::compare(const BlkId& one, const BlkId& two) {
    if (one.m_chunk_num > two.m_chunk_num) {
        return -1;
    } else if (one.m_chunk_num < two.m_chunk_num) {
        return 1;
    }

    if (one.m_blk_num > two.m_blk_num) {
        return -1;
    } else if (one.m_blk_num < two.m_blk_num) {
        return 1;
    }

    if (one.m_nblks > two.m_nblks) {
        return -1;
    } else if (one.m_nblks < two.m_nblks) {
        return 1;
    }

    return 0;
}

uint64_t BlkId::to_integer() const {
    const uint64_t val{m_blk_num | (static_cast< uint64_t >(m_nblks) << BLK_NUM_BITS) |
                       (static_cast< uint64_t >(m_chunk_num) << (BLK_NUM_BITS + NBLKS_BITS))};
    return val;
}

BlkId::BlkId(uint64_t id_int) { set(id_int); }
BlkId::BlkId(blk_num_t blk_num, blk_count_t nblks, chunk_num_t chunk_num) { set(blk_num, nblks, chunk_num); }

void BlkId::invalidate() { set(blk_num_t{0}, blk_count_t{0}, s_chunk_num_mask); }

bool BlkId::is_valid() const { return (m_chunk_num != s_chunk_num_mask); }

BlkId BlkId::get_blkid_at(uint32_t offset, uint32_t pagesz) const {
    assert(offset % pagesz == 0);
    const uint32_t remaining_size{((get_nblks() - (offset / pagesz)) * pagesz)};
    return (get_blkid_at(offset, remaining_size, pagesz));
}

BlkId BlkId::get_blkid_at(uint32_t offset, uint32_t size, uint32_t pagesz) const {
    assert(size % pagesz == 0);
    assert(offset % pagesz == 0);

    BlkId other;

    other.set_blk_num(get_blk_num() + (offset / pagesz));
    other.set_nblks(size / pagesz);
    other.set_chunk_num(get_chunk_num());

    assert(other.get_blk_num() < get_blk_num() + get_nblks());
    assert((other.get_blk_num() + other.get_nblks()) <= (get_blk_num() + get_nblks()));
    return other;
}

void BlkId::set(blk_num_t blk_num, blk_count_t nblks, chunk_num_t chunk_num) {
    set_blk_num(blk_num);
    set_nblks(nblks);
    set_chunk_num(chunk_num);
}

void BlkId::set(const BlkId& bid) { set(bid.get_blk_num(), bid.get_nblks(), bid.get_chunk_num()); }

void BlkId::set(uint64_t id_int) {
    HS_DBG_ASSERT_LE(id_int, max_id_int());
    m_blk_num = (id_int & s_blk_num_mask);
    m_nblks = static_cast< blk_count_t >((id_int >> BLK_NUM_BITS) & s_nblks_mask);
    m_chunk_num = static_cast< chunk_num_t >((id_int >> (BLK_NUM_BITS + NBLKS_BITS)) & s_chunk_num_mask);
}

void BlkId::set_blk_num(blk_num_t blk_num) {
    HS_DBG_ASSERT_LE(blk_num, s_blk_num_mask);
    m_blk_num = blk_num;
}

void BlkId::set_nblks(blk_count_t nblks) {
    HS_DBG_ASSERT_LE(nblks, max_blks_in_op());
    m_nblks = static_cast< blk_count_serialized_t >(nblks - 1);
}

void BlkId::set_chunk_num(chunk_num_t chunk_num) {
    HS_DBG_ASSERT_LE(chunk_num, s_chunk_num_mask);
    m_chunk_num = chunk_num;
}

std::string BlkId::to_string() const {
    return is_valid() ? fmt::format("BlkNum={} nblks={} chunk={}", get_blk_num(), get_nblks(), get_chunk_num())
                      : "Invalid_Blkid";
}
} // namespace homestore