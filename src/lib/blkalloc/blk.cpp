/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
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
#include <homestore/blk.h>
#include "common/homestore_assert.hpp"

namespace homestore {
BlkId::BlkId(uint64_t id_int) {
    *r_cast< uint64_t* >(&s) = id_int;
    DEBUG_ASSERT_EQ(is_multi(), 0, "MultiBlkId is set on BlkId constructor");
}

BlkId::BlkId(blk_num_t blk_num, blk_count_t nblks, chunk_num_t chunk_num) : s{0x0, blk_num, nblks, chunk_num} {}

uint64_t BlkId::to_integer() const { return *r_cast< const uint64_t* >(&s); }

sisl::blob BlkId::serialize() { return sisl::blob{r_cast< uint8_t* >(&s), sizeof(serialized)}; }

uint32_t BlkId::serialized_size() const { return sizeof(BlkId); }
uint32_t BlkId::expected_serialized_size() { return sizeof(BlkId); }

void BlkId::deserialize(sisl::blob const& b, bool copy) {
    serialized* other = r_cast< serialized const* >(b.cbytes());
    s = *other;
}

void BlkId::invalidate() { s.m_nblks = 0; }

bool BlkId::is_valid() const { return (blk_count() > 0); }

std::string BlkId::to_string() const {
    return is_valid() ? fmt::format("BlkNum={} nblks={} chunk={}", blk_num(), blk_count(), chunk_num())
                      : "Invalid_Blkid";
}

int BlkId::compare(const BlkId& one, const BlkId& two) {
    if (one.chunk_num() < two.chunk_num()) {
        return -1;
    } else if (one.chunk_num() > two.chunk_num()) {
        return 1;
    }

    if (one.blk_num() < two.blk_num()) {
        return -1;
    } else if (one.blk_num() > two.blk_num()) {
        return 1;
    }

    if (one.blk_count() < two.blk_count()) {
        return -1;
    } else if (one.blk_count() > two.blk_count()) {
        return 1;
    }

    return 0;
}

//////////////////////////////////// MultiBlkId Section //////////////////////////////
MultiBlkId::MultiBlkId() : BlkId::BlkId() { s.m_is_multi = 1; }

MultiBlkId::MultiBlkId(BlkId const& b) : BlkId::BlkId(b) { s.m_is_multi = 1; }

MultiBlkId::MultiBlkId(blk_num_t blk_num, blk_count_t nblks, chunk_num_t chunk_num) :
        BlkId::BlkId{blk_num, nblks, chunk_num} {
    s.m_is_multi = 1;
}

void MultiBlkId::add(blk_num_t blk_num, blk_count_t nblks, chunk_num_t chunk_num) {
    if (BlkId::is_valid()) {
        RELEASE_ASSERT_EQ(s.m_chunk_num, chunk_num, "MultiBlkId has to be all from same chunk");
        RELEASE_ASSERT_LT(n_addln_piece, max_addln_pieces, "MultiBlkId cannot support more than {} pieces",
                          max_addln_pieces + 1);
        addln_pieces[n_addln_piece] = chain_blkid{.m_blk_num = blk_num, .m_nblks = nblks};
        ++n_addln_piece;
    } else {
        s = BlkId::serialized{0x1, blk_num, nblks, chunk_num};
    }
}

void MultiBlkId::add(BlkId const& b) { add(b.blk_num(), b.blk_count(), b.chunk_num()); }

sisl::blob MultiBlkId::serialize() { return sisl::blob{r_cast< uint8_t* >(this), serialized_size()}; }

uint32_t MultiBlkId::serialized_size() const {
    uint32_t sz = BlkId::serialized_size();
    if (n_addln_piece != 0) { sz += sizeof(uint16_t) + (n_addln_piece * sizeof(chain_blkid)); }
    return sz;
}

void MultiBlkId::deserialize(sisl::blob const& b, bool copy) {
    MultiBlkId* other = r_cast< MultiBlkId const* >(b.cbytes());
    s = other->s;
    if (b.size() == sizeof(BlkId)) {
        n_addln_piece = 0;
    } else {
        n_addln_piece = other->n_addln_piece;
        std::copy(other->addln_pieces.begin(), other->addln_pieces.begin() + other->n_addln_piece,
                  addln_pieces.begin());
    }
}

uint32_t MultiBlkId::expected_serialized_size(uint16_t num_pieces) {
    uint32_t sz = BlkId::expected_serialized_size();
    if (num_pieces > 1) { sz += sizeof(uint16_t) + ((num_pieces - 1) * sizeof(chain_blkid)); }
    return sz;
}

uint32_t MultiBlkId::max_serialized_size() { return expected_serialized_size(max_pieces); }

uint16_t MultiBlkId::num_pieces() const { return BlkId::is_valid() ? n_addln_piece + 1 : 0; }

bool MultiBlkId::has_room() const { return (n_addln_piece < max_addln_pieces); }

MultiBlkId::iterator MultiBlkId::iterate() const { return MultiBlkId::iterator{*this}; }

std::string MultiBlkId::to_string() const {
    std::string str = "MultiBlks: {";
    auto it = iterate();
    while (auto const b = it.next()) {
        str += (b->to_string() + " ");
    }
    str += std::string("}");
    return str;
}

blk_count_t MultiBlkId::blk_count() const {
    blk_count_t nblks{0};
    auto it = iterate();
    while (auto b = it.next()) {
        nblks += b->blk_count();
    }
    return nblks;
}

BlkId MultiBlkId::to_single_blkid() const {
    HS_DBG_ASSERT_LE(num_pieces(), 1, "Can only MultiBlkId with one piece to BlkId");
    return BlkId{blk_num(), blk_count(), chunk_num()};
}

int MultiBlkId::compare(MultiBlkId const& left, MultiBlkId const& right) {
    if (left.chunk_num() < right.chunk_num()) {
        return -1;
    } else if (left.chunk_num() > right.chunk_num()) {
        return 1;
    }

    // Shortcut path for simple BlkId search to avoid building icl set
    if ((left.num_pieces() == 1) && (right.num_pieces() == 1)) {
        return BlkId::compare(d_cast< BlkId const& >(left), d_cast< BlkId const& >(right));
    }

    using IntervalSet = boost::icl::interval_set< uint64_t >;
    using Interval = IntervalSet::interval_type;

    IntervalSet lset;
    auto lit = left.iterate();
    while (auto b = lit.next()) {
        lset.insert(Interval::right_open(b->blk_num(), b->blk_num() + b->blk_count()));
    }

    IntervalSet rset;
    auto rit = right.iterate();
    while (auto b = rit.next()) {
        rset.insert(Interval::right_open(b->blk_num(), b->blk_num() + b->blk_count()));
    }

    if (lset < rset) {
        return -1;
    } else if (lset > rset) {
        return 1;
    } else {
        return 0;
    }
}
} // namespace homestore
