#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <set>
#include <sstream>
#include <string>

#include "blkalloc/blk.h"

namespace homestore {
static constexpr uint32_t META_BLK_HDR_MAX_SZ{512}; // max meta_blk_hdr size
static constexpr uint32_t META_BLK_MAGIC{0xCEEDBEED};
static constexpr uint32_t META_BLK_OVF_MAGIC{0xDEADBEEF};
static constexpr uint32_t META_BLK_SB_MAGIC{0xABCDCEED};
static constexpr uint32_t META_BLK_SB_VERSION{0x1};
static constexpr uint32_t META_BLK_VERSION{0x1};
static constexpr uint32_t MAX_SUBSYS_TYPE_LEN{64};
static constexpr uint32_t CONTEXT_DATA_OFFSET_ALIGNMENT{64};

/**
 * Sub system types and their priorities
 */
typedef uint32_t crc32_t;

// clang-format off
/*
 * MetaBlk (MB) Layout Description:
 * 1. Meta Blks are linked in a single linked list on disk;
 *
 * |----------|      |------------------|      |------------------|               |-------------------|
 * | Meta SSB | ---> | 1st Subsystem MB | ---> | 2nd Subsystem MB | ---> ... ---> | Last Subsystem MB | -> null
 * |----------|      |------------------|      |------------------|               |-------------------|
 *
 * 2. For any Meta Blk:
 *
 *  <-------------------            Subsystem Meta Blk Record        ------------------->
 * |-------------------------------------------------------------------------------------|
 * | magic | crc |   ...  | prev | next | overflow |  data_size |     context_data       | 
 * |-------------------------------------------------------------------------------------|
 *                           |     |        |    
 *                           |     |        |      <--------------          Meta Blk Overflow Blk Chain         ------------------>
 *      |---------------|    |     |        |     |------------------|      |------------------|               |-------------------|
 *      | Prev Meta Blk | <--|     |        |---> | 1st overflow blk | ---> | 2nd overflow blk | ---> ... ---> | Last overflow blk | ---> null
 *      |---------------|          |              |------------------|      |------------------|               |-------------------|
 *                                 |
 *                                 |     |---------------|
 *                                 |---> | Next Meta Blk | ---> ... --> null
 *                                       |---------------|
 *
 * 3. For any Overflow Blk
 *
 *    Note: Al the context data will be stored in ovf blk chain's data blks, 
 *    nothing will be written in meta blk's context data portion (address won't be dma_boundary aligned)
 *
 *                          Overflow Header Blk           Overflow Header Blk
 *   |----------|            |--------------|              |--------------|
 *   | Meta Blk | ---------> |   next_bid   | -----------> |   next_bid   | -----------> ...
 *   |----------|            |--------------|              |--------------|
 *                           |  data_blkid  |              |  data_blkid  |
 *                           |--------------|              |--------------|
 *                                   |                            |
 *                                   |     Overflow Data Blk      |    Overflow Data Blk
 *                                   |      |-------------|       |     |-------------|
 *                                   |--->  | data buffer |       |---> | data buffer |
 *                                          | ------------|             |-------------|
 * */
// clang-format on

// in-memory only data structure
struct MetaSubRegInfo {
    uint8_t do_crc{1};              // crc check for this client
    std::set< uint64_t > meta_bids; // meta blk id
    meta_blk_found_cb_t cb{nullptr};
    meta_blk_recover_comp_cb_t comp_cb{nullptr};
};

// meta blk super block put as 1st block in the block chain;
#pragma pack(1)
struct meta_blk_sb {
    uint32_t magic; // ssb magic
    uint32_t version;
    BlkId8_t next_bid; // next metablk
    BlkId8_t bid;
    uint8_t migrated;
    uint8_t pad[7];
    std::string to_string() const {
        return fmt::format("magic: {}, version: {}, next_bid: {}, self_bid: {}", magic, version, next_bid.to_string(),
                           bid.to_string());
    }
};
#pragma pack()

//
// 1. If overflow blkid is invalid, meaning context_sz is not larger than context_data_size(),
//    context data is stored in context_data field;
// 2. If overflow blkid is not invalid, all the context data is stored in overflow blks;
//
#pragma pack(1)
struct meta_blk_hdr_s {
    uint32_t magic; // magic
    uint32_t version;
    uint32_t gen_cnt; // generation count, bump on every update
    crc32_t crc;
    BlkId8_t next_bid;      // next metablk
    BlkId8_t prev_bid;      // previous metablk
    BlkId8_t ovf_bid;       // overflow blk id;
    BlkId8_t bid;           // current blk id; might not be needd;
    uint64_t context_sz;    // total size of context data; if compressed is true, it is the round up of compressed size
                            // that is written to disk; if compressed is false, it is the original size of context data;
    uint64_t compressed_sz; // compressed size before round up to align_size, used for decompress
    uint64_t src_context_sz;        // context_sz before compression, this field only valid when compressed is true;
    char type[MAX_SUBSYS_TYPE_LEN]; // sub system type;
    uint8_t compressed;             // context data compression bitword
    uint8_t pad[7];

    std::string to_string() const {
        return fmt::format("type: {}, version: {}, magic: {}, crc: {}, next_bid: {}, prev_bid: {}, ovf_bid: {}, "
                           "self_bid: {}, compressed: {}",
                           type, version, magic, crc, next_bid.to_string(), prev_bid.to_string(), ovf_bid.to_string(),
                           bid.to_string(), compressed);
    }
};
#pragma pack()

static constexpr uint32_t META_BLK_HDR_RSVD_SZ{
    (META_BLK_HDR_MAX_SZ - sizeof(meta_blk_hdr_s))}; // reserved size for header

#pragma pack(1)
struct meta_blk_hdr {
    meta_blk_hdr_s h;
    char padding[META_BLK_HDR_RSVD_SZ];

    std::string to_string() const { return h.to_string(); }
};
#pragma pack()

static_assert(sizeof(meta_blk_hdr) == META_BLK_HDR_MAX_SZ);

// meta block
#pragma pack(1)
struct meta_blk {
    meta_blk_hdr hdr; // meta record header

    // NOTE: The context_data area starts immediately after this structure as represented in the code below
    // This was to replace a zero size array which is illegal in C++
    const uint8_t* get_context_data() const { return reinterpret_cast< const uint8_t* >(this) + sizeof(meta_blk); }
    uint8_t* get_context_data_mutable() { return reinterpret_cast< uint8_t* >(this) + sizeof(meta_blk); }
    std::string to_string() const { return hdr.to_string(); }
};
#pragma pack()

// single list overflow block chain
#pragma pack(1)
struct meta_blk_ovf_hdr_s {
    uint32_t magic;    // ovf magic
    uint32_t nbids;    // number of data blkids stored in data_bid;
    BlkId8_t next_bid; // next ovf blk id;
    BlkId8_t bid;      // self blkid
    uint64_t context_sz;
};
#pragma pack()

static constexpr uint32_t MAX_BLK_OVF_HDR_MAX_SZ{META_BLK_HDR_MAX_SZ};

static_assert(sizeof(meta_blk_ovf_hdr_s) <= MAX_BLK_OVF_HDR_MAX_SZ);

static constexpr uint32_t META_BLK_OVF_HDR_RSVD_SZ{
    (MAX_BLK_OVF_HDR_MAX_SZ - sizeof(meta_blk_ovf_hdr_s))}; // reserved size for ovf header

// single list overflow block chain
#pragma pack(1)
struct meta_blk_ovf_hdr {
    meta_blk_ovf_hdr_s h;
    char padding[META_BLK_OVF_HDR_RSVD_SZ];
    // NOTE: The size of this padding is crucial and adding fields to this header before or after without
    // adjusting padding size will cause the assert at bottom of file to fail.

    // NOTE: The data_bid area starts immediately after this structure as represented in the code below
    // This was to replace a zero size array which is illegal in C++
    const BlkId* get_data_bid() const {
        return reinterpret_cast< const BlkId* >(reinterpret_cast< const uint8_t* >(this) + sizeof(meta_blk_ovf_hdr));
    }
    BlkId* get_data_bid_mutable() {
        return reinterpret_cast< BlkId* >(reinterpret_cast< uint8_t* >(this) + sizeof(meta_blk_ovf_hdr));
    }

    [[nodiscard]] std::string to_string(const bool include_data_bid = false) const {
        std::string ovf_hdr_str{
            fmt::format("h: < magic=[{}] next_bid=[{}] self_bid=[{}] nbids=[{}] context_sz={} > data_bid: ", h.magic,
                        h.next_bid, h.bid, h.nbids, h.context_sz)};

        if (include_data_bid) {
            const BlkId* const data_bid{get_data_bid()};
            for (uint32_t i{0}; i < h.nbids; ++i) {
                ovf_hdr_str += data_bid[i].to_string();
                ovf_hdr_str += " ";
            }
        }

        return ovf_hdr_str;
    }
};
#pragma pack()

// static assert to make sure no field to be between padding and data_bid.
static_assert(sizeof(meta_blk_ovf_hdr) == MAX_BLK_OVF_HDR_MAX_SZ);
static_assert(META_BLK_HDR_MAX_SZ % CONTEXT_DATA_OFFSET_ALIGNMENT == 0);
static_assert(MAX_BLK_OVF_HDR_MAX_SZ % CONTEXT_DATA_OFFSET_ALIGNMENT == 0);
} // namespace homestore
