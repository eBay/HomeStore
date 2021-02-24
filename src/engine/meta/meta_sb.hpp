#pragma once
#include <initializer_list>
#include <cstdint>
#include <cstddef>
#include <array>
#include <string>
#include <set>
#include "engine/blkalloc/blk.h"

namespace homestore {
static constexpr uint32_t META_BLK_HDR_MAX_SZ = 512; // max meta_blk_hdr size
static constexpr uint32_t META_BLK_MAGIC = 0xCEEDBEED;
static constexpr uint32_t META_BLK_OVF_MAGIC = 0xDEADBEEF;
static constexpr uint32_t META_BLK_SB_MAGIC = 0xABCDCEED;
static constexpr uint32_t META_BLK_SB_VERSION = 0x1;
static constexpr uint32_t META_BLK_VERSION = 0x1;
static constexpr uint32_t MAX_SUBSYS_TYPE_LEN = 32;
static constexpr uint32_t CONTEXT_DATA_OFFSET_ALIGNMENT = 64;
// static constexpr uint32_t META_BLK_CONTEXT_SZ = (META_BLK_PAGE_SZ - META_BLK_HDR_MAX_SZ); // meta blk context data sz

/**
 * Sub system types and their priorities
 */
using crc32_t = uint32_t;

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

struct MetaSubRegInfo {
    bool do_crc{true};              // crc check for this client
    std::set< uint64_t > meta_bids; // meta blk id
    meta_blk_found_cb_t cb{nullptr};
    meta_blk_recover_comp_cb_t comp_cb{nullptr};
};

// meta blk super block put as 1st block in the block chain;
struct meta_blk_sb {
    uint32_t version;
    uint32_t magic; // ssb magic
    bool migrated;
    BlkId next_bid; // next metablk
    BlkId prev_bid; // previous metablk
    BlkId bid;
};

//
// 1. If overflow blkid is invalid, meaning context_sz is not larger than context_data_size(),
//    context data is stored in context_data field;
// 2. If overflow blkid is not invalid, all the context data is stored in overflow blks;
//
struct meta_blk_hdr_s {
    uint32_t version;
    uint32_t magic; // magic
    crc32_t crc;
    char type[MAX_SUBSYS_TYPE_LEN]; // sub system type;
    BlkId next_bid;                 // next metablk
    BlkId prev_bid;                 // previous metablk
    BlkId ovf_bid;                  // overflow blk id;
    BlkId bid;                      // current blk id; might not be needd;
    uint64_t context_sz;            // total size of context data;
};

static constexpr uint32_t META_BLK_HDR_RSVD_SZ =
    (META_BLK_HDR_MAX_SZ - sizeof(meta_blk_hdr_s)); // reserved size for header

struct meta_blk_hdr {
    meta_blk_hdr_s h;
    char padding[META_BLK_HDR_RSVD_SZ];
};

static_assert(sizeof(meta_blk_hdr) == META_BLK_HDR_MAX_SZ);

// meta block
struct meta_blk {
    meta_blk_hdr hdr;        // meta record header
    uint8_t context_data[0]; // Subsystem dependent context data
};

// single list overflow block chain
struct meta_blk_ovf_hdr_s {
    uint32_t magic; // ovf magic
    BlkId next_bid; // next ovf blk id;
    BlkId bid;      // self blkid
    uint32_t nbids; // number of data blkids stored in data_bid;
    uint64_t context_sz;
};

static constexpr uint32_t MAX_BLK_OVF_HDR_MAX_SZ = META_BLK_HDR_MAX_SZ;

static_assert(sizeof(meta_blk_ovf_hdr_s) <= MAX_BLK_OVF_HDR_MAX_SZ);

static constexpr uint32_t META_BLK_OVF_HDR_RSVD_SZ =
    (MAX_BLK_OVF_HDR_MAX_SZ - sizeof(meta_blk_ovf_hdr_s)); // reserved size for ovf header

// single list overflow block chain
struct meta_blk_ovf_hdr {
    meta_blk_ovf_hdr_s h;
    char padding[META_BLK_OVF_HDR_RSVD_SZ];
    BlkId data_bid[0];

    std::string to_string(bool include_data_bid = false) const {
        std::string ovf_hdr_str =
            fmt::format("h: < magic=[{}] next_bid=[{}] self_bid=[{}] nbids=[{}] context_sz={} > data_bid: ", h.magic,
                        h.next_bid, h.bid, h.nbids, h.context_sz);

        if (include_data_bid) {
            for (uint32_t i = 0; i < h.nbids; ++i) {
                ovf_hdr_str += data_bid[i].to_string();
                ovf_hdr_str += " ";
            }
        }

        return ovf_hdr_str;
    }
};

// static assert to make sure no field to be between padding and data_bid.
static_assert(offsetof(meta_blk_ovf_hdr, data_bid) == MAX_BLK_OVF_HDR_MAX_SZ);
static_assert(META_BLK_HDR_MAX_SZ % CONTEXT_DATA_OFFSET_ALIGNMENT == 0);
static_assert(MAX_BLK_OVF_HDR_MAX_SZ % CONTEXT_DATA_OFFSET_ALIGNMENT == 0);
} // namespace homestore
