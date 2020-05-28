#pragma once
#include <initializer_list>
#include <cstdint>
#include <cstddef>
#include "engine/blkalloc/blk.h"

namespace homestore {
#define META_BLK_PAGE_SZ 4096                       // all data is aligned to 512 byte boundary inside metablk
#define META_BLK_HDR_MAX_SZ 512                     // max meta_blk_hdr size
#define META_BLK_OVF_HDR_MAX_SZ META_BLK_HDR_MAX_SZ // max meta_blk_ovf_hdr size
#define META_BLK_HDR_RSVD_SZ (META_BLK_HDR_MAX_SZ - sizeof(meta_blk_hdr_s))             // reserved size for header
#define META_BLK_OVF_HDR_RSVD_SZ (META_BLK_OVF_HDR_MAX_SZ - sizeof(meta_blk_ovf_hdr_s)) // reserved size for ovf header
#define META_BLK_CONTEXT_SZ (META_BLK_PAGE_SZ - META_BLK_HDR_MAX_SZ)                    // meta blk context data sz
#define META_BLK_OVF_CONTEXT_SZ (META_BLK_PAGE_SZ - META_BLK_OVF_HDR_MAX_SZ)            // meta ovf blk context data sz
#define META_BLK_MAGIC 0xCEEDBEED
#define META_BLK_OVF_MAGIC 0xDEADBEEF
#define META_BLK_SB_MAGIC 0xABCDCEED
#define META_BLK_SB_VERSION 0x1
#define MAX_SUBSYS_TYPE_LEN 32

/**
 * Sub system types and their priorities
 */
using meta_sub_type = std::string;
using crc32_t = uint32_t;

// meta blk super block put as 1st block in the block chain;
struct meta_blk_sb {
    uint32_t version;
    uint32_t magic; // ssb magic
    bool migrated;
    BlkId next_blkid; // next metablk
    BlkId prev_blkid; // previous metablk
    BlkId blkid;
} __attribute((packed));

//
// 1. If overflow blkid is invalid, meaning context_sz is not larger than META_BLK_CONTEXT_SZ,
//    context data is stored in context_data field;
// 2. If overflow blkid is not invalid, all the context data is stored in overflow blks;
//
struct meta_blk_hdr_s {
    uint32_t magic; // magic
    crc32_t crc;
    char type[MAX_SUBSYS_TYPE_LEN];  // sub system type;
    BlkId next_blkid;    // next metablk
    BlkId prev_blkid;    // previous metablk
    BlkId ovf_blkid;     // overflow blk id;
    BlkId blkid;         // current blk id; might not be needd;
    uint64_t context_sz; // total size of context data; 
} __attribute((packed));

struct meta_blk_hdr {
    meta_blk_hdr_s h;
    char padding[META_BLK_HDR_RSVD_SZ];
} __attribute((packed));

static_assert(sizeof(meta_blk_hdr) == META_BLK_HDR_MAX_SZ);

// meta block
struct meta_blk {
    meta_blk_hdr hdr;                       // meta record header
    uint8_t context_data[META_BLK_CONTEXT_SZ]; // Subsystem dependent context data
} __attribute((packed));

struct meta_blk_ovf_hdr_s {
    uint32_t magic; // ovf magic
    BlkId next_blkid;
    BlkId prev_blkid;
    BlkId blkid;
    uint64_t context_sz;
} __attribute((packed));

// overflow blk header
struct meta_blk_ovf_hdr {
    meta_blk_ovf_hdr_s h;
    char padding[META_BLK_OVF_HDR_RSVD_SZ];
} __attribute((packed));

static_assert(sizeof(meta_blk_ovf_hdr) == META_BLK_OVF_HDR_MAX_SZ);
#if 0
// overflow block
struct meta_blk_ovf {
    meta_blk_ovf_hdr hdr; // meta overflow record header
    uint8_t context_data[META_BLK_OVF_CONTEXT_SZ];
} __attribute((packed));
#endif
} // namespace homestore
