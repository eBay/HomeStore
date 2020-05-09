#pragma once
#include <initializer_list>
#include <cstdint>
#include "engine/blkalloc/blk.h"

namespace homestore {

#define META_BLK_PAGE_SZ 4096 // all data is aligned to 512 byte boundary inside metablk
#define META_BLK_HDR_SZ 64
#define META_BLK_HDR_RSVD_SZ 16
#define META_BLK_CONTEXT_SZ (META_BLK_PAGE_SZ - sizeof(meta_blk_hdr)) // meta rec context data sz
#define META_BLK_MAGIC 0xCEEDBEED
#define META_BLK_SB_MAGIC 0xABCDCEED
#define META_BLK_SB_VERSION 0x1
/**
 * Sub system types and their priorities
 */
enum class meta_sub_type { NOT_INIT_TYPE, HOMEBLK, VOLUME, INDX_MGR_CP, JOURNAL };

typedef uint32_t crc32_t;

constexpr std::initializer_list< meta_sub_type > sub_priority_list = {
    meta_sub_type::HOMEBLK, meta_sub_type::VOLUME, meta_sub_type::INDX_MGR_CP, meta_sub_type::JOURNAL};

/**
 * Subsystem states
 */
enum sub_state { NOT_INIT_STATE, ACTIVE, TOMBSTONE };

// vdev: starting blkid;

// meta blk super block put as 1st block in the block chain;
// TODO: internal crc
struct meta_blk_sb {
    uint32_t version;
    uint32_t magic;
    bool migrated;
    BlkId next_blkid; // next metablk
    BlkId prev_blkid; // previous metablk
    BlkId blkid;
} __attribute((packed));

//
// Note:
// 1. If overflow blkid is invalid, meaning context_sz is not larger than META_BLK_CONTEXT_SZ,
//    context data is stored in context_data field;
// 2. If overflow blkid is not invalid, all the context data is stored in overflow blks;
//
struct meta_blk_hdr {
    uint32_t magic; // magic
    crc32_t crc;
    meta_sub_type type; // sub system type;
    BlkId next_blkid;   // next metablk
    BlkId prev_blkid;   // previous metablk
    BlkId ovf_blkid;    // overflow blk id;
    BlkId blkid;        // current blk id; might not be needd;
    uint64_t context_sz;
    char padding[META_BLK_HDR_RSVD_SZ];
} __attribute((packed));

// 512 B
struct meta_blk {
    meta_blk_hdr hdr;                       // meta record header
    char context_data[META_BLK_CONTEXT_SZ]; // Subsystem dependent context data
} __attribute((packed));
} // namespace homestore
