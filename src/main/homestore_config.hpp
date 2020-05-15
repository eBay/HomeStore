
#ifndef _HOMESTORE_CONFIG_HPP_
#define _HOMESTORE_CONFIG_HPP_

#include "homestore_header.hpp"
#include <error/error.h>
#include <cassert>

namespace homestore {

struct HomeStoreConfig {
    static size_t phys_page_size;        // physical block size supported by ssd
    static size_t atomic_phys_page_size; // atomic page size supported by disk
    static size_t align_size;
    static size_t min_io_size;         // minimum io size supported by HS
    static size_t mem_btree_page_size; // page size used by memory btree
    static uint64_t max_chunks;
    static uint64_t max_vdevs;
    static uint64_t max_pdevs;
    static uint64_t max_blk_cnt;
    static io_flag open_flag;
    static bool is_read_only;
    static size_t mem_release_soft_threshold;       // Max mem after which we start releasing memory back to system
    static size_t mem_release_aggressive_threshold; // Max mem after which we release aggressively back to system
};

constexpr uint32_t ID_BITS = 32;
constexpr uint32_t NBLKS_BITS = 8;
constexpr uint32_t CHUNK_NUM_BITS = 8;
constexpr uint32_t BLKID_SIZE_BITS = ID_BITS + NBLKS_BITS + CHUNK_NUM_BITS;
constexpr uint32_t MEMPIECE_ENCODE_MAX_BITS = 8;
constexpr uint64_t MAX_NBLKS = ((1 << NBLKS_BITS) - 1);
constexpr uint64_t MAX_CHUNK_ID = ((1 << CHUNK_NUM_BITS) - 1);
constexpr uint64_t BLKID_SIZE = ((ID_BITS + NBLKS_BITS + CHUNK_NUM_BITS) / 8);
constexpr uint32_t BLKS_PER_PORTION = 1024;
constexpr uint32_t TOTAL_SEGMENTS = 8;

/* DM info size depends on these three parameters. If below parameter changes then we have to add
 * the code for upgrade/revert.
 */
constexpr uint32_t MAX_CHUNKS = 128;
constexpr uint32_t MAX_VDEVS = 16;
constexpr uint32_t MAX_PDEVS = 8;

/* NOTE: it can give size more then the size passed in argument to make it aligned */
#define ALIGN_SIZE(size, align) (((size % align) == 0) ? size : (size + (align - (size % align))))

/* NOTE: it can give size less then size passed in argument to make it aligned */
#define ALIGN_SIZE_TO_LEFT(size, align) (((size % align) == 0) ? size : (size - (size % align)))

/* TODO: we store global unique ID in blkid. Instead it we only store chunk offset then
 * max cacapity will increase from MAX_CHUNK_SIZE to MAX_CHUNKS * MAX_CHUNK_SIZE.
 */
#define MAX_SUPPORTED_CAP MAX_CHUNKS* MAX_CHUNK_SIZE
#define MEMVEC_MAX_IO_SIZE (HomeStoreConfig::min_io_size * ((1 << MEMPIECE_ENCODE_MAX_BITS) - 1))
#define MIN_CHUNK_SIZE (HomeStoreConfig::phys_page_size * BLKS_PER_PORTION * TOTAL_SEGMENTS)
#define MAX_CHUNK_SIZE                                                                                                 \
    ALIGN_SIZE_TO_LEFT((((1lu << ID_BITS) - 1) * (HomeStoreConfig::min_io_size)), MIN_CHUNK_SIZE) // 16T

#define MAX_UUID_LEN 128

} // namespace homestore
#endif
