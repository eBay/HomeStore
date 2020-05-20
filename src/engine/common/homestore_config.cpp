#include "homestore_config.hpp"
size_t homestore::HS_STATIC_CONFIG(disk_attr.phys_page_size) = 8192;
size_t homestore::HS_STATIC_CONFIG(disk_attr.atomic_phys_page_size) = 8192;
size_t homestore::HS_STATIC_CONFIG(disk_attr.align_size) = 512;
size_t homestore::HS_STATIC_CONFIG(engine.min_io_size) = 8192;
size_t homestore::HomeStoreConfig::mem_btree_page_size = 8192;
uint64_t homestore::HS_STATIC_CONFIG(engine.max_chunks) = MAX_CHUNKS;
uint64_t homestore::HS_STATIC_CONFIG(engine.max_vdevs) = MAX_VDEVS;
uint64_t homestore::HS_STATIC_CONFIG(engine.max_pdevs) = MAX_PDEVS;
uint64_t homestore::HomeStoreConfig::max_blk_cnt = 0;
homestore::io_flag HS_STATIC_CONFIG(input.open_flags) = DIRECT_IO;
bool HS_STATIC_CONFIG(input.is_read_only) = false;
