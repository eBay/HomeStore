#include "homestore_config.hpp"
size_t homestore::HomeStoreConfig::phys_page_size = 8192;
size_t homestore::HomeStoreConfig::atomic_phys_page_size = 8192;
size_t homestore::HomeStoreConfig::align_size = 8192;
size_t homestore::HomeStoreConfig::min_io_size = 8192;
size_t homestore::HomeStoreConfig::mem_btree_page_size = 8192;
uint64_t homestore::HomeStoreConfig::max_chunks = MAX_CHUNKS;
uint64_t homestore::HomeStoreConfig::max_vdevs = MAX_VDEVS;
uint64_t homestore::HomeStoreConfig::max_pdevs = MAX_PDEVS;
uint64_t homestore::HomeStoreConfig::max_blk_cnt = 0;
homestore::io_flag homestore::HomeStoreConfig::open_flag = DIRECT_IO;
bool homestore::HomeStoreConfig::is_read_only = false;
