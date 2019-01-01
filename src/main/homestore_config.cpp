#include "homestore_config.hpp"
size_t homestore::HomeStoreConfig::phys_page_size = 8192;
size_t homestore::HomeStoreConfig::hs_page_size = 8192;
size_t homestore::HomeStoreConfig::atomic_phys_page_size = 8192;
size_t homestore::HomeStoreConfig::align_size = 8192;
uint64_t homestore::HomeStoreConfig::max_chunks = MAX_CHUNKS;
uint64_t homestore::HomeStoreConfig::max_vdevs = MAX_VDEVS;
uint64_t homestore::HomeStoreConfig::max_pdevs = MAX_PDEVS;
