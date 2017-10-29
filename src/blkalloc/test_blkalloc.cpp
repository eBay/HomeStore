//#include "BitMap.h"
#include <iostream>
#include <unistd.h>
#include <glog/logging.h>
#include "blk_allocator.h"
#include "varsize_blk_allocator.h"
#include <thread>

using namespace std;
using namespace omstore;

void allocate_blocks(BlkAllocator *allocator)
{
    int i;
    int alloced;

    int iter = 0;

    while (++iter <= 2) {
        Blk blks[4000];

        for (i = 0, alloced = 0; i < 4000; i++, alloced++) {
            Blk b;
            BlkAllocStatus ret = allocator->alloc(8192, 0, &blks[i]);

            if (ret == BLK_ALLOC_SUCCESS) {
                //fprintf(stderr, "Allocated block num = %llu\n", blks[i].get_piece(0).get_blk_id());
            } else {
                LOG(ERROR) << "Block Alloc failed with space full after " << alloced << " allocations";
                break;
            }
        }

        LOG(INFO) << "Allocated " << alloced << " blocks, Allocator state: " << allocator->to_string();
        for (i = 0; i < alloced; i++) {
            allocator->free(blks[i]);
        }
        LOG(INFO) << "Freed " << alloced << " blocks: Allocator state: " << allocator->to_string();
        LOG(INFO) << "Reallocating blocks";
    }
}

int main(int argc, char *argv[])
{
    //uint64_t total_space = 48*1024*1024;
    uint64_t total_space = 1*1024*1024;
    uint32_t blk_size = 8*1024;
    thread tids[100];
    int i;

    LOG(INFO) << "************* Testing FixedSizeBlkAllocator **************";
    BlkAllocConfig fixed_cfg(blk_size, total_space/blk_size);
    FixedBlkAllocator *fixed_allocator = new FixedBlkAllocator(fixed_cfg);

    for (i = 0; i < 1; i++) {
        tids[i] = std::thread(allocate_blocks, fixed_allocator);
    }
    for (i = 0; i < 1; i++) {
        tids[i].join();
    }
    LOG(INFO) << "FixedSizeBlkAllocator test done";

    LOG(INFO) << "************* Testing VarsizeBlkAllocator **************";
    VarsizeBlkAllocConfig var_cfg(blk_size, total_space/blk_size);
    var_cfg.set_max_cache_blks(1000);
    var_cfg.set_page_size(blk_size);
    var_cfg.set_total_segments(1);
    var_cfg.set_pages_per_portion(64);
    var_cfg.set_pages_per_temp_group(10);

    VarsizeBlkAllocator *var_allocator = new VarsizeBlkAllocator(var_cfg);
    for (i = 0; i < 1; i++) {
        tids[i] = std::thread(allocate_blocks, var_allocator);
    }
    for (i = 0; i < 1; i++) {
        tids[i].join();
    }
    LOG(INFO) << "VarsizeBlkAllocator test done";
}
