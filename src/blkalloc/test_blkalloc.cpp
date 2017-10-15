//#include "BitMap.h"
#include <iostream>
#include <unistd.h>
#include "blk_allocator.h"
#include "varsize_blk_allocator.h"
#include "blk.h"
#include <thread>

using namespace std;
using namespace omstorage;

void allocate_blocks(BlkAllocator *allocator)
{
	Blk blks[2000];
	int i;
	int alloced;

	for (i = 0, alloced = 0; i < 2000; i++, alloced++) {
        Blk b;
		BlkAllocStatus ret = allocator->alloc(8192, 0, &blks[i]);

		if (ret == BLK_ALLOC_SUCCESS) {
			fprintf(stderr, "Allocated block num = %llu\n", blks[i].get_piece(0).get_blk_id());
		} else {
			fprintf(stderr, "Block Alloc failed with space full\n");
			break;
		}
	}

	for (i = 0; i < alloced; i++) {
		allocator->free(blks[i]);
	}
}

int main(int argc, char *argv[])
{
	uint64_t total_space = 48*1024*1024;
	uint32_t nblk_size = 8*1024;
	thread tids[100];
	int i;

    std::cout << "Testing FixedSizeBlkAllocator" << "\n";
	BlkAllocConfig fixed_cfg(nblk_size, total_space/nblk_size);
    FixedBlkAllocator *fixed_allocator = new FixedBlkAllocator(fixed_cfg);

	for (i = 0; i < 25; i++) {
		tids[i] = std::thread(allocate_blocks, fixed_allocator);
	}
	for (i = 0; i < 25; i++) {
		tids[i].join();
	}
	cout << "FixedSizeBlkAllocator Test done" << "\n";

    std::cout << "Testing VarSizeBlkAllocator" << "\n";
    VarsizeBlkAllocConfig var_cfg(nblk_size, total_space/nblk_size);
    var_cfg.set_max_cache_blks(1000);

    VarsizeBlkAllocator *var_allocator = new VarsizeBlkAllocator(var_cfg);
    for (i = 0; i < 25; i++) {
        tids[i] = std::thread(allocate_blocks, var_allocator);
    }
    for (i = 0; i < 25; i++) {
        tids[i].join();
    }
    cout << "VarSizeBlkAllocator Test done" << "\n";
}
