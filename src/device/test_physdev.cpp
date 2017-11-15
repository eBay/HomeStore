//
// Created by Kadayam, Hari on 06/11/17.
//

#include <iostream>
#include <glog/logging.h>
#include "blkdev.h"
#include <fcntl.h>

using namespace std;

omstore::PhysicalDev *glob_pdev = nullptr;

void test_add_device() {

}

int main(int argc, char** argv) {
    try {
        glob_pdev = new omstore::PhysicalDev(argv[1], O_CREAT | O_RDWR);
    } catch (std::exception &e) {
        LOG(INFO) << "Exception info " << e.what();
        exit(1);
    }
    LOG(INFO) << "Initial Phys dev dump: " << glob_pdev->to_string();

    auto chunk1 = glob_pdev->alloc_chunk(102400);
    auto chunk2 = glob_pdev->alloc_chunk(51200);
    auto chunk3 = glob_pdev->alloc_chunk(204800);
    auto chunk4 = glob_pdev->alloc_chunk(2097152);
    LOG(INFO) << "After 100K, 50K, 200K, 2MB allocations - Phys dev dump: " << glob_pdev->to_string();

    glob_pdev->free_chunk(chunk3);
    LOG(INFO) << "After 200K free - Phys dev dump: " << glob_pdev->to_string();
    glob_pdev->free_chunk(chunk2);
    LOG(INFO) << "After 50K free - Phys dev dump: " << glob_pdev->to_string();

    // TODO: We are not
}