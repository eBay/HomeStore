//
// Created by Kadayam, Hari on 06/11/17.
//

#include <iostream>
#include <glog/logging.h>
#include "device.h"
#include <fcntl.h>

using namespace std;

omstore::PhysicalDev *glob_pdev = nullptr;

void test_add_device() {

}

void new_vdev_found(omstore::vdev_info_block *vb) {
}

void new_chunk_found(omstore::PhysicalDevChunk *chunk) {
}

int main(int argc, char** argv) {

    std::vector<std::string> dev_names;
    for (auto i : boost::irange(1, argc)) {
        dev_names.emplace_back(argv[i]);
    }

    omstore::DeviceManager *dev_mgr = new omstore::DeviceManager(new_vdev_found, new_chunk_found, 0);
    try {
        dev_mgr->add_devices(dev_names);
    } catch (std::exception &e) {
        LOG(INFO) << "Exception info " << e.what();
        exit(1);
    }
    auto devs = dev_mgr->get_all_devices();
    LOG(INFO) << "Initial Phys dev dump: " << devs[0]->to_string();
    auto chunk1 = dev_mgr->alloc_chunk(devs[0], 1, 102400);
    auto chunk2 = dev_mgr->alloc_chunk(devs[0], 1, 51200);
    auto chunk3 = dev_mgr->alloc_chunk(devs[0], 1, 204800);
    auto chunk4 = dev_mgr->alloc_chunk(devs[0], 1, 2097152);
    LOG(INFO) << "After 100K, 50K, 200K, 2MB allocations - Phys dev dump: " << devs[0]->to_string();

    dev_mgr->free_chunk(chunk3);
    LOG(INFO) << "After 200K free - Phys dev dump: " << devs[0]->to_string();
    dev_mgr->free_chunk(chunk2);
    LOG(INFO) << "After 50K free - Phys dev dump: " << devs[0]->to_string();

    // TODO: We are not
}