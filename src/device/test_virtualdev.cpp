//
// Created by Kadayam, Hari on 06/11/17.
//

#include <iostream>
#include "device.h"
#include <fcntl.h>
#include "device/virtual_dev.hpp"
#include "device/device_selector.hpp"

using namespace std;
using namespace homestore;

homestore::DeviceManager* dev_mgr = nullptr;
homestore::VirtualDev< homestore::VdevFixedBlkAllocatorPolicy, homestore::RoundRobinDeviceSelector >* vdev;

AbstractVirtualDev* new_vdev_found(homestore::DeviceManager* mgr, homestore::vdev_info_block* vb) {
    LOG(INFO) << "New virtual device found id = " << vb->vdev_id << " size = " << vb->size;
    vdev = new homestore::VirtualDev< homestore::VdevFixedBlkAllocatorPolicy, homestore::RoundRobinDeviceSelector >(
        dev_mgr, vb);
    return vdev;
}

#if 0
void new_chunk_found(homestore::PhysicalDevChunk *chunk) {
    LOG(INFO) << "New chunk found for vdev " << chunk->get_vdev_id() << " Chunk size = " << chunk->get_size();
    vdev->add_chunk(chunk);
}
#endif

int main(int argc, char** argv) {
    std::vector< std::string > dev_names;
    bool create = ((argc > 1) && (!strcmp(argv[1], "-c")));

    for (auto i : boost::irange(create ? 2 : 1, argc)) {
        dev_names.emplace_back(argv[i]);
    }

    dev_mgr = new homestore::DeviceManager(new_vdev_found, 0);
    try {
        dev_mgr->add_devices(dev_names);
    } catch (std::exception& e) {
        LOG(INFO) << "Exception info " << e.what();
        exit(1);
    }
    auto devs = dev_mgr->get_all_devices();

    if (create) {
        LOG(INFO) << "Creating Virtual Dev\n";
        uint32_t size = 512 * 1024 * 1024;
        vdev = new homestore::VirtualDev< homestore::VdevFixedBlkAllocatorPolicy, homestore::RoundRobinDeviceSelector >(
            dev_mgr, size, 0, true, 8192, devs);
    }

    homestore::BlkId bids[100];
    homestore::blk_alloc_hints hints;
    hints.desired_temp = 0;
    hints.dev_id_hint = -1;
    hints.is_contiguous = true;

    for (auto i = 0; i < 4; i++) {
        uint8_t nblks = 1;
        auto status = vdev->alloc_blk(nblks, hints, &bids[i]);
        assert(status == BLK_ALLOC_SUCCESS);

        LOG(INFO) << "Requested nblks: " << (uint32_t)nblks << " Allocation info: " << bids[i].to_string();
    }

    char buf[8192];
    for (auto i = 0; i < 4; i++) {
        memset(buf, i, 8192);
        homeds::MemVector< 8192 > mvector((uint8_t*)buf, 8192, 0);
        vdev->write(bids[i], mvector);

        LOG(INFO) << "Written on " << bids[i].to_string() << " for 8192 bytes";
    }

    for (auto i = 0; i < 4; i++) {
        homeds::MemVector< 8192 > mvector((uint8_t*)buf, 8192, 0);
        vdev->readv(bids[i], mvector);

        LOG(INFO) << "Read from " << bids[i].to_string() << " for 8192 bytes";

        homeds::blob b;
        mvector.get(&b, 0);
        assert(b.size == 8192);
        for (auto j = 0; j < b.size; j++) {
            assert(b.bytes[j] == i);
        }
    }
}
