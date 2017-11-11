/*
 * BlkDevManager.cpp
 *
 *  Created on: 20-Aug-2016
 *      Author: hkadayam
 */

#include "blkdev.h"
#include <fcntl.h>

namespace omstore {

BlkDevManager::BlkDevManager() {
    m_open_flags = O_RDWR;
}

BlkDevManager::~BlkDevManager() {
}

void BlkDevManager::add_device(std::string dev_name) {
    m_devices.push_back(std::make_unique<PhysicalDev>(PhysicalDev(dev_name, m_open_flags));
}

const std::vector< std::unique_ptr< PhysicalDev > > &BlkDevManager::get_all_devices() const {
    return m_devices;
}

uint64_t BlkDevManager::get_devices_count() {
    return m_devices.size();
}

} // namespace omstore