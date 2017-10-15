/*
 * BlkDevManager.cpp
 *
 *  Created on: 20-Aug-2016
 *      Author: hkadayam
 */

#include "blkdev.h"
#include <fcntl.h>

static BlkDevManager *devmgr = NULL;

BlkDevManager::BlkDevManager()
{
	m_open_flags = O_RDWR;
}

BlkDevManager::~BlkDevManager()
{
	for (auto it = m_devices.begin(); it != m_devices.end(); it++) {
		delete (*it);
	}
}

void BlkDevManager::add_device(string devName)
{
	m_devices.push_back(new PhysicalDev(devName, m_open_flags));
}

vector<PhysicalDev *> BlkDevManager::get_all_devices()
{
	return m_devices;
}

uint32_t BlkDevManager::get_devices_count()
{
	return m_devices.size();
}

void BlkDevManager::startInstance()
{
	devmgr = new BlkDevManager();
}

BlkDevManager *BlkDevManager::getInstance()
{
	return devmgr;
}
