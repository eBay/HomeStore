/*
 * BlkDevManager.cpp
 *
 *  Created on: 20-Aug-2016
 *      Author: hkadayam
 */

#include "BlkDev.h"
#include <fcntl.h>

static BlkDevManager *devMgr = NULL;

BlkDevManager::BlkDevManager()
{
	m_openFlags = O_RDWR;
}

BlkDevManager::~BlkDevManager()
{
	for (auto it = m_devices.begin(); it != m_devices.end(); it++) {
		delete (*it);
	}
}

void BlkDevManager::addDevice(string devName)
{
	m_devices.push_back(new PhysicalDev(devName, m_openFlags));
}

vector<PhysicalDev *> BlkDevManager::getAllDevices()
{
	return m_devices;
}

uint32_t BlkDevManager::getDevicesCount()
{
	return m_devices.size();
}

void BlkDevManager::startInstance()
{
	devMgr = new BlkDevManager();
}

BlkDevManager *BlkDevManager::getInstance()
{
	return devMgr;
}
