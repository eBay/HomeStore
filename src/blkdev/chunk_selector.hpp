//
// Created by Kadayam, Hari on 11/11/17.
//
#pragma once

#include "virtual_dev.hpp"
#include <folly/ThreadLocal.h>

namespace omstore {

class RoundRobinChunkSelector {
public:
    RoundRobinChunkSelector(VirtualDev *vdev) :
            m_vdev(vdev) {
    }

    uint32_t select(blk_alloc_hints &hints) {
        if (*m_last_dev_id == m_vdev->m_primary_chunks_in_physdev.size()) {
            *m_last_dev_id = 0;
        } else {
            (*m_last_dev_id)++;
        }

        return *m_last_dev_id;
    }

private:
    VirtualDev *m_vdev;
    folly::ThreadLocal< uint32_t > m_last_dev_id;
};

}