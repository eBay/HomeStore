//
// Created by Kadayam, Hari on 11/11/17.
//
#pragma once

#include "virtual_dev.hpp"
#include <folly/ThreadLocal.h>

namespace homestore {

class RoundRobinDeviceSelector {
public:
    explicit RoundRobinDeviceSelector() { *m_last_dev_ind = 0; }

    void add_pdev(const PhysicalDev* pdev) { m_pdevs.push_back(pdev); }

    uint32_t select(const blk_alloc_hints& hints) {
        if (*m_last_dev_ind == (m_pdevs.size() - 1)) {
            *m_last_dev_ind = 0;
        } else {
            (*m_last_dev_ind)++;
        }

        return *m_last_dev_ind;
    }

private:
    std::vector< const PhysicalDev* > m_pdevs;
    folly::ThreadLocal< uint32_t > m_last_dev_ind;
};

} // namespace homestore