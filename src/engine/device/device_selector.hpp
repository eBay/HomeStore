/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 * Author/Developer(s): Harihara Kadayam
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 *********************************************************************************/
#pragma once

#include <vector>
#include <folly/ThreadLocal.h>
#include "engine/blkalloc/blk_allocator.h"

namespace homestore {
class PhysicalDev;

class RoundRobinDeviceSelector {
public:
    explicit RoundRobinDeviceSelector() { *m_last_dev_ind = 0; }

    RoundRobinDeviceSelector(const RoundRobinDeviceSelector&) = delete;
    RoundRobinDeviceSelector(RoundRobinDeviceSelector&&) noexcept = delete;
    RoundRobinDeviceSelector& operator=(const RoundRobinDeviceSelector&) = delete;
    RoundRobinDeviceSelector& operator=(RoundRobinDeviceSelector&&) noexcept = delete;

    ~RoundRobinDeviceSelector() = default;

    void add_pdev(const PhysicalDev* const pdev) { m_pdevs.push_back(pdev); }

    uint32_t select(const blk_alloc_hints& hints) {
        if (*m_last_dev_ind == (m_pdevs.size() - 1)) {
            *m_last_dev_ind = 0;
        } else {
            ++(*m_last_dev_ind);
        }

        return *m_last_dev_ind;
    }

private:
    std::vector< const PhysicalDev* > m_pdevs;
    folly::ThreadLocal< uint32_t > m_last_dev_ind;
};

} // namespace homestore
