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

#include <cstdint>
#include <memory>

#include "log_store.hpp"

namespace homestore {
class RaftLogStore {
public:
    RaftLogStore() = default;
    RaftLogStore(const RaftLogStore&) = delete;
    RaftLogStore& operator=(const RaftLogStore&) = delete;
    RaftLogStore(RaftLogStore&&) noexcept = delete;
    RaftLogStore& operator=(RaftLogStore&&) noexcept = delete;
    ~RaftLogStore() = default;

    [[nodiscard]] uint32_t next_slot() const { return 0; }

private:
    std::shared_ptr< HomeLogStore > m_hlogstore;
};
} // namespace homestore