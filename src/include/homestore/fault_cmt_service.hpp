/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
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
#include <memory>
#include <unordered_map>
#include <vector>

#include <iomgr/iomgr.hpp>
#include <homestore/homestore_decl.hpp>

namespace homestore {
ENUM(FaultContainmentEvent, uint8_t, ENTER = 0, EXIT = 1, ENTER_GLOABLE = 2);

class FaultContainmentCallback {
public:
    virtual ~FaultContainmentCallback() = default;
    virtual void on_fault_containment(FaultContainmentEvent evt, void* cookie, const std::string& reason) { assert(0); }
};

class FaultContainmentService {
private:
    std::unique_ptr< FaultContainmentCallback > m_cb;

public:
    FaultContainmentService(std::unique_ptr< FaultContainmentCallback > cb) : m_cb(std::move(cb)) {}
    ~FaultContainmentService() = default;
    void trigger_fc(FaultContainmentEvent evt, void* cookie, const std::string& reason = "") {
        m_cb->on_fault_containment(evt, cookie, reason);
    }
};

} // namespace homestore
