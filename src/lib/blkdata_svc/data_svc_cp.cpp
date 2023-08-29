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
#include "data_svc_cp.hpp"
#include "device/virtual_dev.hpp"

namespace homestore {

DataSvcCPCallbacks::DataSvcCPCallbacks(VirtualDev* vdev) : m_vdev{vdev} {}

std::unique_ptr< CPContext > DataSvcCPCallbacks::on_switchover_cp(CP* cur_cp, CP* new_cp) {
    return m_vdev->create_cp_context(new_cp->id());
}

folly::Future< bool > DataSvcCPCallbacks::cp_flush(CP* cp) {
    // blocking io call to vdev
    m_vdev->cp_flush(cp);
    return folly::makeFuture< bool >(true);
}

void DataSvcCPCallbacks::cp_cleanup(CP* cp) {}

int DataSvcCPCallbacks::cp_progress_percent() { return 100; }

} // namespace homestore
