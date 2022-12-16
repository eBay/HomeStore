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

#include <string>
#include <functional>
#include <unordered_map>
#include <vector>
#include <shared_mutex>

#include <nlohmann/json.hpp>

namespace homestore {

using get_status_cb_t = std::function< nlohmann::json(const int verbosity_level) >;

class HomeStoreStatusMgr {
public:
    HomeStoreStatusMgr() = default;

    void register_status_cb(const std::string& module, const get_status_cb_t get_status_cb);
    nlohmann::json get_status(const std::vector< std::string >& modules, const int verbosity_level) const;
    std::vector< std::string > get_modules() const;

private:
    std::unordered_map< std::string, get_status_cb_t > m_status_cb_map;
    mutable std::shared_mutex m_mtx;
};

} // namespace homestore
