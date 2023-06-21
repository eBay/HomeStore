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
#include <sisl/fds/buffer.hpp>
#include <iomgr/io_environment.hpp>

#include "homestore_base.hpp"
#include "common/homestore_assert.hpp"

namespace homestore {
HomeStoreBase::~HomeStoreBase() = default;

void HomeStoreBase::set_instance(HomeStoreBaseSafePtr instance) { s_instance = instance; }

void HomeStoreBase::reset_instance() { s_instance.reset(); }

std::shared_ptr< spdlog::logger >& HomeStoreBase::periodic_logger() { return instance()->m_periodic_logger; }

std::shared_ptr< sisl::sobject_manager > HomeStoreBase::sobject_mgr() { return ioenvironment.get_object_mgr(); }

} // namespace homestore
