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

#include <cstdint>
#include <functional>
#include <memory>

#include <sisl/fds/buffer.hpp>

namespace homestore {
class logstore_req;
class HomeLogStore;
struct logdev_key;

typedef int64_t logid_t;
typedef int64_t logstore_seq_num_t;
typedef std::function< void(logstore_req*, logdev_key) > log_req_comp_cb_t;
typedef sisl::byte_view log_buffer;
typedef uint32_t logstore_id_t;
typedef uint8_t logstore_family_id_t;

typedef std::function< void(logstore_req*, logdev_key) > log_req_comp_cb_t;
typedef std::function< void(logstore_seq_num_t, sisl::io_blob&, logdev_key, void*) > log_write_comp_cb_t;
typedef std::function< void(logstore_seq_num_t, log_buffer, void*) > log_found_cb_t;
typedef std::function< void(std::shared_ptr< HomeLogStore >) > log_store_opened_cb_t;
typedef std::function< void(std::shared_ptr< HomeLogStore >, logstore_seq_num_t) > log_replay_done_cb_t;
} // namespace homestore
