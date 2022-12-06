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
