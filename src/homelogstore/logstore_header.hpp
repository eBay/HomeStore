#pragma once
namespace homestore {
class logstore_req;
class HomeLogStore;
struct logdev_key;

typedef int64_t logid_t;
typedef uint32_t logstore_id_t;
typedef int64_t logstore_seq_num_t;
using log_req_comp_cb_t = std::function< void(logstore_req*, logdev_key) >;
using log_buffer = sisl::byte_view;

using log_req_comp_cb_t = std::function< void(logstore_req*, logdev_key) >;
using log_write_comp_cb_t = std::function< void(logstore_seq_num_t, sisl::io_blob&, logdev_key, void*) >;
using log_found_cb_t = std::function< void(logstore_seq_num_t, log_buffer, void*) >;
using log_store_opened_cb_t = std::function< void(std::shared_ptr< HomeLogStore >) >;
using log_replay_done_cb_t = std::function< void(std::shared_ptr< HomeLogStore >) >;
} // namespace homestore
