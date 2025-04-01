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

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <set>
#include <unordered_map>
#include <vector>

#include <sisl/fds/buffer.hpp>
#include <sisl/fds/obj_allocator.hpp>
#include <folly/Synchronized.h>
#include <nlohmann/json.hpp>

namespace homestore {
///////////////////// All typedefs ///////////////////////////////
class logstore_req;
class HomeLogStore;
struct logdev_key;

typedef int64_t logid_t;
typedef int64_t logstore_seq_num_t;
typedef std::function< void(logstore_req*, logdev_key) > log_req_comp_cb_t;
typedef sisl::byte_view log_buffer;
typedef uint32_t logstore_id_t;
typedef uint32_t logdev_id_t;

typedef std::function< void(logstore_req*, logdev_key) > log_req_comp_cb_t;
typedef std::function< void(logstore_seq_num_t, sisl::io_blob&, logdev_key, void*) > log_write_comp_cb_t;
typedef std::function< void(logstore_seq_num_t, log_buffer, void*) > log_found_cb_t;
typedef std::function< void(std::shared_ptr< HomeLogStore >) > log_store_opened_cb_t;
typedef std::function< void(std::shared_ptr< HomeLogStore >, logstore_seq_num_t) > log_replay_done_cb_t;

typedef int64_t logid_t;

VENUM(flush_mode_t, uint32_t, // Various flush modes (can be or'ed together)
      INLINE = 1 << 0,        // Allow flush inline with the append
      TIMER = 1 << 1,         // Allow timer based automatic flush
      EXPLICIT = 1 << 2,      // Allow explcitly user calling flush
);

struct logdev_key {
    logid_t idx;
    off_t dev_offset;

    constexpr logdev_key(const logid_t idx = -1, const off_t dev_offset = std::numeric_limits< uint64_t >::min()) :
            idx{idx}, dev_offset{dev_offset} {}
    logdev_key(const logdev_key&) = default;
    logdev_key& operator=(const logdev_key&) = default;
    logdev_key(logdev_key&&) noexcept = default;
    logdev_key& operator=(logdev_key&&) noexcept = default;
    ~logdev_key() = default;

    bool operator==(const logdev_key& other) { return (other.idx == idx) && (other.dev_offset == dev_offset); }

    operator bool() const { return is_valid(); }
    bool is_valid() const { return !is_lowest() && !is_highest(); }

    bool is_lowest() const { return (idx == -1); }
    bool is_highest() const { return (idx == std::numeric_limits< logid_t >::max()); }

    void set_lowest() {
        idx = -1;
        dev_offset = std::numeric_limits< uint64_t >::min();
    }

    void set_highest() {
        idx = std::numeric_limits< logid_t >::max();
        dev_offset = std::numeric_limits< uint64_t >::max();
    }

    std::string to_string() const { return fmt::format("Logid={} devoffset={}", idx, dev_offset); }

    static const logdev_key& out_of_bound_ld_key() {
        static constexpr logdev_key s_out_of_bound_ld_key{std::numeric_limits< logid_t >::max(),
                                                          std::numeric_limits< off_t >::max()};
        return s_out_of_bound_ld_key;
    }
};

enum log_dump_verbosity : uint8_t { CONTENT, HEADER };

class HomeLogStore;
struct log_dump_req {
    log_dump_req(log_dump_verbosity level = log_dump_verbosity::HEADER,
                 std::shared_ptr< HomeLogStore > logstore = nullptr, logstore_seq_num_t s_seq = 0,
                 logstore_seq_num_t e_seq = std::numeric_limits< int64_t >::max()) :
            verbosity_level{level}, log_store{logstore}, start_seq_num{s_seq}, end_seq_num{e_seq} {}
    log_dump_verbosity verbosity_level;        // How much information we need of log file (entire content or header)
    std::shared_ptr< HomeLogStore > log_store; // if null all log stores are dumped
    logstore_seq_num_t start_seq_num;          // empty_key if from start of log file
    logstore_seq_num_t end_seq_num;            // empty_key if till last log entry
};

struct logstore_record {
    logdev_key m_dev_key;
    // indicates the safe truncation point of the log store
    logdev_key m_trunc_key;

    logstore_record() = default;
    logstore_record(const logdev_key& key, const logdev_key& trunc_key) : m_dev_key{key}, m_trunc_key{trunc_key} {}
};

class HomeLogStore;
struct logstore_req {
    HomeLogStore* log_store; // Backpointer to the log store. We are not storing shared_ptr as user should not destroy
                             // it until all ios are not completed.
    logstore_seq_num_t seq_num; // Log store specific seq_num (which could be monotonically increaseing with logstore)
    sisl::io_blob data;         // Data blob containing data
    void* cookie;               // User generated cookie (considered as opaque)
    bool is_internal_req;       // If the req is created internally by HomeLogStore itself
    log_req_comp_cb_t cb;       // Callback upon completion of write (overridden than default)
    Clock::time_point start_time;
    bool flush_wait{false}; // Wait for the flush to happen

    logstore_req(const logstore_req&) = delete;
    logstore_req& operator=(const logstore_req&) = delete;
    logstore_req(logstore_req&&) noexcept = delete;
    logstore_req& operator=(logstore_req&&) noexcept = delete;
    ~logstore_req() = default;

    // Get the size of the read or written record
    size_t size() const {
        // TODO: Implement this method
        return 0;
    }
    static logstore_req* make(HomeLogStore* store, logstore_seq_num_t seq_num, const sisl::io_blob& data) {
        logstore_req* req = new logstore_req();
        req->log_store = store;
        req->seq_num = seq_num;
        req->data = data;
        req->is_internal_req = true;
        req->cb = nullptr;

        return req;
    }

    static void free(logstore_req* req) {
        if (req->is_internal_req) { delete req; }
    }

    logstore_req() = default;
};

#pragma pack(1)
struct logstore_superblk {
    logstore_superblk(const logstore_seq_num_t seq_num = 0) : m_first_seq_num{seq_num} {}
    logstore_superblk(const logstore_superblk&) = default;
    logstore_superblk(logstore_superblk&&) noexcept = default;
    logstore_superblk& operator=(const logstore_superblk&) = default;
    logstore_superblk& operator=(logstore_superblk&&) noexcept = default;
    ~logstore_superblk() = default;

    [[nodiscard]] static logstore_superblk default_value();
    static void init(logstore_superblk& m);
    static void clear(logstore_superblk& m);
    [[nodiscard]] static bool is_valid(const logstore_superblk& m);

    logstore_seq_num_t m_first_seq_num{0};
};
#pragma pack()

} // namespace homestore