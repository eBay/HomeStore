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
#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <string>

#include <sisl/fds/buffer.hpp>
#include <folly/Synchronized.h>

#include <homestore/logstore_service.hpp>
#include <homestore/logstore/log_store_internal.hpp>
#include "log_dev.hpp"

namespace homestore {
struct log_dump_req;

struct logstore_info_t {
    std::shared_ptr< HomeLogStore > m_log_store;
    log_store_opened_cb_t m_on_log_store_opened;
    bool append_mode;
};

struct truncate_req {
    std::mutex mtx;
    std::condition_variable cv;
    bool wait_till_done{false};
    bool dry_run{false};
    LogStoreService::device_truncate_cb_t cb;
    std::array< logdev_key, LogStoreService::num_log_families > m_trunc_upto_result;
    int trunc_outstanding{0};
};

class JournalVirtualDev;
class HomeLogStore;
struct meta_blk;

class LogStoreFamily {
    friend class LogStoreService;
    friend class LogDev;

public:
    LogStoreFamily(const logstore_family_id_t f_id);
    LogStoreFamily(const LogStoreFamily&) = delete;
    LogStoreFamily(LogStoreFamily&&) noexcept = delete;
    LogStoreFamily& operator=(const LogStoreFamily&) = delete;
    LogStoreFamily& operator=(LogStoreFamily&&) noexcept = delete;

    void meta_blk_found_cb(meta_blk* mblk, sisl::byte_view buf, size_t size);
    void start(const bool format, JournalVirtualDev* blk_store);
    void stop();

    std::shared_ptr< HomeLogStore > create_new_log_store(bool append_mode = false);
    void open_log_store(logstore_id_t store_id, bool append_mode, const log_store_opened_cb_t& on_open_cb);
    bool close_log_store(logstore_id_t store_id) {
        // TODO: Implement this method
        return true;
    }
    void remove_log_store(logstore_id_t store_id);

    void device_truncate_in_user_reactor(const std::shared_ptr< truncate_req >& treq);

    nlohmann::json dump_log_store(const log_dump_req& dum_req);
    std::string metablk_name() const { return m_metablk_name; }

    LogDev& logdev() { return m_log_dev; }

    nlohmann::json get_status(int verbosity) const;
    std::string get_name() const { return m_metablk_name; }

private:
    logdev_key do_device_truncate(bool dry_run = false);

    void on_log_store_found(logstore_id_t store_id, const logstore_superblk& meta);
    void on_io_completion(logstore_id_t id, logdev_key ld_key, logdev_key flush_idx, uint32_t nremaining_in_batch,
                          void* ctx);
    void on_logfound(logstore_id_t id, logstore_seq_num_t seq_num, logdev_key ld_key, logdev_key flush_ld_key,
                     log_buffer buf, uint32_t nremaining_in_batch);
    void on_batch_completion(HomeLogStore* log_store, uint32_t nremaining_in_batch, logdev_key flush_ld_key);

private:
    folly::Synchronized< std::unordered_map< logstore_id_t, logstore_info_t > > m_id_logstore_map;
    std::unordered_map< logstore_id_t, uint64_t > m_unopened_store_io;
    std::unordered_set< logstore_id_t > m_unopened_store_id;
    std::unordered_map< logstore_id_t, logid_t > m_last_flush_info;
    logstore_family_id_t m_family_id;
    std::string m_metablk_name;
    LogDev m_log_dev;
};
} // namespace homestore
