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
#include <array>
#include <condition_variable>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>

#include <iomgr/iomgr.hpp>
#include <sisl/metrics/metrics.hpp>
#include <nlohmann/json.hpp>
#include <boost/uuid/nil_generator.hpp>
#include <homestore/homestore_decl.hpp>
#include <homestore/logstore/log_store.hpp>
#include <homestore/superblk_handler.hpp>

namespace homestore {

class LogStoreServiceMetrics : public sisl::MetricsGroup {
public:
    LogStoreServiceMetrics();
    LogStoreServiceMetrics(const LogStoreServiceMetrics&) = delete;
    LogStoreServiceMetrics(LogStoreServiceMetrics&&) noexcept = delete;
    LogStoreServiceMetrics& operator=(const LogStoreServiceMetrics&) = delete;
    LogStoreServiceMetrics& operator=(LogStoreServiceMetrics&&) noexcept = delete;
};

class HomeLogStore;
class LogDev;
struct logdev_key;
class VirtualDev;
class JournalVirtualDev;
struct vdev_info;
struct log_dump_req;
struct logdev_superblk;

static constexpr uint64_t logstore_service_sb_magic{0xb0b0c01b};
static constexpr uint32_t logstore_service_sb_version{0x1};

#pragma pack(1)
struct logstore_service_super_block {
    uint64_t magic{logstore_service_sb_magic};
    uint32_t version{logstore_service_sb_version};
    uint32_t m_last_logdev_id{0};
};
#pragma pack()

class LogStoreService {
    friend class HomeLogStore;
    friend class LogDev;

public:
    LogStoreService();
    ~LogStoreService();
    LogStoreService(const LogStoreService&) = delete;
    LogStoreService(LogStoreService&&) noexcept = delete;
    LogStoreService& operator=(const LogStoreService&) = delete;
    LogStoreService& operator=(LogStoreService&&) noexcept = delete;

    /**
     * @brief Start the entire LogStoreService set and does recover the existing logstores. Really this is the first
     * method to be executed on log store.
     *
     * @param format If set to true, will not recover, but create a fresh log store set.
     */
    void start(bool format);

    /**
     * @brief Stop the LogStoreService. It resets all parameters and can be restarted with start method.
     *
     */
    void stop();

    /**
     * @brief Create a brand new log dev. A logdev manages a list of chunks and state about the log offsets.
     * Internally each logdev has a journal descriptor which maintains the data start and tail offsets and list of
     * chunks. Logdev can start with zero chunks and dynamically add chunks based on write request.
     * @return Newly created log dev id.
     */
    logdev_id_t create_new_logdev(flush_mode_t flush_mode, uuid_t pid = boost::uuids::nil_uuid());

    /**
     * @brief Open a log dev.
     *
     * @param logdev_id: Logdev ID
     * @return Newly created log dev id.
     */
    void open_logdev(logdev_id_t logdev_id, flush_mode_t flush_mode, uuid_t pid = boost::uuids::nil_uuid());

    /**
     * @brief Destroy a log dev.
     *
     * @param logdev_id: Logdev ID
     */
    void destroy_log_dev(logdev_id_t logdev_id);

    /**
     * @brief Create a brand new log store (both in-memory and on device) and returns its instance. It also book
     * keeps the created log store and user can get this instance of log store by using logstore_id
     *
     * @param logdev_id: Logstores can be created on different log_devs.
     * @param append_mode: If the log store have to be in append mode, user can call append_async and do not need to
     * maintain the log_idx. Else user is expected to keep track of the log idx. Default to false
     *
     * @return std::shared_ptr< HomeLogStore >
     */
    std::shared_ptr< HomeLogStore > create_new_log_store(logdev_id_t logdev_id, bool append_mode = false);

    /**
     * @brief Open an existing log store and does a recovery. It then creates an instance of this logstore and
     * returns
     * @param logdev_id: Logdev ID of the log store to close
     * @param store_id: Store ID of the log store to open
     * @param append_mode: Append or not.
     * @param on_open_cb: Callback to be called once log store is opened.
     * @return std::shared_ptr< HomeLogStore >
     */
    folly::Future< shared< HomeLogStore > > open_log_store(logdev_id_t logdev_id, logstore_id_t store_id,
                                                           bool append_mode, log_found_cb_t log_found_cb = nullptr,
                                                           log_replay_done_cb_t log_replay_done_cb = nullptr);

    /**
     * @brief Close the log store instance and free-up the resources
     * @param logdev_id: Logdev ID of the log store to close
     * @param store_id: Store ID of the log store to close
     * @return true on success
     */
    bool close_log_store(logdev_id_t logdev_id, logstore_id_t store_id) {
        // TODO: Implement this method
        return true;
    }

    /**
     * @brief Remove an existing log store. It removes in-memory and schedule to reuse the store id after device
     * truncation.
     *
     * @param store_id
     */
    void remove_log_store(logdev_id_t logdev_id, logstore_id_t store_id);

    /**
     * @brief Schedule a truncate all the log stores physically on the device.
     */
    void device_truncate();

    folly::Future< std::error_code > create_vdev(uint64_t size, HSDevType devType, uint64_t chunk_size);
    std::shared_ptr< VirtualDev > open_vdev(const vdev_info& vinfo, bool load_existing);
    std::shared_ptr< JournalVirtualDev > get_vdev() const { return m_logdev_vdev; }
    std::vector< std::shared_ptr< LogDev > > get_all_logdevs();
    std::shared_ptr< LogDev > get_logdev(logdev_id_t id);

    nlohmann::json dump_log_store(const log_dump_req& dum_req);
    nlohmann::json get_status(int verbosity) const;

    LogStoreServiceMetrics& metrics() { return m_metrics; }

    uint32_t used_size() const;
    uint32_t total_size() const;
    iomgr::io_fiber_t flush_thread() { return m_flush_fiber; }

    void delete_unopened_logdevs();

private:
    std::shared_ptr< LogDev > create_new_logdev_internal(logdev_id_t logdev_id, flush_mode_t flush_mode,
                                                         uuid_t pid = boost::uuids::nil_uuid());
    void on_meta_blk_found(const sisl::byte_view& buf, void* meta_cookie);
    logdev_id_t get_next_logdev_id();
    void logdev_super_blk_found(const sisl::byte_view& buf, void* meta_cookie);
    void rollback_super_blk_found(const sisl::byte_view& buf, void* meta_cookie);
    void start_threads();
    void flush();

private:
    std::unordered_map< logdev_id_t, std::shared_ptr< LogDev > > m_id_logdev_map;
    folly::SharedMutexWritePriority m_logdev_map_mtx;

    std::shared_ptr< JournalVirtualDev > m_logdev_vdev;
    iomgr::io_fiber_t m_flush_fiber;
    LogStoreServiceMetrics m_metrics;
    std::unordered_set< logdev_id_t > m_unopened_logdev;
    superblk< logstore_service_super_block > m_sb;

private:
    // graceful shutdown related
    std::atomic_bool m_stopping{false};
    mutable std::atomic_uint64_t pending_request_num{0};

    bool is_stopping() const { return m_stopping.load(); }
    void start_stopping() { m_stopping = true; }

    uint64_t get_pending_request_num() const { return pending_request_num.load(); }

    void incr_pending_request_num() const { pending_request_num++; }
    void decr_pending_request_num() const { pending_request_num--; }
};

extern LogStoreService& logstore_service();
} // namespace homestore
