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

#include <homestore/homestore_decl.hpp>
#include <homestore/logstore/log_store.hpp>

namespace homestore {

class LogStoreServiceMetrics : public sisl::MetricsGroup {
public:
    LogStoreServiceMetrics();
    LogStoreServiceMetrics(const LogStoreServiceMetrics&) = delete;
    LogStoreServiceMetrics(LogStoreServiceMetrics&&) noexcept = delete;
    LogStoreServiceMetrics& operator=(const LogStoreServiceMetrics&) = delete;
    LogStoreServiceMetrics& operator=(LogStoreServiceMetrics&&) noexcept = delete;
};

class LogStoreFamily;
class HomeLogStore;
class LogDev;
struct logdev_key;
class VirtualDev;
class JournalVirtualDev;
struct vdev_info;
struct log_dump_req;

class LogStoreService {
    friend class HomeLogStore;
    friend class LogStoreFamily;
    friend class LogDev;

public:
    static constexpr logstore_family_id_t DATA_LOG_FAMILY_IDX{0};
    static constexpr logstore_family_id_t CTRL_LOG_FAMILY_IDX{1};
    static constexpr size_t num_log_families = CTRL_LOG_FAMILY_IDX + 1;
    typedef std::function< void(const std::array< logdev_key, num_log_families >&) > device_truncate_cb_t;

    LogStoreService();
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
     * @brief Create a brand new log store (both in-memory and on device) and returns its instance. It also book
     * keeps the created log store and user can get this instance of log store by using logstore_id
     *
     * @param family_id: Logstores can be created on different log_devs. As of now we only support data log_dev and
     * ctrl log dev. The idx indicates which log device it is from. Its a mandatory parameter.
     * @param append_mode: If the log store have to be in append mode, user can call append_async and do not need to
     * maintain the log_idx. Else user is expected to keep track of the log idx. Default to false
     *
     * @return std::shared_ptr< HomeLogStore >
     */
    std::shared_ptr< HomeLogStore > create_new_log_store(const logstore_family_id_t family_id,
                                                         const bool append_mode = false);

    /**
     * @brief Open an existing log store and does a recovery. It then creates an instance of this logstore and
     * returns
     *
     * @param store_id: Store ID of the log store to open
     * @return std::shared_ptr< HomeLogStore >
     */
    void open_log_store(const logstore_family_id_t family_id, const logstore_id_t store_id, const bool append_mode,
                        const log_store_opened_cb_t& on_open_cb);

    /**
     * @brief Close the log store instance and free-up the resources
     *
     * @param store_id: Store ID of the log store to close
     * @return true on success
     */
    bool close_log_store(const logstore_family_id_t family_id, const logstore_id_t store_id) {
        // TODO: Implement this method
        return true;
    }

    /**
     * @brief Remove an existing log store. It removes in-memory and schedule to reuse the store id after device
     * truncation.
     *
     * @param store_id
     */
    void remove_log_store(const logstore_family_id_t family_id, const logstore_id_t store_id);

    /**
     * @brief Schedule a truncate all the log stores physically on the device.
     *
     * @param cb [OPTIONAL] Callback once truncation is completed, if provided (Default no callback)
     * @param wait_till_done [OPTIONAL] Wait for the truncation to complete before returning from this method.
     * Default to false
     * @param dry_run: If the truncate is a real one or just dry run to simulate the truncation
     */
    void device_truncate(const device_truncate_cb_t& cb = nullptr, const bool wait_till_done = false,
                         const bool dry_run = false);

    folly::Future< bool > create_vdev(uint64_t size, logstore_family_id_t family);
    shared< VirtualDev > open_vdev(const vdev_info& vinfo, logstore_family_id_t family, bool load_existing);
    shared< JournalVirtualDev > get_vdev(logstore_family_id_t family) const {
        return (family == DATA_LOG_FAMILY_IDX) ? m_data_logdev_vdev : m_ctrl_logdev_vdev;
    }

    nlohmann::json dump_log_store(const log_dump_req& dum_req);
    nlohmann::json get_status(const int verbosity) const;

    LogStoreServiceMetrics& metrics() { return m_metrics; }
    LogStoreFamily* data_log_family() { return m_logstore_families[DATA_LOG_FAMILY_IDX].get(); }
    LogStoreFamily* ctrl_log_family() { return m_logstore_families[CTRL_LOG_FAMILY_IDX].get(); }

    LogDev& data_logdev();
    LogDev& ctrl_logdev();

    uint32_t used_size() const;
    uint32_t total_size() const;
    iomgr::io_fiber_t flush_thread() { return m_flush_fiber; }
    iomgr::io_fiber_t truncate_thread() { return m_truncate_fiber; }

private:
    void start_threads();
    void flush_if_needed();

private:
    std::array< std::unique_ptr< LogStoreFamily >, num_log_families > m_logstore_families;
    std::shared_ptr< JournalVirtualDev > m_data_logdev_vdev;
    std::shared_ptr< JournalVirtualDev > m_ctrl_logdev_vdev;
    iomgr::io_fiber_t m_truncate_fiber;
    iomgr::io_fiber_t m_flush_fiber;
    LogStoreServiceMetrics m_metrics;
};

extern LogStoreService& logstore_service();
} // namespace homestore
