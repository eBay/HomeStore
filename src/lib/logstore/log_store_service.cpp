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
#include <iterator>
#include <string>

#include <fmt/format.h>
#include <iomgr/iomgr.hpp>
#include <sisl/utility/thread_factory.hpp>

#include <homestore/meta_service.hpp>
#include <homestore/logstore_service.hpp>
#include <homestore/homestore.hpp>
#include "device/chunk.h"

#include "common/homestore_assert.hpp"
#include "common/homestore_status_mgr.hpp"
#include "device/journal_vdev.hpp"
#include "device/physical_dev.hpp"
#include "log_dev.hpp"

namespace homestore {
SISL_LOGGING_DECL(logstore)

LogStoreService& logstore_service() { return hs()->logstore_service(); }

/////////////////////////////////////// LogStoreService Section ///////////////////////////////////////
LogStoreService::LogStoreService() : m_sb{"LogStoreServiceSB"} {
    meta_service().register_handler(
        logdev_sb_meta_name,
        [this](meta_blk* mblk, sisl::byte_view buf, size_t size) {
            logdev_super_blk_found(std::move(buf), voidptr_cast(mblk));
        },
        nullptr);

    meta_service().register_handler(
        logdev_rollback_sb_meta_name,
        [this](meta_blk* mblk, sisl::byte_view buf, size_t size) {
            rollback_super_blk_found(std::move(buf), voidptr_cast(mblk));
        },
        nullptr, true, std::optional< meta_subtype_vec_t >({logdev_sb_meta_name}));

    meta_service().register_handler(
        "LogStoreServiceSB",
        [this](meta_blk* mblk, sisl::byte_view buf, size_t size) { on_meta_blk_found(std::move(buf), (void*)mblk); },
        nullptr);
}

void LogStoreService::on_meta_blk_found(const sisl::byte_view& buf, void* meta_cookie) {
    m_sb.load(buf, meta_cookie);
    HS_REL_ASSERT_EQ(m_sb->magic, logstore_service_sb_magic, "Invalid log service metablk, magic mismatch");
    HS_REL_ASSERT_EQ(m_sb->version, logstore_service_sb_version, "Invalid version of log service metablk");
}

folly::Future< std::error_code > LogStoreService::create_vdev(uint64_t size, HSDevType devType, uint32_t chunk_size) {
    const auto atomic_page_size = hs()->device_mgr()->atomic_page_size(devType);

    hs_vdev_context hs_ctx;
    hs_ctx.type = hs_vdev_type_t::LOGDEV_VDEV;

#ifdef _PRERELEASE
    auto min_size = iomgr_flip::instance()->get_test_flip< long >("set_minimum_chunk_size");
    if (min_size) {
        chunk_size = min_size.get();
        LOGINFO("Flip set_minimum_chunk_size is enabled, min_chunk_size now is {}", chunk_size);
    }
#endif

    // reason we set alloc_type/chunk_sel_type here instead of by homestore logstore service consumer is because
    // consumer doesn't care or understands the underlying alloc/chunkSel for this service, if this changes in the
    // future, we can let consumer set it by then;
    auto vdev =
        hs()->device_mgr()->create_vdev(vdev_parameters{.vdev_name = "LogDev",
                                                        .size_type = vdev_size_type_t::VDEV_SIZE_DYNAMIC,
                                                        .vdev_size = 0,
                                                        .num_chunks = 0,
                                                        .blk_size = atomic_page_size,
                                                        .chunk_size = chunk_size,
                                                        .dev_type = devType,
                                                        .alloc_type = blk_allocator_type_t::none,
                                                        .chunk_sel_type = chunk_selector_type_t::ROUND_ROBIN,
                                                        .multi_pdev_opts = vdev_multi_pdev_opts_t::ALL_PDEV_STRIPED,
                                                        .context_data = hs_ctx.to_blob()});

    return vdev->async_format();
}

std::shared_ptr< VirtualDev > LogStoreService::open_vdev(const vdev_info& vinfo, bool load_existing) {
    RELEASE_ASSERT(m_logdev_vdev == nullptr, "Duplicate journal vdev");
    auto vdev = std::make_shared< JournalVirtualDev >(*(hs()->device_mgr()), vinfo, nullptr);
    m_logdev_vdev = std::dynamic_pointer_cast< JournalVirtualDev >(vdev);
    return vdev;
}

void LogStoreService::start(bool format) {
    // hs()->status_mgr()->register_status_cb("LogStore", bind_this(LogStoreService::get_status, 1));
    if (format) {
        m_sb.create(sizeof(logstore_service_super_block));
        m_sb.write();
    }

    // Create an truncate thread loop which handles truncation which does sync IO
    start_threads();

    for (auto& [logdev_id, logdev] : m_id_logdev_map) {
        logdev->start(format, m_logdev_vdev);
    }
}

void LogStoreService::stop() {
    start_stopping();
    while (true) {
        if (!get_pending_request_num()) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }

    for (auto& [id, logdev] : m_id_logdev_map) {
        logdev->stop();
    }
}

LogStoreService::~LogStoreService() {
    folly::SharedMutexWritePriority::WriteHolder holder(m_logdev_map_mtx);
    m_id_logdev_map.clear();
}

logdev_id_t LogStoreService::get_next_logdev_id() {
    auto id = ++(m_sb->m_last_logdev_id);
    m_sb.write();
    return id;
}

logdev_id_t LogStoreService::create_new_logdev(flush_mode_t flush_mode, uuid_t pid) {
    if (is_stopping()) return 0;
    incr_pending_request_num();
    folly::SharedMutexWritePriority::WriteHolder holder(m_logdev_map_mtx);
    logdev_id_t logdev_id = get_next_logdev_id();
    auto logdev = create_new_logdev_internal(logdev_id, flush_mode, pid);
    logdev->start(true /* format */, m_logdev_vdev);
    COUNTER_INCREMENT(m_metrics, logdevs_count, 1);
    HS_LOG(INFO, logstore, "Created log_dev={}", logdev_id);
    decr_pending_request_num();
    return logdev_id;
}

void LogStoreService::destroy_log_dev(logdev_id_t logdev_id) {
    if (is_stopping()) return;
    HS_LOG(INFO, logstore, "Destroying logdev {}", logdev_id);
    incr_pending_request_num();
    folly::SharedMutexWritePriority::WriteHolder holder(m_logdev_map_mtx);
    const auto it = m_id_logdev_map.find(logdev_id);
    if (it == m_id_logdev_map.end()) {
        LOGERROR("Logdev not found to destroy {}", logdev_id);
        return;
    }

    // Stop the logdev and release all the chunks from the journal vdev.
    auto& logdev = it->second;
    logdev->stop();

    // First release all chunks.
    m_logdev_vdev->destroy(logdev_id);

    // Destroy the metablks for logdev.
    logdev->destroy();

    m_id_logdev_map.erase(it);
    COUNTER_DECREMENT(m_metrics, logdevs_count, 1);
    HS_LOG(INFO, logstore, "Removed log_dev={}", logdev_id);
    decr_pending_request_num();
}

void LogStoreService::delete_unopened_logdevs() {
    for (auto logdev_id : m_unopened_logdev) {
        HS_LOG(INFO, logstore, "Deleting unopened log_dev={}", logdev_id);
        destroy_log_dev(logdev_id);
    }
    m_unopened_logdev.clear();
}

std::shared_ptr< LogDev > LogStoreService::create_new_logdev_internal(logdev_id_t logdev_id, flush_mode_t flush_mode,
                                                                      uuid_t pid) {
    auto logdev = std::make_shared< LogDev >(logdev_id, flush_mode, pid);
    const auto it = m_id_logdev_map.find(logdev_id);
    HS_REL_ASSERT((it == m_id_logdev_map.end()), "logdev id {} already exists", logdev_id);
    m_id_logdev_map.insert(std::make_pair<>(logdev_id, logdev));
    LOGINFO("Created logdev {}", logdev_id);
    return logdev;
}

void LogStoreService::open_logdev(logdev_id_t logdev_id, flush_mode_t flush_mode, uuid_t pid) {
    folly::SharedMutexWritePriority::WriteHolder holder(m_logdev_map_mtx);
    const auto it = m_id_logdev_map.find(logdev_id);
    if (it == m_id_logdev_map.end()) {
        auto logdev = std::make_shared< LogDev >(logdev_id, flush_mode, pid);
        m_id_logdev_map.emplace(logdev_id, logdev);
        LOGDEBUGMOD(logstore, "log_dev={} does not exist, created!", logdev_id);
    }
    m_unopened_logdev.erase(logdev_id);
    HS_LOG(INFO, logstore, "Opened log_dev={}", logdev_id);
}

std::vector< std::shared_ptr< LogDev > > LogStoreService::get_all_logdevs() {
    std::vector< std::shared_ptr< LogDev > > res;
    if (is_stopping()) return res;
    incr_pending_request_num();
    folly::SharedMutexWritePriority::ReadHolder holder(m_logdev_map_mtx);

    for (auto& [id, logdev] : m_id_logdev_map) {
        res.push_back(logdev);
    }
    decr_pending_request_num();
    return res;
}

std::shared_ptr< LogDev > LogStoreService::get_logdev(logdev_id_t id) {
    folly::SharedMutexWritePriority::ReadHolder holder(m_logdev_map_mtx);
    const auto it = m_id_logdev_map.find(id);
    HS_REL_ASSERT((it != m_id_logdev_map.end()), "logdev id {} doesnt exists", id);
    return it->second;
}

void LogStoreService::logdev_super_blk_found(const sisl::byte_view& buf, void* meta_cookie) {
    superblk< logdev_superblk > sb;
    sb.load(buf, meta_cookie);
    HS_REL_ASSERT_EQ(sb->get_magic(), logdev_superblk::LOGDEV_SB_MAGIC, "Invalid logdev metablk, magic mismatch");
    HS_REL_ASSERT_EQ(sb->get_version(), logdev_superblk::LOGDEV_SB_VERSION, "Invalid version of logdev metablk");
    {
        folly::SharedMutexWritePriority::WriteHolder holder(m_logdev_map_mtx);
        std::shared_ptr< LogDev > logdev;
        auto id = sb->logdev_id;
        auto flush_mode = sb->flush_mode;
        auto const pid = sb->pid;
        const auto it = m_id_logdev_map.find(id);
        // We could update the logdev map either with logdev or rollback superblks found callbacks.
        if (it != m_id_logdev_map.end()) {
            logdev = it->second;
            HS_LOG(DEBUG, logstore, "Log dev superblk found log_dev={}", id);
        } else {
            logdev = std::make_shared< LogDev >(id, flush_mode, pid);
            m_id_logdev_map.emplace(id, logdev);
            // when recover logdev meta blk, we get all the logdevs from the superblk. we put them in m_unopened_logdev
            // too. after logdev meta blks are all recovered, when a client opens a logdev, we remove it from
            // m_unopened_logdev. so that when we start log service, all the left items in m_unopened_logdev are those
            // not open, which can be destroyed
            m_unopened_logdev.insert(id);
            HS_LOG(DEBUG, logstore, "Log dev superblk found log_dev={} added to unopened list", id);
        }

        logdev->log_dev_meta().logdev_super_blk_found(buf, meta_cookie);
    }
}

void LogStoreService::rollback_super_blk_found(const sisl::byte_view& buf, void* meta_cookie) {
    superblk< rollback_superblk > rollback_sb;
    rollback_sb.load(buf, meta_cookie);
    HS_REL_ASSERT_EQ(rollback_sb->get_magic(), rollback_superblk::ROLLBACK_SB_MAGIC, "Rollback sb magic mismatch");
    HS_REL_ASSERT_EQ(rollback_sb->get_version(), rollback_superblk::ROLLBACK_SB_VERSION,
                     "Rollback sb version mismatch");
    {
        folly::SharedMutexWritePriority::WriteHolder holder(m_logdev_map_mtx);
        std::shared_ptr< LogDev > logdev;
        auto id = rollback_sb->logdev_id;
        HS_LOG(DEBUG, logstore, "Log dev rollback superblk found logdev={}", id);
        const auto it = m_id_logdev_map.find(id);
        HS_REL_ASSERT((it != m_id_logdev_map.end()),
                      "found a rollback_super_blk of logdev id {}, but the logdev with id {} doesnt exist", id);
        logdev = it->second;
        logdev->log_dev_meta().rollback_super_blk_found(buf, meta_cookie);
    }
}

std::shared_ptr< HomeLogStore > LogStoreService::create_new_log_store(logdev_id_t logdev_id, bool append_mode) {
    if (is_stopping()) return nullptr;
    incr_pending_request_num();
    folly::SharedMutexWritePriority::WriteHolder holder(m_logdev_map_mtx);
    COUNTER_INCREMENT(m_metrics, logstores_count, 1);
    const auto it = m_id_logdev_map.find(logdev_id);
    HS_REL_ASSERT((it != m_id_logdev_map.end()), "logdev id {} doesnt exist", logdev_id);
    auto ret = it->second->create_new_log_store(append_mode);
    decr_pending_request_num();
    return ret;
}

folly::Future< shared< HomeLogStore > > LogStoreService::open_log_store(logdev_id_t logdev_id, logstore_id_t store_id,
                                                                        bool append_mode, log_found_cb_t log_found_cb,
                                                                        log_replay_done_cb_t log_replay_done_cb) {
    folly::SharedMutexWritePriority::ReadHolder holder(m_logdev_map_mtx);
    const auto it = m_id_logdev_map.find(logdev_id);
    HS_REL_ASSERT((it != m_id_logdev_map.end()), "logdev id {} doesnt exist", logdev_id);
    COUNTER_INCREMENT(m_metrics, logstores_count, 1);
    return it->second->open_log_store(store_id, append_mode, log_found_cb, log_replay_done_cb);
}

void LogStoreService::remove_log_store(logdev_id_t logdev_id, logstore_id_t store_id) {
    if (is_stopping()) return;
    HS_LOG(INFO, logstore, "Removing logstore {} from logdev {}", store_id, logdev_id);
    incr_pending_request_num();
    folly::SharedMutexWritePriority::WriteHolder holder(m_logdev_map_mtx);
    COUNTER_INCREMENT(m_metrics, logstores_count, 1);
    const auto it = m_id_logdev_map.find(logdev_id);
    if (it == m_id_logdev_map.end()) {
        HS_LOG(WARN, logstore, "logdev id {} doesnt exist", logdev_id);
        return;
    }
    it->second->remove_log_store(store_id);
    HS_LOG(INFO, logstore, "Successfully removed logstore {} from logdev {}", store_id, logdev_id);
    decr_pending_request_num();
    COUNTER_DECREMENT(m_metrics, logstores_count, 1);
}

void LogStoreService::device_truncate() {
    // TODO: make device_truncate_under_lock return future and do collectAllFutures;
    if (is_stopping()) return;
    incr_pending_request_num();
    for (auto& [id, logdev] : m_id_logdev_map) {
        HS_LOG(DEBUG, logstore, "Truncating logdev {}", id);
        logdev->truncate();
    }
    decr_pending_request_num();
}

void LogStoreService::flush() {
    if (is_stopping()) return;
    incr_pending_request_num();
    for (auto& [id, logdev] : m_id_logdev_map)
        logdev->flush_under_guard();
    decr_pending_request_num();
}

void LogStoreService::start_threads() {
    struct Context {
        std::condition_variable cv;
        std::mutex mtx;
        size_t thread_cnt{0};
    };
    auto ctx = std::make_shared< Context >();

    m_flush_fiber = nullptr;
    iomanager.create_reactor("log_flush_thread", iomgr::TIGHT_LOOP | iomgr::ADAPTIVE_LOOP, 1 /* num_fibers */,
                             [this, ctx](bool is_started) {
                                 if (is_started) {
                                     m_flush_fiber = iomanager.iofiber_self();
                                     {
                                         std::unique_lock< std::mutex > lk{ctx->mtx};
                                         ++(ctx->thread_cnt);
                                     }
                                     ctx->cv.notify_one();
                                 }
                             });
    {
        std::unique_lock< std::mutex > lk{ctx->mtx};
        ctx->cv.wait(lk, [ctx] { return (ctx->thread_cnt == 1); });
    }
}

nlohmann::json LogStoreService::dump_log_store(const log_dump_req& dump_req) {
    nlohmann::json json_dump{}; // create root object
    if (is_stopping()) return json_dump;
    incr_pending_request_num();
    if (dump_req.log_store == nullptr) {
        for (auto& [id, logdev] : m_id_logdev_map) {
            json_dump[logdev->get_id()] = logdev->dump_log_store(dump_req);
        }
    } else {
        auto logdev = dump_req.log_store->get_logdev();
        // must use operator= construction as copy construction results in error
        nlohmann::json val = logdev->dump_log_store(dump_req);
        json_dump[logdev->get_id()] = std::move(val);
    }
    decr_pending_request_num();
    return json_dump;
}

nlohmann::json LogStoreService::get_status(const int verbosity) const {
    nlohmann::json js;
    if (is_stopping()) return js;
    incr_pending_request_num();
    for (auto& [id, logdev] : m_id_logdev_map) {
        js[logdev->get_id()] = logdev->get_status(verbosity);
    }
    decr_pending_request_num();
    return js;
}

uint32_t LogStoreService::used_size() const { return m_logdev_vdev->used_size(); }

uint32_t LogStoreService::total_size() const { return m_logdev_vdev->size(); }

LogStoreServiceMetrics::LogStoreServiceMetrics() : sisl::MetricsGroup("LogStores", "AllLogStores") {
    REGISTER_COUNTER(logdevs_count, "Total number of log devs", sisl::_publish_as::publish_as_gauge);
    REGISTER_COUNTER(logstores_count, "Total number of log stores", sisl::_publish_as::publish_as_gauge);
    REGISTER_COUNTER(logstore_append_count, "Total number of append requests to log stores", "logstore_op_count",
                     {"op", "write"});
    REGISTER_COUNTER(logstore_read_count, "Total number of read requests to log stores", "logstore_op_count",
                     {"op", "read"});
    REGISTER_HISTOGRAM(logstore_append_latency, "Logstore append latency", "logstore_op_latency", {"op", "write"},
                       HistogramBucketsType(OpLatecyBuckets));
#ifdef _PRERELEASE
    REGISTER_HISTOGRAM(logstore_stream_tracker_lock_latency, "Logstore stream tracker lock latency",
                       "logstore_stream_tracker_lock_latency");
#endif
    REGISTER_HISTOGRAM(logstore_read_latency, "Logstore read latency", "logstore_op_latency", {"op", "read"},
                       HistogramBucketsType(OpLatecyBuckets));
    REGISTER_HISTOGRAM(logdev_flush_size_distribution, "Distribution of flush data size",
                       HistogramBucketsType(ExponentialOfTwoBuckets));
    REGISTER_HISTOGRAM(logdev_flush_records_distribution, "Distribution of num records to flush",
                       HistogramBucketsType(LinearUpto128Buckets));
    REGISTER_HISTOGRAM(logstore_record_size, "Distribution of log record size",
                       HistogramBucketsType(ExponentialOfTwoBuckets));
    REGISTER_HISTOGRAM(logdev_post_flush_processing_latency,
                       "Logdev post flush processing (including callbacks) latency",
                       HistogramBucketsType(OpLatecyBuckets));
    REGISTER_HISTOGRAM(logdev_flush_time_us, "time elapsed since last flush time in us",
                       HistogramBucketsType(OpLatecyBuckets));

    register_me_to_farm();
}
} // namespace homestore
