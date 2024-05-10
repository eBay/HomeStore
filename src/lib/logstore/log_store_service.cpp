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
LogStoreService::LogStoreService() {
    m_id_reserver = std::make_unique< sisl::IDReserver >();
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

    delete_unopened_logdevs();

    // Create an truncate thread loop which handles truncation which does sync IO
    start_threads();

    for (auto& [logdev_id, logdev] : m_id_logdev_map) {
        logdev->start(format);
    }
}

void LogStoreService::stop() {
    // device_truncate(nullptr, true, false);
    for (auto& [id, logdev] : m_id_logdev_map) {
        logdev->stop();
    }
    {
        folly::SharedMutexWritePriority::WriteHolder holder(m_logdev_map_mtx);
        m_id_logdev_map.clear();
    }
    m_id_reserver.reset();
}

logdev_id_t LogStoreService::create_new_logdev() {
    folly::SharedMutexWritePriority::WriteHolder holder(m_logdev_map_mtx);
    logdev_id_t logdev_id = m_id_reserver->reserve();
    auto logdev = create_new_logdev_internal(logdev_id);
    logdev->start(true /* format */);
    COUNTER_INCREMENT(m_metrics, logdevs_count, 1);
    LOGINFO("Created log_dev={}", logdev_id);
    return logdev_id;
}

void LogStoreService::destroy_log_dev(logdev_id_t logdev_id) {
    folly::SharedMutexWritePriority::WriteHolder holder(m_logdev_map_mtx);
    const auto it = m_id_logdev_map.find(logdev_id);
    if (it == m_id_logdev_map.end()) { return; }

    // Stop the logdev and release all the chunks from the journal vdev.
    auto& logdev = it->second;
    if (!logdev->is_stopped()) {
        // Stop the logdev if its started.
        logdev->stop();
    }

    // First release all chunks.
    m_logdev_vdev->destroy(logdev_id);

    // Destroy the metablks for logdev.
    logdev->destroy();

    m_id_logdev_map.erase(it);
    COUNTER_DECREMENT(m_metrics, logdevs_count, 1);
    LOGINFO("Removed log_dev={}", logdev_id);
}

void LogStoreService::delete_unopened_logdevs() {
    for (auto logdev_id : m_unopened_logdev) {
        LOGINFO("Deleting unopened log_dev={}", logdev_id);
        destroy_log_dev(logdev_id);
    }
    m_unopened_logdev.clear();
}

std::shared_ptr< LogDev > LogStoreService::create_new_logdev_internal(logdev_id_t logdev_id) {
    auto logdev = std::make_shared< LogDev >(logdev_id, m_logdev_vdev.get());
    const auto it = m_id_logdev_map.find(logdev_id);
    HS_REL_ASSERT((it == m_id_logdev_map.end()), "logdev id {} already exists", logdev_id);
    m_id_logdev_map.insert(std::make_pair<>(logdev_id, logdev));
    return logdev;
}

void LogStoreService::open_logdev(logdev_id_t logdev_id) {
    folly::SharedMutexWritePriority::WriteHolder holder(m_logdev_map_mtx);
    const auto it = m_id_logdev_map.find(logdev_id);
    if (it == m_id_logdev_map.end()) {
        m_id_reserver->reserve(logdev_id);
        auto logdev = std::make_shared< LogDev >(logdev_id, m_logdev_vdev.get());
        m_id_logdev_map.emplace(logdev_id, logdev);
        LOGDEBUGMOD(logstore, "log_dev={} does not exist, created!", logdev_id);
    }
    m_unopened_logdev.erase(logdev_id);
    LOGDEBUGMOD(logstore, "Opened log_dev={}", logdev_id);
}

std::vector< std::shared_ptr< LogDev > > LogStoreService::get_all_logdevs() {
    folly::SharedMutexWritePriority::ReadHolder holder(m_logdev_map_mtx);
    std::vector< std::shared_ptr< LogDev > > res;
    for (auto& [id, logdev] : m_id_logdev_map) {
        res.push_back(logdev);
    }
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
        LOGDEBUGMOD(logstore, "Log dev superblk found logdev={}", id);
        const auto it = m_id_logdev_map.find(id);
        // We could update the logdev map either with logdev or rollback superblks found callbacks.
        if (it != m_id_logdev_map.end()) {
            logdev = it->second;
        } else {
            logdev = std::make_shared< LogDev >(id, m_logdev_vdev.get());
            m_id_logdev_map.emplace(id, logdev);
            // when recover logdev meta blk, we get all the logdevs from the superblk. we put them in m_unopened_logdev
            // too. after logdev meta blks are all recovered, when a client opens a logdev, we remove it from
            // m_unopened_logdev. so that when we start log service, all the left items in m_unopened_logdev are those
            // not open, which can be destroyed
            m_unopened_logdev.insert(id);
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
        LOGDEBUGMOD(logstore, "Log dev rollback superblk found logdev={}", id);
        const auto it = m_id_logdev_map.find(id);
        if (it != m_id_logdev_map.end()) {
            logdev = it->second;
        } else {
            logdev = std::make_shared< LogDev >(id, m_logdev_vdev.get());
            m_id_logdev_map.emplace(id, logdev);
        }

        logdev->log_dev_meta().rollback_super_blk_found(buf, meta_cookie);
    }
}

std::shared_ptr< HomeLogStore > LogStoreService::create_new_log_store(logdev_id_t logdev_id, bool append_mode) {
    folly::SharedMutexWritePriority::WriteHolder holder(m_logdev_map_mtx);
    COUNTER_INCREMENT(m_metrics, logstores_count, 1);
    const auto it = m_id_logdev_map.find(logdev_id);
    HS_REL_ASSERT((it != m_id_logdev_map.end()), "logdev id {} doesnt exist", logdev_id);
    return it->second->create_new_log_store(append_mode);
}

folly::Future< shared< HomeLogStore > > LogStoreService::open_log_store(logdev_id_t logdev_id, logstore_id_t store_id,
                                                                        bool append_mode) {
    folly::SharedMutexWritePriority::ReadHolder holder(m_logdev_map_mtx);
    const auto it = m_id_logdev_map.find(logdev_id);
    HS_REL_ASSERT((it != m_id_logdev_map.end()), "logdev id {} doesnt exist", logdev_id);
    COUNTER_INCREMENT(m_metrics, logstores_count, 1);
    return it->second->open_log_store(store_id, append_mode);
}

void LogStoreService::remove_log_store(logdev_id_t logdev_id, logstore_id_t store_id) {
    folly::SharedMutexWritePriority::WriteHolder holder(m_logdev_map_mtx);
    COUNTER_INCREMENT(m_metrics, logstores_count, 1);
    const auto it = m_id_logdev_map.find(logdev_id);
    HS_REL_ASSERT((it != m_id_logdev_map.end()), "logdev id {} doesnt exist", logdev_id);
    it->second->remove_log_store(store_id);
    COUNTER_DECREMENT(m_metrics, logstores_count, 1);
}

void LogStoreService::device_truncate(const device_truncate_cb_t& cb, bool wait_till_done, bool dry_run) {
    const auto treq = std::make_shared< truncate_req >();
    treq->wait_till_done = wait_till_done;
    treq->dry_run = dry_run;
    treq->cb = cb;
    if (treq->wait_till_done) { treq->trunc_outstanding = m_id_logdev_map.size(); }

    // TODO: make device_truncate_under_lock return future and do collectAllFutures;
    for (auto& [id, logdev] : m_id_logdev_map) {
        logdev->device_truncate_under_lock(treq);
    }

    if (treq->wait_till_done) {
        std::unique_lock< std::mutex > lk{treq->mtx};
        treq->cv.wait(lk, [&] { return (treq->trunc_outstanding == 0); });
    }
}

void LogStoreService::flush_if_needed() {
    for (auto& [id, logdev] : m_id_logdev_map) {
        logdev->flush_if_needed();
    }
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

    m_truncate_fiber = nullptr;
    iomanager.create_reactor("logstore_truncater", iomgr::INTERRUPT_LOOP, 2 /* num_fibers */,
                             [this, ctx](bool is_started) {
                                 if (is_started) {
                                     m_truncate_fiber = iomanager.sync_io_capable_fibers()[0];
                                     {
                                         std::unique_lock< std::mutex > lk{ctx->mtx};
                                         ++(ctx->thread_cnt);
                                     }
                                     ctx->cv.notify_one();
                                 }
                             });
    {
        std::unique_lock< std::mutex > lk{ctx->mtx};
        ctx->cv.wait(lk, [ctx] { return (ctx->thread_cnt == 2); });
    }
}

nlohmann::json LogStoreService::dump_log_store(const log_dump_req& dump_req) {
    nlohmann::json json_dump{}; // create root object
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
    return json_dump;
}

nlohmann::json LogStoreService::get_status(const int verbosity) const {
    nlohmann::json js;
    for (auto& [id, logdev] : m_id_logdev_map) {
        js[logdev->get_id()] = logdev->get_status(verbosity);
    }
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
    REGISTER_HISTOGRAM(logstore_append_latency, "Logstore append latency", "logstore_op_latency", {"op", "write"});
    REGISTER_HISTOGRAM(logstore_read_latency, "Logstore read latency", "logstore_op_latency", {"op", "read"});
    REGISTER_HISTOGRAM(logdev_flush_size_distribution, "Distribution of flush data size",
                       HistogramBucketsType(ExponentialOfTwoBuckets));
    REGISTER_HISTOGRAM(logdev_flush_records_distribution, "Distribution of num records to flush",
                       HistogramBucketsType(LinearUpto128Buckets));
    REGISTER_HISTOGRAM(logstore_record_size, "Distribution of log record size",
                       HistogramBucketsType(ExponentialOfTwoBuckets));
    REGISTER_HISTOGRAM(logdev_flush_done_msg_time_ns, "Logdev flush completion msg time in ns");
    REGISTER_HISTOGRAM(logdev_post_flush_processing_latency,
                       "Logdev post flush processing (including callbacks) latency");
    REGISTER_HISTOGRAM(logdev_fsync_time_us, "Logdev fsync completion time in us");

    register_me_to_farm();
}
} // namespace homestore
