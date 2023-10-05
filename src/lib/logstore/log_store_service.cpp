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
#include "log_store_family.hpp"
#include "log_dev.hpp"

namespace homestore {
SISL_LOGGING_DECL(logstore)

LogStoreService& logstore_service() { return hs()->logstore_service(); }

/////////////////////////////////////// LogStoreService Section ///////////////////////////////////////
LogStoreService::LogStoreService() :
        m_logstore_families{std::make_unique< LogStoreFamily >(DATA_LOG_FAMILY_IDX),
                            std::make_unique< LogStoreFamily >(CTRL_LOG_FAMILY_IDX)} {}

folly::Future< std::error_code > LogStoreService::create_vdev(uint64_t size, logstore_family_id_t family,
                                                              uint32_t num_chunks) {
    const auto atomic_page_size = hs()->device_mgr()->atomic_page_size(HSDevType::Fast);

    hs_vdev_context hs_ctx;
    std::string name;

    if (family == DATA_LOG_FAMILY_IDX) {
        name = "data_logdev";
        hs_ctx.type = hs_vdev_type_t::DATA_LOGDEV_VDEV;
    } else {
        name = "ctrl_logdev";
        hs_ctx.type = hs_vdev_type_t::CTRL_LOGDEV_VDEV;
    }

    // reason we set alloc_type/chunk_sel_type here instead of by homestore logstore service consumer is because
    // consumer doesn't care or understands the underlying alloc/chunkSel for this service, if this changes in the
    // future, we can let consumer set it by then;
    auto vdev =
        hs()->device_mgr()->create_vdev(vdev_parameters{.vdev_name = name,
                                                        .vdev_size = size,
                                                        .num_chunks = num_chunks,
                                                        .blk_size = atomic_page_size,
                                                        .dev_type = HSDevType::Fast,
                                                        .alloc_type = blk_allocator_type_t::none,
                                                        .chunk_sel_type = chunk_selector_type_t::ROUND_ROBIN,
                                                        .multi_pdev_opts = vdev_multi_pdev_opts_t::ALL_PDEV_STRIPED,
                                                        .context_data = hs_ctx.to_blob()});

    return vdev->async_format();
}

shared< VirtualDev > LogStoreService::open_vdev(const vdev_info& vinfo, logstore_family_id_t family,
                                                bool load_existing) {
    auto vdev = std::make_shared< JournalVirtualDev >(*(hs()->device_mgr()), vinfo, nullptr);
    if (family == DATA_LOG_FAMILY_IDX) {
        m_data_logdev_vdev = std::dynamic_pointer_cast< JournalVirtualDev >(vdev);
    } else {
        m_ctrl_logdev_vdev = std::dynamic_pointer_cast< JournalVirtualDev >(vdev);
    }
    return vdev;
}

void LogStoreService::start(bool format) {
    // hs()->status_mgr()->register_status_cb("LogStore", bind_this(LogStoreService::get_status, 1));

    // Create an truncate thread loop which handles truncation which does sync IO
    start_threads();

    // Start the logstore families
    m_logstore_families[DATA_LOG_FAMILY_IDX]->start(format, m_data_logdev_vdev.get());
    m_logstore_families[CTRL_LOG_FAMILY_IDX]->start(format, m_ctrl_logdev_vdev.get());
}

void LogStoreService::stop() {
    device_truncate(nullptr, true, false);
    for (auto& f : m_logstore_families) {
        f->stop();
    }
}

std::shared_ptr< HomeLogStore > LogStoreService::create_new_log_store(const logstore_family_id_t family_id,
                                                                      const bool append_mode) {
    HS_REL_ASSERT_LT(family_id, num_log_families);
    COUNTER_INCREMENT(m_metrics, logstores_count, 1);
    return m_logstore_families[family_id]->create_new_log_store(append_mode);
}

void LogStoreService::open_log_store(const logstore_family_id_t family_id, const logstore_id_t store_id,
                                     const bool append_mode, const log_store_opened_cb_t& on_open_cb) {
    HS_REL_ASSERT_LT(family_id, num_log_families);
    COUNTER_INCREMENT(m_metrics, logstores_count, 1);
    return m_logstore_families[family_id]->open_log_store(store_id, append_mode, on_open_cb);
}

void LogStoreService::remove_log_store(const logstore_family_id_t family_id, const logstore_id_t store_id) {
    HS_REL_ASSERT_LT(family_id, num_log_families);
    m_logstore_families[family_id]->remove_log_store(store_id);
    COUNTER_DECREMENT(m_metrics, logstores_count, 1);
}

void LogStoreService::device_truncate(const device_truncate_cb_t& cb, const bool wait_till_done, const bool dry_run) {
    const auto treq = std::make_shared< truncate_req >();
    treq->wait_till_done = wait_till_done;
    treq->dry_run = dry_run;
    treq->cb = cb;
    if (treq->wait_till_done) { treq->trunc_outstanding = m_logstore_families.size(); }

    for (auto& l : m_logstore_families) {
        l->device_truncate(treq);
    }

    if (treq->wait_till_done) {
        std::unique_lock< std::mutex > lk{treq->mtx};
        treq->cv.wait(lk, [&] { return (treq->trunc_outstanding == 0); });
    }
}

void LogStoreService::flush_if_needed() {
    for (auto& f : m_logstore_families) {
        f->logdev().flush_if_needed();
    }
}

LogDev& LogStoreService::data_logdev() { return data_log_family()->logdev(); }
LogDev& LogStoreService::ctrl_logdev() { return ctrl_log_family()->logdev(); }

void LogStoreService::start_threads() {
    struct Context {
        std::condition_variable cv;
        std::mutex mtx;
        size_t thread_cnt{0};
    };
    auto ctx = std::make_shared< Context >();

    m_flush_fiber = nullptr;
    iomanager.create_reactor("log_flush_thread", iomgr::TIGHT_LOOP | iomgr::ADAPTIVE_LOOP, 1 /* num_fibers */,
                             [this, &ctx](bool is_started) {
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
                             [this, &ctx](bool is_started) {
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
        ctx->cv.wait(lk, [&ctx] { return (ctx->thread_cnt == 2); });
    }
}

nlohmann::json LogStoreService::dump_log_store(const log_dump_req& dump_req) {
    nlohmann::json json_dump{}; // create root object
    if (dump_req.log_store == nullptr) {
        for (auto& family : m_logstore_families) {
            json_dump[family->get_name()] = family->dump_log_store(dump_req);
        }
    } else {
        auto& family = dump_req.log_store->get_family();
        // must use operator= construction as copy construction results in error
        nlohmann::json val = family.dump_log_store(dump_req);
        json_dump[family.get_name()] = std::move(val);
    }
    return json_dump;
}

nlohmann::json LogStoreService::get_status(const int verbosity) const {
    nlohmann::json js;
    for (auto& l : m_logstore_families) {
        js[l->get_name()] = l->get_status(verbosity);
    }
    return js;
}

uint32_t LogStoreService::used_size() const {
    uint32_t sz{0};
    if (m_data_logdev_vdev) { sz += m_data_logdev_vdev->used_size(); }
    if (m_ctrl_logdev_vdev) { sz += m_ctrl_logdev_vdev->used_size(); }
    return sz;
}

uint32_t LogStoreService::total_size() const {
    uint32_t sz{0};
    if (m_data_logdev_vdev) { sz += m_data_logdev_vdev->size(); }
    if (m_ctrl_logdev_vdev) { sz += m_ctrl_logdev_vdev->size(); }
    return sz;
}

LogStoreServiceMetrics::LogStoreServiceMetrics() : sisl::MetricsGroup("LogStores", "AllLogStores") {
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
