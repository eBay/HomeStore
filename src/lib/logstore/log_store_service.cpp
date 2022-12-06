#include <iterator>
#include <string>

#include <fmt/format.h>
#include <iomgr/iomgr.hpp>
#include <sisl/utility/thread_factory.hpp>

#include <meta_service.hpp>
#include <logstore_service.hpp>
#include <homestore.hpp>

#include "common/homestore_assert.hpp"
#include "common/homestore_status_mgr.hpp"
#include "device/device.h"
#include "device/journal_vdev.hpp"
#include "device/physical_dev.hpp"
#include "log_store_family.hpp"
#include "log_dev.hpp"
#include "log_store.hpp"

namespace homestore {
SISL_LOGGING_DECL(logstore)

LogStoreService& logstore_service() { return hs()->logstore_service(); }

/////////////////////////////////////// LogStoreService Section ///////////////////////////////////////
LogStoreService::LogStoreService() :
        m_logstore_families{std::make_unique< LogStoreFamily >(DATA_LOG_FAMILY_IDX),
                            std::make_unique< LogStoreFamily >(CTRL_LOG_FAMILY_IDX)} {
    meta_service().register_handler(
        data_log_family()->metablk_name(),
        [this](meta_blk* mblk, sisl::byte_view buf, size_t size) {
            m_logstore_families[DATA_LOG_FAMILY_IDX]->meta_blk_found_cb(mblk, std::move(buf), size);
        },
        nullptr);

    meta_service().register_handler(
        ctrl_log_family()->metablk_name(),
        [this](meta_blk* mblk, sisl::byte_view buf, size_t size) {
            m_logstore_families[CTRL_LOG_FAMILY_IDX]->meta_blk_found_cb(mblk, std::move(buf), size);
        },
        nullptr);
}

void LogStoreService::create_vdev(uint64_t size, logstore_family_id_t family, vdev_io_comp_cb_t format_cb) {
    const auto atomic_page_size = hs()->device_mgr()->atomic_page_size({PhysicalDevGroup::FAST});

    struct blkstore_blob blob;
    if (family == DATA_LOG_FAMILY_IDX) {
        blob.type = blkstore_type::DATA_LOGDEV_STORE;
        m_data_logdev_vdev = std::make_unique< JournalVirtualDev >(
            hs()->device_mgr(), "data_logdev", PhysicalDevGroup::FAST, size, 0 /* nmirror */, true /* is_stripe */,
            atomic_page_size /* blk_size */, (char*)&blob, sizeof(blkstore_blob), true /* auto_recovery */);
        m_data_logdev_vdev->async_format(std::move(format_cb));
    } else {
        blob.type = blkstore_type::CTRL_LOGDEV_STORE;
        m_ctrl_logdev_vdev = std::make_unique< JournalVirtualDev >(
            hs()->device_mgr(), "ctrl_logdev", PhysicalDevGroup::FAST, size, 0 /* nmirror */, true /* is_stripe */,
            atomic_page_size /* blk_size */, (char*)&blob, sizeof(blkstore_blob), true /* auto_recovery */);
        m_ctrl_logdev_vdev->async_format(std::move(format_cb));
    }
}

bool LogStoreService::open_vdev(vdev_info_block* vb, logstore_family_id_t family) {
    bool ret{true};
    if (family == DATA_LOG_FAMILY_IDX) {
        m_data_logdev_vdev = std::make_unique< JournalVirtualDev >(hs()->device_mgr(), "data_logdev", vb,
                                                                   PhysicalDevGroup::FAST, vb->is_failed(), false);
    } else {
        m_ctrl_logdev_vdev = std::make_unique< JournalVirtualDev >(hs()->device_mgr(), "ctrl_logdev", vb,
                                                                   PhysicalDevGroup::FAST, vb->is_failed(), false);
    }

    if (vb->is_failed()) {
        LOGERROR("{} vdev is in failed state", vb->get_vdev_id());
        ret = false;
    }
    return ret;
}

void LogStoreService::start(const bool format) {
    // hs()->status_mgr()->register_status_cb("LogStore", bind_this(LogStoreService::get_status, 1));

    // Start the logstore families
    m_logstore_families[DATA_LOG_FAMILY_IDX]->start(format, m_data_logdev_vdev.get());
    m_logstore_families[CTRL_LOG_FAMILY_IDX]->start(format, m_ctrl_logdev_vdev.get());

    // Create an truncate thread loop which handles truncation which does sync IO
    start_threads();
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
        l->device_truncate_in_user_reactor(treq);
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

void LogStoreService::send_flush_msg() {
    iomanager.run_on(m_flush_thread, [this]([[maybe_unused]] const io_thread_addr_t addr) { flush_if_needed(); });
}

void LogStoreService::start_threads() {
    struct Context {
        std::condition_variable cv;
        std::mutex mtx;
        size_t thread_cnt{0};
    };
    auto ctx = std::make_shared< Context >();

    m_flush_thread = nullptr;
    iomanager.create_reactor("log_flush_thread", TIGHT_LOOP | ADAPTIVE_LOOP, [this, &ctx](bool is_started) {
        if (is_started) {
            m_flush_thread = iomanager.iothread_self();
            {
                std::unique_lock< std::mutex > lk{ctx->mtx};
                ++(ctx->thread_cnt);
            }
            ctx->cv.notify_one();
        }
    });

    m_truncate_thread = nullptr;
    iomanager.create_reactor("logstore_truncater", INTERRUPT_LOOP, [this, &ctx](bool is_started) {
        if (is_started) {
            m_truncate_thread = iomanager.iothread_self();
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
            json_dump[family->metablk_name()] = family->dump_log_store(dump_req);
        }
    } else {
        auto& family = dump_req.log_store->get_family();
        // must use operator= construction as copy construction results in error
        nlohmann::json val = family.dump_log_store(dump_req);
        json_dump[family.metablk_name()] = std::move(val);
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
