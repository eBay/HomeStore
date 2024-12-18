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

#include "api/meta_interface.hpp"
#include "engine/common/homestore_assert.hpp"
#include "engine/homestore_base.hpp"
#include "log_dev.hpp"
#include "log_store.hpp"

namespace homestore {
SISL_LOGGING_DECL(logstore)

/////////////////////////////////////// HomeLogStoreMgr Section ///////////////////////////////////////
HomeLogStoreMgr& HomeLogStoreMgr::instance() {
    static HomeLogStoreMgr inst;
    return inst;
}

HomeLogStoreMgr::HomeLogStoreMgr() :
        m_logstore_families{std::make_unique< LogStoreFamily >(DATA_LOG_FAMILY_IDX),
                            std::make_unique< LogStoreFamily >(CTRL_LOG_FAMILY_IDX)} {}

void HomeLogStoreMgr::start(const bool format) {
    m_hb = HomeStoreBase::safe_instance();
    m_sobject = m_hb->sobject_mgr()->create_object(
        "module", "HomeLogStoreMgr", std::bind(&HomeLogStoreMgr::get_status, this, std::placeholders::_1));

    // Start the logstore families
    m_logstore_families[DATA_LOG_FAMILY_IDX]->start(format, m_hb->get_data_logdev_blkstore());
    m_logstore_families[CTRL_LOG_FAMILY_IDX]->start(format, m_hb->get_ctrl_logdev_blkstore());
    m_sobject->add_child(m_logstore_families[DATA_LOG_FAMILY_IDX]->sobject());
    m_sobject->add_child(m_logstore_families[CTRL_LOG_FAMILY_IDX]->sobject());

    // Create an truncate thread loop which handles truncation which does sync IO
    start_threads();
}

void HomeLogStoreMgr::stop() {
    device_truncate(nullptr, true, false);
    for (auto& f : m_logstore_families) {
        f->stop();
    }

    m_hb.reset();
}

void HomeLogStoreMgr::fake_reboot() {}

std::shared_ptr< HomeLogStore > HomeLogStoreMgr::create_new_log_store(const logstore_family_id_t family_id,
                                                                      const bool append_mode) {
    HS_REL_ASSERT_LT(family_id, num_log_families);
    COUNTER_INCREMENT(HomeLogStoreMgrSI().m_metrics, logstores_count, 1);
    return m_logstore_families[family_id]->create_new_log_store(append_mode);
}

void HomeLogStoreMgr::open_log_store(const logstore_family_id_t family_id, const logstore_id_t store_id,
                                     const bool append_mode, const log_store_opened_cb_t& on_open_cb) {
    HS_REL_ASSERT_LT(family_id, num_log_families);
    COUNTER_INCREMENT(m_metrics, logstores_count, 1);
    return m_logstore_families[family_id]->open_log_store(store_id, append_mode, on_open_cb);
}

void HomeLogStoreMgr::remove_log_store(const logstore_family_id_t family_id, const logstore_id_t store_id) {
    HS_REL_ASSERT_LT(family_id, num_log_families);
    m_logstore_families[family_id]->remove_log_store(store_id);
    COUNTER_DECREMENT(m_metrics, logstores_count, 1);
}

void HomeLogStoreMgr::device_truncate(const device_truncate_cb_t& cb, const bool wait_till_done, const bool dry_run) {
    const auto treq{std::make_shared< truncate_req >()};
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

void HomeLogStoreMgr::flush_if_needed() {
    for (auto& f : m_logstore_families) {
        f->logdev().flush_if_needed();
    }
}

void HomeLogStoreMgr::send_flush_msg() {
    iomanager.run_on(m_hb->get_hs_flush_thread(),
                     [this]([[maybe_unused]] const io_thread_addr_t addr) { flush_if_needed(); });
}

void HomeLogStoreMgr::start_threads() {
    struct Context {
        std::condition_variable cv;
        std::mutex mtx;
        size_t thread_cnt{0};
    };
    auto ctx{std::make_shared< Context >()};

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
        ctx->cv.wait(lk, [&ctx] { return (ctx->thread_cnt == 1); });
    }
}

LogStoreFamily* HomeLogStoreMgr::get_family(std::string family_name) {
    for (auto& l : m_logstore_families) {
        if (l->get_name() == family_name) { return l.get(); }
    }
    return nullptr;
}

nlohmann::json HomeLogStoreMgr::dump_log_store(const log_dump_req& dump_req) {
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

sisl::status_response HomeLogStoreMgr::get_status(const sisl::status_request& request) const { return {}; }

HomeLogStoreMgrMetrics::HomeLogStoreMgrMetrics() : sisl::MetricsGroup("LogStores", "AllLogStores") {
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
