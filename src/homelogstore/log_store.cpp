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

#include "engine/common/homestore_assert.hpp"
#include "engine/homestore_base.hpp"
#include "log_dev.hpp"

#include "log_store.hpp"

namespace homestore {
SISL_LOGGING_DECL(logstore)

#define THIS_LOGSTORE_LOG(level, msg, ...) HS_SUBMOD_LOG(level, logstore, , "store", m_fq_name, msg, __VA_ARGS__)
#define THIS_LOGSTORE_PERIODIC_LOG(level, msg, ...)                                                                    \
    HS_PERIODIC_DETAILED_LOG(level, logstore, "store", m_fq_name, , , msg, __VA_ARGS__)

HomeLogStore::HomeLogStore(LogStoreFamily& family, const logstore_id_t id, const bool append_mode,
                           const logstore_seq_num_t start_lsn) :
        m_store_id{id},
        m_logstore_family{family},
        m_logdev{family.logdev()},
        m_records{"HomeLogStoreRecords", start_lsn - 1},
        m_append_mode{append_mode},
        m_seq_num{start_lsn},
        m_fq_name{fmt::format("{}.{}", family.m_family_id, id)} {
    m_truncation_barriers.reserve(10000);
    m_safe_truncation_boundary.seq_num.store(start_lsn - 1, std::memory_order_release);
    auto hb = HomeStoreBase::safe_instance();
    m_sobject = hb->sobject_mgr()->create_object("HomeLogStore", "HomeLogStore_" + std::to_string(m_store_id),
                                                 std::bind(&HomeLogStore::get_status, this, std::placeholders::_1));
}

bool HomeLogStore::write_sync(const logstore_seq_num_t seq_num, const sisl::io_blob& b) {
    HS_LOG_ASSERT((!iomanager.am_i_worker_reactor()), "Sync can not be done in worker reactor thread");

    // these should be static so that they stay in scope in the lambda in case function ends before lambda completes
    struct Context {
        std::mutex write_mutex;
        std::condition_variable write_cv;
        bool write_done{false};
        bool ret{false};
    };
    auto ctx{std::make_shared< Context >()};
    this->write_async(seq_num, b, nullptr,
                      [seq_num, this, ctx](homestore::logstore_seq_num_t seq_num_cb,
                                           [[maybe_unused]] const sisl::io_blob& b, homestore::logdev_key ld_key,
                                           [[maybe_unused]] void* cb_ctx) {
                          HS_DBG_ASSERT((ld_key && seq_num == seq_num_cb), "Write_Async failed or corrupted");
                          {
                              std::unique_lock< std::mutex > lk{ctx->write_mutex};
                              ctx->write_done = true;
                              ctx->ret = true;
                          }
                          ctx->write_cv.notify_one();
                      });

    {
        std::unique_lock< std::mutex > lk{ctx->write_mutex};
        ctx->write_cv.wait(lk, [&ctx] { return ctx->write_done; });
    }

    return ctx->ret;
}

void HomeLogStore::write_async(logstore_req* const req, const log_req_comp_cb_t& cb) {
    HS_LOG_ASSERT((cb || m_comp_cb), "Expected either cb is not null or default cb registered");
    req->cb = (cb ? cb : m_comp_cb);
    req->start_time = Clock::now();

#ifndef NDEBUG
    const auto trunc_upto_lsn{truncated_upto()};
    if (req->seq_num <= trunc_upto_lsn) {
        THIS_LOGSTORE_LOG(ERROR, "Assert: Appending lsn={} lesser than or equal to truncated_upto_lsn={}", req->seq_num,
                          trunc_upto_lsn);
        HS_DBG_ASSERT(0, "Assertion");
    }
#endif

    m_records.create(req->seq_num);
    COUNTER_INCREMENT(HomeLogStoreMgrSI().m_metrics, logstore_append_count, 1);
    HISTOGRAM_OBSERVE(HomeLogStoreMgrSI().m_metrics, logstore_record_size, req->data.size);
    m_logdev.append_async(m_store_id, req->seq_num, req->data, static_cast< void* >(req));
}

void HomeLogStore::write_async(const logstore_seq_num_t seq_num, const sisl::io_blob& b, void* const cookie,
                               const log_write_comp_cb_t& cb) {
    // Form an internal request and issue the write
    auto* const req{logstore_req::make(this, seq_num, b, true /* is_write_req */)};
    req->cookie = cookie;

    write_async(req, [cb](logstore_req* req, logdev_key written_lkey) {
        if (cb) { cb(req->seq_num, req->data, written_lkey, req->cookie); }
        logstore_req::free(req);
    });
}

logstore_seq_num_t HomeLogStore::append_async(const sisl::io_blob& b, void* const cookie,
                                              const log_write_comp_cb_t& cb) {
    HS_DBG_ASSERT_EQ(m_append_mode, true, "append_async can be called only on append only mode");
    const auto seq_num{m_seq_num.fetch_add(1, std::memory_order_acq_rel)};
    write_async(seq_num, b, cookie, cb);
    return seq_num;
}

log_buffer HomeLogStore::read_sync(logstore_seq_num_t seq_num) {
    const auto record{m_records.at(seq_num)};
    const logdev_key ld_key{record.m_dev_key};
    if (!ld_key.is_valid()) {
        THIS_LOGSTORE_LOG(ERROR, "ld_key not valid {}", seq_num);
        throw std::out_of_range("key not valid");
    }

    const auto start_time{Clock::now()};
    THIS_LOGSTORE_LOG(TRACE, "Reading lsn={}:{} mapped to logdev_key=[idx={} dev_offset={}]", m_store_id, seq_num,
                      ld_key.idx, ld_key.dev_offset);
    COUNTER_INCREMENT(HomeLogStoreMgrSI().m_metrics, logstore_read_count, 1);
    serialized_log_record header;
    const auto b{m_logdev.read(ld_key, header)};
    HISTOGRAM_OBSERVE(HomeLogStoreMgrSI().m_metrics, logstore_read_latency, get_elapsed_time_us(start_time));
    return b;
}
#if 0
void HomeLogStore::read_async(logstore_req* req, const log_found_cb_t& cb) {
   HS_LOG_ASSERT( ((cb != nullptr) || (m_comp_cb != nullptr)),
             "Expected either cb is not null or default cb registered");
   auto record = m_records.at(req->seq_num);
   logdev_key ld_key = record.m_dev_key;
   req->cb = cb;
   m_logdev.read_async(ld_key, (void*)req);
}

void HomeLogStore::read_async(logstore_seq_num_t seq_num, void* cookie, const log_found_cb_t& cb) {
   auto record = m_records.at(seq_num);
   logdev_key ld_key = record.m_dev_key;
   sisl::io_blob b;
   auto* req = logstore_req::make(this, seq_num, &b, false /* not write */);
   read_async(req, [cookie, cb](logstore_seq_num_t seq_num, log_buffer log_buf, void* cookie) {
           cb(seq, log_buf, cookie);
           logstore_req::free(req);
           });
}
#endif

void HomeLogStore::on_write_completion(logstore_req* const req, const logdev_key ld_key) {
    // Upon completion, create the mapping between seq_num and log dev key
    m_records.update(req->seq_num, [&](logstore_record& rec) -> bool {
        rec.m_dev_key = ld_key;
        THIS_LOGSTORE_LOG(DEBUG, "Completed write of lsn {} logdev_key={}", req->seq_num, ld_key);
        return true;
    });
    // assert(flush_ld_key.idx >= m_last_flush_ldkey.idx);

    // Update the maximum lsn we have seen for this batch for this store, it is needed to create truncation barrier
    m_flush_batch_max_lsn = std::max(m_flush_batch_max_lsn, req->seq_num);
    HISTOGRAM_OBSERVE(HomeLogStoreMgrSI().m_metrics, logstore_append_latency, get_elapsed_time_us(req->start_time));
    (req->cb) ? req->cb(req, ld_key) : m_comp_cb(req, ld_key);
}

void HomeLogStore::on_read_completion(logstore_req* const req, const logdev_key ld_key) {
    (req->cb) ? req->cb(req, ld_key) : m_comp_cb(req, ld_key);
}

void HomeLogStore::on_log_found(const logstore_seq_num_t seq_num, const logdev_key ld_key,
                                const logdev_key flush_ld_key, const log_buffer buf) {
    THIS_LOGSTORE_LOG(DEBUG, "Found a log lsn={} logdev_key={}", seq_num, ld_key);

    // Create the mapping between seq_num and log dev key
    m_records.create_and_complete(seq_num, ld_key);
    atomic_update_max(m_seq_num, seq_num + 1, std::memory_order_acq_rel);
    m_flush_batch_max_lsn = std::max(m_flush_batch_max_lsn, seq_num);

    if (seq_num <= m_safe_truncation_boundary.seq_num.load(std::memory_order_acquire)) {
        THIS_LOGSTORE_LOG(TRACE, "Log lsn={} is already truncated on per device, ignoring", seq_num);
        return;
    }
    if (m_found_cb != nullptr) m_found_cb(seq_num, buf, nullptr);
}

void HomeLogStore::on_batch_completion(const logdev_key& flush_batch_ld_key) {
    assert(m_flush_batch_max_lsn != std::numeric_limits< logstore_seq_num_t >::min());

    // Create a new truncation barrier for this completion key
    if (m_truncation_barriers.size() && (m_truncation_barriers.back().seq_num >= m_flush_batch_max_lsn)) {
        m_truncation_barriers.back().ld_key = flush_batch_ld_key;
    } else {
        m_truncation_barriers.push_back({m_flush_batch_max_lsn, flush_batch_ld_key});
    }
    m_flush_batch_max_lsn = std::numeric_limits< logstore_seq_num_t >::min(); // Reset the flush batch for next batch.
}

void HomeLogStore::truncate(const logstore_seq_num_t upto_seq_num, const bool in_memory_truncate_only) {
#if 0
   if (!iomanager.is_io_thread()) {
       LOGDFATAL("Expected truncate to be called from iomanager thread. Ignoring truncate");
       return;
   }
#endif

#ifndef NDEBUG
    const auto s{m_safe_truncation_boundary.seq_num.load(std::memory_order_acquire)};
    // Don't check this if we don't know our truncation boundary. The call is made to inform us about
    // correct truncation point.
    if (s != -1) {
        HS_DBG_ASSERT_LE(upto_seq_num, get_contiguous_completed_seq_num(s),
                         "Logstore {} expects truncation to be contiguously completed", m_store_id);
    }
#endif

    // First try to block the flushing of logdevice and if we are successfully able to do, then
    auto shared_this{shared_from_this()};
    const bool locked_now{m_logdev.try_lock_flush([shared_this, upto_seq_num, in_memory_truncate_only]() {
        shared_this->do_truncate(upto_seq_num);
        if (!in_memory_truncate_only) {
            [[maybe_unused]] const auto key{shared_this->get_family().do_device_truncate()};
        }
    })};

    if (locked_now) { m_logdev.unlock_flush(); }
}

// NOTE: This method assumes the flush lock is already acquired by the caller
void HomeLogStore::do_truncate(const logstore_seq_num_t upto_seq_num) {
    m_records.truncate(upto_seq_num);
    m_safe_truncation_boundary.seq_num.store(upto_seq_num, std::memory_order_release);

    // Need to update the superblock with meta, we don't persist yet, will be done as part of log dev truncation
    m_logdev.update_store_superblk(m_store_id, logstore_superblk{upto_seq_num + 1}, false /* persist_now */);

    const int ind{search_max_le(upto_seq_num)};
    if (ind < 0) {
        // m_safe_truncation_boundary.pending_dev_truncation = false;
        THIS_LOGSTORE_PERIODIC_LOG(DEBUG,
                                   "Truncate upto lsn={}, possibly already truncated so ignoring. Current safe device "
                                   "truncation barrier=<log_id={}>",
                                   upto_seq_num, m_safe_truncation_boundary.ld_key);
        return;
    }

    THIS_LOGSTORE_PERIODIC_LOG(
        DEBUG, "Truncate upto lsn={}, nearest safe device truncation barrier <ind={} log_id={}>, is_last_barrier={}",
        upto_seq_num, ind, m_truncation_barriers[ind].ld_key,
        (ind == static_cast< int >(m_truncation_barriers.size() - 1)));

    m_safe_truncation_boundary.ld_key = m_truncation_barriers[ind].ld_key;
    m_safe_truncation_boundary.pending_dev_truncation = true;

    m_truncation_barriers.erase(m_truncation_barriers.begin(), m_truncation_barriers.begin() + ind + 1);
}

// NOTE: This method assumes the flush lock is already acquired by the caller
const truncation_info& HomeLogStore::pre_device_truncation() {
    m_safe_truncation_boundary.active_writes_not_part_of_truncation = (m_truncation_barriers.size() > 0);
    return m_safe_truncation_boundary;
}

// NOTE: This method assumes the flush lock is already acquired by the caller
void HomeLogStore::post_device_truncation(const logdev_key& trunc_upto_loc) {
    if (trunc_upto_loc.idx >= m_safe_truncation_boundary.ld_key.idx) {
        // This method is expected to be called always with this
        m_safe_truncation_boundary.pending_dev_truncation = false;
        m_safe_truncation_boundary.ld_key = trunc_upto_loc;
    } else {
        HS_REL_ASSERT(0,
                      "We expect post_device_truncation to be called only for logstores which has min of all "
                      "truncation boundaries");
    }
}

void HomeLogStore::fill_gap(const logstore_seq_num_t seq_num) {
    HS_DBG_ASSERT_EQ(m_records.status(seq_num).is_hole, true, "Attempted to fill gap lsn={} which has valid data",
                     seq_num);

    logdev_key empty_ld_key;
    m_records.create_and_complete(seq_num, empty_ld_key);
}

int HomeLogStore::search_max_le(const logstore_seq_num_t input_sn) {
    int mid{0};
    int start{-1};
    int end{static_cast< int >(m_truncation_barriers.size())};

    while ((end - start) > 1) {
        mid = start + (end - start) / 2;
        const auto& mid_entry{m_truncation_barriers[mid]};

        if (mid_entry.seq_num == input_sn) {
            return mid;
        } else if (mid_entry.seq_num > input_sn) {
            end = mid;
        } else {
            start = mid;
        }
    }

    return (end - 1);
}

nlohmann::json HomeLogStore::dump_log_store(const log_dump_req& dump_req) {
    nlohmann::json json_dump{}; // create root object
    const auto trunc_upto{this->truncated_upto()};
    std::remove_const_t< decltype(trunc_upto) > idx{trunc_upto + 1};
    if (dump_req.start_seq_num) idx = dump_req.start_seq_num;

    logstore_seq_num_t batch_size;
    if (dump_req.batch_size) {
        batch_size = dump_req.batch_size;
    } else {
        if (dump_req.end_seq_num) {
            batch_size = dump_req.end_seq_num - idx + 1;
        } else {
            batch_size = std::numeric_limits< int64_t >::max() - idx;
        }
    }

    // must use move operator= operation instead of move copy constructor
    nlohmann::json json_records = nlohmann::json::array();
    bool proceed{false};
    m_records.foreach_completed(
        idx,
        [&batch_size, &json_dump, &json_records, &dump_req, &proceed,
         this](decltype(idx) cur_idx, decltype(idx) max_idx, const homestore::logstore_record& record) -> bool {
            // do a sync read
            // must use move operator= operation instead of move copy constructor
            nlohmann::json json_val = nlohmann::json::object();
            serialized_log_record record_header;

            const auto log_buffer{m_logdev.read(record.m_dev_key, record_header)};

            try {
                json_val["size"] = static_cast< uint32_t >(record_header.size);
                json_val["offset"] = static_cast< uint32_t >(record_header.offset);
                json_val["is_inlined"] = static_cast< uint32_t >(record_header.get_inlined());
                json_val["store_seq_num"] = static_cast< uint64_t >(record_header.store_seq_num);
                json_val["store_id"] = static_cast< logstore_id_t >(record_header.store_id);
                if (dump_req.verbosity_level == homestore::log_dump_verbosity::CONTENT) {
                    json_val["content"] = hs_utils::encodeBase64(log_buffer);
                }
            } catch (const std::exception& ex) { THIS_LOGSTORE_LOG(ERROR, "Exception in json dump- {}", ex.what()); }

            json_records.emplace_back(std::move(json_val));
            decltype(idx) end_idx{std::min(max_idx, dump_req.end_seq_num)};
            proceed = (cur_idx < end_idx && --batch_size > 0) ? true : false;
            // User can provide either the end_seq_num or batch_size in the request.
            if (cur_idx < end_idx && !batch_size) { json_dump["next_cursor"] = std::to_string(cur_idx + 1); }
            return proceed;
        });

    json_dump["log_records"] = std::move(json_records);
    return json_dump;
}

void HomeLogStore::foreach (const int64_t start_idx, const std::function< bool(logstore_seq_num_t, log_buffer) >& cb) {

    m_records.foreach_completed(start_idx,
                                [&](long int cur_idx, long int max_idx, homestore::logstore_record& record) -> bool {
                                    // do a sync read
                                    serialized_log_record header;

                                    auto log_buf{m_logdev.read(record.m_dev_key, header)};
                                    return cb(cur_idx, log_buf);
                                });
}

logstore_seq_num_t HomeLogStore::get_contiguous_issued_seq_num(const logstore_seq_num_t from) const {
    return (logstore_seq_num_t)m_records.active_upto(from + 1);
}

logstore_seq_num_t HomeLogStore::get_contiguous_completed_seq_num(const logstore_seq_num_t from) const {
    return (logstore_seq_num_t)m_records.completed_upto(from + 1);
}

sisl::status_response HomeLogStore::get_status(const sisl::status_request& request) {
    sisl::status_response response;
    if (request.json.contains("type") && request.json["type"] == "logstore_record") {
        log_dump_req dump_req{};
        if (!request.next_cursor.empty()) { dump_req.start_seq_num = std::stoull(request.next_cursor); }
        dump_req.batch_size = request.batch_size;
        dump_req.end_seq_num = std::numeric_limits< int64_t >::max() - 1;
        homestore::log_dump_verbosity verbose_level = homestore::log_dump_verbosity::HEADER;
        if (request.json.contains("log_content")) { verbose_level = homestore::log_dump_verbosity::CONTENT; }
        dump_req.verbosity_level = verbose_level;
        response.json.update(dump_log_store(dump_req));
        return response;
    }

    response.json["store_id"] = this->m_store_id;
    response.json["append_mode"] = m_append_mode;
    response.json["highest_lsn"] = m_seq_num.load(std::memory_order_relaxed);
    response.json["max_lsn_in_prev_flush_batch"] = m_flush_batch_max_lsn;
    response.json["truncated_upto_logdev_key"] = m_safe_truncation_boundary.ld_key.to_string();
    response.json["truncated_upto_lsn"] = m_safe_truncation_boundary.seq_num.load(std::memory_order_relaxed);
    response.json["truncation_pending_on_device?"] = m_safe_truncation_boundary.pending_dev_truncation;
    response.json["truncation_parallel_to_writes?"] = m_safe_truncation_boundary.active_writes_not_part_of_truncation;
    response.json["logstore_records"] = m_records.get_status(request.verbose_level);
    response.json["logstore_sb_first_lsn"] = m_logdev.m_logdev_meta.store_superblk(m_store_id).m_first_seq_num;

    return response;
}

logstore_superblk logstore_superblk::default_value() { return logstore_superblk{-1}; }
void logstore_superblk::init(logstore_superblk& meta) { meta.m_first_seq_num = 0; }
void logstore_superblk::clear(logstore_superblk& meta) { meta.m_first_seq_num = -1; }
bool logstore_superblk::is_valid(const logstore_superblk& meta) { return meta.m_first_seq_num >= 0; }

} // namespace homestore
