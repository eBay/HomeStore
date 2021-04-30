#include <iterator>
#include <string>

#include <fmt/format.h>
#include <iomgr/iomgr.hpp>
#include <utility/thread_factory.hpp>

#include "engine/common/homestore_assert.hpp"

#include "log_dev.hpp"

#include "log_store.hpp"

namespace homestore {
SDS_LOGGING_DECL(logstore)

#define THIS_LOGSTORE_LOG(level, msg, ...) HS_SUBMOD_LOG(level, logstore, , "store", m_store_id, msg, __VA_ARGS__)
#define THIS_LOGSTORE_PERIODIC_LOG(level, msg, ...)                                                                    \
    HS_PERIODIC_DETAILED_LOG(level, logstore, "store", m_store_id, , , msg, __VA_ARGS__)

void HomeLogStoreMgr::meta_blk_found_cb(meta_blk* const mblk, const sisl::byte_view buf, const size_t size) {
    HomeLogStoreMgr::instance().m_log_dev.meta_blk_found(mblk, buf, size);
}

/////////////////////////////////////// HomeLogStoreMgr Section ///////////////////////////////////////
HomeLogStoreMgr& HomeLogStoreMgr::instance() {
    static HomeLogStoreMgr inst;
    return inst;
}

HomeLogStoreMgr::HomeLogStoreMgr() {
    // REGISTER_METABLK_SUBSYSTEM(log_dev, "LOG_DEV", HomeLogStoreMgr::meta_blk_found_cb, nullptr)
    MetaBlkMgrSI()->register_handler("LOG_DEV", HomeLogStoreMgr::meta_blk_found_cb, nullptr);
}

void HomeLogStoreMgr::start(const bool format) {
    m_log_dev.register_store_found_cb(bind_this(HomeLogStoreMgr::on_log_store_found, 2));
    m_log_dev.register_append_cb_with_flush_lock(bind_this(HomeLogStoreMgr::on_io_completion_with_flush_lock, 5));
    m_log_dev.register_append_cb_with_flush_unlock(bind_this(HomeLogStoreMgr::on_io_completion_with_flush_unlock, 5));
    m_log_dev.register_logfound_cb(bind_this(HomeLogStoreMgr::on_logfound, 4));

    // Start the logdev
    m_log_dev.start(format);

    // Create an truncate thread loop which handles truncation which does sync IO
    start_truncate_thread();

    // If there are any unopened storeids found, loop and check again if they are indeed open later. Unopened log store
    // could be possible if the ids are deleted, but it is delayed to remove from store id reserver. In that case,
    // do the remove from store id reserver now.
    // TODO: At present we are assuming all unopened store ids could be removed. In future have a callback to this
    // start routine, which takes the list of unopened store ids and can return a new set, which can be removed.
    m_id_logstore_map.withWLock([&](auto& m) {
        for (auto it{std::begin(m_unopened_store_id)}; it != std::end(m_unopened_store_id);) {
            if (m.find(*it) == m.end()) {
                // Not opened even on second time check, simply unreserve id
                m_log_dev.unreserve_store_id(*it);
            }
            it = m_unopened_store_id.erase(it);
        }

        // Also call the logstore to inform that start/replay is completed.
        if (!format) {
            for (auto& p : m) {
                auto& lstore{p.second.m_log_store};
                if (lstore && lstore->m_replay_done_cb) {
                    lstore->m_replay_done_cb(lstore, lstore->m_seq_num.load(std::memory_order_acquire) - 1);
                }
            }
        }
    });
}

void HomeLogStoreMgr::stop() {
    m_id_logstore_map.wlock()->clear();
    m_log_dev.stop();
}

std::shared_ptr< HomeLogStore > HomeLogStoreMgr::create_new_log_store(const bool append_mode) {
    const auto store_id{m_log_dev.reserve_store_id()};
    std::shared_ptr< HomeLogStore > lstore;
    lstore = std::make_shared< HomeLogStore >(store_id, append_mode, 0);

    auto m{m_id_logstore_map.wlock()};
    const auto it{m->find(store_id)};
    HS_RELEASE_ASSERT((it == m->end()), "store_id {} already exists", store_id);

    m->insert(std::make_pair<>(store_id, logstore_info_t{lstore, nullptr, append_mode}));
    COUNTER_INCREMENT(m_metrics, logstores_count, 1);
    return lstore;
}

void HomeLogStoreMgr::open_log_store(const logstore_id_t store_id, const bool append_mode,
                                     const log_store_opened_cb_t& on_open_cb) {
    auto m{m_id_logstore_map.wlock()};
    COUNTER_INCREMENT(m_metrics, logstores_count, 1);
    const auto it{m->find(store_id)};
    HS_RELEASE_ASSERT((it == m->end()), "store_id {} already exists", store_id);
    m->insert(std::make_pair<>(store_id, logstore_info_t{nullptr, on_open_cb, append_mode}));
}

void HomeLogStoreMgr::remove_log_store(const logstore_id_t store_id) {
    LOGINFO("Removing log store id {}", store_id);
    m_id_logstore_map.wlock()->erase(store_id);
    m_log_dev.unreserve_store_id(store_id);
    COUNTER_DECREMENT(m_metrics, logstores_count, 1);
}

void HomeLogStoreMgr::start_truncate_thread() {
    // these should be thread local so that they stay in scope in the lambda in case function ends
    // before lambda completes
    static thread_local std::condition_variable cv;
    static thread_local std::mutex mtx;

    m_truncate_thread = nullptr;
    auto sthread = sisl::named_thread("logstore_truncater", [this, &tl_cv = cv, &tl_mtx = mtx]() {
        iomanager.run_io_loop(false, nullptr, ([this, &tl_cv, &tl_mtx](bool is_started) {
                                  if (is_started) {
                                      std::unique_lock< std::mutex > lk{tl_mtx};
                                      m_truncate_thread = iomanager.iothread_self();
                                      tl_cv.notify_one();
                                  }
                              }));
    });
    {
        std::unique_lock< std::mutex > lk{mtx};
        cv.wait(lk, [this] { return (m_truncate_thread != nullptr); });
    }
    sthread.detach();
}

void HomeLogStoreMgr::on_log_store_found(const logstore_id_t store_id, const logstore_meta& meta) {
    auto m{m_id_logstore_map.rlock()};
    const auto it{m->find(store_id)};
    if (it == m->end()) {
        LOGERROR("Store Id {} found but not opened yet, ignoring the store", store_id);
        m_unopened_store_id.insert(store_id);
        return;
    }

    LOGINFO("Found a logstore store_id={} with start seq_num={}, Creating a new HomeLogStore instance", store_id,
            meta.m_first_seq_num);
    auto& l_info{const_cast< logstore_info_t& >(it->second)};
    l_info.m_log_store = std::make_shared< HomeLogStore >(store_id, l_info.append_mode, meta.m_first_seq_num);
    if (l_info.m_on_log_store_opened) l_info.m_on_log_store_opened(l_info.m_log_store);
}

static thread_local std::vector< HomeLogStore* > s_cur_flush_batch_stores;

void HomeLogStoreMgr::on_io_completion_with_flush_unlock(const logstore_id_t id, const logdev_key ld_key,
                                                         const logdev_key flush_ld_key,
                                                         const uint32_t nremaining_in_batch, void* const ctx) {
    auto* const req{static_cast< logstore_req* >(ctx)};
    HomeLogStore* const log_store{req->log_store};

    if (req->is_write) { log_store->on_write_completion_with_flush_unlock(req, ld_key); }
}

void HomeLogStoreMgr::on_io_completion_with_flush_lock(const logstore_id_t id, const logdev_key ld_key,
                                                       const logdev_key flush_ld_key,
                                                       const uint32_t nremaining_in_batch, void* const ctx) {
    auto* const req{static_cast< logstore_req* >(ctx)};
    HomeLogStore* const log_store{req->log_store};

    if (req->is_write) {
        const auto it{m_last_flush_info.find(id)};
        if ((it == std::end(m_last_flush_info)) || (it->second != flush_ld_key.idx)) {
            // first time completion in this batch for a given store_id
            m_last_flush_info.insert_or_assign(id, flush_ld_key.idx);
            s_cur_flush_batch_stores.push_back(log_store);
        }

        HS_LOG_ASSERT_EQ(log_store->m_store_id, id, "Expecting store id in log store and io completion to match");
        log_store->on_write_completion_with_flush_lock(req, ld_key);

        if (nremaining_in_batch == 0) {
            // This batch is completed, call all log stores participated in this batch about the end of batch
            HS_LOG_ASSERT_GT(s_cur_flush_batch_stores.size(), 0U, "Expecting one store to be flushed in batch");
            for (auto& l : s_cur_flush_batch_stores) {
                l->on_batch_completion(flush_ld_key);
            }
            s_cur_flush_batch_stores.clear();
        }
    } else {
        log_store->on_read_completion(req, ld_key);
    }
}

void HomeLogStoreMgr::on_logfound(const logstore_id_t id, const logstore_seq_num_t seq_num, const logdev_key ld_key,
                                  const log_buffer buf) {
    auto it{m_id_logstore_map.rlock()->find(id)};
    auto& log_store{it->second.m_log_store};
    if (it->second.m_log_store) { log_store->on_log_found(seq_num, ld_key, buf); }
}

void HomeLogStoreMgr::device_truncate(const device_truncate_cb_t& cb, const bool wait_till_done, const bool dry_run) {
    const auto treq{std::make_shared< truncate_req >()};
    treq->wait_till_done = wait_till_done;
    treq->dry_run = dry_run;
    treq->cb = cb;

    device_truncate_in_user_reactor(treq);

    if (treq->wait_till_done) {
        std::unique_lock< std::mutex > lk{treq->mtx};
        treq->cv.wait(lk, [&] { return treq->trunc_done; });
    }
}

void HomeLogStoreMgr::device_truncate_in_user_reactor(const std::shared_ptr< truncate_req >& treq) {
    const bool locked_now{m_log_dev.try_lock_flush([this, treq]() {
        if (iomanager.am_i_tight_loop_reactor()) {
            iomanager.run_on(m_truncate_thread, [this, treq]([[maybe_unused]] io_thread_addr_t addr) {
                device_truncate_in_user_reactor(treq);
            });
        } else {
            const logdev_key trunc_upto{do_device_truncate(treq->dry_run)};
            if (treq->cb) { treq->cb(trunc_upto); }

            if (treq->wait_till_done) {
                {
                    std::lock_guard< std::mutex > lk{treq->mtx};
                    treq->trunc_done = true;
                }
                treq->cv.notify_one();
            }
        }
    })};
    if (locked_now) { m_log_dev.unlock_flush(); }
}

logdev_key HomeLogStoreMgr::do_device_truncate(const bool dry_run) {
    static thread_local std::vector< std::shared_ptr< HomeLogStore > > m_min_trunc_stores;
    static thread_local std::vector< std::shared_ptr< HomeLogStore > > m_non_participating_stores;

    m_min_trunc_stores.clear();
    m_non_participating_stores.clear();
    logdev_key min_safe_ld_key{logdev_key::out_of_bound_ld_key()};

    std::string dbg_str{"Format [store_id:trunc_lsn:logidx:dev_trunc_pending?:active_writes_in_trucate?] "};
    m_id_logstore_map.withRLock([this, &min_safe_ld_key, &dbg_str](auto& id_logstore_map) {
        for (auto& id_logstore : id_logstore_map) {
            auto& store_ptr{id_logstore.second.m_log_store};
            const auto& trunc_info{store_ptr->pre_device_truncation()};

            if (!trunc_info.pending_dev_truncation && !trunc_info.active_writes_not_part_of_truncation) {
                // This log store neither has any pending device truncation nor active logstore io going on for now.
                // Ignore this log store for min safe boundary calculation.
                fmt::format_to(std::back_inserter(dbg_str), "[{}:None] ", store_ptr->get_store_id());
                m_non_participating_stores.push_back(store_ptr);
                continue;
            }

            fmt::format_to(std::back_inserter(dbg_str), "[{}:{}:{}:{}:{}] ", store_ptr->get_store_id(),
                           trunc_info.seq_num, trunc_info.ld_key.idx, trunc_info.pending_dev_truncation,
                           trunc_info.active_writes_not_part_of_truncation);
            if (trunc_info.ld_key.idx > min_safe_ld_key.idx) { continue; }

            if (trunc_info.ld_key.idx < min_safe_ld_key.idx) {
                // New minimum safe l entry
                min_safe_ld_key = trunc_info.ld_key;
                m_min_trunc_stores.clear();
            }
            m_min_trunc_stores.push_back(store_ptr);
        }
    });

    if ((min_safe_ld_key == logdev_key::out_of_bound_ld_key()) || (min_safe_ld_key.idx < 0)) {
        HS_PERIODIC_LOG(INFO, logstore,
                        "No log store append on any log stores, skipping device truncation, all_logstore_info:<{}>",
                        dbg_str);
        return min_safe_ld_key;
    } else {
        HS_PERIODIC_LOG(INFO, logstore, "LogDevice truncate, all_logstore_info:<{}> safe log dev key to truncate={}",
                        dbg_str, min_safe_ld_key);

        // We call post device truncation only to the log stores whose prepared truncation points are fully truncated or
        // to stores which didn't particpate in this device truncation.
        for (auto& store_ptr : m_min_trunc_stores) {
            store_ptr->post_device_truncation(min_safe_ld_key);
        }
        for (auto& store_ptr : m_non_participating_stores) {
            store_ptr->post_device_truncation(min_safe_ld_key);
        }
        m_min_trunc_stores.clear(); // Not clearing here, would cause a shared_ptr ref holding.
        m_non_participating_stores.clear();
    }
    // Got the safest log id to truncate and actually truncate upto the safe log idx to the log device
    if (!dry_run) {
        const auto num_records_to_truncate{m_log_dev.truncate(min_safe_ld_key)};
        if (num_records_to_truncate == 0) min_safe_ld_key = logdev_key::out_of_bound_ld_key();
    }
    return min_safe_ld_key;
}

nlohmann::json HomeLogStoreMgr::dump_log_store(const log_dump_req& dump_req) {
    nlohmann::json json_dump{}; // create root object
    if (dump_req.log_store == nullptr) {
        m_id_logstore_map.withRLock([&](auto& id_logstore_map) {
            for (auto& id_logstore : id_logstore_map) {
                auto store_ptr{id_logstore.second.m_log_store};
                const std::string id{std::to_string(store_ptr->get_store_id())};
                // must use operator= construction as copy construction results in error
                nlohmann::json val = store_ptr->dump_log_store(dump_req);
                json_dump[id] = std::move(val);
            }
        });
    } else {
        const std::string id{std::to_string(dump_req.log_store->get_store_id())};
        // must use operator= construction as copy construction results in error
        nlohmann::json val = dump_req.log_store->dump_log_store(dump_req);
        json_dump[id] = std::move(val);
    }
    return json_dump;
}

LogDev& HomeLogStoreMgr::logdev() { return HomeLogStoreMgr::instance().m_log_dev; }

/////////////////////////////////////// HomeLogStore Section ///////////////////////////////////////
HomeLogStore::HomeLogStore(const logstore_id_t id, const bool append_mode, const logstore_seq_num_t start_lsn) :
        m_store_id{id},
        m_records{"HomeLogStoreRecords", start_lsn - 1},
        m_append_mode{append_mode},
        m_seq_num{start_lsn} {
    m_truncation_barriers.reserve(10000);
    m_safe_truncation_boundary.seq_num.store(start_lsn - 1, std::memory_order_release);
}

bool HomeLogStore::write_sync(const logstore_seq_num_t seq_num, const sisl::io_blob& b) {
    HS_ASSERT(LOGMSG, (!iomanager.am_i_worker_reactor()), "Sync can not be done in worker reactor thread");

    // these should be static so that they stay in scope in the lambda in case function ends before lambda completes
    static thread_local std::mutex write_mutex;
    static thread_local std::condition_variable write_cv;
    static thread_local bool write_done;
    static thread_local bool ret;

    write_done = false;
    ret = false;
    this->write_async(seq_num, b, nullptr,
                      [seq_num, this, &tl_write_mutex = write_mutex, &tl_write_cv = write_cv,
                       &tl_write_done = write_done, &tl_ret = ret](homestore::logstore_seq_num_t seq_num_cb,
                                                                   const sisl::io_blob& b, homestore::logdev_key ld_key,
                                                                   void* ctx) {
                          HS_DEBUG_ASSERT((ld_key && seq_num == seq_num_cb), "Write_Async failed or corrupted");
                          {
                              std::unique_lock< std::mutex > lk{tl_write_mutex};
                              tl_write_done = true;
                              tl_ret = true;
                          }
                          tl_write_cv.notify_one();
                      });

    {
        std::unique_lock< std::mutex > lk{write_mutex};
        write_cv.wait(lk, [] { return write_done; });
    }

    return ret;
}

void HomeLogStore::write_async(logstore_req* const req, const log_req_comp_cb_t& cb) {
    HS_ASSERT(LOGMSG, (cb || m_comp_cb), "Expected either cb is not null or default cb registered");
    req->cb = (cb ? cb : m_comp_cb);
    req->start_time = Clock::now();

#ifndef NDEBUG
    const auto trunc_upto_lsn{truncated_upto()};
    if (req->seq_num <= trunc_upto_lsn) {
        THIS_LOGSTORE_LOG(ERROR, "Assert: Appending lsn={} lesser than or equal to truncated_upto_lsn={}", req->seq_num,
                          trunc_upto_lsn);
        HS_DEBUG_ASSERT(0, "Assertion");
    }
#endif

    m_records.create(req->seq_num);
    COUNTER_INCREMENT(home_log_store_mgr.m_metrics, logstore_append_count, 1);
    HISTOGRAM_OBSERVE(home_log_store_mgr.m_metrics, logstore_record_size, req->data.size);
    [[maybe_unused]] const auto logid{
        HomeLogStoreMgr::logdev().append_async(m_store_id, req->seq_num, req->data, static_cast< void* >(req))};
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
    HS_DEBUG_ASSERT_EQ(m_append_mode, true, "append_async can be called only on append only mode");
    const auto seq_num{m_seq_num.fetch_add(1, std::memory_order_acq_rel)};
    write_async(seq_num, b, cookie, cb);
    return seq_num;
}

log_buffer HomeLogStore::read_sync(logstore_seq_num_t seq_num) {
    const auto record{m_records.at(seq_num)};
    const logdev_key ld_key{record.m_dev_key};
    if (ld_key.idx == -1) { return log_buffer(); }

    const auto start_time{Clock::now()};
    THIS_LOGSTORE_LOG(TRACE, "Reading lsn={}:{} mapped to logdev_key=[idx={} dev_offset={}]", m_store_id, seq_num,
                      ld_key.idx, ld_key.dev_offset);
    COUNTER_INCREMENT(home_log_store_mgr.m_metrics, logstore_read_count, 1);
    serialized_log_record header;
    const auto b{HomeLogStoreMgr::logdev().read(ld_key, header)};
    HISTOGRAM_OBSERVE(home_log_store_mgr.m_metrics, logstore_read_latency, get_elapsed_time_us(start_time));
    return b;
}
#if 0
void HomeLogStore::read_async(logstore_req* req, const log_found_cb_t& cb) {
    HS_ASSERT(LOGMSG, ((cb != nullptr) || (m_comp_cb != nullptr)),
              "Expected either cb is not null or default cb registered");
    auto record = m_records.at(req->seq_num);
    logdev_key ld_key = record.m_dev_key;
    req->cb = cb;
    HomeLogStoreMgr::logdev().read_async(ld_key, (void*)req);
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

void HomeLogStore::on_write_completion_with_flush_lock(logstore_req* const req, const logdev_key ld_key) {
    // Upon completion, create the mapping between seq_num and log dev key
    m_records.update(req->seq_num, [&](logstore_record& rec) -> bool {
        rec.m_dev_key = ld_key;
        THIS_LOGSTORE_LOG(DEBUG, "Completed write of lsn {} logdev_key={}", req->seq_num, ld_key);
        return true;
    });
    // assert(flush_ld_key.idx >= m_last_flush_ldkey.idx);

    // Update the maximum lsn we have seen for this batch for this store, it is needed to create truncation barrier
    m_flush_batch_max_lsn = std::max(m_flush_batch_max_lsn, req->seq_num);
}

void HomeLogStore::on_write_completion_with_flush_unlock(logstore_req* const req, const logdev_key ld_key) {
    HISTOGRAM_OBSERVE(home_log_store_mgr.m_metrics, logstore_append_latency, get_elapsed_time_us(req->start_time));
    (req->cb) ? req->cb(req, ld_key) : m_comp_cb(req, ld_key);
}

void HomeLogStore::on_read_completion(logstore_req* const req, const logdev_key ld_key) {
    (req->cb) ? req->cb(req, ld_key) : m_comp_cb(req, ld_key);
}

void HomeLogStore::on_log_found(const logstore_seq_num_t seq_num, const logdev_key ld_key, const log_buffer buf) {
    THIS_LOGSTORE_LOG(DEBUG, "Found a log lsn={} logdev_key={}", seq_num, ld_key);

    if (seq_num <= m_safe_truncation_boundary.seq_num.load(std::memory_order_acquire)) {
        THIS_LOGSTORE_LOG(TRACE, "Log lsn={} is already truncated on per device, ignoring", seq_num);
        return;
    }

    // Create the mapping between seq_num and log dev key
    m_records.create_and_complete(seq_num, ld_key);
    atomic_update_max(m_seq_num, seq_num + 1, std::memory_order_acq_rel);
    m_flush_batch_max_lsn = std::max(m_flush_batch_max_lsn, seq_num);

    if (m_found_cb != nullptr) m_found_cb(seq_num, buf, nullptr);
    on_batch_completion(ld_key); // Log replay will always be on non-batch mode, so call batch completion everytime.
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
        HS_DEBUG_ASSERT_LE(upto_seq_num, get_contiguous_completed_seq_num(s),
                           "Logstore {} expects truncation to be contiguously completed", m_store_id);
    }
#endif

    // First try to block the flushing of logdevice and if we are successfully able to do, then
    auto shared_this{shared_from_this()};
    const bool locked_now{
        HomeLogStoreMgr::logdev().try_lock_flush([shared_this, upto_seq_num, in_memory_truncate_only]() {
            shared_this->do_truncate(upto_seq_num);
            if (!in_memory_truncate_only) { [[maybe_unused]] const auto key{home_log_store_mgr.do_device_truncate()}; }
        })};

    if (locked_now) { HomeLogStoreMgr::logdev().unlock_flush(); }
}

// NOTE: This method assumes the flush lock is already acquired by the caller
void HomeLogStore::do_truncate(const logstore_seq_num_t upto_seq_num) {
    m_records.truncate(upto_seq_num);
    m_safe_truncation_boundary.seq_num.store(upto_seq_num, std::memory_order_release);

    // Need to update the superblock with meta, we don't persist yet, will be done as part of log dev truncation
    HomeLogStoreMgr::logdev().update_store_meta(m_store_id, logstore_meta{upto_seq_num + 1}, false /* persist_now */);

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
        HS_RELEASE_ASSERT(0,
                          "We expect post_device_truncation to be called only for logstores which has min of all "
                          "truncation boundaries");
    }
}

void HomeLogStore::fill_gap(const logstore_seq_num_t seq_num) {
    HS_DEBUG_ASSERT_EQ(m_records.status(seq_num).is_hole, true, "Attempted to fill gap lsn={} which has valid data",
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
    json_dump["store_id"] = this->m_store_id;

    const auto trunc_upto{this->truncated_upto()};
    std::remove_const_t< decltype(trunc_upto) > idx{trunc_upto + 1};
    if (dump_req.start_seq_num != 0) idx = dump_req.start_seq_num;

    // must use move operator= operation instead of move copy constructor
    nlohmann::json json_records = nlohmann::json::array();
    bool end_iterate{false};
    m_records.foreach_completed(
        idx,
        [&json_records, &dump_req, &end_iterate](decltype(idx) cur_idx, decltype(idx) max_idx,
                                                 const homestore::logstore_record& record) -> bool {
            // do a sync read
            // must use move operator= operation instead of move copy constructor
            nlohmann::json json_val = nlohmann::json::object();
            serialized_log_record record_header;

            const auto log_buffer{HomeLogStoreMgr::logdev().read(record.m_dev_key, record_header)};

            try {
                json_val["size"] = static_cast< uint32_t >(record_header.size);
                json_val["offset"] = static_cast< uint32_t >(record_header.offset);
                json_val["is_inlined"] = static_cast< uint32_t >(record_header.get_inlined());
                json_val["store_seq_num"] = static_cast< uint64_t >(record_header.store_seq_num);
                json_val["store_id"] = static_cast< logstore_id_t >(record_header.store_id);
            } catch (const std::exception& ex) { LOGERRORMOD(logstore, "Exception in json dump- {}", ex.what()); }

            if (dump_req.verbosity_level == homestore::log_dump_verbosity::CONTENT) {
                const uint8_t* const b{log_buffer.bytes()};
                const std::vector< uint8_t > bv(b, b + log_buffer.size());
                auto content = nlohmann::json::binary_t(bv);
                json_val["content"] = std::move(content);
            }
            json_records.emplace_back(std::move(json_val));
            decltype(idx) end_idx{std::min(max_idx, dump_req.end_seq_num)};
            end_iterate = (cur_idx < end_idx) ? true : false;
            return end_iterate;
        });

    json_dump["log_records"] = std::move(json_records);
    return json_dump;
}

void HomeLogStore::foreach (const int64_t start_idx, const std::function< bool(logstore_seq_num_t, log_buffer) >& cb) {

    m_records.foreach_completed(start_idx,
                                [&](long int cur_idx, long int max_idx, homestore::logstore_record& record) -> bool {
                                    // do a sync read
                                    serialized_log_record header;

                                    auto log_buf{HomeLogStoreMgr::logdev().read(record.m_dev_key, header)};
                                    return cb(cur_idx, log_buf);
                                });
}

logstore_seq_num_t HomeLogStore::get_contiguous_issued_seq_num(const logstore_seq_num_t from) {
    return (logstore_seq_num_t)m_records.active_upto(from + 1);
}

logstore_seq_num_t HomeLogStore::get_contiguous_completed_seq_num(const logstore_seq_num_t from) {
    return (logstore_seq_num_t)m_records.completed_upto(from + 1);
}

HomeLogStoreMgrMetrics::HomeLogStoreMgrMetrics() : sisl::MetricsGroup("LogStores", "AllLogStores") {
    REGISTER_COUNTER(logstores_count, "Total number of log stores", sisl::_publish_as::publish_as_gauge);
    REGISTER_COUNTER(logstore_append_count, "Total number of append requests to log stores", "logstore_op_count",
                     {"op", "write"});
    REGISTER_COUNTER(logstore_read_count, "Total number of read requests to log stores", "logstore_op_count",
                     {"op", "read"});
    REGISTER_COUNTER(logdev_flush_by_size_count, "Total flushing attempted because of filled buffer");
    REGISTER_COUNTER(logdev_flush_by_timer_count, "Total flushing attempted because of expired timer");
    REGISTER_COUNTER(logdev_back_to_back_flushing, "Number of attempts to do back to back flush prepare");

    REGISTER_HISTOGRAM(logstore_append_latency, "Logstore append latency", "logstore_op_latency", {"op", "write"});
    REGISTER_HISTOGRAM(logstore_read_latency, "Logstore read latency", "logstore_op_latency", {"op", "read"});
    REGISTER_HISTOGRAM(logdev_flush_size_distribution, "Distribution of flush data size",
                       HistogramBucketsType(ExponentialOfTwoBuckets));
    REGISTER_HISTOGRAM(logdev_flush_records_distribution, "Distribution of num records to flush",
                       HistogramBucketsType(LinearUpto128Buckets));
    REGISTER_HISTOGRAM(logstore_record_size, "Distribution of log record size",
                       HistogramBucketsType(ExponentialOfTwoBuckets));

    register_me_to_farm();
}

logstore_meta logstore_meta::default_value() { return logstore_meta{-1}; }
void logstore_meta::init(logstore_meta& meta) { meta.m_first_seq_num = 0; }
void logstore_meta::clear(logstore_meta& meta) { meta.m_first_seq_num = -1; }
bool logstore_meta::is_valid(const logstore_meta& meta) { return meta.m_first_seq_num >= 0; }

} // namespace homestore
