#include <iterator>
#include <string>

#include <fmt/format.h>
#include <iomgr/iomgr.hpp>
#include <sisl/utility/thread_factory.hpp>

#include <homestore.hpp>
#include "common/homestore_assert.hpp"

#include "log_store_family.hpp"
#include "log_dev.hpp"
#include "log_store.hpp"

namespace homestore {
SISL_LOGGING_DECL(logstore)

LogStoreFamily::LogStoreFamily(logstore_family_id_t f_id) :
        m_family_id{f_id},
        m_metablk_name{std::string("LogDevFamily") + std::to_string(f_id)},
        m_log_dev{f_id, m_metablk_name} {}

void LogStoreFamily::meta_blk_found_cb(meta_blk* mblk, sisl::byte_view buf, size_t size) {
    m_log_dev.meta_blk_found(mblk, buf, size);
}

void LogStoreFamily::start(bool format, JournalVirtualDev* blk_store) {
    m_log_dev.register_store_found_cb(bind_this(LogStoreFamily::on_log_store_found, 2));
    m_log_dev.register_append_cb(bind_this(LogStoreFamily::on_io_completion, 5));
    m_log_dev.register_logfound_cb(bind_this(LogStoreFamily::on_logfound, 6));

    // Start the logdev, which loads the device in case of recovery.
    m_log_dev.start(format, blk_store);
    for (auto it{std::begin(m_unopened_store_io)}; it != std::end(m_unopened_store_io); ++it) {
        LOGINFO("skip log entries for store id {}-{}, ios {}", m_family_id, it->first, it->second);
    }
    m_unopened_store_io.clear();

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
                    lstore->truncate(lstore->m_safe_truncation_boundary.seq_num.load(std::memory_order_acquire));
                }
            }
        }
    });
}

void LogStoreFamily::stop() {
    m_id_logstore_map.wlock()->clear();
    m_log_dev.stop();
}

std::shared_ptr< HomeLogStore > LogStoreFamily::create_new_log_store(bool append_mode) {
    auto const store_id = m_log_dev.reserve_store_id();
    std::shared_ptr< HomeLogStore > lstore;
    lstore = std::make_shared< HomeLogStore >(*this, store_id, append_mode, 0);

    auto m = m_id_logstore_map.wlock();
    const auto it = m->find(store_id);
    HS_REL_ASSERT((it == m->end()), "store_id {}-{} already exists", m_family_id, store_id);

    m->insert(std::make_pair<>(store_id, logstore_info_t{lstore, nullptr, append_mode}));

    LOGINFO("Created log store id {}-{}", m_family_id, store_id);
    return lstore;
}

void LogStoreFamily::open_log_store(logstore_id_t store_id, bool append_mode, const log_store_opened_cb_t& on_open_cb) {
    auto m = m_id_logstore_map.wlock();
    const auto it = m->find(store_id);
    HS_REL_ASSERT((it == m->end()), "store_id {}-{} already exists", m_family_id, store_id);

    LOGINFO("Opening log store id {}-{}", m_family_id, store_id);
    m->insert(std::make_pair<>(store_id, logstore_info_t{nullptr, on_open_cb, append_mode}));
}

void LogStoreFamily::remove_log_store(logstore_id_t store_id) {
    LOGINFO("Removing log store id {}-{}", m_family_id, store_id);
    auto ret = m_id_logstore_map.wlock()->erase(store_id);
    HS_REL_ASSERT((ret == 1), "try to remove invalid store_id {}-{}", m_family_id, store_id);
    m_log_dev.unreserve_store_id(store_id);
}

void LogStoreFamily::device_truncate_in_user_reactor(const std::shared_ptr< truncate_req >& treq) {
    const bool locked_now = m_log_dev.try_lock_flush([this, treq]() {
        if (iomanager.am_i_tight_loop_reactor()) {
            iomanager.run_on(
                logstore_service().m_truncate_thread,
                [this, treq]([[maybe_unused]] iomgr::io_thread_addr_t addr) { device_truncate_in_user_reactor(treq); });
        } else {
            const logdev_key trunc_upto = do_device_truncate(treq->dry_run);
            bool done{false};
            if (treq->cb || treq->wait_till_done) {
                {
                    std::lock_guard< std::mutex > lk{treq->mtx};
                    done = (--treq->trunc_outstanding == 0);
                    treq->m_trunc_upto_result[m_family_id] = trunc_upto;
                }
            }
            if (done) {
                if (treq->cb) { treq->cb(treq->m_trunc_upto_result); }
                if (treq->wait_till_done) { treq->cv.notify_one(); }
            }
        }
    });
    if (locked_now) { m_log_dev.unlock_flush(); }
}

void LogStoreFamily::on_log_store_found(logstore_id_t store_id, const logstore_superblk& sb) {
    auto m = m_id_logstore_map.rlock();
    const auto it = m->find(store_id);
    if (it == m->end()) {
        LOGERROR("Store Id {}-{} found but not opened yet.", m_family_id, store_id);
        m_unopened_store_id.insert(store_id);
        m_unopened_store_io.insert(std::make_pair<>(store_id, 0));
        return;
    }

    LOGINFO("Found a logstore store_id={}-{} with start seq_num={}, Creating a new HomeLogStore instance", m_family_id,
            store_id, sb.m_first_seq_num);
    auto& l_info = const_cast< logstore_info_t& >(it->second);
    l_info.m_log_store = std::make_shared< HomeLogStore >(*this, store_id, l_info.append_mode, sb.m_first_seq_num);
    if (l_info.m_on_log_store_opened) l_info.m_on_log_store_opened(l_info.m_log_store);
}

static thread_local std::vector< std::shared_ptr< HomeLogStore > > s_cur_flush_batch_stores;

void LogStoreFamily::on_io_completion(logstore_id_t id, logdev_key ld_key, logdev_key flush_ld_key,
                                      uint32_t nremaining_in_batch, void* ctx) {
    auto* req = s_cast< logstore_req* >(ctx);
    HomeLogStore* log_store = req->log_store;

    if (req->is_write) {
        HS_LOG_ASSERT_EQ(log_store->m_store_id, id, "Expecting store id in log store and io completion to match");
        log_store->on_write_completion(req, ld_key);
        on_batch_completion(log_store, nremaining_in_batch, flush_ld_key);
    } else {
        log_store->on_read_completion(req, ld_key);
    }
}

void LogStoreFamily::on_logfound(logstore_id_t id, logstore_seq_num_t seq_num, logdev_key ld_key,
                                 logdev_key flush_ld_key, log_buffer buf, uint32_t nremaining_in_batch) {
    auto m = m_id_logstore_map.rlock();
    auto const it = m->find(id);
    if (it == m->end()) {
        auto [unopened_it, inserted] = m_unopened_store_io.insert(std::make_pair<>(id, 0));
        if (inserted) {
            // HS_REL_ASSERT(0, "log id  {}-{} not found", m_family_id, id);
        }
        ++unopened_it->second;
        return;
    }
    auto& log_store = it->second.m_log_store;
    if (!log_store) { return; }
    log_store->on_log_found(seq_num, ld_key, flush_ld_key, buf);
    on_batch_completion(log_store.get(), nremaining_in_batch, flush_ld_key);
}

void LogStoreFamily::on_batch_completion(HomeLogStore* log_store, uint32_t nremaining_in_batch,
                                         logdev_key flush_ld_key) {

    /* check if it is a first update on this log store */
    auto id = log_store->get_store_id();
    const auto it = m_last_flush_info.find(id);
    if ((it == std::end(m_last_flush_info)) || (it->second != flush_ld_key.idx)) {
        // first time completion in this batch for a given store_id
        m_last_flush_info.insert_or_assign(id, flush_ld_key.idx);
        if (it == std::end(m_last_flush_info)) { s_cur_flush_batch_stores.push_back(log_store->shared_from_this()); }
    }
    if (nremaining_in_batch == 0) {
        // This batch is completed, call all log stores participated in this batch about the end of batch
        HS_LOG_ASSERT_GT(s_cur_flush_batch_stores.size(), 0U, "Expecting one store to be flushed in batch");

        for (auto& l : s_cur_flush_batch_stores) {
            l->on_batch_completion(flush_ld_key);
        }
        s_cur_flush_batch_stores.clear();
        m_last_flush_info.clear();
    }
}

logdev_key LogStoreFamily::do_device_truncate(bool dry_run) {
    static thread_local std::vector< std::shared_ptr< HomeLogStore > > m_min_trunc_stores;
    static thread_local std::vector< std::shared_ptr< HomeLogStore > > m_non_participating_stores;

    m_min_trunc_stores.clear();
    m_non_participating_stores.clear();
    logdev_key min_safe_ld_key = logdev_key::out_of_bound_ld_key();

    std::string dbg_str{"Format [store_id:trunc_lsn:logidx:dev_trunc_pending?:active_writes_in_trucate?] "};
    m_id_logstore_map.withRLock([this, &min_safe_ld_key, &dbg_str](auto& id_logstore_map) {
        for (auto& id_logstore : id_logstore_map) {
            auto& store_ptr = id_logstore.second.m_log_store;
            const auto& trunc_info = store_ptr->pre_device_truncation();

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
        HS_PERIODIC_LOG(
            INFO, logstore,
            "[Family={}] No log store append on any log stores, skipping device truncation, all_logstore_info:<{}>",
            m_family_id, dbg_str);
        return min_safe_ld_key;
    }

    // Got the safest log id to truncate and actually truncate upto the safe log idx to the log device
    if (!dry_run) { m_log_dev.truncate(min_safe_ld_key); }
    HS_PERIODIC_LOG(INFO, logstore,
                    "[Family={}] LogDevice truncate, all_logstore_info:<{}> safe log dev key to truncate={}",
                    m_family_id, dbg_str, min_safe_ld_key);

    // We call post device truncation only to the log stores whose prepared truncation points are fully
    // truncated or to stores which didn't particpate in this device truncation.
    for (auto& store_ptr : m_min_trunc_stores) {
        store_ptr->post_device_truncation(min_safe_ld_key);
    }
    for (auto& store_ptr : m_non_participating_stores) {
        store_ptr->post_device_truncation(min_safe_ld_key);
    }
    m_min_trunc_stores.clear(); // Not clearing here, would cause a shared_ptr ref holding.
    m_non_participating_stores.clear();

    return min_safe_ld_key;
}

nlohmann::json LogStoreFamily::dump_log_store(const log_dump_req& dump_req) {
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

nlohmann::json LogStoreFamily::get_status(int verbosity) const {
    nlohmann::json js;
    auto unopened = nlohmann::json::array();
    for (const auto& l : m_unopened_store_id) {
        unopened.push_back(l);
    }
    js["logstores_unopened"] = std::move(unopened);

    // Logdev status
    m_log_dev.get_status(verbosity, js);

    // All logstores
    m_id_logstore_map.withRLock([&](auto& id_logstore_map) {
        for (const auto& [id, lstore] : id_logstore_map) {
            js["logstore_id_" + std::to_string(id)] = lstore.m_log_store->get_status(verbosity);
        }
    });
    return js;
}
} // namespace homestore
