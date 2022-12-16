#include "hs_log_store.h"

#include "cast_helper.h"
#include "common.h"
#include "stat.h"
#include "storage_engine_buffer.h"
#include "logger.h"

#include "lz4.h"

#include <ios>
#include <map>
#include <mutex>

#include <assert.h>
#include <stdexcept>

using namespace nukv;

namespace nuraft {
ptr< buffer > zero_buf1;
#define iomanager iomgr::IOManager::instance()

struct hs_log_store::log_cache {
    log_cache(const hs_log_store::Options& opt = hs_log_store::Options()) :
            maxCacheSize(opt.maxCacheSizeBytes), maxLogsToKeep(opt.maxCachedLogs), logsSize(0), curStartIdx(0) {}

    void set(ulong log_idx, ptr< log_entry > log) {
        static StatElem& cache_min_idx =
            *StatMgr::getInstance()->createStat(StatElem::GAUGE, "raft_log_cache_min_index");
        static StatElem& cache_max_idx =
            *StatMgr::getInstance()->createStat(StatElem::GAUGE, "raft_log_cache_max_index");
        static StatElem& cache_usage = *StatMgr::getInstance()->createStat(StatElem::GAUGE, "raft_log_cache_usage");

        auto l = std::lock_guard< std::mutex >(lock);

        // Check if already exists.
        {
            auto entry = logs.find(log_idx);
            if (entry != logs.end()) {
                // Same log index already exists,
                // we will overwrite it. Substract the existing size first.
                ptr< log_entry >& log_to_erase = entry->second;
                logsSize.fetch_sub(sizeof(uint64_t) * 2 + log_to_erase->get_buf().container_size());
                logs.erase(entry);
            }
        }

        // Insert into map.
        logs[log_idx] = log;
        logsSize.fetch_add(sizeof(uint64_t) * 2 + log->get_buf().container_size());

        // Check min/max index numbers.
        auto min = logs.begin();
        uint64_t min_log_idx = (min != logs.end()) ? min->first : 0;
        auto max = logs.rbegin();
        uint64_t max_log_idx = (max != logs.rend()) ? max->first : 0;

        // If the number of logs in the map exceeds the limit,
        // purge logs in the front.
        if (max_log_idx > maxLogsToKeep + min_log_idx || logsSize > maxCacheSize) {
            size_t count = 0;
            auto itr = logs.begin();
            while (itr != logs.end()) {
                ptr< log_entry >& log_to_erase = itr->second;
                logsSize.fetch_sub(sizeof(uint64_t) * 2 + log_to_erase->get_buf().container_size());
                itr = logs.erase(itr);
                count++;
                if (count + min_log_idx + maxLogsToKeep >= max_log_idx && logsSize <= maxCacheSize) break;
            }
        }
        min = logs.begin();
        min_log_idx = (min != logs.end()) ? min->first : 0;

        // Update stats.
        cache_min_idx = min_log_idx;
        cache_max_idx = max_log_idx;
        cache_usage = logsSize;
    }

    // If cache is empty, return 0.
    uint64_t nextSlot() {
        auto l = std::lock_guard< std::mutex >(lock);
        if (!logs.size()) return 0;
        auto max = logs.rbegin();
        uint64_t max_log_idx = (max != logs.rend()) ? max->first : 0;
        if (max_log_idx) return max_log_idx + 1;
        return 0;
    }

    void compact(ulong log_idx_upto) {
        static StatElem& cache_usage = *StatMgr::getInstance()->createStat(StatElem::GAUGE, "raft_log_cache_usage");

        auto l = std::lock_guard< std::mutex >(lock);
        auto itr = logs.begin();
        while (itr != logs.end()) {
            // Purge logs in the front.
            // `log_idx_upto` itself also will be purged,
            // and next min index will be `log_idx_upto + 1`.
            if (itr->first > log_idx_upto) break;

            ptr< log_entry >& log_to_erase = itr->second;
            logsSize.fetch_sub(sizeof(uint64_t) * 2 + log_to_erase->get_buf().container_size());
            itr = logs.erase(itr);
        }
        cache_usage = logsSize;
    }

    ptr< log_entry > get(ulong log_idx) {
        // Point query.
        auto l = std::lock_guard< std::mutex >(lock);
        auto itr = logs.find(log_idx);
        if (itr == logs.end()) return nullptr;
        return itr->second;
    }

    bool gets(ulong start, ulong end, ptr< std::vector< ptr< log_entry > > >& vector_out) {
        // Range query.
        auto l = std::lock_guard< std::mutex >(lock);

        // Check min index number. If request's start number is
        // earlier than this cache, just return false.
        auto min = logs.begin();
        uint64_t min_log_idx = (min != logs.end()) ? min->first : 0;
        if (!min_log_idx || min_log_idx > start) return false;

        size_t cur_idx = 0;
        auto itr = logs.find(start);
        while (itr != logs.end() && cur_idx + start < end) {
            (*vector_out)[cur_idx] = itr->second;
            ++cur_idx;
            ++itr;
        }

        return true;
    }

    void drop() {
        static StatElem& cache_usage = *StatMgr::getInstance()->createStat(StatElem::GAUGE, "raft_log_cache_usage");

        auto l = std::lock_guard< std::mutex >(lock);
        logs.clear();
        logsSize.store(0);
        cache_usage = logsSize;
    }

    uint64_t getStartIndex() const { return curStartIdx.load(); }

    void setStartIndex(uint64_t to) { curStartIdx = to; }

    uint64_t maxCacheSize;

    uint64_t maxLogsToKeep;

    // Cached logs and its lock.
    std::mutex lock;
    std::map< ulong, ptr< log_entry > > logs;

    // Currently cached data size.
    std::atomic< uint64_t > logsSize;

    // Current start index, to avoid access to underlying DB.
    // This value is separate and irrelevant to min value of `logs`.
    std::atomic< uint64_t > curStartIdx;
};

static size_t jl_calc_len(ptr< log_entry >& src) {
    // Term                 8 bytes
    // Type                 1 byte
    // Data length (=N)     4 bytes
    // Data                 N bytes
    return sizeof(uint64_t) + sizeof(uint8_t) + sizeof(uint32_t) + src->get_buf().size();
}

static void jl_enc_le(ptr< log_entry >& src, SEBufSerializer& ss) {
    // `log_entry` to binary.
    ss.putU64(src->get_term());
    ss.putU8(_SC(uint8_t, src->get_val_type()));
    buffer& buf = src->get_buf();
    buf.pos(0);
    SEBuf sebuf(buf.size(), buf.data());
    ss.putSEBuf(sebuf);

    // LOGDEBUGMOD(nublox_logstore, "hs_log_store::jl_enc_le(), term {}, data {}", src->get_term(), sebuf.toString());
}

static ptr< log_entry > jl_dec_le(const SEBuf& src) {
    // binary to `log_entry.
    SEBufSerializer ss(src);
    uint64_t term = ss.getU64();

    log_val_type type = _SC(log_val_type, ss.getU8());
    SEBuf data = ss.getSEBuf();
    ptr< buffer > _data = buffer::alloc(data.len);
    _data->pos(0);
    memcpy(_data->data(), data.buf, data.len);
    // LOGDEBUGMOD(nublox_logstore, "hs_log_store::jl_dec_le(), term {}, data {}, size {}", term, data.toString(),
    // data.size());

    return cs_new< log_entry >(term, _data, type);
}

struct hs_log_store::FlushElem {
    FlushElem(uint64_t desired = 0) : desiredLogIdx(desired), done(false) {}

    /**
     * Awaiter for caller.
     */
    EventAwaiter eaCaller;

    /**
     * Desired Raft log index to be durable.
     */
    uint64_t desiredLogIdx;

    /**
     * `true` if the request is processed.
     */
    std::atomic< bool > done;
};

ssize_t hs_log_store::getCompMaxSize(homestore::HomeLogStore* db, const homestore::log_buffer& rec) {
    if (!myOpt.compression) {
        // LZ4 is available, but compression is disabled.
        return 0;
    }
    return LZ4_compressBound(rec.size()) + 2;
}

ssize_t hs_log_store::compress(homestore::HomeLogStore* db, const homestore::log_buffer& src,
                               homestore::log_buffer& dst) {
    if (!myOpt.compression || dst.size() < 2) { return 0; }

    // NOTE: For future extension, we will make this format
    //       compatible with the one in `storage_engine_jungle`.
    //
    //   << Internal meta format >>
    // Meta length (for future extension)       1 byte
    // Compression type                         1 byte
    dst.bytes()[0] = 1;
    dst.bytes()[1] = 1;

    ssize_t comp_size = LZ4_compress_default((char*)src.bytes(), (char*)dst.bytes() + 2, src.size(), dst.size() - 2);
    return comp_size + 2;
}

ssize_t hs_log_store::decompress(homestore::HomeLogStore* db, const homestore::log_buffer& src,
                                 homestore::log_buffer& dst) {
    return LZ4_decompress_safe((char*)src.bytes() + 2, (char*)dst.bytes(), src.size() - 2, dst.size());
}

void hs_log_store::flushLoop() {
    // Flush loop is not necessary if strong durability option is disabled.
    if (!myOpt.strongDurability) return;

    while (!flushThreadStopSignal) {
        std::list< std::shared_ptr< FlushElem > > reqs;
        {
            auto l = std::lock_guard< std::mutex >(flushReqsLock);
            reqs = flushReqs;
            flushReqs.clear();
        }
        if (!reqs.size()) {
            // No request, sleep.
            eaFlushThread.wait_us(myOpt.flushThreadSleepTimeUs);
            eaFlushThread.reset();
            continue;
        }

        // Find the max desired log index to check if actual
        // flush is needed.
        bool flush_required = false;
        for (auto& entry : reqs) {
            std::shared_ptr< FlushElem > cur = entry;
            if (cur->desiredLogIdx > lastDurableLogIdx) {
                flush_required = true;
                break;
            }
        }

        if (flush_required) { flush(); }

        for (auto& entry : reqs) {
            std::shared_ptr< FlushElem > cur = entry;
            if (cur->desiredLogIdx <= lastDurableLogIdx) {
                cur->done = true;
                cur->eaCaller.invoke();
            } else {
                // Try it again.
                auto l = std::lock_guard< std::mutex >(flushReqsLock);
                flushReqs.push_back(cur);
            }
        }
    }
}

hs_log_store::hs_log_store(const homestore::logstore_id_t logstore_id, const Options& opt) :
        dummyLogEntry(cs_new< log_entry >(0, zero_buf1, log_val_type::app_log)),
        m_log_store(nullptr),
        cacheInst(opt.cache_enabled ? std::make_shared< log_cache >(opt) : nullptr),
        flushThread(nullptr),
        lastDurableLogIdx(0),
        flushThreadStopSignal(false),
        myOpt(opt) {

    if (logstore_id == UINT32_MAX) {
        m_log_store =
            homestore::HomeLogStoreMgrSI().create_new_log_store(homestore::HomeLogStoreMgr::CTRL_LOG_FAMILY_IDX, false);
        LOGDEBUGMOD(nublox_logstore, "Creating new log store");
        if (!m_log_store) throw std::runtime_error("Failed to create log store");
        {
            std::lock_guard lock{m_wait_lock};
            m_done = true;
        }
        m_wait_cv.notify_one();
    } else {
        LOGDEBUGMOD(nublox_logstore, "Opening existing log store");
        homestore::HomeLogStoreMgrSI().open_log_store(homestore::HomeLogStoreMgr::CTRL_LOG_FAMILY_IDX, logstore_id,
                                                      false,
                                                      [this](std::shared_ptr< homestore::HomeLogStore > log_store) {
                                                          {
                                                              auto lg = std::lock_guard(m_wait_lock);
                                                              if (log_store) {
                                                                  LOGDEBUGMOD(nublox_logstore, "Found log store");
                                                                  m_log_store = log_store;
                                                              } else {
                                                                  LOGERROR("Logstore returned emtpy {}!");
                                                              }
                                                              m_done = true;
                                                          }
                                                          m_wait_cv.notify_one();
                                                      });
    }
}

std::error_condition hs_log_store::get() {
    {
        // check if done
        auto ul{std::unique_lock(m_wait_lock)};
        m_wait_cv.wait(ul, [this] { return m_done; });
    }
    if (!m_log_store) return std::make_error_condition(std::errc::no_such_device_or_address);
    m_log_store->register_log_found_cb(std::bind(&hs_log_store::on_log_found, this, std::placeholders::_1,
                                                 std::placeholders::_2, std::placeholders::_3));
    if (myOpt.strongDurability) { flushThread = new std::thread(&hs_log_store::flushLoop, this); }
    return std::error_condition();
}

homestore::logstore_id_t hs_log_store::getLogstoreId() { return m_log_store->get_store_id(); }

void hs_log_store::on_log_found(homestore::logstore_seq_num_t lsn, homestore::log_buffer buf, void* ctx) {
    LOGDEBUGMOD(nublox_logstore, "Recovered lsn {}:{} with log data of size {}", m_log_store->get_store_id(), lsn,
                buf.size());
}

hs_log_store::~hs_log_store() { close(); }

ulong hs_log_store::next_slot() const {
    static StatElem& lat = *StatMgr::getInstance()->createStat(StatElem::HISTOGRAM, "raft_log_next_slot_latency");
    GenericTimer tt;
    uint64_t _next_slot = 0;
    if (cacheInst != nullptr) _next_slot = cacheInst->nextSlot();
    if (!_next_slot) {
        // Cache is empty now.
        uint64_t max_seq = 0;
        max_seq = m_log_store->get_contiguous_issued_seq_num(0);
        _next_slot = max_seq + 1;
    }
    LOGDEBUGMOD(nublox_logstore, "hs_log_store::next_slot() {}", _next_slot);

    lat += tt.getElapsedUs();
    return _next_slot;
}

ulong hs_log_store::start_index() const {
    static StatElem& lat = *StatMgr::getInstance()->createStat(StatElem::HISTOGRAM, "raft_log_start_index_latency");
    GenericTimer tt;
    uint64_t start_index = 0;
    if (cacheInst != nullptr) start_index = cacheInst->getStartIndex();
    if (!start_index) {
        // In Jungle's perspective, min seqnum == last flushed seqnum + 1
        int64_t min_seq = 0;
        min_seq = m_log_store->truncated_upto() + 1;
        // min_seq = m_log_store->get_contiguous_completed_seq_num(0);

        // start_index starts from 1.
        start_index = std::max((int64_t)1, min_seq);
        if (cacheInst != nullptr) cacheInst->setStartIndex(start_index);
    }
    lat += tt.getElapsedUs();
    LOGDEBUGMOD(nublox_logstore, "hs_log_store::start_index(): {}", start_index);
    return start_index;
}

ptr< log_entry > hs_log_store::last_entry() const {
    static StatElem& lat = *StatMgr::getInstance()->createStat(StatElem::HISTOGRAM, "raft_log_last_entry_latency");
    static StatElem& hit_cnt = *StatMgr::getInstance()->createStat(StatElem::COUNTER, "raft_log_cache_hit");
    static StatElem& miss_cnt = *StatMgr::getInstance()->createStat(StatElem::COUNTER, "raft_log_cache_miss");
    GenericTimer tt;

    uint64_t max_seq;
    max_seq = m_log_store->get_contiguous_completed_seq_num(0);
    LOGDEBUGMOD(nublox_logstore, "hs_log_store::last_entry(), seqnum {}", max_seq);
    if (max_seq == 0) return dummyLogEntry;
    ptr< log_entry > ret = nullptr;
    if (cacheInst != nullptr) ret = cacheInst->get(max_seq);
    if (!ret) {
        ++miss_cnt;

        // homestore::log_buffer logentry;
        try {
            auto logentry = m_log_store->read_sync(max_seq);
            SEBuf value_buf(logentry.size(), logentry.bytes());
            LOGDEBUGMOD(nublox_logstore, "hs_log_store::last_entry(), size {} value {}", logentry.size(),
                        value_buf.toString());

            ret = jl_dec_le(value_buf);
        } catch (const std::exception& e) {
            LOGERROR("hs_log_store::last_entry(), out_of_range {}", max_seq);
            throw e;
        }

        // TODO: Free the log_buffer
    } else {
        ++hit_cnt;
    }

    lat += tt.getElapsedUs();
    return ret;
}

ulong hs_log_store::append(ptr< log_entry >& entry) {
    LOGDEBUGMOD(nublox_logstore, "hs_log_store::append()");

    auto l = std::lock_guard< std::recursive_mutex >(writeLock);
    const uint64_t next_seq{static_cast< uint64_t >(m_log_store->get_contiguous_issued_seq_num(0)) + 1};
    write_at_internal(next_seq, entry);
    return next_seq;
}

void hs_log_store::write_at_internal(ulong index, ptr< log_entry >& entry) {
    static StatElem& write_lat = *StatMgr::getInstance()->createStat(StatElem::HISTOGRAM, "raft_log_write_latency");
    GenericTimer tt;
    auto l = std::lock_guard< std::recursive_mutex >(writeLock);
    size_t sz = jl_calc_len(entry);
    SEBuf value_buf = SEBuf::alloc(sz);
    SEBufSerializer ss(value_buf);
    jl_enc_le(entry, ss);

    LOGDEBUGMOD(nublox_logstore, "hs_log_store::write_async(), index: {}, size: {}, value: {}", index, value_buf.size(),
                value_buf.toString());
    m_log_store->write_sync(
        index, sisl::io_blob{reinterpret_cast< uint8_t* >(value_buf.data()), static_cast< uint32_t >(sz), false});
    value_buf.free();
    if (cacheInst != nullptr) cacheInst->set(index, entry);

    write_lat += tt.getElapsedUs();
}

void hs_log_store::write_at(ulong index, ptr< log_entry >& entry) {
    LOGDEBUGMOD(nublox_logstore, "hs_log_store::write_at()");

    auto l = std::lock_guard< std::recursive_mutex >(writeLock);

    uint64_t next_seq = 0;
    next_seq = m_log_store->get_contiguous_issued_seq_num(0);

    if (next_seq && next_seq > index) {
        // Overwrite log in the middle, rollback required before that.
        LOGDEBUGMOD(nublox_logstore, "hs_log_store::write_at(): Rollback");

        rollback(index - 1);
    }
    write_at_internal(index, entry);
}

void hs_log_store::end_of_append_batch(ulong start, ulong cnt) {
    if (!myOpt.strongDurability) return;

    std::shared_ptr< FlushElem > my_req = std::make_shared< FlushElem >(start + cnt - 1);
    {
        auto l = std::lock_guard< std::mutex >(flushReqsLock);
        flushReqs.push_back(my_req);
    }
    eaFlushThread.invoke();
    while (!my_req->done) {
        my_req->eaCaller.wait_ms(100);
    }
}

ptr< std::vector< ptr< log_entry > > > hs_log_store::log_entries(ulong start, ulong end) {
    LOGDEBUGMOD(nublox_logstore, "hs_log_store::log_entries(), start-index {}, end {}", start, end);

    static StatElem& read_lat = *StatMgr::getInstance()->createStat(StatElem::HISTOGRAM, "raft_log_read_latency");
    static StatElem& read_dist =
        *StatMgr::getInstance()->createStat(StatElem::HISTOGRAM, "raft_log_read_size_distribution");
    static StatElem& hit_cnt = *StatMgr::getInstance()->createStat(StatElem::COUNTER, "raft_log_cache_hit");
    static StatElem& miss_cnt = *StatMgr::getInstance()->createStat(StatElem::COUNTER, "raft_log_cache_miss");
    GenericTimer tt;

    if (start >= end) {
        // Mostly for heartbeat.
        return nullptr;
    }

    read_dist += end - start;

    ptr< std::vector< ptr< log_entry > > > ret(cs_new< std::vector< ptr< log_entry > > >(end - start));
    bool cache_hit = false;
    if (cacheInst != nullptr) cache_hit = cacheInst->gets(start, end, ret);
    if (!cache_hit) {
        ++miss_cnt;
        // if (end <= 2 + start) {
        // In case of just 1-2 entries, point query is much lighter than iterator.
        for (ulong ii = start; ii < end; ++ii) {
            (*ret)[ii - start] = entry_at(ii);
        }
        read_lat += tt.getElapsedUs();
        return ret;
        // }

        // ulong idx = start;

        // try {
        //     m_log_store->foreach(
        //     idx,
        //     [end, start, &ret, &idx, this] (int64_t seq_num, const homestore::log_buffer& log_entry) -> bool {
        //         SEBuf value_buf( log_entry.size(), log_entry.bytes() );
        //         (*ret)[idx-start] = jl_dec_le(value_buf);
        //         LOGDEBUGMOD(nublox_logstore, "hs_log_store::log_entries->foreach(), seq: {}, count: {}, size: {}",
        //         seq_num, idx-start+1, log_entry.size()); idx++; return (seq_num +1 < end) ? true : false;
        //     });
        // } catch (const std::exception& e) {
        //         LOGFATAL("Unexpected out_of_range exception for lsn={}:{}", m_log_store->get_store_id(), idx);
        // }
    } else {
        ++hit_cnt;
    }

    read_lat += tt.getElapsedUs();
    return ret;
}

ptr< log_entry > hs_log_store::entry_at(ulong index) {
    LOGDEBUGMOD(nublox_logstore, "hs_log_store::entry_at() {} ", index);

    static StatElem& read_lat = *StatMgr::getInstance()->createStat(StatElem::HISTOGRAM, "raft_log_entry_at_latency");
    static StatElem& hit_cnt = *StatMgr::getInstance()->createStat(StatElem::COUNTER, "raft_log_cache_hit");
    static StatElem& miss_cnt = *StatMgr::getInstance()->createStat(StatElem::COUNTER, "raft_log_cache_miss");
    GenericTimer tt;
    ptr< log_entry > ret = nullptr;
    if (cacheInst != nullptr) ret = cacheInst->get(index);
    if (ret) {
        ++hit_cnt;
    } else {
        ++miss_cnt;

        // homestore::log_buffer logentry;
        try {
            auto logentry = m_log_store->read_sync(index);
            SEBuf value_buf(logentry.size(), logentry.bytes());
            ret = jl_dec_le(value_buf);
        } catch (const std::out_of_range& e) {
            LOGERROR("hs_log_store::last_entry(), out_of_range {}", index);
            throw e;
        }

        // TODO: Free the log_buffer
    }

    read_lat += tt.getElapsedUs();
    return ret;
}

ulong hs_log_store::term_at(ulong index) {
    static StatElem& read_lat = *StatMgr::getInstance()->createStat(StatElem::HISTOGRAM, "raft_log_term_at_latency");
    GenericTimer tt;

    // NOTE: `term_at` will not update cache hit/miss count
    //       as it will be periodically invoked so that will spoil
    //       the hit ratio.

    uint64_t term = 0;
    ptr< log_entry > ret = nullptr;
    if (cacheInst != nullptr) ret = cacheInst->get(index);

    if (ret) {
        term = ret->get_term();
    } else {
        homestore::log_buffer logentry;

        try {
            logentry = m_log_store->read_sync(index);
        } catch (const std::out_of_range& e) {
            LOGERROR("hs_log_store::last_entry(), out_of_range {}", index);
            throw e;
        }

        SEBuf value_buf(logentry.size(), logentry.bytes());
        SEBufSerializer ss(value_buf);
        term = ss.getU64();

        // TODO: Free the log_buffer
    }

    read_lat += tt.getElapsedUs();
    LOGDEBUGMOD(nublox_logstore, "hs_log_store::term_at(), term {}", index, term);

    return term;
}

ptr< buffer > hs_log_store::pack(ulong index, int32 cnt) {
    LOGDEBUGMOD(nublox_logstore, "hs_log_store::pack()");

    std::vector< ptr< nuraft::log_entry > > records(cnt);
    ulong idx = 0;
    for (ulong ii = index; ii < index + cnt; ++ii) {
        records[idx++] = entry_at(ii);
    }

    // m_log_store->foreach(
    // (int64_t)index,
    // [cnt, &records, &idx, index, this](homestore::logstore_seq_num_t seq_num, const homestore::log_buffer& log_entry)
    // -> bool {
    //     assert(seq_num == index + idx);
    //     records[idx++] = log_entry;
    //     return idx < cnt ? true : false;
    // });

    assert(static_cast< decltype(cnt) >(idx) == cnt);

    //   << Format >>
    // # records (N)        4 bytes
    // +---
    // | log length (X)     4 bytes
    // | log data           X bytes
    // +--- repeat N

    // Calculate size.
    uint64_t buf_size = sz_int;
    for (auto& entry : records) {
        buf_size += sz_int;
        buf_size += entry->get_buf().size();
        ;
    }

    ptr< buffer > ret_buf = buffer::alloc(buf_size);

    // Put data
    ret_buf->put((int32)records.size());
    for (auto& entry : records) {
        ret_buf->put((uint8_t*)entry->get_buf().data(), entry->get_buf().size());
    }

    ret_buf->pos(0);
    return ret_buf;
}

void hs_log_store::apply_pack(ulong index, buffer& pack) {
    pack.pos(0);

    static std::mutex write_mutex;
    static std::condition_variable write_cv;
    static bool write_done;
    write_done = false;

    size_t num = pack.get_int();
    LOGDEBUGMOD(nublox_logstore, "hs_log_store::apply_pack(), pack size: {}", num);

    for (size_t ii = 0; ii < num; ++ii) {

        size_t log_len;
        uint8_t* ptr = const_cast< uint8_t* >(pack.get_bytes(log_len));

        // sisl::io_blob hs_entry((uint8_t*)value_buf.data(), value_buf.size(), false);
        // auto d = prepare_data(index);
        m_log_store->write_async(
            index + ii, {ptr, (uint32_t)log_len, false}, nullptr,
            [index, ptr, num, ii, this](homestore::logstore_seq_num_t seq_num, const sisl::io_blob& b,
                                        homestore::logdev_key ld_key, void* ctx) {
                LOGDEBUGMOD(nublox_logstore, "hs_log_store::write_async() index: {}, seqnum {}", index + ii, seq_num);

                assert(ld_key);
                // assert(seq_num, ld_key.idx);
                if (seq_num >= static_cast< decltype(seq_num) >(index + num - 1)) {
                    {
                        auto l = std::lock_guard< std::mutex >(write_mutex);
                        write_done = true;
                    }
                    write_cv.notify_one();
                }
            });
    }

    {
        std::unique_lock< std::mutex > lk(write_mutex);
        write_cv.wait(lk, [&] { return write_done; });
    }
    // Sync at once.
    m_log_store->sync();

    // Drop all contents in the cache.
    if (cacheInst != nullptr) cacheInst->drop();
}

bool hs_log_store::compact(ulong last_log_index) {
    static StatElem& cpt_lat = *StatMgr::getInstance()->createStat(StatElem::HISTOGRAM, "raft_log_compact_latency");
    GenericTimer tt;

    // append(), write_at(), and compact() are already protected by
    // Raft's lock, but add it here just in case.
    auto l = std::lock_guard< std::recursive_mutex >(writeLock);

    uint64_t max_seq;
    max_seq = m_log_store->get_contiguous_issued_seq_num(0);
    LOGDEBUGMOD(nublox_logstore, "hs_log_store::compact(), max_seq{}, last_log_seq{}", max_seq, last_log_index);

    if (max_seq < last_log_index) {
        // This happens during snapshot sync.
        // Append a dummy log and then purge.
        std::string dummy_str = "dummy_value";

        sisl::io_blob hs_entry((uint8_t*)dummy_str.c_str(), dummy_str.size(), false);
        static std::mutex write_mutex;
        static std::condition_variable write_cv;
        static bool write_done;
        write_done = false;

        m_log_store->write_async(last_log_index, hs_entry, nullptr,
                                 [last_log_index, this](homestore::logstore_seq_num_t seq_num, const sisl::io_blob& b,
                                                        homestore::logdev_key ld_key, void* ctx) {
                                     LOGDEBUGMOD(nublox_logstore, "hs_log_store::write_async() index: {}, seqnum {}",
                                                 last_log_index, seq_num);
                                     assert(ld_key);
                                     if (cacheInst != nullptr) cacheInst->drop();

                                     {
                                         auto l = std::lock_guard< std::mutex >(write_mutex);
                                         write_done = true;
                                     }
                                     write_cv.notify_one();
                                 });
        {
            std::unique_lock< std::mutex > lk(write_mutex);
            write_cv.wait(lk, [&] { return write_done; });
        }
    }

    bool f1 = m_log_store->sync();

    if (!f1) { return false; }

    m_log_store->truncate(last_log_index);
    if (cacheInst != nullptr) {
        cacheInst->compact(last_log_index);
        // Reset cached start index number.
        // Next `start_index()` will synchronize it.
        cacheInst->setStartIndex(0);
    }
    cpt_lat += tt.getElapsedUs();

    return true;
}

bool hs_log_store::flush() {
    LOGDEBUGMOD(nublox_logstore, "hs_log_store::flush()");

    if (m_log_store) {
        m_log_store->sync();

        uint64_t last_synced_idx = 0;
        last_synced_idx = m_log_store->get_contiguous_completed_seq_num(0);
        if (last_synced_idx) { lastDurableLogIdx = last_synced_idx; }
    }
    return true;
}

void hs_log_store::rollback(ulong to) {
    LOGDEBUGMOD(nublox_logstore, "hs_log_store::rollback()");

    m_log_store->rollback((homestore::logstore_seq_num_t)to);
    // Should drop cache.
    if (cacheInst != nullptr) cacheInst->drop();
}

void hs_log_store::close() {
    // Should close flush thread first.
    LOGDEBUGMOD(nublox_logstore, "hs_log_store::close()");

    flushThreadStopSignal = true;
    if (flushThread) {
        if (flushThread->joinable()) {
            eaFlushThread.invoke();
            flushThread->join();
        }
        DELETE(flushThread);
    }

    if (m_log_store) {
        m_log_store->sync();
        m_log_store = nullptr;
    }
}

void hs_log_store::shutdown() {}

void hs_log_store::removeLogStore(homestore::logstore_id_t logstore_id) {
    homestore::HomeLogStoreMgrSI().remove_log_store(homestore::HomeLogStoreMgr::CTRL_LOG_FAMILY_IDX, logstore_id);
}

} // namespace nuraft
