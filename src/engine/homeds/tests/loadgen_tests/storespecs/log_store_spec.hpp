/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 * Author/Developer(s): Yaming Kuang
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

#include <cassert>
#include <cstdint>
#include <iterator>
#include <mutex>
#include <unordered_map>

#include "homeds/loadgen/spec/store_spec.hpp"
#include "homeds/tests/loadgen_tests/keyspecs/logstore_key_spec.hpp"
#include "homeds/tests/loadgen_tests/valuespecs/logstore_value_spec.hpp"
#include "homelogstore/log_store.hpp"

namespace homeds {
namespace loadgen {

class LogStoreSpec : public StoreSpec< LogStoreKey, LogStoreValue > {
    LogStoreSpec() = default;
    LogStoreSpec(const LogStoreSpec&) = delete;
    LogStoreSpec& operator=(const LogStoreSpec&) = delete;
    LogStoreSpec(LogStoreSpec&&) noexcept = delete;
    LogStoreSpec& operator=(LogStoreSpec&&) noexcept = delete;
    virtual ~LogStoreSpec() override = default;

    struct LogWriteInfo {
        bool completed;
        uint64_t crc;
    };

public:
    virtual void init_store(const homeds::loadgen::Param& parameters) override {
        HomeLogStoreMgrSI().start(true);
        m_store =
            HomeLogStoreMgrSI().create_new_log_store(HomeLogStoreMgr::DATA_LOG_FAMILY_IDX, false /* append_mode */);
    }

    //
    // Similar as volume, only verify read on seq that write has returned, for outstanding write, just skip
    // verification;
    //
    virtual bool get(const LogStoreKey& k, LogStoreValue* const out_v) const override {
        const logstore_seq_num_t seq{k.get_key()};
        {
            std::lock_guard< std::mutex > lg{m_mtx};
            const auto it{m_wrt_map.find(seq)};
            assert(it != std::cend(m_wrt_map));

            if (it->second.completed == false) {
                // write on this seq num is still outstanding, just return;
                return true;
            }
        }

        // do a sync read;
        const auto log_read{m_store->read_sync(seq)};

        {
            std::lock_guard< std::mutex > lg{m_mtx};
            const auto hash{util::Hash64(reinterpret_cast< const char* >(log_read.bytes()), log_read.size())};
            const auto itr{m_wrt_map.find(seq)};
            if ((itr == std::end(m_wrt_map)) || (hash != itr->second.crc)) {
                if (itr != std::cend(m_wrt_map)) {
                    LOGERROR("Crc Mismatch Failure! read crc: {}, write crc: {}", hash, itr->second.crc);
                } else {
                    LOGERROR("Crc Mismatch Failure! read crc: {}, write crc not found for seq: {}", hash, seq);
                }
                assert(false);
            }
        }

        return true;
    }

    // write is just append;
    virtual bool insert(LogStoreKey& k, std::shared_ptr< LogStoreValue > v) override {
        const logstore_seq_num_t seq{k.get_key()};
        {
            std::lock_guard< std::mutex > lg{m_mtx};
            assert(m_wrt_map.find(seq) == std::end(m_wrt_map));

            m_wrt_map[seq].completed = false;
            m_wrt_map[seq].crc = v->get_hash_code();
        }

        // trigger the async write;
        m_store->write_async(seq, sisl::io_blob{v->get_blob().bytes, v->get_blob().size, false}, nullptr,
                             [this](logstore_seq_num_t seq_num, sisl::blob& iob, bool success, void* const ctx) {
                                 std::lock_guard< std::mutex > lg{m_mtx};
                                 LOGINFO("Completed write of seq {}", seq_num);
                                 m_wrt_map[seq_num].completed = true;
                             });

        return true;
    }

    virtual bool upsert(LogStoreKey& k, std::shared_ptr< LogStoreValue > v) override {
        assert(false);
        return false;
    }

    //
    // over-write
    // there is no such use case for logstore
    //
    virtual bool update(LogStoreKey& k, std::shared_ptr< LogStoreValue > v) override { return true; }

    virtual bool remove(const LogStoreKey& k, LogStoreValue* const removed_v = nullptr) override {
        assert(false);
        return false;
    }

    virtual bool remove_any(const LogStoreKey& start_key, const bool start_incl, const LogStoreKey& end_key,
                            const bool end_incl, LogStoreKey* const out_key, LogStoreValue* const out_val) override {
        assert(false);
        return false;
    }

    virtual uint32_t query(const LogStoreKey& start_key, const bool start_incl, const LogStoreKey& end_key,
                           const bool end_incl, std::vector< std::pair< LogStoreKey, LogStoreValue > >& result) const {
        assert(false);
        return 0;
    }

    virtual bool range_update(LogStoreKey& start_key, const bool start_incl, LogStoreKey& end_key, const bool end_incl,
                              std::vector< std::shared_ptr< LogStoreValue > >& result) override {
        assert(false);
        return false;
    }

private:
    std::shared_ptr< HomeLogStore > m_store = nullptr;
    std::unordered_map< logstore_seq_num_t, LogWriteInfo >
        m_wrt_map; // seq to its written data crc map, used for verfication;
    mutable std::mutex m_mtx;
};

} // namespace loadgen
} // namespace homeds
