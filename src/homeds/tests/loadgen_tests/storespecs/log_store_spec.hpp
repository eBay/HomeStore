//
//  Created by Yaming Kuang
//
#pragma once

#include "homeds/loadgen/spec/store_spec.hpp"
#include "homeds/tests/loadgen_tests/keyspecs/logstore_key_spec.hpp"
#include "homeds/tests/loadgen_tests/valuespecs/logstore_value_spec.hpp"
#include "logdev/log_store.hpp"

namespace homeds {
namespace loadgen {

class LogStoreSpec : public StoreSpec< LogStoreKey, LogStoreValue > {

struct LogWriteInfo {
    bool        completed;
    uint64_t    crc;
};

public:
    virtual void init_store(homeds::loadgen::Param& parameters) override {
        HomeLogStore::start(true);
        m_store = HomeLogStore::create_new_log_store();
    }

    //
    // Similar as volume, only verify read on seq that write has returned, for outstanding write, just skip verification;
    //
    virtual bool get(LogStoreKey& k, LogStoreValue* out_v) override {
        logstore_seq_num_t seq = k.get_key();
        {
            std::lock_guard<std::mutex> lg(m_mtx);
            auto it = m_wrt_map.find(seq);
            assert(it != m_wrt_map.end());

            if (it->second.completed == false)
            {
                // write on this seq num is still outstanding, just return;
                return true;
            }
        }

        // do a sync read;
        auto log_read = m_store->read_sync(seq);

        {
            std::lock_guard<std::mutex> lg(m_mtx);
            auto hash = util::Hash64((const char*)log_read.data(), log_read.size());
            if (hash != m_wrt_map[seq].crc) {
                LOGERROR("Crc Mismatch Failure! read crc: {}, write crc: {}", hash, m_wrt_map[seq].crc);
                assert(0);
            }
        }

        return true;
    }

    // write is just append;
    virtual bool insert(LogStoreKey& k, std::shared_ptr<LogStoreValue> v) override {
        logstore_seq_num_t seq = k.get_key();
        {
            std::lock_guard<std::mutex> lg(m_mtx);
            assert(m_wrt_map.find(seq) == m_wrt_map.end());

            m_wrt_map[seq].completed = false;
            m_wrt_map[seq].crc = v->get_hash_code();
        }

        // trigger the async write;
        m_store->write_async(seq, {v->get_blob().bytes, v->get_blob().size}, nullptr,
                [this](logstore_seq_num_t seq_num, bool success, void* ctx) {
                    std::lock_guard<std::mutex> lg(m_mtx);
                    LOGINFO("Completed write of seq {}", seq_num);
                    m_wrt_map[seq_num].completed    = true;
                });

        return true;
    }

    virtual bool upsert(LogStoreKey& k, std::shared_ptr<LogStoreValue> v) override {
        assert(0);
        return true;
    }

    //
    // over-write
    // there is no such use case for logstore
    //
    virtual bool update(LogStoreKey& k, std::shared_ptr<LogStoreValue> v) override {
        return true;
    }

    virtual bool remove(LogStoreKey& k, LogStoreValue* removed_v = nullptr) override {
        assert(0);
        return true;
    }

    virtual bool remove_any(LogStoreKey& start_key, bool start_incl, LogStoreKey& end_key, bool end_incl, LogStoreKey *out_key, LogStoreValue* out_val) override {
        assert(0);
        return true;
    }

    virtual uint32_t query(LogStoreKey& start_key, bool start_incl, LogStoreKey& end_key, bool end_incl, std::vector<std::pair<LogStoreKey, LogStoreValue>> &result) {
        assert(0);
        return 1;
    }

    virtual bool range_update(LogStoreKey& start_key, bool start_incl, LogStoreKey& end_key, bool end_incl,
                              std::vector< std::shared_ptr<LogStoreValue> > &result) {
        assert(0);
        return true;
    }

private:
    std::shared_ptr<HomeLogStore>                           m_store = nullptr;
    std::unordered_map<logstore_seq_num_t, LogWriteInfo>    m_wrt_map;          // seq to its written data crc map, used for verfication;
    std::mutex                                              m_mtx;
};

}
}
