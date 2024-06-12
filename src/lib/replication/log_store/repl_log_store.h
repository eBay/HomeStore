#pragma once

#include <mutex>
#include <condition_variable>
#include "replication/log_store/home_raft_log_store.h"

namespace homestore {

class RaftReplDev;
class RaftStateMachine;

class ReplLogStore : public HomeRaftLogStore {
private:
    RaftReplDev& m_rd;
    RaftStateMachine& m_sm;
    std::mutex m_batch_mtx;
    std::condition_variable m_batch_cv;
    int64_t m_batch_lsn{0};

public:
    template < typename... Args >
    ReplLogStore(RaftReplDev& rd, RaftStateMachine& sm, const log_found_cb_t& log_found_cb,
                 const log_replay_done_cb_t& log_replay_done_cb, Args&&... args) :
            HomeRaftLogStore{std::forward< Args >(args)...}, m_rd{rd}, m_sm{sm} {
        register_log_found_cb(log_found_cb);
        register_log_replay_done_cb(log_replay_done_cb);
    }

    ////////////////////////  function override ////////////////////////
    uint64_t append(nuraft::ptr< nuraft::log_entry >& entry) override;
    void write_at(ulong index, nuraft::ptr< nuraft::log_entry >& entry) override;
    void end_of_append_batch(ulong start_lsn, ulong count) override;
    bool compact(ulong last_lsn) override;

private:
    std::string rdev_name() const;
};

} // namespace homestore
