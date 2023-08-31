#pragma once

#include <mutex>
#include <condition_variable>
#include "home_raft_log_store.h"

namespace homestore {

class ReplDevImpl;
class ReplicaStateMachine;

class ReplicaLogStore : public HomeRaftLogStore {
private:
    ReplDevImpl* m_rd{nullptr};
    ReplicaStateMachine* m_sm{nullptr};
    std::mutex m_batch_mtx;
    std::condition_variable m_batch_cv;
    int64_t m_batch_lsn{0};

public:
    template < typename... Args >
    ReplicaLogStore(Args&&... args) : HomeRaftLogStore{std::forward< Args >(args)...} {}

    void attach_replica_set(ReplDevImpl* rd);
    uint64_t append(nuraft::ptr< nuraft::log_entry >& entry) override;
    void write_at(ulong index, nuraft::ptr< nuraft::log_entry >& entry) override;
    void end_of_append_batch(ulong start_lsn, ulong count) override;
};

} // namespace homestore
