#pragma once

#include "state_machine/repl_set_impl.h"
#include "state_machine/state_machine.h"
#include "log_store/journal_entry.h"

namespace homestore {

template < typename... Args >
void ReplicaLogStore::attach_replica_set(ReplDevImpl* rd) {
    m_rd = rd;
    m_sm = r_cast< ReplicaStateMachine* >(m_rd->get_state_machine().get());
}

uint64_t ReplicaLogStore::append(nuraft::ptr< nuraft::log_entry >& entry) {
    repl_req* req = m_sm->transform_journal_entry(entry->get_buf_ptr());
    auto const lsn = HomeRaftLogStore::append(entry);
    if (req) { m_sm->link_lsn_to_req(req, int64_cast(lsn)); }
    return lsn;
}

void ReplicaLogStore::write_at(ulong index, nuraft::ptr< nuraft::log_entry >& entry) {
    repl_req* req = m_sm->transform_journal_entry(entry->get_buf_ptr());
    HomeRaftLogStore::write_at(index, entry);
    if (req) { m_sm->link_lsn_to_req(req, int64_cast(index)); }
}

void ReplicaLogStore::end_of_append_batch(ulong start_lsn, ulong count) {
    // Skip this call in leader, since this method will synchronously flush the data, which is not required for
    // leader. Leader will call the flush as part of commit after receiving quorum, upon which time, there is a high
    // possibility the log entry is already flushed.
    if (!m_rs->is_leader()) {
        int64_t end_lsn = int64_cast(start_lsn + count);

        // Start fetch the batch of data for this lsn range from remote if its not available yet.
        static thread_local std::vector< RemoteBlkId > s_rblkids;
        static thread_local std::vector< repl_req* > s_reqs;
        s_rblkids.clear();
        s_reqs.clear();
        for (int64_t lsn = int64_cast(start_lsn); lsn <= end_lsn; ++lsn) {
            repl_req* req = m_sm->lsn_to_req(lsn);
            s_rblkids.push_back(req->remote_blkid);
            s_reqs.push_back(req);
        }

        bool wait = m_sm->async_fetch_write_pbas(s_rblkids, [this, end_lsn]() {
            {
                std::unique_lock lg(m_batch_mtx);
                m_batch_lsn = end_lsn;
            }
            m_batch_cv.notify_one();
        });

        // Flush the journal for this lsn batch
        HomeRaftLogStore::end_of_append_batch(start_lsn, count);

        // If we had to fetch the data from remote, wait here until it is completed
        if (wait) {
            std::unique_lock< std::mutex > lg(m_batch_mtx);
            m_batch_cv.wait(lg, [this, end_lsn]() { return (m_batch_lsn == end_lsn); });
        }

        // Mark all the pbas also completely written
        for (auto* req : s_reqs) {
            req->is_raft_written.store(true);
            req->num_pbas_written.store(req->local_pbas.size());
        }
    }
}

} // namespace homestore
