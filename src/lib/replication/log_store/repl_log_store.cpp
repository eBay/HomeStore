#include <sisl/fds/vector_pool.hpp>
#include "replication/log_store/repl_log_store.h"
#include "replication/repl_dev/raft_state_machine.h"
#include "replication/repl_dev/raft_repl_dev.h"
#include "replication/repl_dev/common.h"

namespace homestore {

uint64_t ReplLogStore::append(nuraft::ptr< nuraft::log_entry >& entry) {
    repl_req_ptr_t rreq = m_sm.transform_journal_entry(entry);
    ulong lsn;
    if (rreq) {
        lsn = HomeRaftLogStore::append(rreq->raft_journal_buf());
        m_sm.link_lsn_to_req(rreq, int64_cast(lsn));
        RD_LOG(INFO, "Raft Channel: Received log entry rreq=[{}]", rreq->to_compact_string());
    } else {
        lsn = HomeRaftLogStore::append(entry);
    }
    return lsn;
}

void ReplLogStore::write_at(ulong index, nuraft::ptr< nuraft::log_entry >& entry) {
    repl_req_ptr_t rreq = m_sm.transform_journal_entry(entry);
    if (rreq) {
        HomeRaftLogStore::write_at(index, rreq->raft_journal_buf());
        m_sm.link_lsn_to_req(rreq, int64_cast(index));
        RD_LOG(INFO, "Raft Channel: Received log entry rreq=[{}]", rreq->to_compact_string());
    } else {
        HomeRaftLogStore::write_at(index, entry);
    }
}

void ReplLogStore::end_of_append_batch(ulong start_lsn, ulong count) {
    // Skip this call in leader, since this method will synchronously flush the data, which is not required for
    // leader. Leader will call the flush as part of commit after receiving quorum, upon which time, there is a high
    // possibility the log entry is already flushed.
    if (!m_rd.is_leader()) {
        int64_t end_lsn = int64_cast(start_lsn + count - 1);

        // Start fetch the batch of data for this lsn range from remote if its not available yet.
        auto reqs = sisl::VectorPool< repl_req_ptr_t >::alloc();
        for (int64_t lsn = int64_cast(start_lsn); lsn <= end_lsn; ++lsn) {
            reqs->emplace_back(m_sm.lsn_to_req(lsn));
        }

        // Check the map if data corresponding to all of these requsts have been received and written. If not, schedule
        // a fetch and write. Once all requests are completed and written, these requests are poped out of the map and
        // the future will be ready.
        auto fut = m_rd.notify_after_data_written(reqs);

        // In the meanwhile, we can flush the journal for this lsn batch. It is ok to flush the entries in log before
        // actual data is written, because, even if we have the log, it doesn't mean data is committed, until state
        // machine reports that. This way the flush and fetch both can run in parallel.
        HomeRaftLogStore::end_of_append_batch(start_lsn, count);

        // Wait for the fetch and write to be completed successfully.
        std::move(fut).get();

        // Mark all the pbas also completely written
        for (auto const& rreq : *reqs) {
            if (rreq) { rreq->state.fetch_or(uint32_cast(repl_req_state_t::LOG_FLUSHED)); }
        }

        sisl::VectorPool< repl_req_ptr_t >::free(reqs);
    }
}

std::string ReplLogStore::rdev_name() const { return m_rd.rdev_name(); }

bool ReplLogStore::compact(ulong last_lsn) {
    m_rd.on_compact(last_lsn);
    return HomeRaftLogStore::compact(last_lsn);
}

} // namespace homestore
