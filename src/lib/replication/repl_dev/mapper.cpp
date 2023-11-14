#include <iomgr/iomgr_timer.hpp>
#include <sisl/logging/logging.h>
#include <sisl/fds/utils.hpp>
#include <sisl/fds/vector_pool.hpp>

#include "repl_dev/raft_state_machine.h"
#include "repl_dev/raft_repl_dev.h"

namespace homestore {
repl_req_ptr_t RaftReplDev::follower_create_req(repl_key const& rkey, sisl::blob const& user_header,
                                                sisl::blob const& user_key) {
    auto const [it, happened] = m_repl_key_req_map.try_emplace(rkey, repl_req_ptr_t(new repl_req_ctx()));
    RD_DBG_ASSERT_EQ(it, m_repl_key_req_map.end(), "Unexpected error in map_repl_key_to_req");
    auto rreq = it->second;

    if (!happened) {
        // We already have the entry in the map, check if we are already allocated the blk by previous caller, in that
        // case we need to return the req.
        if (rreq->state.load() & repl_req_state_t::BLK_ALLOCATED) {
            // Do validation if we have the correct mapping
            RD_REL_ASSERT(false, blob_equals(user_header, rreq->header), "User header mismatch for repl_key={}", rkey);
            RD_REL_ASSERT(false, blob_equals(user_key, rreq->key), "User key mismatch for repl_key={}", rkey);
            return rreq;
        }
    }

    // We need to allocate the block, since entry doesn't exist or if it exist, two threads are trying to do the same
    // thing. So take state mutex and allocate the blk
    std::unique_lock< std::mutex > lg(rreq->state_mtx);
    if (rreq->state.load() & repl_req_state_t::BLK_ALLOCATED) { return rreq; }
    rreq->rkey = rkey;
    rreq->header = header;
    rreq->key = key;
    rreq->local_blkid = do_alloc_blk(remote_blkid.get_num_blks(), m_rd->m_listener->get_blk_alloc_hints(user_header));
    rreq->state.fetch_or(repl_req_state_t::BLK_ALLOCATED);

    return rreq;
}

AsyncNotify RaftReplDev::notify_after_data_written(std::vector< repl_req_ptr_t >&& rreqs) {
    // Pop any entries that are already completed - from the entries list as well as from map
    rreqs.erase(std::remove_if(rreqs.begin(), rreqs.end(), [this](repl_req_ptr_t const& rreq) {
        if (rreq->state.load() & repl_req_state_t::DATA_WRITTEN) {
            m_repl_key_req_map.erase(rreq->rkey); // Remove=Pop from map as well, since it is completed
            return true;                          // Remove from the pending list
        }
    }));

    // All the entries are done already, no need to wait
    if (rreqs.size() == 0) { return folly::makeFuture< folly::Unit >(); }

    std::vector< folly::SemiFuture< folly::Unit > > futs;
    futs.reserve(rreqs.size());
    for (auto const& rreq : rreqs) {
        futs.emplace_back(rreq->data_written_promise.getSemiFuture());
    }

    return folly::collectAll(futs).deferValue([this, rreqs]() {
        for (auto const& rreq : rreqs) {
            HS_DBG_ASSERT(rreq->state.load() & repl_req_state_t::DATA_WRITTEN,
                          "Data written promise raised without updating DATA_WRITTEN state for rkey={}", rreq->rkey);
            m_repl_key_req_map.erase(rreq->rkey); // Remove=Pop from map as well, since it is completed
        }
    });
#if 0
    // We are yet to support reactive fetch from remote.
    AsyncNotifier p;
    auto ret = p.getFuture();

    if (m_resync_mode) {
        // if in resync mode, fetch data from remote immediately;
        check_and_fetch_remote_data(std::move(rreqs), std::move(p));
    } else {
        // some blkids are not in completed state, let's schedule a timer to check it again;
        // we wait for data channel to fill in the data. Still if its not done we trigger a fetch from remote;
        m_wait_blkid_write_timer_hdl = iomanager.schedule_thread_timer( // timer wakes up in current thread;
            HS_DYNAMIC_CONFIG(repl->wait_blkid_write_timer_sec) * 1000 * 1000 * 1000, false /* recurring */,
            nullptr /* cookie */, [this, std::move(rreqs), std::move(p)](auto) {
                check_and_fetch_remote_data(std::move(rreqs), std::move(p));
            });
    }
    return ret;
#endif
}

AsyncNotify RaftReplDev::map_fetch_write_pop(std::vector< repl_req_ptr_t >&& rreqs) {
    // Pop any entries that are already completed - from the entries list as well as from map
    rreqs.erase(std::remove_if(rreqs.begin(), rreqs.end(), [this](repl_req_ptr_t const& rreq) {
        if (rreq->state.load() & repl_req_state_t::DATA_WRITTEN) {
            m_repl_key_req_map.erase(rreq->rkey); // Remove=Pop from map as well, since it is completed
            return true;                          // Remove from the pending list
        }
    }));

    // All the entries are done already, no need to wait
    if (rreqs.size() == 0) { return folly::makeFuture< folly::Unit >(); }

    AsyncNotifier p;
    auto ret = p.getFuture();

    if (m_resync_mode) {
        // if in resync mode, fetch data from remote immediately;
        check_and_fetch_remote_data(std::move(rreqs), std::move(p));
    } else {
        // some blkids are not in completed state, let's schedule a timer to check it again;
        // we wait for data channel to fill in the data. Still if its not done we trigger a fetch from remote;
        m_wait_blkid_write_timer_hdl = iomanager.schedule_thread_timer( // timer wakes up in current thread;
            HS_DYNAMIC_CONFIG(repl->wait_blkid_write_timer_sec) * 1000 * 1000 * 1000, false /* recurring */,
            nullptr /* cookie */, [this, std::move(rreqs), std::move(p)](auto) {
                check_and_fetch_remote_data(std::move(rreqs), std::move(p));
            });
    }
    return ret;
}

} // namespace homestore