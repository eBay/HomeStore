#include <home_replication/repl_set.h>

#include <sisl/fds/obj_allocator.hpp>
#include <sisl/fds/vector_pool.hpp>
#include <home_replication/repl_service.h>
#include "state_machine/state_machine.h"
#include "log_store/repl_log_store.hpp"
#include "log_store/journal_entry.h"
#include "storage/storage_engine.h"

namespace home_replication {
ReplDev::ReplDev(const std::string& group_id) :
        m_state_machine{std::make_shared< ReplicaStateMachine >(this)}, m_group_id{group_id} {
    RD_STORE_LOG(INFO, "Creating new instance of repl dev for uuid={}", rs_uuid);
    m_data_journal = std::make_shared< HomeRaftLogStore >();

    // Create logstore to store the free pba records
    m_free_blks_journal = logstore_service().create_new_log_store(true /* append_mode */);
    if (!m_free_blks_journal) { throw std::runtime_error("Failed to create log store"); }

    // Create a superblk for the replica set.
    m_sb.create(sizeof(repldev_superblk));
    m_sb->uuid = rs_uuid;
    m_sb->free_blks_store_id = m_free_blks_journal->get_store_id();
    m_sb.write();
    m_sb_in_mem = *m_sb;

    RD_STORE_LOG(DEBUG, "New free pba record logstore={} created", m_sb->free_blks_store_id);
}

ReplDev::ReplDev(const superblk< repldev_superblk >& rd_sb) : m_sb{"replica_device"} {
    RD_STORE_LOG(INFO, "Opening existing replica state machine store for uuid={}", rs_sb->uuid);
    m_sb = rs_sb;
    m_sb_in_mem = *m_sb;
    RD_STORE_LOG(DEBUG, "Opening free pba record logstore={}", m_sb->free_blks_store_id);
    logstore_service().open_log_store(m_sb->free_blks_store_id, true,
                                      bind_this(HomeStateMachineStore::on_store_created, 1));
}

void ReplDev::async_write(const sisl::blob& header, const sisl::blob& key, const sisl::sg_list& value, void* user_ctx) {
    m_state_machine->propose(header, key, value, user_ctx);
}

void ReplDev::free_blks(int64_t lsn, const pba_list_t& pbas) { m_state_store->add_free_pba_record(lsn, pbas); }

// void ReplicaSet::on_data_received() {}

std::shared_ptr< nuraft::state_machine > ReplicaSet::get_state_machine() {
    return std::dynamic_pointer_cast< nuraft::state_machine >(m_state_machine);
}

bool ReplicaSet::is_leader() {
    // TODO: Need to implement after setting up RAFT replica set
    return true;
}
} // namespace home_replication
