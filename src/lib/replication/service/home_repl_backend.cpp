#include <home_replication/repl_service.h>
#include "service/home_repl_backend.h"
#include "log_store/repl_log_store.hpp"
#include "log_store/home_raft_log_store.h"
#include "storage/home_storage_engine.h"

SISL_LOGGING_DECL(home_replication)

namespace home_replication {

HomeReplicationBackend::HomeReplicationBackend(ReplicationService* svc) : ReplicationServiceBackend{svc} {
    homestore::meta_service().register_handler(
        "replica_set",
        [this](homestore::meta_blk* mblk, sisl::byte_view buf, size_t) {
            rs_super_blk_found(std::move(buf), voidptr_cast(mblk));
        },
        nullptr);
}

void HomeReplicationBackend::rs_super_blk_found(const sisl::byte_view& buf, void* meta_cookie) {
    homestore::superblk< home_rs_superblk > rs_sb;
    rs_sb.load(buf, meta_cookie);
    DEBUG_ASSERT_EQ(rs_sb->get_magic(), home_rs_superblk::REPLICA_SET_SB_MAGIC, "Invalid rs metablk, magic mismatch");
    DEBUG_ASSERT_EQ(rs_sb->get_version(), home_rs_superblk::REPLICA_SET_SB_VERSION, "Invalid version of rs metablk");

    auto sms = std::make_shared< HomeStateMachineStore >(rs_sb);
    auto rls = std::make_shared< ReplicaLogStore< HomeRaftLogStore > >(rs_sb->m_data_journal_id);
    m_svc->on_replica_store_found(rs_sb->uuid, sms, rls);
}

std::shared_ptr< StateMachineStore > HomeReplicationBackend::create_state_store(uuid_t uuid) {
    return std::make_shared< HomeStateMachineStore >(uuid);
}

std::shared_ptr< nuraft::log_store > HomeReplicationBackend::create_log_store() {
    return std::make_shared< ReplicaLogStore< HomeRaftLogStore > >();
}

void HomeReplicationBackend::link_log_store_to_replica_set(nuraft::log_store* ls, ReplicaSet* rs) {
    r_cast< ReplicaLogStore< HomeRaftLogStore >* >(ls)->attach_replica_set(rs);
}
} // namespace home_replication
